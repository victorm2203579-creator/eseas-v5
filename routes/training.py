import io
import json
from datetime import datetime, timezone

from flask import (Blueprint, render_template, request, redirect,
                   url_for, jsonify, flash, abort, make_response)
from flask_login import login_required, current_user

from models import db
from models.training import (TrainingModule, Quiz, UserProgress,
                              TrainingAssignment, UserBadge)
from models.user import User
from models.notification import NotificationService
from routes.decorators import admin_required
from routes.badge_service import BadgeService

training       = Blueprint('training',       __name__, url_prefix='/training')
training_admin = Blueprint('training_admin', __name__, url_prefix='/admin')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_progress(user_id, module_id):
    return UserProgress.query.filter_by(
        user_id=user_id, module_id=module_id).first()

def _get_assignment(user_id, module_id):
    return TrainingAssignment.query.filter_by(
        user_id=user_id, module_id=module_id, completed=False).first()

def _next_module(current_order):
    return (TrainingModule.query
            .filter_by(is_active=True)
            .filter(TrainingModule.order_index > current_order)
            .order_by(TrainingModule.order_index)
            .first())


# ── User routes ───────────────────────────────────────────────────────────────

@training.route('/')
@login_required
def index():
    modules = (TrainingModule.query
               .filter_by(is_active=True)
               .order_by(TrainingModule.order_index)
               .all())

    progress_map = {p.module_id: p
                    for p in UserProgress.query.filter_by(user_id=current_user.id).all()}

    pending_assignments = (TrainingAssignment.query
                           .filter_by(user_id=current_user.id, completed=False)
                           .all())
    pending_module_ids = {a.module_id for a in pending_assignments}

    module_data = []
    for m in modules:
        p = progress_map.get(m.id)
        module_data.append({
            'module':     m,
            'progress':   p,
            'is_mandatory': m.id in pending_module_ids,
            'assignment': next((a for a in pending_assignments if a.module_id == m.id), None),
        })

    badges       = UserBadge.query.filter_by(user_id=current_user.id).all()
    earned_keys  = {b.badge_key for b in badges}
    passed_count = sum(1 for p in progress_map.values() if p.quiz_passed)
    total        = len(modules)
    pct          = round(passed_count / total * 100) if total else 0

    return render_template('training/dashboard.html',
                           module_data=module_data,
                           badges=badges,
                           earned_keys=earned_keys,
                           pending_count=len(pending_assignments),
                           passed_count=passed_count,
                           total_modules=total,
                           progress_pct=pct,
                           ALL_BADGES=BadgeService.BADGES)


@training.route('/module/<int:mid>')
@login_required
def lesson(mid):
    module   = TrainingModule.query.filter_by(id=mid, is_active=True).first_or_404()
    progress = _get_progress(current_user.id, mid)
    now      = datetime.now(timezone.utc)

    if not progress:
        progress = UserProgress(
            user_id=current_user.id,
            module_id=mid,
            status='in_progress',
            started_at=now,
        )
        db.session.add(progress)
        db.session.commit()
    elif progress.status == 'not_started':
        progress.status     = 'in_progress'
        progress.started_at = now
        db.session.commit()

    return render_template('training/lesson.html',
                           module=module,
                           progress=progress,
                           assignment=_get_assignment(current_user.id, mid),
                           next_module=_next_module(module.order_index))


@training.route('/module/<int:mid>/quiz')
@login_required
def quiz(mid):
    module   = TrainingModule.query.filter_by(id=mid, is_active=True).first_or_404()
    progress = _get_progress(current_user.id, mid)

    if not progress or progress.status == 'not_started':
        flash('Please read the lesson before taking the quiz.', 'warning')
        return redirect(url_for('training.lesson', mid=mid))

    questions = Quiz.query.filter_by(module_id=mid).order_by(Quiz.id).all()
    return render_template('training/quiz.html',
                           module=module,
                           questions=questions,
                           progress=progress)


@training.route('/module/<int:mid>/quiz/submit', methods=['POST'])
@login_required
def submit_quiz(mid):
    module   = TrainingModule.query.filter_by(id=mid, is_active=True).first_or_404()
    progress = _get_progress(current_user.id, mid)

    if not progress:
        return jsonify({'error': 'Please visit the lesson first.'}), 400

    data      = request.get_json(silent=True) or {}
    answers   = data.get('answers', {})   # {str(question_id): 'a'/'b'/'c'/'d'}
    questions = Quiz.query.filter_by(module_id=mid).order_by(Quiz.id).all()

    max_points   = sum(q.points for q in questions)
    total_points = 0
    question_results = []

    for q in questions:
        user_answer     = str(answers.get(str(q.id), '')).lower().strip()
        correct_answer  = q.correct_option.lower()
        is_correct      = (user_answer == correct_answer)
        if is_correct:
            total_points += q.points

        question_results.append({
            'id':                  q.id,
            'question':            q.question_text,
            'your_answer':         user_answer,
            'correct_answer':      correct_answer,
            'your_answer_text':    q.get_option_text(user_answer) if user_answer else '— Not answered —',
            'correct_answer_text': q.get_option_text(correct_answer),
            'is_correct':          is_correct,
            'explanation':         q.explanation,
        })

    score  = round(total_points / max_points * 100) if max_points else 0
    passed = score >= 70
    now    = datetime.now(timezone.utc)

    progress.quiz_score       = score
    progress.quiz_passed      = passed
    progress.attempts         = (progress.attempts or 0) + 1
    progress.last_attempt_at  = now
    progress.status           = 'passed' if passed else 'failed'
    progress.last_attempt_json = json.dumps(question_results)
    if passed and not progress.completed_at:
        progress.completed_at = now
    db.session.commit()

    badges_earned = []
    if passed:
        badges_earned = BadgeService.check_and_award_badges(current_user.id)

        NotificationService.quiz_passed(current_user.id, module.title, score)
        for badge_key in badges_earned:
            badge_name = BadgeService.BADGES.get(badge_key, {}).get('name', badge_key)
            NotificationService.badge_awarded(current_user.id, badge_name)

        assignment = _get_assignment(current_user.id, mid)
        if assignment:
            assignment.completed    = True
            assignment.completed_at = now
            db.session.commit()

    next_mod = _next_module(module.order_index)

    return jsonify({
        'score':          score,
        'passed':         passed,
        'questions':      question_results,
        'badges_earned':  badges_earned,
        'next_module_id': next_mod.id if next_mod else None,
        'result_url':     url_for('training.quiz_result', mid=mid),
        'message': (f'Congratulations! You scored {score}/100 and passed!'
                    if passed else
                    f'You scored {score}/100. You need 70 to pass. Please review and retake.'),
    })


@training.route('/module/<int:mid>/result')
@login_required
def quiz_result(mid):
    module   = TrainingModule.query.filter_by(id=mid, is_active=True).first_or_404()
    progress = _get_progress(current_user.id, mid)

    if not progress or not progress.last_attempt_json:
        return redirect(url_for('training.quiz', mid=mid))

    result_data = progress.last_result
    next_mod    = _next_module(module.order_index)

    return render_template('training/quiz_result.html',
                           module=module,
                           progress=progress,
                           result_data=result_data,
                           next_module=next_mod)


@training.route('/badges')
@login_required
def badges():
    earned = UserBadge.query.filter_by(user_id=current_user.id).all()
    earned_map = {b.badge_key: b for b in earned}
    return render_template('training/badges.html',
                           earned_map=earned_map,
                           ALL_BADGES=BadgeService.BADGES)


@training.route('/leaderboard')
@login_required
def leaderboard():
    users         = User.query.filter_by(is_active=True).all()
    total_modules = TrainingModule.query.filter_by(is_active=True).count()

    board = []
    for u in users:
        badges_count  = UserBadge.query.filter_by(user_id=u.id).count()
        passed_count  = UserProgress.query.filter_by(user_id=u.id, quiz_passed=True).count()
        risk          = u.risk_score or 0.0
        security_score = max(0, int(100 - risk + badges_count * 5 + passed_count * 2))
        risk_level    = 'High' if risk >= 70 else ('Medium' if risk >= 40 else 'Low')
        board.append({
            'user':           u,
            'security_score': security_score,
            'modules_passed': passed_count,
            'badges':         badges_count,
            'risk_level':     risk_level,
            'is_current':     u.id == current_user.id,
        })

    board.sort(key=lambda x: x['security_score'], reverse=True)
    for i, row in enumerate(board):
        row['rank'] = i + 1

    top3 = board[:3]
    return render_template('training/leaderboard.html',
                           board=board, top3=top3,
                           total_modules=total_modules)


@training.route('/certificate')
@login_required
def certificate():
    modules = (TrainingModule.query
               .filter_by(is_active=True)
               .order_by(TrainingModule.order_index)
               .all())

    passed_pairs = []
    all_passed   = True
    for m in modules:
        p = _get_progress(current_user.id, m.id)
        if p and p.quiz_passed:
            passed_pairs.append((m, p))
        else:
            all_passed = False

    return render_template('training/certificate.html',
                           passed_pairs=passed_pairs,
                           all_passed=all_passed,
                           total_modules=len(modules))


@training.route('/certificate/download')
@login_required
def download_certificate():
    modules = (TrainingModule.query
               .filter_by(is_active=True)
               .order_by(TrainingModule.order_index)
               .all())

    passed_pairs = []
    for m in modules:
        p = _get_progress(current_user.id, m.id)
        if p and p.quiz_passed:
            passed_pairs.append((m, p))

    if len(passed_pairs) < len(modules):
        flash('Complete all modules before downloading your certificate.', 'warning')
        return redirect(url_for('training.certificate'))

    pdf_bytes = _generate_certificate_pdf(current_user, passed_pairs)
    response  = make_response(pdf_bytes)
    response.headers['Content-Type']        = 'application/pdf'
    response.headers['Content-Disposition'] = (
        f'attachment; filename=ESEAS_Certificate_{current_user.name.replace(" ", "_")}.pdf'
    )
    return response


def _generate_certificate_pdf(user, passed_pairs):
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.lib.units import cm

    buf  = io.BytesIO()
    W, H = landscape(A4)     # 841.89 × 595.28 pt
    c    = canvas.Canvas(buf, pagesize=landscape(A4))

    NAVY   = HexColor('#0a1628')
    ORANGE = HexColor('#ff6b35')
    GOLD   = HexColor('#d4a017')

    # Outer navy border
    c.setStrokeColor(NAVY)
    c.setLineWidth(12)
    c.rect(18, 18, W - 36, H - 36, stroke=1, fill=0)

    # Inner thin gold border
    c.setStrokeColor(GOLD)
    c.setLineWidth(2)
    c.rect(30, 30, W - 60, H - 60, stroke=1, fill=0)

    # Header background strip
    c.setFillColor(NAVY)
    c.rect(0, H - 90, W, 90, stroke=0, fill=1)

    # Project logo / name in header
    c.setFillColor(ORANGE)
    c.setFont('Helvetica-Bold', 22)
    c.drawCentredString(W / 2, H - 45, 'ESEAS')
    c.setFillColor(white)
    c.setFont('Helvetica', 11)
    c.drawCentredString(W / 2, H - 63,
                        'Enhanced Social Engineering Attack Simulator | Cybersecurity Awareness Programme')

    # Main heading
    c.setFillColor(NAVY)
    c.setFont('Helvetica-Bold', 32)
    c.drawCentredString(W / 2, H - 145, 'CERTIFICATE OF COMPLETION')

    # Decorative line
    c.setStrokeColor(ORANGE)
    c.setLineWidth(2.5)
    c.line(W * 0.15, H - 158, W * 0.85, H - 158)

    # Body text
    c.setFillColor(black)
    c.setFont('Helvetica', 13)
    c.drawCentredString(W / 2, H - 188, 'This certifies that')

    # User name
    c.setFont('Helvetica-Bold', 26)
    c.setFillColor(NAVY)
    c.drawCentredString(W / 2, H - 222, user.name)

    c.setFont('Helvetica', 13)
    c.setFillColor(black)
    c.drawCentredString(W / 2, H - 248,
                        'has successfully completed the Cybersecurity Awareness Training Programme')

    # Completion date
    completion_date = max(p.completed_at for _, p in passed_pairs).strftime('%d %B %Y')
    c.setFont('Helvetica', 11)
    c.drawCentredString(W / 2, H - 268, f'Completion Date: {completion_date}')

    # Module list (two columns)
    c.setFont('Helvetica-Bold', 10)
    c.setFillColor(NAVY)
    c.drawCentredString(W / 2, H - 298, 'Modules Completed:')

    col_x = [W * 0.18, W * 0.58]
    y_start = H - 318
    for i, (mod, prog) in enumerate(passed_pairs):
        col = i % 2
        row = i // 2
        y   = y_start - row * 18
        c.setFont('Helvetica', 9)
        c.setFillColor(black)
        date_str = prog.completed_at.strftime('%d %b %Y') if prog.completed_at else ''
        c.drawString(col_x[col], y,
                     f'✓  {mod.title}  ({date_str})  — Score: {prog.quiz_score}/100')

    # Signature line
    sig_y = 68
    c.setStrokeColor(NAVY)
    c.setLineWidth(1)
    c.line(W * 0.30, sig_y, W * 0.48, sig_y)
    c.line(W * 0.52, sig_y, W * 0.70, sig_y)

    c.setFont('Helvetica', 9)
    c.setFillColor(black)
    c.drawCentredString(W * 0.39, sig_y - 12, 'Participant Signature')
    c.drawCentredString(W * 0.61, sig_y - 12, 'Supervisor / Administrator')

    # Footer
    c.setFont('Helvetica', 8)
    c.setFillColor(HexColor('#666666'))
    c.drawCentredString(W / 2, 44,
                        f'Issued: {datetime.now().strftime("%d %B %Y")}  |  '
                        'Federal University of Technology, Minna  |  Cybersecurity Final Year Project')

    c.save()
    return buf.getvalue()


# ── Admin routes ──────────────────────────────────────────────────────────────

@training_admin.route('/training')
@login_required
@admin_required
def training_management():
    modules = (TrainingModule.query
               .filter_by(is_active=True)
               .order_by(TrainingModule.order_index)
               .all())

    # Per-module pass rates
    module_stats = []
    for m in modules:
        attempts = UserProgress.query.filter_by(module_id=m.id).count()
        passed   = UserProgress.query.filter_by(module_id=m.id, quiz_passed=True).count()
        module_stats.append({
            'module':    m,
            'attempts':  attempts,
            'passed':    passed,
            'pass_rate': round(passed / attempts * 100) if attempts else 0,
        })

    # All-users progress summary
    users = User.query.filter_by(is_active=True).order_by(User.name).all()
    total_mod_count = len(modules)
    user_summaries = []
    for u in users:
        progresses  = UserProgress.query.filter_by(user_id=u.id).all()
        passed_ids  = {p.module_id for p in progresses if p.quiz_passed}
        scores      = [p.quiz_score for p in progresses if p.quiz_score is not None]
        avg_score   = round(sum(scores) / len(scores)) if scores else None
        pending     = TrainingAssignment.query.filter_by(user_id=u.id, completed=False).count()
        last_active = max((p.last_attempt_at for p in progresses if p.last_attempt_at),
                          default=None)
        badge_count = UserBadge.query.filter_by(user_id=u.id).count()
        user_summaries.append({
            'user':           u,
            'passed':         len(passed_ids),
            'total':          total_mod_count,
            'avg_score':      avg_score,
            'pending_assign': pending,
            'last_active':    last_active,
            'badge_count':    badge_count,
        })

    pending_assignments = (TrainingAssignment.query
                           .filter_by(completed=False)
                           .order_by(TrainingAssignment.assigned_at.desc())
                           .limit(20).all())

    return render_template('admin/training_management.html',
                           module_stats=module_stats,
                           user_summaries=user_summaries,
                           pending_assignments=pending_assignments,
                           all_users=users,
                           all_modules=modules)


@training_admin.route('/training/modules/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_module():
    if request.method == 'POST':
        title     = request.form.get('title', '').strip()
        topic     = request.form.get('topic', '')
        if not title or not topic:
            flash('Title and topic are required.', 'danger')
            return redirect(url_for('training_admin.new_module'))

        module = TrainingModule(
            title=request.form.get('title', '').strip(),
            description=request.form.get('description', '').strip(),
            topic=topic,
            content_html=request.form.get('content_html', ''),
            video_url=request.form.get('video_url', '').strip() or None,
            order_index=int(request.form.get('order_index', 99)),
            estimated_minutes=int(request.form.get('estimated_minutes', 10)),
            icon_class=request.form.get('icon_class', 'fa-book').strip(),
        )
        db.session.add(module)
        db.session.commit()
        flash(f'Module "{module.title}" created.', 'success')
        return redirect(url_for('training_admin.training_management'))

    topics = list(TrainingModule.TOPIC_META.items())
    return render_template('admin/module_form.html',
                           mode='new', topics=topics)


@training_admin.route('/training/modules/<int:mid>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_module(mid):
    module = TrainingModule.query.get_or_404(mid)

    if request.method == 'POST':
        module.title             = request.form.get('title', module.title).strip()
        module.description       = request.form.get('description', '').strip()
        module.topic             = request.form.get('topic', module.topic)
        module.content_html      = request.form.get('content_html', module.content_html)
        module.video_url         = request.form.get('video_url', '').strip() or None
        module.order_index       = int(request.form.get('order_index', module.order_index))
        module.estimated_minutes = int(request.form.get('estimated_minutes', module.estimated_minutes))
        module.icon_class        = request.form.get('icon_class', module.icon_class).strip()
        module.is_active         = 'is_active' in request.form
        db.session.commit()
        flash('Module updated.', 'success')
        return redirect(url_for('training_admin.training_management'))

    topics = list(TrainingModule.TOPIC_META.items())
    return render_template('admin/module_form.html',
                           module=module, mode='edit', topics=topics)


@training_admin.route('/training/modules/<int:mid>/questions')
@login_required
@admin_required
def module_questions(mid):
    module    = TrainingModule.query.get_or_404(mid)
    questions = Quiz.query.filter_by(module_id=mid).order_by(Quiz.id).all()
    return render_template('admin/module_questions.html',
                           module=module, questions=questions)


@training_admin.route('/training/modules/<int:mid>/questions/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_question(mid):
    module = TrainingModule.query.get_or_404(mid)

    if request.method == 'POST':
        question_text = request.form.get('question_text', '').strip()
        correct       = request.form.get('correct_option', '').lower().strip()
        if not question_text or correct not in ('a', 'b', 'c', 'd'):
            flash('Question text and a valid correct option (a/b/c/d) are required.', 'danger')
        else:
            db.session.add(Quiz(
                module_id=mid,
                question_text=question_text,
                option_a=request.form.get('option_a', '').strip(),
                option_b=request.form.get('option_b', '').strip(),
                option_c=request.form.get('option_c', '').strip(),
                option_d=request.form.get('option_d', '').strip(),
                correct_option=correct,
                explanation=request.form.get('explanation', '').strip(),
                points=int(request.form.get('points', 20)),
            ))
            db.session.commit()
            flash('Question added.', 'success')
            return redirect(url_for('training_admin.module_questions', mid=mid))

    return render_template('admin/question_form.html', module=module)


@training_admin.route('/training/progress')
@login_required
@admin_required
def all_progress():
    """Standalone page for all user progress — used if accessed directly."""
    return redirect(url_for('training_admin.training_management') + '#progress')


@training_admin.route('/training/assign', methods=['POST'])
@login_required
@admin_required
def assign_training():
    user_ids   = request.form.getlist('user_ids', type=int)
    module_ids = request.form.getlist('module_ids', type=int)
    reason     = request.form.get('reason', 'manual')

    if not user_ids or not module_ids:
        flash('Select at least one user and one module.', 'danger')
        return redirect(url_for('training_admin.training_management'))

    count = 0
    for uid in user_ids:
        for mid in module_ids:
            existing = TrainingAssignment.query.filter_by(
                user_id=uid, module_id=mid).first()
            if not existing:
                db.session.add(TrainingAssignment(
                    user_id=uid,
                    module_id=mid,
                    assigned_by_id=current_user.id,
                    reason=reason,
                ))
                count += 1

    db.session.commit()
    flash(f'Assigned {count} new training task(s).', 'success')
    return redirect(url_for('training_admin.training_management'))
