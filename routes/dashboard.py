import json
from datetime import datetime, timezone, timedelta

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func

from models import (
    db, User, UserSession, ScanResult, Campaign, CampaignTarget,
    TrainingModule, UserProgress, UserBadge, TrainingAssignment,
    Notification,
)
from routes.decorators import admin_required

# ---------------------------------------------------------------------------
# Blueprint: dashboard  (existing — personal scan dashboard)
# ---------------------------------------------------------------------------

dashboard = Blueprint('dashboard', __name__, url_prefix='/dashboard')


@dashboard.route('/')
@login_required
def index():
    uid = current_user.id

    total_scans      = ScanResult.query.filter_by(user_id=uid).count()
    dangerous_count  = ScanResult.query.filter_by(user_id=uid, final_label='Dangerous').count()
    suspicious_count = ScanResult.query.filter_by(user_id=uid, final_label='Suspicious').count()
    safe_count       = ScanResult.query.filter_by(user_id=uid, final_label='Safe').count()

    recent_scans = (ScanResult.query.filter_by(user_id=uid)
                    .order_by(ScanResult.scanned_at.desc())
                    .limit(5).all())

    today = datetime.now(timezone.utc).date()
    days  = [(today - timedelta(days=i)) for i in range(13, -1, -1)]

    day_counts = dict(
        db.session.query(
            func.date(ScanResult.scanned_at),
            func.count(ScanResult.id)
        )
        .filter(
            ScanResult.user_id == uid,
            ScanResult.scanned_at >= datetime.now(timezone.utc) - timedelta(days=14)
        )
        .group_by(func.date(ScanResult.scanned_at))
        .all()
    )

    chart_labels = json.dumps([d.strftime('%d %b') for d in days])
    chart_data   = json.dumps([day_counts.get(str(d), 0) for d in days])
    donut_data   = json.dumps([safe_count, suspicious_count, dangerous_count])

    risk_score = current_user.risk_score or 0.0
    risk_color = 'danger' if risk_score >= 70 else ('warning' if risk_score >= 40 else 'success')

    return render_template('dashboard/index.html',
        total_scans=total_scans, dangerous_count=dangerous_count,
        suspicious_count=suspicious_count, safe_count=safe_count,
        recent_scans=recent_scans, chart_labels=chart_labels,
        chart_data=chart_data, donut_data=donut_data,
        risk_score=risk_score, risk_color=risk_color)


# ---------------------------------------------------------------------------
# Blueprint: admin_dash  (admin overview dashboard)
# ---------------------------------------------------------------------------

admin_dash = Blueprint('admin_dash', __name__, url_prefix='/admin')


@admin_dash.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_users  = User.query.count()
    total_scans  = ScanResult.query.count()
    phishing_detected = ScanResult.query.filter(
        ScanResult.final_label.in_(['Suspicious', 'Dangerous'])
    ).count()
    total_campaigns = Campaign.query.count()

    campaigns_with_sends = Campaign.query.filter(Campaign.emails_sent > 0).all()
    avg_click_rate = (
        round(sum(c.click_rate for c in campaigns_with_sends) / len(campaigns_with_sends), 1)
        if campaigns_with_sends else 0.0
    )

    active_users = User.query.filter_by(is_active=True, role='user').count()
    users_with_pass = (
        db.session.query(func.count(func.distinct(UserProgress.user_id)))
        .filter(UserProgress.quiz_passed == True)  # noqa: E712
        .scalar() or 0
    )
    training_completion_rate = (
        round(users_with_pass / active_users * 100, 1) if active_users else 0.0
    )

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = ScanResult.query.filter(ScanResult.scanned_at >= today_start).count()

    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    new_users_this_week = User.query.filter(User.created_at >= week_ago).count()

    return render_template('admin/dashboard.html',
        total_users=total_users,
        total_scans=total_scans,
        phishing_detected=phishing_detected,
        total_campaigns=total_campaigns,
        avg_click_rate=avg_click_rate,
        training_completion_rate=training_completion_rate,
        scans_today=scans_today,
        new_users_this_week=new_users_this_week,
    )


# ---------------------------------------------------------------------------
# Blueprint: api_stats  (JSON endpoints for charts & stats)
# ---------------------------------------------------------------------------

api_stats = Blueprint('api_stats', __name__, url_prefix='/api')


# -- helper shared by admin_dashboard and stats_overview -------------------
def _compute_overview():
    total_users  = User.query.count()
    total_scans  = ScanResult.query.count()
    phishing_detected = ScanResult.query.filter(
        ScanResult.final_label.in_(['Suspicious', 'Dangerous'])
    ).count()
    total_campaigns = Campaign.query.count()

    campaigns_with_sends = Campaign.query.filter(Campaign.emails_sent > 0).all()
    avg_click_rate = (
        round(sum(c.click_rate for c in campaigns_with_sends) / len(campaigns_with_sends), 1)
        if campaigns_with_sends else 0.0
    )

    active_users = User.query.filter_by(is_active=True, role='user').count()
    users_with_pass = (
        db.session.query(func.count(func.distinct(UserProgress.user_id)))
        .filter(UserProgress.quiz_passed == True)  # noqa: E712
        .scalar() or 0
    )
    training_completion_rate = (
        round(users_with_pass / active_users * 100, 1) if active_users else 0.0
    )

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = ScanResult.query.filter(ScanResult.scanned_at >= today_start).count()

    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    new_users_this_week = User.query.filter(User.created_at >= week_ago).count()

    return {
        'total_users': total_users,
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'total_campaigns': total_campaigns,
        'avg_click_rate': avg_click_rate,
        'training_completion_rate': training_completion_rate,
        'scans_today': scans_today,
        'new_users_this_week': new_users_this_week,
    }


@api_stats.route('/stats/overview')
@login_required
@admin_required
def stats_overview():
    return jsonify(_compute_overview())


@api_stats.route('/stats/scans-over-time')
@login_required
@admin_required
def scans_over_time():
    today  = datetime.now(timezone.utc).date()
    days   = [(today - timedelta(days=i)) for i in range(29, -1, -1)]
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    counts = dict(
        db.session.query(
            func.date(ScanResult.scanned_at),
            func.count(ScanResult.id)
        )
        .filter(ScanResult.scanned_at >= cutoff)
        .group_by(func.date(ScanResult.scanned_at))
        .all()
    )
    return jsonify([{'date': str(d), 'count': counts.get(str(d), 0)} for d in days])


@api_stats.route('/stats/risk-distribution')
@login_required
@admin_required
def risk_distribution():
    safe       = ScanResult.query.filter_by(final_label='Safe').count()
    suspicious = ScanResult.query.filter_by(final_label='Suspicious').count()
    dangerous  = ScanResult.query.filter_by(final_label='Dangerous').count()
    return jsonify({'safe': safe, 'suspicious': suspicious, 'dangerous': dangerous})


@api_stats.route('/stats/attack-types')
@login_required
@admin_required
def attack_types():
    rows = (
        db.session.query(Campaign.attack_type, func.count(Campaign.id))
        .group_by(Campaign.attack_type)
        .all()
    )
    return jsonify([{'type': r[0], 'count': r[1]} for r in rows])


@api_stats.route('/stats/training-completion')
@login_required
@admin_required
def training_completion():
    modules     = (TrainingModule.query.filter_by(is_active=True)
                   .order_by(TrainingModule.order_index).all())
    total_users = User.query.filter_by(is_active=True, role='user').count()
    result = []
    for m in modules:
        passed      = UserProgress.query.filter_by(module_id=m.id, quiz_passed=True).count()
        failed      = UserProgress.query.filter_by(module_id=m.id, status='failed').count()
        in_progress = UserProgress.query.filter_by(module_id=m.id, status='in_progress').count()
        not_started = max(0, total_users - passed - failed - in_progress)
        result.append({
            'module': m.title,
            'passed': passed,
            'failed': failed,
            'not_started': not_started,
        })
    return jsonify(result)


@api_stats.route('/stats/campaign-performance')
@login_required
@admin_required
def campaign_performance():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(8).all()
    return jsonify([{
        'name': c.name[:30],
        'click_rate': c.click_rate,
        'report_rate': c.report_rate,
        'credential_rate': c.credential_rate,
    } for c in campaigns])


@api_stats.route('/stats/user-risk-ranking')
@login_required
@admin_required
def user_risk_ranking():
    users = (User.query.filter_by(is_active=True)
             .order_by(User.risk_score.desc()).limit(10).all())
    result = []
    total_modules = TrainingModule.query.filter_by(is_active=True).count()
    for u in users:
        total_targets = CampaignTarget.query.filter_by(user_id=u.id).count()
        clicked       = CampaignTarget.query.filter_by(user_id=u.id, link_clicked=True).count()
        click_rate    = round(clicked / total_targets * 100, 1) if total_targets else 0.0

        passed_modules    = UserProgress.query.filter_by(user_id=u.id, quiz_passed=True).count()
        training_complete = total_modules > 0 and passed_modules >= total_modules

        risk       = u.risk_score or 0.0
        risk_level = 'High' if risk >= 70 else ('Medium' if risk >= 40 else 'Low')

        result.append({
            'name': u.name,
            'email': u.email,
            'risk_score': risk,
            'click_rate': click_rate,
            'training_complete': training_complete,
            'risk_level': risk_level,
        })
    return jsonify(result)


@api_stats.route('/stats/recent-activity')
@login_required
@admin_required
def recent_activity():
    events = []

    # Recent scans
    scans = (
        ScanResult.query
        .join(User, ScanResult.user_id == User.id)
        .add_columns(User.name)
        .order_by(ScanResult.scanned_at.desc())
        .limit(10).all()
    )
    for scan, uname in scans:
        try:
            from urllib.parse import urlparse
            host = urlparse(scan.url).netloc[:40] or scan.url[:40]
        except Exception:
            host = scan.url[:40]
        events.append({
            'type': 'scan', 'icon': 'fa-link', 'color': 'orange',
            'description': f'Scanned {host}',
            'user': uname,
            'timestamp': scan.scanned_at.isoformat(),
        })

    # Recent link clicks
    clicks = (
        CampaignTarget.query.filter_by(link_clicked=True)
        .join(User, CampaignTarget.user_id == User.id)
        .add_columns(User.name)
        .order_by(CampaignTarget.clicked_at.desc())
        .limit(5).all()
    )
    for ct, uname in clicks:
        if ct.clicked_at:
            events.append({
                'type': 'click', 'icon': 'fa-computer-mouse', 'color': 'warning',
                'description': 'Clicked a simulation phishing link',
                'user': uname,
                'timestamp': ct.clicked_at.isoformat(),
            })

    # Recent credential submissions
    creds = (
        CampaignTarget.query.filter_by(credentials_entered=True)
        .join(User, CampaignTarget.user_id == User.id)
        .add_columns(User.name)
        .order_by(CampaignTarget.credential_at.desc())
        .limit(5).all()
    )
    for ct, uname in creds:
        if ct.credential_at:
            events.append({
                'type': 'credential', 'icon': 'fa-skull-crossbones', 'color': 'danger',
                'description': 'Entered credentials on a fake page',
                'user': uname,
                'timestamp': ct.credential_at.isoformat(),
            })

    # Recent phishing reports
    reports = (
        CampaignTarget.query.filter_by(reported_suspicious=True)
        .join(User, CampaignTarget.user_id == User.id)
        .add_columns(User.name)
        .order_by(CampaignTarget.reported_at.desc())
        .limit(5).all()
    )
    for ct, uname in reports:
        if ct.reported_at:
            events.append({
                'type': 'report', 'icon': 'fa-shield-check', 'color': 'success',
                'description': 'Reported a phishing simulation',
                'user': uname,
                'timestamp': ct.reported_at.isoformat(),
            })

    # Recent training completions
    passed = (
        UserProgress.query.filter_by(status='passed')
        .join(User, UserProgress.user_id == User.id)
        .join(TrainingModule, UserProgress.module_id == TrainingModule.id)
        .add_columns(User.name, TrainingModule.title)
        .order_by(UserProgress.completed_at.desc())
        .limit(8).all()
    )
    for prog, uname, title in passed:
        if prog.completed_at:
            events.append({
                'type': 'training', 'icon': 'fa-graduation-cap', 'color': 'info',
                'description': f'Passed "{title}" quiz',
                'user': uname,
                'timestamp': prog.completed_at.isoformat(),
            })

    # Recent badge awards
    badges = (
        UserBadge.query
        .join(User, UserBadge.user_id == User.id)
        .add_columns(User.name)
        .order_by(UserBadge.earned_at.desc())
        .limit(5).all()
    )
    for badge, uname in badges:
        events.append({
            'type': 'badge', 'icon': 'fa-trophy', 'color': 'warning',
            'description': f'Earned "{badge.badge_name}" badge',
            'user': uname,
            'timestamp': badge.earned_at.isoformat(),
        })

    events.sort(key=lambda e: e['timestamp'], reverse=True)
    return jsonify(events[:20])


@api_stats.route('/my-stats')
@login_required
def my_stats():
    uid = current_user.id

    my_scans     = ScanResult.query.filter_by(user_id=uid).count()
    phishing_found = ScanResult.query.filter(
        ScanResult.user_id == uid,
        ScanResult.final_label.in_(['Suspicious', 'Dangerous'])
    ).count()
    risk_score   = current_user.risk_score or 0.0
    total_modules = TrainingModule.query.filter_by(is_active=True).count()
    passed_modules = UserProgress.query.filter_by(user_id=uid, quiz_passed=True).count()
    training_percent = round(passed_modules / total_modules * 100) if total_modules else 0
    badges_count = UserBadge.query.filter_by(user_id=uid).count()
    mandatory_pending = TrainingAssignment.query.filter_by(user_id=uid, completed=False).count()

    return jsonify({
        'my_scans': my_scans,
        'phishing_found': phishing_found,
        'risk_score': risk_score,
        'training_percent': training_percent,
        'badges_count': badges_count,
        'mandatory_pending': mandatory_pending,
    })


@api_stats.route('/my-scans-chart')
@login_required
def my_scans_chart():
    uid    = current_user.id
    today  = datetime.now(timezone.utc).date()
    days   = [(today - timedelta(days=i)) for i in range(29, -1, -1)]
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    counts = dict(
        db.session.query(
            func.date(ScanResult.scanned_at),
            func.count(ScanResult.id)
        )
        .filter(ScanResult.user_id == uid, ScanResult.scanned_at >= cutoff)
        .group_by(func.date(ScanResult.scanned_at))
        .all()
    )
    return jsonify([{'date': str(d), 'count': counts.get(str(d), 0)} for d in days])


# ---------------------------------------------------------------------------
# Blueprint: user_dash  (personal user dashboard page)
# ---------------------------------------------------------------------------

user_dash = Blueprint('user_dash', __name__, url_prefix='/user')


@user_dash.route('/dashboard')
@login_required
def user_dashboard():
    uid = current_user.id

    risk_score = current_user.risk_score or 0.0
    risk_color = 'danger' if risk_score >= 70 else ('warning' if risk_score >= 40 else 'success')

    my_scans = ScanResult.query.filter_by(user_id=uid).count()

    total_modules = TrainingModule.query.filter_by(is_active=True).count()

    modules = (TrainingModule.query.filter_by(is_active=True)
               .order_by(TrainingModule.order_index).all())
    module_data = []
    for m in modules:
        prog = UserProgress.query.filter_by(user_id=uid, module_id=m.id).first()
        module_data.append({'module': m, 'progress': prog})

    passed_count = sum(1 for md in module_data if md['progress'] and md['progress'].quiz_passed)
    training_percent = round(passed_count / total_modules * 100) if total_modules else 0

    badges = (UserBadge.query.filter_by(user_id=uid)
              .order_by(UserBadge.earned_at.desc()).all())

    recent_scans = (ScanResult.query.filter_by(user_id=uid)
                    .order_by(ScanResult.scanned_at.desc()).limit(5).all())

    mandatory_pending = TrainingAssignment.query.filter_by(user_id=uid, completed=False).count()

    return render_template('user/dashboard.html',
        risk_score=risk_score, risk_color=risk_color,
        my_scans=my_scans, total_modules=total_modules,
        module_data=module_data, passed_count=passed_count,
        training_percent=training_percent, badges=badges,
        recent_scans=recent_scans, mandatory_pending=mandatory_pending,
    )


# ---------------------------------------------------------------------------
# Notification API routes  (/api/notifications/...)
# ---------------------------------------------------------------------------

@api_stats.route('/notifications')
@login_required
def get_notifications():
    notifs = (Notification.query
              .filter_by(user_id=current_user.id)
              .order_by(Notification.created_at.desc())
              .limit(20).all())
    return jsonify([n.to_dict() for n in notifs])


@api_stats.route('/notifications/<int:nid>/read', methods=['POST'])
@login_required
def mark_notification_read(nid):
    n = Notification.query.filter_by(id=nid, user_id=current_user.id).first()
    if n:
        n.is_read = True
        db.session.commit()
    return jsonify({'ok': True})


@api_stats.route('/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'ok': True})


