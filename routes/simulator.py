import csv
import io
import threading
import uuid
from datetime import datetime, timezone

from flask import (Blueprint, render_template, request, redirect,
                   url_for, jsonify, flash, Response, abort, current_app)
from flask_login import login_required, current_user

from models import db, User
from models.simulator import AttackTemplate, Campaign, CampaignTarget
from routes.decorators import admin_required

simulator = Blueprint('simulator', __name__, url_prefix='/simulator')
tracking  = Blueprint('tracking',  __name__, url_prefix='/track')

ATTACK_TYPES = [
    {'id': 'phishing_email', 'label': 'Phishing Email', 'icon': 'fa-envelope',       'color': 'danger'},
    {'id': 'spear_phishing', 'label': 'Spear Phishing', 'icon': 'fa-crosshairs',     'color': 'danger'},
    {'id': 'smishing',       'label': 'SMS Phishing',   'icon': 'fa-mobile-screen',  'color': 'warning'},
    {'id': 'pretexting',     'label': 'Pretexting',     'icon': 'fa-user-secret',    'color': 'warning'},
    {'id': 'prize_lure',     'label': 'Prize Lure',     'icon': 'fa-gift',           'color': 'success'},
    {'id': 'it_support',     'label': 'IT Support',     'icon': 'fa-headset',        'color': 'info'},
]

_FAKE_PAGES = {
    'it_login':    'tracking/fake_it_login.html',
    'bank_login':  'tracking/fake_bank_login.html',
    'prize_claim': 'tracking/fake_prize.html',
}


# ── Campaign management ───────────────────────────────────────────────────────

@simulator.route('/')
@login_required
@admin_required
def index():
    campaigns = (Campaign.query
                 .filter_by(admin_id=current_user.id)
                 .order_by(Campaign.created_at.desc())
                 .all())

    total      = len(campaigns)
    active     = sum(1 for c in campaigns if c.status == 'active')
    avg_click  = round(sum(c.click_rate  for c in campaigns) / total, 1) if total else 0.0
    avg_report = round(sum(c.report_rate for c in campaigns) / total, 1) if total else 0.0

    return render_template('simulator/index.html',
                           campaigns=campaigns,
                           total=total, active=active,
                           avg_click=avg_click, avg_report=avg_report,
                           attack_types=ATTACK_TYPES)


@simulator.route('/campaigns/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_campaign():
    templates = (AttackTemplate.query
                 .filter_by(is_active=True)
                 .order_by(AttackTemplate.name).all())
    users = User.query.filter_by(is_active=True).order_by(User.name).all()

    if request.method == 'POST':
        name            = request.form.get('name', '').strip()
        description     = request.form.get('description', '').strip()
        attack_type     = request.form.get('attack_type', '')
        template_id     = request.form.get('template_id', type=int)
        target_user_ids = request.form.getlist('target_users')
        schedule_type   = request.form.get('schedule_type', 'draft')

        if not name or not attack_type:
            flash('Campaign name and attack type are required.', 'danger')
            return render_template('simulator/new_campaign.html',
                                   templates=templates, users=users,
                                   attack_types=ATTACK_TYPES)

        campaign = Campaign(
            name=name,
            description=description,
            attack_type=attack_type,
            template_id=template_id or None,
            admin_id=current_user.id,
            status='draft',
            target_count=len(target_user_ids),
        )
        db.session.add(campaign)
        db.session.flush()

        for uid in target_user_ids:
            db.session.add(CampaignTarget(
                campaign_id=campaign.id,
                user_id=int(uid),
                tracking_token=str(uuid.uuid4()),
            ))

        db.session.commit()
        flash(f'Campaign "{name}" created with {len(target_user_ids)} target(s).', 'success')

        if schedule_type == 'launch':
            campaign.status = 'active'
            campaign.launched_at = datetime.now(timezone.utc)
            db.session.commit()
            app = current_app._get_current_object()
            t = threading.Thread(target=_do_launch_bg, args=(app, campaign.id), daemon=True)
            t.start()
            flash('Campaign launched — emails are being sent in the background.', 'success')

        return redirect(url_for('simulator.campaign_detail', id=campaign.id))

    return render_template('simulator/new_campaign.html',
                           templates=templates, users=users,
                           attack_types=ATTACK_TYPES)


@simulator.route('/campaigns/<int:id>')
@login_required
@admin_required
def campaign_detail(id):
    campaign = Campaign.query.filter_by(
        id=id, admin_id=current_user.id).first_or_404()
    recent_targets = (campaign.targets
                      .order_by(CampaignTarget.clicked_at.desc())
                      .limit(10).all())
    return render_template('simulator/campaign_detail.html',
                           campaign=campaign, recent_targets=recent_targets,
                           attack_types=ATTACK_TYPES)


@simulator.route('/campaigns/<int:id>/launch', methods=['POST'])
@login_required
@admin_required
def launch_campaign(id):
    campaign = Campaign.query.filter_by(
        id=id, admin_id=current_user.id).first_or_404()

    if campaign.status not in ('draft', 'scheduled'):
        return jsonify({'error': 'Campaign already launched.'}), 400

    campaign.status = 'active'
    campaign.launched_at = datetime.now(timezone.utc)
    db.session.commit()
    app = current_app._get_current_object()
    threading.Thread(target=_do_launch_bg, args=(app, campaign.id), daemon=True).start()
    return jsonify({'ok': True, 'sent': 0, 'message': 'Emails sending in background'})


def _do_launch_bg(app, campaign_id):
    """Send campaign emails in a background thread (non-blocking)."""
    from routes.email_service import send_campaign_email
    with app.app_context():
        from models.simulator import Campaign, CampaignTarget
        from models import db
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return
        for target in campaign.targets.filter_by(email_sent=False).all():
            try:
                send_campaign_email(target, campaign)
            except Exception:
                pass
        campaign.emails_sent = campaign.targets.filter_by(email_sent=True).count()
        db.session.commit()


def _do_launch(campaign):
    """Mark all targets as sent, update campaign status. Tries real email first."""
    from routes.email_service import send_campaign_email
    now = datetime.now(timezone.utc)
    sent = 0
    for target in campaign.targets.filter_by(email_sent=False).all():
        send_campaign_email(target, campaign)
        sent += 1

    campaign.emails_sent = campaign.targets.filter_by(email_sent=True).count()
    campaign.status      = 'active'
    campaign.launched_at = now


@simulator.route('/campaigns/<int:id>/complete', methods=['POST'])
@login_required
@admin_required
def complete_campaign(id):
    campaign = Campaign.query.filter_by(
        id=id, admin_id=current_user.id).first_or_404()
    campaign.status       = 'completed'
    campaign.completed_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({'ok': True})


@simulator.route('/campaigns/<int:id>/results')
@login_required
@admin_required
def campaign_results(id):
    campaign = Campaign.query.filter_by(
        id=id, admin_id=current_user.id).first_or_404()
    targets  = campaign.targets.order_by(CampaignTarget.email_sent_at.desc()).all()

    total              = len(targets)
    clicked_count      = sum(1 for t in targets if t.link_clicked)
    credentials_count  = sum(1 for t in targets if t.credentials_entered)
    reported_count     = sum(1 for t in targets if t.reported_suspicious)
    safe_count         = sum(1 for t in targets if not t.link_clicked and not t.reported_suspicious)

    return render_template('simulator/results.html',
                           campaign=campaign,
                           targets=targets,
                           total=total,
                           clicked_count=clicked_count,
                           credentials_count=credentials_count,
                           reported_count=reported_count,
                           safe_count=safe_count)


@simulator.route('/campaigns/<int:id>/export')
@login_required
@admin_required
def export_results(id):
    campaign = Campaign.query.filter_by(
        id=id, admin_id=current_user.id).first_or_404()

    def generate():
        buf    = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['name', 'email', 'email_sent', 'link_clicked',
                         'credentials_entered', 'reported_suspicious',
                         'time_to_click', 'outcome', 'click_ip'])
        yield buf.getvalue(); buf.seek(0); buf.truncate()
        for t in campaign.targets.all():
            writer.writerow([
                t.user.name, t.user.email,
                'Yes' if t.email_sent else 'No',
                'Yes' if t.link_clicked else 'No',
                'Yes' if t.credentials_entered else 'No',
                'Yes' if t.reported_suspicious else 'No',
                t.time_to_click, t.outcome, t.click_ip or '',
            ])
            yield buf.getvalue(); buf.seek(0); buf.truncate()

    fname = f'campaign_{id}_results.csv'
    return Response(generate(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={fname}'})


@simulator.route('/campaigns/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_campaign(id):
    campaign = Campaign.query.filter_by(
        id=id, admin_id=current_user.id).first_or_404()
    if campaign.status == 'active':
        return jsonify({'error': 'Cannot delete an active campaign.'}), 400
    db.session.delete(campaign)
    db.session.commit()
    return jsonify({'ok': True})


# ── Template management ───────────────────────────────────────────────────────

@simulator.route('/templates')
@login_required
@admin_required
def templates():
    all_templates = (AttackTemplate.query
                     .order_by(AttackTemplate.attack_type, AttackTemplate.name)
                     .all())
    return render_template('simulator/templates.html',
                           templates=all_templates, attack_types=ATTACK_TYPES)


@simulator.route('/templates/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_template():
    if request.method == 'POST':
        name             = request.form.get('name', '').strip()
        attack_type      = request.form.get('attack_type', '')
        subject          = request.form.get('subject', '').strip()
        preview_text     = request.form.get('preview_text', '').strip()
        body_html        = request.form.get('body_html', '')
        fake_page_type   = request.form.get('fake_page_type', 'it_login')
        description      = request.form.get('description', '').strip()
        difficulty_level = int(request.form.get('difficulty_level', 3))

        if not name or not attack_type or not subject or not body_html:
            flash('Name, attack type, subject and email body are required.', 'danger')
            return render_template('simulator/template_form.html',
                                   attack_types=ATTACK_TYPES, mode='new')

        tmpl = AttackTemplate(
            name=name, attack_type=attack_type, subject=subject,
            preview_text=preview_text, body_html=body_html,
            fake_page_type=fake_page_type, description=description,
            difficulty_level=difficulty_level, created_by=current_user.id,
        )
        db.session.add(tmpl)
        db.session.commit()
        flash(f'Template "{name}" created.', 'success')
        return redirect(url_for('simulator.templates'))

    return render_template('simulator/template_form.html',
                           attack_types=ATTACK_TYPES, mode='new')


@simulator.route('/templates/<int:tid>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_template(tid):
    tmpl = AttackTemplate.query.get_or_404(tid)

    if request.method == 'POST':
        tmpl.name             = request.form.get('name', tmpl.name).strip()
        tmpl.attack_type      = request.form.get('attack_type', tmpl.attack_type)
        tmpl.subject          = request.form.get('subject', tmpl.subject).strip()
        tmpl.preview_text     = request.form.get('preview_text', '').strip()
        tmpl.body_html        = request.form.get('body_html', tmpl.body_html)
        tmpl.fake_page_type   = request.form.get('fake_page_type', tmpl.fake_page_type)
        tmpl.description      = request.form.get('description', '').strip()
        tmpl.difficulty_level = int(request.form.get('difficulty_level', tmpl.difficulty_level))
        db.session.commit()
        flash('Template updated.', 'success')
        return redirect(url_for('simulator.templates'))

    return render_template('simulator/template_form.html',
                           tmpl=tmpl, attack_types=ATTACK_TYPES, mode='edit')


@simulator.route('/templates/<int:tid>/preview')
@login_required
@admin_required
def preview_template(tid):
    tmpl = AttackTemplate.query.get_or_404(tid)
    return render_template('simulator/template_preview.html', tmpl=tmpl)


@simulator.route('/templates/<int:tid>/preview-email')
def preview_template_email(tid):
    """Serves the rendered email HTML directly — loaded into the preview iframe via src=."""
    from flask import make_response
    tmpl = AttackTemplate.query.get_or_404(tid)
    html = tmpl.body_html or '<p style="padding:20px;color:#666;">No email body defined.</p>'
    now_str = datetime.now(timezone.utc).strftime('%d %B %Y')
    for src, dst in [
        ('{{user_name}}',     'John Adeyemi'),
        ('{{user_email}}',    'j.adeyemi@futminna.edu.ng'),
        ('{{date}}',          now_str),
        ('{{tracking_link}}', '#'),
        ('{{report_link}}',   '#'),
        ('{user_name}',       'John Adeyemi'),
        ('{user_email}',      'j.adeyemi@futminna.edu.ng'),
        ('{date}',            now_str),
        ('{tracking_link}',   '#'),
        ('{report_link}',     '#'),
    ]:
        html = html.replace(src, dst)
    # Disable all links and form submissions in the preview
    block = '<style>a,a *,form,button{pointer-events:none!important;cursor:default!important;}</style>'
    resp = make_response(html + block)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@simulator.route('/templates/<int:tid>/json')
@login_required
@admin_required
def template_json(tid):
    from flask import jsonify
    tmpl = AttackTemplate.query.get_or_404(tid)
    fake_page_labels = {'it_login': 'IT Portal', 'bank_login': 'Bank Login', 'prize_claim': 'Prize Claim'}
    return jsonify({
        'id':               tmpl.id,
        'name':             tmpl.name,
        'attack_type_label': tmpl.attack_type_label,
        'attack_type_color': tmpl.attack_type_color,
        'attack_type_icon':  tmpl.attack_type_icon,
        'difficulty_stars':  tmpl.difficulty_stars,
        'difficulty_level':  tmpl.difficulty_level,
        'fake_page':         fake_page_labels.get(tmpl.fake_page_type, tmpl.fake_page_type),
        'subject':           tmpl.subject,
        'preview_text':      tmpl.preview_text or '',
        'description':       tmpl.description or '',
        'body_html':         tmpl.body_html,
        'created_at':        tmpl.created_at.strftime('%d %b %Y'),
    })


@simulator.route('/templates/<int:tid>', methods=['DELETE'])
@login_required
@admin_required
def delete_template(tid):
    tmpl = AttackTemplate.query.get_or_404(tid)
    db.session.delete(tmpl)
    db.session.commit()
    return jsonify({'ok': True})


# ── Tracking routes (PUBLIC — no login required) ──────────────────────────────

@tracking.route('/<token>')
def click(token):
    target   = CampaignTarget.query.filter_by(tracking_token=token).first_or_404()
    campaign = target.campaign

    if not target.link_clicked:
        target.link_clicked = True
        target.clicked_at   = datetime.now(timezone.utc)
        target.click_ip     = request.headers.get('X-Forwarded-For',
                                                    request.remote_addr)
        campaign.links_clicked += 1
        # Auto-assign phishing awareness module when link is clicked
        try:
            from routes.badge_service import auto_assign_training
            auto_assign_training(target.user_id, reason='campaign_click',
                                 campaign_id=campaign.id)
        except Exception:
            pass
        db.session.commit()

    fake_page_type = (campaign.template.fake_page_type
                      if campaign.template else 'it_login')
    page = _FAKE_PAGES.get(fake_page_type, 'tracking/fake_it_login.html')
    return render_template(page, token=token)


@tracking.route('/<token>/submit', methods=['POST'])
def submit_credentials(token):
    target   = CampaignTarget.query.filter_by(tracking_token=token).first_or_404()
    campaign = target.campaign

    if not target.credentials_entered:
        target.credentials_entered = True
        target.credential_at       = datetime.now(timezone.utc)
        target.training_assigned   = True
        campaign.credentials_entered += 1
        # Auto-assign ALL training modules when credentials are entered
        try:
            from routes.badge_service import auto_assign_training
            auto_assign_training(target.user_id, reason='credential_entry',
                                 campaign_id=campaign.id, assign_all=True)
        except Exception:
            pass
        db.session.commit()

    return render_template('tracking/simulation_reveal.html',
                           token=token, campaign=campaign)


@tracking.route('/<token>/report')
def report_suspicious(token):
    target   = CampaignTarget.query.filter_by(tracking_token=token).first_or_404()
    campaign = target.campaign

    if not target.reported_suspicious:
        target.reported_suspicious = True
        target.reported_at         = datetime.now(timezone.utc)
        campaign.reports_submitted += 1
        db.session.commit()
        # Award vigilant_defender badge for reporting
        try:
            from routes.badge_service import BadgeService
            BadgeService.award_vigilant_defender(target.user_id)
        except Exception:
            pass

    return render_template('tracking/good_catch.html',
                           token=token, campaign=campaign, user=target.user)
