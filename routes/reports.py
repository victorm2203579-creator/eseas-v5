import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, render_template, Response, flash, redirect, url_for
from flask_login import login_required, current_user

from models import (
    db, User, ScanResult, Campaign, CampaignTarget,
    TrainingModule, UserProgress, UserBadge, TrainingAssignment
)
from routes.decorators import admin_required
from extensions import limiter

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

reports = Blueprint('reports', __name__, url_prefix='/reports')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _avg_click_rate():
    """Return average click rate (%) across campaigns that have sent emails."""
    campaigns = Campaign.query.filter(Campaign.emails_sent > 0).all()
    if not campaigns:
        return 0.0
    return round(sum(c.click_rate for c in campaigns) / len(campaigns), 1)


def _users_completed_all():
    """Return the count of active users who have passed every active module."""
    active_modules = TrainingModule.query.filter_by(is_active=True).all()
    if not active_modules:
        return 0
    module_ids = {m.id for m in active_modules}
    active_users = User.query.filter_by(is_active=True).all()
    count = 0
    for user in active_users:
        passed_ids = {
            p.module_id
            for p in UserProgress.query.filter_by(
                user_id=user.id, quiz_passed=True
            ).all()
            if p.module_id in module_ids
        }
        if passed_ids >= module_ids:
            count += 1
    return count


def _training_completion_rate(active_user_count):
    """Return % of active users who passed at least one module."""
    if not active_user_count:
        return 0.0
    users_with_pass = (
        db.session.query(UserProgress.user_id)
        .filter_by(quiz_passed=True)
        .distinct()
        .count()
    )
    return round(users_with_pass / active_user_count * 100, 1)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@reports.route('/')
@login_required
@admin_required
def index():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_scans = ScanResult.query.count()
    dangerous_count = ScanResult.query.filter_by(final_label='Dangerous').count()
    suspicious_count = ScanResult.query.filter_by(final_label='Suspicious').count()
    safe_count = ScanResult.query.filter_by(final_label='Safe').count()

    detection_rate = (
        round((dangerous_count + suspicious_count) / total_scans * 100, 1)
        if total_scans else 0.0
    )

    total_campaigns = Campaign.query.count()
    avg_click_rate = _avg_click_rate()
    total_badges_awarded = UserBadge.query.count()
    active_modules = TrainingModule.query.filter_by(is_active=True).count()
    users_completed_all = _users_completed_all()

    return render_template(
        'reports/index.html',
        total_users=total_users,
        active_users=active_users,
        total_scans=total_scans,
        dangerous_count=dangerous_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        detection_rate=detection_rate,
        total_campaigns=total_campaigns,
        avg_click_rate=avg_click_rate,
        total_badges_awarded=total_badges_awarded,
        active_modules=active_modules,
        users_completed_all=users_completed_all,
    )


# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------

@reports.route('/export/scans/csv')
@login_required
@admin_required
@limiter.limit('5 per minute; 20 per hour')  # Threat 10: Rate limit expensive export
def export_scans_csv():
    scans = (
        db.session.query(ScanResult, User.name)
        .join(User, ScanResult.user_id == User.id)
        .order_by(ScanResult.scanned_at.desc())
        .all()
    )

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            'URL', 'Risk Score', 'Label', 'ML Score',
            'VT Detections', 'Scanned By', 'Date'
        ])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for scan, user_name in scans:
            writer.writerow([
                scan.url,
                scan.final_score,
                scan.final_label,
                scan.ml_score,
                f"{scan.vt_detections}/{scan.vt_total_engines}"
                    if scan.vt_total_engines else scan.vt_detections,
                user_name,
                scan.scanned_at.strftime('%Y-%m-%d %H:%M:%S')
                    if scan.scanned_at else '',
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return Response(
        generate(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=eseas_scans.csv'},
    )


@reports.route('/export/campaigns/csv')
@login_required
@admin_required
@limiter.limit('5 per minute; 20 per hour')  # Threat 10: Rate limit expensive export
def export_campaigns_csv():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            'Campaign Name', 'Attack Type', 'Status', 'Targets',
            'Emails Sent', 'Click Rate%', 'Credential Rate%',
            'Report Rate%', 'Created Date'
        ])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for c in campaigns:
            writer.writerow([
                c.name,
                c.attack_type_label,
                c.status,
                c.target_count,
                c.emails_sent,
                round(c.click_rate, 1),
                round(c.credential_rate, 1),
                round(c.report_rate, 1),
                c.created_at.strftime('%Y-%m-%d') if c.created_at else '',
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return Response(
        generate(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=eseas_campaigns.csv'},
    )


@reports.route('/export/users/csv')
@login_required
@admin_required
@limiter.limit('5 per minute; 20 per hour')  # Threat 10: Rate limit expensive export
def export_users_csv():
    users = User.query.order_by(User.created_at.desc()).all()

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            'Name', 'Email', 'Role', 'Risk Score',
            'Total Scans', 'Registered Date', 'Is Active'
        ])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for u in users:
            total_scans = ScanResult.query.filter_by(user_id=u.id).count()
            writer.writerow([
                u.name,
                u.email,
                u.role,
                u.risk_score,
                total_scans,
                u.created_at.strftime('%Y-%m-%d') if u.created_at else '',
                'Yes' if u.is_active else 'No',
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return Response(
        generate(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=eseas_users.csv'},
    )


@reports.route('/export/training/csv')
@login_required
@admin_required
@limiter.limit('5 per minute; 20 per hour')  # Threat 10: Rate limit expensive export
def export_training_csv():
    rows = (
        db.session.query(UserProgress, User, TrainingModule)
        .join(User, UserProgress.user_id == User.id)
        .join(TrainingModule, UserProgress.module_id == TrainingModule.id)
        .order_by(User.name, TrainingModule.order_index)
        .all()
    )

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            'User Name', 'User Email', 'Module Title',
            'Status', 'Quiz Score', 'Completed Date'
        ])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for progress, user, module in rows:
            writer.writerow([
                user.name,
                user.email,
                module.title,
                progress.status,
                progress.quiz_score if progress.quiz_score is not None else '',
                progress.completed_at.strftime('%Y-%m-%d')
                    if progress.completed_at else '',
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return Response(
        generate(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=eseas_training.csv'},
    )


# ---------------------------------------------------------------------------
# Full PDF report
# ---------------------------------------------------------------------------

@reports.route('/full/pdf')
@login_required
@admin_required
@limiter.limit('5 per minute; 20 per hour')  # Threat 10: Rate limit expensive export
def export_full_pdf():
    if not REPORTLAB_OK:
        flash(
            'ReportLab is not installed. Run: pip install reportlab',
            'danger'
        )
        return redirect(url_for('reports.index'))

    # ---- Gather all data ------------------------------------------------
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_scans = ScanResult.query.count()
    dangerous_count = ScanResult.query.filter_by(final_label='Dangerous').count()
    suspicious_count = ScanResult.query.filter_by(final_label='Suspicious').count()
    safe_count = ScanResult.query.filter_by(final_label='Safe').count()
    phishing_detected = dangerous_count + suspicious_count

    total_campaigns = Campaign.query.count()
    avg_click_rate = _avg_click_rate()
    total_badges_awarded = UserBadge.query.count()

    training_completion_rate = _training_completion_rate(active_users)

    all_campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()

    top_risk_scans = (
        db.session.query(ScanResult, User.name)
        .join(User, ScanResult.user_id == User.id)
        .order_by(ScanResult.final_score.desc())
        .limit(10)
        .all()
    )

    top_vulnerable_users = (
        User.query.filter_by(is_active=True)
        .order_by(User.risk_score.desc())
        .limit(5)
        .all()
    )

    active_modules = TrainingModule.query.filter_by(is_active=True).order_by(
        TrainingModule.order_index
    ).all()

    # Per-module stats
    module_stats = []
    for mod in active_modules:
        all_progress = UserProgress.query.filter_by(module_id=mod.id).all()
        passed = sum(1 for p in all_progress if p.quiz_passed)
        failed = sum(1 for p in all_progress if p.status == 'completed' and not p.quiz_passed)
        not_started = active_users - len(all_progress)
        total_attempted = len(all_progress)
        pass_rate = round(passed / total_attempted * 100, 1) if total_attempted else 0.0
        module_stats.append({
            'title': mod.title,
            'passed': passed,
            'failed': failed,
            'not_started': max(not_started, 0),
            'pass_rate': pass_rate,
        })

    # Users who completed all modules
    all_completers = []
    if active_modules:
        module_ids = {m.id for m in active_modules}
        for user in User.query.filter_by(is_active=True).all():
            passed_ids = {
                p.module_id
                for p in UserProgress.query.filter_by(
                    user_id=user.id, quiz_passed=True
                ).all()
                if p.module_id in module_ids
            }
            if passed_ids >= module_ids:
                all_completers.append(user.name)

    # ---- PDF styles -------------------------------------------------------
    NAVY = colors.HexColor('#0a1628')
    ORANGE = colors.HexColor('#ff6b35')
    LIGHT_GREY = colors.HexColor('#f5f5f5')
    WHITE = colors.white

    styles = getSampleStyleSheet()

    style_cover_title = ParagraphStyle(
        'CoverTitle',
        parent=styles['Title'],
        fontSize=28,
        textColor=NAVY,
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
    )
    style_cover_subtitle = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontSize=16,
        textColor=ORANGE,
        spaceAfter=8,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
    )
    style_cover_body = ParagraphStyle(
        'CoverBody',
        parent=styles['Normal'],
        fontSize=12,
        textColor=NAVY,
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica',
    )
    style_section = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=NAVY,
        spaceAfter=10,
        spaceBefore=6,
        fontName='Helvetica-Bold',
    )
    style_body = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.black,
        spaceAfter=6,
        leading=14,
        fontName='Helvetica',
    )
    style_rec = ParagraphStyle(
        'Recommendation',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.black,
        spaceAfter=8,
        leading=14,
        leftIndent=12,
        fontName='Helvetica',
    )

    # Reusable table style helpers
    def header_table_style(extra=None):
        base = [
            ('BACKGROUND', (0, 0), (-1, 0), NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cccccc')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]
        if extra:
            base.extend(extra)
        return TableStyle(base)

    today_str = datetime.now(timezone.utc).strftime('%d %B %Y')

    # ---- Build story -------------------------------------------------------
    story = []
    page_w, page_h = A4

    # ========== PAGE 1 — COVER ==========
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("ESEAS Security Awareness Report", style_cover_title))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Enhanced Social Engineering Attack Simulator", style_cover_subtitle))
    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph(f"Generated: {today_str}", style_cover_body))
    story.append(Paragraph(f"Generated by: {current_user.name}", style_cover_body))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Final Year Cybersecurity Project", style_cover_body))

    # Decorative orange rule
    rule_data = [[''] * 1]
    rule_table = Table(rule_data, colWidths=[page_w - 4 * cm])
    rule_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 3, ORANGE),
    ]))
    story.append(Spacer(1, 2 * cm))
    story.append(rule_table)

    story.append(PageBreak())

    # ========== PAGE 2 — EXECUTIVE SUMMARY ==========
    story.append(Paragraph("Executive Summary", style_section))
    story.append(Spacer(1, 0.3 * cm))

    overview_data = [
        ['Metric', 'Value'],
        ['Total Users', str(total_users)],
        ['Total URL Scans', str(total_scans)],
        ['Phishing URLs Detected', str(phishing_detected)],
        ['Total Campaigns', str(total_campaigns)],
        ['Average Campaign Click Rate', f'{avg_click_rate}%'],
        ['Training Completion Rate', f'{training_completion_rate}%'],
    ]
    overview_table = Table(overview_data, colWidths=[10 * cm, 6 * cm])
    overview_table.setStyle(header_table_style())
    story.append(overview_table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph(
        f"The ESEAS system has monitored {total_users} users across "
        f"{total_campaigns} phishing simulation campaigns. "
        f"Of all active users, {training_completion_rate}% have completed at "
        f"least one training module, demonstrating the current level of "
        f"security awareness engagement within the organisation.",
        style_body,
    ))
    story.append(Paragraph(
        f"URL scanning analysis identified {phishing_detected} potentially "
        f"malicious URLs out of {total_scans} total scans, giving an overall "
        f"threat detection coverage of "
        f"{round(phishing_detected / total_scans * 100, 1) if total_scans else 0}%. "
        f"The average click rate across all phishing campaigns was {avg_click_rate}%, "
        f"indicating the susceptibility of users to social engineering attacks.",
        style_body,
    ))

    story.append(PageBreak())

    # ========== PAGE 3 — URL SCANNING ANALYSIS ==========
    story.append(Paragraph("URL Scanning Analysis", style_section))
    story.append(Spacer(1, 0.3 * cm))

    scan_summary_data = [
        ['Category', 'Count', 'Percentage'],
        ['Safe', str(safe_count),
         f"{round(safe_count / total_scans * 100, 1) if total_scans else 0}%"],
        ['Suspicious', str(suspicious_count),
         f"{round(suspicious_count / total_scans * 100, 1) if total_scans else 0}%"],
        ['Dangerous', str(dangerous_count),
         f"{round(dangerous_count / total_scans * 100, 1) if total_scans else 0}%"],
        ['Total', str(total_scans), '100%'],
    ]
    scan_summary_table = Table(scan_summary_data, colWidths=[7 * cm, 4 * cm, 5 * cm])
    scan_summary_table.setStyle(header_table_style([
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (0, -1), (-1, -1), LIGHT_GREY),
    ]))
    story.append(scan_summary_table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Top 10 Highest Risk URLs", style_section))
    risk_header = ['URL', 'Score', 'Label', 'Scanned By', 'Date']
    risk_rows = [risk_header]
    for scan, uname in top_risk_scans:
        url_display = scan.url[:60] + '...' if len(scan.url) > 60 else scan.url
        risk_rows.append([
            url_display,
            str(scan.final_score),
            scan.final_label,
            uname,
            scan.scanned_at.strftime('%Y-%m-%d') if scan.scanned_at else '',
        ])
    risk_table = Table(risk_rows, colWidths=[7 * cm, 2 * cm, 2.5 * cm, 3.5 * cm, 3 * cm])
    risk_table.setStyle(header_table_style([
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('WORDWRAP', (0, 0), (0, -1), True),
    ]))
    story.append(risk_table)

    story.append(PageBreak())

    # ========== PAGE 4 — SIMULATION RESULTS ==========
    story.append(Paragraph("Phishing Simulation Results", style_section))
    story.append(Spacer(1, 0.3 * cm))

    campaign_header = ['Campaign Name', 'Type', 'Targets', 'Click%', 'Cred%', 'Report%']
    campaign_rows = [campaign_header]
    for c in all_campaigns:
        campaign_rows.append([
            c.name,
            c.attack_type_label,
            str(c.target_count),
            f'{round(c.click_rate, 1)}%',
            f'{round(c.credential_rate, 1)}%',
            f'{round(c.report_rate, 1)}%',
        ])
    if len(campaign_rows) == 1:
        campaign_rows.append(['No campaigns yet', '', '', '', '', ''])

    campaign_table = Table(
        campaign_rows,
        colWidths=[5 * cm, 3 * cm, 2.5 * cm, 2 * cm, 2 * cm, 2.5 * cm]
    )
    campaign_table.setStyle(header_table_style())
    story.append(campaign_table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Top 5 Vulnerable Users (by Risk Score)", style_section))
    vuln_header = ['Name', 'Email', 'Risk Score']
    vuln_rows = [vuln_header]
    for u in top_vulnerable_users:
        scan_count = ScanResult.query.filter_by(user_id=u.id).count()
        vuln_rows.append([
            u.name,
            u.email,
            str(u.risk_score),
        ])
    if len(vuln_rows) == 1:
        vuln_rows.append(['No users yet', '', ''])

    vuln_table = Table(vuln_rows, colWidths=[5 * cm, 8 * cm, 3 * cm])
    vuln_table.setStyle(header_table_style())
    story.append(vuln_table)

    story.append(PageBreak())

    # ========== PAGE 5 — TRAINING & AWARENESS ==========
    story.append(Paragraph("Training & Awareness", style_section))
    story.append(Spacer(1, 0.3 * cm))

    mod_header = ['Module', 'Passed', 'Failed', 'Not Started', 'Pass Rate%']
    mod_rows = [mod_header]
    low_pass_modules = []
    for ms in module_stats:
        mod_rows.append([
            ms['title'],
            str(ms['passed']),
            str(ms['failed']),
            str(ms['not_started']),
            f"{ms['pass_rate']}%",
        ])
        if ms['pass_rate'] < 60 and (ms['passed'] + ms['failed']) > 0:
            low_pass_modules.append(ms)

    if len(mod_rows) == 1:
        mod_rows.append(['No modules available', '', '', '', ''])

    mod_table = Table(mod_rows, colWidths=[7 * cm, 2.5 * cm, 2.5 * cm, 3 * cm, 3 * cm])
    mod_table.setStyle(header_table_style())
    story.append(mod_table)
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph(
        f"Total badges awarded to date: <b>{total_badges_awarded}</b>",
        style_body,
    ))
    story.append(Spacer(1, 0.3 * cm))

    if all_completers:
        story.append(Paragraph(
            f"Users who completed all active modules ({len(all_completers)}):",
            style_body,
        ))
        for name in all_completers:
            story.append(Paragraph(f"• {name}", style_rec))
    else:
        story.append(Paragraph(
            "No users have completed all active training modules yet.",
            style_body,
        ))

    story.append(PageBreak())

    # ========== PAGE 6 — RECOMMENDATIONS ==========
    story.append(Paragraph("Recommendations", style_section))
    story.append(Spacer(1, 0.3 * cm))

    recommendations = []

    if avg_click_rate > 50:
        recommendations.append(
            f"<b>URGENT:</b> Average click rate of {avg_click_rate}% is critically high. "
            "Immediate phishing awareness training is recommended for all staff."
        )

    for ms in low_pass_modules:
        recommendations.append(
            f"Module '<b>{ms['title']}</b>' has a pass rate of only {ms['pass_rate']}%. "
            "Additional training resources should be provided for this topic."
        )

    high_risk_users = User.query.filter(User.risk_score > 80).count()
    if high_risk_users > 0:
        recommendations.append(
            f"<b>{high_risk_users} user(s)</b> have been flagged with high risk scores (&gt;80). "
            "Targeted one-on-one security coaching is recommended."
        )

    if training_completion_rate < 50:
        recommendations.append(
            f"Only <b>{training_completion_rate}%</b> of users have completed any training "
            "module. A mandatory awareness campaign should be launched."
        )

    recommendations.append(
        "Regular phishing simulations should be scheduled quarterly to maintain "
        "awareness and measure improvement over time."
    )

    for i, rec in enumerate(recommendations, start=1):
        story.append(Paragraph(f"{i}. {rec}", style_rec))

    # ---- Build PDF ---------------------------------------------------------
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="ESEAS Full Security Report",
        author=current_user.name,
    )
    doc.build(story)
    buf.seek(0)

    return Response(
        buf.read(),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': 'attachment; filename=eseas_full_report.pdf'
        },
    )
