import logging
from datetime import datetime, timezone

from flask import url_for, current_app
from flask_mail import Message

from extensions import mail
from security.email_guard import (
    sanitize_email_header,
    sanitize_email_html_value,
    validate_recipient_email,
)

logger = logging.getLogger(__name__)


def send_campaign_email(target, campaign):
    tmpl = campaign.template
    if tmpl:
        subject   = _replace_placeholders(tmpl.subject, target, campaign)
        body_html = _replace_placeholders(tmpl.body_html, target, campaign)
    else:
        subject   = f'[ESEAS Simulation] {campaign.name}'
        body_html = _generic_body(target, campaign)

    try:
        msg = Message(
            subject=subject,
            recipients=[target.user.email],
            html=body_html,
            sender=current_app.config.get('MAIL_USERNAME', 'noreply@eseas.dev'),
        )
        mail.send(msg)
        logger.info('Campaign email sent to %s', target.user.email)
    except Exception as exc:
        logger.error('SMTP failed for %s: %s', target.user.email, exc)
    finally:
        target.email_sent    = True
        target.email_sent_at = datetime.now(timezone.utc)


def _replace_placeholders(text: str, target, campaign) -> str:
    if not text:
        return text
    base = current_app.config.get('BASE_URL', 'http://127.0.0.1:5000').rstrip('/')
    tracking_url = f"{base}/track/{target.tracking_token}"
    report_url   = f"{base}/track/{target.tracking_token}/report"

    # Threat 9: Sanitize user-supplied values to prevent email header injection and XSS
    sanitized_user_name = sanitize_email_html_value(target.user.name)
    sanitized_user_email = sanitize_email_html_value(target.user.email)
    sanitized_campaign_name = sanitize_email_html_value(campaign.name)

    subs = {
        '{{user_name}}':     sanitized_user_name,
        '{{user_email}}':    sanitized_user_email,
        '{{tracking_link}}': tracking_url,
        '{{report_link}}':   report_url,
        '{{company_name}}':  'FUT Minna IT Department',
        '{{date}}':          datetime.now().strftime('%d %B %Y'),
        '{{campaign_name}}': sanitized_campaign_name,
        '{user_name}':       sanitized_user_name,
        '{user_email}':      sanitized_user_email,
        '{tracking_link}':   tracking_url,
        '{report_link}':     report_url,
        '{date}':            datetime.now().strftime('%d %B %Y'),
    }
    for k, v in subs.items():
        text = text.replace(k, v)
    return text


def _generic_body(target, campaign) -> str:
    base = current_app.config.get('BASE_URL', 'http://127.0.0.1:5000').rstrip('/')
    tracking_url = f"{base}/track/{target.tracking_token}"
    # Threat 9: Sanitize user-supplied values for email body
    sanitized_user_name = sanitize_email_html_value(target.user.name)
    sanitized_user_email = sanitize_email_html_value(target.user.email)
    return f"""
<html>
<body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:auto;padding:20px;">
  <p>Dear {sanitized_user_name},</p>
  <p>This is an important notice from FUT Minna IT Services.
     Please verify your account details to avoid suspension.</p>
  <p style="text-align:center;margin:30px 0;">
    <a href="{tracking_url}"
       style="background:#003366;color:#fff;padding:12px 28px;
              border-radius:4px;text-decoration:none;font-weight:bold;">
      Verify My Account
    </a>
  </p>
  <p style="color:#666;font-size:0.85em;">
    FUT Minna Information Technology Services<br>
    This email was sent to {sanitized_user_email}
  </p>
</body>
</html>
"""
