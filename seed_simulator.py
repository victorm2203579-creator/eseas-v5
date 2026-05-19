"""
Seed 10 realistic phishing attack templates for the simulator.
Called from app.py on startup. Idempotent — checks by name before inserting.
"""

TEMPLATES = [
    {
        'name': 'IT Department: Mandatory Password Reset',
        'attack_type': 'it_support',
        'subject': '[IT Security] Mandatory password reset required – action by end of day',
        'preview_text': 'Your FUT Minna portal password will expire in 4 hours.',
        'description': 'IT support impersonation requesting urgent password reset via a fake portal link.',
        'difficulty_level': 1,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f4f4f4" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.12);">

  <!-- Header -->
  <tr><td bgcolor="#003366" style="padding:20px 30px;">
    <img src="https://via.placeholder.com/160x40/ffffff/003366?text=FUT+Minna+IT" alt="FUT Minna IT" height="40"/>
  </td></tr>

  <!-- Alert banner -->
  <tr><td bgcolor="#cc0000" style="padding:12px 30px;color:#fff;font-size:13px;font-weight:bold;">
    ⚠ SECURITY ALERT — Immediate action required
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="margin:0 0 16px;font-size:15px;color:#333;">Dear {{user_name}},</p>
    <p style="margin:0 0 16px;font-size:14px;color:#555;line-height:1.6;">
      Our automated security system has flagged your account as requiring a mandatory password reset.
      Your current password will <strong>expire in 4 hours</strong> as part of our quarterly security audit.
    </p>
    <p style="margin:0 0 16px;font-size:14px;color:#555;line-height:1.6;">
      Failure to reset your password before the deadline will result in your account being
      <strong style="color:#cc0000;">temporarily suspended</strong> until manual verification is completed
      (up to 3 business days).
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:24px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#003366;color:#fff;
           padding:14px 36px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:15px;">
          Reset My Password Now
        </a>
      </td></tr>
    </table>
    <p style="margin:0 0 16px;font-size:13px;color:#888;">
      If you believe you received this email in error, please contact the IT Help Desk at ext. 4455.
      Do not reply to this automated message.
    </p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0;"/>
    <p style="margin:0;font-size:12px;color:#aaa;">
      FUT Minna Information Technology Services &bull; This is an automated security notification &bull;
      Sent to {{user_email}}
    </p>
    <p style="margin:8px 0 0;font-size:11px;color:#ccc;">
      <a href="{{report_link}}" style="color:#ccc;">Report this email as suspicious</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'PayPal: Account Access Limited',
        'attack_type': 'phishing_email',
        'subject': 'Your PayPal account has been limited – verify your information',
        'preview_text': 'We noticed unusual activity on your account. Your access is limited.',
        'description': 'PayPal impersonation claiming account access has been limited due to suspicious activity.',
        'difficulty_level': 2,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f5f7fa;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f5f7fa" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#009cde" style="padding:22px 30px;">
    <span style="font-size:24px;font-weight:bold;color:#fff;letter-spacing:-0.5px;">Pay<span style="color:#003087;">Pal</span></span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:32px 30px;">
    <h2 style="margin:0 0 16px;font-size:20px;color:#2c2e2f;">Your account access has been limited</h2>
    <p style="margin:0 0 14px;font-size:14px;color:#687173;line-height:1.6;">Dear {{user_name}},</p>
    <p style="margin:0 0 14px;font-size:14px;color:#687173;line-height:1.6;">
      We detected <strong>unusual activity</strong> on your PayPal account from an unrecognised device.
      To protect you, we've temporarily limited access to certain features until you verify your identity.
    </p>
    <div style="background:#fff8e6;border-left:4px solid #f5a623;padding:14px 16px;margin:20px 0;border-radius:0 4px 4px 0;">
      <strong style="color:#c87400;">What has been limited:</strong>
      <ul style="margin:8px 0 0;padding-left:18px;color:#555;font-size:13px;">
        <li>Sending payments</li>
        <li>Withdrawing funds to bank</li>
        <li>Adding new cards or bank accounts</li>
      </ul>
    </div>
    <p style="margin:0 0 14px;font-size:14px;color:#687173;line-height:1.6;">
      Please verify your identity by clicking the button below. This takes less than 2 minutes.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:24px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#0070ba;color:#fff;
           padding:14px 40px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Restore My Account Access
        </a>
      </td></tr>
    </table>
    <p style="margin:0 0 14px;font-size:12px;color:#aaa;">
      This link expires in 72 hours. If you don't verify, your account will remain limited.
    </p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0;"/>
    <p style="font-size:11px;color:#ccc;margin:0;">
      © PayPal Inc. &bull; This email was sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#ccc;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'DHL: Package On Hold – Pay Customs Fee',
        'attack_type': 'phishing_email',
        'subject': 'Your DHL package is on hold – customs payment required',
        'preview_text': 'Package #7842891 is awaiting your customs clearance payment of ₦2,500.',
        'description': 'Fake DHL delivery notification requiring a small customs payment to release a package.',
        'difficulty_level': 2,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f4f4f4" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;">

  <!-- Header -->
  <tr><td bgcolor="#FFCC00" style="padding:20px 30px;">
    <span style="font-size:22px;font-weight:900;color:#d40511;letter-spacing:1px;">DHL</span>
    <span style="font-size:13px;color:#333;margin-left:12px;font-weight:bold;">EXPRESS</span>
  </td></tr>

  <!-- Status bar -->
  <tr><td bgcolor="#d40511" style="padding:10px 30px;color:#fff;font-size:13px;">
    📦 Package Status: <strong>ON HOLD — Action Required</strong>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="margin:0 0 14px;font-size:14px;color:#333;">Dear {{user_name}},</p>
    <p style="margin:0 0 14px;font-size:14px;color:#555;line-height:1.6;">
      Your package with tracking number <strong>#7842891-NG</strong> has arrived at our
      Lagos customs facility but is currently <strong>on hold</strong> pending payment of import duties.
    </p>
    <table width="100%" style="border:1px solid #eee;border-radius:4px;margin:16px 0;">
      <tr style="background:#f9f9f9;"><td style="padding:10px 14px;font-size:13px;"><strong>Tracking No.</strong></td><td style="padding:10px 14px;font-size:13px;">#7842891-NG</td></tr>
      <tr><td style="padding:10px 14px;font-size:13px;"><strong>Status</strong></td><td style="padding:10px 14px;font-size:13px;color:#d40511;">On Hold</td></tr>
      <tr style="background:#f9f9f9;"><td style="padding:10px 14px;font-size:13px;"><strong>Customs Fee Due</strong></td><td style="padding:10px 14px;font-size:13px;"><strong>₦2,500.00</strong></td></tr>
      <tr><td style="padding:10px 14px;font-size:13px;"><strong>Pay By</strong></td><td style="padding:10px 14px;font-size:13px;color:#d40511;"><strong>{{date}} (Today)</strong></td></tr>
    </table>
    <p style="margin:0 0 14px;font-size:13px;color:#555;line-height:1.6;">
      Failure to pay the customs fee within 24 hours will result in the package being returned to the sender
      or destroyed. Please click below to pay securely.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#d40511;color:#fff;
           padding:13px 36px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Pay ₦2,500 Customs Fee
        </a>
      </td></tr>
    </table>
    <p style="font-size:11px;color:#ccc;margin:20px 0 0;">
      DHL Nigeria Customer Service &bull; Sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#ccc;">Report suspicious email</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'Microsoft 365: Licence Expiry Warning',
        'attack_type': 'phishing_email',
        'subject': 'Action required: Your Microsoft 365 licence expires in 48 hours',
        'preview_text': 'Renew now to avoid losing access to Outlook, Teams, Word, and OneDrive.',
        'description': 'Microsoft 365 licence expiry notice pushing users to a fake login to "renew" their account.',
        'difficulty_level': 2,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" bgcolor="#f3f3f3" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:4px;overflow:hidden;box-shadow:0 1px 6px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#0078d4" style="padding:20px 30px;">
    <span style="font-size:20px;font-weight:600;color:#fff;">Microsoft 365</span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="margin:0 0 16px;font-size:14px;color:#333;">Dear {{user_name}},</p>
    <p style="margin:0 0 14px;font-size:14px;color:#333;line-height:1.7;">
      Your <strong>Microsoft 365 Business Standard</strong> subscription is set to expire in
      <span style="color:#d83b01;font-weight:bold;">48 hours</span>.
      After expiry, you will <strong>lose access to:</strong>
    </p>
    <ul style="color:#555;font-size:13px;line-height:2;">
      <li>Outlook Mail &amp; Calendar</li>
      <li>Microsoft Teams</li>
      <li>Word, Excel, PowerPoint (online &amp; desktop)</li>
      <li>OneDrive (1 TB cloud storage)</li>
    </ul>
    <div style="background:#fff4ce;border:1px solid #ffbe00;border-radius:4px;padding:14px;margin:20px 0;">
      <strong style="color:#7a4f00;">⚠ Your subscription expires: {{date}}</strong><br/>
      <span style="font-size:13px;color:#555;">Sign in now to verify your payment method and avoid interruption.</span>
    </div>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:24px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#0078d4;color:#fff;
           padding:13px 36px;text-decoration:none;border-radius:2px;font-weight:600;font-size:14px;">
          Sign in and Renew
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#aaa;margin:0;">
      Microsoft Corporation &bull; One Microsoft Way, Redmond, WA 98052<br/>
      Sent to {{user_email}} &bull; <a href="{{report_link}}" style="color:#aaa;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'CEO Emergency: Urgent Wire Transfer',
        'attack_type': 'spear_phishing',
        'subject': 'Urgent – confidential wire transfer needed today',
        'preview_text': 'Hi, I need you to process a transfer urgently. I\'m in a meeting and cannot call.',
        'description': 'Business Email Compromise (BEC): CEO impersonation requesting an urgent wire transfer.',
        'difficulty_level': 4,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#ffffff;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#ffffff" cellpadding="0" cellspacing="0">
<tr><td style="padding:30px;max-width:580px;">

  <p style="margin:0 0 16px;font-size:14px;color:#333;">Hi {{user_name}},</p>
  <p style="margin:0 0 16px;font-size:14px;color:#333;line-height:1.7;">
    I need you to handle something for me urgently and confidentially.
    We're in the process of closing a strategic acquisition and I need a wire transfer
    processed <strong>today before 3pm</strong>. I'm currently in a board meeting and can't take calls.
  </p>
  <p style="margin:0 0 16px;font-size:14px;color:#333;line-height:1.7;">
    The amount is <strong>₦4,800,000</strong> to our legal counsel's holding account.
    Please log in to the finance portal to initiate the transfer and confirm via this email.
    Keep this confidential until the deal is announced.
  </p>
  <table cellpadding="0" cellspacing="0" style="margin:20px 0;">
    <tr><td>
      <a href="{{tracking_link}}" style="display:inline-block;background:#1a56db;color:#fff;
         padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:13px;">
        Open Finance Portal
      </a>
    </td></tr>
  </table>
  <p style="margin:0 0 16px;font-size:14px;color:#333;line-height:1.7;">
    This is time sensitive. Please confirm as soon as this is done.
  </p>
  <p style="margin:0;font-size:14px;color:#333;">
    Best regards,<br/>
    <strong>Prof. A. Musa</strong><br/>
    Vice-Chancellor, FUT Minna<br/>
    <span style="font-size:12px;color:#888;">Sent from mobile device</span>
  </p>
  <p style="margin:20px 0 0;font-size:11px;color:#ddd;">
    <a href="{{report_link}}" style="color:#ddd;">Report suspicious email</a>
  </p>

</td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'HR: Annual Benefits Enrollment Closing',
        'attack_type': 'spear_phishing',
        'subject': 'HR Notice: Benefits enrollment closes {{date}} – update your selections',
        'preview_text': 'Open enrollment ends today. Log in to confirm your healthcare and pension selections.',
        'description': 'HR department impersonation for annual benefits enrollment with fake HR portal link.',
        'difficulty_level': 3,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f0f2f5" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#2d6a4f" style="padding:20px 30px;">
    <span style="font-size:18px;font-weight:bold;color:#fff;">
      🏢 FUT Minna Human Resources
    </span>
  </td></tr>

  <!-- Deadline bar -->
  <tr><td bgcolor="#f77f00" style="padding:10px 30px;color:#fff;font-size:13px;font-weight:bold;">
    ⏰ ENROLLMENT CLOSES TODAY: {{date}}
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="margin:0 0 14px;font-size:14px;color:#333;">Dear {{user_name}},</p>
    <p style="margin:0 0 14px;font-size:14px;color:#555;line-height:1.6;">
      This is a reminder that the <strong>2024/2025 Employee Benefits Enrollment</strong> period
      closes <strong>today at 5:00 PM</strong>. If you do not confirm your selections,
      you will be enrolled in the <em>default plan</em>, which may not match your needs.
    </p>
    <div style="background:#e8f5e9;border-left:4px solid #2d6a4f;padding:14px;margin:16px 0;">
      <strong style="color:#2d6a4f;">What you need to confirm:</strong>
      <ul style="margin:8px 0 0;padding-left:18px;font-size:13px;color:#555;">
        <li>Health insurance plan selection</li>
        <li>Pension contribution percentage</li>
        <li>Emergency contact information</li>
        <li>Life assurance beneficiary details</li>
      </ul>
    </div>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#2d6a4f;color:#fff;
           padding:13px 36px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Log In to HR Portal
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#aaa;margin:0;">
      FUT Minna HR Department &bull; Benefits Administration Team &bull; Sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#aaa;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'Prize Winner: ₦500,000 Lottery Claim',
        'attack_type': 'prize_lure',
        'subject': '🎉 CONGRATULATIONS! You\'ve won ₦500,000 — claim within 24 hours',
        'preview_text': 'Your email address was selected in our quarterly prize draw. Claim now!',
        'description': 'Prize lure promising ₦500,000 winnings that require personal verification to claim.',
        'difficulty_level': 1,
        'fake_page_type': 'prize_claim',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#1a0533;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#1a0533" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:10px;overflow:hidden;">

  <!-- Header -->
  <tr><td align="center" bgcolor="#f7c61f" style="padding:30px 20px;">
    <div style="font-size:36px;">🏆</div>
    <h1 style="margin:10px 0 0;font-size:26px;color:#1a0533;font-weight:900;">
      CONGRATULATIONS!
    </h1>
    <p style="margin:6px 0 0;font-size:14px;color:#7a5c00;">You are our lucky winner!</p>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;text-align:center;">
    <p style="font-size:16px;color:#333;font-weight:bold;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 16px;">
      Your email address <strong>({{user_email}})</strong> was randomly selected
      in our <strong>MTN Nigeria Quarterly Prize Draw</strong> and you have won the grand prize of:
    </p>
    <div style="background:#1a0533;color:#f7c61f;font-size:38px;font-weight:900;
                padding:20px;border-radius:8px;margin:20px 0;">
      ₦500,000.00
    </div>
    <p style="font-size:13px;color:#888;margin:0 0 20px;">
      Reference: <strong>WIN/MTN/2024/{{user_email}}</strong>
    </p>
    <div style="background:#fff8e1;border:2px dashed #f7c61f;border-radius:6px;padding:16px;margin:0 0 24px;text-align:left;">
      <strong style="font-size:13px;color:#333;">⏰ Claim expires in: 24 hours</strong><br/>
      <span style="font-size:12px;color:#888;">Unclaimed prizes are forfeited and redistributed.</span>
    </div>
    <a href="{{tracking_link}}" style="display:inline-block;background:#e63946;color:#fff;
       padding:16px 48px;text-decoration:none;border-radius:6px;font-weight:bold;font-size:16px;">
      CLAIM MY PRIZE NOW
    </a>
    <p style="font-size:11px;color:#ccc;margin:20px 0 0;">
      MTN Nigeria &bull; Prize Administration Department &bull; Lagos, Nigeria<br/>
      <a href="{{report_link}}" style="color:#ccc;">Report suspicious email</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'DocuSign: Document Awaiting Your Signature',
        'attack_type': 'phishing_email',
        'subject': 'DocuSign: "Contract Agreement" sent for your signature',
        'preview_text': 'Review and sign your document before it expires on {{date}}.',
        'description': 'Fake DocuSign notification for a contract requiring the user to "sign in" to review.',
        'difficulty_level': 3,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f4f4f4" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:4px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">

  <!-- Header -->
  <tr><td bgcolor="#1a3563" style="padding:18px 30px;display:flex;align-items:center;gap:12px;">
    <span style="font-size:20px;font-weight:bold;color:#f7c61f;">DocuSign</span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="margin:0 0 14px;font-size:14px;color:#333;">
      <strong>FUT Minna Administration Office</strong> has sent you a document to review and sign.
    </p>
    <div style="border:1px solid #e0e0e0;border-radius:4px;padding:20px;margin:16px 0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-size:13px;color:#555;padding-bottom:8px;">
            <strong>Document:</strong> Employment Contract Amendment 2024
          </td>
        </tr>
        <tr>
          <td style="font-size:13px;color:#555;padding-bottom:8px;">
            <strong>From:</strong> admin@futminna.edu.ng
          </td>
        </tr>
        <tr>
          <td style="font-size:13px;color:#555;padding-bottom:8px;">
            <strong>Sent to:</strong> {{user_email}}
          </td>
        </tr>
        <tr>
          <td style="font-size:13px;color:#e74c3c;">
            <strong>Expires:</strong> {{date}}
          </td>
        </tr>
      </table>
    </div>
    <p style="font-size:14px;color:#555;margin:0 0 20px;line-height:1.6;">
      Please review and sign this document at your earliest convenience, {{user_name}}.
      You will need to verify your identity to access the document.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#f7c61f;color:#1a3563;
           padding:13px 40px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Review Document
        </a>
      </td></tr>
    </table>
    <hr style="border:none;border-top:1px solid #eee;margin:24px 0;"/>
    <p style="font-size:11px;color:#aaa;margin:0;">
      DocuSign, Inc. &bull; 221 Main Street, Suite 1000, San Francisco, CA 94105<br/>
      This is an automated notification. Do not reply.<br/>
      <a href="{{report_link}}" style="color:#aaa;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'Bank: Suspicious Login Detected',
        'attack_type': 'phishing_email',
        'subject': 'Security alert: Suspicious login detected on your First Bank account',
        'preview_text': 'A login attempt from an unrecognised device in Abuja was detected.',
        'description': 'Bank security alert about a suspicious login requiring immediate account verification.',
        'difficulty_level': 2,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f5f5f5" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#003580" style="padding:20px 30px;">
    <span style="font-size:22px;font-weight:900;color:#ffffff;letter-spacing:1px;">FIRST BANK</span>
    <span style="font-size:11px;color:#99bbdd;margin-left:10px;">of Nigeria</span>
  </td></tr>

  <!-- Alert banner -->
  <tr><td bgcolor="#c0392b" style="padding:10px 30px;color:#fff;font-size:13px;font-weight:bold;">
    🔐 Security Alert — Unusual Login Activity
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:14px;color:#333;margin:0 0 14px;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.6;margin:0 0 14px;">
      We detected a login attempt to your <strong>First Bank Online Banking</strong> account
      from an unrecognised device. For your security, access has been temporarily restricted.
    </p>
    <div style="background:#fff0f0;border:1px solid #e74c3c;border-radius:4px;padding:14px;margin:16px 0;">
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">
        <tr><td style="padding:4px 0;color:#555;"><strong>Time:</strong></td><td style="color:#333;">Today, {{date}} at 11:42 PM</td></tr>
        <tr><td style="padding:4px 0;color:#555;"><strong>Device:</strong></td><td style="color:#333;">Unknown Android Device</td></tr>
        <tr><td style="padding:4px 0;color:#555;"><strong>Location:</strong></td><td style="color:#e74c3c;font-weight:bold;">Abuja, Nigeria (new location)</td></tr>
      </table>
    </div>
    <p style="font-size:14px;color:#555;line-height:1.6;margin:0 0 20px;">
      If this was you, please verify your identity to restore full access.
      If this was NOT you, verify immediately to secure your account and
      <strong>prevent unauthorised transactions</strong>.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#003580;color:#fff;
           padding:13px 40px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Secure My Account Now
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#aaa;margin:0;">
      First Bank of Nigeria &bull; Customer Security Centre &bull; Sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#aaa;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'University Portal: Account Verification Required',
        'attack_type': 'phishing_email',
        'subject': 'FUT Minna Student Portal: Account verification required before {{date}}',
        'preview_text': 'Verify your student account to retain access to examination results and course materials.',
        'description': 'University portal impersonation requiring students to verify account to access exam results.',
        'difficulty_level': 2,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f0f4f8" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#006400" style="padding:20px 30px;">
    <span style="font-size:16px;font-weight:bold;color:#fff;">
      Federal University of Technology, Minna
    </span><br/>
    <span style="font-size:12px;color:#90ee90;">Student Information System</span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:14px;color:#333;margin:0 0 14px;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.6;margin:0 0 14px;">
      As part of our annual student database audit, all students are required to
      <strong>re-verify their portal accounts</strong> before accessing:
    </p>
    <ul style="font-size:13px;color:#555;line-height:2;margin:0 0 14px;padding-left:20px;">
      <li>2023/2024 Examination Results</li>
      <li>Course Registration for 2024/2025 Session</li>
      <li>Clearance and Transcript Requests</li>
    </ul>
    <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:14px;margin:16px 0;">
      <strong style="color:#856404;">⚠ Deadline: {{date}}</strong><br/>
      <span style="font-size:13px;color:#555;">Unverified accounts will be <strong>suspended</strong> and access to all portal services will be blocked.</span>
    </div>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#006400;color:#fff;
           padding:13px 36px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Verify My Student Account
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#aaa;margin:0;">
      FUT Minna ICT Centre &bull; Student Records Unit &bull; Sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#aaa;">Report suspicious email</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },
]


def seed_simulator_templates():
    """Insert the 10 default attack templates if they don't already exist."""
    from models.simulator import AttackTemplate
    from models import db

    existing_names = {t.name for t in AttackTemplate.query.all()}
    added = 0
    for tmpl_data in TEMPLATES:
        if tmpl_data['name'] not in existing_names:
            db.session.add(AttackTemplate(
                name=tmpl_data['name'],
                attack_type=tmpl_data['attack_type'],
                subject=tmpl_data['subject'],
                preview_text=tmpl_data['preview_text'],
                body_html=tmpl_data['body_html'],
                fake_page_type=tmpl_data['fake_page_type'],
                description=tmpl_data['description'],
                difficulty_level=tmpl_data['difficulty_level'],
                is_active=True,
                created_by=None,
            ))
            added += 1

    if added:
        db.session.commit()
        print(f'[seed_simulator] Added {added} attack templates.')


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed_simulator_templates()
