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
    # ── 10 NEW HARDER TEMPLATES ──────────────────────────────────────────────

    {
        'name': 'Google: Critical Security Alert — Sign-in Blocked',
        'attack_type': 'phishing_email',
        'subject': 'Critical security alert — sign-in attempt blocked on your Google Account',
        'preview_text': 'A new sign-in on Windows was blocked. Review this activity now.',
        'description': 'Google security alert impersonation — exact copy of real Google security emails with correct branding.',
        'difficulty_level': 4,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f1f3f4;font-family:Roboto,Arial,sans-serif;">
<table width="100%" bgcolor="#f1f3f4" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.15);">

  <!-- Header -->
  <tr><td style="padding:24px 30px;border-bottom:1px solid #e8eaed;">
    <span style="font-size:22px;font-weight:400;color:#202124;">
      <span style="color:#4285f4;">G</span><span style="color:#ea4335;">o</span><span style="color:#fbbc05;">o</span><span style="color:#4285f4;">g</span><span style="color:#34a853;">l</span><span style="color:#ea4335;">e</span>
    </span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:32px 30px;">
    <div style="width:48px;height:48px;background:#fce8e6;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px;">
      <span style="font-size:24px;">⚠️</span>
    </div>
    <h2 style="margin:0 0 8px;font-size:20px;font-weight:400;color:#202124;">Critical security alert</h2>
    <p style="margin:0 0 20px;font-size:14px;color:#5f6368;">for {{user_email}}</p>

    <div style="border:1px solid #e8eaed;border-radius:8px;padding:16px;margin:0 0 24px;">
      <p style="margin:0 0 8px;font-size:14px;color:#202124;font-weight:500;">A new sign-in on Windows</p>
      <p style="margin:0 0 4px;font-size:13px;color:#5f6368;">📍 Lagos, Nigeria &nbsp;·&nbsp; {{date}}</p>
      <p style="margin:0;font-size:13px;color:#ea4335;font-weight:500;">⛔ Sign-in was blocked</p>
    </div>

    <p style="margin:0 0 16px;font-size:14px;color:#202124;line-height:1.6;">
      Someone just used your password to try to sign in to your account from a non-Google app.
      Google blocked them, but you should <strong>review your account activity</strong> to confirm it was not you.
    </p>
    <p style="margin:0 0 24px;font-size:14px;color:#202124;line-height:1.6;">
      If you do not recognise this sign-in, you should <strong>change your password immediately</strong>
      to secure your account.
    </p>

    <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
      <tr>
        <td style="padding-right:12px;">
          <a href="{{tracking_link}}" style="display:inline-block;background:#1a73e8;color:#fff;
             padding:10px 24px;text-decoration:none;border-radius:4px;font-size:14px;font-weight:500;">
            Check activity
          </a>
        </td>
        <td>
          <a href="{{tracking_link}}" style="display:inline-block;background:#fff;color:#1a73e8;
             padding:10px 24px;text-decoration:none;border-radius:4px;font-size:14px;font-weight:500;
             border:1px solid #dadce0;">
            Change password
          </a>
        </td>
      </tr>
    </table>

    <p style="font-size:12px;color:#5f6368;line-height:1.6;margin:0 0 8px;">
      You received this email to let you know about important changes to your Google Account and services.<br/>
      © 2024 Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043
    </p>
    <p style="font-size:12px;margin:0;">
      <a href="{{report_link}}" style="color:#1a73e8;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'GTBank: BVN Verification — Account Restriction Notice',
        'attack_type': 'phishing_email',
        'subject': 'IMPORTANT: Verify your BVN to avoid account restriction — GTBank',
        'preview_text': 'Your account will be restricted within 24 hours unless you complete BVN verification.',
        'description': 'GTBank impersonation demanding BVN verification to avoid account suspension.',
        'difficulty_level': 3,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f5f5f5" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:4px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#e30613" style="padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:18px 30px;">
          <span style="font-size:26px;font-weight:900;color:#ffffff;letter-spacing:2px;">GTBank</span>
        </td>
        <td align="right" style="padding:18px 30px;">
          <span style="font-size:11px;color:rgba(255,255,255,.8);">Guaranty Trust Bank Plc</span>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Orange urgency bar -->
  <tr><td bgcolor="#ff6600" style="padding:10px 30px;color:#fff;font-size:13px;font-weight:bold;">
    ⚠️ ACTION REQUIRED: BVN Verification Pending
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:15px;color:#333;margin:0 0 16px;font-weight:bold;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      Following the Central Bank of Nigeria (CBN) directive on customer data verification,
      we are required to validate the Bank Verification Number (BVN) linked to your GTBank account.
    </p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      Our records indicate that your BVN verification is <strong style="color:#e30613;">incomplete</strong>.
      Failure to complete verification by <strong>{{date}}</strong> will result in:
    </p>
    <div style="background:#fff5f5;border:1px solid #ffcccc;border-radius:4px;padding:16px;margin:16px 0;">
      <ul style="margin:0;padding-left:18px;font-size:13px;color:#555;line-height:2;">
        <li>Restriction of all debit card transactions</li>
        <li>Suspension of internet and mobile banking</li>
        <li>Freeze on all inward/outward transfers</li>
      </ul>
    </div>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 20px;">
      Click the button below to verify your BVN securely and avoid any disruption to your banking services.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#e30613;color:#fff;
           padding:14px 44px;text-decoration:none;border-radius:3px;font-weight:bold;font-size:15px;
           letter-spacing:.5px;">
          Verify My BVN Now
        </a>
      </td></tr>
    </table>
    <div style="border-top:1px solid #eee;padding-top:16px;margin-top:8px;">
      <p style="font-size:12px;color:#999;margin:0 0 4px;">
        GTBank Customer Care: 0700-482-6268 &bull; Email: gtconnect@gtbank.com
      </p>
      <p style="font-size:11px;color:#bbb;margin:0;">
        Guaranty Trust Bank Plc &bull; Plot 635, Akin Adesola St, Victoria Island, Lagos &bull;
        Sent to {{user_email}}<br/>
        <a href="{{report_link}}" style="color:#bbb;">Report phishing</a>
      </p>
    </div>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'JAMB: Admission Status Update — Login Required',
        'attack_type': 'phishing_email',
        'subject': 'JAMB CAPS: Your admission status has been updated — login to view',
        'preview_text': 'Your 2024 UTME admission status has been updated. Log in to JAMB CAPS to view.',
        'description': 'JAMB CAPS admission portal impersonation targeting Nigerian students checking admission status.',
        'difficulty_level': 3,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f0f4f8" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#006633" style="padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:18px 30px;">
          <p style="margin:0;font-size:16px;font-weight:bold;color:#fff;">JAMB</p>
          <p style="margin:2px 0 0;font-size:11px;color:#90ee90;">Joint Admissions and Matriculation Board</p>
        </td>
        <td align="right" style="padding:18px 30px;">
          <span style="font-size:11px;color:rgba(255,255,255,.7);">Federal Republic of Nigeria</span>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Status banner -->
  <tr><td bgcolor="#ffd700" style="padding:12px 30px;">
    <p style="margin:0;font-size:13px;font-weight:bold;color:#333;">
      📋 CAPS NOTIFICATION — Admission Status Update
    </p>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:14px;color:#333;margin:0 0 14px;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      We write to inform you that your <strong>2024 UTME/DE Admission Status</strong> on the
      Central Admissions Processing System (CAPS) has been <strong>updated</strong>.
    </p>
    <div style="border:2px solid #006633;border-radius:6px;padding:20px;margin:16px 0;text-align:center;">
      <p style="margin:0 0 8px;font-size:13px;color:#555;">Registration Number</p>
      <p style="margin:0 0 12px;font-size:20px;font-weight:bold;color:#006633;letter-spacing:2px;">
        23{{user_email}}4NG
      </p>
      <p style="margin:0;font-size:13px;color:#e65c00;font-weight:bold;">
        ⚠ Status Update Available — Login Required to View
      </p>
    </div>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      To view your complete admission status, accept/reject your admission offer, or print your
      admission letter, please log in to your JAMB profile immediately.
    </p>
    <p style="font-size:13px;color:#e65c00;margin:0 0 20px;">
      <strong>Note:</strong> Unclaimed admission offers are automatically withdrawn after <strong>{{date}}</strong>.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#006633;color:#fff;
           padding:14px 40px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Login to JAMB CAPS Portal
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#aaa;margin:0;">
      JAMB Headquarters &bull; Bwari, Abuja, Nigeria &bull; support@jamb.gov.ng<br/>
      Sent to {{user_email}} &bull; <a href="{{report_link}}" style="color:#aaa;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'WhatsApp: Your Account Has Been Suspended',
        'attack_type': 'phishing_email',
        'subject': 'Your WhatsApp account has been suspended — appeal within 24 hours',
        'preview_text': 'Your WhatsApp account was suspended for violating our Terms of Service.',
        'description': 'WhatsApp account suspension notice with an appeal link that harvests credentials.',
        'difficulty_level': 3,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,Helvetica,Arial,sans-serif;">
<table width="100%" bgcolor="#f0f2f5" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#25d366" style="padding:22px 30px;text-align:center;">
    <div style="width:52px;height:52px;background:#ffffff;border-radius:50%;display:inline-block;line-height:52px;font-size:28px;margin-bottom:8px;">💬</div>
    <p style="margin:0;font-size:20px;font-weight:700;color:#ffffff;">WhatsApp</p>
  </td></tr>

  <!-- Red alert -->
  <tr><td bgcolor="#dc3545" style="padding:12px 30px;text-align:center;color:#fff;font-size:13px;font-weight:bold;">
    🚫 Account Suspended — Immediate Action Required
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:32px 30px;">
    <p style="font-size:15px;color:#1c1e21;margin:0 0 16px;font-weight:600;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#4b4f56;line-height:1.7;margin:0 0 14px;">
      Your WhatsApp account linked to <strong>{{user_email}}</strong> has been
      <strong style="color:#dc3545;">temporarily suspended</strong> due to a violation of our
      Terms of Service. Specifically:
    </p>
    <div style="background:#fff5f5;border-left:4px solid #dc3545;padding:14px 16px;margin:16px 0;border-radius:0 6px 6px 0;">
      <p style="margin:0 0 6px;font-size:13px;color:#721c24;font-weight:600;">Reason for suspension:</p>
      <p style="margin:0;font-size:13px;color:#555;">Suspected automated messaging activity detected on your account (Section 7.2 of WhatsApp Terms of Service).</p>
    </div>
    <p style="font-size:14px;color:#4b4f56;line-height:1.7;margin:0 0 14px;">
      If you believe this is a mistake, you can appeal this decision within
      <strong>24 hours</strong>. After this period, your account and all associated
      message history will be <strong>permanently deleted</strong>.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:24px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#25d366;color:#fff;
           padding:14px 44px;text-decoration:none;border-radius:24px;font-weight:700;font-size:15px;">
          Appeal Suspension
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#90949c;margin:0;text-align:center;">
      WhatsApp LLC &bull; 1601 Willow Road, Menlo Park, CA 94025<br/>
      <a href="{{report_link}}" style="color:#90949c;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'UBA: Unusual Transaction Alert — Verify Immediately',
        'attack_type': 'phishing_email',
        'subject': 'UBA Alert: Unusual transaction of ₦185,000 — verify now to stop it',
        'preview_text': 'A transaction of ₦185,000 was initiated on your UBA account. Not you? Stop it now.',
        'description': 'UBA bank transaction alert impersonation with a fake verification link to stop a large transfer.',
        'difficulty_level': 4,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#f5f5f5" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:4px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#e60026" style="padding:18px 30px;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td>
          <span style="font-size:24px;font-weight:900;color:#ffffff;letter-spacing:1px;">UBA</span>
          <span style="font-size:11px;color:rgba(255,255,255,.8);margin-left:8px;">United Bank for Africa</span>
        </td>
        <td align="right">
          <span style="font-size:11px;color:rgba(255,255,255,.7);">Transaction Alert</span>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Alert -->
  <tr><td bgcolor="#1a1a1a" style="padding:12px 30px;">
    <p style="margin:0;font-size:13px;color:#ff4444;font-weight:bold;">
      ⚡ HIGH VALUE TRANSACTION ALERT
    </p>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:14px;color:#333;margin:0 0 16px;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      A <strong>debit transaction</strong> has been initiated on your UBA account.
      If you did not authorise this transaction, click <strong>"Stop Transaction"</strong>
      immediately to reverse it before it is processed.
    </p>

    <div style="border:2px solid #e60026;border-radius:6px;overflow:hidden;margin:20px 0;">
      <div style="background:#e60026;padding:10px 16px;">
        <p style="margin:0;font-size:13px;font-weight:bold;color:#fff;">Transaction Details</p>
      </div>
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">
        <tr style="background:#fff9f9;"><td style="padding:10px 16px;color:#555;border-bottom:1px solid #f0e0e0;"><strong>Amount</strong></td><td style="padding:10px 16px;color:#e60026;font-weight:bold;font-size:15px;border-bottom:1px solid #f0e0e0;">₦185,000.00</td></tr>
        <tr><td style="padding:10px 16px;color:#555;border-bottom:1px solid #f0e0e0;"><strong>Beneficiary</strong></td><td style="padding:10px 16px;color:#333;border-bottom:1px solid #f0e0e0;">OKEKE CHUKWUEMEKA</td></tr>
        <tr style="background:#fff9f9;"><td style="padding:10px 16px;color:#555;border-bottom:1px solid #f0e0e0;"><strong>Bank</strong></td><td style="padding:10px 16px;color:#333;border-bottom:1px solid #f0e0e0;">Zenith Bank</td></tr>
        <tr><td style="padding:10px 16px;color:#555;border-bottom:1px solid #f0e0e0;"><strong>Date/Time</strong></td><td style="padding:10px 16px;color:#333;border-bottom:1px solid #f0e0e0;">{{date}}, 02:17 AM</td></tr>
        <tr style="background:#fff9f9;"><td style="padding:10px 16px;color:#555;"><strong>Status</strong></td><td style="padding:10px 16px;color:#ff6600;font-weight:bold;">Processing — Not Yet Sent</td></tr>
      </table>
    </div>

    <p style="font-size:14px;color:#555;margin:0 0 20px;line-height:1.6;">
      You have <strong style="color:#e60026;">10 minutes</strong> to stop this transaction before it
      is completed and funds leave your account permanently.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%">
      <tr>
        <td align="center" style="padding-right:8px;">
          <a href="{{tracking_link}}" style="display:inline-block;background:#e60026;color:#fff;
             padding:13px 32px;text-decoration:none;border-radius:3px;font-weight:bold;font-size:14px;">
            Stop Transaction
          </a>
        </td>
        <td align="center" style="padding-left:8px;">
          <a href="{{tracking_link}}" style="display:inline-block;background:#fff;color:#e60026;
             padding:13px 32px;text-decoration:none;border-radius:3px;font-weight:bold;font-size:14px;
             border:2px solid #e60026;">
            It Was Me
          </a>
        </td>
      </tr>
    </table>
    <p style="font-size:11px;color:#bbb;margin:20px 0 0;">
      UBA Nigeria &bull; UBA House, 57 Marina, Lagos &bull; Sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#bbb;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'Netflix: Payment Failed — Update Billing Details',
        'attack_type': 'phishing_email',
        'subject': 'Your Netflix membership is on hold — update payment to keep watching',
        'preview_text': 'We had trouble processing your last payment. Update your billing info to continue.',
        'description': 'Netflix billing failure impersonation targeting active subscribers to harvest payment details.',
        'difficulty_level': 3,
        'fake_page_type': 'bank_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#000000;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#000000" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#141414" cellpadding="0" cellspacing="0" style="border-radius:4px;overflow:hidden;">

  <!-- Header -->
  <tr><td bgcolor="#000000" style="padding:22px 30px;border-bottom:1px solid #333;">
    <span style="font-size:28px;font-weight:900;color:#e50914;letter-spacing:-1px;">NETFLIX</span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:36px 30px;">
    <h2 style="margin:0 0 16px;font-size:22px;color:#ffffff;font-weight:400;">
      Your membership is on hold
    </h2>
    <p style="font-size:14px;color:#b3b3b3;line-height:1.7;margin:0 0 20px;">
      Hi {{user_name}},
    </p>
    <p style="font-size:14px;color:#b3b3b3;line-height:1.7;margin:0 0 20px;">
      We're having trouble with your current billing information. To keep your Netflix membership
      and continue enjoying all your favourite shows and movies, please update your payment details.
    </p>

    <div style="background:#1f1f1f;border:1px solid #333;border-radius:4px;padding:20px;margin:20px 0;">
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;color:#b3b3b3;">
        <tr><td style="padding:6px 0;"><strong style="color:#fff;">Plan:</strong></td><td>Standard with Ads</td></tr>
        <tr><td style="padding:6px 0;"><strong style="color:#fff;">Amount Due:</strong></td><td style="color:#e50914;font-weight:bold;">₦4,200 / month</td></tr>
        <tr><td style="padding:6px 0;"><strong style="color:#fff;">Payment Failed:</strong></td><td>{{date}}</td></tr>
        <tr><td style="padding:6px 0;"><strong style="color:#fff;">Account:</strong></td><td>{{user_email}}</td></tr>
      </table>
    </div>

    <table cellpadding="0" cellspacing="0" width="100%" style="margin:28px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#e50914;color:#fff;
           padding:16px 48px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:15px;">
          Update Payment Info
        </a>
      </td></tr>
    </table>

    <p style="font-size:13px;color:#666;line-height:1.6;margin:0 0 16px;">
      If we don't receive your payment within <strong style="color:#fff;">7 days</strong>,
      your account will be cancelled and you will lose access to all your profiles, viewing history
      and personalised recommendations.
    </p>

    <hr style="border:none;border-top:1px solid #333;margin:24px 0;"/>
    <p style="font-size:11px;color:#666;margin:0;">
      Netflix International &bull; 100 Winchester Circle, Los Gatos, CA 95032<br/>
      This email was sent to {{user_email}}<br/>
      <a href="{{report_link}}" style="color:#666;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'NIMC: NIN Verification Expiry Notice',
        'attack_type': 'phishing_email',
        'subject': 'NIMC Notice: Your NIN profile requires re-verification before {{date}}',
        'preview_text': 'Your National Identification Number profile is incomplete. Verify now to avoid deactivation.',
        'description': 'Nigerian NIMC impersonation requiring NIN re-verification — highly targeted at Nigerians.',
        'difficulty_level': 3,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#eef2f7" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#006400" style="padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:16px 30px;">
          <p style="margin:0;font-size:15px;font-weight:bold;color:#fff;">NIMC</p>
          <p style="margin:2px 0 0;font-size:11px;color:#90ee90;">National Identity Management Commission</p>
          <p style="margin:1px 0 0;font-size:10px;color:rgba(255,255,255,.6);">Federal Republic of Nigeria</p>
        </td>
        <td align="right" style="padding:16px 30px;">
          <div style="background:rgba(255,255,255,.15);border-radius:4px;padding:6px 12px;">
            <p style="margin:0;font-size:10px;color:#fff;">Official Communication</p>
          </div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Alert bar -->
  <tr><td bgcolor="#cc7700" style="padding:10px 30px;color:#fff;font-size:13px;font-weight:bold;">
    📋 NIN Profile Re-Verification Required
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:14px;color:#333;margin:0 0 14px;">Dear {{user_name}},</p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      Following the National Identity Management Commission (NIMC) Circular No. NIMC/ICT/2024/07,
      all NIN holders are required to update and verify their biometric profiles on the
      <strong>NIMC Self-Service Portal</strong> as part of the national database upgrade exercise.
    </p>
    <div style="background:#f9f9f9;border:1px solid #ddd;border-radius:4px;padding:16px;margin:16px 0;">
      <p style="margin:0 0 8px;font-size:13px;color:#333;font-weight:bold;">Your NIN Profile Status</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">
        <tr><td style="padding:4px 0;color:#555;">Account Email:</td><td style="color:#333;">{{user_email}}</td></tr>
        <tr><td style="padding:4px 0;color:#555;">Verification Status:</td><td style="color:#cc7700;font-weight:bold;">⚠ Pending Update</td></tr>
        <tr><td style="padding:4px 0;color:#555;">Deadline:</td><td style="color:#cc0000;font-weight:bold;">{{date}}</td></tr>
      </table>
    </div>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 14px;">
      Failure to complete re-verification by the deadline may result in your NIN being
      <strong>temporarily deactivated</strong>, which could affect SIM card registration,
      bank account operations, and access to government services.
    </p>
    <table cellpadding="0" cellspacing="0" width="100%" style="margin:20px 0;">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#006400;color:#fff;
           padding:14px 40px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:14px;">
          Verify My NIN Profile
        </a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#aaa;margin:0;">
      NIMC Headquarters &bull; No. 4 Zinguinchor Street, Wuse Zone 5, Abuja &bull; info@nimc.gov.ng<br/>
      Sent to {{user_email}} &bull; <a href="{{report_link}}" style="color:#aaa;">Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'LinkedIn: You Appeared in 14 Searches — Recruiter Message',
        'attack_type': 'spear_phishing',
        'subject': 'You appeared in 14 searches this week — a recruiter left you a message',
        'preview_text': 'Sarah Mitchell from Deloitte Nigeria viewed your profile and sent you a job opportunity.',
        'description': 'LinkedIn recruiter impersonation with a high-paying job offer to harvest credentials.',
        'difficulty_level': 4,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#f3f2ef;font-family:-apple-system,Helvetica,Arial,sans-serif;">
<table width="100%" bgcolor="#f3f2ef" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

  <!-- Header -->
  <tr><td bgcolor="#0a66c2" style="padding:20px 30px;">
    <span style="font-size:22px;font-weight:700;color:#ffffff;letter-spacing:-.5px;">in</span>
    <span style="font-size:16px;font-weight:400;color:#ffffff;margin-left:8px;">LinkedIn</span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:30px;">
    <p style="font-size:15px;color:#191919;margin:0 0 4px;font-weight:600;">Hi {{user_name}},</p>
    <p style="font-size:13px;color:#666;margin:0 0 24px;">Your profile is getting noticed.</p>

    <!-- Search stat -->
    <div style="background:#eef3fb;border-radius:8px;padding:20px;margin:0 0 24px;text-align:center;">
      <p style="margin:0 0 4px;font-size:32px;font-weight:700;color:#0a66c2;">14</p>
      <p style="margin:0;font-size:13px;color:#555;">people searched for you this week</p>
    </div>

    <!-- Recruiter message -->
    <div style="border:1px solid #e0e0e0;border-radius:8px;padding:20px;margin:0 0 24px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="48" valign="top" style="padding-right:14px;">
            <div style="width:48px;height:48px;background:#0a66c2;border-radius:50%;text-align:center;line-height:48px;font-size:18px;color:#fff;font-weight:bold;">S</div>
          </td>
          <td valign="top">
            <p style="margin:0 0 2px;font-size:14px;font-weight:600;color:#191919;">Sarah Mitchell</p>
            <p style="margin:0 0 2px;font-size:13px;color:#555;">Senior Talent Acquisition, Deloitte Nigeria</p>
            <p style="margin:0 0 12px;font-size:12px;color:#888;">2nd connection · 2 hours ago</p>
            <div style="background:#f9f9f9;border-radius:6px;padding:14px;border:1px solid #eee;">
              <p style="margin:0;font-size:13px;color:#333;line-height:1.6;">
                "Hi {{user_name}}, I came across your profile and I'm impressed with your background.
                We have an urgent opening for a <strong>Cybersecurity Analyst</strong> role at Deloitte Nigeria —
                ₦8.5M annual package + benefits. I'd love to share the full JD with you. Are you open to a quick chat?"
              </p>
            </div>
          </td>
        </tr>
      </table>
    </div>

    <table cellpadding="0" cellspacing="0" width="100%" style="margin:0 0 24px;">
      <tr>
        <td align="center" style="padding-right:8px;">
          <a href="{{tracking_link}}" style="display:inline-block;background:#0a66c2;color:#fff;
             padding:12px 28px;text-decoration:none;border-radius:24px;font-weight:600;font-size:14px;">
            Reply to Sarah
          </a>
        </td>
        <td align="center" style="padding-left:8px;">
          <a href="{{tracking_link}}" style="display:inline-block;background:#fff;color:#0a66c2;
             padding:12px 28px;text-decoration:none;border-radius:24px;font-weight:600;font-size:14px;
             border:1.5px solid #0a66c2;">
            View Full Profile
          </a>
        </td>
      </tr>
    </table>

    <hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0;"/>
    <p style="font-size:11px;color:#999;margin:0;text-align:center;">
      This email was intended for {{user_name}} ({{user_email}})<br/>
      LinkedIn Corporation, 1000 West Maude Avenue, Sunnyvale, CA 94085<br/>
      <a href="{{report_link}}" style="color:#999;">Unsubscribe · Report phishing</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'MTN: Free 50GB Data — Loyalty Reward',
        'attack_type': 'prize_lure',
        'subject': '🎁 MTN is giving you FREE 50GB data — claim before midnight tonight',
        'preview_text': 'You have been selected as an MTN loyalty customer. Claim your 50GB free data now.',
        'description': 'MTN free data loyalty reward lure — extremely effective against Nigerian mobile users.',
        'difficulty_level': 2,
        'fake_page_type': 'prize_claim',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#fff200;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" bgcolor="#fff200" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.15);">

  <!-- Header -->
  <tr><td bgcolor="#fff200" style="padding:30px;text-align:center;">
    <div style="display:inline-block;background:#0057a8;border-radius:50%;width:70px;height:70px;line-height:70px;text-align:center;font-size:28px;margin-bottom:12px;">📡</div>
    <h1 style="margin:0 0 4px;font-size:28px;font-weight:900;color:#0057a8;letter-spacing:1px;">MTN</h1>
    <p style="margin:0;font-size:13px;color:#555;font-weight:bold;">EVERYWHERE YOU GO</p>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:32px 30px;text-align:center;">
    <p style="font-size:16px;color:#333;font-weight:bold;margin:0 0 8px;">🎉 Congratulations, {{user_name}}!</p>
    <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 20px;">
      You have been selected as one of our <strong>Top 500 Loyalty Customers</strong> for
      May 2024. As a special thank-you for being a valued MTN customer, we are rewarding you with:
    </p>

    <div style="background:linear-gradient(135deg,#0057a8,#0099cc);border-radius:10px;padding:28px;margin:20px 0;">
      <p style="margin:0 0 4px;font-size:48px;font-weight:900;color:#fff200;">50GB</p>
      <p style="margin:0 0 8px;font-size:18px;color:#ffffff;font-weight:bold;">FREE DATA</p>
      <p style="margin:0;font-size:13px;color:rgba(255,255,255,.8);">Valid for 30 days · No strings attached</p>
    </div>

    <div style="background:#fffde7;border:2px dashed #ffc107;border-radius:8px;padding:16px;margin:20px 0;text-align:left;">
      <p style="margin:0 0 6px;font-size:13px;color:#333;font-weight:bold;">⏳ Offer expires:</p>
      <p style="margin:0 0 4px;font-size:15px;color:#cc0000;font-weight:bold;">{{date}} — 11:59 PM</p>
      <p style="margin:0;font-size:12px;color:#888;">Unclaimed rewards expire and cannot be reissued.</p>
    </div>

    <a href="{{tracking_link}}" style="display:inline-block;background:#0057a8;color:#fff200;
       padding:16px 52px;text-decoration:none;border-radius:8px;font-weight:900;font-size:17px;
       letter-spacing:.5px;margin:8px 0 24px;">
      CLAIM MY 50GB NOW
    </a>

    <p style="font-size:13px;color:#999;margin:0 0 4px;">
      Simply log in with your MTN account to activate your reward.
    </p>
    <p style="font-size:11px;color:#ccc;margin:0;">
      MTN Nigeria Communications Plc &bull; MTN Plaza, Falomo, Ikoyi, Lagos<br/>
      Sent to {{user_email}} &bull; <a href="{{report_link}}" style="color:#ccc;">Report suspicious email</a>
    </p>
  </td></tr>

</table></td></tr>
</table>
</body></html>
""",
    },

    {
        'name': 'IT Support: VPN Access Expiring — Re-authenticate Now',
        'attack_type': 'it_support',
        'subject': '[IT Security] VPN certificate expiring in 2 hours — re-authenticate to maintain access',
        'preview_text': 'Your remote access VPN certificate expires tonight. Re-authenticate to avoid lockout.',
        'description': 'IT/VPN certificate expiry notice targeting remote workers — extremely convincing for corporate targets.',
        'difficulty_level': 4,
        'fake_page_type': 'it_login',
        'body_html': """
<html>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" bgcolor="#0d1117" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:30px 10px;">
<table width="600" bgcolor="#161b22" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden;border:1px solid #30363d;">

  <!-- Header -->
  <tr><td bgcolor="#161b22" style="padding:20px 30px;border-bottom:1px solid #30363d;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td>
          <span style="font-size:14px;font-weight:600;color:#58a6ff;">🔒 IT Security Operations</span><br/>
          <span style="font-size:12px;color:#8b949e;">Automated Security Certificate Alert</span>
        </td>
        <td align="right">
          <span style="background:#da3633;color:#fff;font-size:11px;padding:4px 10px;border-radius:12px;font-weight:600;">URGENT</span>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:28px 30px;">
    <p style="font-size:14px;color:#c9d1d9;margin:0 0 16px;">Hi {{user_name}},</p>

    <div style="background:#1c2128;border:1px solid #da3633;border-radius:6px;padding:16px;margin:0 0 20px;">
      <p style="margin:0 0 6px;font-size:13px;color:#da3633;font-weight:600;">⚠ Certificate Expiry Warning</p>
      <p style="margin:0;font-size:13px;color:#8b949e;line-height:1.6;">
        Your <strong style="color:#c9d1d9;">GlobalProtect VPN certificate</strong> is scheduled to expire in
        <strong style="color:#f0883e;">2 hours 14 minutes</strong>. After expiry, you will be unable to
        connect to the corporate network remotely until manual IT re-provisioning (24-48 hours).
      </p>
    </div>

    <table width="100%" cellpadding="0" cellspacing="0" style="background:#1c2128;border:1px solid #30363d;border-radius:6px;margin:0 0 20px;font-size:12px;color:#8b949e;">
      <tr style="border-bottom:1px solid #30363d;"><td style="padding:10px 16px;">Certificate CN</td><td style="padding:10px 16px;color:#c9d1d9;font-family:monospace;">CORP-VPN-USER-{{user_email}}</td></tr>
      <tr style="border-bottom:1px solid #30363d;"><td style="padding:10px 16px;">Expiry</td><td style="padding:10px 16px;color:#f0883e;font-family:monospace;">{{date}} 23:59:59 UTC</td></tr>
      <tr style="border-bottom:1px solid #30363d;"><td style="padding:10px 16px;">Issuer</td><td style="padding:10px 16px;color:#c9d1d9;font-family:monospace;">Corporate-CA-Root-G3</td></tr>
      <tr><td style="padding:10px 16px;">Action Required</td><td style="padding:10px 16px;color:#3fb950;font-family:monospace;">Re-authenticate</td></tr>
    </table>

    <p style="font-size:14px;color:#c9d1d9;line-height:1.6;margin:0 0 24px;">
      To renew your certificate automatically, click the button below and re-authenticate with
      your corporate credentials. This takes under 60 seconds and requires no IT involvement.
    </p>

    <table cellpadding="0" cellspacing="0" width="100%">
      <tr><td align="center">
        <a href="{{tracking_link}}" style="display:inline-block;background:#238636;color:#ffffff;
           padding:12px 32px;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;
           border:1px solid #2ea043;">
          Re-authenticate VPN Certificate
        </a>
      </td></tr>
    </table>

    <p style="font-size:12px;color:#484f58;margin:24px 0 0;">
      IT Security Operations &bull; Do not reply to this automated message<br/>
      Sent to {{user_email}} &bull; <a href="{{report_link}}" style="color:#484f58;">Report phishing</a>
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
