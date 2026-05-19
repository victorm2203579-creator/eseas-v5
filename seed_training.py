"""
Seed the 5 default training modules and their quiz questions.
Called automatically from app.py when the training_modules table is empty.
Can also be run manually: python seed_training.py
"""

MODULE_1_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">What is Phishing?</h4>
<p>Phishing is one of the most prevalent cybersecurity threats facing individuals and organisations today. It is a form of social engineering where attackers impersonate trustworthy entities — such as your bank, employer, or a popular online service — to trick you into revealing sensitive information. This may include your login credentials, financial details, personal identification numbers (PINs), or one-time passwords.</p>
<p>According to cybersecurity reports, over <strong>3 billion phishing emails</strong> are sent every day, and phishing accounts for more than 80% of reported security incidents. Despite advances in technical defences, phishing remains effective because it targets the most vulnerable part of any system — <strong>the human element</strong>.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Why Phishing Works</h5>
<div class="row g-3 mb-4">
  <div class="col-md-6">
    <div class="card border-0 bg-light h-100 p-3">
      <div class="d-flex align-items-start gap-2">
        <i class="fa-solid fa-clock text-danger mt-1 fa-lg"></i>
        <div><strong>Urgency:</strong> "Your account will be suspended in 2 hours!" forces hasty decisions without careful thought.</div>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 bg-light h-100 p-3">
      <div class="d-flex align-items-start gap-2">
        <i class="fa-solid fa-user-tie text-primary mt-1 fa-lg"></i>
        <div><strong>Authority:</strong> Messages appearing to come from IT, HR, the CEO, or government agencies carry undue trust.</div>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 bg-light h-100 p-3">
      <div class="d-flex align-items-start gap-2">
        <i class="fa-solid fa-triangle-exclamation text-warning mt-1 fa-lg"></i>
        <div><strong>Fear:</strong> Threats of account closure, legal action, or financial loss cloud judgment and override rational thinking.</div>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 bg-light h-100 p-3">
      <div class="d-flex align-items-start gap-2">
        <i class="fa-solid fa-gift text-success mt-1 fa-lg"></i>
        <div><strong>Reward:</strong> Fake prizes, tax refunds, or unclaimed packages attract curious clicks from unsuspecting victims.</div>
      </div>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">7 Warning Signs of a Phishing Email</h5>
<div class="list-group mb-4">
  <div class="list-group-item border-start border-danger border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-danger rounded-pill mt-1 flex-shrink-0">1</span>
      <div><strong>Urgency Language</strong> — Phrases like "Immediate action required", "Your account will be locked", or "Respond within 24 hours" are designed to bypass rational thinking and pressure you into acting before you think.</div>
    </div>
  </div>
  <div class="list-group-item border-start border-danger border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-danger rounded-pill mt-1 flex-shrink-0">2</span>
      <div><strong>Sender Email Mismatch</strong> — The display name may say "PayPal Security" but the actual address is something like <code>noreply@paypa1-alerts.com</code>. Always click on the sender name to see the full email address.</div>
    </div>
  </div>
  <div class="list-group-item border-start border-warning border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-warning text-dark rounded-pill mt-1 flex-shrink-0">3</span>
      <div><strong>Spelling and Grammar Errors</strong> — Many phishing emails contain obvious spelling mistakes or awkward phrasing. Note: AI tools have improved phishing quality, so don't rely solely on this indicator.</div>
    </div>
  </div>
  <div class="list-group-item border-start border-warning border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-warning text-dark rounded-pill mt-1 flex-shrink-0">4</span>
      <div><strong>Suspicious Hover Links</strong> — The visible link text may say "Click here to verify" but hovering reveals a completely different URL destination. Always hover before clicking to see the real URL in your browser's status bar.</div>
    </div>
  </div>
  <div class="list-group-item border-start border-warning border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-warning text-dark rounded-pill mt-1 flex-shrink-0">5</span>
      <div><strong>Unexpected Attachments</strong> — Unsolicited files — especially <code>.exe</code>, <code>.js</code>, <code>.docm</code>, or <code>.xlsm</code> (macro-enabled) — may contain malware. Never open attachments from unknown or unexpected senders.</div>
    </div>
  </div>
  <div class="list-group-item border-start border-secondary border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-secondary rounded-pill mt-1 flex-shrink-0">6</span>
      <div><strong>Generic Greetings</strong> — "Dear Customer", "Dear User", or "Dear Account Holder" suggests a mass campaign. Legitimate services that know you will address you by your full name.</div>
    </div>
  </div>
  <div class="list-group-item border-start border-secondary border-4 mb-2 rounded">
    <div class="d-flex gap-3 align-items-start">
      <span class="badge bg-secondary rounded-pill mt-1 flex-shrink-0">7</span>
      <div><strong>Requests for Passwords or PINs</strong> — No legitimate organisation will ever ask you to provide your password, PIN, or full credit card number via email. This is <em>always</em> a red flag, no exceptions.</div>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How to Check Links Safely</h5>
<ol>
  <li class="mb-2"><strong>Hover first:</strong> Move your mouse over the link without clicking. Your browser shows the real URL in the status bar at the bottom of the screen.</li>
  <li class="mb-2"><strong>Check the domain:</strong> The real domain is the part immediately before the first single slash. In <code>https://login.evil.com/paypal/verify</code>, the domain is <code>evil.com</code> — not "paypal".</li>
  <li class="mb-2"><strong>Use a URL scanner:</strong> Tools like ESEAS, VirusTotal, or Google Safe Browsing let you analyse a URL without visiting it.</li>
  <li class="mb-2"><strong>Go directly:</strong> Instead of clicking, type the official website address directly into your browser's address bar.</li>
</ol>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What to Do When You Receive a Suspicious Email</h5>
<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="card border-0 shadow-sm text-center p-3 h-100" style="border-top:4px solid #dc3545;">
      <i class="fa-solid fa-hand fa-2x text-danger mb-2"></i>
      <strong class="d-block mb-1">Do NOT Click</strong>
      <p class="small text-muted mb-0">Do not click any links or open any attachments, even to "check" if they are real.</p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card border-0 shadow-sm text-center p-3 h-100" style="border-top:4px solid #dc3545;">
      <i class="fa-solid fa-reply fa-2x text-danger mb-2"></i>
      <strong class="d-block mb-1">Do NOT Reply</strong>
      <p class="small text-muted mb-0">Replying confirms your address is active and may invite further targeted attacks.</p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card border-0 shadow-sm text-center p-3 h-100" style="border-top:4px solid #198754;">
      <i class="fa-solid fa-flag fa-2x text-success mb-2"></i>
      <strong class="d-block mb-1">Report It</strong>
      <p class="small text-muted mb-0">Use your email client's phishing report feature and notify your IT security team.</p>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Real-World Phishing Subject Lines</h5>
<div class="table-responsive">
  <table class="table table-sm table-bordered">
    <thead class="table-dark"><tr><th>Subject Line</th><th>What the attacker wants</th></tr></thead>
    <tbody>
      <tr><td>"Your PayPal account has been limited"</td><td>Login credentials</td></tr>
      <tr><td>"Important: Your Microsoft 365 password expires today"</td><td>Corporate account credentials</td></tr>
      <tr><td>"You have an unclaimed package — verify your address"</td><td>Personal info / payment details</td></tr>
      <tr><td>"HR: Pending salary update — confirm your bank details"</td><td>Financial information</td></tr>
      <tr><td>"[IT Support] Immediate action required on your account"</td><td>Corporate network credentials</td></tr>
    </tbody>
  </table>
</div>
<div class="alert alert-success mt-3">
  <i class="fa-solid fa-shield-check me-2"></i>
  <strong>Golden rule:</strong> When in doubt, do not click. Report suspicious emails to your security team — it is always better to be cautious than to be compromised.
</div>
"""

MODULE_2_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">What is Social Engineering?</h4>
<p>Social engineering is the art of manipulating people into divulging confidential information or performing actions that compromise security. Unlike technical hacking, social engineering exploits <strong>human psychology</strong> rather than software vulnerabilities. An attacker who fails to penetrate a firewall may simply call an employee and ask for their password.</p>
<p>Research shows that <strong>over 98% of cyberattacks</strong> rely on some form of social engineering. Understanding the tactics attackers use is the first step towards defending against them.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Cialdini's 6 Principles of Influence — Weaponised</h5>
<p>Psychologist Robert Cialdini identified six universal principles of influence. Attackers routinely exploit these:</p>
<div class="table-responsive mb-4">
  <table class="table table-bordered align-middle">
    <thead class="table-dark"><tr><th>Principle</th><th>How attackers use it</th><th>Example</th></tr></thead>
    <tbody>
      <tr><td><strong>Reciprocity</strong></td><td>Give something first, then ask for something in return</td><td>"We've unlocked your account — just verify your identity to continue"</td></tr>
      <tr><td><strong>Commitment</strong></td><td>Get small agreements before the critical ask</td><td>Multiple "yes" questions before requesting credentials</td></tr>
      <tr><td><strong>Social Proof</strong></td><td>Imply others have already complied</td><td>"Thousands of users have already updated their details"</td></tr>
      <tr><td><strong>Authority</strong></td><td>Impersonate figures of authority</td><td>Claiming to be IT Support, CEO, or a regulator</td></tr>
      <tr><td><strong>Liking</strong></td><td>Build rapport before the attack</td><td>Befriending targets on social media before the con</td></tr>
      <tr><td><strong>Scarcity</strong></td><td>Create artificial urgency or fear of missing out</td><td>"Only 2 hours left before your account is permanently deleted"</td></tr>
    </tbody>
  </table>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Common Social Engineering Attack Vectors</h5>

<div class="accordion mb-4" id="seAccordion">
  <div class="accordion-item">
    <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#se1"><i class="fa-solid fa-masks-theater me-2 text-warning"></i>Pretexting</button></h2>
    <div id="se1" class="accordion-collapse collapse" data-bs-parent="#seAccordion">
      <div class="accordion-body small">Creating a fabricated scenario (a "pretext") to manipulate a target. An attacker may pose as a new IT contractor, a bank auditor, or a delivery person to extract information or gain physical access to a building. The pretext makes the request seem legitimate.</div>
    </div>
  </div>
  <div class="accordion-item">
    <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#se2"><i class="fa-solid fa-usb me-2 text-danger"></i>Baiting</button></h2>
    <div id="se2" class="accordion-collapse collapse" data-bs-parent="#seAccordion">
      <div class="accordion-body small">Leaving infected USB drives in car parks, lifts, or office lobbies labelled "Staff Salaries" or "Confidential". Curious employees who plug them in automatically execute malware. Studies show over 48% of people plug in found USB drives without checking.</div>
    </div>
  </div>
  <div class="accordion-item">
    <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#se3"><i class="fa-solid fa-door-open me-2 text-info"></i>Tailgating (Piggybacking)</button></h2>
    <div id="se3" class="accordion-collapse collapse" data-bs-parent="#seAccordion">
      <div class="accordion-body small">Physically following an authorised person through a secure door without swiping a badge. The attacker may carry boxes or act confident to avoid challenge. Always challenge unfamiliar people in restricted areas.</div>
    </div>
  </div>
  <div class="accordion-item">
    <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#se4"><i class="fa-solid fa-phone me-2 text-danger"></i>Vishing (Voice Phishing)</button></h2>
    <div id="se4" class="accordion-collapse collapse" data-bs-parent="#seAccordion">
      <div class="accordion-body small">Phone-based social engineering where attackers call victims pretending to be IT support, banks, HMRC, or Microsoft. They create urgency ("Your account has been compromised") and request actions such as installing remote access software or transferring funds.</div>
    </div>
  </div>
  <div class="accordion-item">
    <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#se5"><i class="fa-solid fa-handshake me-2 text-warning"></i>Quid Pro Quo</button></h2>
    <div id="se5" class="accordion-collapse collapse" data-bs-parent="#seAccordion">
      <div class="accordion-body small">Offering a service in exchange for information. An attacker posing as IT support calls employees offering free software upgrades in return for login credentials or system access. The "help" is the bait; the credentials are the goal.</div>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Real-World Case Examples</h5>
<ul>
  <li class="mb-2"><strong>Twitter Hack (2020):</strong> Attackers called Twitter employees posing as internal IT staff, convincing them to hand over admin credentials. 130 high-profile accounts including Barack Obama and Elon Musk were hijacked.</li>
  <li class="mb-2"><strong>RSA SecurID Breach (2011):</strong> An employee opened a phishing email titled "2011 Recruitment Plan.xls" — a seemingly routine HR document — which executed malware and eventually compromised RSA's SecurID authentication system.</li>
  <li class="mb-2"><strong>Ubiquiti Networks (2015):</strong> Attackers impersonated executives via email (BEC attack) and convinced the finance team to wire $46.7 million to attacker-controlled accounts.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Defence Strategies</h5>
<ul>
  <li class="mb-2"><strong>Verify through a separate channel:</strong> If someone calls asking for credentials, hang up and call back on a known, official number.</li>
  <li class="mb-2"><strong>Adopt a zero-trust mindset:</strong> Verify even familiar-looking requests. Attackers can spoof emails and caller IDs.</li>
  <li class="mb-2"><strong>Challenge unfamiliar visitors:</strong> Politely ask for ID and escort unknown visitors — this is not rude, it is security awareness.</li>
  <li class="mb-2"><strong>Never plug in unknown devices:</strong> Report found USB drives or hardware to IT without connecting them.</li>
</ul>
<div class="alert alert-warning mt-3">
  <i class="fa-solid fa-brain me-2"></i>
  <strong>Key principle:</strong> Social engineering succeeds when victims act on emotion rather than reason. Slow down, verify, and trust your instincts — if something feels wrong, it probably is.
</div>
"""

MODULE_3_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">Why URL Inspection Matters</h4>
<p>The Uniform Resource Locator (URL) is the address of a web page. A malicious URL that looks legitimate is one of the most powerful tools in a phisher's arsenal. Understanding how to read and analyse URLs is a critical skill for anyone who uses the internet — which is everyone.</p>
<p>Studies show that over <strong>70% of phishing attacks</strong> use HTTPS (the padlock), meaning many people are fooled by the false sense of security it provides. Learning to read URLs properly will protect you from a wide range of attacks.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Anatomy of a URL</h5>
<div class="card border-0 bg-light p-4 mb-4">
  <code class="fs-6">https://secure-login.<span class="text-danger fw-bold">paypa1.com</span>/verify?token=abc123</code>
  <div class="row mt-3 g-2 small">
    <div class="col-md-3"><span class="badge bg-primary me-1">https://</span> Scheme (protocol)</div>
    <div class="col-md-3"><span class="badge bg-secondary me-1">secure-login</span> Subdomain (attacker-controlled)</div>
    <div class="col-md-3"><span class="badge bg-danger me-1">paypa1.com</span> Domain (note "1" not "l")</div>
    <div class="col-md-3"><span class="badge bg-warning text-dark me-1">/verify?token=...</span> Path / query string</div>
  </div>
  <p class="mt-3 mb-0 small text-muted"><strong>Rule:</strong> The real domain is always the part immediately before the first single forward slash — regardless of what subdomains or paths precede or follow it.</p>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Common URL Spoofing Tricks</h5>
<div class="table-responsive mb-4">
  <table class="table table-bordered align-middle">
    <thead class="table-dark"><tr><th>Trick</th><th>Example</th><th>Why it works</th></tr></thead>
    <tbody>
      <tr><td><strong>Typosquatting</strong></td><td><code>micros0ft.com</code>, <code>gooogle.com</code></td><td>People misread quickly scanned text</td></tr>
      <tr><td><strong>Subdomain abuse</strong></td><td><code>paypal.com.login.attacker.net</code></td><td>Legitimate brand appears at the start</td></tr>
      <tr><td><strong>Look-alike TLDs</strong></td><td><code>bank.com.co</code> vs <code>bank.com</code></td><td>Extra extension is easy to miss</td></tr>
      <tr><td><strong>IP addresses</strong></td><td><code>http://192.168.1.105/login</code></td><td>No domain name needed</td></tr>
      <tr><td><strong>URL shorteners</strong></td><td><code>bit.ly/3xYz</code>, <code>t.co/abc</code></td><td>Completely hides the destination</td></tr>
      <tr><td><strong>Homograph attacks</strong></td><td>Cyrillic "а" in place of Latin "a"</td><td>Visually indistinguishable in many fonts</td></tr>
    </tbody>
  </table>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Understanding SSL / HTTPS</h5>
<div class="alert alert-danger">
  <i class="fa-solid fa-triangle-exclamation me-2"></i>
  <strong>Common misconception:</strong> The padlock icon (HTTPS) does NOT mean a website is safe. It only means the connection between your browser and the server is <em>encrypted</em>. Phishing sites can and do obtain SSL certificates — often free ones from Let's Encrypt. Always verify the domain itself, not just the padlock.
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Homograph Attacks Explained</h5>
<p>Unicode contains thousands of characters that look identical to standard Latin letters. Attackers register domains using these alternative characters to create fake-but-convincing addresses:</p>
<ul>
  <li>Latin <code>a</code> vs Cyrillic <code>а</code> (U+0430) — visually identical in most fonts</li>
  <li>Latin <code>o</code> vs Greek <code>ο</code> (U+03BF) — same appearance</li>
  <li><code>аpple.com</code> (Cyrillic а) vs <code>apple.com</code> (Latin a) — different domains, same appearance</li>
</ul>
<p>Modern browsers show a warning for known homograph domains, but this protection is not perfect. Always copy-paste suspicious URLs into a text editor to check for unusual characters.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Safe URL Checking Tools</h5>
<ul>
  <li class="mb-2"><strong>ESEAS URL Scanner</strong> — This platform's built-in ML + VirusTotal + Google Safe Browsing analyser.</li>
  <li class="mb-2"><strong>VirusTotal (virustotal.com)</strong> — Scans URLs against 70+ security engines.</li>
  <li class="mb-2"><strong>Google Safe Browsing</strong> — Checks URLs against Google's list of known malicious sites.</li>
  <li class="mb-2"><strong>CheckShortURL (checkshorturl.com)</strong> — Expands shortened URLs to reveal their true destination before you click.</li>
  <li class="mb-2"><strong>URLScan.io</strong> — Takes a screenshot of a URL and analyses its content and behaviour without you visiting it.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Browser Security Settings to Enable</h5>
<ul>
  <li class="mb-2"><strong>Safe Browsing (Chrome/Firefox/Edge):</strong> Settings → Privacy → Enable Enhanced Safe Browsing. Warns before visiting known phishing/malware sites.</li>
  <li class="mb-2"><strong>HTTPS-Only mode (Firefox/Chrome):</strong> Forces all connections to use HTTPS, blocking plain HTTP sites.</li>
  <li class="mb-2"><strong>Pop-up blocker:</strong> Prevents fake pop-up alerts designed to scare you into calling a fake "support" number.</li>
  <li class="mb-2"><strong>Keep your browser updated:</strong> Updates patch security vulnerabilities that attackers exploit via malicious sites.</li>
</ul>
<div class="alert alert-info mt-3">
  <i class="fa-solid fa-lightbulb me-2"></i>
  <strong>Practical habit:</strong> Before clicking any link in an email, hover to preview the URL. Ask yourself: "Is this the <em>exact</em> official domain I'd expect?" If you're not sure, don't click — go directly to the official website by typing it in your browser.
</div>
"""

MODULE_4_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">Why Password Security Matters</h4>
<p>Passwords are the primary key protecting your digital accounts. Despite years of security advice, weak and reused passwords remain the <strong>number one cause of account breaches</strong>. In 2023 alone, data breaches exposed over 8 billion username and password pairs — many of which were used to gain access to other accounts through automated attacks.</p>
<p>The goal of this module is to help you understand what makes a password strong, how attackers crack passwords, and how to manage your credentials securely.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How Attackers Crack Passwords</h5>
<div class="row g-3 mb-4">
  <div class="col-md-6">
    <div class="card border-0 shadow-sm h-100 p-3">
      <h6 class="fw-bold"><i class="fa-solid fa-list me-2 text-danger"></i>Dictionary Attacks</h6>
      <p class="small text-muted mb-0">Automated tools try millions of common words, names, phrases, and known passwords from breach databases. "password123", "admin", "qwerty" are cracked in under a second.</p>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm h-100 p-3">
      <h6 class="fw-bold"><i class="fa-solid fa-robot me-2 text-warning"></i>Brute Force</h6>
      <p class="small text-muted mb-0">Systematically tries every possible combination. A 6-character password using only lowercase letters can be cracked in seconds. Length dramatically increases security: adding 2 characters multiplies time by 676×.</p>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm h-100 p-3">
      <h6 class="fw-bold"><i class="fa-solid fa-table me-2 text-info"></i>Rainbow Table Attacks</h6>
      <p class="small text-muted mb-0">Pre-computed tables of password hashes allow instant lookup of common passwords. Properly "salted" hashes defeat this attack — another reason to use unique passwords.</p>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm h-100 p-3">
      <h6 class="fw-bold"><i class="fa-solid fa-database me-2 text-danger"></i>Credential Stuffing</h6>
      <p class="small text-muted mb-0">Attackers buy or download billions of leaked username/password pairs and automatically try them on other websites. If you reuse passwords, one breach compromises all your accounts.</p>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Anatomy of a Strong Password</h5>
<div class="card border-0 bg-light p-3 mb-3">
  <p class="mb-2 fw-bold">What makes a password strong:</p>
  <ul class="mb-0">
    <li><strong>Length</strong> — At least 12 characters. Length is the single biggest factor in password strength.</li>
    <li><strong>Complexity</strong> — Mix uppercase, lowercase, numbers, and symbols.</li>
    <li><strong>Uniqueness</strong> — Never reuse a password across different sites or services.</li>
    <li><strong>Randomness</strong> — Avoid personal info (birthdays, pet names) that attackers can research.</li>
  </ul>
</div>
<div class="table-responsive mb-4">
  <table class="table table-bordered table-sm">
    <thead class="table-dark"><tr><th>Password</th><th>Type</th><th>Time to crack (estimate)</th></tr></thead>
    <tbody>
      <tr class="table-danger"><td><code>password</code></td><td>Common word</td><td>Instantly</td></tr>
      <tr class="table-warning"><td><code>P@ssw0rd!</code></td><td>Common substitutions</td><td>Less than 1 hour</td></tr>
      <tr class="table-info"><td><code>Tr0ub4dor&3</code></td><td>Mixed — complex but short</td><td>Days to weeks</td></tr>
      <tr class="table-success"><td><code>correct-horse-battery-staple</code></td><td>Passphrase (4 random words)</td><td>Centuries</td></tr>
    </tbody>
  </table>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">The Passphrase Method</h5>
<p>A passphrase consists of four or more random, unrelated words strung together. It is both highly secure (due to length) and memorable:</p>
<div class="card border-0 bg-light p-3 mb-4 text-center">
  <code class="fs-5">correct-horse-battery-staple-2024!</code>
  <p class="small text-muted mt-2 mb-0">28 characters · Easy to remember · Extremely hard to crack</p>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Password Managers</h5>
<p>A password manager generates, stores, and autofills unique passwords for every account. You only need to remember <em>one</em> strong master password. Recommended options:</p>
<ul>
  <li class="mb-1"><strong>Bitwarden</strong> (open source, free) — excellent for personal and teams</li>
  <li class="mb-1"><strong>1Password</strong> — polished UI, strong business features</li>
  <li class="mb-1"><strong>KeePass</strong> — local storage, fully offline, highly secure</li>
</ul>
<div class="alert alert-info my-3">
  <i class="fa-solid fa-circle-info me-2"></i>
  A password manager is <strong>not a security risk</strong> — it is far safer than reusing weak passwords or writing them on sticky notes. If your master password is strong and unique, your vault is extremely secure.
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Multi-Factor Authentication (MFA)</h5>
<p>MFA adds a second layer of verification beyond your password. Even if an attacker steals your password, they cannot log in without the second factor. MFA prevents over <strong>99.9% of automated attacks</strong> (Microsoft, 2019).</p>
<div class="row g-3 mb-4">
  <div class="col-md-4 text-center">
    <div class="card border-0 bg-light p-3">
      <i class="fa-solid fa-key fa-2x text-warning mb-2"></i>
      <strong>Something you know</strong>
      <p class="small text-muted mb-0">Your password or PIN</p>
    </div>
  </div>
  <div class="col-md-4 text-center">
    <div class="card border-0 bg-light p-3">
      <i class="fa-solid fa-mobile-screen fa-2x text-primary mb-2"></i>
      <strong>Something you have</strong>
      <p class="small text-muted mb-0">Authenticator app, hardware key, SMS code</p>
    </div>
  </div>
  <div class="col-md-4 text-center">
    <div class="card border-0 bg-light p-3">
      <i class="fa-solid fa-fingerprint fa-2x text-success mb-2"></i>
      <strong>Something you are</strong>
      <p class="small text-muted mb-0">Biometrics: fingerprint, face recognition</p>
    </div>
  </div>
</div>
<p class="small text-muted">Prefer authenticator apps (Google Authenticator, Authy) or hardware keys (YubiKey) over SMS codes — SMS is vulnerable to SIM-swapping attacks.</p>
<div class="alert alert-success mt-3">
  <i class="fa-solid fa-check-circle me-2"></i>
  <strong>Action:</strong> Enable MFA on every account that supports it today — start with email, banking, and work accounts.
</div>
"""

MODULE_5_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">Why Your Response Matters</h4>
<p>When a cyberattack occurs, the first few minutes of response are critical. Acting quickly and correctly can be the difference between a minor incident and a major breach. Equally important: knowing what <em>not</em> to do to avoid making the situation worse.</p>
<p>This module walks you through the <strong>immediate steps to take when you suspect an attack</strong>, how to report it, what information to include, and what happens after you report.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Immediate Steps: The DO-NOT List</h5>
<div class="row g-3 mb-4">
  <div class="col-md-6">
    <div class="card border-danger border-2 h-100">
      <div class="card-header bg-danger text-white fw-bold"><i class="fa-solid fa-ban me-2"></i>DO NOT do these things</div>
      <ul class="list-group list-group-flush small">
        <li class="list-group-item"><i class="fa-solid fa-xmark text-danger me-2"></i>Click any links or open attachments in the suspicious email</li>
        <li class="list-group-item"><i class="fa-solid fa-xmark text-danger me-2"></i>Reply to the sender (confirms your address is active)</li>
        <li class="list-group-item"><i class="fa-solid fa-xmark text-danger me-2"></i>Forward the email to colleagues to "warn them" (may spread malware)</li>
        <li class="list-group-item"><i class="fa-solid fa-xmark text-danger me-2"></i>Download any attachments "just to check"</li>
        <li class="list-group-item"><i class="fa-solid fa-xmark text-danger me-2"></i>Enter any credentials on a page reached through the email</li>
        <li class="list-group-item"><i class="fa-solid fa-xmark text-danger me-2"></i>Panic and restart your computer (may destroy evidence)</li>
      </ul>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-success border-2 h-100">
      <div class="card-header bg-success text-white fw-bold"><i class="fa-solid fa-check me-2"></i>DO these things instead</div>
      <ul class="list-group list-group-flush small">
        <li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i>Stay calm — panicking leads to mistakes</li>
        <li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i>Take a screenshot of the suspicious content</li>
        <li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i>Note the time you received it and any actions you took</li>
        <li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i>Report it using your email client's phishing report function</li>
        <li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i>Notify your IT/Security team immediately</li>
        <li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i>If you clicked a link: disconnect from the network and report urgently</li>
      </ul>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How to Report in Your Email Client</h5>
<div class="row g-3 mb-4">
  <div class="col-md-6">
    <div class="card border-0 shadow-sm p-3 h-100">
      <h6 class="fw-bold"><i class="fa-brands fa-google me-2 text-danger"></i>Gmail</h6>
      <ol class="small mb-0">
        <li>Open the suspicious email</li>
        <li>Click the three-dot menu (⋮) in the top-right of the email</li>
        <li>Select <strong>"Report phishing"</strong></li>
        <li>The email is sent to Google's security team</li>
      </ol>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm p-3 h-100">
      <h6 class="fw-bold"><i class="fa-brands fa-microsoft me-2 text-primary"></i>Outlook</h6>
      <ol class="small mb-0">
        <li>Select the suspicious email</li>
        <li>Click the three-dot menu (···) or right-click</li>
        <li>Select <strong>"Report" → "Report phishing"</strong></li>
        <li>Microsoft analyses and removes the email</li>
      </ol>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Who to Notify in Your Organisation</h5>
<ul>
  <li class="mb-2"><strong>IT Help Desk / Security Team:</strong> First point of contact for any suspected security incident. They can investigate, block threats, and advise next steps.</li>
  <li class="mb-2"><strong>Your Line Manager:</strong> Keep them informed, especially if the email targeted you specifically (spear phishing) or involved sensitive business information.</li>
  <li class="mb-2"><strong>Finance Department:</strong> If the email involved financial requests (invoices, wire transfers), the finance team must be notified immediately to halt any potential transactions.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Evidence Preservation Basics</h5>
<p>Before reporting, preserve evidence to help the security team investigate:</p>
<ul>
  <li class="mb-2"><strong>Screenshot the email:</strong> Including the full sender address and any visible URLs.</li>
  <li class="mb-2"><strong>Do not delete the email:</strong> The original email contains headers with metadata useful for tracing the attacker.</li>
  <li class="mb-2"><strong>Note your actions:</strong> Write down exactly what you did — did you hover over a link? Click it? Enter any information? The more detail, the better.</li>
  <li class="mb-2"><strong>Record the timestamp:</strong> When you received it and when you noticed it.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What to Include in Your Report</h5>
<div class="card border-0 bg-light p-3 mb-4">
  <ul class="mb-0 small">
    <li>The original email (forwarded as an attachment if possible, NOT as a regular forward)</li>
    <li>Full sender email address (not just the display name)</li>
    <li>Date and time you received the email</li>
    <li>A description of what the email asked you to do</li>
    <li>Any actions you already took (clicked a link, opened an attachment, entered credentials)</li>
    <li>Whether you saw any unusual system behaviour after any interaction</li>
  </ul>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What Happens After You Report</h5>
<ol>
  <li class="mb-2"><strong>Triage:</strong> The security team assesses the threat level and scope — is this a single targeted email, or part of a broader campaign?</li>
  <li class="mb-2"><strong>Containment:</strong> Blocking the sender, pulling the email from all inboxes, and isolating any affected systems.</li>
  <li class="mb-2"><strong>Investigation:</strong> Analysing email headers, URLs, and attachments to identify indicators of compromise (IoCs).</li>
  <li class="mb-2"><strong>Remediation:</strong> Password resets, system scans, and security patches as needed.</li>
  <li class="mb-2"><strong>Communication:</strong> You will typically be informed of the outcome and any actions you need to take.</li>
</ol>
<div class="alert alert-success mt-3">
  <i class="fa-solid fa-shield-check me-2"></i>
  <strong>Reporting is never weakness</strong> — security teams <em>depend</em> on employees to report suspicious activity. Early reporting limits damage and helps protect your colleagues. You are a critical part of your organisation's security defence.
</div>
"""

MODULE_6_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">What is Spear Phishing?</h4>
<p>Regular phishing casts a wide net — millions of identical emails sent to random recipients. <strong>Spear phishing</strong> is the targeted version: a carefully crafted attack aimed at a specific individual, team, or organisation. The attacker researches the target before striking, making the attack far more convincing and dangerous.</p>
<p>While regular phishing has a click rate of around 3%, spear phishing campaigns achieve click rates of <strong>up to 70%</strong> — because the email appears to come from someone the recipient knows and references real, verifiable details about their life.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How Attackers Research Their Targets</h5>
<p>Attackers use Open Source Intelligence (OSINT) — publicly available information — to build a profile of their target before launching the attack. Sources include:</p>
<ul>
  <li class="mb-2"><strong>LinkedIn:</strong> Job title, employer, colleagues, projects, professional history, skills, and connections.</li>
  <li class="mb-2"><strong>Facebook/Instagram:</strong> Personal interests, family members, holiday dates, location check-ins, and social connections.</li>
  <li class="mb-2"><strong>Twitter/X:</strong> Opinions, affiliations, recent events attended, and public conversations.</li>
  <li class="mb-2"><strong>Company website:</strong> Org charts, team pages, email address formats (firstname.lastname@company.com), and recent news.</li>
  <li class="mb-2"><strong>Breached databases:</strong> Past usernames, passwords, and account details from previous leaks (available on the dark web).</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What Makes Spear Phishing So Convincing</h5>
<div class="card border-0 bg-light p-4 mb-4">
  <p class="mb-2">An attacker targeting a finance officer named Sarah might send:</p>
  <blockquote class="blockquote border-start border-danger border-4 ps-3 mb-0">
    <p class="small mb-0"><em>"Hi Sarah, it's James from IT. As discussed at last Thursday's all-hands meeting, we're rolling out MFA for all finance accounts today. Please click the link below and authenticate before 5pm to avoid losing access. — James Chen, IT Security"</em></p>
  </blockquote>
  <p class="mt-3 mb-0 small text-muted">This email references her name, a real internal process (MFA rollout), a real event (all-hands meeting), uses a real colleague's name and role, and creates urgency. All details gathered from LinkedIn and the company website.</p>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">High-Profile Spear Phishing Cases</h5>
<ul>
  <li class="mb-2"><strong>Operation Aurora (2009):</strong> Attackers targeted specific Google engineers with personalised emails referencing colleagues and internal projects. Led to one of the largest corporate breaches in history.</li>
  <li class="mb-2"><strong>Democratic National Committee Hack (2016):</strong> Spear phishing emails targeting specific campaign staff members were responsible for the breach that dominated global news.</li>
  <li class="mb-2"><strong>Ubiquiti Networks ($46.7M loss):</strong> Attackers researched staff roles and impersonated executives with tailored requests to finance staff.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How to Protect Yourself Against Targeted Attacks</h5>
<ul>
  <li class="mb-2"><strong>Reduce your digital footprint:</strong> Review your LinkedIn privacy settings. Avoid oversharing specifics about internal projects, team names, or processes.</li>
  <li class="mb-2"><strong>Verify unusual requests by phone:</strong> If someone sends an unexpected request — even from a known colleague — call them on a known number to confirm before acting.</li>
  <li class="mb-2"><strong>Be suspicious of flattering or highly personalised emails:</strong> If an email knows specific details about you, it may have been researched. This should raise, not lower, your suspicion.</li>
  <li class="mb-2"><strong>Use MFA:</strong> Even if a spear phishing attack captures your credentials, MFA prevents the attacker from using them.</li>
  <li class="mb-2"><strong>Report unusual emails:</strong> Even if you are not sure, report to IT Security. It is never wrong to check.</li>
</ul>
<div class="alert alert-danger mt-3">
  <i class="fa-solid fa-crosshairs me-2"></i>
  <strong>Remember:</strong> Spear phishing works because it feels personal and credible. The more an email seems to "know" you, the more carefully you should verify it before taking any action.
</div>
"""

MODULE_7_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">What is Smishing?</h4>
<p>Smishing is <strong>phishing delivered via SMS text messages</strong>. The name combines "SMS" and "phishing". As email security has improved and spam filters have become more effective, attackers have moved to text messages — which most people trust more than email and which lack the same level of filtering protection.</p>
<p>Studies show that <strong>SMS open rates are around 98%</strong>, compared to approximately 20% for email. Text messages also create a sense of immediacy — most people read a text within three minutes of receiving it. Attackers exploit this reflex to create urgency and drive impulsive clicks.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Common Smishing Lures</h5>
<div class="row g-3 mb-4">
  <div class="col-md-6">
    <div class="card border-0 shadow-sm p-3 h-100 border-start border-danger border-3">
      <strong class="d-block mb-2"><i class="fa-solid fa-box me-2 text-danger"></i>Fake Delivery Notifications</strong>
      <p class="small mb-1">"Your Royal Mail parcel is held due to an unpaid customs fee. Pay £1.45 to release it: [link]"</p>
      <p class="small text-muted mb-0">Attackers send these en masse, knowing that many recipients will have a genuine delivery in transit.</p>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm p-3 h-100 border-start border-danger border-3">
      <strong class="d-block mb-2"><i class="fa-solid fa-building-columns me-2 text-danger"></i>Bank Fraud Alerts</strong>
      <p class="small mb-1">"HSBC: Suspicious login detected on your account. Verify immediately or your account will be frozen: [link]"</p>
      <p class="small text-muted mb-0">Creates panic about financial security to drive immediate action without careful thought.</p>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm p-3 h-100 border-start border-warning border-3">
      <strong class="d-block mb-2"><i class="fa-solid fa-trophy me-2 text-warning"></i>Prize Notifications</strong>
      <p class="small mb-1">"Congratulations! You've been selected for an Amazon Gift Card worth £500. Claim in 24 hours: [link]"</p>
      <p class="small text-muted mb-0">Exploits excitement and the fear of missing out on something valuable.</p>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card border-0 shadow-sm p-3 h-100 border-start border-warning border-3">
      <strong class="d-block mb-2"><i class="fa-solid fa-landmark me-2 text-warning"></i>Government Impersonation</strong>
      <p class="small mb-1">"HMRC: You are owed a tax refund of £312.50. Claim via: [link] — expires in 48hrs"</p>
      <p class="small text-muted mb-0">Exploits trust in authority figures to bypass scepticism.</p>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What is Vishing?</h5>
<p>Vishing is <strong>voice phishing — social engineering conducted over phone calls</strong>. Attackers call victims while impersonating IT support teams, bank fraud departments, government agencies (HMRC, DVLA), or well-known companies (Microsoft, Amazon).</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Common Vishing Scripts</h5>
<ul>
  <li class="mb-3"><strong>"Microsoft Technical Support":</strong> Caller claims your computer has been infected with a virus they can detect remotely. They ask you to install remote access software (like AnyDesk or TeamViewer) to fix the problem — then steal your data or deploy ransomware.</li>
  <li class="mb-3"><strong>"Bank Fraud Team":</strong> Claims suspicious transactions have been made from your account. Asks you to read out your card number, PIN, or one-time passcode "to verify your identity". Legitimate banks will NEVER ask for your PIN or OTP.</li>
  <li class="mb-3"><strong>"IT Department":</strong> Asks for your login credentials to "reset your profile" or "investigate a security alert" on your account. Your IT team will never need your password.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Red Flags in Suspicious Calls and Texts</h5>
<ul>
  <li class="mb-2">Unexpected contact about an issue you did not raise yourself</li>
  <li class="mb-2">Urgency — "must act now", "24 hours", "immediate suspension"</li>
  <li class="mb-2">Request for passwords, PINs, or one-time codes — legitimate organisations never ask for these</li>
  <li class="mb-2">Request to install software, especially remote access tools</li>
  <li class="mb-2">A number you don't recognise, or a withheld number</li>
  <li class="mb-2">Caller reads back personal details to "prove they are real" — this information may be from a public breach</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What To Do</h5>
<ul>
  <li class="mb-2">For suspicious texts: <strong>Do not click any links.</strong> If it appears to be from a real company, contact them directly via their official website or a number you already know.</li>
  <li class="mb-2">For suspicious calls: <strong>Hang up.</strong> Then call the organisation back on a number from their official website — not a number the caller gives you.</li>
  <li class="mb-2">Never share passwords, PINs, or OTPs over phone or text, regardless of how official the caller sounds.</li>
</ul>
"""

MODULE_8_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">Why Fake Websites Are So Dangerous</h4>
<p>Modern phishing attacks rarely rely on just a suspicious email — they direct victims to convincing fake websites that look identical to legitimate ones. With free website building tools, stolen CSS, and automated site-cloning software, attackers can recreate a pixel-perfect copy of any website in under an hour.</p>
<p>Once on a fake website, victims willingly type in their credentials, payment card details, or personal information — believing they are on the real site. The attacker captures everything entered on the page in real time.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How Attackers Clone Websites</h5>
<ul>
  <li class="mb-2"><strong>HTTrack / website copiers:</strong> Tools that download every file from a real website — HTML, CSS, images, fonts — to create a local copy that looks identical.</li>
  <li class="mb-2"><strong>Manual copying:</strong> Attacker opens the real site, saves the HTML source, and hosts it on their own domain. The logo, layout, and styling are all from the original.</li>
  <li class="mb-2"><strong>Reverse proxy attacks:</strong> The fake site forwards legitimate content from the real site in real time, only capturing the credentials entered by the victim. The victim sees and interacts with the real content — making detection extremely difficult.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Spotting the Differences: Domain Inspection</h5>
<div class="table-responsive mb-4">
  <table class="table table-bordered align-middle">
    <thead class="table-dark"><tr><th>Legitimate URL</th><th>Fake URL</th><th>Trick Used</th></tr></thead>
    <tbody>
      <tr><td>paypal.com</td><td>paypa1.com</td><td>Number "1" replacing letter "l"</td></tr>
      <tr><td>netflix.com</td><td>netflix-login.com</td><td>Hyphen with added word</td></tr>
      <tr><td>amazon.co.uk</td><td>amazon.co.uk.login-verify.net</td><td>Real domain used as subdomain</td></tr>
      <tr><td>hsbc.com</td><td>hsbc.com-secure.xyz</td><td>Hyphen + fake TLD</td></tr>
      <tr><td>apple.com</td><td>аpple.com (Cyrillic "а")</td><td>Homograph — visually identical</td></tr>
    </tbody>
  </table>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">The HTTPS Misconception — Again</h5>
<div class="alert alert-danger">
  <i class="fa-solid fa-triangle-exclamation me-2"></i>
  <strong>Fake websites can have padlocks (HTTPS).</strong> Over 80% of phishing websites now use HTTPS with a valid SSL certificate — many obtained for free. The padlock only confirms the connection is encrypted. It says nothing about whether the site itself is legitimate. Always verify the domain, not just the padlock.
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Visual Clues of Fake Pages</h5>
<ul>
  <li class="mb-2"><strong>Slightly off branding:</strong> Colours that do not quite match, logos that are lower resolution, or layouts that feel slightly "wrong".</li>
  <li class="mb-2"><strong>Broken links:</strong> On clone sites, clicking most links either goes nowhere or redirects to the real site — only the login form is functional.</li>
  <li class="mb-2"><strong>Generic login forms:</strong> The form may not have the autofill your password manager normally provides — because the domain is different.</li>
  <li class="mb-2"><strong>No personalisation:</strong> Your real bank's website may greet you by name after you enter your username — fake sites typically don't have access to this.</li>
</ul>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How to Verify You Are on the Real Site</h5>
<ol>
  <li class="mb-2"><strong>Check the full URL in the address bar</strong> — not just the page content or padlock.</li>
  <li class="mb-2"><strong>Use bookmarks for important accounts</strong> — navigate to your bank, email, and other critical accounts only through saved bookmarks you created yourself.</li>
  <li class="mb-2"><strong>Let your password manager guide you</strong> — a reputable password manager will only autofill on the exact domain it saved the password for. If it doesn't autofill, that's a warning sign the domain is different.</li>
  <li class="mb-2"><strong>Check the certificate details</strong> — click the padlock and check the certificate issuer. Major banks will typically have Extended Validation (EV) certificates showing the organisation name.</li>
</ol>
<div class="alert alert-info mt-3">
  <i class="fa-solid fa-bookmark me-2"></i>
  <strong>Best practice:</strong> For your online banking and critical accounts — bookmark the real URL yourself, right now. Never navigate to your bank through search results or links in emails.
</div>
"""

MODULE_9_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">Why Email Attachments Are a Major Threat Vector</h4>
<p>Email attachments remain one of the most effective malware delivery mechanisms available to attackers. A well-crafted phishing email with a malicious attachment can deploy ransomware, spyware, or remote access trojans with a single click — bypassing many network-level defences because the malicious code arrives inside a trusted file format.</p>
<p>According to cybersecurity research, <strong>over 90% of malware is delivered via email</strong>, with attachments being the primary vehicle. Understanding which file types are dangerous and how attackers use them is essential for everyone who uses email.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Dangerous File Types to Know</h5>
<div class="table-responsive mb-4">
  <table class="table table-bordered align-middle">
    <thead class="table-dark"><tr><th>Extension</th><th>File Type</th><th>Risk</th></tr></thead>
    <tbody>
      <tr><td><code>.exe</code></td><td>Executable</td><td class="text-danger fw-bold">Critical — runs code immediately on double-click</td></tr>
      <tr><td><code>.vbs</code> / <code>.js</code></td><td>Script files</td><td class="text-danger fw-bold">Critical — executes scripts that download malware</td></tr>
      <tr><td><code>.docm</code> / <code>.xlsm</code></td><td>Office with macros</td><td class="text-danger fw-bold">High — macros can execute arbitrary commands</td></tr>
      <tr><td><code>.pdf</code></td><td>PDF document</td><td class="text-warning fw-bold">Medium — can contain malicious scripts or links</td></tr>
      <tr><td><code>.docx</code> / <code>.xlsx</code></td><td>Office documents</td><td class="text-warning fw-bold">Medium — can embed malicious links or OLE objects</td></tr>
      <tr><td><code>.zip</code> / <code>.rar</code></td><td>Archives</td><td class="text-warning fw-bold">Medium — may contain any of the above hidden inside</td></tr>
      <tr><td><code>.iso</code></td><td>Disk image</td><td class="text-warning fw-bold">Medium — increasingly used to bypass AV detection</td></tr>
    </tbody>
  </table>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">The Macro Threat — Never Enable Macros from Unknown Sources</h5>
<p>Microsoft Office macros are small programs embedded inside Word, Excel, and PowerPoint files. They were designed for legitimate automation, but attackers abuse them to execute malicious code the moment you click "Enable Content".</p>
<div class="alert alert-danger mb-4">
  <i class="fa-solid fa-ban me-2"></i>
  <strong>The golden rule:</strong> Never enable macros in a document received via email unless you specifically requested a macro-enabled file from a trusted source and have separately verified its authenticity.
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">How Email Spoofing Works</h5>
<p>Attackers can forge the "From" field in an email to make it appear to come from any address — including addresses inside your own organisation. This is called <strong>email spoofing</strong>. Three protocols exist to combat it:</p>
<ul>
  <li class="mb-2"><strong>SPF (Sender Policy Framework):</strong> Specifies which mail servers are authorised to send email on behalf of a domain. An email from an unauthorised server fails SPF.</li>
  <li class="mb-2"><strong>DKIM (DomainKeys Identified Mail):</strong> Adds a cryptographic signature to each email that proves it was sent by an authorised server and not modified in transit.</li>
  <li class="mb-2"><strong>DMARC (Domain-based Message Authentication):</strong> Tells receiving servers what to do when SPF and DKIM checks fail — reject, quarantine, or report.</li>
</ul>
<p class="small text-muted">Most major email providers check these automatically. However, domains without proper SPF/DKIM/DMARC setup can still receive spoofed emails. Never trust an email based solely on the sender display name.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Safe Practices for Email Attachments</h5>
<ul>
  <li class="mb-2"><strong>Verify before opening:</strong> Contact the sender through a separate channel (phone call, separate email) to confirm they sent you an attachment before opening it.</li>
  <li class="mb-2"><strong>Use sandboxing tools:</strong> Services like Any.run or Joe Sandbox allow you to execute files in an isolated virtual environment to observe behaviour without risk.</li>
  <li class="mb-2"><strong>Check the sender address carefully:</strong> Not just the display name — click on it to see the full email address.</li>
  <li class="mb-2"><strong>Open in Protected View:</strong> When Office opens a downloaded document in Protected View, keep it in Protected View. This prevents macros from executing.</li>
  <li class="mb-2"><strong>Preview when possible:</strong> Google Drive and OneDrive allow you to preview documents online without downloading them — safer than opening locally.</li>
</ul>
"""

MODULE_10_HTML = """
<h4 class="fw-bold mb-3" style="color:var(--navy)">Why a Password Alone Is No Longer Enough</h4>
<p>Even a long, complex, unique password provides no protection if it is stolen via a phishing attack, purchased from a breach database, or guessed through credential stuffing. <strong>Multi-Factor Authentication (MFA)</strong> — also called Two-Factor Authentication (2FA) — solves this problem by requiring a second proof of identity beyond the password.</p>
<p>According to Microsoft, MFA blocks <strong>over 99.9% of automated account compromise attacks</strong>. Even if an attacker obtains your password, they cannot access your account without the second factor. MFA is the single most impactful action you can take to protect your accounts.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">The Three Authentication Factors</h5>
<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="card border-0 shadow-sm h-100 text-center p-3">
      <i class="fa-solid fa-brain fa-2x mb-2" style="color:var(--navy)"></i>
      <strong class="d-block mb-1">Something You Know</strong>
      <p class="small text-muted mb-0">Password, PIN, security question answer</p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card border-0 shadow-sm h-100 text-center p-3">
      <i class="fa-solid fa-mobile-screen fa-2x mb-2 text-primary"></i>
      <strong class="d-block mb-1">Something You Have</strong>
      <p class="small text-muted mb-0">Authenticator app, hardware key (YubiKey), SMS code, smart card</p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card border-0 shadow-sm h-100 text-center p-3">
      <i class="fa-solid fa-fingerprint fa-2x mb-2 text-success"></i>
      <strong class="d-block mb-1">Something You Are</strong>
      <p class="small text-muted mb-0">Fingerprint, face recognition, retina scan</p>
    </div>
  </div>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">MFA Methods Compared: Weakest to Strongest</h5>
<div class="table-responsive mb-4">
  <table class="table table-bordered align-middle">
    <thead class="table-dark"><tr><th>Method</th><th>How It Works</th><th>Strength</th><th>Weakness</th></tr></thead>
    <tbody>
      <tr><td>SMS Code</td><td>6-digit code sent by text</td><td class="text-warning">Moderate</td><td>Vulnerable to SIM swapping and real-time phishing</td></tr>
      <tr><td>Email OTP</td><td>Code sent to your email</td><td class="text-warning">Moderate</td><td>Only as secure as your email account</td></tr>
      <tr><td>Authenticator App</td><td>Time-based 6-digit code (TOTP)</td><td class="text-success">Strong</td><td>Codes can be intercepted by real-time phishing proxies</td></tr>
      <tr><td>Push Notification</td><td>Approve on your phone app</td><td class="text-success">Strong</td><td>MFA fatigue attacks (spamming approval requests)</td></tr>
      <tr><td>Hardware Key (FIDO2)</td><td>Physical USB/NFC key</td><td class="text-success fw-bold">Strongest</td><td>Must physically carry the key; costs money</td></tr>
    </tbody>
  </table>
</div>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">SIM Swapping — Why SMS MFA Is Weaker</h5>
<p>SIM swapping is an attack where the attacker contacts your mobile network provider, impersonates you, and convinces them to transfer your phone number to a SIM card the attacker controls. Once they have your number, they receive all your SMS codes and can access accounts that rely solely on SMS MFA.</p>
<p>High-profile victims of SIM swap attacks include cryptocurrency investors who lost millions and celebrities whose social media accounts were hijacked. Where possible, <strong>use an authenticator app instead of SMS codes</strong>.</p>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">Setting Up MFA — Recommended Steps</h5>
<ol>
  <li class="mb-2">Download an authenticator app (Google Authenticator, Microsoft Authenticator, or Authy — Authy has cloud backup).</li>
  <li class="mb-2">Go to your account's security settings (look for "Two-Factor Authentication", "Two-Step Verification", or "MFA").</li>
  <li class="mb-2">Choose "Authenticator App" as your method (not SMS if avoidable).</li>
  <li class="mb-2">Scan the QR code with the app.</li>
  <li class="mb-2">Save the one-time backup codes in a secure location (password manager or printed and locked away).</li>
  <li class="mb-2">Enable MFA on <em>every</em> account that supports it, prioritising email, banking, and work accounts.</li>
</ol>

<h5 class="fw-bold mt-4 mb-3" style="color:var(--navy)">What to Do If You Lose MFA Access</h5>
<ul>
  <li class="mb-2"><strong>Use your backup codes:</strong> Saved during setup, these one-time codes let you log in when your authenticator app is unavailable.</li>
  <li class="mb-2"><strong>Account recovery:</strong> Most services offer recovery via a trusted email, backup phone number, or identity verification process.</li>
  <li class="mb-2"><strong>Contact support:</strong> If all else fails, contact the service's support team with identity verification documents.</li>
</ul>
<div class="alert alert-success mt-3">
  <i class="fa-solid fa-key me-2"></i>
  <strong>Action now:</strong> Enable MFA on your email account today. Your email is the master key to all your other accounts — if an attacker controls it, they can reset every other password you have.
</div>
"""

MODULES = [
    {
        'title': 'How to Spot a Phishing Email',
        'description': 'Learn to identify phishing emails through 7 key warning signs, link checking techniques, and real-world examples of deceptive subject lines.',
        'topic': 'phishing',
        'content_html': MODULE_1_HTML,
        'order_index': 1,
        'estimated_minutes': 10,
        'icon_class': 'fa-envelope-open-text',
        'quiz': [
            {
                'question_text': 'Which of the following is the clearest sign of a phishing email?',
                'option_a': 'The email was sent at an unusual time of day',
                'option_b': 'The email contains an urgent request to "verify your account immediately" or face suspension',
                'option_c': 'The email has professional formatting and a company logo',
                'option_d': 'The email is addressed to your full name',
                'correct_option': 'b',
                'explanation': 'Urgency is the most common phishing tactic. Phrases like "verify immediately" or "account will be suspended" are designed to pressure victims into acting before thinking rationally.',
            },
            {
                'question_text': 'You receive an email from "security@paypa1.com" asking you to reset your password. What should you do FIRST?',
                'option_a': 'Click the reset link immediately to protect your account',
                'option_b': 'Check whether the sender domain is the genuine paypal.com domain',
                'option_c': 'Reply to the email to ask if it is legitimate',
                'option_d': 'Forward it to your colleagues to warn them',
                'correct_option': 'b',
                'explanation': 'Phishers use look-alike domains like "paypa1.com" (with a digit "1" instead of "l"). Always verify the full sender email address — not just the display name — before taking any action.',
            },
            {
                'question_text': 'What does hovering your cursor over a link (without clicking) allow you to detect?',
                'option_a': 'Whether the email contains a virus in its code',
                'option_b': 'How long the email has been in your inbox',
                'option_c': 'The actual destination URL before you click it',
                'option_d': 'Whether the sender is in your contacts list',
                'correct_option': 'c',
                'explanation': 'Hovering reveals the real URL in your browser\'s status bar, which may be completely different from the displayed link text. This is one of the most important habits for spotting phishing links.',
            },
            {
                'question_text': 'Which action is the SAFEST when you receive an unexpected email with an urgent attachment?',
                'option_a': 'Open the attachment quickly to see if it is important',
                'option_b': 'Reply to the sender asking whether the attachment is real',
                'option_c': 'Delete the email and report it to your IT security team without opening anything',
                'option_d': 'Save the attachment to a USB drive and open it on another computer',
                'correct_option': 'c',
                'explanation': 'Never open attachments from unexpected or suspicious senders. Reporting to IT without opening anything preserves evidence and prevents potential malware execution.',
            },
            {
                'question_text': 'Why do phishing emails often use generic greetings like "Dear Customer" instead of your name?',
                'option_a': 'Because generic greetings are considered more professional',
                'option_b': 'Because regulations require impersonal language in security emails',
                'option_c': 'Because attackers send mass emails to thousands of victims and do not know recipients\' names',
                'option_d': 'Because personalised emails are more likely to be blocked by spam filters',
                'correct_option': 'c',
                'explanation': 'Mass phishing campaigns target thousands of victims simultaneously. Attackers do not have your name, so they use generic greetings. Legitimate services that hold your data will always address you personally.',
            },
        ],
    },
    {
        'title': 'Social Engineering Tactics Explained',
        'description': 'Understand how attackers exploit psychological principles and human trust through pretexting, vishing, baiting, tailgating, and real-world attack case studies.',
        'topic': 'social_engineering',
        'content_html': MODULE_2_HTML,
        'order_index': 2,
        'estimated_minutes': 12,
        'icon_class': 'fa-user-secret',
        'quiz': [
            {
                'question_text': 'What is "pretexting" in social engineering?',
                'option_a': 'Sending a pre-written phishing email template',
                'option_b': 'Creating a fabricated scenario to build trust and manipulate a target into disclosing information',
                'option_c': 'Previewing a phishing message before sending it',
                'option_d': 'Testing a phishing link to confirm it works',
                'correct_option': 'b',
                'explanation': 'Pretexting involves fabricating a believable scenario (e.g., pretending to be an IT contractor, bank auditor, or new employee) to lower the target\'s defences and extract sensitive information.',
            },
            {
                'question_text': 'Which Cialdini principle is exploited when an attacker says: "Only 3 accounts left — update yours NOW before it expires"?',
                'option_a': 'Authority',
                'option_b': 'Liking',
                'option_c': 'Scarcity',
                'option_d': 'Reciprocity',
                'correct_option': 'c',
                'explanation': 'The scarcity principle creates a fear of missing out or losing something valuable. Attackers use artificial urgency and limited availability to pressure victims into acting without thinking.',
            },
            {
                'question_text': 'What is "vishing"?',
                'option_a': 'Phishing conducted through social media direct messages',
                'option_b': 'Voice phishing — manipulating victims through phone calls by impersonating a trusted entity',
                'option_c': 'Phishing using visual images or videos to deceive victims',
                'option_d': 'A technique for stealing Wi-Fi network credentials',
                'correct_option': 'b',
                'explanation': 'Vishing (voice phishing) involves attackers calling victims while impersonating IT support, banks, government agencies, or Microsoft. They create urgency and request remote access or credentials.',
            },
            {
                'question_text': 'You find a USB drive in your organisation\'s car park labelled "Staff Payroll Q3". What is the correct action?',
                'option_a': 'Plug it into a personal device to see if it contains anything interesting',
                'option_b': 'Leave it where you found it so the owner can collect it',
                'option_c': 'Hand it to IT or Security without connecting it to any device',
                'option_d': 'Plug it into a work computer but keep antivirus running',
                'correct_option': 'c',
                'explanation': 'Infected USB drives ("baiting") are a classic social engineering technique. The label is designed to provoke curiosity. Never plug in unknown devices — hand them directly to IT Security.',
            },
            {
                'question_text': 'What is the BEST overall defence against social engineering attacks?',
                'option_a': 'Installing the latest antivirus software',
                'option_b': 'Using a VPN for all internet connections',
                'option_c': 'Being appropriately sceptical and verifying unusual requests through official, separate channels',
                'option_d': 'Never answering calls from unknown numbers',
                'correct_option': 'c',
                'explanation': 'Social engineering exploits human psychology, not technology. The best defence is awareness, a healthy scepticism, and always verifying requests through a known, separate communication channel before acting.',
            },
        ],
    },
    {
        'title': 'Safe Browsing and URL Inspection',
        'description': 'Master URL anatomy, detect spoofing tricks including homograph attacks and URL shorteners, and configure your browser for maximum security.',
        'topic': 'safe_browsing',
        'content_html': MODULE_3_HTML,
        'order_index': 3,
        'estimated_minutes': 8,
        'icon_class': 'fa-globe',
        'quiz': [
            {
                'question_text': 'In the URL "https://secure-paypal.com.login.phishing.co/verify", what is the REAL domain?',
                'option_a': 'paypal.com',
                'option_b': 'secure-paypal.com',
                'option_c': 'phishing.co',
                'option_d': 'login.phishing.co',
                'correct_option': 'c',
                'explanation': 'The real domain is always the part immediately before the first single forward slash — in this URL that is "phishing.co". Everything before it (secure-paypal.com.login) is a subdomain that the attacker controls to make it look legitimate.',
            },
            {
                'question_text': 'What does the padlock icon (HTTPS) in a browser\'s address bar actually confirm?',
                'option_a': 'The website has been verified as safe and legitimate by a government authority',
                'option_b': 'The data transmitted between your browser and the server is encrypted',
                'option_c': 'The website cannot contain phishing content',
                'option_d': 'Your password is protected from being stolen on this site',
                'correct_option': 'b',
                'explanation': 'HTTPS only means the connection is encrypted in transit. Phishing sites can and do obtain SSL certificates for free. The padlock does NOT confirm a website is legitimate or safe to use.',
            },
            {
                'question_text': 'What is a homograph attack in the context of domain names?',
                'option_a': 'Copying the visual layout of a legitimate website to create a fake one',
                'option_b': 'Using visually identical characters from different alphabets (e.g., Cyrillic) to register look-alike domains',
                'option_c': 'An attack that targets graphic design elements of a website',
                'option_d': 'Registering a domain name that is one character longer than the original',
                'correct_option': 'b',
                'explanation': 'Homograph attacks use Unicode characters from other alphabets (like Cyrillic "а" or Greek "ο") that look identical to Latin letters. The domain may appear identical to the legitimate one but goes to a completely different server.',
            },
            {
                'question_text': 'Why should you be cautious before clicking a shortened URL like "bit.ly/3xYzAB"?',
                'option_a': 'Shortened URLs always expire after 24 hours',
                'option_b': 'URL shorteners are illegal in some jurisdictions',
                'option_c': 'The shortener completely hides the real destination URL until after you click',
                'option_d': 'Shortened URLs are automatically blocked by all security tools',
                'correct_option': 'c',
                'explanation': 'URL shorteners mask the actual destination, preventing you from seeing if it is safe before clicking. Use a URL expander (like CheckShortURL) to preview the full destination before clicking any shortened link.',
            },
            {
                'question_text': 'Which browser security feature specifically warns you before visiting known phishing and malware websites?',
                'option_a': 'Private / Incognito browsing mode',
                'option_b': 'Blocking all third-party cookies',
                'option_c': 'Safe Browsing / Enhanced Protection (available in Chrome, Firefox, Edge)',
                'option_d': 'Disabling JavaScript globally',
                'correct_option': 'c',
                'explanation': 'Safe Browsing (Enhanced Protection in Chrome) checks URLs against Google\'s continuously updated database of known phishing and malware sites and warns you before you visit them.',
            },
        ],
    },
    {
        'title': 'Password Security Best Practices',
        'description': 'Understand password cracking techniques, build strong passphrases, use password managers effectively, and enable multi-factor authentication.',
        'topic': 'passwords',
        'content_html': MODULE_4_HTML,
        'order_index': 4,
        'estimated_minutes': 10,
        'icon_class': 'fa-lock',
        'quiz': [
            {
                'question_text': 'Which of the following is the STRONGEST password?',
                'option_a': 'Password123!',
                'option_b': 'P@$$w0rd',
                'option_c': 'MyD0g!sN4med$am',
                'option_d': 'correct-horse-battery-staple-2024!',
                'correct_option': 'd',
                'explanation': 'A long passphrase (4+ random words with numbers/symbols) is both highly secure due to its length and much easier to remember. Length is the most important factor in password strength — this passphrase has 34 characters.',
            },
            {
                'question_text': 'What is "credential stuffing"?',
                'option_a': 'A technique for generating very long and complex passwords',
                'option_b': 'Writing passwords on paper and storing them securely',
                'option_c': 'Using leaked username and password pairs from one breach to try to access other websites automatically',
                'option_d': 'Adding extra characters to an existing password to make it stronger',
                'correct_option': 'c',
                'explanation': 'When a website is breached, attackers sell or publish the stolen credentials. Automated tools then try these same username/password pairs across hundreds of other sites. This is why every account MUST have a unique password.',
            },
            {
                'question_text': 'What is the PRIMARY security benefit of a password manager?',
                'option_a': 'It automatically changes your passwords every 30 days',
                'option_b': 'It lets you generate and use a unique, complex password for every account without needing to remember them',
                'option_c': 'It warns you when a website is a phishing site',
                'option_d': 'It stores your passwords on a USB drive for portability',
                'correct_option': 'b',
                'explanation': 'A password manager generates cryptographically random, unique passwords for every site. You only memorise one strong master password. This eliminates password reuse — the primary cause of credential stuffing attacks.',
            },
            {
                'question_text': 'What does Multi-Factor Authentication (MFA) add to your account security?',
                'option_a': 'A requirement to use a longer password',
                'option_b': 'An additional verification step beyond the password, so stolen passwords alone cannot grant access',
                'option_c': 'Automatic password rotation every month',
                'option_d': 'Biometric authentication only — face recognition or fingerprint',
                'correct_option': 'b',
                'explanation': 'MFA requires something you know (password) PLUS something you have (authenticator app, hardware key) or something you are (biometrics). Even if your password is stolen, an attacker cannot log in without the second factor.',
            },
            {
                'question_text': 'How do attackers perform "dictionary attacks" on stolen password databases?',
                'option_a': 'By reading through an actual dictionary for inspiration',
                'option_b': 'By systematically trying lists of common passwords, words, names, and known leaked passwords',
                'option_c': 'By guessing every possible combination of letters and numbers',
                'option_d': 'By using keyloggers installed on victim computers',
                'correct_option': 'b',
                'explanation': 'Dictionary attacks use pre-built wordlists containing millions of common passwords, names, phrases, and known leaked credentials. Passwords like "password123", "admin", or "iloveyou" are cracked in under a second.',
            },
        ],
    },
    {
        'title': 'What To Do When You Suspect an Attack',
        'description': 'Learn the correct immediate steps when you suspect phishing, how to report in Gmail and Outlook, what evidence to preserve, and what happens after you report.',
        'topic': 'incident_response',
        'content_html': MODULE_5_HTML,
        'order_index': 5,
        'estimated_minutes': 8,
        'icon_class': 'fa-shield-halved',
        'quiz': [
            {
                'question_text': 'You receive a suspicious email with a link claiming your account needs urgent verification. What should you do FIRST?',
                'option_a': 'Click the link to check whether it is a real threat',
                'option_b': 'Forward the email to your colleagues to warn them about it',
                'option_c': 'Do NOT click anything — take a screenshot and report it to IT Security immediately',
                'option_d': 'Reply to the sender asking whether the email is legitimate',
                'correct_option': 'c',
                'explanation': 'Clicking the link could execute malware or harvest credentials. Forwarding can spread the attack. Replying confirms your address is active. The correct action is always to not interact, preserve evidence, and report to IT Security.',
            },
            {
                'question_text': 'Which of the following BEST describes correct evidence preservation after a suspected attack?',
                'option_a': 'Immediately delete all suspicious emails to prevent spreading them',
                'option_b': 'Restart your computer to remove potential malware before anything else',
                'option_c': 'Take screenshots, keep the original email, and note exactly what actions you already took',
                'option_d': 'Change all your passwords immediately before notifying anyone',
                'correct_option': 'c',
                'explanation': 'Preserving evidence (screenshots, original email with headers, timestamps, your actions) helps the security team investigate the attack vector and scope. Deleting emails or restarting destroys forensic evidence.',
            },
            {
                'question_text': 'When reporting a phishing email in Gmail, which option should you use?',
                'option_a': 'Delete permanently',
                'option_b': 'Block sender',
                'option_c': 'Report phishing (via the three-dot menu in the email)',
                'option_d': 'Mark as spam',
                'correct_option': 'c',
                'explanation': '"Report phishing" in Gmail sends the email to Google\'s security team for analysis and helps protect other Gmail users. "Mark as spam" only filters it from your inbox and provides no security intelligence to Google.',
            },
            {
                'question_text': 'After you report a suspected phishing attack to your IT Security team, what typically happens next?',
                'option_a': 'Your email account is immediately suspended as a precaution',
                'option_b': 'Nothing — IT security reports are rarely acted upon',
                'option_c': 'The security team investigates, contains the threat, and may notify other potentially affected users',
                'option_d': 'The attacker receives an automatic warning that they have been reported',
                'correct_option': 'c',
                'explanation': 'After receiving a report, security teams triage the threat, pull malicious emails from other inboxes, block sender domains, analyse indicators of compromise (IoCs), and patch affected systems to prevent further damage.',
            },
            {
                'question_text': 'Which information is MOST important to include when reporting a suspicious email to IT Security?',
                'option_a': 'Only the sender\'s email address and nothing else',
                'option_b': 'A verbal description of roughly what the email looked like',
                'option_c': 'The original email (as attachment or forwarded), date/time received, and a clear account of any actions you took (including if you clicked)',
                'option_d': 'Your own password to help IT verify your identity before they assist you',
                'correct_option': 'c',
                'explanation': 'Complete, accurate information enables effective investigation. Headers reveal the origin server, timestamps help reconstruct the timeline, and knowing what you clicked (if anything) determines the urgency of containment needed.',
            },
        ],
    },
    {
        'title': 'Understanding Spear Phishing',
        'description': 'Discover how targeted spear phishing attacks use OSINT research to craft convincing personalised emails and how to defend against them.',
        'topic': 'phishing',
        'content_html': MODULE_6_HTML,
        'order_index': 6,
        'estimated_minutes': 10,
        'icon_class': 'fa-crosshairs',
        'quiz': [
            {
                'question_text': 'What is the key difference between regular phishing and spear phishing?',
                'option_a': 'Spear phishing uses text messages instead of email',
                'option_b': 'Spear phishing is a targeted attack using personal details to deceive a specific individual or organisation',
                'option_c': 'Spear phishing only targets corporate executives and not regular employees',
                'option_d': 'Regular phishing is more dangerous because it targets more people',
                'correct_option': 'b',
                'explanation': 'Spear phishing is a targeted variant that uses researched personal details — name, employer, colleagues, recent events — to make the attack highly convincing. Click rates are dramatically higher than bulk phishing.',
            },
            {
                'question_text': 'What does OSINT stand for, and why is it relevant to spear phishing?',
                'option_a': 'Online Security Intelligence Network Tracking — used by security teams to track attackers',
                'option_b': 'Open Source Intelligence — publicly available information attackers collect to research targets before attacking',
                'option_c': 'Organised Social Infiltration Network Tactics — a type of malware',
                'option_d': 'Official System Integration Network Tool — a corporate security framework',
                'correct_option': 'b',
                'explanation': 'OSINT (Open Source Intelligence) refers to information gathered from publicly available sources: LinkedIn, social media, company websites, and breached databases. Attackers use OSINT to make spear phishing emails appear personal and credible.',
            },
            {
                'question_text': 'You receive a perfectly worded email from your "line manager" asking you to urgently approve a supplier invoice. The email references your real project name. What should you do?',
                'option_a': 'Approve it immediately since it references internal project details only your manager would know',
                'option_b': 'Reply to the email to confirm before approving',
                'option_c': 'Call your manager on their known phone number to verify the request before taking any action',
                'option_d': 'Forward it to the finance team for immediate processing',
                'correct_option': 'c',
                'explanation': 'Spear phishing emails are researched and convincing. The project detail could be from LinkedIn or the company website. Always verify unusual financial or access requests through a separate, trusted communication channel.',
            },
            {
                'question_text': 'Which social media platform do spear phishers find most valuable for researching corporate targets?',
                'option_a': 'TikTok',
                'option_b': 'Snapchat',
                'option_c': 'LinkedIn',
                'option_d': 'Pinterest',
                'correct_option': 'c',
                'explanation': 'LinkedIn is the primary OSINT resource for spear phishing. It reveals job titles, reporting lines, team names, project names, email formats, and professional relationships — all of which attackers use to craft convincing targeted emails.',
            },
            {
                'question_text': 'A spear phishing email addresses you by your full name, mentions your actual employer, and references a real event you attended. Should you trust it?',
                'option_a': 'Yes — only legitimate senders would know these personal details',
                'option_b': 'No — personal details are available publicly and should increase, not decrease, your suspicion',
                'option_c': 'Yes — phishing emails always contain spelling errors, and this one does not',
                'option_d': 'Yes — the email has a company logo, which confirms it is real',
                'correct_option': 'b',
                'explanation': 'Attackers gather personal details from public sources before striking. A highly personalised email should INCREASE suspicion, not reduce it. The more an email seems to know about you, the more carefully you should verify it.',
            },
            {
                'question_text': 'What is "whaling" in the context of spear phishing?',
                'option_a': 'A phishing attack that uses very long emails to overwhelm the recipient',
                'option_b': 'A spear phishing attack that specifically targets senior executives (the "big fish") in an organisation',
                'option_c': 'A technique that uses large file attachments to deliver malware',
                'option_d': 'A campaign that targets organisations in the fishing and maritime industry',
                'correct_option': 'b',
                'explanation': 'Whaling targets high-value individuals — CEOs, CFOs, board members — who have authority to authorise large transactions or access sensitive systems. A successful whale attack can result in massive financial or data losses.',
            },
            {
                'question_text': 'Which of the following actions MOST reduces your risk of being spear phished via LinkedIn?',
                'option_a': 'Posting frequently to show you are an active, trusted professional',
                'option_b': 'Connecting with everyone who sends a connection request to build a large network',
                'option_c': 'Reviewing your privacy settings and limiting what organisational details are publicly visible',
                'option_d': 'Listing all your internal projects and technical skills in detail',
                'correct_option': 'c',
                'explanation': 'Reducing your public digital footprint limits the information attackers can use to craft convincing spear phishing emails. Review LinkedIn privacy settings, avoid sharing internal project names, team structures, or org chart details publicly.',
            },
            {
                'question_text': 'What security control is MOST effective at protecting accounts even when spear phishing successfully steals credentials?',
                'option_a': 'Using a unique, complex password for the targeted account',
                'option_b': 'Multi-Factor Authentication (MFA) — which requires a second factor the attacker does not have',
                'option_c': 'Changing your password every 30 days',
                'option_d': 'Using a VPN when accessing the account',
                'correct_option': 'b',
                'explanation': 'MFA is the strongest protection against credential theft. Even if a spear phishing attack captures your username and password, the attacker cannot log in without the second authentication factor (an app code or hardware key).',
            },
            {
                'question_text': 'An email from your "IT Security team" says: "We detected unusual login activity. Click here to verify your identity before your access is revoked in 1 hour." What is this?',
                'option_a': 'A legitimate urgent security alert that you should action immediately',
                'option_b': 'A phishing or spear phishing email using urgency and authority to manipulate you into clicking',
                'option_c': 'An automated system notification that is always safe to follow',
                'option_d': 'A test from your IT department to check your awareness',
                'correct_option': 'b',
                'explanation': 'This combines the authority principle (IT Security) with urgency (1 hour). Legitimate IT security teams never threaten to revoke access via email and ask you to verify via a link. Contact your IT team directly on a known number or address to verify.',
            },
            {
                'question_text': 'Why are spear phishing click rates (up to 70%) so much higher than generic phishing rates (around 3%)?',
                'option_a': 'Spear phishing emails are sent from more powerful email servers',
                'option_b': 'Spear phishing emails contain personalised, credible details that make them appear genuine to the specific recipient',
                'option_c': 'Spear phishing emails are exempt from spam filter detection',
                'option_d': 'Spear phishing emails are always shorter and easier to read',
                'correct_option': 'b',
                'explanation': 'Generic phishing is a numbers game — most people recognise it. Spear phishing emails are tailored to the specific target using researched personal and professional details, making them appear completely legitimate and dramatically increasing their success rate.',
            },
        ],
    },
    {
        'title': 'Smishing and Vishing Attacks',
        'description': 'Learn how attackers use SMS messages and phone calls to manipulate victims, and how to identify and respond to these social engineering techniques.',
        'topic': 'social_engineering',
        'content_html': MODULE_7_HTML,
        'order_index': 7,
        'estimated_minutes': 8,
        'icon_class': 'fa-mobile-screen',
        'quiz': [
            {
                'question_text': 'What is smishing?',
                'option_a': 'Phishing attacks that use social media platforms',
                'option_b': 'Phishing attacks delivered via SMS text messages',
                'option_c': 'A smarter, AI-powered version of email phishing',
                'option_d': 'Phishing attacks that target small businesses specifically',
                'correct_option': 'b',
                'explanation': 'Smishing combines "SMS" and "phishing". Attackers send fraudulent text messages containing malicious links or urgent instructions, exploiting the high trust and open rate of text messages compared to email.',
            },
            {
                'question_text': 'You receive a text from "Royal Mail" saying your parcel is held due to an unpaid £1.45 customs fee, with a link to pay. You are expecting a delivery. What should you do?',
                'option_a': 'Pay immediately — £1.45 is a small amount and the text references a real delivery situation',
                'option_b': 'Click the link first to see what website it goes to',
                'option_c': 'Do not click the link — visit the Royal Mail website directly by typing it in your browser to check your parcel status',
                'option_d': 'Reply to the text message asking for confirmation of the fee',
                'correct_option': 'c',
                'explanation': 'Attackers send delivery smishing to millions of people, knowing many will have a genuine delivery. The small fee amount reduces scepticism. Always navigate to the delivery company\'s official website directly — never through a text link.',
            },
            {
                'question_text': 'Why is SMS (text message) particularly effective as a phishing channel?',
                'option_a': 'Text messages cannot be filtered by spam detection systems',
                'option_b': 'Most people trust and read text messages quickly, with SMS open rates around 98% compared to 20% for email',
                'option_c': 'Text messages are encrypted end-to-end so attackers feel they cannot be caught',
                'option_d': 'Text messages can contain hidden malware that activates on receipt',
                'correct_option': 'b',
                'explanation': 'SMS has extremely high open rates (around 98%) and most people read texts within three minutes. This immediacy and high trust makes smishing more effective than email phishing — people act quickly and impulsively on texts.',
            },
            {
                'question_text': 'What is vishing?',
                'option_a': 'Phishing using video calls and deepfake technology',
                'option_b': 'Voice phishing — social engineering attacks conducted via phone calls',
                'option_c': 'A variant of phishing that targets VIP executives only',
                'option_d': 'Phishing using virtual reality environments',
                'correct_option': 'b',
                'explanation': 'Vishing (voice phishing) involves attackers calling victims while impersonating IT support, banks, government agencies, or tech companies. They use scripts designed to create urgency and extract credentials, card details, or remote access.',
            },
            {
                'question_text': 'A caller claims to be from Microsoft and says your computer has been infected with a serious virus that their systems detected remotely. They ask you to install remote access software. What should you do?',
                'option_a': 'Install the software — Microsoft genuinely monitors computers for viruses',
                'option_b': 'Hang up immediately — Microsoft does not make unsolicited calls about computer problems',
                'option_c': 'Ask the caller for their employee ID before installing anything',
                'option_d': 'Ask them to call back on a number you give them',
                'correct_option': 'b',
                'explanation': 'Microsoft, Apple, and other tech companies do NOT call customers about detected viruses. This is a classic vishing script designed to gain remote access to your device, then steal data or install ransomware. Hang up immediately.',
            },
            {
                'question_text': 'A caller from your "bank\'s fraud team" asks you to read out your one-time passcode (OTP) that just arrived by text, to "verify your identity". What should you do?',
                'option_a': 'Read out the code — the bank needs to verify you before discussing your account',
                'option_b': 'Refuse — legitimate banks NEVER ask for your OTP, PIN, or full card number over the phone',
                'option_c': 'Read out part of the code but not all of it',
                'option_d': 'Ask them to send you another OTP first to prove they are real',
                'correct_option': 'b',
                'explanation': 'Legitimate banks explicitly state they will NEVER ask for your full PIN, OTP, or password. OTPs are designed to be one-time secrets — the moment you share it, the attacker uses it to authorise a transaction or log into your account.',
            },
            {
                'question_text': 'Which of the following is a red flag that a phone call may be a vishing attack?',
                'option_a': 'The caller introduces themselves by full name and department',
                'option_b': 'The caller creates intense urgency ("your account will be closed in 10 minutes unless you act now")',
                'option_c': 'The caller asks you to verify by providing your date of birth',
                'option_d': 'The call comes during normal business hours',
                'correct_option': 'b',
                'explanation': 'Extreme urgency is a hallmark of vishing. Attackers create artificial time pressure to prevent you from stopping to think, verify independently, or consult a colleague. Legitimate organisations give you time to verify before acting.',
            },
            {
                'question_text': 'You receive a suspicious text from an unknown number claiming to be from HMRC saying you owe a tax debt and face arrest unless you call a number. What is this?',
                'option_a': 'A legitimate HMRC notice — they do send urgent texts about tax debts',
                'option_b': 'A smishing/vishing scam — HMRC communicates by post, not texts about arrest threats',
                'option_c': 'A genuine government communication that uses urgent language for serious debts',
                'option_d': 'A test from your employer to check your security awareness',
                'correct_option': 'b',
                'explanation': 'HMRC communicates primarily by post and never threatens arrest via text message. Tax debt threats by text or phone are among the most common government impersonation scams. If uncertain, contact HMRC directly using the number on their official website.',
            },
            {
                'question_text': 'After hanging up on a suspicious caller claiming to be your bank, what is the safest way to verify whether the call was genuine?',
                'option_a': 'Call back the number the caller gave you',
                'option_b': 'Wait for them to call you back if it was real',
                'option_c': 'Call the number printed on the back of your bank card or on the bank\'s official website',
                'option_d': 'Send an email to the address the caller provided',
                'correct_option': 'c',
                'explanation': 'After hanging up, always call your bank on the number from the back of your card or the official website — not a number provided by the caller. Wait a few minutes first (some phone systems allow attackers to stay on the line briefly after you "hang up").',
            },
            {
                'question_text': 'What is "MFA fatigue" in the context of vishing attacks?',
                'option_a': 'A condition where users become too tired to set up MFA on new accounts',
                'option_b': 'An attack where the criminal repeatedly sends MFA push notification requests until the victim accidentally approves one',
                'option_c': 'When MFA apps stop generating codes due to software fatigue',
                'option_d': 'When users share their MFA codes because they have too many accounts to manage',
                'correct_option': 'b',
                'explanation': 'MFA fatigue attacks involve bombarding a victim with push notification approval requests until they approve one out of frustration or confusion. Vishing attackers may then call and impersonate IT support to pressure the victim to approve. Only approve MFA pushes you personally initiated.',
            },
        ],
    },
    {
        'title': 'Recognising Fake Websites',
        'description': 'Learn how attackers clone legitimate websites, detect subtle domain differences, and use browser tools and bookmarks to verify you are on the real site.',
        'topic': 'safe_browsing',
        'content_html': MODULE_8_HTML,
        'order_index': 8,
        'estimated_minutes': 10,
        'icon_class': 'fa-spider',
        'quiz': [
            {
                'question_text': 'How can attackers create a website that looks pixel-perfect identical to your bank\'s login page?',
                'option_a': 'They hack into the bank\'s web servers and copy the files',
                'option_b': 'They use website cloning tools that download all HTML, CSS, images, and fonts from the real site',
                'option_c': 'They pay web designers to manually recreate the website from screenshots',
                'option_d': 'They purchase the design template from the same company the bank uses',
                'correct_option': 'b',
                'explanation': 'Tools like HTTrack and similar cloning software can download every file from a legitimate website in minutes, creating a visually identical copy. Only the domain and the form submission target are different — everything else looks genuine.',
            },
            {
                'question_text': 'Which of the following domain names is DEFINITELY fake if the real site is "paypal.com"?',
                'option_a': 'paypal.com',
                'option_b': 'www.paypal.com',
                'option_c': 'paypal.com.secure-verify.net',
                'option_d': 'paypal.co.uk',
                'correct_option': 'c',
                'explanation': '"paypal.com.secure-verify.net" uses paypal.com as a subdomain to appear legitimate, but the REAL domain is "secure-verify.net" — which the attacker controls. The real domain is always the part immediately before the first forward slash.',
            },
            {
                'question_text': 'A phishing website has a padlock (HTTPS) in the address bar. Does this mean it is safe?',
                'option_a': 'Yes — only verified, legitimate websites can obtain an HTTPS certificate',
                'option_b': 'No — over 80% of phishing sites now use HTTPS; the padlock only means the connection is encrypted, not that the site is legitimate',
                'option_c': 'Yes — phishing sites are blocked from obtaining SSL certificates by law',
                'option_d': 'Yes — if the padlock is green, the site has been verified by a government authority',
                'correct_option': 'b',
                'explanation': 'Free SSL certificates (from Let\'s Encrypt) are available to anyone — including attackers. The padlock only confirms that data in transit is encrypted. It says nothing about whether the site is legitimate. Always verify the domain itself.',
            },
            {
                'question_text': 'Your password manager does NOT autofill your credentials on a website you normally use. What does this suggest?',
                'option_a': 'Your password manager has a bug and needs updating',
                'option_b': 'The website has updated its login page layout',
                'option_c': 'You may be on a fake domain — the password manager only autofills on the exact domain it saved the password for',
                'option_d': 'Your password has expired and needs to be reset',
                'correct_option': 'c',
                'explanation': 'Password managers autofill only on the exact domain where the credentials were originally saved. If the manager doesn\'t autofill, the domain you\'re on is different from the one you saved the credentials for — a strong indicator of a fake site.',
            },
            {
                'question_text': 'What is a reverse proxy phishing attack?',
                'option_a': 'An attack that redirects you backwards through multiple legitimate websites',
                'option_b': 'A fake site that sits in the middle, forwarding real content from the legitimate site while capturing your credentials in transit',
                'option_c': 'An attack that disguises malicious links inside legitimate websites',
                'option_d': 'A technique for reversing DNS lookup records to impersonate domains',
                'correct_option': 'b',
                'explanation': 'Reverse proxy phishing tools (like Evilginx) sit between you and the real website. You see and interact with genuine content forwarded from the real site, but the proxy captures your session cookies and credentials — making it very hard to detect.',
            },
            {
                'question_text': 'What is the SAFEST way to navigate to your online banking website?',
                'option_a': 'Search for the bank in Google and click the top result',
                'option_b': 'Click the link in your bank\'s latest email newsletter',
                'option_c': 'Use a bookmark you personally created by typing the official URL directly into your browser',
                'option_d': 'Click the advertisement at the top of the Google results page',
                'correct_option': 'c',
                'explanation': 'Bookmarks you create yourself by manually typing the known correct URL are the safest navigation method. Search results can be manipulated (SEO poisoning), and email links may go to cloned sites. Never click ads for financial sites.',
            },
            {
                'question_text': 'Which of these is a visual clue that a cloned website may be fake?',
                'option_a': 'The website loads quickly and looks professional',
                'option_b': 'Most links on the page do nothing or redirect to the real site — only the login form is functional',
                'option_c': 'The website has a privacy policy at the bottom of the page',
                'option_d': 'The website shows your city name based on your location',
                'correct_option': 'b',
                'explanation': 'Cloned phishing sites only need the login form to work. All other links — navigation, footer, "Contact Us", "About" — either do nothing, lead to error pages, or redirect to the real site. Broken internal navigation is a common tell.',
            },
            {
                'question_text': 'What is typosquatting?',
                'option_a': 'A technique where attackers physically watch you type to steal your password',
                'option_b': 'Registering domains with common misspellings or character substitutions of legitimate brand names (e.g. "gooogle.com", "micros0ft.com")',
                'option_c': 'Inserting invisible characters into URLs to redirect browsers',
                'option_d': 'Squatting on legitimate website domains after they expire',
                'correct_option': 'b',
                'explanation': 'Typosquatting exploits common typing errors. Domains like "facbook.com", "twittter.com", or "amazzon.com" look legitimate when typed quickly. These fake domains often host phishing pages or malware download pages.',
            },
            {
                'question_text': 'A website uses a Cyrillic "а" (U+0430) in its domain name to impersonate a legitimate site. What is this attack called?',
                'option_a': 'Domain spoofing',
                'option_b': 'A homograph attack — using visually identical characters from different alphabets to create look-alike domains',
                'option_c': 'Unicode injection',
                'option_d': 'Character replacement phishing',
                'correct_option': 'b',
                'explanation': 'Homograph attacks exploit Unicode characters that look identical to standard Latin letters but are encoded differently. A domain using a Cyrillic "а" looks exactly like the Latin "a" in most fonts but resolves to a completely different server.',
            },
            {
                'question_text': 'When visiting an important financial website, what additional check can you perform by clicking the padlock icon?',
                'option_a': 'Confirm the website\'s IP address is in the correct country',
                'option_b': 'Verify the SSL certificate details — including the organisation name on Extended Validation (EV) certificates',
                'option_c': 'Check how many users have visited the website recently',
                'option_d': 'See whether the website has been reported for phishing previously',
                'correct_option': 'b',
                'explanation': 'Clicking the padlock shows certificate details. Major banks and financial institutions often have Extended Validation (EV) certificates that display the organisation\'s verified legal name. A certificate for a generic free SSL provider on a "bank" site is a red flag.',
            },
        ],
    },
    {
        'title': 'Email Security and Safe Attachments',
        'description': 'Understand dangerous file types, the macro threat, how email spoofing works, and the SPF/DKIM/DMARC protocols that protect your organisation.',
        'topic': 'phishing',
        'content_html': MODULE_9_HTML,
        'order_index': 9,
        'estimated_minutes': 10,
        'icon_class': 'fa-paperclip',
        'quiz': [
            {
                'question_text': 'Which file extension is MOST immediately dangerous to open from an unexpected email?',
                'option_a': '.pdf',
                'option_b': '.docx',
                'option_c': '.exe',
                'option_d': '.txt',
                'correct_option': 'c',
                'explanation': 'An .exe (executable) file runs code directly on your computer the moment it is opened. It requires no additional steps to cause harm. Never open .exe, .bat, .com, .scr, or .msi files received unexpectedly via email.',
            },
            {
                'question_text': 'What are macros in Microsoft Office documents, and why are they dangerous?',
                'option_a': 'Large image files embedded in Office documents that can be used for phishing',
                'option_b': 'Small embedded programs that can execute arbitrary commands on your computer when enabled',
                'option_c': 'External links in Word documents that connect to untrusted websites',
                'option_d': 'Password-protected sections of a document that hide malicious content',
                'correct_option': 'b',
                'explanation': 'Macros are mini-programs inside Office files (filenames ending .docm, .xlsm). When you click "Enable Content" on a received file, the macro runs and can download malware, create backdoors, or steal data. Never enable macros from unexpected documents.',
            },
            {
                'question_text': 'An email appears to come from your CEO\'s real email address asking for urgent wire transfer approval. How is this possible if you haven\'t been hacked?',
                'option_a': 'Your CEO\'s computer must have been hacked to send the email',
                'option_b': 'Email spoofing — attackers can forge the "From" field to display any email address',
                'option_c': 'Someone inside your company is impersonating the CEO',
                'option_d': 'The CEO\'s email account password was guessed',
                'correct_option': 'b',
                'explanation': 'Email spoofing allows attackers to set any email address in the "From" display field. Without proper SPF, DKIM, and DMARC configurations, spoofed emails can appear to come from legitimate internal addresses. Always verify financial requests through a phone call.',
            },
            {
                'question_text': 'What does SPF (Sender Policy Framework) do?',
                'option_a': 'It adds a digital signature to each email to prove it was not modified in transit',
                'option_b': 'It specifies which mail servers are authorised to send email on behalf of a domain',
                'option_c': 'It encrypts email content so only the recipient can read it',
                'option_d': 'It blocks all emails from domains less than 30 days old',
                'correct_option': 'b',
                'explanation': 'SPF records in DNS specify which mail servers are authorised to send email for a domain. If an email arrives from an unauthorised server, receiving mail systems can reject or flag it. It is one of three core email authentication standards alongside DKIM and DMARC.',
            },
            {
                'question_text': 'You receive a Word document (.docx) from an unknown sender. When you open it, a message says "Enable editing and enable content to view this document." What should you do?',
                'option_a': 'Click "Enable Content" — the document needs macros to display properly',
                'option_b': 'Click "Enable Editing" only — that is safe',
                'option_c': 'Close the document and report it to IT Security — this is the classic prompt used to trick users into running malicious macros',
                'option_d': 'Enable content only if your antivirus is running',
                'correct_option': 'c',
                'explanation': 'The "Enable Content" prompt is the most common trigger for macro-based malware. Attackers craft documents that appear to need macros enabled to display properly — they do not. Never enable content in a document from an unexpected source.',
            },
            {
                'question_text': 'Which of the following is the SAFEST way to check a suspicious attachment before opening it?',
                'option_a': 'Open it on an older computer that you consider disposable',
                'option_b': 'Rename the file extension to .txt before opening',
                'option_c': 'Upload it to a sandboxing service (like Any.run or VirusTotal) that analyses it in an isolated environment',
                'option_d': 'Open it with Notepad to read the raw content',
                'correct_option': 'c',
                'explanation': 'Online sandboxes execute suspicious files in an isolated virtual environment where they cannot cause real harm, then report what behaviour the file exhibited. This is the safest way to evaluate a suspicious attachment without exposing your own system.',
            },
            {
                'question_text': 'Why are .zip or .rar archive attachments potentially dangerous even if the email says they contain "important documents"?',
                'option_a': 'Archive files are too large for email servers and are automatically rejected',
                'option_b': 'Archives can contain any file type inside, including dangerous executables or macro-enabled Office files, bypassing some email filters',
                'option_c': 'Archive files automatically execute their contents when downloaded',
                'option_d': 'Attackers can embed viruses directly into the ZIP file format itself',
                'correct_option': 'b',
                'explanation': 'Archives (.zip, .rar, .7z) can contain any file type inside — including .exe files or macro-enabled documents. Some email filters only scan the outer container, not the contents. Attackers use password-protected archives specifically to defeat scanning.',
            },
            {
                'question_text': 'What does DMARC tell receiving email servers to do?',
                'option_a': 'Encrypt all incoming emails automatically',
                'option_b': 'Specify what action to take (reject, quarantine, or report) when an email fails SPF and DKIM checks',
                'option_c': 'Verify the identity of the email recipient before delivery',
                'option_d': 'Block emails from domains registered less than 90 days ago',
                'correct_option': 'b',
                'explanation': 'DMARC (Domain-based Message Authentication Reporting and Conformance) builds on SPF and DKIM by telling receiving servers what to do when authentication fails: reject the email, quarantine it (spam folder), or report it to the domain owner. Proper DMARC dramatically reduces spoofing.',
            },
            {
                'question_text': 'Microsoft Word opens a downloaded document in "Protected View". What should you do?',
                'option_a': 'Click "Enable Editing" immediately to read the document properly',
                'option_b': 'Stay in Protected View or close the document — Protected View prevents macros from running',
                'option_c': 'Disable Protected View in Word settings as it is inconvenient',
                'option_d': 'Right-click the file and choose "Run as Administrator" to bypass the restriction',
                'correct_option': 'b',
                'explanation': 'Protected View is a security sandbox that opens potentially unsafe documents in read-only mode and prevents macros from executing. It is your first line of defence against malicious Office files. Keep Protected View enabled and only exit it for documents from fully trusted sources.',
            },
            {
                'question_text': 'You receive an invoice PDF from a supplier you work with regularly. The email sender address looks correct. What should you do before paying?',
                'option_a': 'Pay immediately — the sender address is correct and the invoice looks real',
                'option_b': 'Call the supplier on their known phone number to verbally confirm they sent the invoice and verify the bank details',
                'option_c': 'Check the invoice PDF for spelling errors before paying',
                'option_d': 'Forward the invoice to your manager for approval and then pay',
                'correct_option': 'b',
                'explanation': 'Invoice fraud involves attackers intercepting or spoofing supplier emails to redirect payments to their own accounts. Always verify payment details — especially new or changed bank account numbers — by calling the supplier on a known, pre-existing number before authorising any transfer.',
            },
        ],
    },
    {
        'title': 'Multi-Factor Authentication Deep Dive',
        'description': 'Understand how MFA works, compare authentication methods from weakest to strongest, learn about SIM swapping, and enable MFA on your critical accounts.',
        'topic': 'passwords',
        'content_html': MODULE_10_HTML,
        'order_index': 10,
        'estimated_minutes': 12,
        'icon_class': 'fa-key',
        'quiz': [
            {
                'question_text': 'What is the PRIMARY security benefit of Multi-Factor Authentication (MFA)?',
                'option_a': 'It prevents attackers from even attempting to guess your password',
                'option_b': 'It requires a second proof of identity so stolen passwords alone cannot grant access',
                'option_c': 'It automatically changes your password after each login',
                'option_d': 'It encrypts your password before sending it to the server',
                'correct_option': 'b',
                'explanation': 'MFA requires something you know (password) PLUS something you have (a code or key) or something you are (biometrics). Even if your password is stolen, phished, or guessed, an attacker cannot log in without the second factor.',
            },
            {
                'question_text': 'Which MFA method is considered STRONGEST against phishing attacks?',
                'option_a': 'SMS one-time code',
                'option_b': 'Email one-time code',
                'option_c': 'Authenticator app (TOTP)',
                'option_d': 'Hardware security key (FIDO2/WebAuthn)',
                'correct_option': 'd',
                'explanation': 'Hardware security keys (like YubiKey) using FIDO2/WebAuthn are cryptographically bound to the specific website domain. They cannot be phished by a fake website because the key will not authenticate a domain it was not registered on. SMS and TOTP codes can be intercepted via real-time phishing proxies.',
            },
            {
                'question_text': 'What is a SIM swapping attack?',
                'option_a': 'Physically stealing someone\'s SIM card from their phone',
                'option_b': 'An attacker convincing a mobile carrier to transfer a victim\'s phone number to an attacker-controlled SIM card',
                'option_c': 'Installing malware on a phone that clones the SIM card remotely',
                'option_d': 'Swapping SMS messages between two victims to confuse them',
                'correct_option': 'b',
                'explanation': 'In a SIM swap, attackers call the victim\'s mobile carrier, impersonate the victim using personal information (from OSINT or breaches), and convince the carrier to transfer the phone number to a new SIM. This gives the attacker control of all SMS codes sent to that number.',
            },
            {
                'question_text': 'A TOTP (Time-based One-Time Password) code from an authenticator app expires after how long?',
                'option_a': '1 minute',
                'option_b': '30 seconds',
                'option_c': '5 minutes',
                'option_d': '24 hours',
                'correct_option': 'b',
                'explanation': 'TOTP codes generated by authenticator apps (Google Authenticator, Microsoft Authenticator) change every 30 seconds. This time-based expiry limits the window in which a stolen code can be used — though real-time phishing proxies can still capture and use them within that window.',
            },
            {
                'question_text': 'You receive 15 MFA push notification approval requests on your phone in quick succession, even though you are not trying to log in. What is happening?',
                'option_a': 'Your authenticator app has a bug causing duplicate notifications',
                'option_b': 'An MFA fatigue attack — an attacker who has your password is hoping you approve one request by mistake or frustration',
                'option_c': 'Your account is being tested by your IT Security team',
                'option_d': 'A legitimate system update requires repeated authentication',
                'correct_option': 'b',
                'explanation': 'MFA fatigue (also called MFA prompt bombing) involves an attacker who already has your credentials spamming approval requests hoping you tap Approve to stop the notifications. NEVER approve a push notification you did not personally initiate. Report it to IT Security immediately.',
            },
            {
                'question_text': 'Why is an authenticator app safer than SMS codes for MFA?',
                'option_a': 'Authenticator apps generate longer codes than SMS',
                'option_b': 'Authenticator apps work offline and are not vulnerable to SIM swapping, carrier attacks, or SS7 network interception',
                'option_c': 'Authenticator apps are free while SMS codes cost money to receive',
                'option_d': 'Authenticator apps automatically notify your bank when a login is attempted',
                'correct_option': 'b',
                'explanation': 'Authenticator apps generate codes locally on your device without sending anything over the phone network. This makes them immune to SIM swapping and SS7 protocol attacks that can intercept SMS messages. They are significantly more secure than SMS for account protection.',
            },
            {
                'question_text': 'Which of the following represents the "Something You Are" authentication factor?',
                'option_a': 'Your employee ID card',
                'option_b': 'Your password',
                'option_c': 'Your fingerprint or facial recognition scan',
                'option_d': 'A one-time code from an SMS',
                'correct_option': 'c',
                'explanation': '"Something you are" refers to biometric authentication: fingerprint, face recognition, retina scan, or voice recognition. These are inherently personal and cannot be easily shared or stolen the way passwords and code-generating devices can.',
            },
            {
                'question_text': 'You lose your phone which has your authenticator app. What is the CORRECT recovery method for your accounts?',
                'option_a': 'Contact each website\'s support team, give them your email address, and they will grant access',
                'option_b': 'Use the backup codes you saved during MFA setup, or follow the account\'s official recovery process with identity verification',
                'option_c': 'You permanently lose access to all accounts — there is no recovery option',
                'option_d': 'Use the SMS option which is always available as a fallback',
                'correct_option': 'b',
                'explanation': 'During MFA setup, one-time backup codes are provided specifically for this scenario. Save these codes securely (password manager or printed in a safe place) during setup. Most services also offer account recovery through verified email, trusted devices, or identity verification.',
            },
            {
                'question_text': 'According to Microsoft, what percentage of automated account compromise attacks does MFA block?',
                'option_a': 'Around 50%',
                'option_b': 'Around 75%',
                'option_c': 'Around 99.9%',
                'option_d': 'Around 85%',
                'correct_option': 'c',
                'explanation': 'Microsoft research shows MFA blocks over 99.9% of automated account compromise attacks. Even basic MFA — including SMS codes despite its limitations — provides massive protection compared to password-only authentication.',
            },
            {
                'question_text': 'Which account should you prioritise enabling MFA on FIRST, if you can only do one?',
                'option_a': 'Your online gaming account',
                'option_b': 'Your email account — because it is the master key used to reset all other account passwords',
                'option_c': 'Your social media account — because it contains the most personal information',
                'option_d': 'Your work computer login — because it contains work data',
                'correct_option': 'b',
                'explanation': 'Your email account is the master key to your digital life. Virtually every other account — banking, work, social media — can be compromised by an attacker who controls your email (via "Forgot password" resets). Protecting email with strong MFA protects everything connected to it.',
            },
        ],
    },
]


def seed_training_modules():
    """Seed training modules incrementally — adds new modules without touching existing ones."""
    from models.training import TrainingModule, Quiz
    from models import db

    existing_titles = {m.title for m in TrainingModule.query.all()}
    added = 0

    for mod_data in MODULES:
        if mod_data['title'] in existing_titles:
            continue  # already in DB, skip

        quiz_items = mod_data.pop('quiz')
        module = TrainingModule(**mod_data)
        db.session.add(module)
        db.session.flush()   # get module.id

        for q in quiz_items:
            db.session.add(Quiz(module_id=module.id, **q))

        added += 1

    if added:
        db.session.commit()
    print(f'[seed_training] Added {added} new module(s). Total in DB: {TrainingModule.query.count()}.')


if __name__ == '__main__':
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed_training_modules()
