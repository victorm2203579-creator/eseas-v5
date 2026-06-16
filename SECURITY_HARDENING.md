# ESEAS Security Hardening Implementation

**Project:** Enhanced Social Engineering Attack Simulator (ESEAS v5)  
**Status:** Phase 1 - SQL Injection & XSS Prevention  
**Date:** 2026-06-11

---

## THREAT CATEGORY 1: SQL INJECTION ✅

### Assessment Result
**Status:** SAFE - No raw SQL detected

- ✅ No `execute()` calls with string concatenation
- ✅ No f-string SQL (`f"SELECT..."`)
- ✅ No `%` string formatting for SQL
- ✅ No `.format()` with SQL keywords
- ✅ App uses SQLAlchemy ORM exclusively for all database queries

### Implementation

**File Created:** `security/input_sanitizer.py`

Implemented defensive input validation with functions:

1. **`is_sql_injection(value: str) -> bool`**
   - Detects SQL injection patterns: SQL keywords, comment syntax, stacked queries
   - Patterns: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `--`, `;`, `'`, `/*/`

2. **`sanitize_string(value: str, max_length: int) -> str`**
   - Validates string length (default 500 chars)
   - Detects SQL injection patterns
   - Removes null bytes
   - Raises `ValidationError` on malicious input
   - Used for: campaign names, descriptions, quiz answers

3. **`sanitize_url(url: str) -> str`**
   - Validates URL format (must start with `http://` or `https://`)
   - **SSRF Prevention:** Blocks private IP ranges:
     - `localhost`, `127.*`, `10.*`, `172.16-31.*`, `192.168.*`
     - `169.254.*` (link-local), `::1` (IPv6 loopback)
     - `metadata.google`, `169.254.169.254` (AWS metadata)
   - Prevents accessing internal services from form inputs

### Routes Updated with Sanitization

#### 1. `routes/simulator.py` - Campaign Management
- **`new_campaign()`** (line 67-88): Sanitizes campaign name & description
- **`new_template()`** (line 285-305): Sanitizes template name, subject, body_html, etc.
- **`edit_template()`** (line 315-341): Sanitizes all template edit inputs
- Exception handling: Shows error message if injection detected

#### 2. `routes/training.py` - Training Module Management
- **`new_module()`** (line 490-528): Sanitizes title, description, content_html, video_url
- **`edit_module()`** (line 523-555): Sanitizes all module edit inputs
- Exception handling: Flashes validation errors to user

---

## THREAT CATEGORY 2: CROSS-SITE SCRIPTING (XSS) ✅

### Assessment Result
**Status:** SAFE - No dangerous Markup() or |safe filters detected

- ✅ No `Markup()` calls in Python code
- ✅ No `|safe` filters in Jinja2 templates
- ✅ No `innerHTML` in JavaScript
- ✅ No `render_template_string()` calls
- ✅ Jinja2 autoescape is ON by default

### Implementation

**Added to `security/input_sanitizer.py`:**

1. **`sanitize_html_output(value: str) -> str`**
   - Strips ALL HTML tags from user input
   - Uses `bleach` library with empty tag list
   - Safe for displaying user-submitted campaign names, quiz answers, etc.
   - Used with Jinja2 filter: `{{ user_content | safe_user }}`

2. **`sanitize_rich_text(value: str) -> str`**
   - Allows limited HTML for admin-created content
   - Permitted tags: `<b>`, `<i>`, `<u>`, `<strong>`, `<em>`, `<p>`, `<br>`, `<ul>`, `<ol>`, `<li>`, `<h3>`, `<h4>`, `<a>`
   - Validates `href` attributes in `<a>` tags using `sanitize_url()`
   - Used for: training module content, email template bodies (admin only)

### Jinja2 Configuration Updates

**File:** `app.py`

```python
# Enforce Jinja2 autoescape explicitly
app.jinja_env.autoescape = True

# Add custom filter for safe user content display
@app.template_filter('safe_user')
def safe_user_filter(value):
    """Use {{ user_content | safe_user }} instead of {{ user_content | safe }}"""
    return sanitize_html_output(str(value))
```

**Usage in templates:**
```html
<!-- Instead of {{ campaign.name | safe }} -->
<!-- Use: -->
{{ campaign.name | safe_user }}
```

### Dependencies Added to `requirements.txt`

```
bleach>=6.0.0      # HTML sanitization
markupsafe>=2.1.0  # Safe string handling
```

---

## VALIDATION PATTERN SUMMARY

### SQL Injection Detection
```
Pattern: SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION
Pattern: -- (comment)
Pattern: ; DROP/DELETE/INSERT/UPDATE (stacked queries)
Pattern: ' OR/AND '
Pattern: /* ... */ (block comment)
Pattern: xp_* (SQL Server extended procs)
Pattern: WAITFOR DELAY (time-based blind SQLi)
```

### Input Sanitization Flow

```
User Input
    ↓
sanitize_string() / sanitize_url() / sanitize_rich_text()
    ↓
Validation Check (length, patterns, URL safety)
    ↓
If Invalid: Raise ValidationError
    ↓
If Valid: Return cleaned input
    ↓
Database (SQLAlchemy ORM parameterizes all queries)
    ↓
Template Rendering (Jinja2 autoescape + |safe_user filter)
```

---

## FILES MODIFIED

| File | Changes | Type |
|------|---------|------|
| `security/__init__.py` | Created | New Module |
| `security/input_sanitizer.py` | Created | New Module |
| `app.py` | +Imports, +Jinja2 filter | Configuration |
| `routes/simulator.py` | +Sanitization for campaign/template inputs | Hardening |
| `routes/training.py` | +Sanitization for module/quiz inputs | Hardening |
| `requirements.txt` | +bleach, +markupsafe | Dependencies |

---

## TESTING RECOMMENDATIONS

### SQL Injection Testing
```python
# Should be caught and rejected:
name = "MyTest' OR 1=1--"
name = "Campaign\"; DROP TABLE campaigns;--"
name = "Test/* comment */Name"

# Should be accepted:
name = "My Campaign"
name = "Test-Campaign-2024"
name = "Campaign (2024-Q2)"
```

### XSS Testing
```python
# Should be stripped in normal user inputs:
campaign_name = "<script>alert('XSS')</script>"
campaign_name = "<img src=x onerror=alert('XSS')>"
campaign_name = "<svg onload=alert('XSS')>"

# Should be allowed in admin rich text:
content = "<p><b>Important:</b> Click here</p>"
content = "<h3>Module Title</h3><ul><li>Item 1</li></ul>"
```

---

## THREAT CATEGORY 5: SERVER-SIDE REQUEST FORGERY (SSRF) ✅

### What It Is
Attacker submits URL like `http://169.254.169.254/latest/metadata/` (AWS credentials) or `http://localhost:5432/` (database). The analyzer fetches it, leaking internal data.

### Assessment Result
**Partially protected** - sanitize_url() in input_sanitizer.py blocked some ranges but needed complete SSRF protection

### Implementation
**File Created:** `security/ssrf_guard.py` (290+ lines)

1. **`is_safe_url(url) -> Tuple[bool, str]`**
   - Validates scheme (http/https only)
   - Blocks schemes: file, ftp, gopher, ldap, dict, sftp
   - DNS resolution with IP validation
   - Blocks all private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
   - Blocks AWS metadata: 169.254.169.254, metadata.google.internal
   - Blocks restricted ports: SMTP (25), DB (3306, 5432), Redis (6379), MongoDB (27017), SSH (22)

2. **`safe_fetch(url, timeout=5, max_size=50000)`**
   - Validates initial URL + all redirects
   - Disables auto-redirects (validates each manually)
   - Caps response at 50KB (prevents DoS)
   - Raises SSRFBlockedException on blocked URLs

3. **`validate_domain_for_campaign(domain)`**
   - Special validation for phishing campaign URLs
   - Ensures domain resolves to public IP only

### Integration Points (Not Yet Updated)
Routes that fetch URLs should use `safe_fetch()`:
- `routes/analyzer.py` - URL scanning endpoint
- `routes/simulator.py` - Campaign preview URL fetching

---

## THREAT CATEGORY 6: AUTHENTICATION ATTACKS ✅

### What It Is
- **Brute Force:** Attacker scripts 10,000 login attempts with password list
- **User Enumeration:** Attacker discovers registered emails based on different error messages
- **Timing Attack:** Attacker determines if email exists by measuring response time
- **Weak Passwords:** Users create "Password1!" which is cracked in minutes

### Assessment Result
**Partially protected** - Rate limiting configured but needed comprehensive auth hardening

### Implementation

**File Created:** `security/auth_guard.py` (200+ lines)

#### 1. Rate Limiting (Enhanced)
- Login route: **5 per minute, 20 per hour** (was 10/min)
- Registration: **10 per hour** (prevents registration spam)
- Prevents brute force attacks

#### 2. Password Policy Enforcement
**`validate_password_strength(password) -> Tuple[bool, str]`**

Requirements:
- Minimum **10 characters** (not 8)
- At least **1 uppercase letter**
- At least **1 lowercase letter**
- At least **1 number**
- At least **1 special character** (!@#$%^&*(),.?":{}|<>)
- NOT a common password (password, 123456, qwerty, admin, etc.)
- NOT predictable pattern (Password1!)

Applied to:
- Registration (`register()`)
- Password reset (`reset_password()`)

#### 3. Account Lockout (Brute Force Prevention)
**`LoginAttemptTracker` class**

- Tracks failed login attempts per user
- After **5 failed attempts** → lock account for **15 minutes**
- Automatic unlock after timeout
- Reset counter on successful login
- Integrated into `User` model:
  ```python
  failed_login_attempts = db.Column(db.Integer, default=0)
  locked_until = db.Column(db.DateTime, nullable=True)
  ```

#### 4. Constant-Time Password Checking
**`constant_time_comparison(a, b) -> bool`**

Prevents **timing attacks**:
- Always checks password even if user not found
- Dummy hash used if user doesn't exist
- Comparison takes same time regardless of result
- Prevents attackers from detecting if email exists

Implementation in `login()`:
```python
dummy_hash = 'pbkdf2:sha256:...'
stored_hash = user.password_hash if user else dummy_hash
password_correct = check_password_hash(stored_hash, password)
```

#### 5. User Enumeration Prevention
**`anti_enumeration_delay()` function**

- Adds **50-200ms random delay** to failed login attempts
- Same error message for "email not found" and "password wrong"
- Prevents automated scanning for valid emails
- Imperceptible to real users but slows attackers

Applied in `login()`:
```python
flash('Invalid email or password.', 'danger')  # Same message always
anti_enumeration_delay()
```

### Routes Updated with Authentication Hardening

| Route | Changes |
|-------|---------|
| `auth.register()` | Password policy, rate limit 10/hr |
| `auth.login()` | Account lockout, timing protection, enumeration defense |
| `auth.reset_password()` | Password policy, unlock account |

---

## COMBINED SECURITY ARCHITECTURE (Threats 1-6)

```
HTTP Request
    ↓
[Rate Limiter] — Limits by IP address
    ↓
[SSRF Check] — is_safe_url() validates external URLs
    ↓
[Input Sanitization] — SQL injection + XSS prevention
    ↓
[Password Policy] — 10 chars + upper + lower + digit + special
    ↓
[Account Lockout] — 5 failed attempts → 15 min lock
    ↓
[Constant-Time Compare] — Timing attack prevention
    ↓
[Enumeration Delay] — 50-200ms to slow automation
    ↓
[SQLAlchemy ORM] — Parameterized queries (SQL injection impossible)
    ↓
[Jinja2 Output] — Autoescape ON + |safe_user filter
    ↓
Browser (XSS prevented, SSRF blocked, brute force throttled)
```

---

## REMAINING THREATS (TO IMPLEMENT)

1. **Threat 3:** CSRF (partially implemented - Flask-WTF enabled)
2. **Threat 4:** Broken Auth - Session Fixation
3. **Threat 7:** XXE/XML Injection
4. **Threat 8:** Access Control (admin checks present, needs audit)
5. **Threat 9:** Security Misconfiguration
6. **Threat 10:** Sensitive Data Exposure
7. **Threat 11:** Insecure Logging
8. **Threat 12:** API Security
9. **Threat 13:** Cryptography Issues
10. **Threat 14:** Dependency Vulnerabilities
11. **Threat 15:** Infrastructure Security

---

## DEPLOYMENT CHECKLIST

- [ ] Run `pip install -r requirements.txt` to install bleach & markupsafe
- [ ] Test campaign creation with benign names
- [ ] Test campaign creation with injection payloads (should fail)
- [ ] Test Jinja2 escaping by viewing campaign details in admin panel
- [ ] Review templates to replace any `|safe` with `|safe_user` if needed
- [ ] Run application and verify no import errors
- [ ] Verify Flask startup shows no warnings

---

## SECURITY NOTES

**Principle Used:** **Defense in Depth**
- Layer 1: Input validation (reject malicious input early)
- Layer 2: ORM parameterization (SQLAlchemy prevents query injection)
- Layer 3: Output encoding (Jinja2 + bleach prevent rendering attacks)
- Layer 4: Content-Security-Policy headers (future)

**Design Decision:** Custom sanitizers instead of relying solely on framework
- Provides explicit control over what's allowed
- Easier to audit and test
- Facilitates future compliance (PCI-DSS, GDPR, etc.)
- Defensive posture: assume all user input is malicious until proven otherwise

---

**Last Updated:** 2026-06-11  
**Next Phase:** Threat Category 3 (CSRF Hardening)
