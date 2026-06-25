# ESEAS v5 — Enhanced Social Engineering Attack Simulator

**Final Year Cybersecurity Project**
*Design and Implementation of an Enhanced Social Engineering Attack Simulator with Phishing Link Analysis*

---

## What this is

A Flask web application with three main capabilities:

1. **Phishing URL Scanner** — multi-layer risk analysis combining VirusTotal, Google Safe
   Browsing, a trained ML model, URL pattern heuristics, threat feeds (URLhaus/OpenPhish),
   SSL certificate checks, redirect-chain analysis, and typosquatting detection into a single
   risk score with a full explanation of *why* a URL was flagged.
2. **Phishing Simulation Campaigns** — admin-created email/SMS templates sent to test users,
   with click/open tracking, training assignment on failure, and campaign reporting.
3. **Security Awareness Training** — interactive modules, quizzes, badges, leaderboard, and
   downloadable completion certificates.

---

## Project Structure

```
project/
├── app.py                    # Flask application factory, DB init, auto-seeding
├── config.py                 # DevelopmentConfig (env-var driven)
├── extensions.py             # Flask-Login, Flask-Mail, Flask-Limiter, Flask-Talisman init
├── requirements.txt
├── runtime.txt                # Python version pin (Railway/Heroku)
├── Procfile / railway.toml    # Deployment start commands (gunicorn)
├── .env                       # Your local secrets — NOT committed (see Setup below)
├── .gitignore
│
├── models/
│   ├── user.py                 # User model (roles, is_primary_admin, lockout, sessions)
│   ├── scan.py                 # ScanResult model (+ accuracy property)
│   ├── campaign.py              # Campaign / CampaignTarget / EmailTemplate
│   ├── simulator.py             # Simulator-specific models
│   ├── training.py              # TrainingModule / Quiz / Badge / Certificate
│   ├── notification.py          # In-app notifications
│   └── privilege_change.py      # Admin promote/revoke audit trail
│
├── routes/
│   ├── auth.py                  # Login / Register / Logout / Admin user management
│   ├── analyzer.py              # URL phishing scanner (the main /analyzer/scan endpoint)
│   ├── simulator.py             # Campaigns + email templates (admin)
│   ├── training.py              # Awareness training, quizzes, badges, leaderboard
│   ├── dashboard.py             # User / admin dashboards
│   └── reports.py               # Admin report generation
│
├── security/
│   ├── access_control.py, auth_guard.py, concurrency_guard.py
│   ├── email_guard.py, input_sanitizer.py, secrets_check.py, ssrf_guard.py
│   └── (rate limiting, IDOR prevention, SSRF guards, concurrent-scan locks)
│
├── ml_engine/
│   ├── feature_extractor.py    # 43-feature URL extractor (fast=True = lexical-only, instant)
│   ├── predictor.py             # Loads model, runs prediction, VT/GSB integration
│   ├── scoring_engine.py        # Combines all analysis layers into one final risk score
│   ├── threat_feeds.py          # URLhaus / OpenPhish / URLvoid queries
│   ├── ssl_checker.py, redirect_analyzer.py, typosquatting.py, header_analyzer.py
│   ├── train_model.py           # Retrains phishing_model.pkl from Data/URL dataset.csv
│   └── phishing_model.pkl, label_encoder.pkl   # Trained model (committed — see note below)
│
├── static/css, static/js, static/images
├── templates/                   # Jinja2 templates (Bootstrap 5)
├── migrations/                  # Flask-Migrate / Alembic migration scripts
├── tests/                       # Test scripts (smoke tests, integration tests)
└── instance/                    # SQLite DB file lives here (gitignored, auto-created)
```

The training dataset itself (`Data/URL dataset.csv`, ~450k labeled URLs) lives one level
above `project/`, in `../Data/`.

---

## Setup (from scratch, on a new machine)

### 1. Prerequisites

- Python 3.11+ (the project is pinned to 3.11.0 in `runtime.txt`, but any 3.11/3.12 works locally)
- `pip`

### 2. Create & activate a virtual environment

```bash
# from inside the project/ folder
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# Windows (cmd)
.venv\Scripts\activate.bat
# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

If you ever plan to retrain the ML model and want the feature-importance chart saved as a
PNG, also run `pip install matplotlib` (optional — training works fine without it).

### 4. Configure environment variables

Create a `.env` file in the `project/` folder (same level as `app.py`):

```env
SECRET_KEY=replace-with-a-long-random-string
BASE_URL=http://127.0.0.1:5000

# Email (used for password reset / notifications) — optional for local testing
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password

# Threat intelligence API keys — the scanner works without these (heuristics +
# ML still run), but VirusTotal/GSB checks will be skipped/empty until set
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
```

**Getting the API keys (both free):**
- VirusTotal: https://www.virustotal.com/gui/my-apikey (free tier: 4 requests/min)
- Google Safe Browsing: https://console.cloud.google.com → enable "Safe Browsing API" → Credentials

A `.env` with only `SECRET_KEY` set will still run the app and the scanner — it just won't
query VirusTotal/GSB, relying on the ML model and URL-heuristics layer instead.

### 5. Run the application

```bash
python app.py
```

The app starts at **http://127.0.0.1:5000** and will:
- Create the SQLite database (`instance/phishing_simulator.db`) automatically
- Auto-seed a primary admin account and a demo user (see credentials below)
- Auto-seed the 10 default training modules

You do **not** need to run any separate seeding script — this happens automatically every
time `app.py` starts (it safely skips re-creating accounts that already exist).

### 6. Log in

| Role  | Email             | Password     |
|-------|-------------------|--------------|
| Admin | admin@eseas.com   | Admin@1234   |
| User  | alice@eseas.com   | User@1234    |

**Change these passwords immediately if deploying anywhere beyond your own machine.**
The admin account is flagged as the "primary admin" — it can promote/revoke other admins,
and it cannot itself be demoted or deactivated by anyone else.

---

## Database migrations

The project uses Flask-Migrate (Alembic) for schema changes. New tables are created
automatically by `db.create_all()` on startup, but if you pull a future update that adds a
new *column* to an existing table, run:

```bash
flask db upgrade
```

If you're developing further and add new model columns yourself:

```bash
flask db migrate -m "describe your change"
flask db upgrade
```

---

## How the risk score is calculated

Each scan combines several independent signals, weighted by reliability:

| Layer | Weight | What it checks |
|---|---|---|
| VirusTotal | **30%** | 70+ antivirus engine consensus — most authoritative when available |
| ML Model | **25%** | Trained classifier on lexical URL features — catches novel zero-day patterns |
| Google Safe Browsing | **20%** | Google's crawled threat index — independent verification |
| URL Heuristics (rule-based) | **10%** | Hex tracking tokens, malware file extensions, phishing keywords, IP-as-host, suspicious paths — works on brand-new URLs no database has seen |
| Threat Feeds | **8%** | URLhaus / OpenPhish / URLvoid — independent real-time feeds |
| SSL Certificate Analysis | **4%** | Domain mismatch, self-signed, expired certificates |
| Redirect Chain Analysis | **2%** | Multi-hop redirects often hide phishing destination |
| Typosquatting Detection | **1%** | Similarity to known legitimate brands |

**Measured full-system performance**: 95.00% accuracy, 90.91% precision, 100% recall, 95.24% F1 — measured end-to-end (real VT/GSB API calls included) on 100 held-out URLs not used in ML training. See `python ml_engine/evaluate_system.py` and `PROJECT_SUMMARY.md` → "Full-System Evaluation" for methodology and the 5 false-positive cases.

### Override Rules

On top of the weighted average, several **override floors** enforce minimum scores to catch
phishing that would otherwise slip through:

- **VirusTotal detections floor**: 1+ engine → min 52 (Suspicious), 5+ → min 78 (High Risk), 10+ → min 85 (Phishing)
- **GSB phishing flag**: min 70 (High Risk)
- **3+ heuristic red flags**: min 41 (Suspicious) — prevents Safe/Low Risk when multiple local patterns match
- **Heuristic score ≥70**: min 62 (Suspicious) — strong local signals override weak external votes
- **Unresolvable URL shortener**: known shortener domain (`t.co`, `bit.ly`, `tinyurl.com`, etc.) + redirect chain couldn't be resolved → min 41 (Suspicious). Zero visibility into a shortener's real destination is itself a risk signal — VT/GSB/heuristics otherwise grade the clean-looking literal short link instead of where it actually goes.

### Risk Labels & Thresholds

| Label | Score Range | What it means | Action |
|---|---|---|---|
| **Safe** | 0–20 | Very low risk indicators | Proceed normally |
| **Low Risk** | 21–40 | Minor suspicious patterns present | Normal caution |
| **Suspicious** | 41–60 | Multiple indicators or high heuristic score | Verify authenticity before clicking |
| **High Risk** | 61–79 | Strong confirmation from multiple sources | Do NOT click; report to IT security |
| **Phishing** | 80–100 | Malicious intent confirmed (VT detections + ML + GSB agreement) | ALERT: confirmed phishing; report immediately |

> **Note:** No "borderline" verdicts (61–79 gap intentional) — signals must agree to force a verdict between Low Risk and High Risk.

### Accuracy Percentage Explained

The **accuracy score** (40–97%) shows how confident the analysis is, NOT how risky the URL is.
It reflects signal diversity:

- **40–50%**: Only URL patterns available (brand-new domain, VT/GSB haven't indexed it yet)
- **60–70%**: Some API confirmation (1–2 sources flagged)
- **75–85%**: Multiple sources agree (VT + GSB + ML + threat feeds)
- **90–97%**: Very high consensus (10+ VT engines + GSB + ML + multiple feeds)

Example: A newly created phishing URL with no VT/GSB history might show:
- **Risk Level**: Suspicious (correctly flagged by heuristics)
- **Accuracy**: 45% (low confidence because external sources haven't seen it yet)

This is *honest* — don't claim 90% certainty when only pattern analysis is available.

---

## Testing the Scanner

### Quick Manual Test

1. Start the app and log in
2. Go to **Analyzer → Scan a URL**
3. Try these test URLs:

| URL | Expected Behavior |
|---|---|
| `https://google.com` | Safe (80+ accuracy) |
| `http://paypa1-login.tk/verify?token=2efa55ca0006a876f55d0748f2cf056e` | Suspicious (45–60 accuracy) — multiple heuristic flags, no VT history |
| `https://kyojunokai.jp/G-pp-B/hmpg.php` | Suspicious/High Risk — unusual TLD, hyphenated path, suspicious PHP name |

### Running Automated Tests

```bash
# Run smoke tests (checks basic routes, no deep analysis)
python -m pytest tests/test_integrated_scanner.py -v

# Run with coverage reporting
python -m pytest tests/ -v --cov=ml_engine --cov=routes
```

### Testing Specific Layers

To test individual scoring layers, edit `ml_engine/scoring_engine.py` at the bottom
and modify the `test_input` dict:

```python
if __name__ == '__main__':
    test_input = {
        'ml_prediction': 0.85,
        'virustotal': {
            'detection_count': 5,
            'total_scanners': 70,
            'is_malicious': True
        },
        # ... add/remove layers to test ...
    }
    result = compute_final_risk_score(test_input)
    print(f"Score: {result['final_score']}, Risk: {result['risk_level']}")
```

Then run:
```bash
python ml_engine/scoring_engine.py
```

---

## Debugging

### Enable Debug Logging

In `config.py`, set:
```python
DEBUG = True
TESTING = True
LOG_LEVEL = 'DEBUG'
```

Then restart `app.py`. Flask will reload on code changes and show full tracebacks.

### Common Issues

**"VirusTotal API error" in scan results**
- Check `.env` has `VIRUSTOTAL_API_KEY` set
- Verify the key is valid at https://www.virustotal.com/gui/my-apikey
- Check you haven't hit the free tier rate limit (4 requests/minute)

**"Google Safe Browsing API error"**
- Create a Google Cloud project and enable "Safe Browsing API"
- Generate API key at https://console.cloud.google.com → Credentials
- Add to `.env` as `GOOGLE_SAFE_BROWSING_API_KEY`

**Scan takes >8 seconds**
- Long delays usually mean API timeout (VT/GSB taking >4s each). Check your internet.
- ThreadPoolExecutor has 8s timeout per future; partial results are still returned.

**"Login rate limit (429) hit"**
- Login is limited to 15 attempts/minute globally for security
- Wait 1 minute or reduce `@limiter.limit('15/minute')` in `routes/auth.py` for development

**Database is corrupted / won't start**
```bash
# Delete the DB file and get a fresh auto-seeded copy
rm instance/phishing_simulator.db
python app.py
```

### Inspect the Database

Use SQLite CLI to check database state:

```bash
sqlite3 instance/phishing_simulator.db

# View users
SELECT id, username, email, role, is_primary_admin FROM users;

# View recent scans
SELECT id, url, final_score, final_label, accuracy, scanned_at FROM scan_results ORDER BY scanned_at DESC LIMIT 10;

# View privilege changes (admin audits)
SELECT * FROM privilege_changes ORDER BY timestamp DESC;

# Exit
.quit
```

---

## Retraining the ML model (optional)

The trained model (`ml_engine/phishing_model.pkl`) is already committed and ready to use —
you don't need to retrain it to run the app. If you want to retrain it (e.g. after changing
features or getting a larger dataset):

```bash
python ml_engine/train_model.py
```

This reads `../Data/URL dataset.csv` (real, labeled legitimate + phishing URLs — **not**
synthetic data), extracts the 43-feature lexical vector in the same `fast=True` mode used at
inference time (30 original CTU/PhishTank-style features + 13 enriched features: entropy,
character ratios, brand-similarity, suspicious-TLD/punycode flags, etc.), applies SMOTE
oversampling to the training split, trains a soft-voting ensemble (RandomForest + ExtraTrees +
XGBoost) with a balanced 50/50 sample of both classes, and overwrites `phishing_model.pkl`.

**Measured test-set performance**: 91.92% accuracy, 94.32% precision, 89.20% recall, 91.69% F1.
An earlier single-RandomForest version on the original 30-feature set measured only 60.90%
accuracy — the gap was feature impoverishment, not the algorithm: in `fast=True` mode, only
9 of those 30 features actually vary (the rest depend on skipped network calls and default to
constants). The 13 enriched features fixed that without adding any network dependency.

> **Why "fast=True" for both training and inference matters:** the live scanner uses
> lexical-only feature extraction (no live network calls) to keep every scan under 10
> seconds. The model is trained on the *same* feature distribution it sees at inference —
> training on a richer feature set (with WHOIS/SSL/page-content data) while serving on the
> lexical-only set would make the model see out-of-distribution input on every real scan.

### Evaluating the full system (optional)

`train_model.py` measures the ML model alone. To measure the actual deployed pipeline —
ML + VirusTotal + Google Safe Browsing + URL rules + threat feeds + SSL + redirect +
typosquatting, combined exactly as `routes/analyzer.py` does on a real scan:

```bash
python ml_engine/evaluate_system.py --n-per-class 50
```

This samples URLs held out from ML training, runs each through the real pipeline (live VT/GSB
API calls included), and reports accuracy/precision/recall/F1 against ground truth. Runtime is
dominated by VirusTotal's free-tier rate limit (~4 req/min), so `--n-per-class 50` (100 URLs
total) takes ~25-30 minutes. Results are saved to `ml_engine/system_eval_results.json`.

**Measured result**: 95.00% accuracy, 90.91% precision, 100% recall, 95.24% F1.

---

## Features & Architecture

### Multi-Layer Scoring (Fast & Accurate)

- **VirusTotal**: 70+ independent antivirus engines (when available)
- **ML Model**: Fast lexical-only voting ensemble (RandomForest + ExtraTrees + XGBoost), no network calls, <1s, 91.92% test accuracy
- **Google Safe Browsing**: Binary phishing/malware flag
- **URL Heuristics**: Pattern matching (hex tokens, malware extensions, phishing keywords, IP hosts, suspicious paths)
- **Threat Feeds**: Real-time URLhaus/OpenPhish/URLvoid consensus
- **SSL/Redirect/Typo**: Supporting signals

All layers run in parallel with 8s timeout per layer; partial results are still returned if
a layer times out. A full scan usually completes in 4–8 seconds.

### Admin Features

- **User Management**: Promote/revoke admins, lock accounts, view sessions
- **Privilege Audit Trail**: Every admin promotion/demotion logged with timestamp and actor
- **Campaign Creation**: Template emails, bulk user targeting, click/open tracking
- **Training Modules**: Interactive lessons, quizzes, badges, certificates, leaderboard
- **Reports**: Dashboard analytics, campaign performance, user progress

### Security

- **Rate Limiting**: Login (15/min), scans (30/min per user), API endpoints
- **CSRF Protection**: All forms require `{{ csrf_token() }}`
- **SSRF Guard**: Prevents URL scanning from hitting internal IPs
- **Input Sanitization**: XSS protection, SQL injection prevention via ORM
- **Concurrent Scan Lock**: Only 1 scan per user at a time (prevents DoS via queued scans)
- **Session Management**: Auto-logout after 30 min inactivity
- **HTTPS Enforcement**: Talisman enforces HTTPS in production

---

## Deployment

The app is ready for deployment to **Railway**, **Heroku**, or any WSGI-compatible host.

### Railway (recommended)

1. Fork this repo to GitHub
2. Create a Railway project and connect your GitHub repo
3. Set environment variables in Railway dashboard:
   - `SECRET_KEY` (generate with `python -c "import secrets; print(secrets.token_hex(32))"`)
   - `VIRUSTOTAL_API_KEY` (optional)
   - `GOOGLE_SAFE_BROWSING_API_KEY` (optional)
   - `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` (for email functionality)
4. Railway auto-detects `Procfile` and deploys

### Heroku (deprecated, still works)

```bash
heroku create your-app-name
heroku config:set SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
git push heroku main
heroku logs --tail
```

---

## Troubleshooting

**Scan takes a long time on the first request**
The OpenPhish feed cache warms up on first use (one HTTP fetch); subsequent scans in the
same process are faster. This is expected.

**"VirusTotal API error" / "GSB API error" in scan results**
Either the API key is missing/invalid in `.env`, or you've hit the free-tier rate limit
(VirusTotal free tier: 4 requests/minute). The scanner still produces a full result using
the ML model and URL heuristics even when these are unavailable.

**Login rate limit (429) hit during testing**
Login is limited to 15 attempts/minute. Wait a minute, or raise the limit in
`routes/auth.py` (`@limiter.limit(...)`) for local development.

**`flask db` commands fail / "no such table"**
Make sure your virtual environment is active and you're running commands from inside
`project/`. Delete `instance/phishing_simulator.db` and restart `app.py` to get a fresh
auto-seeded database if it becomes corrupted during development.

**Want to use ngrok to expose your local server publicly**
Download ngrok yourself from https://ngrok.com/download — it's not bundled in this repo
(it's a third-party binary, intentionally excluded from version control).

---

## Performance & Benchmarks

- **Scan latency**: 4–8 seconds (all layers in parallel, 8s timeout per layer)
- **VirusTotal**: ~2–4s (API call + 70 engine scanning)
- **ML inference**: <1s (lexical features only, no network)
- **URL heuristics**: <100ms (regex pattern matching)
- **Threat feeds**: ~1–2s (cached URLhaus, live OpenPhish)
- **Concurrent scans**: Locked per user (only 1 at a time to prevent DoS)

---

## License

Academic project — for educational and research purposes only.

---

## Contact & Support

For questions or issues, refer to the source code comments or contact the project maintainer.
