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
│   ├── feature_extractor.py    # 30-feature URL extractor (fast=True = lexical-only, instant)
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
├── tests/                       # Manual smoke-test scripts
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

## Retraining the ML model (optional)

The trained model (`ml_engine/phishing_model.pkl`) is already committed and ready to use —
you don't need to retrain it to run the app. If you want to retrain it (e.g. after changing
features or getting a larger dataset):

```bash
python ml_engine/train_model.py
```

This reads `../Data/URL dataset.csv` (real, labeled legitimate + phishing URLs — **not**
synthetic data), extracts the 30-feature lexical vector in the same `fast=True` mode used at
inference time, trains a `RandomForestClassifier` with a balanced 50/50 sample of both
classes, and overwrites `phishing_model.pkl`.

> **Why "fast=True" for both training and inference matters:** the live scanner uses
> lexical-only feature extraction (no live network calls) to keep every scan under 10
> seconds. The model is trained on the *same* feature distribution it sees at inference —
> training on a richer feature set (with WHOIS/SSL/page-content data) while serving on the
> lexical-only set would make the model see out-of-distribution input on every real scan.

---

## How the risk score is calculated

Each scan combines several independent signals, weighted by reliability:

| Layer | Weight | What it checks |
|---|---|---|
| VirusTotal | 28% | 70+ antivirus engine consensus |
| URL Heuristics (rule-based) | 20% | Hex tracking tokens, malware file extensions, phishing keywords, IP-as-host, suspicious paths — works even on brand-new URLs no database has seen yet |
| Google Safe Browsing | 18% | Google's crawled threat index |
| ML Model | 13% | Trained classifier on lexical URL features |
| Threat Feeds | 12% | URLhaus / OpenPhish / URLvoid |
| SSL / Redirects / Typosquatting | 9% combined | Supporting signals |

On top of the weighted average, several **override rules** enforce a minimum score
regardless of the weighted result — e.g. any VirusTotal detection forces at least
"Suspicious", and 3+ URL-heuristic red flags can never return "Safe" or "Low Risk". A scan
also reports an **accuracy percentage** alongside the score, reflecting how many independent
signals actually had data for that URL (a brand-new domain with no VT/GSB history will show
a lower accuracy than one confirmed by multiple sources).

Scans are capped at ~8 seconds per analysis layer and run all layers in parallel, so a full
scan typically completes in 4–8 seconds.

---

## Troubleshooting

**Scan takes a long time on the first request of a session**
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

## License

Academic project — for educational and research purposes only.
