# ESEAS v5 — Enhanced Social Engineering Attack Simulator

**Final Year Cybersecurity Project**  
*Design and Implementation of an Enhanced Social Engineering Attack Simulator with Phishing Link Analysis*

---

## Project Structure

```
project/
├── app.py                   # Flask application factory
├── config.py                # DevelopmentConfig class
├── requirements.txt         # Python dependencies
├── seed_db.py               # Database seeding script
├── .env                     # Environment variables (not committed)
├── .gitignore
├── models/
│   └── __init__.py          # SQLAlchemy db + User model
├── routes/
│   ├── auth.py              # Login / Register / Logout
│   ├── analyzer.py          # URL phishing scanner
│   ├── simulator.py         # Attack simulation campaigns (admin)
│   ├── training.py          # Awareness training modules
│   ├── dashboard.py         # User/admin dashboard
│   └── reports.py           # Report generation (admin)
├── ml_engine/
│   ├── feature_extractor.py # URL feature extraction (15 features)
│   ├── train_model.py       # Model training script
│   └── phishing_model.pkl   # Trained RandomForest model
├── static/
│   ├── css/style.css
│   └── js/main.js
├── templates/
│   ├── base.html            # Master layout (Bootstrap 5)
│   ├── index.html           # Landing page
│   ├── auth/                # Login, register, profile
│   ├── dashboard/
│   ├── analyzer/
│   ├── simulator/
│   ├── training/
│   ├── reports/
│   └── errors/              # 403, 404, 500
└── tests/
```

---

## Setup

### 1. Create & activate a virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Edit `.env` with your real values:

```
SECRET_KEY=<strong-random-key>
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
VIRUSTOTAL_API_KEY=<your-key>
GOOGLE_SAFE_BROWSING_API_KEY=<your-key>
```

### 4. Run the application

```bash
flask run
```

The app starts at **http://127.0.0.1:5000**

---

## Seed the Database

Creates an admin and a test user:

```bash
python seed_db.py
```

| Role  | Email              | Password   |
|-------|--------------------|------------|
| Admin | admin@eseas.dev    | Admin@1234 |
| User  | user@eseas.dev     | User@1234  |

---

## Train the ML Model

The datasets are in `../Data/`. Run from the `project/` directory:

```bash
python ml_engine/train_model.py
```

This reads `URL dataset.csv`, extracts 15 URL features, trains a
`RandomForestClassifier`, and saves `ml_engine/phishing_model.pkl`.

---

## API Keys

- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **Google Safe Browsing**: https://console.cloud.google.com

---

## License

Academic project — for educational and research purposes only.
