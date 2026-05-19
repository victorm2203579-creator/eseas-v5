import os
from dotenv import load_dotenv

load_dotenv()

# Railway sets RAILWAY_ENVIRONMENT when running on their platform
_ON_RAILWAY = bool(os.getenv('RAILWAY_ENVIRONMENT') or os.getenv('RAILWAY_PROJECT_ID'))


class DevelopmentConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-fallback-key-change-in-production')

    # Use DATABASE_URL if provided (Railway Postgres), else SQLite
    _db_url = os.getenv('DATABASE_URL', '')
    if _db_url.startswith('postgres://'):
        # SQLAlchemy 2.x requires postgresql:// not postgres://
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = _db_url or 'sqlite:///phishing_simulator.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER   = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT     = int(os.getenv('MAIL_PORT', 587))
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_USE_TLS  = True
    MAIL_USE_SSL  = False
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')

    WTF_CSRF_ENABLED = True

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    UPLOAD_FOLDER = 'static/uploads'

    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

    BASE_URL = os.getenv('BASE_URL', 'http://127.0.0.1:5000')

    # Debug off on Railway, on locally
    DEBUG = not _ON_RAILWAY
