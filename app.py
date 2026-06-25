import truststore
truststore.inject_into_ssl()  # trust the OS certificate store (needed when local
# AV/security software does TLS interception with a root CA that's trusted by
# Windows but not by Python's bundled certifi list) — must run before any
# requests/ssl usage, so this import stays first.

from flask import Flask, render_template, session, redirect, url_for, request
from flask_login import LoginManager, logout_user, current_user
from flask_migrate import Migrate
from dotenv import load_dotenv
from datetime import datetime

from config import DevelopmentConfig
from extensions import mail, limiter, csrf, talisman
from models import db, User, Notification
from security.input_sanitizer import sanitize_html_output

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(DevelopmentConfig)

    # ── Security: Jinja2 Auto-Escaping ──────────────────
    app.jinja_env.autoescape = True  # On by default for .html, but enforce explicitly

    # ── Security: Custom Jinja2 Filter ──────────────────
    @app.template_filter('safe_user')
    def safe_user_filter(value):
        """Use {{ user_content | safe_user }} to safely display user-supplied data."""
        return sanitize_html_output(str(value))

    # ── Extensions ──────────────────────────────────────
    db.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    Migrate(app, db)

    # ── Security Headers (Threat 12) ─────────────────────
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
        'style-src': ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'fonts.googleapis.com'],
        'font-src': ["'self'", 'fonts.gstatic.com', 'cdnjs.cloudflare.com'],
        'img-src': ["'self'", 'data:', 'https:'],
        'connect-src': ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
        'frame-ancestors': "'none'",
        'form-action': "'self'",
    }
    talisman.init_app(app,
        content_security_policy=csp,
        force_https=False,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        frame_options='DENY',
        referrer_policy='strict-origin-when-cross-origin',
    )

    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ── Session Security (Threat 7) ──────────────────────
    @app.before_request
    def session_management():
        """Enforce session timeout and session binding (user-agent change detection)."""
        if current_user.is_authenticated:
            # Check session timeout (2 hours)
            last_activity = session.get('_last_activity')
            now = datetime.utcnow()

            if last_activity:
                try:
                    last = datetime.fromisoformat(last_activity)
                    if (now - last).total_seconds() > 7200:  # 2 hours
                        logout_user()
                        session.clear()
                        return redirect(url_for('auth.login'))
                except (ValueError, TypeError):
                    pass

            session['_last_activity'] = now.isoformat()
            session.modified = True

            # Detect session hijacking via user-agent change
            stored_ua = session.get('_ua', '')
            current_ua = request.headers.get('User-Agent', '')[:200]
            if stored_ua and stored_ua != current_ua:
                logout_user()
                session.clear()
                return redirect(url_for('auth.login'))

    # ── Blueprints ───────────────────────────────────────
    from routes.auth import auth, admin_bp
    from routes.analyzer import analyzer
    from routes.simulator import simulator, tracking
    from routes.training import training, training_admin
    from routes.dashboard import dashboard, admin_dash, api_stats, user_dash
    from routes.reports import reports

    app.register_blueprint(auth)           # /auth/...
    app.register_blueprint(admin_bp)       # /admin/...
    app.register_blueprint(analyzer)
    app.register_blueprint(simulator)
    app.register_blueprint(tracking)
    app.register_blueprint(training)       # /training/...
    app.register_blueprint(training_admin) # /admin/training/...
    app.register_blueprint(dashboard)      # /dashboard/...
    app.register_blueprint(admin_dash)     # /admin/dashboard
    app.register_blueprint(api_stats)      # /api/stats/...
    app.register_blueprint(user_dash)      # /user/dashboard
    app.register_blueprint(reports)

    # Exempt blueprints that use fetch()/DELETE or are public-facing
    csrf.exempt(analyzer)       # scan endpoint uses fetch POST
    csrf.exempt(tracking)       # public phishing simulation pages
    csrf.exempt(api_stats)      # JSON-only GET endpoints
    csrf.exempt(simulator)      # DELETE routes via fetch
    csrf.exempt(training)       # quiz submit uses fetch POST
    csrf.exempt(dashboard)      # no form submissions
    csrf.exempt(admin_dash)     # no form submissions
    csrf.exempt(user_dash)      # no form submissions

    # ── Landing ──────────────────────────────────────────
    @app.route('/')
    def index():
        return render_template('index.html')

    # ── Error handlers ───────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    # ── DB init + auto-seed ───────────────────────────────
    with app.app_context():
        db.create_all()

        # Seed default users (safe — only creates if not already present)
        try:
            if not User.query.filter_by(email='admin@eseas.com').first():
                admin = User(name='Admin User', email='admin@eseas.com', role='admin', is_primary_admin=True)
                admin.set_password('Admin@1234')
                db.session.add(admin)
                db.session.commit()
        except Exception:
            db.session.rollback()

        try:
            if not User.query.filter_by(email='alice@eseas.com').first():
                demo = User(name='Alice Demo', email='alice@eseas.com', role='user')
                demo.set_password('User@1234')
                db.session.add(demo)
                db.session.commit()
        except Exception:
            db.session.rollback()

        try:
            from seed_training import seed_training_modules
            seed_training_modules()
        except Exception:
            pass
        try:
            from seed_simulator import seed_simulator_templates
            seed_simulator_templates()
        except Exception:
            pass

        # Ensure there is always exactly one primary admin
        _init_primary_admin()

    return app


def _init_primary_admin():
    """Ensure there is always exactly one primary admin."""
    try:
        primary = User.query.filter_by(is_primary_admin=True).first()
        if not primary:
            # Find the first admin (or create one)
            existing_admin = User.query.filter_by(role='admin').order_by(User.created_at).first()
            if existing_admin:
                existing_admin.is_primary_admin = True
                db.session.commit()
    except Exception:
        # Column may not exist yet if migrations haven't been run — silently continue
        pass


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
