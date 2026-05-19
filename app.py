from flask import Flask, render_template
from flask_login import LoginManager
from flask_migrate import Migrate
from dotenv import load_dotenv

from config import DevelopmentConfig
from extensions import mail, limiter, csrf
from models import db, User, Notification

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(DevelopmentConfig)

    # ── Extensions ──────────────────────────────────────
    db.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    Migrate(app, db)

    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

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
                admin = User(name='Admin User', email='admin@eseas.com', role='admin')
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

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
