from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import current_app

db = SQLAlchemy()

_RESET_SALT = 'password-reset-salt'
_RESET_EXPIRY = 1800  # 30 minutes


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'user' | 'admin'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    risk_score = db.Column(db.Float, default=0.0, nullable=False)  # 0–100

    sessions = db.relationship('UserSession', backref='user', lazy='dynamic',
                               cascade='all, delete-orphan')

    # ---- Flask-Login interface ----

    @property
    def is_authenticated(self):
        return True

    def get_id(self):
        return str(self.id)

    # ---- Helpers ----

    @property
    def avatar_initials(self):
        parts = self.name.split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[1][0]).upper()
        return self.name[:2].upper() if self.name else '??'

    def is_admin(self):
        return self.role == 'admin'

    # ---- Password ----

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ---- Password-reset tokens ----

    def get_reset_token(self):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return s.dumps(self.email, salt=_RESET_SALT)

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt=_RESET_SALT, max_age=_RESET_EXPIRY)
        except (SignatureExpired, BadSignature):
            return None
        return User.query.filter_by(email=email).first()

    def __repr__(self):
        return f'<User {self.name!r} ({self.role})>'


class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False,
                        index=True)
    ip_address = db.Column(db.String(45))   # IPv6 max length
    user_agent = db.Column(db.String(256))
    logged_in_at = db.Column(db.DateTime,
                             default=lambda: datetime.now(timezone.utc))
    logged_out_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<UserSession user_id={self.user_id} ip={self.ip_address}>'
