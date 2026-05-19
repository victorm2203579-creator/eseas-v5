import json
from datetime import datetime, timezone
from models.user import db


class TrainingModule(db.Model):
    __tablename__ = 'training_modules'

    id                 = db.Column(db.Integer, primary_key=True)
    title              = db.Column(db.String(120), nullable=False)
    description        = db.Column(db.Text, default='')
    topic              = db.Column(db.String(40), nullable=False)
    content_html       = db.Column(db.Text, nullable=False, default='')
    video_url          = db.Column(db.String(300), nullable=True)
    order_index        = db.Column(db.Integer, default=0)
    is_active          = db.Column(db.Boolean, default=True)
    estimated_minutes  = db.Column(db.Integer, default=10)
    icon_class         = db.Column(db.String(60), default='fa-book')

    # topic options: phishing, social_engineering, safe_browsing, passwords, incident_response
    TOPIC_META = {
        'phishing':          ('Phishing',          'danger',  'fa-envelope-open-text'),
        'social_engineering': ('Social Engineering','warning', 'fa-user-secret'),
        'safe_browsing':     ('Safe Browsing',      'info',    'fa-globe'),
        'passwords':         ('Passwords',          'primary', 'fa-lock'),
        'incident_response': ('Incident Response',  'success', 'fa-shield-halved'),
    }

    questions   = db.relationship('Quiz', backref='module', cascade='all, delete-orphan',
                                   lazy='dynamic', order_by='Quiz.id')
    progress    = db.relationship('UserProgress', backref='module', cascade='all, delete-orphan')
    assignments = db.relationship('TrainingAssignment', backref='module', cascade='all, delete-orphan')

    @property
    def topic_label(self):
        return self.TOPIC_META.get(self.topic, (self.topic,))[0]

    @property
    def topic_color(self):
        return self.TOPIC_META.get(self.topic, ('', 'secondary', ''))[1]

    @property
    def question_count(self):
        return self.questions.count()


class Quiz(db.Model):
    __tablename__ = 'quiz_questions'

    id             = db.Column(db.Integer, primary_key=True)
    module_id      = db.Column(db.Integer, db.ForeignKey('training_modules.id'), nullable=False)
    question_text  = db.Column(db.Text, nullable=False)
    option_a       = db.Column(db.String(300), nullable=False)
    option_b       = db.Column(db.String(300), nullable=False)
    option_c       = db.Column(db.String(300), nullable=False)
    option_d       = db.Column(db.String(300), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)   # 'a' / 'b' / 'c' / 'd'
    explanation    = db.Column(db.Text, nullable=False, default='')
    points         = db.Column(db.Integer, default=20)

    def get_option_text(self, letter):
        return getattr(self, f'option_{letter.lower()}', '')


class UserProgress(db.Model):
    __tablename__ = 'user_progress'

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    module_id        = db.Column(db.Integer, db.ForeignKey('training_modules.id'), nullable=False)
    status           = db.Column(db.String(20), default='not_started')
    # status: not_started / in_progress / passed / failed
    started_at       = db.Column(db.DateTime, nullable=True)
    completed_at     = db.Column(db.DateTime, nullable=True)
    quiz_score       = db.Column(db.Integer, nullable=True)
    quiz_passed      = db.Column(db.Boolean, default=False)
    attempts         = db.Column(db.Integer, default=0)
    last_attempt_at  = db.Column(db.DateTime, nullable=True)
    last_attempt_json = db.Column(db.Text, nullable=True)   # JSON per-question breakdown

    __table_args__ = (
        db.UniqueConstraint('user_id', 'module_id', name='uq_user_module_v2'),
    )

    @property
    def last_result(self):
        if self.last_attempt_json:
            try:
                return json.loads(self.last_attempt_json)
            except Exception:
                return []
        return []

    @property
    def elapsed_minutes(self):
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds() / 60, 1)
        return None


class TrainingAssignment(db.Model):
    __tablename__ = 'training_assignments'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    module_id      = db.Column(db.Integer, db.ForeignKey('training_modules.id'), nullable=False)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reason         = db.Column(db.String(40), nullable=False, default='manual')
    # reason: campaign_click / credential_entry / manual
    campaign_id    = db.Column(db.Integer, db.ForeignKey('sim_campaigns.id'), nullable=True)
    assigned_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    due_date       = db.Column(db.DateTime, nullable=True)
    completed      = db.Column(db.Boolean, default=False)
    completed_at   = db.Column(db.DateTime, nullable=True)

    user        = db.relationship('User', foreign_keys=[user_id], backref='training_assignments')
    assigned_by = db.relationship('User', foreign_keys=[assigned_by_id])

    REASON_LABELS = {
        'campaign_click':   ('Clicked simulation link',    'warning'),
        'credential_entry': ('Entered fake credentials',   'danger'),
        'manual':           ('Manually assigned by admin', 'info'),
    }

    @property
    def reason_label(self):
        return self.REASON_LABELS.get(self.reason, (self.reason, 'secondary'))[0]

    @property
    def reason_color(self):
        return self.REASON_LABELS.get(self.reason, ('', 'secondary'))[1]


class UserBadge(db.Model):
    __tablename__ = 'user_badges'

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    badge_key         = db.Column(db.String(40), nullable=False)
    badge_name        = db.Column(db.String(80), nullable=False)
    badge_description = db.Column(db.String(200), nullable=False)
    badge_icon        = db.Column(db.String(60), nullable=False)
    earned_at         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'badge_key', name='uq_user_badge'),
    )

    user = db.relationship('User', backref='badges')
