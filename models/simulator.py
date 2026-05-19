import uuid
from datetime import datetime, timezone
from models.user import db


class AttackTemplate(db.Model):
    __tablename__ = 'attack_templates'

    id               = db.Column(db.Integer, primary_key=True)
    name             = db.Column(db.String(120), nullable=False)
    attack_type      = db.Column(db.String(40), nullable=False)
    subject          = db.Column(db.String(200), nullable=False)
    preview_text     = db.Column(db.String(200), default='')
    body_html        = db.Column(db.Text, nullable=False)
    fake_page_type   = db.Column(db.String(40), default='it_login')
    description      = db.Column(db.Text, default='')
    difficulty_level = db.Column(db.Integer, default=3)   # 1–5
    created_by       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active        = db.Column(db.Boolean, default=True)

    creator          = db.relationship('User', backref='created_templates',
                                        foreign_keys=[created_by])

    ATTACK_TYPE_META = {
        'phishing_email': ('Phishing Email',  'fa-envelope',       'danger'),
        'spear_phishing': ('Spear Phishing',  'fa-crosshairs',     'danger'),
        'smishing':       ('SMS Phishing',    'fa-mobile-screen',  'warning'),
        'pretexting':     ('Pretexting',      'fa-user-secret',    'warning'),
        'prize_lure':     ('Prize Lure',      'fa-gift',           'success'),
        'it_support':     ('IT Support',      'fa-headset',        'info'),
    }

    FAKE_PAGE_CHOICES = [
        ('it_login',   'Corporate IT Portal'),
        ('bank_login', 'Bank Login Page'),
        ('prize_claim','Prize Claim Page'),
    ]

    @property
    def attack_type_label(self):
        return self.ATTACK_TYPE_META.get(self.attack_type, (self.attack_type,))[0]

    @property
    def attack_type_icon(self):
        return self.ATTACK_TYPE_META.get(self.attack_type, ('', 'fa-envelope', 'secondary'))[1]

    @property
    def attack_type_color(self):
        return self.ATTACK_TYPE_META.get(self.attack_type, ('', '', 'secondary'))[2]

    @property
    def difficulty_stars(self):
        return '★' * self.difficulty_level + '☆' * (5 - self.difficulty_level)


class Campaign(db.Model):
    __tablename__ = 'sim_campaigns'

    id                  = db.Column(db.Integer, primary_key=True)
    name                = db.Column(db.String(120), nullable=False)
    description         = db.Column(db.Text, default='')
    attack_type         = db.Column(db.String(40), nullable=False)
    template_id         = db.Column(db.Integer,
                                     db.ForeignKey('attack_templates.id'), nullable=True)
    admin_id            = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status              = db.Column(db.String(20), default='draft')
    target_count        = db.Column(db.Integer, default=0)
    emails_sent         = db.Column(db.Integer, default=0)
    links_clicked       = db.Column(db.Integer, default=0)
    credentials_entered = db.Column(db.Integer, default=0)
    reports_submitted   = db.Column(db.Integer, default=0)
    created_at          = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    scheduled_at        = db.Column(db.DateTime, nullable=True)
    launched_at         = db.Column(db.DateTime, nullable=True)
    completed_at        = db.Column(db.DateTime, nullable=True)

    admin    = db.relationship('User', backref='sim_campaigns',
                                foreign_keys=[admin_id])
    template = db.relationship('AttackTemplate', backref='campaigns')
    targets  = db.relationship('CampaignTarget', backref='campaign',
                                cascade='all, delete-orphan', lazy='dynamic')

    @property
    def click_rate(self):
        return round(self.links_clicked / self.emails_sent * 100, 1) if self.emails_sent else 0.0

    @property
    def credential_rate(self):
        return round(self.credentials_entered / self.emails_sent * 100, 1) if self.emails_sent else 0.0

    @property
    def report_rate(self):
        return round(self.reports_submitted / self.emails_sent * 100, 1) if self.emails_sent else 0.0

    @property
    def status_color(self):
        return {
            'draft':     'secondary',
            'scheduled': 'info',
            'active':    'warning',
            'completed': 'success',
        }.get(self.status, 'secondary')

    @property
    def status_icon(self):
        return {
            'draft':     'fa-file-pen',
            'scheduled': 'fa-clock',
            'active':    'fa-play',
            'completed': 'fa-flag-checkered',
        }.get(self.status, 'fa-circle')

    @property
    def attack_type_label(self):
        return AttackTemplate.ATTACK_TYPE_META.get(
            self.attack_type, (self.attack_type,))[0]

    @property
    def attack_type_icon(self):
        return AttackTemplate.ATTACK_TYPE_META.get(
            self.attack_type, ('', 'fa-envelope', 'secondary'))[1]

    @property
    def attack_type_color(self):
        return AttackTemplate.ATTACK_TYPE_META.get(
            self.attack_type, ('', '', 'secondary'))[2]


class CampaignTarget(db.Model):
    __tablename__ = 'sim_targets'

    id                  = db.Column(db.Integer, primary_key=True)
    campaign_id         = db.Column(db.Integer,
                                     db.ForeignKey('sim_campaigns.id'), nullable=False)
    user_id             = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tracking_token      = db.Column(db.String(36), unique=True, nullable=False,
                                     default=lambda: str(uuid.uuid4()))
    email_sent          = db.Column(db.Boolean, default=False)
    email_sent_at       = db.Column(db.DateTime, nullable=True)
    link_clicked        = db.Column(db.Boolean, default=False)
    clicked_at          = db.Column(db.DateTime, nullable=True)
    click_ip            = db.Column(db.String(45), nullable=True)
    credentials_entered = db.Column(db.Boolean, default=False)
    credential_at       = db.Column(db.DateTime, nullable=True)
    reported_suspicious = db.Column(db.Boolean, default=False)
    reported_at         = db.Column(db.DateTime, nullable=True)
    training_assigned   = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='campaign_targets')

    @property
    def outcome(self):
        if self.reported_suspicious:
            return 'reported'
        if self.credentials_entered:
            return 'compromised'
        if self.link_clicked:
            return 'clicked'
        if self.email_sent:
            return 'sent'
        return 'pending'

    @property
    def outcome_color(self):
        return {
            'reported':    'success',
            'compromised': 'danger',
            'clicked':     'warning',
            'sent':        'info',
            'pending':     'secondary',
        }.get(self.outcome, 'secondary')

    @property
    def outcome_icon(self):
        return {
            'reported':    'fa-shield-check',
            'compromised': 'fa-skull-crossbones',
            'clicked':     'fa-computer-mouse',
            'sent':        'fa-envelope',
            'pending':     'fa-clock',
        }.get(self.outcome, 'fa-circle')

    @property
    def time_to_click(self):
        if self.clicked_at and self.email_sent_at:
            delta   = self.clicked_at - self.email_sent_at
            minutes = int(delta.total_seconds() / 60)
            if minutes < 60:
                return f'{minutes}m'
            return f'{minutes // 60}h {minutes % 60}m'
        return '—'
