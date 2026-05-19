from datetime import datetime, timezone
from models.user import db


class Campaign(db.Model):
    __tablename__ = 'campaigns'

    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(120), nullable=False)
    description    = db.Column(db.Text, default='')
    template_type  = db.Column(db.String(40), default='generic')
    status         = db.Column(db.String(20), default='draft')  # draft | active | completed
    created_by_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    targets        = db.relationship('SimulationTarget', backref='campaign',
                                     cascade='all, delete-orphan', lazy='dynamic')
    creator        = db.relationship('User', backref='campaigns')

    @property
    def target_count(self):
        return self.targets.count()

    @property
    def sent_count(self):
        return self.targets.filter(SimulationTarget.sent_at.isnot(None)).count()

    @property
    def clicked_count(self):
        return self.targets.filter(SimulationTarget.clicked_at.isnot(None)).count()

    @property
    def reported_count(self):
        return self.targets.filter(SimulationTarget.reported_at.isnot(None)).count()

    @property
    def click_rate(self):
        sent = self.sent_count
        if sent == 0:
            return 0.0
        return round(self.clicked_count / sent * 100, 1)

    @property
    def status_color(self):
        return {'draft': 'secondary', 'active': 'warning', 'completed': 'success'}.get(self.status, 'secondary')

    @property
    def template_label(self):
        labels = {
            'generic':      'Generic Phishing',
            'credential':   'Credential Harvest',
            'invoice':      'Fake Invoice',
            'it_support':   'IT Support',
            'prize':        'Prize/Lottery',
        }
        return labels.get(self.template_type, self.template_type.title())


class SimulationTarget(db.Model):
    __tablename__ = 'simulation_targets'

    id           = db.Column(db.Integer, primary_key=True)
    campaign_id  = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    email        = db.Column(db.String(120), nullable=False)
    sent_at      = db.Column(db.DateTime, nullable=True)
    clicked_at   = db.Column(db.DateTime, nullable=True)
    reported_at  = db.Column(db.DateTime, nullable=True)

    @property
    def status(self):
        if self.reported_at:
            return 'reported'
        if self.clicked_at:
            return 'clicked'
        if self.sent_at:
            return 'sent'
        return 'pending'

    @property
    def status_color(self):
        return {
            'reported': 'success',
            'clicked':  'danger',
            'sent':     'warning',
            'pending':  'secondary',
        }.get(self.status, 'secondary')
