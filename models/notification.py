from datetime import datetime, timezone
from models.user import db


class Notification(db.Model):
    __tablename__ = 'notifications'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    type       = db.Column(db.String(50), nullable=False, default='info')
    title      = db.Column(db.String(100), nullable=False)
    message    = db.Column(db.String(300), nullable=False)
    link       = db.Column(db.String(200), nullable=True)
    is_read    = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='notifications')

    def to_dict(self):
        return {
            'id':         self.id,
            'type':       self.type,
            'title':      self.title,
            'message':    self.message,
            'link':       self.link,
            'is_read':    self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class NotificationService:
    @staticmethod
    def create(user_id, type, title, message, link=None):
        try:
            n = Notification(
                user_id=user_id,
                type=type,
                title=title,
                message=message,
                link=link,
            )
            db.session.add(n)
            db.session.commit()
            return n
        except Exception:
            db.session.rollback()
            return None

    # Convenience wrappers
    @staticmethod
    def training_assigned(user_id, module_title, link=None):
        NotificationService.create(
            user_id, 'warning',
            'Mandatory Training Assigned',
            f'You have been assigned: {module_title}',
            link=link or '/training/',
        )

    @staticmethod
    def badge_awarded(user_id, badge_name):
        NotificationService.create(
            user_id, 'success',
            'Badge Earned!',
            f'You earned the "{badge_name}" badge.',
            link='/training/badges',
        )

    @staticmethod
    def quiz_passed(user_id, module_title, score):
        NotificationService.create(
            user_id, 'success',
            'Quiz Passed',
            f'You passed "{module_title}" with a score of {score}%.',
            link='/training/',
        )
