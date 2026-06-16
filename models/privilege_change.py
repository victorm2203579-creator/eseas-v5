from datetime import datetime, timezone
from models.user import db


class PrivilegeChange(db.Model):
    """Audit log for admin privilege promotions and demotions."""
    __tablename__ = 'privilege_changes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    changed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False)  # 'promoted' or 'demoted'
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    reason = db.Column(db.String(255), nullable=True)

    # Relationships (use overlaps to suppress warnings about multiple FKs to same table)
    target_user = db.relationship('User', foreign_keys=[user_id], overlaps='privilege_changes')
    actor_user = db.relationship('User', foreign_keys=[changed_by], overlaps='actor_privilege_changes')

    def __repr__(self):
        return f'<PrivilegeChange {self.id}: {self.action} user_id={self.user_id} by {self.changed_by} at {self.timestamp}>'
