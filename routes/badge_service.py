"""
Badge awarding logic and training auto-assignment helpers.
Imported by routes/training.py and routes/simulator.py.
"""
from datetime import datetime, timezone

from models import db


# ── Badge catalogue ───────────────────────────────────────────────────────────

class BadgeService:
    BADGES = {
        'vigilant_defender': {
            'name':        'Vigilant Defender',
            'description': 'Reported a phishing simulation instead of clicking.',
            'icon':        'fa-shield-halved',
            'how_to_earn': 'Report a simulated phishing email using the "Report" link.',
            'color':       'success',
        },
        'quick_learner': {
            'name':        'Quick Learner',
            'description': 'Completed your first training module.',
            'icon':        'fa-graduation-cap',
            'how_to_earn': 'Pass any training module quiz.',
            'color':       'info',
        },
        'cyber_champion': {
            'name':        'Cyber Champion',
            'description': 'Completed all cybersecurity training modules.',
            'icon':        'fa-trophy',
            'how_to_earn': 'Pass the quiz in every available training module.',
            'color':       'warning',
        },
        'phishing_spotter': {
            'name':        'Phishing Spotter',
            'description': 'Scored 100% on the Phishing module quiz.',
            'icon':        'fa-crosshairs',
            'how_to_earn': 'Answer all questions correctly on the phishing module quiz.',
            'color':       'danger',
        },
        'perfect_score': {
            'name':        'Perfect Score',
            'description': 'Achieved 100% on any quiz.',
            'icon':        'fa-star',
            'how_to_earn': 'Answer every question correctly on any module quiz.',
            'color':       'warning',
        },
        'speed_learner': {
            'name':        'Speed Learner',
            'description': 'Completed a full module (lesson + quiz) in under 10 minutes.',
            'icon':        'fa-bolt',
            'how_to_earn': 'Read the lesson and pass the quiz in under 10 minutes.',
            'color':       'primary',
        },
    }

    @staticmethod
    def _award(user_id, badge_key):
        """Award a badge if not already earned. Returns badge_key if newly awarded, else None."""
        from models.training import UserBadge
        existing = UserBadge.query.filter_by(user_id=user_id, badge_key=badge_key).first()
        if existing:
            return None
        meta = BadgeService.BADGES[badge_key]
        db.session.add(UserBadge(
            user_id=user_id,
            badge_key=badge_key,
            badge_name=meta['name'],
            badge_description=meta['description'],
            badge_icon=meta['icon'],
        ))
        return badge_key

    @staticmethod
    def award_vigilant_defender(user_id):
        """Call when a user reports a simulation."""
        earned = BadgeService._award(user_id, 'vigilant_defender')
        if earned:
            db.session.commit()
        return [earned] if earned else []

    @staticmethod
    def check_and_award_badges(user_id):
        """
        Check all badge conditions and award any newly earned badges.
        Called after a quiz is passed. Returns list of newly awarded badge_keys.
        """
        from models.training import TrainingModule, UserProgress, UserBadge

        newly_earned = []
        passed_progresses = (UserProgress.query
                             .filter_by(user_id=user_id, quiz_passed=True)
                             .all())
        passed_module_ids = {p.module_id for p in passed_progresses}

        # quick_learner: first module passed
        if len(passed_module_ids) >= 1:
            k = BadgeService._award(user_id, 'quick_learner')
            if k:
                newly_earned.append(k)

        # cyber_champion: all active modules passed
        total_active = TrainingModule.query.filter_by(is_active=True).count()
        if total_active > 0 and len(passed_module_ids) >= total_active:
            k = BadgeService._award(user_id, 'cyber_champion')
            if k:
                newly_earned.append(k)

        # phishing_spotter: 100% on the phishing module
        phishing_mod = TrainingModule.query.filter_by(topic='phishing', is_active=True).first()
        if phishing_mod:
            p = UserProgress.query.filter_by(
                user_id=user_id, module_id=phishing_mod.id, quiz_passed=True).first()
            if p and p.quiz_score == 100:
                k = BadgeService._award(user_id, 'phishing_spotter')
                if k:
                    newly_earned.append(k)

        # perfect_score: 100% on any quiz
        has_perfect = any(p.quiz_score == 100 for p in passed_progresses)
        if has_perfect:
            k = BadgeService._award(user_id, 'perfect_score')
            if k:
                newly_earned.append(k)

        # speed_learner: completed any module in under 10 minutes
        for p in passed_progresses:
            if p.started_at and p.completed_at:
                elapsed = (p.completed_at - p.started_at).total_seconds()
                if elapsed < 600:
                    k = BadgeService._award(user_id, 'speed_learner')
                    if k:
                        newly_earned.append(k)
                    break

        if newly_earned:
            db.session.commit()

        return newly_earned


# ── Auto-assignment helpers ───────────────────────────────────────────────────

def auto_assign_training(user_id, reason, campaign_id=None,
                         assigned_by_id=None, assign_all=False):
    """
    Add TrainingAssignment rows for a user.
    Does NOT call db.session.commit() — caller is responsible.

    assign_all=False → assigns only modules with topic='phishing'
    assign_all=True  → assigns all active modules (used after credential entry)
    """
    from models.training import TrainingModule, TrainingAssignment

    if assign_all:
        modules = TrainingModule.query.filter_by(is_active=True).all()
    else:
        modules = TrainingModule.query.filter_by(topic='phishing', is_active=True).all()

    for module in modules:
        existing = TrainingAssignment.query.filter_by(
            user_id=user_id, module_id=module.id).first()
        if not existing:
            db.session.add(TrainingAssignment(
                user_id=user_id,
                module_id=module.id,
                assigned_by_id=assigned_by_id,
                reason=reason,
                campaign_id=campaign_id,
            ))
