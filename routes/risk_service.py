"""Risk score calculation service."""
from models import db


def calculate_user_risk_score(user_id):
    """
    Score starts at 0.
    +30 if user clicked any campaign link
    +20 if user entered credentials in any simulation
    -15 if user reported any campaign as suspicious
    -10 per completed training module (max -40 deduction)
    +5 per failed quiz attempt (UserProgress where attempts > 0 and quiz_passed=False)
    Clamp to 0-100. Save to user.risk_score. Return score.
    """
    from models.user import User
    from models.simulator import CampaignTarget
    from models.training import UserProgress

    score = 0

    if CampaignTarget.query.filter_by(user_id=user_id, link_clicked=True).first():
        score += 30
    if CampaignTarget.query.filter_by(user_id=user_id, credentials_entered=True).first():
        score += 20
    if CampaignTarget.query.filter_by(user_id=user_id, reported_suspicious=True).first():
        score -= 15

    completed = UserProgress.query.filter_by(user_id=user_id, quiz_passed=True).count()
    score -= min(completed * 10, 40)

    failed = UserProgress.query.filter(
        UserProgress.user_id == user_id,
        UserProgress.attempts > 0,
        UserProgress.quiz_passed == False,  # noqa: E712
    ).count()
    score += failed * 5

    score = max(0, min(100, score))

    user = db.session.get(User, user_id)
    if user:
        user.risk_score = float(score)
        db.session.commit()

    return score


def update_all_risk_scores():
    from models.user import User
    for user in User.query.filter_by(is_active=True).all():
        calculate_user_risk_score(user.id)
