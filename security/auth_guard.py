"""
Authentication security for ESEAS.
Prevents brute force, timing attacks, user enumeration, weak passwords.
"""

import re
import time
from datetime import datetime, timedelta, timezone


class PasswordValidationError(ValueError):
    """Raised when password fails validation."""
    pass


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforce minimum password security standards.

    Requirements:
    - Minimum 10 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    - Not a common weak password

    Args:
        password: Password to validate

    Returns:
        Tuple[bool, str]: (is_valid, reason)
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>[\]\-_=+;:`~\\]', password):
        return False, "Password must contain at least one special character"

    # Check against common weak passwords
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'letmein', 'welcome', 'monkey', 'dragon', 'master',
        'sunshine', 'princess', 'football', 'baseball', 'iloveyou',
        'admin', 'admin123', 'pass', 'pass123', 'password123',
    ]

    if password.lower() in common_passwords:
        return False, "Password is too common"

    # Check for patterns like "Password123!" (predictable)
    if re.match(r'^[A-Z][a-z]+\d+[!@#$%^&*]?$', password):
        if len(password) == 11 or len(password) == 12:
            # Likely "Password1!" pattern
            return False, "Password pattern is too predictable"

    return True, "OK"


def constant_time_comparison(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        bool: True if strings are equal
    """
    # Ensure both strings have same length to prevent length-based timing attack
    if len(a) != len(b):
        # Use a dummy comparison to maintain constant time
        for _ in range(len(b)):
            _ = a[0] == b[0]
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)

    return result == 0


class LoginAttemptTracker:
    """
    Track login attempts per user and IP for rate limiting and lockout.
    """

    def __init__(self, db=None):
        """Initialize tracker (requires Flask-SQLAlchemy db instance)."""
        self.db = db

    def record_failed_attempt(self, user_id: int = None, email: str = None, ip_address: str = None):
        """Record a failed login attempt."""
        if not self.db:
            return

        try:
            from models import User
            from datetime import datetime, timezone

            # Get user by ID or email
            if user_id:
                user = User.query.get(user_id)
            elif email:
                user = User.query.filter_by(email=email.lower()).first()
            else:
                return

            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

                # Lock account after 5 failed attempts for 15 minutes
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)

                self.db.session.commit()
        except Exception:
            pass  # Silent fail to prevent DB errors from breaking login

    def record_successful_login(self, user_id: int):
        """Reset failed attempts counter after successful login."""
        if not self.db:
            return

        try:
            from models import User

            user = User.query.get(user_id)
            if user:
                user.failed_login_attempts = 0
                user.locked_until = None
                self.db.session.commit()
        except Exception:
            pass

    def is_user_locked(self, user_id: int = None, email: str = None) -> bool:
        """Check if user account is locked."""
        if not self.db:
            return False

        try:
            from models import User
            from datetime import datetime, timezone

            if user_id:
                user = User.query.get(user_id)
            elif email:
                user = User.query.filter_by(email=email.lower()).first()
            else:
                return False

            if user and user.locked_until:
                if datetime.now(timezone.utc) < user.locked_until:
                    return True
                else:
                    # Unlock if lockout period has expired
                    user.locked_until = None
                    self.db.session.commit()

            return False
        except Exception:
            return False

    def get_lockout_remaining_time(self, user_id: int = None, email: str = None) -> int:
        """Get remaining lockout time in seconds."""
        if not self.db:
            return 0

        try:
            from models import User
            from datetime import datetime, timezone

            if user_id:
                user = User.query.get(user_id)
            elif email:
                user = User.query.filter_by(email=email.lower()).first()
            else:
                return 0

            if user and user.locked_until:
                now = datetime.now(timezone.utc)
                if now < user.locked_until:
                    delta = user.locked_until - now
                    return int(delta.total_seconds())

            return 0
        except Exception:
            return 0


def anti_enumeration_delay():
    """
    Add a small random delay to login failures.
    Slows down automated enumeration attacks without being noticeable to humans.
    """
    import random
    time.sleep(random.uniform(0.05, 0.2))  # 50-200ms
