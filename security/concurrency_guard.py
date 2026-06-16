"""Prevent race conditions and concurrent duplicate operations."""
import threading
from functools import wraps
from flask import jsonify
from flask_login import current_user


_locks: dict = {}
_registry_lock = threading.Lock()


def _get_lock(user_id: int, operation: str) -> threading.Lock:
    """Get or create a per-user per-operation lock."""
    key = f"{user_id}:{operation}"
    with _registry_lock:
        if key not in _locks:
            _locks[key] = threading.Lock()
    return _locks[key]


def prevent_concurrent(operation: str):
    """
    Decorator: Prevent concurrent requests of the same operation by the same user.
    Useful for quiz submission, URL scans, etc. to prevent duplicate processing.

    Usage:
        @prevent_concurrent('quiz_submit')
        def submit_quiz(module_id):
            ...

    If a user has a request in progress, subsequent requests from that user
    for the same operation will return 429 (Too Many Requests).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            lock = _get_lock(current_user.id, operation)

            # Try to acquire lock with 5-second timeout
            acquired = lock.acquire(timeout=5)
            if not acquired:
                return jsonify({
                    'error': 'Operation in progress. Please wait and try again.'
                }), 429

            try:
                return f(*args, **kwargs)
            finally:
                lock.release()

        return decorated
    return decorator
