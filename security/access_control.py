"""Access control decorators to prevent IDOR and privilege escalation."""
from functools import wraps
from flask import abort, current_app
from flask_login import current_user


def owner_required(model_class, id_param='id', owner_field='user_id'):
    """
    Decorator: Route accessible only if the requested resource belongs to current_user.
    Admins bypass the ownership check.

    Usage:
        @owner_required(ScanResult, 'scan_id')
        def view_scan(scan_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resource_id = kwargs.get(id_param)

            # Fetch resource — abort 404 if not found
            resource = model_class.query.get_or_404(resource_id)

            # Admins can access any resource
            if current_user.role == 'admin':
                return f(*args, **kwargs)

            # Regular users: check ownership
            owner_id = getattr(resource, owner_field, None)
            if owner_id != current_user.id:
                current_app.logger.warning(
                    f"IDOR attempt detected: user_id={current_user.id} "
                    f"tried to access {model_class.__name__}:{resource_id} "
                    f"owned by user_id={owner_id}"
                )
                abort(403)

            return f(*args, **kwargs)
        return decorated
    return decorator
