from functools import wraps
from flask import abort
from flask_login import current_user

def permission_required(permission_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.PermissionTier < permission_level:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(3)(f)

def super_admin_required(f):
    return permission_required(4)(f)

def employee_required(f):
    return permission_required(2)(f)
