from functools import wraps
from flask import (
    session,
    flash,
    redirect,
    url_for,
    current_app,
)  # Use current_app for config/logger
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from .. import db  # Import db from parent package's __init__
from ..models import User

# --- Decorators ---


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "warning")
            return redirect(url_for("auth.login"))
        # Optional: Add verification check here too if needed for most logged-in routes
        user = db.session.get(User, session["user_id"])
        if not user:  # Handle case where user_id in session is invalid
            session.clear()
            flash("Invalid session. Please log in again.", "warning")
            return redirect(url_for("auth.login"))
        if (
            not user.is_verified and not user.is_admin
        ):  # Admins bypass verification generally
            # Check if verification is needed based on DB state, not just session flag
            session["needs_verification"] = True  # Ensure session reflects state
            flash("Please verify your email to continue.", "warning")
            return redirect(url_for("auth.verify"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "warning")
            return redirect(url_for("auth.login"))

        user = db.session.get(User, session["user_id"])
        # Check user exists AND is_admin flag is True
        if not user or not user.is_admin:
            flash("Admin privileges required for this page.", "danger")
            # Redirect non-admins based on role or to home
            if user and user.role == "medic":
                return redirect(url_for("medic.medicDashboard"))
            elif user:
                return redirect(url_for("main.home"))  # Or patient app URL
            else:  # User not found in DB
                session.clear()
                return redirect(url_for("auth.login"))

        # Ban check specifically for admins accessing admin areas
        if user.is_banned:
            session.clear()  # Log out banned admin too
            flash("Your admin account has been banned.", "danger")
            return redirect(url_for("auth.login"))

        return f(*args, **kwargs)

    return decorated_function


def medic_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "warning")
            return redirect(url_for("auth.login"))

        user = db.session.get(User, session["user_id"])
        # Check user exists, role is 'medic', not banned, and verified
        if not user or user.role != "medic":
            flash("Medic privileges required for this page.", "danger")
            if (
                user and user.is_admin
            ):  # Admin might access? Decide policy. Redirecting admin for now.
                return redirect(url_for("admin.adminDashboard"))
            elif user:
                return redirect(url_for("main.home"))  # Or patient app URL
            else:  # User not found
                session.clear()
                return redirect(url_for("auth.login"))

        if user.is_banned:
            session.clear()
            flash("Your medic account has been banned.", "danger")
            return redirect(url_for("auth.login"))

        if not user.is_verified:
            session["needs_verification"] = True
            flash("Please verify your email to access the dashboard.", "danger")
            return redirect(url_for("auth.verify"))

        # ---- NEW CHECK ---
        if not user.is_approved:
            flash("Your medic account is awaiting administrator approval.", "danger")
            # Redirect to login or a dedicated landing page
            return redirect(url_for("auth.login"))

        return f(*args, **kwargs)

    return decorated_function


# Note: ban_check is integrated into before_request or other decorators now.
# If you need it separately:
# def ban_check(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if "user_id" in session:
#             user = db.session.get(User, session["user_id"])
#             if user and user.is_banned:
#                 session.clear()
#                 flash("Your account has been banned", "danger")
#                 return redirect(url_for("auth.login"))
#         return f(*args, **kwargs)
#     return decorated_function

# --- Token Generation/Confirmation ---


def generate_reset_token(email):
    """Generate a secure token for password reset"""
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=current_app.config["SECURITY_PASSWORD_SALT"])


def confirm_reset_token(token, expiration=3600):
    """Confirm the reset token"""
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        email = serializer.loads(
            token, salt=current_app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except (SignatureExpired, BadSignature):
        return None
