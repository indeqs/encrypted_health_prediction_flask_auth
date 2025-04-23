from markupsafe import Markup
from flask import (
    redirect,
    url_for,
    flash,
    session,
    current_app,
)  # Use current_app for logger/config
from functools import wraps
from ..models import User  # Use relative import from parent package
from .. import db


def nl2br_filter(s):
    """Convert newlines to <br> tags for proper display in HTML"""
    if s is None:
        return ""
    # Ensure s is a string before replacing
    s = str(s)
    return Markup(s.replace("\n", "<br>\n"))


def redirect_logged_in_user(user):
    """Redirects a logged-in and verified user based on their role."""
    if not user:
        return redirect(url_for("auth.login"))  # Use blueprint name

    # Use is_admin flag primarily for admin role checks
    if user.is_admin:
        flash(f"Welcome back, Admin {user.username}!", "success")
        return redirect(url_for("admin.adminDashboard"))
    elif user.role == "medic":
        # --- NEW CHECK
        if not user.is_approved:
            # This user verified email but is waiting for admin approval
            flash("Your medic account is awaiting administrator approval.", "danger")
            # Maybe redirect to login to show flash, or a dedicated static page
            return redirect(
                url_for("auth.login")
            )  # Or create url_for('main.pending_approval')

        # Approved medic proceeds
        flash(f"Welcome back, Dr. {user.username}!", "success")
        return redirect(url_for("medic.medicDashboard"))
    elif user.role == "patient":
        # flash(f"Welcome back, {user.username}!", "success")
        # Consider making this URL configurable
        return redirect(
            current_app.config.get("PATIENT_APP_URL", "http://localhost:7860/")
        )
    else:
        # Fallback for unknown roles
        current_app.logger.warning(
            f"User {user.username} (ID: {user.id}) has unknown role: {user.role}. Redirecting home."
        )
        flash(f"Welcome back, {user.username}!", "info")
        return redirect(url_for("main.home"))
