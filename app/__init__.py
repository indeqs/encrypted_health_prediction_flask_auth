import os
import logging
from flask import Flask, session, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime

# Initialize extensions without app instances
db = SQLAlchemy()


def create_app(config_name=None):
    """Application factory function."""
    app = Flask(
        __name__, instance_relative_config=False
    )  # instance_relative_config can be useful

    # Load configuration
    if config_name is None:
        config_name = os.getenv("FLASK_CONFIG", "default")
    try:
        from .config import config_by_name

        app.config.from_object(config_by_name[config_name])
        app.logger.info(f"Loading configuration: {config_name}")
    except ImportError:
        app.logger.error("Config file not found or invalid.")
        app.config.from_object("app.config.Config")  # Fallback to base config
    except KeyError:
        app.logger.warning(f"Invalid FLASK_CONFIG name '{config_name}'. Using default.")
        app.config.from_object(config_by_name["default"])

    # Initialize extensions with the app instance
    db.init_app(app)

    # Import models here after db is initialized and configured
    from . import models  # Import models to ensure they are registered with SQLAlchemy
    from .models import User

    # --- Create Database Tables and Initial Admin ---
    with app.app_context():
        db.create_all()
        app.logger.info("Database tables checked/created.")

        # Create admin user if it doesn't exist
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_password = os.getenv(
            "ADMIN_PASSWORD", "admin"
        )  # Default password, CHANGE THIS!
        admin_email = os.getenv("ADMIN_EMAIL", "konfushon+admin@gmail.com")

        if not models.User.query.filter_by(username=admin_username).first():
            try:
                admin = models.User(
                    username=admin_username,
                    email=admin_email,
                    password_hash=generate_password_hash(admin_password),
                    is_admin=True,
                    is_verified=True,  # Make admin verified by default
                    role="admin",  # Explicitly set role
                    is_approved=True,
                )
                db.session.add(admin)
                db.session.commit()
                app.logger.info(f"Admin user '{admin_username}' created.")
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Failed to create admin user: {e}")

    # --- Register Blueprints ---
    from .auth import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")  # Optional prefix

    from .admin import admin_bp

    app.register_blueprint(admin_bp, url_prefix="/admin")

    from .medic import medic_bp

    app.register_blueprint(medic_bp, url_prefix="/medic")  # Example prefix

    from .main import main_bp

    app.register_blueprint(main_bp)  # No prefix for main routes like /, /contact

    from .api import api_bp

    app.register_blueprint(api_bp, url_prefix="/api")

    app.logger.info("Blueprints registered.")

    # --- Register Template Filters ---
    from .utils.helpers import nl2br_filter

    app.template_filter("nl2br")(nl2br_filter)
    
    @app.context_processor
    def inject_user():
        user = None
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id) # Use db.session.get
        return dict(current_user_ctx=user) # Use a distinct name like current_user_ctx


    # --- Register Request Hooks ---
    @app.before_request
    def before_request_checks():
        # Ban check - applied to all requests
        if "user_id" in session:
            user = db.session.get(models.User, session["user_id"])
            if user and user.is_banned:
                session.clear()
                flash("Your account has been banned", "danger")
                # Check if current request is already for login to avoid redirect loop
                if request.endpoint and "auth.login" not in request.endpoint:
                    return redirect(url_for("auth.login"))  # Use blueprint.endpoint

        # Verification check - applied to relevant requests
        # Note: This check is now more granular within decorators or specific routes
        #       as doing it globally here can be too broad.
        #       However, keeping a basic check might be useful if needed.
        # if "user_id" in session and session.get("needs_verification"):
        #     allowed_endpoints = [
        #         "auth.verify", "auth.resend_code", "auth.logout",
        #         "static", "auth.login" # Adjust endpoint names
        #     ]
        #     # Ensure request.endpoint is not None before checking
        #     if request.endpoint and request.endpoint not in allowed_endpoints:
        #         flash("Please verify your email to continue", "warning")
        #         return redirect(url_for("auth.verify"))

    return app
