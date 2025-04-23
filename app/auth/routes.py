from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    current_app,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from .. import db  # Import db from parent __init__
from ..models import User
from ..utils.email_sender import send_verification_code, send_email
from ..utils.helpers import redirect_logged_in_user  # Import helper
from . import auth_bp  # Import the blueprint instance defined in auth/__init__.py
from .utils import (
    generate_reset_token,
    confirm_reset_token,
    login_required,
)  # Import auth utils


# --- Signup ---
@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    # Redirect if already logged in and verified
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user and user.is_verified:
            flash("You are already logged in.", "info")
            return redirect_logged_in_user(user)  # Redirect based on role

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        # Explicitly default role to 'patient' on signup form
        role = request.form.get("role", "patient")

        # --- Validation ---
        error = None
        if not all([username, email, password, confirm_password]):
            error = "All fields are required"
        elif password != confirm_password:
            error = "Passwords do not match"
        elif role not in ["patient", "medic"]:  # Prevent self-assigning admin
            error = "Invalid role selected"
        elif User.query.filter(
            User.username.ilike(username)
        ).first():  # Case-insensitive check
            error = "Username already exists"
        elif User.query.filter(
            User.email.ilike(email)
        ).first():  # Case-insensitive check
            error = "Email already registered"

        if error:
            flash(error, "danger")
            # Return template with potentially pre-filled values (add value=... to inputs)
            return render_template(
                "auth/signup.html", username=username, email=email, role=role
            )

        # --- Create User ---
        try:
            new_user = User(
                username=username,
                email=email.lower(),  # Store email in lowercase
                role=role,
                is_verified=False,  # Require verification
                is_admin=False,  # Ensure new signups are not admin
            )
            new_user.set_password(password)  # Use the method to hash

            # --- SET is_approved based on role ---
            if role == "medic":
                new_user.is_approved = False  # Medic requires approval from the admin
            else:
                new_user.is_approved = True  # Implicitly approved

            db.session.add(new_user)
            db.session.flush()  # Get the ID before commit for session

            # Generate and send verification code
            code = new_user.set_verification_code()
            # Commit user *after* setting code, before sending email
            db.session.commit()

            if send_verification_code(new_user.email, code):
                session["user_id"] = new_user.id
                session["needs_verification"] = True
                flash(
                    "Account created! Please check your email for a verification code.",
                    "success",
                )
                return redirect(url_for("auth.verify"))  # Use blueprint name
            else:
                current_app.logger.error(
                    f"Failed to send verification email to {email} after signup."
                )
                # User created, but email failed. Let them log in to trigger resend.
                flash(
                    "Account created, but couldn't send verification email. Please try logging in.",
                    "warning",
                )
                return redirect(url_for("auth.login"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during signup for {username}: {e}")
            flash("An error occurred during signup. Please try again.", "danger")
            return render_template(
                "auth/signup.html", username=username, email=email, role=role
            )

    # --- GET Request ---
    return render_template("auth/signup.html")


# --- Login ---
# app/auth/routes.py


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    # Redirect checks for already logged-in users
    if "user_id" in session:
        user = db.session.get(User, session.get("user_id"))
        if user:
            if user.is_verified:
                # --- Check for the specific loop condition ---
                if user.role == "medic" and not user.is_approved:
                    # User is verified but awaiting approval.
                    # DO NOT redirect. Let the request proceed to render the login template.
                    # The flash message from the previous redirect attempt will be displayed.
                    pass  # Explicitly do nothing and fall through
                else:
                    # Verified and approved/admin/patient: Redirect away from login.
                    # Optional: Consider if this flash is needed if they just came from verify
                    # flash("You are already logged in.", "info")
                    return redirect_logged_in_user(user)
            # else: User is logged in but not verified yet (e.g., came back later)
            # Allow them to stay on login page or proceed with login POST

    # Handle POST request (login attempt)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template("auth/login.html", username=username)

        user = User.query.filter(User.username.ilike(username)).first()

        if not user or not user.check_password(password):
            flash("Invalid username or password", "danger")
            return render_template("auth/login.html", username=username)

        if user.is_banned:
            flash("Your account has been banned. Please contact support.", "danger")
            return render_template("auth/login.html", username=username)

        # Login Successful - Set session
        session.clear()
        session["user_id"] = user.id
        session.permanent = True

        # Handle Verification / Redirection AFTER setting session
        if user.is_admin:
            session["needs_verification"] = False
            return redirect_logged_in_user(user)
        elif not user.is_verified:
            # Send verification code if needed (handles login for unverified users)
            code = user.set_verification_code()
            db.session.commit()
            if send_verification_code(user.email, code):
                session["needs_verification"] = True
                flash(
                    "Login successful. Please check your email for a verification code.",
                    "warning",
                )
                return redirect(url_for("auth.verify"))
            else:
                # ... (handle email sending failure) ...
                session.clear()
                flash(
                    "Login failed: Couldn't send verification email. Contact support.",
                    "danger",
                )
                return redirect(url_for("auth.login"))
        else:
            # Verified non-admin user (patient or approved medic)
            session["needs_verification"] = False
            return redirect_logged_in_user(
                user
            )  # This will now correctly handle approved/unapproved

    # --- GET Request ---
    # Render login page for GET requests OR if user is logged in but awaiting approval
    return render_template("auth/login.html")


# --- Verify Email ---
@auth_bp.route("/verify", methods=["GET", "POST"])
def verify():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        flash("User session error. Please log in again.", "danger")
        return redirect(url_for("auth.login"))

    # If already verified (DB state is source of truth)
    if user.is_verified:
        session["needs_verification"] = False  # Sync session state
        flash("Your email is already verified.", "info")
        return redirect_logged_in_user(user)

    # Ensure 'needs_verification' flag is set if we reach here
    session["needs_verification"] = True

    if request.method == "POST":
        code = request.form.get("verification_code")

        if not code:
            flash("Verification code is required", "danger")
            return render_template("auth/verify.html", email=user.email)

        if user.verify_code(code):
            try:
                db.session.commit()
                session["needs_verification"] = False  # Update session state
                flash("Email verified successfully!", "success")
                return redirect_logged_in_user(user)
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(
                    f"Error committing user verification for {user.id}: {e}"
                )
                flash(
                    "An error occurred during verification. Please try again.", "danger"
                )
                return render_template("auth/verify.html", email=user.email)
        else:
            # Check if the code might have expired (verify_code handles setting code to None on expiry)
            expired = (
                not user.verification_code
                and user.verification_code_expires
                and datetime.utcnow() > user.verification_code_expires
            )
            if expired:
                flash(
                    "Verification code has expired. Please request a new one.", "danger"
                )
            else:
                flash("Invalid verification code. Please try again.", "danger")
            return render_template("auth/verify.html", email=user.email)

    # --- GET Request ---
    # Display email address on the verification page
    return render_template("auth/verify.html", email=user.email)


# --- Resend Verification Code ---
@auth_bp.route("/resend-code", methods=["POST"])
def resend_code():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    if "user_id" not in session:
        message = "Authentication required. Please log in."
        status_code = 401
        if is_ajax:
            return jsonify({"success": False, "message": message}), status_code
        else:
            flash(message, "warning")
            return redirect(url_for("auth.login"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        message = "User session error. Please log in again."
        status_code = 404
        if is_ajax:
            return jsonify({"success": False, "message": message}), status_code
        else:
            flash(message, "danger")
            return redirect(url_for("auth.login"))

    if user.is_verified:
        message = "Your email is already verified."
        status_code = 200  # Or maybe 400 Bad Request? 200 seems fine.
        if is_ajax:
            return jsonify({"success": True, "message": message}), status_code
        else:
            flash(message, "info")
            return redirect_logged_in_user(user)

    # Optional: Rate Limiting (Check if code was generated recently)
    # if user.verification_code_expires and user.verification_code_expires > datetime.utcnow() + timedelta(minutes=9):
    #     message = "Please wait a minute before requesting another code."
    #     status_code = 429 # Too Many Requests
    #     if is_ajax: return jsonify({"success": False, "message": message}), status_code
    #     else: flash(message, "warning"); return redirect(url_for("auth.verify"))

    # Generate and send new code
    try:
        code = user.set_verification_code()
        db.session.commit()  # Commit new code and expiry

        success = send_verification_code(user.email, code)

        if success:
            session["needs_verification"] = True  # Ensure session state is correct
            message = "Verification code resent. Please check your email."
            flash_category = "success"
            status_code = 200
        else:
            current_app.logger.error(
                f"Failed to resend verification email to {user.email}"
            )
            message = (
                "Failed to send verification code. Try again later or contact support."
            )
            flash_category = "danger"
            status_code = 500
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error resending code for {user.email}: {e}")
        success = False
        message = "An internal error occurred. Please try again later."
        flash_category = "danger"
        status_code = 500

    if is_ajax:
        return jsonify({"success": success, "message": message}), status_code
    else:
        flash(message, flash_category)
        return redirect(url_for("auth.verify"))


# --- Forgot Password ---
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()

        if not email:  # Basic check, rely on user.email lookup mostly
            flash("Email address is required.", "danger")
            return render_template("auth/forgot_password.html")

        user = User.query.filter_by(email=email).first()

        flash_message = (
            "If an account with that email exists, a password reset link has been sent."
        )
        flash_category = "info"

        if user:
            # Check if user is banned - maybe prevent password reset for banned users?
            # if user.is_banned:
            #    flash("Cannot reset password for a banned account.", "warning")
            #    return redirect(url_for('auth.login'))
            try:
                token = generate_reset_token(user.email)
                reset_url = url_for("auth.reset_password", token=token, _external=True)

                subject = "Password Reset Request - FHE Health Prediction"
                # Consider using Flask-Mail and HTML templates for richer emails
                body = render_template(
                    "auth/email/reset_password_email.txt",  # Example text template
                    username=user.username,
                    reset_url=reset_url,
                )

                if not send_email(user.email, subject, body):
                    current_app.logger.error(
                        f"Failed to send password reset email to {user.email}"
                    )
                    # Avoid specific error messages to user
                    flash_message = "Could not send password reset email. Please try again later or contact support."
                    flash_category = "danger"  # Be cautious revealing failure
                # else: # Email sent successfully (or user didn't exist) -> show generic message

            except Exception as e:
                current_app.logger.error(
                    f"Error generating reset token/email for {email}: {e}"
                )
                # Avoid specific error messages to user

        flash(flash_message, flash_category)
        # Always redirect to login to prevent email enumeration
        return redirect(url_for("auth.login"))

    # --- GET Request ---
    return render_template("auth/forgot_password.html")


# --- Reset Password ---
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_reset_token(token)  # Default expiration handled by confirm func
    if not email:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user:
        # User deleted after token was sent?
        flash("User not found for this reset link.", "danger")
        return redirect(url_for("auth.login"))
    # Optional: Check if banned
    # if user.is_banned: ...

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not password or not confirm_password:
            flash("Both password fields are required", "danger")
            return render_template("auth/reset_password.html", token=token)

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template("auth/reset_password.html", token=token)

        # Add password complexity checks here if needed

        try:
            user.set_password(password)  # Use the method to hash
            # Optional: Force re-verification after password reset?
            # user.is_verified = False
            # user.verification_code = None
            # user.verification_code_expires = None
            db.session.commit()
            flash("Password updated successfully! You can now log in.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error updating password for {email} via reset: {e}"
            )
            flash(
                "An error occurred updating your password. Please try again.", "danger"
            )
            return render_template("auth/reset_password.html", token=token)

    # --- GET Request ---
    return render_template("auth/reset_password.html", token=token)


# --- Logout ---
@auth_bp.route("/logout")
@login_required  # Ensure user is logged in to log out
def logout():
    user_id = session.get("user_id")  # Get user ID before clearing
    username = "User"
    if user_id:
        user = db.session.get(User, user_id)
        if user:
            username = user.username

    session.clear()
    flash("You have been logged out.", "info")
    current_app.logger.info(f"User '{username}' (ID: {user_id}) logged out.")
    return redirect(url_for("auth.login"))  # Redirect to login page
