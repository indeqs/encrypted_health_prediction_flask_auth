import logging
from dotenv import load_dotenv

load_dotenv()
import csv
from io import StringIO
from flask import (
    Flask,
    render_template,
    make_response,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from utils.email_sender import (
    generate_verification_code,
    send_verification_code,
    send_email,
)

# Flask app setup
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(
    24
)  # Generate a random secret key but is in `bytes`
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECURITY_PASSWORD_SALT"] = os.getenv("SECURITY_PASSWORD_SALT")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 2FA fields
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(10), nullable=True)
    verification_code_expires = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"

    def set_verification_code(self):
        """Generate and store a verification code"""
        code = generate_verification_code()
        self.verification_code = code
        self.verification_code_expires = datetime.utcnow() + timedelta(minutes=10)
        return code

    def verify_code(self, code):
        """Verify the provided code against the stored code"""
        if not self.verification_code or not self.verification_code_expires:
            return False

        if datetime.utcnow() > self.verification_code_expires:
            return False

        if self.verification_code != code:
            return False

        # Code is valid - mark user as verified and clear code
        self.is_verified = True
        self.verification_code = None
        self.verification_code_expires = None
        return True


# Create all database tables
with app.app_context():
    db.create_all()
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            email="admin@app.com",
            password_hash=generate_password_hash("admin"),
            is_admin=True,
        )
        db.session.add(admin)
        db.session.commit()


# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "warning")
            return redirect(url_for("login"))

        user = db.session.get(User, session["user_id"])
        if not user or not user.is_admin:
            flash("You do not have permission to access this page", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return decorated_function


def ban_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" in session:
            user = db.session.get(User, session["user_id"])
            if user and user.is_banned:
                session.clear()
                flash("Your account has been banned", "danger")
                return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route("/")
def home():
    # Redirect logged-in users away from the generic home page if desired
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user:
            if user.is_admin:
                # Don't redirect admin from here, maybe they want to see the public home?
                # Or redirect to admin dashboard: return redirect(url_for('adminDashboard'))
                pass  # Let admin see the public home page if they navigate here
            elif user.is_verified:
                # Redirect verified non-admin users to their main app
                return redirect("http://localhost:7860/")
            else:
                # Redirect unverified users to verification
                return redirect(url_for("verify"))
    # Render home for logged-out users
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validation
        if not all([username, email, password, confirm_password]):
            flash("All fields are required", "error")
            return render_template("signup.html")

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("signup.html")

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists", "error")
            return render_template("signup.html")

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email already registered", "error")
            return render_template("signup.html")

        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_verified=False,
        )
        try:
            db.session.add(new_user)
            db.session.commit()

            # Generate and send verification code
            code = new_user.set_verification_code()
            db.session.commit()
            if send_verification_code(email, code):
                # Store user_id in session but mark as unverified
                session["user_id"] = new_user.id
                session["needs_verification"] = True

                flash("Account created! Please verify your email.", "success")
                return redirect(url_for("verify"))
            else:
                app.logger.error(f"Failed to send verification email to {email}")
                flash(
                    "Account created but couldn't send verification email. Please try logging in.",
                    "warning",
                )
                return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during signup: {e}")
            flash("An error occurred. Please try again.", "danger")
            return redirect(url_for("signup"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validation
        if not all([username, password]):
            flash("Username and password are required", "error")
            return render_template("login.html")

        # Check if user exists
        user = User.query.filter_by(username=username).first()

        # Check user existence and password
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

        # Check if user is banned
        if user.is_banned:
            flash("Your account has been banned. Please contact support.", "danger")
            return redirect(url_for("login"))

        # User exists, password is correct, and not banned.
        # Store user ID in session immediately.
        session["user_id"] = user.id

        # Check verification status
        if not user.is_verified:
            # Generate and send new verification code
            code = user.set_verification_code()
            db.session.commit()

            if send_verification_code(user.email, code):
                # Mark session as needing verification
                session["needs_verification"] = True
                flash(
                    "Your email is not verified. Please check your inbox for a verification code.",
                    "warning",
                )
                return redirect(url_for("verify"))
            else:
                # Log error, clear session, and inform user
                app.logger.error(
                    f"Failed to send verification email to {user.email} during login."
                )
                session.clear()  # Log out user if verification email fails critically
                flash(
                    "Couldn't send verification email. Please try logging in again or contact support.",
                    "danger",
                )
                return redirect(url_for("login"))
        else:
            # User is verified, clear the verification flag if it exists
            session["needs_verification"] = False

            # *** <<< FIX FOR ISSUE 3 >>> ***
            # Check if the verified user is an admin
            if user.is_admin:
                flash(f"Welcome back, Admin {user.username}!", "success")
                return redirect(url_for("adminDashboard"))
            else:
                # Verified non-admin user
                flash(f"Welcome back, {user.username}!", "success")
                # Redirect normal users to the external URL
                return redirect("http://localhost:7860/")
            # *** <<< END FIX FOR ISSUE 3 >>> ***

    # For GET request or if POST fails validation before checks
    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    # Check if user is in session AND needs verification
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    if not session.get("needs_verification", False):  # Default to False if key missing
        flash("Your email is already verified.", "info")
        # Redirect already verified users appropriately
        user = db.session.get(User, session["user_id"])
        if user and user.is_admin:
            return redirect(url_for("adminDashboard"))
        elif user:
            return redirect("http://localhost:7860/")
        else:  # Should not happen if user_id is in session, but handle defensively
            session.clear()
            return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        flash("User session error. Please log in again.", "danger")
        return redirect(url_for("login"))

    # If user somehow got marked as verified in DB but not session, fix session
    if user.is_verified:
        session["needs_verification"] = False
        flash("Your email is already verified.", "info")
        if user.is_admin:
            return redirect(url_for("adminDashboard"))
        else:
            return redirect("http://localhost:7860/")

    if request.method == "POST":
        code = request.form.get("verification_code")

        if not code:
            flash("Verification code is required", "danger")
            # Don't redirect, show error on the same page
            return render_template("verify.html", email=user.email)

        if user.verify_code(code):  # verify_code now handles marking user verified
            db.session.commit()
            session["needs_verification"] = False  # Update session state

            flash("Email verified successfully!", "success")

            # Redirect based on user type AFTER successful verification
            if user.is_admin:
                return redirect(url_for("adminDashboard"))
            else:
                # Redirect normal users to external URL
                return redirect("http://localhost:7860/")
        else:
            # Check if the code might have expired
            expired = (
                user.verification_code_expires
                and datetime.utcnow() > user.verification_code_expires
            )
            if expired:
                flash(
                    "Verification code has expired. Please request a new one.", "danger"
                )
            else:
                flash("Invalid verification code. Please try again.", "danger")
            # Show error on the same page
            return render_template("verify.html", email=user.email)

    # For GET request
    return render_template("verify.html", email=user.email)


@app.route("/resend-code", methods=["POST"])
def resend_code():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    # Security: Ensure user is logged in
    if "user_id" not in session:
        message = "Authentication required. Please log in."
        if is_ajax:
            return jsonify({"success": False, "message": message}), 401
        else:
            flash(message, "warning")
            return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        message = "User session error. Please log in again."
        if is_ajax:
            return jsonify({"success": False, "message": message}), 404
        else:
            flash(message, "danger")
            return redirect(url_for("login"))

    # Check if the user actually needs verification
    # Allow resend even if session['needs_verification'] is somehow False but user.is_verified is False
    if user.is_verified:
        message = "Your email is already verified."
        if is_ajax:
            return (
                jsonify({"success": True, "message": message}),
                200,
            )  # 200 OK, nothing to do
        else:
            flash(message, "info")
            # Redirect appropriately
            return redirect(
                url_for("adminDashboard") if user.is_admin else "http://localhost:7860/"
            )

    # Prevent spamming: Add rate limiting here if needed (e.g., check last resend time)
    # Example: Check if code was generated less than 60 seconds ago
    # if user.verification_code_expires and user.verification_code_expires > datetime.utcnow() + timedelta(minutes=9): # (10 min expiry - 1 min buffer)
    #     message = "Please wait a minute before requesting another code."
    #     if is_ajax:
    #         return jsonify({"success": False, "message": message}), 429 # Too Many Requests
    #     else:
    #         flash(message, "warning")
    #         return redirect(url_for("verify"))

    # Generate and send new verification code
    code = user.set_verification_code()
    db.session.commit()

    success = send_verification_code(user.email, code)

    if success:
        # Ensure session reflects need for verification
        session["needs_verification"] = True
        message = "Verification code resent. Please check your email."
        flash_category = "success"
        status_code = 200
    else:
        app.logger.error(f"Failed to resend verification email to {user.email}")
        message = "Failed to send verification code. Please try again later or contact support."
        flash_category = "danger"
        status_code = 500  # Internal Server Error

    if is_ajax:
        return jsonify({"success": success, "message": message}), status_code
    else:
        flash(message, flash_category)
        return redirect(
            url_for("verify")
        )  # Always redirect back to verify page for non-AJAX


# Generate a secure token for password reset
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])


# Confirm the reset token
def confirm_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(
            token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except (SignatureExpired, BadSignature):
        return None


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        if not email:
            flash("Email address is required.", "danger")
            return render_template("forgot_password.html")

        # Basic email format check (optional, browser validation is often sufficient)
        # if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        #     flash("Invalid email format.", "danger")
        #     return render_template("forgot_password.html")

        # Check if email exists
        user = User.query.filter_by(email=email).first()

        # Security: Always show the same message regardless of whether the email exists
        # This prevents attackers from confirming which emails are registered.
        flash_message = (
            "If an account with that email exists, a password reset link has been sent."
        )

        if user:
            try:
                # Generate token
                token = generate_reset_token(user.email)
                reset_url = url_for("reset_password", token=token, _external=True)

                # Email subject and body
                subject = "Password Reset Request - FHE Health Prediction"
                # Use a more robust email template system in production (e.g., Jinja templates)
                body = f"""
Hello {user.username},

You requested a password reset for your account on the FHE Health Prediction platform.

Please click the link below to set a new password:
{reset_url}

This link is valid for 1 hour.

If you did not request this, please ignore this email. Your password will remain unchanged.

Regards,
The FHE Health Prediction Team
                """

                # Send email
                if not send_email(user.email, subject, body):
                    app.logger.error(
                        f"Failed to send password reset email to {user.email}"
                    )
                    # Don't reveal the error to the user for security
                    # flash("Error sending reset email. Please try again later.", "danger")

            except Exception as e:
                app.logger.error(
                    f"Error generating reset token or sending email for {email}: {e}"
                )
                # Don't reveal the error

        # Always show the generic message and redirect to login
        flash(flash_message, "info")
        return redirect(url_for("login"))

    # For GET request
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Verify token first for both GET and POST
    email = confirm_reset_token(token)  # Default expiration is 1 hour (3600s)
    if not email:
        flash(
            "The password reset link is invalid or has expired. Please request a new one.",
            "danger",
        )
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    # If the user associated with the email was deleted after token generation
    if not user:
        flash("User associated with this reset link no longer exists.", "danger")
        return redirect(url_for("login"))
    # If user is banned, maybe prevent password reset? (Optional)
    # if user.is_banned:
    #     flash("Cannot reset password for a banned account.", "danger")
    #     return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validate passwords
        if not password or not confirm_password:
            flash("Both password fields are required", "danger")
            # Return the render_template to show the form again with the error
            return render_template("reset_password.html", token=token)

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template("reset_password.html", token=token)

        # Add password complexity requirements here if desired
        # e.g., if len(password) < 8: flash(...) return render_template(...)

        try:
            # Update password - use password_hash attribute
            user.password_hash = generate_password_hash(password)
            # Invalidate the reset token implicitly by changing the password hash
            # Optionally, clear verification codes if you want them to re-verify after reset
            # user.verification_code = None
            # user.verification_code_expires = None
            # user.is_verified = False # If you want re-verification
            db.session.commit()
            flash(
                "Your password has been updated successfully! You can now log in with your new password.",
                "success",
            )
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating password for {email}: {e}")
            flash(
                "An error occurred while updating your password. Please try again.",
                "danger",
            )
            return render_template("reset_password.html", token=token)

    # For GET request, just show the form
    return render_template("reset_password.html", token=token)


# Update the before_request function to handle verification
@app.before_request
def before_request_checks():
    # Check if user is banned
    if "user_id" in session:
        # Use db.session.get for potentially better caching/identity map usage
        user = db.session.get(User, session["user_id"])
        # Make sure user object exists before accessing attributes
        if user and user.is_banned:
            session.clear()
            flash("Your account has been banned", "danger")
            # Use abort(403) or redirect depending on context, redirect is safer for UX
            # Using redirect here as it's consistent with other checks
            return redirect(url_for("login"))  # Or perhaps a dedicated 'banned' page

    # Check if user needs verification, avoiding infinite loops
    if "user_id" in session and session.get("needs_verification"):
        # Allow access to verification-related routes and static files
        allowed_endpoints = ["verify", "resend_code", "logout", "static", "login"]
        if request.endpoint not in allowed_endpoints:
            flash("Please verify your email to continue", "warning")
            return redirect(url_for("verify"))
    # No return needed here if checks pass


# Admin routes
@app.route("/admin")
@admin_required
def adminDashboard():
    # Exclude the logged-in admin from the list shown? Usually not needed.
    # If you want to exclude the *main* admin ('admin'), filter it out.
    users = (
        User.query.filter(User.username != "admin")
        .order_by(User.created_at.desc())
        .all()
    )
    # Alternatively, show all users including the current admin:
    # users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/adminDashboard.html", users=users)


@app.route("/admin/ban/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    user_to_ban = User.query.get_or_404(user_id)
    current_admin = db.session.get(User, session["user_id"])  # Get the current admin

    # Prevent banning the main 'admin' user
    if user_to_ban.username == "admin":
        flash("The primary admin account cannot be banned.", "danger")
        return redirect(url_for("adminDashboard"))

    # Prevent admins from banning themselves (optional but good practice)
    if user_to_ban.id == current_admin.id:
        flash("You cannot ban yourself.", "danger")
        return redirect(url_for("adminDashboard"))

    # Prevent admins from banning other admins (optional security rule)
    # if user_to_ban.is_admin:
    #     flash("Admins cannot ban other admins.", "danger")
    #     return redirect(url_for("adminDashboard"))

    user_to_ban.is_banned = not user_to_ban.is_banned
    action = "banned" if user_to_ban.is_banned else "unbanned"

    try:
        db.session.commit()
        flash(
            f"User '{user_to_ban.username}' has been successfully {action}.", "success"
        )
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error changing ban status for user {user_id}: {e}")
        flash(f"An error occurred while trying to {action} the user.", "danger")

    return redirect(url_for("adminDashboard"))


@app.route("/admin/download-users")
@admin_required
def download_users():
    """Generate and download a CSV file with all users' information."""
    try:
        # Create a StringIO object to hold the CSV data in memory
        csv_data = StringIO()
        # Use DictWriter for easier header mapping and row writing
        fieldnames = [
            "ID",
            "Username",
            "Email",
            "Created At",
            "Is Banned",
            "Is Admin",
            "Is Verified",
        ]
        csv_writer = csv.DictWriter(csv_data, fieldnames=fieldnames)

        # Write the header row
        csv_writer.writeheader()

        # Get all users (or filter as needed, e.g., exclude primary admin)
        # users = User.query.filter(User.username != 'admin').all()
        users = User.query.all()  # Include all users in the download

        # Write user data
        for user in users:
            csv_writer.writerow(
                {
                    "ID": user.id,
                    "Username": user.username,
                    "Email": user.email,
                    "Created At": (
                        user.created_at.strftime("%Y-%m-%d %H:%M:%S")
                        if user.created_at
                        else "N/A"
                    ),
                    "Is Banned": "Yes" if user.is_banned else "No",
                    "Is Admin": "Yes" if user.is_admin else "No",
                    "Is Verified": "Yes" if user.is_verified else "No",
                }
            )

        # Get the CSV data as a string
        output = csv_data.getvalue()
        csv_data.close()  # Close the StringIO object

        # Create a response with the CSV data
        response = make_response(output)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        response.headers["Content-Disposition"] = (
            f"attachment; filename=users_{timestamp}.csv"
        )
        response.headers["Content-Type"] = "text/csv"

        return response

    except Exception as e:
        app.logger.error(f"Error generating user CSV download: {e}")
        flash("Failed to generate user download. Please check logs.", "danger")
        return redirect(url_for("adminDashboard"))


@app.route("/admin/toggle-admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    """Toggle admin privileges for a user."""
    user_to_toggle = User.query.get_or_404(user_id)
    current_admin = db.session.get(User, session["user_id"])

    # Prevent modifying the primary 'admin' user's status
    if user_to_toggle.username == "admin":
        flash("Cannot modify privileges for the primary admin user.", "danger")
        return redirect(url_for("adminDashboard"))

    # Prevent admins from revoking their own privileges (optional but safer)
    if user_to_toggle.id == current_admin.id:
        flash("You cannot change your own admin status.", "danger")
        return redirect(url_for("adminDashboard"))

    # Toggle admin status
    user_to_toggle.is_admin = not user_to_toggle.is_admin
    action = "granted" if user_to_toggle.is_admin else "revoked"

    try:
        db.session.commit()
        flash(
            f"Admin privileges {action} for user '{user_to_toggle.username}'.",
            "success",
        )
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error toggling admin status for user {user_id}: {e}")
        flash(f"An error occurred while changing admin status: {str(e)}", "danger")

    return redirect(url_for("adminDashboard"))


# API routes for validation
@app.route("/api/check-username", methods=["POST"])
def check_username():
    username = request.json.get("username", "").strip()
    if not username:
        # Return available: false if username is empty or whitespace only
        return jsonify({"available": False, "message": "Username cannot be empty."})

    # Consider adding username format validation here (length, allowed characters)

    user = User.query.filter(
        User.username.ilike(username)
    ).first()  # Case-insensitive check
    is_available = not user
    message = "Username available." if is_available else "Username is already taken."
    return jsonify({"available": is_available, "message": message})


@app.route("/logout")
def logout():
    session.clear()  # Clear the entire session
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)  # Use INFO or DEBUG
    # Consider adding file logging for production
    # from logging.handlers import RotatingFileHandler
    # handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
    # handler.setLevel(logging.INFO)
    # app.logger.addHandler(handler)

    app.run(debug=True)  # debug=True is okay for development
