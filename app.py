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
    role = db.Column(db.String(20), default="patient", nullable=False)
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


class Inquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=True)  # The main question
    symptoms = db.Column(db.Text, nullable=True)  # Add this line for symptoms
    urgency = db.Column(db.String(20), default="medium", nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Foreign Keys
    patient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Optional: Track which medic is assigned or responded
    # medic_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationships
    patient = db.relationship(
        "User",
        backref=db.backref("patient_inquiries", lazy=True),
        foreign_keys=[patient_id],
    )
    # medic = db.relationship('User', backref=db.backref('medic_inquiries', lazy=True), foreign_keys=[medic_id])

    def __repr__(self):
        return f"<Inquiry {self.id} - {self.subject}>"


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


# Add this function somewhere near your route definitions
def redirect_logged_in_user(user):
    """Redirects a logged-in and verified user based on their role."""
    if not user:  # Should not happen if called correctly, but safe check
        return redirect(url_for("login"))

    if user.is_admin:
        # Admins go to admin dashboard
        flash(
            f"Welcome back, Admin {user.username}!", "success"
        )  # Optional: Flash message here or in calling route
        return redirect(url_for("adminDashboard"))
    elif user.role == "medic":
        # Medics go to medic dashboard
        flash(
            f"Welcome back, Dr. {user.username}!", "success"
        )  # Customize welcome message
        return redirect(url_for("medicDashboard"))
    elif user.role == "patient":
        # Patients go to the external app
        flash(f"Welcome back, {user.username}!", "success")
        return redirect("http://localhost:7860/")
    else:
        # Fallback for unknown roles (maybe log this)
        app.logger.warning(
            f"User {user.username} (ID: {user.id}) has unknown role: {user.role}. Redirecting home."
        )
        flash(f"Welcome back, {user.username}!", "info")
        return redirect(url_for("home"))  # Or maybe login?


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
            if not user.is_verified:
                session["needs_verification"] = True
                return redirect(url_for("verify"))
            else:
                return redirect_logged_in_user(user)
            # if user.is_admin:
            #     # Don't redirect admin from here, maybe they want to see the public home?
            #     # Or redirect to admin dashboard: return redirect(url_for('adminDashboard'))
            #     pass  # Let admin see the public home page if they navigate here
            # elif user.is_verified:
            #     # Redirect verified non-admin users to their main app
            #     return redirect("http://localhost:7860/")
            # else:
            #     # Redirect unverified users to verification
            #     return redirect(url_for("verify"))
    # Render home for logged-out users
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        role = request.form.get("role", "patient")

        # Validation
        if not all([username, email, password, confirm_password]):
            flash("All fields are required", "error")
            return render_template("signup.html")

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("signup.html")

        # Validate role
        if role not in ["patient", "medic"]:
            flash("Invalid role selected", "error")
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
            role=role,
            is_verified=False,
        )

        if role == "admin":
            pass
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
            return redirect(url_for("login"))  # Redirect back to login on failure

        # Check if user is banned
        if user.is_banned:
            flash("Your account has been banned. Please contact support.", "danger")
            return redirect(url_for("login"))  # Redirect back to login if banned

        # User exists, password is correct, and not banned.
        session["user_id"] = user.id
        session["needs_verification"] = False  # Default assumption

        # --- SPECIAL CASE: ADMIN LOGIN ---
        # Check if the user has the is_admin flag set to True
        if user.is_admin:
            # Admin bypasses verification check entirely.
            # No need to check user.is_verified for admin.
            # Session flag 'needs_verification' is already False.
            # Redirect directly using the helper function.
            # The helper function will add the appropriate flash message.
            # flash(f"Admin Login: Welcome {user.username}!", "success") # Message handled by helper
            return redirect_logged_in_user(user)

        # --- REGULAR USER LOGIN (NON-ADMIN) ---
        # If the user is NOT an admin, proceed with verification check.
        elif not user.is_verified:
            # User is NOT admin and NOT verified - Initiate verification
            code = user.set_verification_code()
            db.session.commit()

            if send_verification_code(user.email, code):
                session["needs_verification"] = (
                    True  # Set flag ONLY if verification is needed
                )
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
                return redirect(url_for("login"))  # Redirect back to login on failure
        else:
            # User is NOT admin AND IS verified
            # Session flag 'needs_verification' is already False.
            # Redirect using the helper function.
            return redirect_logged_in_user(user)

    # For GET request or if POST fails initial validation
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
            return redirect_logged_in_user(user)

            # Redirect based on user type AFTER successful verification
            # if user.is_admin:
            #     return redirect(url_for("adminDashboard"))
            # else:
            #     # Redirect normal users to external URL
            #     return redirect("http://localhost:7860/")
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
            return redirect_logged_in_user(user)

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


# Decorators to ensure user is logged in and is a medic
def medic_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "warning")
            return redirect(url_for("login"))

        user = db.session.get(User, session["user_id"])
        # Check if user exists and has the 'medic' role
        if not user or user.role != "medic":
            flash("You do not have permission to access this page.", "danger")
            # Redirect non-medics somewhere else (e.g., home or their own dashboard)
            return redirect(url_for("home"))
        # Check if banned
        if user.is_banned:
            session.clear()
            flash("Your account has been banned", "danger")
            return redirect(url_for("login"))
        # Check if verified (medics should also be verified)
        if not user.is_verified:
            session["needs_verification"] = True  # Ensure flag is set if needed
            flash("Please verify your email to access the dashboard.", "warning")
            return redirect(url_for("verify"))

        return f(*args, **kwargs)

    return decorated_function


@app.route("/medicDashboard")
@login_required
@medic_required
def medicDashboard():
    # Get the current logged-in medic
    # medic_required already ensures user exists and is a medic
    current_medic = db.session.get(User, session["user_id"])

    # --- Fetch Data ---

    # Stats
    total_patients_count = User.query.filter_by(role="patient", is_banned=False).count()
    new_inquiries_count = Inquiry.query.filter_by(status="pending").count()
    # predictions_made_count = Prediction.query.count() # REMOVED
    one_week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_patients_count = User.query.filter(
        User.role == "patient",
        User.created_at >= one_week_ago,
        User.is_banned == False,
    ).count()

    # Recent Inquiries (Get latest 5, join with User to get patient name easily)
    recent_inquiries_data = (
        db.session.query(Inquiry, User.username)
        .join(User, Inquiry.patient_id == User.id)
        .order_by(Inquiry.created_at.desc())
        .limit(5)
        .all()
    )
    recent_inquiries_list = [
        {
            "id": inquiry.id,
            "patient_id": inquiry.patient_id,
            "name": patient_username,
            "date": inquiry.created_at.strftime("%Y-%m-%d"),
            "subject": inquiry.subject,
            "urgency": inquiry.urgency,
            "status": inquiry.status,
        }
        for inquiry, patient_username in recent_inquiries_data
    ]

    recent_patients_users = (
        User.query.filter_by(role="patient", is_banned=False)
        .order_by(User.created_at.desc())
        .limit(3)
        .all()
    )
    recent_patients_list = []
    for patient in recent_patients_users:
        # Placeholder for last visit - you'd query appointments/inquiries/predictions
        last_visit_placeholder = "N/A"
        # Find latest activity timestamp if needed (more complex query)
        # latest_inquiry = Inquiry.query.filter_by(patient_id=patient.id).order_by(Inquiry.created_at.desc()).first()
        # latest_prediction = Prediction.query.filter_by(patient_id=patient.id).order_by(Prediction.created_at.desc()).first()
        # Determine actual last visit based on latest_inquiry.created_at vs latest_prediction.created_at etc.

        recent_patients_list.append(
            {
                "id": patient.id,
                "name": patient.username,
                "last_visit": last_visit_placeholder,
                # "prediction_count": pred_count, # REMOVED
            }
        )

    # Activity Graph Data (Remove prediction data)
    # You might want to fetch actual inquiry counts grouped by time period here
    activity_labels_data = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]  # Dummy labels
    # Fetch real inquiry data per month/week instead of dummy data
    inquiry_data_points = [10, 15, 8, 12, 20, 18]  # Dummy inquiry data
    # prediction_data_points = [5, 8, 6, 10, 15, 12] # REMOVED

    # --- Pass Data to Template (Predictions Removed) ---
    return render_template(
        "medic/medicDashboard.html",
        current_user=current_medic,
        total_patients=total_patients_count,
        new_inquiries=new_inquiries_count,
        # predictions_made=predictions_made_count, # REMOVED
        weekly_patients=weekly_patients_count,
        recent_inquiries=recent_inquiries_list,
        # recent_predictions=recent_predictions_list, # REMOVED
        activity_labels=activity_labels_data,
        inquiry_data=inquiry_data_points,
        # prediction_data=prediction_data_points, # REMOVED
        recent_patients=recent_patients_list,
    )


@app.route("/medicFeedback", methods=["GET", "POST"])
@login_required  # Ensure user is logged in to submit feedback tied to their account
def medicFeedback():
    # Get the current logged-in user
    user = db.session.get(User, session["user_id"])
    if not user:
        # Should be caught by @login_required, but good practice
        flash("User session error. Please log in again.", "danger")
        return redirect(url_for("login"))

    # Prevent medics/admins from using this specific patient feedback form? (Optional)
    # if user.role != 'patient':
    #     flash("This feedback form is intended for patients.", "warning")
    #     return redirect(url_for('home')) # Or appropriate dashboard

    if request.method == "POST":
        # --- Process Form Submission ---
        # No need to get name/email from form, use logged-in user's details
        subject = request.form.get("subject")
        symptoms_text = request.form.get("symptoms")  # Optional field
        message_text = request.form.get("message")
        urgency_level = request.form.get("urgency", "medium")  # Default if not provided
        consent = request.form.get("privacy_consent")

        # --- Basic Server-Side Validation ---
        if not subject or not message_text:
            flash("Subject and Medical Question are required.", "danger")
            # Re-render form, passing back submitted values (and user)
            return render_template(
                "medic/medicFeedback.html",
                user=user,
                form_subject=subject,
                form_symptoms=symptoms_text,
                form_message=message_text,
                form_urgency=urgency_level,
            )

        if not consent:
            flash(
                "You must consent to sharing information to submit your question.",
                "danger",
            )
            return render_template(
                "medic/medicFeedback.html",
                user=user,
                form_subject=subject,
                form_symptoms=symptoms_text,
                form_message=message_text,
                form_urgency=urgency_level,
            )

        # --- Save to Database ---
        try:
            new_inquiry = Inquiry(
                patient_id=user.id,  # Use logged-in user's ID
                subject=subject,
                message=message_text,
                symptoms=symptoms_text,  # Save symptoms text
                urgency=urgency_level,
                status="pending",  # Default status for new inquiries
            )

            # TODO (Optional Advanced): If prediction_id is provided,
            # you might want to validate it exists and potentially link it.
            # if prediction_id_str:
            #    try:
            #        prediction_id = int(prediction_id_str)
            #        prediction = Prediction.query.get(prediction_id)
            #        if prediction and prediction.patient_id == user.id:
            #             new_inquiry.prediction_ref_id = prediction_id # Add a column to Inquiry model?
            #        else:
            #             flash("Invalid or inaccessible Prediction ID provided.", "warning")
            #    except ValueError:
            #        flash("Invalid format for Prediction ID.", "warning")

            db.session.add(new_inquiry)
            db.session.commit()

            # Optional: Send email notification to medics/admin?
            # send_email(admin_email, f"New Medical Inquiry: {subject}", f"...")

            flash(
                "Your medical question has been submitted successfully. A provider will respond soon.",
                "success",
            )
            return redirect(url_for("medicFeedback"))  # Redirect after successful POST

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving medical inquiry for user {user.id}: {e}")
            flash(
                "An error occurred while submitting your question. Please try again.",
                "danger",
            )
            # Re-render form with error state
            return render_template(
                "medic/medicFeedback.html",
                user=user,
                form_subject=subject,
                form_symptoms=symptoms_text,
                form_message=message_text,
                form_urgency=urgency_level,
            )

    # --- Handle GET Request (Display the form) ---
    # Pass the user object to pre-fill name/email
    return render_template("medic/medicFeedback.html", user=user)


@app.route("/admin-feedback", methods=["GET", "POST"])
def adminFeedback():
    return render_template("admin/adminFeedback.html")


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


@app.route("/view_inquiry/<int:inquiry_id>")
@login_required
# @medic_required # Decide if only medics can view
def view_inquiry(inquiry_id):
    # Fetch inquiry details later
    return f"Viewing inquiry {inquiry_id} (Implementation Pending)"


@app.route("/respond_inquiry/<int:inquiry_id>")
@login_required
@medic_required
def respond_inquiry(inquiry_id):
    # Add logic to respond/update inquiry status
    return f"Responding to inquiry {inquiry_id} (Implementation Pending)"


# Route might need GET/POST
@app.route("/add_patient", methods=["GET", "POST"])
@login_required
@medic_required  # Or maybe admin? Decide who can add patients
def add_patient():
    # Display form to add a new patient user
    return "Add patient page (Implementation Pending)"


# medicFeedback route already exists


# Route might need GET/POST depending on implementation
@app.route("/export_data")
@login_required
@medic_required  # Or admin?
def export_data():
    # Logic to generate and return data export (e.g., CSV)
    return "Export data page (Implementation Pending)"


@app.route("/view_patient/<int:patient_id>")
@login_required
# @medic_required # Decide who can view patient details
def view_patient(patient_id):
    # Fetch and display patient details
    return f"Viewing patient {patient_id} (Implementation Pending)"


@app.route("/logout")
def logout():
    session.clear()  # Clear the entire session
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/contact", methods=["GET", "POST"])
def contact():
    """Renders the contact page and handles form submission."""
    if request.method == "POST":
        # --- Process the Form Data ---
        name = request.form.get(
            "name"
        )  # Get data using the 'name' attribute from your form input fields
        email = request.form.get("email")
        subject = request.form.get(
            "subject", "Contact Form Submission"
        )  # Optional subject with default
        message = request.form.get("message")

        # --- Basic Server-Side Validation ---
        if not name or not email or not message:
            flash(
                "Please fill out all required fields (Name, Email, Message).", "danger"
            )
            # Re-render the form, potentially passing back entered values to repopulate
            return render_template(
                "contact.html",
                form_name=name,
                form_email=email,
                form_subject=subject,
                form_message=message,
            )

        # --- Attempt to Send Email (Replace with your actual logic) ---
        try:
            # Example: Construct email body
            email_body = f"""
            New contact form submission:
            Name: {name}
            Email: {email}
            Subject: {subject}

            Message:
            {message}
            """
            # Replace 'your_admin_email@example.com' with where you want emails sent
            admin_email = os.getenv(
                "ADMIN_CONTACT_EMAIL", "admin@app.com"
            )  # Use env var or default

            # Assuming your send_email function takes (recipient, subject, body)
            if send_email(admin_email, f"Website Contact: {subject}", email_body):
                app.logger.info(f"Contact form submitted successfully by {email}")
                flash(
                    "Thank you for your message! We will get back to you soon.",
                    "success",
                )
            else:
                app.logger.error(f"Failed to send contact form email from {email}")
                flash(
                    "Sorry, there was an error sending your message. Please try again later or contact us directly.",
                    "danger",
                )

        except Exception as e:
            app.logger.error(f"Error processing contact form from {email}: {e}")
            flash("An unexpected error occurred. Please try again.", "danger")

        # Redirect after POST to prevent form resubmission on refresh (Post-Redirect-Get Pattern)
        return redirect(
            url_for("contact")
        )  # Redirects back to the contact page (GET request)

    # --- Handle GET Request (Display the form) ---
    # This part runs if request.method is 'GET'
    return render_template("contact.html")


@app.route("/terms-of-service")
def terms_of_service():
    """Renders the terms of service page."""
    return render_template("tos.html")


@app.route("/privacy-policy")
def privacy_policy():
    """Renders the privacy policy page."""
    return render_template("policy.html")


# Add this within your app.py, for example, after the other static page routes


@app.route(
    "/subscribe", methods=["POST"]
)  # Needs methods=['POST'] because the form uses method="post"
def subscribe():
    """Handles newsletter subscription form (placeholder)."""
    email = request.form.get("email")
    if email:
        # In a real application, add logic here:
        # 1. Validate the email format more robustly.
        # 2. Store the email address in a database or send it to a mailing list service.
        # 3. Handle potential errors during storage.
        app.logger.info(f"Newsletter subscription attempt: {email}")
        flash("Thank you for subscribing!", "success")
    else:
        flash("Please provide a valid email address.", "warning")

    # Redirect back to the page the user came from, or to the home page.
    # Using request.referrer can be unreliable/insecure, redirecting home is safer.
    # Make sure you have the 'index' route defined correctly (or use 'home' if you kept that name)
    return redirect(url_for("terms_of_service"))


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)  # Use INFO or DEBUG
    # Consider adding file logging for production
    # from logging.handlers import RotatingFileHandler
    # handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
    # handler.setLevel(logging.INFO)
    # app.logger.addHandler(handler)

    app.run(debug=True)  # debug=True is okay for development
