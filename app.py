from dotenv import load_dotenv

load_dotenv()

from flask import (
    Flask,
    render_template,
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
from utils.email_sender import generate_verification_code, send_verification_code, send_email

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


# Apply ban_check to all routes
def before_request():
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user and user.is_banned:
            session.clear()
            flash("Your account has been banned", "danger")
            return redirect(url_for("login"))


# Routes
@app.route("/")
def home():
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
                flash(
                    "Account created but couldn't send verification email. Please try logging in.",
                    "warning",
                )
                return redirect(url_for("login"))
        except Exception as e:
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
            flash("All fields are required", "error")
            return render_template("login.html")

        # Check if user exists
        user = User.query.filter_by(username=username).first()

        # Check user existence and password
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

        # Check if user is banned
        if user.is_banned:
            flash("Your account has been banned", "danger")
            return redirect(url_for("login"))

        # Skip verification for admin user
        if user.username == "admin":
            # Mark admin as verified if they aren't already
            if not user.is_verified:
                user.is_verified = True
                db.session.commit()

            # Log admin in
            session["user_id"] = user.id
            session["needs_verification"] = False
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("adminDashboard"))

        # Check if user is verified
        if not user.is_verified:
            # Generate and send new verification code
            code = user.set_verification_code()
            db.session.commit()

            if send_verification_code(user.email, code):
                # Store user_id in session but mark as unverified
                session["user_id"] = user.id
                session["needs_verification"] = True

                flash("Please verify your email to continue.", "warning")
                return redirect(url_for("verify"))
            else:
                flash("Couldn't send verification email. Please try again.", "danger")
                return redirect(url_for("login"))

        # Log user in
        session["user_id"] = user.id
        session["needs_verification"] = False

        flash(f"Welcome back, {user.username}!", "success")

        # Redirect normal users to external URL
        return redirect("http://localhost:7860/")

    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    # Check if user is in session and needs verification
    if "user_id" not in session or not session.get("needs_verification"):
        return redirect(url_for("index"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        flash("User not found", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("verification_code")

        if not code:
            flash("Verification code is required", "danger")
            return redirect(url_for("verify"))

        if user.verify_code(code):
            db.session.commit()
            session["needs_verification"] = False

            flash("Email verified successfully!", "success")

            # Redirect based on user type
            if user.is_admin:
                return redirect(url_for("adminDashboard"))
            else:
                # Redirect normal users to external URL
                return redirect("http://localhost:5678")
        else:
            flash("Invalid or expired verification code", "danger")

    return render_template("verify.html", email=user.email)


# Add resend code route
@app.route("/resend-code", methods=["POST"])
def resend_code():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        flash("User not found", "danger")
        return redirect(url_for("login"))

    # Generate and send new verification code
    code = user.set_verification_code()
    db.session.commit()

    if send_verification_code(user.email, code):
        flash("Verification code resent. Please check your email.", "success")
    else:
        flash("Failed to send verification code. Please try again.", "danger")

    return redirect(url_for("verify"))


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

        # Check if email exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash(
                "If this email is registered, you will receive a password reset link.",
                "info",
            )
            return redirect(url_for("login"))

        # Generate token
        token = generate_reset_token(user.email)
        reset_url = url_for("reset_password", token=token, _external=True)

        # Email subject and body
        subject = "Password Reset Request"
        body = f"""
Hello {user.username},

To reset your password, please visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.

Regards,
Sentiment Analysis System Team
        """

        # Send email
        if send_email(user.email, subject, body):
            flash(
                "If this email is registered, you will receive a password reset link.",
                "info",
            )
        else:
            flash("Error sending reset email. Please try again later.", "danger")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Verify token
    email = confirm_reset_token(token)
    if not email:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validate passwords
        if not password or not confirm_password:
            flash("Both fields are required", "danger")
            return redirect(url_for("reset_password", token=token))

        if password != confirm_password:
            flash("Passwords don't match", "danger")
            return redirect(url_for("reset_password", token=token))

        # Find user and update password
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash("Your password has been updated! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("User not found", "danger")
            return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# Update the before_request function to handle verification
def before_request():
    if "user_id" in session:
        # Check if user is banned
        user = db.session.get(User, session["user_id"])
        if user and user.is_banned:
            session.clear()
            flash("Your account has been banned", "danger")
            return redirect(url_for("login"))

        # Check if user needs verification
        if session.get("needs_verification") and request.endpoint not in [
            "verify",
            "resend_code",
            "logout",
            "static",
        ]:
            flash("Please verify your email to continue", "warning")
            return redirect(url_for("verify"))


# Admin routes
@app.route("/admin")
@admin_required
def adminDashboard():
    users = User.query.filter(User.username != "admin").all()
    return render_template("admin/adminDashboard.html", users=users)


@app.route("/admin/ban/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.username == "admin":
        flash("Cannot ban admin user", "danger")
        return redirect(url_for("adminDashboard"))

    user.is_banned = not user.is_banned

    try:
        db.session.commit()
        status = "banned" if user.is_banned else "unbanned"
        flash(f"User {user.username} has been {status}", "success")
    except Exception as e:
        flash("An error occurred", "danger")

    return redirect(url_for("adminDashboard"))


# API routes for validation
@app.route("/api/check-username", methods=["POST"])
def check_username():
    username = request.json.get("username", "")
    user = User.query.filter_by(username=username).first()
    return jsonify({"available": not user})


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
