from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import random
from twilio.rest import Client

# Flask app setup
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(
    24
)  # Generate a random secret key but is in `bytes`
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Twilio configuration
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Initialize database
db = SQLAlchemy(app)


# User model - update to include phone number and verification fields
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"


# Create all database tables
with app.app_context():
    db.create_all()


# Helper function to generate a random 6-digit code
def generate_verification_code():
    return str(random.randint(100000, 999999))


# Helper function to send SMS via Twilio
def send_verification_sms(phone_number, code):
    try:
        message = twilio_client.messages.create(
            body=f"Your FHE Health Prediction verification code is: {code}",
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number,
        )
        return True, message.sid
    except Exception as e:
        return False, str(e)


# Routes
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        phone_number = request.form.get("phone_number")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Format phone number to ensure it has +254 format
        if phone_number.startswith("0"):
            phone_number = "+254" + phone_number[1:]
        elif not phone_number.startswith("+254"):
            phone_number = "+254" + phone_number

        # Validation
        if not all([username, email, phone_number, password, confirm_password]):
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

        existing_phone = User.query.filter_by(phone_number=phone_number).first()
        if existing_phone:
            flash("Phone number already registered", "error")
            return render_template("signup.html")

        # Generate verification code
        verification_code = generate_verification_code()

        # Create new user
        new_user = User(
            username=username,
            email=email,
            phone_number=phone_number,
            password_hash=generate_password_hash(password),
            verification_code=verification_code,
            is_verified=False,
        )

        db.session.add(new_user)
        db.session.commit()

        # Send verification SMS
        success, message = send_verification_sms(phone_number, verification_code)

        if not success:
            flash(f"Failed to send verification code: {message}", "error")
            return render_template("signup.html")

        # Store user_id in session for verification
        session["pending_verification_id"] = new_user.id

        flash(
            "Account created! Please verify your phone number with the code sent via SMS.",
            "success",
        )
        return redirect(url_for("verify"))

    return render_template("signup.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "pending_verification_id" not in session:
        flash("Please sign up first", "error")
        return redirect(url_for("signup"))

    user_id = session["pending_verification_id"]
    user = db.session.get(User, user_id)

    if not user:
        flash("User not found", "error")
        return redirect(url_for("signup"))

    if user.is_verified:
        flash("Your account is already verified. Please log in.", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        verification_code = request.form.get("verification_code")

        if not verification_code:
            flash("Please enter the verification code", "error")
            return render_template("verify.html")

        if verification_code == user.verification_code:
            user.is_verified = True
            user.verification_code = (
                None  # Clear the code after successful verification
            )
            db.session.commit()

            session.pop("pending_verification_id", None)
            flash("Phone number verified successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid verification code. Please try again.", "error")

    return render_template("verify.html", phone_number=user.phone_number)


@app.route("/resend-code")
def resend_code():
    if "pending_verification_id" not in session:
        flash("Please sign up first", "error")
        return redirect(url_for("signup"))

    user_id = session["pending_verification_id"]
    user = db.session.get(User, user_id)

    if not user:
        flash("User not found", "error")
        return redirect(url_for("signup"))

    # Generate new verification code
    verification_code = generate_verification_code()
    user.verification_code = verification_code
    db.session.commit()

    # Send verification SMS
    success, message = send_verification_sms(user.phone_number, verification_code)

    if success:
        flash("Verification code has been resent to your phone", "success")
    else:
        flash(f"Failed to send verification code: {message}", "error")

    return redirect(url_for("verify"))


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

        if not user:
            flash("Invalid username or password", "error")
            return render_template("login.html")

        if not user.is_verified:
            # Store user ID in session for verification
            session["pending_verification_id"] = user.id
            flash("Please verify your phone number before logging in", "error")
            return redirect(url_for("verify"))

        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "error")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("pending_verification_id", None)
    flash("You have been logged out", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
