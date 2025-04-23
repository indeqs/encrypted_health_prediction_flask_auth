import os
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
)
from .. import db
from ..models import User  # Import User if needed (e.g., for context)
from ..utils.email_sender import send_email
from ..utils.helpers import redirect_logged_in_user
from . import main_bp  # Import blueprint instance


# --- Home Page ---
@main_bp.route("/")
def home():
    if "user_id" in session:
        user = db.session.get(User, session.get("user_id"))
        if user:
            # If logged in, check verification and redirect appropriately
            if (
                not user.is_verified and not user.is_admin
            ):  # Admins don't need verify redirect from here
                session["needs_verification"] = True
                flash("Please verify your email.", "warning")
                return redirect(url_for("auth.verify"))
            else:
                # Verified user or admin, redirect to their dashboard/app
                return redirect_logged_in_user(user)
        else:
            # Invalid user_id in session, clear it
            session.clear()

    # Render home for logged-out users or if session check fails
    return render_template("main/index.html")


# --- Contact Page ---
@main_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject", "Contact Form Submission")
        message = request.form.get("message")

        if not name or not email or not message:
            flash("Please fill out Name, Email, and Message.", "danger")
            return render_template(
                "main/contact.html",
                form_name=name,
                form_email=email,
                form_subject=subject,
                form_message=message,
            )

        # Send email to admin contact address
        admin_email = current_app.config.get("ADMIN_CONTACT_EMAIL")
        if not admin_email:
            current_app.logger.error(
                "ADMIN_CONTACT_EMAIL not set. Cannot send contact form email."
            )
            flash(
                "Could not process your request due to a configuration error.", "danger"
            )
            return render_template(
                "main/contact.html",
                form_name=name,
                form_email=email,
                form_subject=subject,
                form_message=message,
            )

        email_body = f"Contact form submission:\nName: {name}\nEmail: {email}\nSubject: {subject}\n\nMessage:\n{message}"
        email_subject = f"Website Contact: {subject}"

        try:
            if send_email(admin_email, email_subject, email_body):
                flash("Thank you for your message! We'll be in touch.", "success")
                return redirect(url_for(".contact"))  # Redirect to GET after POST
            else:
                flash(
                    "Sorry, there was an error sending your message. Please try again.",
                    "danger",
                )
        except Exception as e:
            current_app.logger.error(
                f"Error sending contact form email from {email}: {e}"
            )
            flash("An unexpected error occurred.", "danger")

        # Re-render form if email sending failed but no exception
        return render_template(
            "main/contact.html",
            form_name=name,
            form_email=email,
            form_subject=subject,
            form_message=message,
        )

    # --- GET Request ---
    return render_template("main/contact.html")


# --- Static Pages ---
@main_bp.route("/terms-of-service")
def terms_of_service():
    return render_template("main/tos.html")  # Assuming tos.html is in templates/main/


@main_bp.route("/privacy-policy")
def privacy_policy():
    return render_template(
        "main/policy.html"
    )  # Assuming policy.html is in templates/main/


# --- Newsletter Subscription (Example) ---
# This might be better in its own blueprint or integrated elsewhere if complex
@main_bp.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email")
    if email:  # Add proper validation
        # Logic to store email (e.g., add to a MailingList model/table)
        current_app.logger.info(f"Newsletter subscription: {email}")
        flash("Thank you for subscribing!", "success")
    else:
        flash("Please provide a valid email address.", "warning")

    # Redirect back to the referring page or a default page
    # Using request.referrer is generally discouraged due to security/reliability
    # Redirecting to home or the page where the form likely is (e.g., terms)
    return redirect(request.referrer or url_for(".home"))
