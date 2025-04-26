import os
from datetime import datetime
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
    abort,
)
from .. import db
from ..models import User, Inquiry, Message
from ..utils.email_sender import send_email
from ..utils.helpers import redirect_logged_in_user
from . import main_bp  # Import blueprint instance
from ..auth.utils import login_required
from sqlalchemy.orm import selectinload
from ..models import Inquiry, Message


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

@main_bp.route('/my-inquiries')
@login_required
def my_inquiries():
    user_id = session['user_id']
    # Order by last activity (updated_at timestamp)
    inquiries = Inquiry.query.filter_by(patient_id=user_id)\
                     .order_by(Inquiry.updated_at.desc())\
                     .all()
    return render_template('main/my_inquiries.html', inquiries=inquiries)

# --- View Single Inquiry ---
@main_bp.route('/my-inquiry/<int:inquiry_id>')
@login_required
def view_my_inquiry(inquiry_id):
    user_id = session['user_id']

    try:
        # Fetch inquiry with messages and the user who sent each message, ordered by creation time
        inquiry = db.session.query(Inquiry)\
                      .options(
                          selectinload(Inquiry.messages).joinedload(Message.user),
                          selectinload(Inquiry.messages).options(db.defer(Message.user_id)) # Optional: Defer unused columns
                      )\
                      .filter_by(id=inquiry_id)\
                      .first() # Use first() instead of first_or_404 for custom check

        if not inquiry:
             abort(404) # Inquiry not found

        # --- SECURITY CHECK: Ensure current user owns this inquiry ---
        if inquiry.patient_id != user_id:
            flash("You do not have permission to view this inquiry.", "danger")
            # Redirect to list instead of aborting if it's just a permission issue
            return redirect(url_for('.my_inquiries'))

        # Order messages chronologically after loading
        inquiry.messages.sort(key=lambda msg: msg.created_at)

    except Exception as e:
        current_app.logger.error(f"Error fetching inquiry {inquiry_id} for user {user_id}: {e}")
        flash("Could not retrieve inquiry details.", "danger")
        return redirect(url_for('.my_inquiries'))

    # --- Enable Replies for Patients ---
    can_reply = True

    return render_template(
        'main/view_my_inquiry.html',
        inquiry=inquiry,
        can_reply=can_reply,
        current_user_id=user_id # Pass user_id for comparison in template
    )

# --- Reply Route for Patients ---
@main_bp.route('/my-inquiry/<int:inquiry_id>/reply', methods=['POST'])
@login_required
def reply_to_my_inquiry(inquiry_id):
    user_id = session['user_id']
    message_content = request.form.get('message_content')

    if not message_content:
        flash("Reply message cannot be empty.", "warning")
        return redirect(url_for('.view_my_inquiry', inquiry_id=inquiry_id))

    try:
        # Fetch the inquiry again for security check and updates
        inquiry = db.session.get(Inquiry, inquiry_id)

        # --- Security Check: Ensure inquiry exists and belongs to the user ---
        if not inquiry:
            abort(404)
        if inquiry.patient_id != user_id:
            flash("You do not have permission to reply to this inquiry.", "danger")
            abort(403) # Forbidden access

        # Create the new message
        new_message = Message(
            inquiry_id=inquiry_id,
            user_id=user_id,
            body=message_content
            # created_at defaults to now()
        )

        # Update inquiry's last activity time
        inquiry.updated_at = datetime.utcnow()

        # Optional: Re-open inquiry if it was resolved
        if inquiry.status == 'resolved':
            inquiry.status = 'in_progress'
            flash("Inquiry status changed back to 'In Progress'.", "info")

        db.session.add(new_message)
        # No need to add inquiry again unless status changed, but it's safe to do so
        db.session.add(inquiry)
        db.session.commit()

        flash("Your reply has been added.", "success")

    except Exception as e:
        db.session.rollback() # Rollback in case of error
        current_app.logger.error(f"Error adding reply to inquiry {inquiry_id} by user {user_id}: {e}")
        flash("An error occurred while adding your reply. Please try again.", "danger")

    return redirect(url_for('.view_my_inquiry', inquiry_id=inquiry_id))


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
