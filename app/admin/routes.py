import csv
from io import StringIO
from datetime import datetime
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    make_response,
    current_app,
)
from sqlalchemy.orm import joinedload  # For efficient loading
from .. import db
from ..models import User, Inquiry
from ..auth.utils import admin_required  # Import decorator from auth utils
from . import admin_bp  # Import blueprint instance


# --- Admin Dashboard ---
@admin_bp.route("/")  # Route is /admin/
@admin_required
def adminDashboard():
    try:
        # Query users, excluding the primary admin from the main list if desired
        # primary_admin_username = current_app.config.get("ADMIN_USERNAME", "admin")
        users = User.query.order_by(
            User.created_at.desc()
        ).all()  # Or filter out primary admin

        # Query recent inquiries with patient username
        recent_inquiries_data = (
            db.session.query(Inquiry, User.username)
            .options(joinedload(Inquiry.patient))  # Eager load patient for efficiency
            .join(User, Inquiry.patient_id == User.id)
            .order_by(Inquiry.created_at.desc())
            .limit(10)
            .all()
        )

        recent_inquiries_list = [
            {
                "id": inquiry.id,
                "patient_id": inquiry.patient_id,
                "name": patient_username,  # Username from join
                "date": inquiry.created_at.strftime("%Y-%m-%d"),
                "subject": inquiry.subject,
                "urgency": inquiry.urgency,
                "status": inquiry.status.replace(
                    "_", " "
                ).title(),  # Make status readable
            }
            for inquiry, patient_username in recent_inquiries_data
        ]

        # Add more stats if needed (counts, etc.)

    except Exception as e:
        current_app.logger.error(f"Error loading admin dashboard data: {e}")
        flash("Failed to load dashboard data.", "danger")
        users = []
        recent_inquiries_list = []

    return render_template(
        "admin/adminDashboard.html",
        users=users,
        recent_inquiries_admin=recent_inquiries_list,
    )


# --- View Inquiry (Admin Perspective) ---
@admin_bp.route("/view_inquiry/<int:inquiry_id>")
@admin_required
def admin_view_inquiry(inquiry_id):
    try:
        # Eager load the related patient (submitter) user object
        inquiry = (
            db.session.query(Inquiry)
            .options(joinedload(Inquiry.patient))
            .get_or_404(inquiry_id)
        )

        # inquiry.patient should be populated due to joinedload
        submitter = inquiry.patient
        if not submitter:
            flash("Submitter user not found for this inquiry.", "warning")
            # Decide how to handle - show inquiry anyway or error?

    except Exception as e:
        current_app.logger.error(
            f"Error retrieving inquiry {inquiry_id} for admin: {e}"
        )
        flash("Could not retrieve inquiry details.", "danger")
        return redirect(url_for("admin.adminDashboard"))

    return render_template(
        "admin/viewInquiryAdmin.html",  # Specific admin view template
        inquiry=inquiry,
        submitter=submitter,  # Pass the submitter object
    )


# --- Update Inquiry Status (Admin Perspective) ---
@admin_bp.route("/update_inquiry_status/<int:inquiry_id>", methods=["POST"])
@admin_required
def admin_update_inquiry_status(inquiry_id):
    inquiry = Inquiry.query.get_or_404(inquiry_id)
    new_status = request.form.get("status")

    # Define allowed statuses for admin actions
    allowed_statuses = ["pending", "in_progress", "resolved", "closed", "on_hold"]
    if new_status not in allowed_statuses:
        flash("Invalid status value selected.", "danger")
        return redirect(url_for("admin.admin_view_inquiry", inquiry_id=inquiry_id))

    inquiry.status = new_status
    inquiry.updated_at = datetime.utcnow()  # Update timestamp

    try:
        db.session.commit()
        status_display = new_status.replace("_", " ").title()
        flash(f"Inquiry status updated to '{status_display}'.", "success")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Admin error updating inquiry {inquiry_id} status: {e}"
        )
        flash("An error occurred while updating the inquiry status.", "danger")

    return redirect(url_for("admin.admin_view_inquiry", inquiry_id=inquiry_id))


# --- Ban/Unban User ---
@admin_bp.route("/ban/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    user_to_ban = User.query.get_or_404(user_id)
    current_admin_id = session.get("user_id")

    # Prevent banning the primary admin (defined by config/env or username)
    primary_admin_username = current_app.config.get("ADMIN_USERNAME", "admin")
    if user_to_ban.username == primary_admin_username:
        flash("The primary admin account cannot be banned.", "danger")
        return redirect(
            url_for(".adminDashboard")
        )  # Use relative endpoint '.adminDashboard'

    # Prevent admins from banning themselves
    if user_to_ban.id == current_admin_id:
        flash("You cannot ban yourself.", "danger")
        return redirect(url_for(".adminDashboard"))

    # Optional: Prevent admins from banning other admins
    # if user_to_ban.is_admin:
    #     flash("Admins cannot ban other admins through this action.", "danger")
    #     return redirect(url_for(".adminDashboard"))

    user_to_ban.is_banned = not user_to_ban.is_banned
    action = "banned" if user_to_ban.is_banned else "unbanned"

    try:
        db.session.commit()
        flash(f"User '{user_to_ban.username}' has been {action}.", "success")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error changing ban status for user {user_id}: {e}")
        flash(f"An error occurred trying to {action} the user.", "danger")

    return redirect(url_for(".adminDashboard"))  # Relative endpoint within blueprint


# --- Toggle Admin Status ---
@admin_bp.route("/toggle-admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user_to_toggle = User.query.get_or_404(user_id)
    current_admin_id = session.get("user_id")

    primary_admin_username = current_app.config.get("ADMIN_USERNAME", "admin")
    if user_to_toggle.username == primary_admin_username:
        flash("Cannot modify privileges for the primary admin user.", "danger")
        return redirect(url_for(".adminDashboard"))

    if user_to_toggle.id == current_admin_id:
        flash("You cannot change your own admin status.", "danger")
        return redirect(url_for(".adminDashboard"))

    # Toggle admin status and potentially role
    user_to_toggle.is_admin = not user_to_toggle.is_admin
    if user_to_toggle.is_admin:
        user_to_toggle.role = "admin"  # Ensure role matches flag
        action = "granted"
    else:
        # Decide what role a demoted admin gets (e.g., patient or their previous role if stored)
        user_to_toggle.role = "patient"  # Revert to patient? Or check previous role?
        action = "revoked"

    try:
        db.session.commit()
        flash(
            f"Admin privileges {action} for user '{user_to_toggle.username}'. Role set to '{user_to_toggle.role}'.",
            "success",
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error toggling admin status for user {user_id}: {e}")
        flash(f"An error occurred changing admin status: {str(e)}", "danger")

    return redirect(url_for(".adminDashboard"))


# --- Download Users CSV ---
@admin_bp.route("/download-users")
@admin_required
def download_users():
    try:
        csv_data = StringIO()
        fieldnames = [
            "ID",
            "Username",
            "Email",
            "Role",
            "Created At",
            "Is Banned",
            "Is Admin",
            "Is Verified",
        ]
        csv_writer = csv.DictWriter(csv_data, fieldnames=fieldnames)
        csv_writer.writeheader()

        users = User.query.order_by(User.id).all()

        for user in users:
            csv_writer.writerow(
                {
                    "ID": user.id,
                    "Username": user.username,
                    "Email": user.email,
                    "Role": user.role,
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

        output = csv_data.getvalue()
        csv_data.close()

        response = make_response(output)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        response.headers["Content-Disposition"] = (
            f"attachment; filename=users_{timestamp}.csv"
        )
        response.headers["Content-Type"] = "text/csv"
        return response

    except Exception as e:
        current_app.logger.error(f"Error generating user CSV download: {e}")
        flash("Failed to generate user download.", "danger")
        return redirect(url_for(".adminDashboard"))


# --- Admin Feedback Form (Route where users SUBMIT feedback TO admin) ---
# This might logically belong in 'main' or 'medic' depending on who uses it,
# but keeping it here if it's primarily for issues reported *to* admin.
# If any logged-in user can submit, remove @admin_required.
# Let's assume any logged-in user can submit this form.
from ..auth.utils import login_required  # Import general login_required


@admin_bp.route("/feedback", methods=["GET", "POST"])
@login_required  # Any logged-in user can access
def adminFeedback():
    user = db.session.get(User, session["user_id"])  # Get current user
    if not user:  # Should be caught by decorator, but safeguard
        flash("Session error.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        subject = request.form.get("subject")
        message_text = request.form.get("message")
        issue_type = request.form.get("issue_type")
        browser_info = request.form.get("browser_info")
        consent = request.form.get("privacy_consent")

        if not subject or not message_text or not issue_type:
            flash("Issue Type, Subject, and Message are required.", "danger")
            # Pass back form data to re-render
            return render_template(
                "admin/adminFeedback.html",
                user=user,
                form_subject=subject,
                form_message=message_text,
                form_issue_type=issue_type,
                form_browser_info=browser_info,
            )

        if not consent:
            flash("You must consent to storing information to submit.", "danger")
            return render_template(
                "admin/adminFeedback.html",
                user=user,
                form_subject=subject,
                form_message=message_text,
                form_issue_type=issue_type,
                form_browser_info=browser_info,
            )

        # Store as an Inquiry? Add distinguishing feature.
        try:
            full_message = f"Issue Type: {issue_type}\nBrowser: {browser_info or 'N/A'}\n\n{message_text}"
            new_inquiry = Inquiry(
                patient_id=user.id,  # User reporting the issue
                subject=f"Admin Support Req: {subject}",
                message=full_message,
                urgency="medium",  # Default urgency for support tickets
                status="pending",
            )
            db.session.add(new_inquiry)
            db.session.commit()

            # Notify admin via email (optional)
            admin_contact_email = current_app.config.get("ADMIN_CONTACT_EMAIL")
            if admin_contact_email:
                from ..utils.email_sender import send_email

                email_subject = f"New Admin Support Request: {subject}"
                email_body = f"Support request from {user.username} ({user.email}):\n\n{full_message}"
                send_email(admin_contact_email, email_subject, email_body)

            flash("Your support request has been submitted.", "success")
            return redirect(url_for(".adminFeedback"))  # Redirect to same page

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error saving admin feedback from user {user.id}: {e}"
            )
            flash("An error occurred submitting your request.", "danger")
            # Re-render form with data
            return render_template(
                "admin/adminFeedback.html",
                user=user,
                form_subject=subject,
                form_message=message_text,
                form_issue_type=issue_type,
                form_browser_info=browser_info,
            )

    # --- GET Request ---
    return render_template("admin/adminFeedback.html", user=user)


# --- Approve Medic ---
@admin_bp.route("/approve_medic/<int:user_id>", methods=["POST"])
@admin_required
def approve_medic(user_id):
    user_to_approve = User.query.get_or_404(user_id)

    # Validation checks
    if user_to_approve.role != "medic":
        flash(f"User '{user_to_approve.username}' is not a medic.", "warning")
        return redirect(url_for(".adminDashboard"))

    if user_to_approve.is_approved:
        flash(f"Medic '{user_to_approve.username}' is already approved.", "info")
        return redirect(url_for(".adminDashboard"))

    # Perform approval
    try:
        user_to_approve.is_approved = True
        db.session.commit()
        flash(
            f"Medic '{user_to_approve.username}' has been approved successfully.",
            "success",
        )
        # Optional: Send email notification to the approved medic
        # send_email(user_to_approve.email, "Your Medic Account is Approved!", "...")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error approving medic {user_id}: {e}")
        flash("An error occurred while approving the medic.", "danger")

    return redirect(url_for(".adminDashboard"))
