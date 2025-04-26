from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
)
from datetime import datetime, timedelta
from sqlalchemy.orm import joinedload, selectinload
from .. import db
from ..models import User, Inquiry, Message
from ..auth.utils import login_required, medic_required  # Import decorators
from . import medic_bp  # Import blueprint instance
from ..utils.helpers import redirect_logged_in_user


# --- Medic Dashboard ---
@medic_bp.route("/dashboard")  # Route is /medic/dashboard
@login_required  # Redundant if medic_required used, but explicit
@medic_required
def medicDashboard():
    current_medic = db.session.get(User, session["user_id"])

    try:
        # Stats
        total_patients_count = User.query.filter_by(
            role="patient", is_banned=False
        ).count()
        new_inquiries_count = Inquiry.query.filter_by(status="pending").count()
        one_week_ago = datetime.utcnow() - timedelta(days=7)
        weekly_patients_count = User.query.filter(
            User.role == "patient",
            User.created_at >= one_week_ago,
            User.is_banned == False,
        ).count()

        # Recent Inquiries (Join with User for patient name)
        recent_inquiries_data = (
            db.session.query(Inquiry, User.username)
            .options(
                joinedload(Inquiry.patient)
            )  # Efficiently load patient data if needed beyond username
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
                "urgency": inquiry.urgency.title(),
                "status": inquiry.status.replace("_", " ").title(),
            }
            for inquiry, patient_username in recent_inquiries_data
        ]

        # Recent Patients
        recent_patients_users = (
            User.query.filter_by(role="patient", is_banned=False)
            .order_by(User.created_at.desc())
            .limit(3)
            .all()
        )
        recent_patients_list = [
            {"id": p.id, "name": p.username, "last_visit": "N/A"}  # Placeholder
            for p in recent_patients_users
        ]

        # Activity Graph Data (Replace dummy data with real aggregated data)
        activity_labels_data = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
        inquiry_data_points = [10, 15, 8, 12, 20, 18]  # Example data

    except Exception as e:
        current_app.logger.error(
            f"Error loading medic dashboard for {current_medic.username}: {e}"
        )
        flash("Failed to load dashboard data.", "danger")
        # Set defaults for template rendering
        total_patients_count = new_inquiries_count = weekly_patients_count = 0
        recent_inquiries_list = []
        recent_patients_list = []
        activity_labels_data = []
        inquiry_data_points = []

    return render_template(
        "medic/medicDashboard.html",
        current_user=current_medic,  # Pass the medic user object
        total_patients=total_patients_count,
        new_inquiries=new_inquiries_count,
        weekly_patients=weekly_patients_count,
        recent_inquiries=recent_inquiries_list,
        recent_patients=recent_patients_list,
        activity_labels=activity_labels_data,
        inquiry_data=inquiry_data_points,
    )


# --- Medical Feedback/Inquiry Submission Form (Used by Patients, submits TO Medics) ---
# This route handles the form *for* submitting medical questions.
# It should be accessible by logged-in patients.
@medic_bp.route("/submit_inquiry", methods=["GET", "POST"])
@login_required  # Require login, but not necessarily medic
def medicFeedback():
    user = db.session.get(User, session["user_id"])
    if not user:
        flash("Session error.", "danger")
        return redirect(url_for("auth.login"))
    
    # --- ADD ROLE CHECK ---
    # Only allow patients to submit medical inquiries via this form.
    # Redirect admins and medics away.
    if user.role != 'patient':
         flash("Only patients can submit medical inquiries.", "warning")
         # Redirect based on their actual role
         if user.is_admin:
             return redirect(url_for('admin.adminDashboard'))
         elif user.role == 'medic':
             # If the medic is approved, redirect to their dashboard, otherwise login (handled by redirect_logged_in_user)
             return redirect_logged_in_user(user) # Let helper decide where approved/unapproved medics go
         else:
            # Fallback for unknown roles
            return redirect(url_for('main.home'))
    # --- END ROLE CHECK ---

    # Optional: Restrict access if needed (e.g., only patients can submit)
    if user.role != "patient":
        flash("Only patients can submit medical inquiries via this form.", "warning")
        # Redirect based on role
        if user.is_admin:
            return redirect(url_for("admin.adminDashboard"))
        if user.role == "medic":
            return redirect(url_for("medic.medicDashboard"))
        return redirect(url_for("main.home"))

    if request.method == "POST":
        subject = request.form.get("subject")
        symptoms_text = request.form.get("symptoms")
        message_text = request.form.get("message")
        urgency_level = request.form.get("urgency", "medium")
        consent = request.form.get("privacy_consent")

        if not subject or not message_text:
            flash("Subject and Medical Question are required.", "danger")
            return render_template(
                "medic/medicFeedback.html",
                user=user,
                form_subject=subject,
                form_symptoms=symptoms_text,
                form_message=message_text,
                form_urgency=urgency_level,
            )

        if not consent:
            flash("You must consent to sharing information.", "danger")
            return render_template(
                "medic/medicFeedback.html",
                user=user,
                form_subject=subject,
                form_symptoms=symptoms_text,
                form_message=message_text,
                form_urgency=urgency_level,
            )

        try:
            new_inquiry = Inquiry(
                patient_id=user.id,
                subject=subject,
                message=message_text,
                symptoms=symptoms_text,
                urgency=urgency_level,
                status="pending",
            )
            db.session.add(new_inquiry)
            db.session.commit()
            flash("Your medical question has been submitted successfully.", "success")
            # Redirect to prevent resubmit, maybe to a confirmation page or back to form
            return redirect(
                url_for(".medicFeedback")
            )  # Redirect to the GET view of the same form

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error saving medical inquiry for user {user.id}: {e}"
            )
            flash("An error occurred submitting your question.", "danger")
            return render_template(
                "medic/medicFeedback.html",
                user=user,
                form_subject=subject,
                form_symptoms=symptoms_text,
                form_message=message_text,
                form_urgency=urgency_level,
            )

    # --- GET Request ---
    # Pass user to pre-fill info if needed (though form doesn't ask for name/email now)
    return render_template("medic/medicFeedback.html", user=user)


# --- View Specific Inquiry (Medic Perspective) ---
# --- View Specific Inquiry (Medic Perspective) ---
@medic_bp.route("/view_inquiry/<int:inquiry_id>")
@login_required
@medic_required # Only medics view inquiries this way
def view_inquiry(inquiry_id):
    try:
        # Eager load patient and messages efficiently
        inquiry = db.session.query(Inquiry)\
                      .options(
                          joinedload(Inquiry.patient), # Load patient info
                          selectinload(Inquiry.messages).joinedload(Message.user) # Load messages and their senders
                      )\
                      .get_or_404(inquiry_id)

        patient = inquiry.patient # Access the loaded patient object
        if not patient:
             flash("Patient record associated with this inquiry not found.", "warning")

        # --- GET THE CURRENT USER ---
        current_user = db.session.get(User, session.get('user_id'))
        # Basic check, although decorators should handle non-logged-in users
        if not current_user:
             flash("Could not identify current user.", "danger")
             return redirect(url_for('.medicDashboard'))
        # --- END GET CURRENT USER ---

        # Format dates for display (moved inside try block)
        created_date = inquiry.created_at.strftime("%Y-%m-%d %H:%M")
        updated_date = inquiry.updated_at.strftime("%Y-%m-%d %H:%M") if inquiry.updated_at else "N/A"

    except Exception as e:
        current_app.logger.error(f"Error retrieving inquiry {inquiry_id} for medic view: {e}")
        flash("Could not retrieve inquiry details.", "danger")
        return redirect(url_for('.medicDashboard')) # Redirect to medic dashboard on error

    # --- PASS current_user TO TEMPLATE ---
    return render_template(
        "medic/viewInquiry.html", # Specific medic view template
        inquiry=inquiry,
        patient=patient, # Pass the patient object
        created_date=created_date,
        updated_date=updated_date,
        current_user=current_user # <-- ADD THIS
    )

@medic_bp.route('/inquiry/<int:inquiry_id>/reply', methods=['POST'])
@login_required
@medic_required # Ensure only approved medic replies
def reply_to_inquiry_medic(inquiry_id):
    # Similar logic as admin reply, but user_id is the medic's ID
    inquiry = db.session.query(Inquiry).get_or_404(inquiry_id)
    reply_body = request.form.get('reply_body')
    current_medic_id = session['user_id']

    # Optional: Extra check if this medic should be handling this specific inquiry?
    # (For now, any approved medic can reply)

    if not reply_body:
        flash("Reply message cannot be empty.", "danger")
        return redirect(url_for('.view_inquiry', inquiry_id=inquiry_id))

    try:
        new_message = Message(
            body=reply_body,
            inquiry_id=inquiry.id,
            user_id=current_medic_id # Medic is the sender
        )
        inquiry.updated_at = datetime.utcnow()
        db.session.add(new_message)
        db.session.commit()
        flash("Reply sent successfully.", "success")

        # TODO: Optional - Send email notification to inquiry.patient

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error saving medic reply for inquiry {inquiry_id}: {e}")
        flash("An error occurred while sending the reply.", "danger")

    return redirect(url_for('.view_inquiry', inquiry_id=inquiry_id))

# --- Update Inquiry Status (Medic Perspective) ---
@medic_bp.route("/update_inquiry_status/<int:inquiry_id>", methods=["POST"])
@login_required
@medic_required  # Only medics update status this way
def update_inquiry_status(inquiry_id):
    inquiry = Inquiry.query.get_or_404(inquiry_id)
    new_status = request.form.get("status")

    # Define allowed statuses for medic actions
    allowed_statuses = [
        "pending",
        "in_progress",
        "resolved",
    ]  # Medics might have fewer options than admin
    if new_status not in allowed_statuses:
        flash("Invalid status value selected.", "danger")
        return redirect(url_for(".view_inquiry", inquiry_id=inquiry_id))

    inquiry.status = new_status
    inquiry.updated_at = datetime.utcnow()

    try:
        db.session.commit()
        flash(
            f"Inquiry status updated to {new_status.replace('_', ' ').title()}.",
            "success",
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Medic error updating inquiry {inquiry_id} status: {e}"
        )
        flash("An error occurred while updating the status.", "danger")

    # Redirect back to the inquiry view page
    return redirect(url_for(".view_inquiry", inquiry_id=inquiry_id))
