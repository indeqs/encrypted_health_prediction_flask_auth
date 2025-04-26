from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from . import db  # Import db from the current package's __init__
from .utils.email_sender import generate_verification_code  # Keep email utils together


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(
        db.String(20), default="patient", nullable=False
    )  # patient, medic, admin
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 2FA fields
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_code = db.Column(db.String(10), nullable=True)
    verification_code_expires = db.Column(db.DateTime, nullable=True)
    is_approved = db.Column(
        db.Boolean, default=False, nullable=False
    )  # Medics need admin approval

    # Add relationship to messages sent BY this user
    messages = db.relationship('Message', back_populates='user', lazy='dynamic', foreign_keys='Message.user_id') # Explicit FK

    # Relationships (adjust lazy loading as needed)
    # For inquiries submitted BY this user (if they are a patient)
    patient_inquiries = db.relationship(
        "Inquiry",
        foreign_keys="Inquiry.patient_id",
        back_populates="patient",
        lazy="dynamic"
    )
    # Optional: If you track which medic handles an inquiry
    # medic_assigned_inquiries = db.relationship('Inquiry', foreign_keys='Inquiry.medic_id', back_populates='medic', lazy='dynamic')

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
            self.verification_code = None  # Expire the code in DB too
            self.verification_code_expires = None
            return False  # Code expired

        if self.verification_code != code:
            return False  # Code invalid

        # Code is valid - mark user as verified and clear code
        self.is_verified = True
        self.verification_code = None
        self.verification_code_expires = None
        return True


class Inquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=True)
    symptoms = db.Column(db.Text, nullable=True)
    urgency = db.Column(
        db.String(20), default="medium", nullable=False
    )  # e.g., low, medium, high
    status = db.Column(
        db.String(20), default="pending", nullable=False
    )  # e.g., pending, in_progress, resolved, closed, on_hold
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
        "User", back_populates="patient_inquiries", foreign_keys=[patient_id]
    )
    # Optional: Relationship to the medic
    # medic = db.relationship('User', back_populates='medic_assigned_inquiries', foreign_keys=[medic_id])

    # Add relationship to messages WITHIN this inquiry
    messages = db.relationship('Message', back_populates='inquiry', cascade="all, delete-orphan", order_by='Message.created_at')

    # Optional: Helper to get latest message timestamp (useful for sorting inquiries)
    # @property
    # def last_activity(self):
    #     last_message = self.messages.order_by(Message.created_at.desc()).first()
    #     if last_message:
    #         return last_message.created_at
    #     return self.updated_at # Fallback to inquiry update time

    def __repr__(self):
        return f"<Inquiry {self.id} - {self.subject}>"
    
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign Keys
    inquiry_id = db.Column(db.Integer, db.ForeignKey('inquiry.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # ID of the message sender

    # Relationships (add back_populates for bidirectional access)
    inquiry = db.relationship('Inquiry', back_populates='messages')
    user = db.relationship('User', back_populates='messages') # User who sent this message

    def __repr__(self):
        return f'<Message {self.id} for Inquiry {self.inquiry_id}>'
