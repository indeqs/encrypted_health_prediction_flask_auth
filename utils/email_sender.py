from os import getenv
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def generate_verification_code(length=6):
    """Generate a random numeric verification code"""
    return "".join(random.choices(string.digits, k=length))


def send_email(recipient_email, subject, body):
    """
    Send an email using SMTP

    Parameters:
        recipient_email (str): Recipient's email address
        subject (str): Email subject
        body (str): Email body content
    """
    sender_email = getenv("EMAIL_USERNAME")
    sender_password = getenv("EMAIL_PASSWORD")

    # Create a multipart message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject

    # Add body to email
    message.attach(MIMEText(body, "plain"))

    try:
        # Create SMTP session for sending the mail
        server = smtplib.SMTP(
            getenv("SMTP_SERVER", "smtp.gmail.com"), int(getenv("SMTP_PORT", "587"))
        )
        server.starttls()  # Secure the connection

        # Login to sender email
        server.login(sender_email, sender_password)

        # Send email
        text = message.as_string()
        server.sendmail(sender_email, recipient_email, text)

        # Terminate the session
        server.quit()
        return True

    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def send_verification_code(email, code):
    """Send a verification code to the user's email"""
    subject = "Your Verification Code for FHE Health Prediction"
    body = f"""
Hello,

Your Verification Code for the FHE Health Prediction System is: {code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Regards,
FHE Health Prediction Team
    """
    return send_email(email, subject, body)
