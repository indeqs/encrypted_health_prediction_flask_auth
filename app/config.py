import os
from dotenv import load_dotenv

# Ensure .env is loaded if this file is imported directly elsewhere,
# although run.py should load it first in the main execution path.
load_dotenv()


class Config:
    """Base configuration settings."""

    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24))
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///users.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECURITY_PASSWORD_SALT = os.getenv(
        "SECURITY_PASSWORD_SALT", "default_salt_please_change"
    )  # Provide a default or ensure it's in .env

    # Email configuration
    EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    ADMIN_CONTACT_EMAIL = os.getenv(
        "ADMIN_CONTACT_EMAIL", "admin@app.com"
    )  # Email for contact form

    # Add other configurations if needed
    # e.g., SESSION_COOKIE_SECURE = True (for production)
    # e.g., REMEMBER_COOKIE_SECURE = True


class DevelopmentConfig(Config):
    """Development specific configurations."""

    DEBUG = True
    SQLALCHEMY_ECHO = False  # Set to True to see SQL queries


class ProductionConfig(Config):
    """Production specific configurations."""

    DEBUG = False
    # Add production specific settings like secure cookies, different DB URL, etc.
    # SESSION_COOKIE_SECURE = True
    # REMEMBER_COOKIE_SECURE = True


# Dictionary to access config classes by name
config_by_name = dict(
    dev=DevelopmentConfig, prod=ProductionConfig, default=DevelopmentConfig
)


# Function to get secret key (optional, if SECRET_KEY is complexly derived)
def get_secret_key():
    # Example: load from file or other secure source
    return Config.SECRET_KEY
