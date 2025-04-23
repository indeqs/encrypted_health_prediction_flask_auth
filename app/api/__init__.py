from flask import Blueprint

api_bp = Blueprint("api", __name__)  # No template folder needed usually for APIs

from . import routes
