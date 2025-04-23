from flask import Blueprint

admin_bp = Blueprint("admin", __name__)  # Or use main template dir

from . import routes
