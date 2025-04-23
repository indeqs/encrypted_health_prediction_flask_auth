from flask import Blueprint

medic_bp = Blueprint("medic", __name__)  # Or use main template dir

from . import routes
