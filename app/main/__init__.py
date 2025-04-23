from flask import Blueprint

main_bp = Blueprint("main", __name__)  # Or use main template dir

from . import routes
