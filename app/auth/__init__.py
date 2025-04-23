from flask import Blueprint

# Define blueprint: 'auth' is the name, __name__ helps Flask find templates/static
# template_folder='templates' tells Flask to look for templates in 'app/auth/templates/'
# However, it's often easier to keep all templates in the main 'app/templates/' dir
# and specify the path in render_template (e.g., "auth/login.html").
# If you keep templates separate, uncomment template_folder.
auth_bp = Blueprint("auth", __name__)  # , template_folder='templates')

# Import routes after blueprint creation to avoid circular imports
from . import routes, utils  # Import utils if decorators are defined there
