from flask import request, jsonify, current_app
from ..models import User
from . import api_bp  # Import blueprint instance


@api_bp.route("/check-username", methods=["POST"])
def check_username():
    username = request.json.get("username", "").strip()
    if not username:
        return (
            jsonify({"available": False, "message": "Username cannot be empty."}),
            400,
        )  # Bad Request

    # Add more validation (length, characters) if needed

    try:
        # Case-insensitive check
        user = User.query.filter(User.username.ilike(username)).first()
        is_available = not user
        message = (
            "Username available." if is_available else "Username is already taken."
        )
        return jsonify({"available": is_available, "message": message})
    except Exception as e:
        current_app.logger.error(f"Error checking username '{username}': {e}")
        return (
            jsonify(
                {"available": False, "message": "Error checking username availability."}
            ),
            500,
        )


# Add other API endpoints here (e.g., check-email)
