import os
from dotenv import load_dotenv
import logging

# Load environment variables first
load_dotenv()

# Now import the app factory
from app import create_app

# Configure logging (optional but good practice)
logging.basicConfig(level=logging.INFO)
# from logging.handlers import RotatingFileHandler
# handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
# handler.setLevel(logging.INFO)
# logging.getLogger().addHandler(handler) # Add handler to root logger

# Create the Flask app instance using the factory
app = create_app()

if __name__ == "__main__":
    # Use Flask's built-in server for development
    # debug=True should get config from FLASK_DEBUG env var if set
    is_debug = os.getenv('FLASK_ENV') == 'development' or os.getenv('FLASK_DEBUG') == '1'
    app.run(debug=is_debug, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))