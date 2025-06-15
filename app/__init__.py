from flask import Flask
from .utils.logging import setup_logging
from .routes import init_routes

def create_app():
    """Create and configure the Flask application."""
    try:
        setup_logging()  # Configure logging before routes
        app = Flask(__name__)
        init_routes(app)
        app.logger.info("Flask application initialized successfully")
        return app
    except Exception as e:
        print(f"Failed to create Flask app: {str(e)}")
        raise