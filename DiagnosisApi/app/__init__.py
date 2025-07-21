# # from flask import Flask
# # from .utils.logging import setup_logging
# # from .routes import init_routes

# # def create_app():
# #     app = Flask(__name__)
# #     setup_logging()  # Configure logging
# #     init_routes(app)  # Register routes
# #     return app

# # app = create_app()

# # File: DiagnosisApi/app/__init__.py
# from flask import Flask

# app = Flask(__name__)

# from app.routes import init_routes # Import routes after initializing Flask
# init_routes(app)

# 📁 DiagnosisApi/app/__init__.py
from flask import Flask
import logging
import os

def create_app():
    app = Flask(__name__)
    
    # Configure basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/app/logs/app.log')
        ]
    )
    
    # Create logs directory if it doesn't exist
    os.makedirs('/app/logs', exist_ok=True)
    
    # Import and register routes
    from .routes import init_routes
    init_routes(app)
    
    return app

app = create_app()