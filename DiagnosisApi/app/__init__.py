# DiagnosisApi/app/__init__.py
from flask import Flask, jsonify
from .utils.logging import setup_logging
from .routes import init_routes
import logging
import psutil
import os
import gc

logger = logging.getLogger(__name__)

def create_app():
    """Create and configure the Flask application."""
    try:
        app = Flask(__name__)
        setup_logging()  # Configure logging before routes
        
        # ✅ NEW: Memory monitoring and management
        def check_memory_usage():
            """Monitor memory usage and trigger cleanup if needed"""
            try:
                process = psutil.Process(os.getpid())
                memory_info = process.memory_info()
                memory_percent = process.memory_percent()
                
                # Log memory usage
                logger.info(f"Memory usage: {memory_info.rss / 1024 / 1024:.1f}MB ({memory_percent:.1f}%)")
                
                # If memory usage is high, trigger garbage collection
                if memory_percent > 80:
                    logger.warning(f"High memory usage detected: {memory_percent:.1f}%. Triggering cleanup...")
                    gc.collect()
                    
                    # Check again after cleanup
                    process = psutil.Process(os.getpid())
                    memory_percent_after = process.memory_percent()
                    logger.info(f"Memory after cleanup: {memory_percent_after:.1f}%")
                    
                    # If still high, log warning
                    if memory_percent_after > 85:
                        logger.error(f"Memory usage still high after cleanup: {memory_percent_after:.1f}%")
                        return False
                
                return True
            except Exception as e:
                logger.warning(f"Could not check memory usage: {e}")
                return True
        
        # ✅ NEW: Memory check before each request
        @app.before_request
        def before_request():
            """Check memory before processing each request"""
            if not check_memory_usage():
                logger.error("Memory usage too high, rejecting request")
                return jsonify({
                    "error": "Server temporarily unavailable due to high memory usage",
                    "message": "Please try again in a few minutes"
                }), 503
        
        # ✅ NEW: Memory cleanup after each request
        @app.after_request
        def after_request(response):
            """Clean up memory after processing request"""
            try:
                # Force garbage collection after each request
                gc.collect()
                
                # Log memory usage after cleanup
                process = psutil.Process(os.getpid())
                memory_info = process.memory_info()
                memory_percent = process.memory_percent()
                logger.info(f"Memory after request cleanup: {memory_info.rss / 1024 / 1024:.1f}MB ({memory_percent:.1f}%)")
                
            except Exception as e:
                logger.warning(f"Error during memory cleanup: {e}")
            
            return response
        
        # Initialize routes (includes health check)
        init_routes(app)
        
        # Add global error handlers
        @app.errorhandler(404)
        def not_found(error):
            return jsonify({"error": "Endpoint not found"}), 404
        
        @app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {str(error)}")
            return jsonify({"error": "Internal server error"}), 500
        
        @app.errorhandler(503)
        def service_unavailable(error):
            logger.error(f"Service unavailable: {str(error)}")
            return jsonify({"error": "Service temporarily unavailable"}), 503
        
        logger.info("Flask application initialized successfully with memory monitoring")
        app.logger.info("Flask application initialized successfully with memory monitoring")
        return app
        
    except Exception as e:
        error_msg = f"Failed to create Flask app: {str(e)}"
        logger.error(error_msg)
        print(error_msg)
        raise