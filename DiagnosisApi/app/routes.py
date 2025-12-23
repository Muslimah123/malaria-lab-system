# DiagnosisApi/app/routes.py 
# Basic YOLO Detection with simple endpoints

from flask import jsonify, request
from .detection.analysis import MalariaAnalyzer
import json
import logging
import os
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

def init_routes(app):
    """Initialize all API routes for the Flask application with basic YOLO detection."""
    analyzer = MalariaAnalyzer()

    @app.route('/')
    def root():
        """Root endpoint with API information."""
        return jsonify({
            "service": "malaria-detection-api",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "detection": [
                    "/diagnose - Basic malaria diagnosis",
                    "/analyze - Backward compatible analysis"
                ],
                "system": [
                    "/health - Basic health check"
                ]
            },
            "features": {
                "parasite_detection": "Detect PF, PM, PO, PV parasites",
                "wbc_detection": "Detect white blood cells",
                "bounding_boxes": "Basic coordinate detection",
                "confidence_scoring": "Detection confidence thresholds"
            }
        })

    @app.route('/health', methods=['GET'])
    def health_check():
        """Basic health check endpoint."""
        try:
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "service": "malaria-detection-api",
                "version": "1.0.0"
            })
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }), 500

    @app.route('/diagnose', methods=['POST'])
    def diagnose():
        """Main diagnosis endpoint for malaria detection."""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    "status": "ERROR",
                    "error": "No data provided"
                }), 400

            image_paths = data.get('image_paths', [])
            
            if not image_paths:
                return jsonify({
                    "status": "ERROR",
                    "error": "No image paths provided"
                }), 400

            if not isinstance(image_paths, list):
                return jsonify({
                    "status": "ERROR",
                    "error": "image_paths must be a list"
                }), 400

            logger.info(f"Starting diagnosis for {len(image_paths)} images")
            
            # Validate image files exist
            for image_path in image_paths:
                if not os.path.exists(image_path):
                    return jsonify({
                        "status": "ERROR",
                        "error": f"Image file not found: {image_path}"
                    }), 400

            # Run analysis
            result = analyzer.analyze_patient_slides(image_paths)
            
            if result.get("status") == "ERROR":
                return jsonify(result), 500

            logger.info(f"Diagnosis completed successfully - Status: {result.get('status')}")
            
            return jsonify(result)

        except Exception as e:
            logger.error(f"Diagnosis failed: {e}")
            return jsonify({
                "status": "ERROR",
                "error": f"Diagnosis failed: {str(e)}"
            }), 500

    @app.route('/analyze', methods=['POST'])
    def analyze():
        """Backward compatible analysis endpoint."""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    "status": "ERROR",
                    "error": "No data provided"
                }), 400

            image_paths = data.get('image_paths', [])
            
            if not image_paths:
                return jsonify({
                    "status": "ERROR",
                    "error": "No image paths provided"
                }), 400

            logger.info(f"Starting analysis for {len(image_paths)} images")
            
            # Validate image files exist
            for image_path in image_paths:
                if not os.path.exists(image_path):
                    return jsonify({
                        "status": "ERROR",
                        "error": f"Image file not found: {image_path}"
                    }), 400

            # Run analysis
            result = analyzer.analyze_patient_slides(image_paths)
            
            if result.get("status") == "ERROR":
                return jsonify(result), 500

            logger.info(f"Analysis completed successfully - Status: {result.get('status')}")
            
            return jsonify(result)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return jsonify({
                "status": "ERROR",
                "error": f"Analysis failed: {str(e)}"
            }), 500

    @app.route('/model_info', methods=['GET'])
    def model_info():
        """Get basic model information."""
        try:
            return jsonify({
                "model": "V12.pt",
                "type": "YOLO",
                "version": "1.0.0",
                "capabilities": {
                    "detection": True,
                    "segmentation": False,
                    "classification": False
                },
                "supported_classes": {
                    "parasites": ["PF", "PM", "PO", "PV"],
                    "wbc": ["WBC"]
                },
                "confidence_threshold": 0.26
            })
        except Exception as e:
            logger.error(f"Model info failed: {e}")
            return jsonify({
                "status": "ERROR",
                "error": f"Failed to get model info: {str(e)}"
            }), 500

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "status": "ERROR",
            "error": "Endpoint not found"
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "status": "ERROR",
            "error": "Internal server error"
        }), 500

    @app.errorhandler(Exception)
    def handle_exception(error):
        logger.error(f"Unhandled exception: {error}")
        return jsonify({
            "status": "ERROR",
            "error": "An unexpected error occurred"
        }), 500