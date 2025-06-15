from flask import jsonify, request
from .detection.analysis import MalariaAnalyzer
import json
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

def init_routes(app):
    """Initialize API routes for the Flask application."""
    analyzer = MalariaAnalyzer()

    @app.route('/')
    def testapp():
        return "app is up!!"
    
    @app.route('/diagnose', methods=['POST'])
    def diagnose() -> Tuple[str, int, dict]:
        """Handle diagnosis requests for multiple images."""
        try:
            data = request.get_json()
            if not data or 'image_paths' not in data:
                logger.warning("Invalid request: No image paths provided")
                return jsonify({"error": "No image paths provided"}), 400, {'Content-Type': 'application/json'}

            image_paths = data.get('image_paths', [])
            if not image_paths:
                logger.warning("Empty image paths list in request")
                return jsonify({"error": "No image paths provided"}), 400, {'Content-Type': 'application/json'}

            logger.info(f"Received diagnosis request with {len(image_paths)} image paths")
            report = analyzer.analyze_patient_slides(image_paths)
            
            if report.get("status") == "ERROR":
                logger.error(f"Diagnosis failed: {report.get('error')}")
                return jsonify(report), 500, {'Content-Type': 'application/json'}

            logger.info(f"Diagnosis completed successfully: Status={report['status']}, "
                       f"Images processed={report['total_images_processed']}")
            return json.dumps(report, indent=2), 200, {'Content-Type': 'application/json'}

        except Exception as e:
            logger.error(f"Unexpected error in diagnose endpoint: {str(e)}")
            return jsonify({"error": f"Internal server error: {str(e)}"}), 500, {'Content-Type': 'application/json'}