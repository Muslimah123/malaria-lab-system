# from flask import jsonify, request
# from .detection.analysis import analyze_patient_slides
# import json
# import logging

# logger = logging.getLogger(__name__)

# def init_routes(app):
#     @app.route('/diagnose', methods=['POST'])
#     def diagnose():
#         data = request.json
#         image_paths = data.get('image_paths', [])
#         if not image_paths:
#             logger.warning("No image paths provided in request")
#             return jsonify({"error": "No image paths provided"}), 400
#         logger.info(f"Received request with {len(image_paths)} image paths")
#         report = analyze_patient_slides(image_paths)
#         return json.dumps(report, indent=2), 200, {'Content-Type': 'application/json'}
from flask import jsonify, request
from .detection.analysis import analyze_patient_slides
import json
import logging
import os
from datetime import datetime
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

# Configure upload settings
UPLOAD_FOLDER = '/app/shared_uploads'  # Shared with Node.js backend
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'tiff', 'tif'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_routes(app):
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for Docker and monitoring"""
        try:
            # Check if model file exists
            model_path = os.path.join(app.root_path, 'models', 'best.pt')
            model_exists = os.path.exists(model_path)
            
            # Check shared upload directory
            upload_dir_exists = os.path.exists(UPLOAD_FOLDER)
            upload_dir_writable = os.access(UPLOAD_FOLDER, os.W_OK) if upload_dir_exists else False
            
            health_data = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'service': 'malaria-diagnosis-api',
                'version': '1.0.0',
                'checks': {
                    'model_loaded': model_exists,
                    'upload_directory': upload_dir_exists,
                    'upload_writable': upload_dir_writable,
                    'api_ready': True
                }
            }
            
            # Return appropriate status code
            if all(check is True for check in health_data['checks'].values() if isinstance(check, bool)):
                return jsonify(health_data), 200
            else:
                return jsonify(health_data), 503
                
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }), 503

    @app.route('/info', methods=['GET'])
    def api_info():
        """API information and capabilities"""
        try:
            return jsonify({
                'name': 'Malaria Diagnosis API',
                'version': '1.0.0',
                'description': 'AI-powered malaria detection from blood smear images',
                'capabilities': [
                    'malaria_detection',
                    'parasite_classification',
                    'multi_image_analysis'
                ],
                'supported_formats': list(ALLOWED_EXTENSIONS),
                'max_file_size': MAX_FILE_SIZE,
                'max_files_per_request': 10,
                'endpoints': {
                    'health': '/health',
                    'info': '/info', 
                    'diagnose_paths': '/diagnose',
                    'diagnose_files': '/analyze'
                }
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/diagnose', methods=['POST'])
    def diagnose():
        """Original endpoint - accepts image paths"""
        try:
            data = request.json
            if not data:
                return jsonify({"error": "No JSON data provided"}), 400
                
            image_paths = data.get('image_paths', [])
            if not image_paths:
                logger.warning("No image paths provided in request")
                return jsonify({"error": "No image paths provided"}), 400
                
            logger.info(f"Received request with {len(image_paths)} image paths")
            
            # Validate that all paths exist
            missing_files = []
            for path in image_paths:
                if not os.path.exists(path):
                    missing_files.append(path)
            
            if missing_files:
                return jsonify({
                    "error": "Some image files not found",
                    "missing_files": missing_files
                }), 400
            
            # Analyze images
            report = analyze_patient_slides(image_paths)
            logger.info(f"Analysis completed - Status: {report.get('status', 'unknown')}")
            
            return jsonify(report), 200
            
        except Exception as e:
            logger.error(f"Diagnosis failed: {str(e)}")
            return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

    @app.route('/analyze', methods=['POST'])
    def analyze_files():
        """New endpoint - accepts file uploads via FormData"""
        try:
            # Check if files were uploaded
            if 'files' not in request.files:
                return jsonify({"error": "No files provided"}), 400
            
            files = request.files.getlist('files')
            if not files or all(file.filename == '' for file in files):
                return jsonify({"error": "No files selected"}), 400
            
            logger.info(f"Received {len(files)} files for analysis")
            
            # Create upload directory if it doesn't exist
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            # Save uploaded files and collect paths
            saved_paths = []
            for i, file in enumerate(files):
                if file and allowed_file(file.filename):
                    # Create unique filename
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = secure_filename(file.filename)
                    unique_filename = f"{timestamp}_{i}_{filename}"
                    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
                    
                    try:
                        file.save(filepath)
                        saved_paths.append(filepath)
                        logger.debug(f"Saved file: {unique_filename}")
                    except Exception as e:
                        logger.error(f"Failed to save file {filename}: {str(e)}")
                        return jsonify({"error": f"Failed to save file: {filename}"}), 500
                else:
                    return jsonify({
                        "error": f"Invalid file: {file.filename}",
                        "allowed_types": list(ALLOWED_EXTENSIONS)
                    }), 400
            
            if not saved_paths:
                return jsonify({"error": "No valid files to process"}), 400
            
            try:
                # Analyze the saved images
                report = analyze_patient_slides(saved_paths)
                logger.info(f"Analysis completed - Status: {report.get('status', 'unknown')}")
                
                # Add metadata about processed files
                report['metadata'] = {
                    'files_processed': len(saved_paths),
                    'analysis_timestamp': datetime.now().isoformat(),
                    'api_version': '1.0.0'
                }
                
                return jsonify(report), 200
                
            except Exception as e:
                logger.error(f"Analysis failed: {str(e)}")
                return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
            
            finally:
                # Clean up uploaded files after analysis
                for path in saved_paths:
                    try:
                        if os.path.exists(path):
                            os.remove(path)
                            logger.debug(f"Cleaned up file: {path}")
                    except Exception as e:
                        logger.warning(f"Failed to clean up file {path}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Unexpected error in analyze_files: {str(e)}")
            return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

    @app.route('/ready', methods=['GET'])  
    def readiness_check():
        """Readiness check - ensures API is ready to handle requests"""
        try:
            # Check if model can be loaded
            model_path = os.path.join(app.root_path, 'models', 'best.pt')
            if not os.path.exists(model_path):
                return jsonify({
                    'status': 'not_ready',
                    'reason': 'Model file not found',
                    'timestamp': datetime.now().isoformat()
                }), 503
            
            # Check upload directory
            if not os.path.exists(UPLOAD_FOLDER):
                try:
                    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                except Exception as e:
                    return jsonify({
                        'status': 'not_ready',
                        'reason': f'Cannot create upload directory: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }), 503
            
            return jsonify({
                'status': 'ready',
                'timestamp': datetime.now().isoformat(),
                'message': 'API is ready to process requests'
            }), 200
            
        except Exception as e:
            return jsonify({
                'status': 'not_ready', 
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }), 503