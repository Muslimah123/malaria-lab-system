# DiagnosisApi/app/routes.py
# Malaria Detection API with parallel processing and streaming progress

from flask import jsonify, request, Response, stream_with_context
from .detection.analysis import MalariaAnalyzer
import json
import logging
import os
import queue
import threading
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

def init_routes(app):
    """Initialize all API routes for the Flask application with parallel processing."""
    analyzer = MalariaAnalyzer()

    @app.route('/')
    def root():
        """Root endpoint with API information."""
        return jsonify({
            "service": "malaria-detection-api",
            "version": "2.0.0",
            "status": "running",
            "features": {
                "parallel_processing": True,
                "workers": analyzer.num_workers,
                "streaming_progress": True
            },
            "endpoints": {
                "detection": [
                    "/diagnose - Standard diagnosis (parallel processing)",
                    "/diagnose/stream - Diagnosis with streaming progress",
                    "/analyze - Backward compatible analysis"
                ],
                "system": [
                    "/health - Health check"
                ]
            },
            "supported_classes": {
                "parasites": ["PF", "PM", "PO", "PV"],
                "wbc": ["WBC"]
            }
        })

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        try:
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "service": "malaria-detection-api",
                "version": "2.0.0",
                "parallelWorkers": analyzer.num_workers
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
        """
        Main diagnosis endpoint with parallel processing.
        Returns complete result after all images are processed.
        """
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

            logger.info(f"Starting PARALLEL diagnosis for {len(image_paths)} images with {analyzer.num_workers} workers")

            # Validate image files exist
            missing_files = [p for p in image_paths if not os.path.exists(p)]
            if missing_files:
                return jsonify({
                    "status": "ERROR",
                    "error": f"Image files not found: {missing_files[:5]}{'...' if len(missing_files) > 5 else ''}"
                }), 400

            # Run parallel analysis
            result = analyzer.analyze_patient_slides(image_paths)

            if result.get("status") == "ERROR":
                return jsonify(result), 500

            logger.info(f"Diagnosis completed - Status: {result.get('status')}, Images: {len(image_paths)}")

            return jsonify(result)

        except Exception as e:
            logger.error(f"Diagnosis failed: {e}")
            return jsonify({
                "status": "ERROR",
                "error": f"Diagnosis failed: {str(e)}"
            }), 500

    @app.route('/diagnose/stream', methods=['POST'])
    def diagnose_stream():
        """
        Diagnosis endpoint with Server-Sent Events (SSE) for real-time progress.
        Streams progress updates as each image completes.
        """
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

            # Validate image files exist
            missing_files = [p for p in image_paths if not os.path.exists(p)]
            if missing_files:
                return jsonify({
                    "status": "ERROR",
                    "error": f"Image files not found: {missing_files[:5]}"
                }), 400

            logger.info(f"Starting STREAMING diagnosis for {len(image_paths)} images")

            def generate():
                """Generator for SSE stream."""
                progress_queue = queue.Queue()
                final_result = [None]
                error_occurred = [None]

                def progress_callback(completed, total, current_image, result):
                    """Callback for each completed image."""
                    progress_data = {
                        "type": "progress",
                        "completed": completed,
                        "total": total,
                        "percentage": round((completed / total) * 100, 1),
                        "currentImage": current_image,
                        "imageResult": {
                            "success": result.get("success", False),
                            "parasiteCount": result.get("parasiteCount", 0),
                            "wbcCount": result.get("whiteBloodCellsDetected", 0),
                            "timing": result.get("timing", {})
                        } if result.get("success") else {
                            "success": False,
                            "error": result.get("error", "Unknown error")
                        }
                    }
                    progress_queue.put(progress_data)

                def run_analysis():
                    """Run analysis in background thread."""
                    try:
                        result = analyzer.analyze_patient_slides(image_paths, progress_callback)
                        final_result[0] = result
                    except Exception as e:
                        logger.error(f"Analysis error: {e}")
                        error_occurred[0] = str(e)
                    finally:
                        progress_queue.put(None)  # Signal completion

                # Start analysis in background thread
                analysis_thread = threading.Thread(target=run_analysis)
                analysis_thread.start()

                # Stream progress updates
                while True:
                    try:
                        progress = progress_queue.get(timeout=120)  # 2 min timeout per update

                        if progress is None:
                            # Analysis complete
                            break

                        yield f"data: {json.dumps(progress)}\n\n"

                    except queue.Empty:
                        # Send keepalive
                        yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

                # Wait for analysis thread to complete
                analysis_thread.join(timeout=300)  # 5 min max wait

                # Send final result or error
                if error_occurred[0]:
                    yield f"data: {json.dumps({'type': 'error', 'error': error_occurred[0]})}\n\n"
                elif final_result[0]:
                    yield f"data: {json.dumps({'type': 'complete', 'result': final_result[0]})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Analysis timeout'})}\n\n"

            return Response(
                stream_with_context(generate()),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'X-Accel-Buffering': 'no'
                }
            )

        except Exception as e:
            logger.error(f"Streaming diagnosis failed: {e}")
            return jsonify({
                "status": "ERROR",
                "error": f"Streaming diagnosis failed: {str(e)}"
            }), 500

    @app.route('/analyze', methods=['POST'])
    def analyze():
        """Backward compatible analysis endpoint (uses parallel processing)."""
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

            # Run parallel analysis
            result = analyzer.analyze_patient_slides(image_paths)

            if result.get("status") == "ERROR":
                return jsonify(result), 500

            logger.info(f"Analysis completed - Status: {result.get('status')}")

            return jsonify(result)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return jsonify({
                "status": "ERROR",
                "error": f"Analysis failed: {str(e)}"
            }), 500

    @app.route('/model_info', methods=['GET'])
    def model_info():
        """Get model and processing information."""
        try:
            return jsonify({
                "model": "yolov12.onnx",
                "type": "ONNX",
                "version": "2.0.0",
                "runtime": "ONNX Runtime",
                "processing": {
                    "mode": "parallel",
                    "workers": analyzer.num_workers,
                    "streaming": True
                },
                "capabilities": {
                    "detection": True,
                    "segmentation": False,
                    "classification": False,
                    "timing_metrics": True,
                    "parallel_processing": True,
                    "streaming_progress": True
                },
                "supported_classes": {
                    "parasites": ["PF", "PM", "PO", "PV"],
                    "wbc": ["WBC"]
                },
                "confidence_threshold": 0.26,
                "max_images": 50
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
