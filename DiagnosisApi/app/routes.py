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

    @app.route('/render-reviewed', methods=['POST'])
    def render_reviewed():
        """
        Re-render annotated images using clinician-corrected detections.
        Draws reviewed boxes on the original (un-annotated) image and stamps a watermark.

        Expected body:
        {
          "imagePaths": [{ "imageId": "...", "originalPath": "/app/uploads/..." }],
          "reviewedDetections": [{ "parasiteId": 1, "type": "PF", "confidence": 0.8, "bbox": [x1,y1,x2,y2], "source": "model"|"clinician" }],
          "reviewedWbcs":       [{ "wbcId": 1, "confidence": 0.9, "bbox": [x1,y1,x2,y2], "source": "model"|"clinician" }],
          "reviewerName": "Dr. Smith"
        }
        """
        try:
            import cv2
            import numpy as np
            from datetime import datetime
            from pathlib import Path

            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            image_paths_input = data.get('imagePaths', [])
            reviewed_detections = data.get('reviewedDetections', [])
            reviewed_wbcs       = data.get('reviewedWbcs', [])
            reviewer_name       = data.get('reviewerName', 'Clinician')
            upload_dir          = os.environ.get('UPLOAD_FOLDER', '/app/uploads')

            # Colour scheme (BGR)
            class_colors = {
                'PF':  (50,  50,  255),
                'PM':  (0,  140,  255),
                'PO':  (0,  220,  220),
                'PV':  (255, 100,   0),
                'WBC': (50,  200,  50),
            }
            clinician_tint = (255, 200, 0)   # cyan-gold tint for clinician-added boxes
            font       = cv2.FONT_HERSHEY_SIMPLEX
            font_scale = 0.42
            font_thick = 1
            box_thick  = 2

            def draw_label_outlined(img, text, x1, y1, y2, color):
                (tw, th), baseline = cv2.getTextSize(text, font, font_scale, font_thick)
                lx = x1
                ly = y1 - 4 if y1 > th + baseline + 6 else y2 + th + 4
                cv2.putText(img, text, (lx, ly), font, font_scale, (0,0,0), font_thick + 2, cv2.LINE_AA)
                cv2.putText(img, text, (lx, ly), font, font_scale, color,   font_thick,     cv2.LINE_AA)

            def stamp_watermark(img, reviewer, ts):
                """Bottom-left watermark identifying clinician review."""
                h, w = img.shape[:2]
                text = f"Clinician Verified  |  {reviewer}  |  {ts}"
                (tw, th), _ = cv2.getTextSize(text, font, 0.45, 1)
                # Semi-transparent dark bar
                overlay = img.copy()
                cv2.rectangle(overlay, (0, h - th - 14), (tw + 12, h), (10, 10, 10), -1)
                cv2.addWeighted(overlay, 0.65, img, 0.35, 0, img)
                cv2.putText(img, text, (6, h - 6), font, 0.45, (0, 230, 180), 1, cv2.LINE_AA)

            reviewed_image_results = []
            ts = datetime.now().strftime('%Y-%m-%d  %H:%M')

            for img_entry in image_paths_input:
                image_id    = img_entry.get('imageId', '')
                image_path  = img_entry.get('originalPath', '')

                if not image_path or not os.path.exists(image_path):
                    logger.warning(f"render-reviewed: original image not found: {image_path}")
                    continue

                img = cv2.imread(image_path)
                if img is None:
                    logger.warning(f"render-reviewed: cv2 could not read: {image_path}")
                    continue

                # Filter detections that belong to this image
                # (all detections are sent together; imageId is matched)
                img_parasites = [d for d in reviewed_detections if d.get('imageId', image_id) == image_id]
                img_wbcs      = [d for d in reviewed_wbcs      if d.get('imageId', image_id) == image_id]

                # If no imageId filtering was sent, apply all to every image (single-image case)
                if not any('imageId' in d for d in reviewed_detections):
                    img_parasites = reviewed_detections
                    img_wbcs      = reviewed_wbcs

                # Draw WBCs first
                for wbc in img_wbcs:
                    x1, y1, x2, y2 = [int(v) for v in wbc['bbox']]
                    color = class_colors['WBC']
                    style = cv2.LINE_AA
                    # Dashed-style for clinician-added: draw with slightly different shade
                    if wbc.get('source') == 'clinician':
                        cv2.rectangle(img, (x1-1, y1-1), (x2+1, y2+1), clinician_tint, 1)
                    cv2.rectangle(img, (x1, y1), (x2, y2), color, box_thick)
                    label = f"W{wbc.get('wbcId','?')} {wbc.get('confidence',0):.2f}"
                    if wbc.get('source') == 'clinician':
                        label += ' [C]'
                    draw_label_outlined(img, label, x1, y1, y2, color)

                # Draw parasites
                for det in img_parasites:
                    x1, y1, x2, y2 = [int(v) for v in det['bbox']]
                    ptype  = det.get('type', 'PF').upper()
                    pid    = det.get('parasiteId', '?')
                    conf   = det.get('confidence', 0)
                    color  = class_colors.get(ptype, (180,180,180))
                    if det.get('source') == 'clinician':
                        cv2.rectangle(img, (x1-1, y1-1), (x2+1, y2+1), clinician_tint, 1)
                    cv2.rectangle(img, (x1, y1), (x2, y2), color, box_thick)
                    label = f"#{pid} {ptype} {conf:.2f}"
                    if det.get('source') == 'clinician':
                        label += ' [C]'
                    draw_label_outlined(img, label, x1, y1, y2, color)

                stamp_watermark(img, reviewer_name, ts)

                # Save to uploads/reviewed/
                reviewed_dir  = os.path.join(upload_dir, 'reviewed')
                os.makedirs(reviewed_dir, exist_ok=True)
                filename      = Path(image_path).name
                save_path     = os.path.join(reviewed_dir, filename)
                cv2.imwrite(save_path, img)
                logger.info(f"render-reviewed: saved {save_path}")

                reviewed_image_results.append({
                    'imageId':           image_id,
                    'reviewedImagePath': save_path,
                })

            return jsonify({
                'success': True,
                'reviewedImages': reviewed_image_results,
            })

        except Exception as e:
            logger.error(f"render-reviewed failed: {e}")
            return jsonify({"error": str(e)}), 500

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
