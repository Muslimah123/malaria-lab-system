import logging
import os
import time
from pathlib import Path
import shutil
from typing import Tuple, Dict, Optional, List

from ultralytics import YOLO

logger = logging.getLogger(__name__)


class MalariaDetector:
    def __init__(self, model_path: str = "app/models/V12.pt", imgsz: int = 2048):
        """Initialize the YOLO model for malaria detection."""
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found at {model_path}")

            self.model = YOLO(model_path)
            self.imgsz = imgsz

            base_dir = Path(__file__).resolve().parents[2]
            shared_root = Path(os.environ.get("UPLOAD_FOLDER", base_dir / "uploads"))
            self.shared_upload_root = shared_root
            self.shared_upload_root.mkdir(parents=True, exist_ok=True)

            self.annotated_output_dir = self.shared_upload_root / "annotated"
            self.annotated_output_dir.mkdir(parents=True, exist_ok=True)

            self.yolo_runtime_dir = self.shared_upload_root / "_yolo_render_buffer"
            self.yolo_runtime_dir.mkdir(parents=True, exist_ok=True)

            # Define valid parasite types (WBC is NOT a parasite!)
            self.valid_parasite_types = {'PF', 'PM', 'PO', 'PV'}
            self.valid_wbc_types = {'WBC', 'wbc'}

            logger.info(f"Successfully loaded YOLO model from {model_path}")
            logger.info(f"Model classes: {self.model.names}")
            logger.info(f"Shared upload root: {self.shared_upload_root}")
            logger.info(f"Annotated output directory: {self.annotated_output_dir}")
            logger.info(f"Valid parasite types: {self.valid_parasite_types}")

        except Exception as e:
            logger.error(f"Failed to load YOLO model: {str(e)}")
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    def detectAndQuantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Detect parasites and WBCs in a single image using YOLO model with timing."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image not found at {image_path}")

            logger.info(f"Starting PT detection for image: {image_path}")

            # Start timing
            start_time = time.time()

            # Run YOLO inference (includes preprocessing internally)
            inference_start = time.time()
            results = self.model.predict(
                source=image_path,
                imgsz=self.imgsz,
                conf=confidence_threshold,
                save=True,
                project=str(self.yolo_runtime_dir),
                name="predict",
                exist_ok=True
            )
            inference_time = time.time() - inference_start

            parasites_detected: List[Dict] = []
            wbcs_detected: List[Dict] = []
            wbc_count: int = 0
            annotated_image_path: Optional[str] = None

            if results and len(results) > 0:
                result = results[0]
                boxes = result.boxes

                logger.info(f"Raw YOLO detections for {image_path}: {len(boxes)} total boxes")

                total_detections = len(boxes)
                filtered_detections = 0

                for box in boxes:
                    class_id = int(box.cls[0])
                    confidence = float(box.conf[0])
                    bbox = box.xyxy[0].tolist()  # [x1, y1, x2, y2]

                    class_name = self.model.names.get(class_id, f'Class_{class_id}')
                    filtered_detections += 1

                    logger.info(f"Detection: {class_name} with confidence {confidence:.3f}")

                    # Create detection data structure
                    detection_data = {
                        "type": class_name,
                        "confidence": confidence,
                        "bbox": [int(b) for b in bbox]
                    }

                    class_name_upper = class_name.upper()

                    if class_name.lower() == 'wbc':
                        wbc_count += 1
                        detection_data["type"] = "WBC"
                        wbcs_detected.append(detection_data)
                        logger.info(f"COUNTED WBC: Total WBCs now: {wbc_count}")

                    elif class_name_upper in self.valid_parasite_types:
                        detection_data["type"] = class_name_upper
                        parasites_detected.append(detection_data)
                        logger.info(f"COUNTED PARASITE: {class_name_upper} (confidence: {confidence:.3f}). Total parasites now: {len(parasites_detected)}")

                    else:
                        logger.warning(f"UNKNOWN CLASS TYPE DETECTED: '{class_name}'")

                # Save annotated image
                annotated_image_path = self._persist_annotated_image(result, image_path)

                logger.info(f"DETECTION SUMMARY for {image_path}:")
                logger.info(f"- Raw detections: {total_detections}")
                logger.info(f"- After filtering: {filtered_detections}")

            parasite_count = len(parasites_detected)
            parasite_wbc_ratio = parasite_count / wbc_count if wbc_count > 0 else 0.0

            logger.info(f"- Final parasite count: {parasite_count}")
            logger.info(f"- Final WBC count: {wbc_count}")
            logger.info(f"- Parasite/WBC ratio: {parasite_wbc_ratio:.3f}")
            logger.info(f"Annotated image path: {annotated_image_path}")

            # Calculate total time
            total_time = time.time() - start_time
            # Note: Ultralytics YOLO bundles preprocess/postprocess into the predict call
            # We can't separate them, so we report inference_ms as the main metric

            detection_result = {
                "parasitesDetected": parasites_detected,
                "wbcsDetected": wbcs_detected,
                "whiteBloodCellsDetected": wbc_count,
                "parasiteCount": parasite_count,
                "parasiteWbcRatio": parasite_wbc_ratio,
                "annotatedImagePath": annotated_image_path,
                "modelType": "PyTorch",
                "timing": {
                    "preprocess_ms": 0,  # Included in YOLO inference
                    "inference_ms": round(inference_time * 1000, 2),
                    "postprocess_ms": 0,  # Included in YOLO inference
                    "total_ms": round(total_time * 1000, 2)
                }
            }

            if parasites_detected:
                most_probable_parasite = max(parasites_detected, key=lambda x: x["confidence"])
                logger.info(
                    f"Detection completed for {image_path}: {parasite_count} parasites, "
                    f"Most Probable Parasite={most_probable_parasite['type']}, "
                    f"Confidence: {most_probable_parasite['confidence']:.2f}, "
                    f"{wbc_count} WBCs, ratio: {parasite_wbc_ratio:.2f}"
                )
            else:
                logger.info(f"Detection completed for {image_path}: No parasites detected, {wbc_count} WBCs")

            return detection_result, None

        except Exception as e:
            logger.error(f"Error processing image {image_path}: {str(e)}")
            return None, f"Error processing image: {str(e)}"

    def detect_and_quantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Alias for detectAndQuantify for backward compatibility."""
        return self.detectAndQuantify(image_path, confidence_threshold)

    def _persist_annotated_image(self, result, original_image_path: str) -> Optional[str]:
        """Copy the YOLO-rendered image into the shared uploads directory."""
        try:
            raw_path = Path(result.save_dir) / Path(result.path).name
            if not raw_path.exists():
                logger.warning(f"No annotated image produced for {original_image_path}")
                return None

            final_name = f"{Path(original_image_path).stem}_annotated{raw_path.suffix}"
            final_path = self.annotated_output_dir / final_name
            shutil.copy2(raw_path, final_path)

            relative_path = Path("annotated") / final_name
            logger.info(f"Annotated image saved to {final_path}")
            return str(relative_path).replace("\\", "/")

        except Exception as exc:
            logger.warning(f"Failed to persist annotated image for {original_image_path}: {exc}")
            return None
