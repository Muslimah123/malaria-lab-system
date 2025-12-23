
from ultralytics import YOLO
import logging
import os
from pathlib import Path
import shutil
from typing import Tuple, Dict, Optional, List

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
            
            # ✅ NEW: Define valid parasite types (WBC is NOT a parasite!)
            self.valid_parasite_types = {'PF', 'PM', 'PO', 'PV'}
            self.valid_wbc_types = {'WBC', 'wbc'}  # Handle case variations
            
            logger.info(f"Successfully loaded YOLO model from {model_path}")
            logger.info(f"✅ Shared upload root: {self.shared_upload_root}")
            logger.info(f"✅ Annotated output directory: {self.annotated_output_dir}")
            logger.info(f"Valid parasite types: {self.valid_parasite_types}")
            logger.info(f"Valid WBC types: {self.valid_wbc_types}")
            
        except Exception as e:
            logger.error(f"Failed to load YOLO model: {str(e)}")
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    def detectAndQuantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Detect parasites and WBCs in a single image."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image not found at {image_path}")
            
            logger.info(f"Starting detection for image: {image_path} with confidence threshold: {confidence_threshold}")
            results = self.model.predict(
                source=image_path,
                conf=confidence_threshold,
                imgsz=self.imgsz,
                save=True,
                save_conf=True,
                show_labels=True,
                show_conf=True,
                show_boxes=True,
                visualize=False,
                project=str(self.yolo_runtime_dir),
                name="latest",
                exist_ok=True,
                verbose=False
            )
            
            parasites_detected: List[Dict] = []
            wbcs_detected: List[Dict] = []  # Separate array for WBCs
            wbc_count: int = 0
            annotated_image_path: Optional[str] = None
            
            # Debug: Count all detections before filtering
            total_detections = 0
            filtered_detections = 0

            for result in results:
                annotated_image_path = self._persist_annotated_image(result, image_path)
                boxes = result.boxes.data.tolist()
                class_names = result.names
                logger.info(f"Raw YOLO detections for {image_path}: {len(boxes)} total boxes")
                logger.info(f"Model class names: {class_names}")
                
                for box in boxes:
                    x_min, y_min, x_max, y_max, confidence, class_id = box
                    class_name = class_names[int(class_id)]
                    total_detections += 1
                    
                    logger.info(f"Detection: {class_name} with confidence {confidence:.3f} (threshold: {confidence_threshold})")
                    
                    if confidence < confidence_threshold:
                        logger.info(f"FILTERED OUT: {class_name} confidence {confidence:.3f} below threshold {confidence_threshold}")
                        continue
                    
                    filtered_detections += 1
                    
                    # Create detection data structure
                    detection_data = {
                        "type": class_name,
                        "confidence": confidence,
                        "bbox": [x_min, y_min, x_max, y_max]
                    }
                    
                   
                    class_name_upper = class_name.upper()
                    
                    if class_name.lower() in ['wbc'] or class_name_upper in ['WBC']:
                       
                        wbc_count += 1
                        
                        detection_data["type"] = "WBC"  
                        wbcs_detected.append(detection_data)
                        logger.info(f"COUNTED WBC: Total WBCs now: {wbc_count}")
                        
                    elif class_name_upper in self.valid_parasite_types:
                        # This is an actual parasite
                        # Normalize to uppercase for consistency
                        detection_data["type"] = class_name_upper
                        parasites_detected.append(detection_data)
                        logger.info(f"COUNTED PARASITE: {class_name_upper} (confidence: {confidence:.3f}). Total parasites now: {len(parasites_detected)}")
                        
                    else:
                        # ⚠️ UNKNOWN CLASS TYPE - Log as warning
                        logger.warning(f"UNKNOWN CLASS TYPE DETECTED: '{class_name}' - This may need model retraining")
                        logger.warning(f"Expected parasite types: {self.valid_parasite_types}")
                        logger.warning(f"Expected WBC types: {self.valid_wbc_types}")
                        
                        # For now, skip unknown types to prevent classification errors
                        continue

            parasite_count = len(parasites_detected)
            parasite_wbc_ratio = parasite_count / wbc_count if wbc_count > 0 else 0.0

            # Debug summary
            logger.info(f"DETECTION SUMMARY for {image_path}:")
            logger.info(f"- Raw detections: {total_detections}")
            logger.info(f"- After confidence filtering: {filtered_detections}")
            logger.info(f"- Final parasite count: {parasite_count}")
            logger.info(f"- Final WBC count: {wbc_count}")
            logger.info(f"- Parasite/WBC ratio: {parasite_wbc_ratio:.3f}")
            logger.info(f"✅ Annotated image path: {annotated_image_path}")

            detection_result = {
                "parasitesDetected": parasites_detected,  
                "wbcsDetected": wbcs_detected,  
                "whiteBloodCellsDetected": wbc_count,  
                "parasiteCount": parasite_count,  
                "parasiteWbcRatio": parasite_wbc_ratio,  
                "annotatedImagePath": annotated_image_path
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
        """Copy the YOLO-rendered image into the shared uploads directory and return a relative path."""
        try:
            raw_path = Path(result.save_dir) / Path(result.path).name
            if not raw_path.exists():
                logger.warning(f"No annotated image produced for {original_image_path}")
                return None

            final_name = f"{Path(original_image_path).stem}_annotated{raw_path.suffix}"
            final_path = self.annotated_output_dir / final_name
            shutil.copy2(raw_path, final_path)

            relative_path = Path("annotated") / final_name
            logger.info(f"✅ Annotated image saved to {final_path}")
            logger.info(f"✅ Relative path: {relative_path}")
            return str(relative_path).replace("\\", "/")
        except Exception as exc:
            logger.warning(f"Failed to persist annotated image for {original_image_path}: {exc}")
            return None