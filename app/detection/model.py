from ultralytics import YOLO
import logging
import os
from typing import Tuple, Dict, Optional, List

logger = logging.getLogger(__name__)

class MalariaDetector:
    def __init__(self, model_path: str = "app/models/malaria_yolov10.pt"):
        """Initialize the YOLO model for malaria detection."""
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found at {model_path}")
            self.model = YOLO(model_path)
            logger.info(f"Successfully loaded YOLO model from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load YOLO model: {str(e)}")
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    def detect_and_quantify(self, image_path: str, confidence_threshold: float = 0.3) -> Tuple[Optional[Dict], Optional[str]]:
        """Detect parasites and WBCs in a single image."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image not found at {image_path}")
            
            logger.info(f"Starting detection for image: {image_path}")
            results = self.model(image_path)
            parasites_detected: List[Dict] = []
            wbc_count: int = 0

            for result in results:
                boxes = result.boxes.data.tolist()
                class_names = result.names
                for box in boxes:
                    x_min, y_min, x_max, y_max, confidence, class_id = box
                    if confidence < confidence_threshold:
                        continue
                    class_name = class_names[int(class_id)]
                    if class_name == "WBC":
                        wbc_count += 1
                    else:
                        parasites_detected.append({
                            "type": class_name,
                            "confidence": confidence,
                            "bbox": [x_min, y_min, x_max, y_max]
                        })

            parasite_count = len(parasites_detected)
            parasite_wbc_ratio = parasite_count / wbc_count if wbc_count > 0 else 0.0

            detection_result = {
                "parasites_detected": parasites_detected,
                "white_blood_cells_detected": wbc_count,
                "parasite_count": parasite_count,
                "parasite_wbc_ratio": parasite_wbc_ratio
            }

            logger.info(f"Detection completed for {image_path}: {parasite_count} parasites, {wbc_count} WBCs, ratio: {parasite_wbc_ratio}")
            return detection_result, None

        except Exception as e:
            logger.error(f"Error processing image {image_path}: {str(e)}")
            return None, f"Error processing image: {str(e)}"