import cv2
import logging
import os
import time
from pathlib import Path
from typing import Tuple, Dict, Optional, List

from ultralytics import YOLO

logger = logging.getLogger(__name__)

# BGR colors per class
_CLASS_COLORS = {
    'PF':  (50,  50,  255),   # red
    'PM':  (0,  140,  255),   # orange
    'PO':  (0,  220,  220),   # yellow
    'PV':  (255, 100,   0),   # blue
    'WBC': (50,  200,  50),   # green
}
_DEFAULT_COLOR = (180, 180, 180)

_FONT       = cv2.FONT_HERSHEY_SIMPLEX
_FONT_SCALE = 0.42
_FONT_THICK = 1
_BOX_THICK  = 2


def _draw_label(img, text: str, x1: int, y1: int, y2: int, color: tuple):
    """Draw label with outlined text (no background), placed above the box (below if near top edge)."""
    (tw, th), baseline = cv2.getTextSize(text, _FONT, _FONT_SCALE, _FONT_THICK)
    if y1 > th + baseline + 6:
        lx, ly = x1, y1 - 4
    else:
        lx, ly = x1, y2 + th + 4
    # Black stroke outline, then colored text on top
    cv2.putText(img, text, (lx, ly), _FONT, _FONT_SCALE, (0, 0, 0),       _FONT_THICK + 2, cv2.LINE_AA)
    cv2.putText(img, text, (lx, ly), _FONT, _FONT_SCALE, color,            _FONT_THICK,     cv2.LINE_AA)


class MalariaDetector:
    def __init__(self, model_path: str = "app/models/V12.pt", imgsz: int = 2048):
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found at {model_path}")

            self.model = YOLO(model_path)
            self.imgsz = imgsz
            self.valid_parasite_types = {'PF', 'PM', 'PO', 'PV'}
            self.valid_wbc_types = {'WBC', 'wbc'}

            logger.info(f"Successfully loaded YOLO model from {model_path}")
            logger.info(f"Model classes: {self.model.names}")
            logger.info(f"Valid parasite types: {self.valid_parasite_types}")

        except Exception as e:
            logger.error(f"Failed to load YOLO model: {str(e)}")
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    # ------------------------------------------------------------------
    # Custom OpenCV annotation
    # ------------------------------------------------------------------

    def _draw_annotations(
        self,
        image_path: str,
        parasites: List[Dict],
        wbcs: List[Dict],
        upload_dir: str,
    ) -> Optional[str]:
        """Render bounding boxes + labels onto the original image using OpenCV.

        Parasites are numbered sequentially (parasiteId 1, 2, 3…).
        WBCs are drawn first so parasite boxes render on top when overlapping.
        Returns the absolute path to the saved annotated image, or None on failure.
        """
        img = cv2.imread(image_path)
        if img is None:
            logger.error(f"cv2 could not read image for annotation: {image_path}")
            return None

        # --- WBCs (draw first / bottom layer) ---
        for wbc in wbcs:
            x1, y1, x2, y2 = [int(v) for v in wbc['bbox']]
            color = _CLASS_COLORS['WBC']
            cv2.rectangle(img, (x1, y1), (x2, y2), color, _BOX_THICK)
            label = f"WBC {wbc.get('confidence', 0):.2f}"
            _draw_label(img, label, x1, y1, y2, color)

        # --- Parasites (numbered, draw on top) ---
        for parasite in parasites:
            x1, y1, x2, y2 = [int(v) for v in parasite['bbox']]
            ptype = parasite.get('type', 'PF').upper()
            pid   = parasite.get('parasiteId', '?')
            conf  = parasite.get('confidence', 0)
            color = _CLASS_COLORS.get(ptype, _DEFAULT_COLOR)

            cv2.rectangle(img, (x1, y1), (x2, y2), color, _BOX_THICK)
            label = f"#{pid} {ptype} {conf:.2f}"
            _draw_label(img, label, x1, y1, y2, color)

        annotated_dir = os.path.join(upload_dir, "annotated")
        os.makedirs(annotated_dir, exist_ok=True)
        save_path = os.path.join(annotated_dir, Path(image_path).name)
        cv2.imwrite(save_path, img)
        logger.info(f"Custom annotation saved: {save_path}")
        return save_path

    # ------------------------------------------------------------------
    # Main detection entry point
    # ------------------------------------------------------------------

    def detectAndQuantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Detect parasites and WBCs in a single image. Returns (result_dict, error_string)."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image not found at {image_path}")

            logger.info(f"Starting PT detection for image: {image_path}")

            start_time      = time.time()
            inference_start = time.time()
            upload_dir      = os.environ.get('UPLOAD_FOLDER', '/app/uploads')

            results = self.model.predict(
                source=image_path,
                imgsz=self.imgsz,
                conf=confidence_threshold,
                save=False,     # we draw annotations ourselves
                verbose=False,
            )
            inference_time = time.time() - inference_start

            parasites_detected: List[Dict] = []
            wbcs_detected: List[Dict]      = []
            wbc_count: int                 = 0
            raw_yolo_detections: List[Dict] = []
            parasite_counter: int          = 1   # sequential ID for each parasite

            if results and len(results) > 0:
                result = results[0]
                boxes  = result.boxes

                logger.info(f"Raw YOLO detections for {image_path}: {len(boxes)} total boxes")

                img_w, img_h = result.orig_shape[1], result.orig_shape[0]

                for box in boxes:
                    class_id   = int(box.cls[0])
                    confidence = float(box.conf[0])
                    bbox_xyxy  = box.xyxy[0].tolist()   # [x1, y1, x2, y2]
                    bbox_xywh  = box.xywh[0].tolist()   # [cx, cy, w, h] pixels

                    x_c, y_c, w, h = bbox_xywh
                    raw_yolo_detections.append({
                        "class_id":  class_id,
                        "confidence": confidence,
                        "xywh":      [x_c, y_c, w, h],
                        "xywh_norm": [x_c / img_w, y_c / img_h, w / img_w, h / img_h],
                        "xyxy":      bbox_xyxy,
                    })

                    class_name       = self.model.names.get(class_id, f'Class_{class_id}')
                    class_name_upper = class_name.upper()
                    logger.info(f"Detection: {class_name} conf={confidence:.3f}")

                    detection_data = {
                        "type":       class_name,
                        "confidence": confidence,
                        "bbox":       [int(b) for b in bbox_xyxy],
                    }

                    if class_name.lower() == 'wbc':
                        wbc_count += 1
                        detection_data["type"] = "WBC"
                        wbcs_detected.append(detection_data)
                        logger.info(f"COUNTED WBC: total={wbc_count}")

                    elif class_name_upper in self.valid_parasite_types:
                        detection_data["type"]       = class_name_upper
                        detection_data["parasiteId"] = parasite_counter
                        parasites_detected.append(detection_data)
                        logger.info(
                            f"COUNTED PARASITE #{parasite_counter}: {class_name_upper} "
                            f"conf={confidence:.3f}  total={len(parasites_detected)}"
                        )
                        parasite_counter += 1

                    else:
                        logger.warning(f"UNKNOWN CLASS: '{class_name}'")

                logger.info(f"DETECTION SUMMARY — {len(boxes)} raw, {len(parasites_detected)} parasites, {wbc_count} WBCs")

            parasite_count     = len(parasites_detected)
            parasite_wbc_ratio = parasite_count / wbc_count if wbc_count > 0 else 0.0

            # Draw and save annotated image
            annotated_path = self._draw_annotations(
                image_path, parasites_detected, wbcs_detected, upload_dir
            )

            total_time = time.time() - start_time

            detection_result = {
                "parasitesDetected":      parasites_detected,
                "wbcsDetected":           wbcs_detected,
                "whiteBloodCellsDetected": wbc_count,
                "parasiteCount":          parasite_count,
                "parasiteWbcRatio":       parasite_wbc_ratio,
                "annotatedImagePath":     annotated_path,
                "modelType":              "PyTorch",
                "timing": {
                    "preprocess_ms":  0,
                    "inference_ms":   round(inference_time * 1000, 2),
                    "postprocess_ms": 0,
                    "total_ms":       round(total_time * 1000, 2),
                },
                "raw_yolo_detections": raw_yolo_detections,
                "image_shape":         [img_h, img_w] if results else [0, 0],
            }

            if parasites_detected:
                best = max(parasites_detected, key=lambda x: x["confidence"])
                logger.info(
                    f"Completed {image_path}: {parasite_count} parasites "
                    f"(best={best['type']} conf={best['confidence']:.2f}), {wbc_count} WBCs"
                )
            else:
                logger.info(f"Completed {image_path}: no parasites, {wbc_count} WBCs")

            return detection_result, None

        except Exception as e:
            logger.error(f"Error processing image {image_path}: {str(e)}")
            return None, f"Error processing image: {str(e)}"

    def detect_and_quantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Alias for detectAndQuantify for backward compatibility."""
        return self.detectAndQuantify(image_path, confidence_threshold)
