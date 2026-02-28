import logging
import os
import time
import cv2
import numpy as np
import onnxruntime as ort
from pathlib import Path
from typing import Tuple, Dict, Optional, List

logger = logging.getLogger(__name__)


class MalariaDetectorONNX:
    """ONNX-based malaria detector using ONNX Runtime with cv2 for annotation."""

    def __init__(self, model_path: str = "app/models/yolov12.onnx", imgsz: int = 2048):
        """Initialize the ONNX Runtime model for malaria detection."""
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found at {model_path}")

            # Initialize ONNX Runtime session
            providers = ['CUDAExecutionProvider', 'CPUExecutionProvider']
            self.session = ort.InferenceSession(model_path, providers=providers)
            self.input_name = self.session.get_inputs()[0].name
            self.output_names = [output.name for output in self.session.get_outputs()]

            # Get input shape from model
            input_shape = self.session.get_inputs()[0].shape
            # Handle dynamic dimensions (None or -1)
            if isinstance(input_shape[2], int) and input_shape[2] > 0:
                self.model_input_size = input_shape[2]
            else:
                self.model_input_size = imgsz

            self.imgsz = imgsz
            self.model_type = "ONNX"

            # Class names mapping
            self.class_names = {0: 'PF', 1: 'PM', 2: 'PO', 3: 'PV', 4: 'WBC'}
            self.valid_parasite_types = {'PF', 'PM', 'PO', 'PV'}
            self.valid_wbc_types = {'WBC', 'wbc'}

            # Colors for each class (BGR format)
            self.class_colors = {
                'PF': (0, 0, 255),    # Red
                'PM': (0, 165, 255),  # Orange
                'PO': (0, 255, 255),  # Yellow
                'PV': (255, 0, 255),  # Magenta
                'WBC': (0, 255, 0)    # Green
            }

            # Setup directories
            base_dir = Path(__file__).resolve().parents[2]
            shared_root = Path(os.environ.get("UPLOAD_FOLDER", base_dir / "uploads"))
            self.shared_upload_root = shared_root
            self.shared_upload_root.mkdir(parents=True, exist_ok=True)

            self.annotated_output_dir = self.shared_upload_root / "annotated_onnx"
            self.annotated_output_dir.mkdir(parents=True, exist_ok=True)

            logger.info(f"ONNX model loaded from {model_path}")
            logger.info(f"ONNX Runtime providers: {self.session.get_providers()}")
            logger.info(f"Model input size: {self.model_input_size}")
            logger.info(f"Class names: {self.class_names}")
            logger.info(f"Annotated output directory: {self.annotated_output_dir}")

        except Exception as e:
            logger.error(f"Failed to load ONNX model: {str(e)}")
            raise RuntimeError(f"ONNX model initialization failed: {str(e)}")

    def _preprocess_image(self, image: np.ndarray) -> Tuple[np.ndarray, float, float]:
        """Preprocess image for ONNX model inference."""
        original_height, original_width = image.shape[:2]

        # Calculate scale to fit image into model input size while maintaining aspect ratio
        scale = min(self.imgsz / original_width, self.imgsz / original_height)
        new_width = int(original_width * scale)
        new_height = int(original_height * scale)

        # Resize image
        resized = cv2.resize(image, (new_width, new_height))

        # Create padded image (letterbox)
        padded = np.full((self.imgsz, self.imgsz, 3), 114, dtype=np.uint8)
        pad_x = (self.imgsz - new_width) // 2
        pad_y = (self.imgsz - new_height) // 2
        padded[pad_y:pad_y + new_height, pad_x:pad_x + new_width] = resized

        # Convert BGR to RGB and normalize
        rgb = cv2.cvtColor(padded, cv2.COLOR_BGR2RGB)
        normalized = rgb.astype(np.float32) / 255.0

        # Transpose to NCHW format and add batch dimension
        input_tensor = np.transpose(normalized, (2, 0, 1))
        input_tensor = np.expand_dims(input_tensor, 0)

        return input_tensor, scale, (pad_x, pad_y)

    def _postprocess_detections(
        self,
        outputs: List[np.ndarray],
        original_shape: Tuple[int, int],
        scale: float,
        padding: Tuple[int, int],
        confidence_threshold: float = 0.26,
        iou_threshold: float = 0.7
    ) -> List[Dict]:
        """Post-process ONNX model outputs to extract detections."""
        detections = []
        original_height, original_width = original_shape
        pad_x, pad_y = padding

        # Get detection output (first output)
        output = outputs[0]

        # Handle different output shapes
        # YOLOv8/v12 format: [1, num_classes+4, num_detections] or [1, num_detections, num_classes+4]
        if len(output.shape) == 3:
            output = output[0]  # Remove batch dimension

            # Check if we need to transpose (classes+4 x detections -> detections x classes+4)
            if output.shape[0] < output.shape[1]:
                output = output.T

        # Parse detections
        boxes = []
        scores = []
        class_ids = []

        for detection in output:
            # Format: [x_center, y_center, width, height, class_scores...]
            x_center, y_center, width, height = detection[:4]
            class_scores = detection[4:4+len(self.class_names)]

            # Get best class
            class_id = np.argmax(class_scores)
            confidence = class_scores[class_id]

            if confidence < confidence_threshold:
                continue

            # Convert from center format to corner format
            x1 = x_center - width / 2
            y1 = y_center - height / 2
            x2 = x_center + width / 2
            y2 = y_center + height / 2

            # Remove padding and scale back to original image coordinates
            x1 = (x1 - pad_x) / scale
            y1 = (y1 - pad_y) / scale
            x2 = (x2 - pad_x) / scale
            y2 = (y2 - pad_y) / scale

            # Clip to image bounds
            x1 = max(0, min(x1, original_width))
            y1 = max(0, min(y1, original_height))
            x2 = max(0, min(x2, original_width))
            y2 = max(0, min(y2, original_height))

            boxes.append([x1, y1, x2, y2])
            scores.append(float(confidence))
            class_ids.append(int(class_id))

        # Apply NMS
        if boxes:
            boxes_np = np.array(boxes)
            scores_np = np.array(scores)
            indices = cv2.dnn.NMSBoxes(
                boxes_np.tolist(),
                scores_np.tolist(),
                confidence_threshold,
                iou_threshold
            )

            if len(indices) > 0:
                indices = indices.flatten() if isinstance(indices, np.ndarray) else indices
                for i in indices:
                    detections.append({
                        'bbox': [int(b) for b in boxes[i]],
                        'confidence': scores[i],
                        'class_id': class_ids[i]
                    })

        return detections

    def _draw_annotations(self, image: np.ndarray, detections: List[Dict]) -> np.ndarray:
        """Draw bounding boxes on image."""
        annotated = image.copy()

        for det in detections:
            x1, y1, x2, y2 = det['bbox']
            confidence = det['confidence']
            class_id = det['class_id']
            class_name = self.class_names.get(class_id, f"Class_{class_id}")

            # Get color for this class
            color = self.class_colors.get(class_name, (255, 255, 255))

            # Draw bounding box
            cv2.rectangle(annotated, (x1, y1), (x2, y2), color, 2)

            # Draw label background
            label = f"{class_name} {confidence:.2f}"
            (label_width, label_height), baseline = cv2.getTextSize(
                label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1
            )
            cv2.rectangle(
                annotated,
                (x1, y1 - label_height - baseline - 5),
                (x1 + label_width, y1),
                color,
                -1
            )

            # Draw label text
            cv2.putText(
                annotated,
                label,
                (x1, y1 - baseline - 2),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (255, 255, 255),
                1
            )

        return annotated

    def detectAndQuantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Detect parasites and WBCs in a single image using ONNX model."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image not found at {image_path}")

            logger.info(f"Starting ONNX detection for image: {image_path}")

            # Read image
            image = cv2.imread(image_path)
            if image is None:
                raise ValueError(f"Failed to read image: {image_path}")

            original_shape = image.shape[:2]

            # Start timing
            start_time = time.time()

            # Preprocess
            preprocess_start = time.time()
            input_tensor, scale, padding = self._preprocess_image(image)
            preprocess_time = time.time() - preprocess_start

            # Run inference
            inference_start = time.time()
            outputs = self.session.run(self.output_names, {self.input_name: input_tensor})
            inference_time = time.time() - inference_start

            # Postprocess
            postprocess_start = time.time()
            raw_detections = self._postprocess_detections(
                outputs, original_shape, scale, padding, confidence_threshold
            )
            postprocess_time = time.time() - postprocess_start

            # Process detections
            parasites_detected: List[Dict] = []
            wbcs_detected: List[Dict] = []
            wbc_count: int = 0

            logger.info(f"Raw ONNX detections for {image_path}: {len(raw_detections)} total boxes")

            for det in raw_detections:
                class_id = det['class_id']
                confidence = det['confidence']
                bbox = det['bbox']

                class_name = self.class_names.get(class_id, f'Class_{class_id}')

                detection_data = {
                    "type": class_name,
                    "confidence": confidence,
                    "bbox": bbox
                }

                class_name_upper = class_name.upper()

                if class_name.lower() == 'wbc':
                    wbc_count += 1
                    detection_data["type"] = "WBC"
                    wbcs_detected.append(detection_data)
                    logger.debug(f"COUNTED WBC: Total WBCs now: {wbc_count}")

                elif class_name_upper in self.valid_parasite_types:
                    detection_data["type"] = class_name_upper
                    parasites_detected.append(detection_data)
                    logger.debug(f"COUNTED PARASITE: {class_name_upper}. Total: {len(parasites_detected)}")

                else:
                    logger.warning(f"UNKNOWN CLASS TYPE: '{class_name}'")

            # Draw and save annotated image
            annotated_image = self._draw_annotations(image, raw_detections)
            annotated_image_path = self._save_annotated_image(annotated_image, image_path)

            parasite_count = len(parasites_detected)
            parasite_wbc_ratio = parasite_count / wbc_count if wbc_count > 0 else 0.0

            # Calculate total time
            total_time = time.time() - start_time

            logger.info(f"DETECTION SUMMARY for {image_path}:")
            logger.info(f"- Total detections: {len(raw_detections)}")
            logger.info(f"- Final parasite count: {parasite_count}")
            logger.info(f"- Final WBC count: {wbc_count}")
            logger.info(f"- Parasite/WBC ratio: {parasite_wbc_ratio:.3f}")

            detection_result = {
                "parasitesDetected": parasites_detected,
                "wbcsDetected": wbcs_detected,
                "whiteBloodCellsDetected": wbc_count,
                "parasiteCount": parasite_count,
                "parasiteWbcRatio": parasite_wbc_ratio,
                "annotatedImagePath": annotated_image_path,
                "modelType": "ONNX",
                "timing": {
                    "preprocess_ms": round(preprocess_time * 1000, 2),
                    "inference_ms": round(inference_time * 1000, 2),
                    "postprocess_ms": round(postprocess_time * 1000, 2),
                    "total_ms": round(total_time * 1000, 2)
                }
            }

            if parasites_detected:
                most_probable_parasite = max(parasites_detected, key=lambda x: x["confidence"])
                logger.info(
                    f"ONNX detection completed: {parasite_count} parasites, "
                    f"Most Probable={most_probable_parasite['type']}, "
                    f"Confidence: {most_probable_parasite['confidence']:.2f}, "
                    f"{wbc_count} WBCs, ratio: {parasite_wbc_ratio:.2f}"
                )
            else:
                logger.info(f"ONNX detection completed: No parasites, {wbc_count} WBCs")

            return detection_result, None

        except Exception as e:
            logger.error(f"ONNX error processing {image_path}: {str(e)}")
            return None, f"ONNX error: {str(e)}"

    def detect_and_quantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Alias for backward compatibility."""
        return self.detectAndQuantify(image_path, confidence_threshold)

    def _save_annotated_image(self, image: np.ndarray, original_image_path: str) -> Optional[str]:
        """Save annotated image to output directory."""
        try:
            final_name = f"{Path(original_image_path).stem}_onnx.jpg"
            final_path = self.annotated_output_dir / final_name
            cv2.imwrite(str(final_path), image)

            relative_path = Path("annotated_onnx") / final_name
            logger.info(f"ONNX annotated image saved to {final_path}")
            return str(relative_path).replace("\\", "/")

        except Exception as exc:
            logger.warning(f"Failed to save ONNX annotated image: {exc}")
            return None
