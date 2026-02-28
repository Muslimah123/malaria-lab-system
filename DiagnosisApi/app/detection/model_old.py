
import onnxruntime as ort
import cv2
import numpy as np
import logging
import os
from pathlib import Path
import shutil
from typing import Tuple, Dict, Optional, List

logger = logging.getLogger(__name__)

class MalariaDetector:
    def __init__(self, model_path: str = "app/models/yolov12.onnx", imgsz: int = 2048):
        """Initialize the ONNX Runtime model for malaria detection."""
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found at {model_path}")
            
            # Initialize ONNX Runtime session
            self.session = ort.InferenceSession(model_path, providers=['CUDAExecutionProvider', 'CPUExecutionProvider'])
            self.input_name = self.session.get_inputs()[0].name
            self.output_names = [output.name for output in self.session.get_outputs()]
            self.input_shape = self.session.get_inputs()[0].shape
            
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
            
            logger.info(f"Successfully loaded ONNX model from {model_path}")
            logger.info(f"ONNX Runtime Execution Providers: {ort.get_available_providers()}")
            logger.info(f"✅ Shared upload root: {self.shared_upload_root}")
            logger.info(f"✅ Annotated output directory: {self.annotated_output_dir}")
            logger.info(f"Valid parasite types: {self.valid_parasite_types}")
            logger.info(f"Valid WBC types: {self.valid_wbc_types}")
            
        except Exception as e:
            logger.error(f"Failed to load YOLO model: {str(e)}")
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    def _preprocess_image(self, image_path: str) -> Tuple[np.ndarray, Tuple[int, int, int, int]]:
        """Preprocess image for ONNX model inference."""
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"Failed to read image: {image_path}")
        
        original_height, original_width = image.shape[:2]
        
        # Resize to model input size (typically 640x640 for YOLOv12)
        resized = cv2.resize(image, (640, 640))
        
        # Convert BGR to RGB and normalize
        resized = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB)
        resized = resized.astype(np.float32) / 255.0
        
        # Add batch dimension and convert to NCHW format
        input_data = np.transpose(resized, (2, 0, 1))
        input_data = np.expand_dims(input_data, 0)
        
        return input_data, (original_width, original_height, 640, 640)

    def _postprocess_detections(self, outputs: list, original_size: Tuple[int, int, int, int], confidence_threshold: float = 0.26) -> List[Dict]:
        """Post-process ONNX model outputs to extract detections."""
        detections = []
        original_width, original_height, model_width, model_height = original_size
        
        # ONNX output is typically [1, num_detections, 5+num_classes]
        # Format: [x_center, y_center, width, height, conf, class_scores...]
        predictions = outputs[0]
        
        if len(predictions.shape) == 3:
            predictions = predictions[0]
        
        for pred in predictions:
            # Extract box coordinates and confidence
            x_center, y_center, width, height = pred[:4]
            confidences = pred[4:]
            
            # Get class with max confidence
            class_id = np.argmax(confidences)
            confidence = confidences[class_id]
            
            if confidence < confidence_threshold:
                continue
            
            # Scale coordinates back to original image
            scale_x = original_width / model_width
            scale_y = original_height / model_height
            
            x_min = int((x_center - width / 2) * scale_x)
            y_min = int((y_center - height / 2) * scale_y)
            x_max = int((x_center + width / 2) * scale_x)
            y_max = int((y_center + height / 2) * scale_y)
            
            detections.append({
                'bbox': [x_min, y_min, x_max, y_max],
                'confidence': float(confidence),
                'class_id': int(class_id)
            })
        
        return detections

    def _draw_annotations(self, image_path: str, detections: List[Dict], class_names: Dict[int, str]) -> Optional[str]:
        """Draw bounding boxes on image and save annotated version."""
        try:
            image = cv2.imread(image_path)
            if image is None:
                return None
            
            for det in detections:
                x_min, y_min, x_max, y_max = det['bbox']
                confidence = det['confidence']
                class_id = det['class_id']
                class_name = class_names.get(class_id, f"Class_{class_id}")
                
                # Draw bounding box
                cv2.rectangle(image, (x_min, y_min), (x_max, y_max), (0, 255, 0), 2)
                
                # Draw label
                label = f"{class_name} {confidence:.2f}"
                cv2.putText(image, label, (x_min, y_min - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
            
            # Save annotated image
            final_name = f"{Path(image_path).stem}_annotated.jpg"
            final_path = self.annotated_output_dir / final_name
            cv2.imwrite(str(final_path), image)
            
            relative_path = Path("annotated") / final_name
            logger.info(f"\u2705 Annotated image saved to {final_path}")
            return str(relative_path).replace("\\", "/")
            
        except Exception as exc:
            logger.warning(f"Failed to draw annotations for {image_path}: {exc}")
            return None

    def detectAndQuantify(self, image_path: str, confidence_threshold: float = 0.26) -> Tuple[Optional[Dict], Optional[str]]:
        """Detect parasites and WBCs in a single image using ONNX model."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image not found at {image_path}")
            
            logger.info(f"Starting detection for image: {image_path} with confidence threshold: {confidence_threshold}")
            
            # Preprocess image
            input_data, original_size = self._preprocess_image(image_path)
            
            # Run inference
            outputs = self.session.run(self.output_names, {self.input_name: input_data})
            
            # Post-process detections
            raw_detections = self._postprocess_detections(outputs, original_size, confidence_threshold)
            
            parasites_detected: List[Dict] = []
            wbcs_detected: List[Dict] = []  # Separate array for WBCs
            wbc_count: int = 0
            annotated_image_path: Optional[str] = None
            
            logger.info(f"Raw ONNX detections for {image_path}: {len(raw_detections)} total boxes")
            
            total_detections = len(raw_detections)
            filtered_detections = 0
            
            # Map class IDs to class names (adjust based on your YOLO model's class mapping)
            # YOLOv12 typically has: 0=PF, 1=PM, 2=PO, 3=PV, 4=WBC (adjust if different)
            class_names_map = {
                0: 'PF',
                1: 'PM', 
                2: 'PO',
                3: 'PV',
                4: 'WBC'
            }
            
            for detection in raw_detections:
                class_id = detection['class_id']
                confidence = detection['confidence']
                bbox = detection['bbox']
                
                class_name = class_names_map.get(class_id, f'Class_{class_id}')
                filtered_detections += 1
                
                logger.info(f"Detection: {class_name} with confidence {confidence:.3f}")
                
                # Create detection data structure
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
                    logger.info(f"COUNTED WBC: Total WBCs now: {wbc_count}")
                    
                elif class_name_upper in self.valid_parasite_types:
                    # This is an actual parasite
                    detection_data["type"] = class_name_upper
                    parasites_detected.append(detection_data)
                    logger.info(f"COUNTED PARASITE: {class_name_upper} (confidence: {confidence:.3f}). Total parasites now: {len(parasites_detected)}")
                    
                else:
                    # ⚠️ UNKNOWN CLASS TYPE - Log as warning
                    logger.warning(f"UNKNOWN CLASS TYPE DETECTED: '{class_name}' - This may need model retraining")
                    logger.warning(f"Expected parasite types: {self.valid_parasite_types}")

            # Draw and save annotated image
            annotated_image_path = self._draw_annotations(image_path, raw_detections, class_names_map)
                    
                   
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