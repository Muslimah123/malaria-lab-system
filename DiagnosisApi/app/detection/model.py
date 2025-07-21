from ultralytics import YOLO
import logging

logger = logging.getLogger(__name__)

# Load model once (global variable)
model = YOLO("app/models/best.pt")
# app\models\best.pt

def detect_and_quantify(image_path, confidence_threshold=0.5):
    """Detect parasites and WBCs in a single image."""
    try:
        results = model(image_path)
        parasites_detected = []
        wbc_count = 0

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

        logger.info(f"Processed image {image_path}: {parasite_count} parasites, {wbc_count} WBCs")
        return {
            "parasites_detected": parasites_detected,
            "white_blood_cells_detected": wbc_count,
            "parasite_count": parasite_count,
            "parasite_wbc_ratio": parasite_wbc_ratio
        }, None

    except Exception as e:
        logger.error(f"Error processing image {image_path}: {str(e)}")
        return None, f"Error processing image: {str(e)}"