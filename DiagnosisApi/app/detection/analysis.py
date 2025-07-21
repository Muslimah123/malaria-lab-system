from .model import detect_and_quantify
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

def analyze_patient_slides(image_paths):
    """Analyze multiple images and generate a report."""
    detections = []
    total_parasite_count = 0
    total_wbc_count = 0
    all_parasite_confidences = defaultdict(list)

    for idx, image_path in enumerate(image_paths):
        result, error = detect_and_quantify(image_path)
        if error:
            continue
        image_id = image_path.split('/')[-1]
        detections.append({
            "image_id": image_id,
            "parasites_detected": result["parasites_detected"],
            "white_blood_cells_detected": result["white_blood_cells_detected"],
            "parasite_count": result["parasite_count"],
            "parasite_wbc_ratio": result["parasite_wbc_ratio"]
        })
        total_parasite_count += result["parasite_count"]
        total_wbc_count += result["white_blood_cells_detected"]
        for parasite in result["parasites_detected"]:
            all_parasite_confidences[parasite["type"]].append(parasite["confidence"])

    patient_status = "POSITIVE" if total_parasite_count > 0 else "NEGATIVE"
    most_probable_parasite = None
    if all_parasite_confidences:
        max_conf_species = max(all_parasite_confidences.items(), key=lambda x: max(x[1], default=0))
        most_probable_parasite = {"type": max_conf_species[0], "confidence": max(max_conf_species[1])}

    parasite_wbc_ratio = total_parasite_count / total_wbc_count if total_wbc_count > 0 else 0.0
    logger.info(f"Analysis complete: Status={patient_status}, Parasites={total_parasite_count}")
    return {
        "status": patient_status,
        "most_probable_parasite": most_probable_parasite,
        "parasite_wbc_ratio": parasite_wbc_ratio,
        "detections": detections
    }