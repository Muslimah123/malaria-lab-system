from .model import MalariaDetector
from collections import defaultdict
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class MalariaAnalyzer:
    def __init__(self):
        self.detector = MalariaDetector()

    def analyze_patient_slides(self, image_paths: List[str]) -> Dict:
        """Analyze multiple images and generate a comprehensive report."""
        try:
            if not image_paths:
                raise ValueError("No image paths provided for analysis")

            detections = []
            total_parasite_count = 0
            total_wbc_count = 0
            all_parasite_confidences = defaultdict(list)

            logger.info(f"Starting analysis for {len(image_paths)} images")
            
            for idx, image_path in enumerate(image_paths, 1):
                logger.info(f"Processing image {idx}/{len(image_paths)}: {image_path}")
                result, error = self.detector.detect_and_quantify(image_path)
                
                if error:
                    logger.warning(f"Skipping image {image_path} due to error: {error}")
                    continue

                image_id = image_path.split('/')[-1]
                detection_data = {
                    "image_id": image_id,
                    "parasites_detected": result["parasites_detected"],
                    "white_blood_cells_detected": result["white_blood_cells_detected"],
                    "parasite_count": result["parasite_count"],
                    "parasite_wbc_ratio": result["parasite_wbc_ratio"]
                }
                detections.append(detection_data)
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
            
            analysis_report = {
                "status": patient_status,
                "parasite_name": most_probable_parasite,
                "parasite_wbc_ratio": parasite_wbc_ratio,
                "detections": detections,
                "total_images_processed": len(detections),
                "total_images_attempted": len(image_paths)
            }

            logger.info(f"Analysis completed: Status={patient_status}, Total Parasites={total_parasite_count}, "
                       f"Total WBCs={total_wbc_count}, Ratio={parasite_wbc_ratio}")
            logger.info(f"Analysis summary: {len(detections)}/{len(image_paths)} images successfully processed")
            
            return analysis_report

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {
                "status": "ERROR",
                "error": str(e),
                "detections": [],
                "total_images_processed": 0,
                "total_images_attempted": len(image_paths)
            }