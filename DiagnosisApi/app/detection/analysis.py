# DiagnosisApi/app/detection/analysis.py 

from .model import MalariaDetector
from collections import defaultdict
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class MalariaAnalyzer:
    def __init__(self):
        self.detector = MalariaDetector()
        # ✅ NEW: Define valid parasite types for validation
        self.valid_parasite_types = {'PF', 'PM', 'PO', 'PV'}

    def analyze_patient_slides(self, image_paths: List[str]) -> Dict:
        """Analyze multiple images and generate a comprehensive report."""
        try:
            if not image_paths:
                raise ValueError("No image paths provided for analysis")

            detections = []
            total_parasite_count = 0
            total_wbc_count = 0
            
            # ✅ FIXED: Separate tracking for parasites and WBCs
            all_parasite_confidences = defaultdict(list)  # Only actual parasites
            all_wbc_confidences = []  # WBC confidences tracked separately

            logger.info(f"Starting analysis for {len(image_paths)} images")
            
            for idx, image_path in enumerate(image_paths, 1):
                logger.info(f"Processing image {idx}/{len(image_paths)}: {image_path}")
                result, error = self.detector.detectAndQuantify(image_path)
                
                if error:
                    logger.warning(f"Skipping image {image_path} due to error: {error}")
                    continue

                image_id = image_path.split('/')[-1]
                
                # Debug logging: Check what we're getting from detector
                logger.info(f"Raw detection result for {image_id}: parasites={result['parasiteCount']}, WBCs={result['whiteBloodCellsDetected']}")
                
                # ✅ UPDATED: Handle new structure with separated WBC data
                detection_data = {
                    "imageId": image_id,  # ✅ FIXED: Changed from image_id to imageId to match backend schema
                    "originalFilename": image_id,  # ✅ ADDED: Add originalFilename field
                    "parasitesDetected": result["parasitesDetected"],      # ✅ FIXED: Use camelCase from model
                    "wbcsDetected": result.get("wbcsDetected", []),        # ✅ FIXED: Use camelCase from model
                    "whiteBloodCellsDetected": result["whiteBloodCellsDetected"],  # ✅ FIXED: Use camelCase from model
                    "parasiteCount": result["parasiteCount"],              # ✅ FIXED: Use camelCase from model
                    "parasiteWbcRatio": result["parasiteWbcRatio"],        # ✅ FIXED: Use camelCase from model
                    "annotatedImagePath": result.get("annotatedImagePath"),
                    # ✅ ADDED: Basic metadata for Node.js compatibility
                    "metadata": {
                        "totalDetections": len(result["parasitesDetected"]) + result["whiteBloodCellsDetected"],
                        "detectionRate": 1.0  # Basic rate for now
                    }
                }
                detections.append(detection_data)
                
                # Debug: Log before adding to totals
                logger.info(f"Before adding to totals - Current total parasites: {total_parasite_count}, Current total WBCs: {total_wbc_count}")
                
                total_parasite_count += result["parasiteCount"]
                total_wbc_count += result["whiteBloodCellsDetected"]
                
                # Debug: Log after adding to totals
                logger.info(f"After adding to totals - New total parasites: {total_parasite_count}, New total WBCs: {total_wbc_count}")
                
                # ✅ FIXED: Only add actual parasites to parasite confidence tracking
                logger.info(f"DEBUG: Processing {len(result['parasitesDetected'])} parasites from result")
                for parasite in result["parasitesDetected"]:
                    parasite_type = parasite["type"].upper()  # Normalize case
                    logger.info(f"DEBUG: Processing parasite type: '{parasite_type}' (original: '{parasite['type']}')")
                    logger.info(f"DEBUG: Valid parasite types: {self.valid_parasite_types}")
                    
                    if parasite_type in self.valid_parasite_types:
                        all_parasite_confidences[parasite_type].append(parasite["confidence"])
                        logger.info(f"Added PARASITE: {parasite_type} with confidence {parasite['confidence']:.3f}")
                    else:
                        logger.warning(f"Invalid parasite type detected: '{parasite_type}' - skipping from most probable calculation")
                        logger.warning(f"Expected types: {self.valid_parasite_types}")

                # ✅ NEW: Track WBC confidences separately (for potential quality metrics)
                for wbc in result.get("wbcsDetected", []):
                    if wbc["type"].upper() == "WBC":
                        all_wbc_confidences.append(wbc["confidence"])
                        logger.info(f"Added WBC with confidence {wbc['confidence']:.3f}")

            # Debug: Final totals before creating report
            logger.info(f"FINAL TOTALS - Parasites: {total_parasite_count}, WBCs: {total_wbc_count}")
            logger.info(f"Number of processed images: {len(detections)}")
            logger.info(f"DEBUG: all_parasite_confidences keys: {list(all_parasite_confidences.keys())}")
            logger.info(f"DEBUG: all_parasite_confidences content: {dict(all_parasite_confidences)}")
            
            patient_status = "POSITIVE" if total_parasite_count > 0 else "NEGATIVE"
            
            # ✅ CRITICAL FIX: Most probable parasite calculation excludes WBCs
            most_probable_parasite = None
            if all_parasite_confidences:
                # Find the parasite type with the highest individual confidence
                max_conf_species = None
                max_confidence = 0
                
                for parasite_type, confidences in all_parasite_confidences.items():
                    max_type_confidence = max(confidences)
                    if max_type_confidence > max_confidence:
                        max_confidence = max_type_confidence
                        max_conf_species = parasite_type
                
                if max_conf_species:
                    # ✅ NEW: Map parasite type codes to full names
                    parasite_type_names = {
                        'PF': 'Plasmodium Falciparum',
                        'PM': 'Plasmodium Malariae',
                        'PO': 'Plasmodium Ovale',
                        'PV': 'Plasmodium Vivax'
                    }
                    
                    most_probable_parasite = {
                        "type": max_conf_species, 
                        "confidence": max_confidence,
                        "fullName": parasite_type_names.get(max_conf_species, max_conf_species)
                    }
                    logger.info(f"Most probable parasite: {most_probable_parasite}")
                    logger.info(f"Selected from {len(all_parasite_confidences)} parasite types, excluding {len(all_wbc_confidences)} WBC detections")
            else:
                logger.info("No valid parasites found for most probable determination")
                logger.warning(f"WARNING: all_parasite_confidences is empty but total_parasite_count is {total_parasite_count}")
                logger.warning(f"This suggests parasites were detected but not properly tracked in confidence tracking")

            parasite_wbc_ratio = total_parasite_count / total_wbc_count if total_wbc_count > 0 else 0.0
            
            # ✅ ENHANCED: Updated report structure
            analysis_report = {
                "status": patient_status,
                "mostProbableParasite": most_probable_parasite,  # ✅ FIXED: Changed to camelCase
                "parasiteWbcRatio": parasite_wbc_ratio,  # ✅ FIXED: Changed to camelCase
                "detections": detections,
                "totalImagesAttempted": len(image_paths),  # ✅ FIXED: Changed to camelCase
                "totalParasites": total_parasite_count,  # ✅ FIXED: Changed to camelCase
                "totalWbcs": total_wbc_count,  # ✅ FIXED: Changed to camelCase
                # ✅ NEW: Additional metrics for quality assessment
                "analysisSummary": {  # ✅ FIXED: Changed to camelCase
                    "parasiteTypesDetected": list(all_parasite_confidences.keys()),  # ✅ FIXED: Changed to camelCase
                    "avgWbcConfidence": sum(all_wbc_confidences) / len(all_wbc_confidences) if all_wbc_confidences else 0,  # ✅ FIXED: Changed to camelCase
                    "totalWbcDetections": len(all_wbc_confidences),  # ✅ FIXED: Changed to camelCase
                    "imagesProcessed": len(detections)  # ✅ FIXED: Changed to camelCase
                }
            }

            # Final verification logging
            logger.info(f"REPORT VERIFICATION:")
            logger.info(f"- Status: {patient_status}")
            logger.info(f"- Total Parasites in Report: {total_parasite_count}")
            logger.info(f"- Total WBCs in Report: {total_wbc_count}")
            logger.info(f"- Ratio: {parasite_wbc_ratio:.2f}")
            logger.info(f"- Images processed: {len(detections)}/{len(image_paths)}")
            
            # Verify each image's data in the report
            for i, detection in enumerate(detections):
                parasite_count = detection['parasiteCount']
                wbc_count = detection['whiteBloodCellsDetected']
                wbc_bbox_count = len(detection.get('wbcsDetected', []))
                logger.info(f"- Image {i+1} ({detection['imageId']}): {parasite_count} parasites, {wbc_count} WBCs ({wbc_bbox_count} with bboxes)")
            
            if most_probable_parasite:
                logger.info(f"- Most Probable: {most_probable_parasite['type']} ({most_probable_parasite['confidence']:.2f})")
            else:
                logger.info("- Most Probable: None (no parasites detected)")
            
            return analysis_report

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {
                "status": "ERROR",
                "error": str(e),
                "detections": [],
                "total_images_attempted": len(image_paths)
            }