# DiagnosisApi/app/detection/analysis.py

from .model import MalariaDetector  # PyTorch model
from collections import defaultdict
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable

logger = logging.getLogger(__name__)

class MalariaAnalyzer:
    def __init__(self, num_workers: int = None):
        """
        Initialize the analyzer with parallel processing support.

        Args:
            num_workers: Number of parallel workers. Defaults to 1 for PyTorch.
        """
        # Use PyTorch model (sequential processing - not thread-safe)
        self.detector = MalariaDetector()
        self.model_type = "PyTorch"
        # Define valid parasite types for validation
        self.valid_parasite_types = {'PF', 'PM', 'PO', 'PV'}
        # PyTorch/Ultralytics is NOT thread-safe - use 1 worker
        self.num_workers = 1
        logger.info(f"MalariaAnalyzer initialized with {self.num_workers} worker (PyTorch)")

    def _process_single_image(self, image_path: str, idx: int, total: int) -> Dict:
        """
        Process a single image and return the result.
        Thread-safe method for parallel processing.
        """
        try:
            image_id = image_path.split('/')[-1]
            logger.info(f"Processing image {idx}/{total}: {image_id}")

            result, error = self.detector.detectAndQuantify(image_path)

            if error:
                logger.warning(f"Error processing {image_id}: {error}")
                return {
                    "success": False,
                    "error": error,
                    "image_path": image_path,
                    "idx": idx
                }

            timing = result.get("timing", {})

            detection_data = {
                "success": True,
                "idx": idx,
                "imageId": image_id,
                "originalFilename": image_id,
                "parasitesDetected": result["parasitesDetected"],
                "wbcsDetected": result.get("wbcsDetected", []),
                "whiteBloodCellsDetected": result["whiteBloodCellsDetected"],
                "parasiteCount": result["parasiteCount"],
                "parasiteWbcRatio": result["parasiteWbcRatio"],
                "annotatedImagePath": result.get("annotatedImagePath"),
                "timing": timing,
                "metadata": {
                    "totalDetections": len(result["parasitesDetected"]) + result["whiteBloodCellsDetected"],
                    "detectionRate": 1.0,
                    "modelType": self.model_type
                }
            }

            logger.info(f"Completed image {idx}/{total}: {image_id} - {result['parasiteCount']} parasites, {result['whiteBloodCellsDetected']} WBCs")
            return detection_data

        except Exception as e:
            logger.error(f"Exception processing image {idx}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "image_path": image_path,
                "idx": idx
            }

    def analyze_patient_slides(self, image_paths: List[str], progress_callback: Callable = None) -> Dict:
        """
        Analyze multiple images using parallel processing.

        Args:
            image_paths: List of image file paths
            progress_callback: Optional callback function(completed, total, current_image, result)

        Returns:
            Comprehensive analysis report
        """
        try:
            if not image_paths:
                raise ValueError("No image paths provided for analysis")

            total_images = len(image_paths)
            logger.info(f"Starting PARALLEL analysis for {total_images} images using {self.num_workers} workers")

            # Results storage (thread-safe)
            results_lock = threading.Lock()
            all_results = []
            completed_count = [0]  # Use list for mutable reference in closure

            def on_complete(future, idx, image_path):
                """Callback when a future completes."""
                try:
                    result = future.result()
                    with results_lock:
                        all_results.append(result)
                        completed_count[0] += 1

                    # Call progress callback if provided
                    if progress_callback:
                        progress_callback(
                            completed=completed_count[0],
                            total=total_images,
                            current_image=image_path.split('/')[-1],
                            result=result
                        )
                except Exception as e:
                    logger.error(f"Error in completion callback: {e}")

            # Submit all tasks to thread pool
            with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
                # Submit tasks
                futures = {}
                for idx, image_path in enumerate(image_paths, 1):
                    future = executor.submit(self._process_single_image, image_path, idx, total_images)
                    futures[future] = (idx, image_path)

                # Process results as they complete
                for future in as_completed(futures):
                    idx, image_path = futures[future]
                    on_complete(future, idx, image_path)

            # Sort results by original index to maintain order
            all_results.sort(key=lambda x: x.get('idx', 0))

            # Aggregate results
            return self._aggregate_results(all_results, total_images)

        except Exception as e:
            logger.error(f"Parallel analysis failed: {str(e)}")
            return {
                "status": "ERROR",
                "error": str(e),
                "detections": [],
                "total_images_attempted": len(image_paths) if image_paths else 0
            }

    def _aggregate_results(self, results: List[Dict], total_images: int) -> Dict:
        """
        Aggregate individual image results into a comprehensive report.
        """
        detections = []
        total_parasite_count = 0
        total_wbc_count = 0

        # Timing aggregates
        total_preprocess_ms = 0
        total_inference_ms = 0
        total_postprocess_ms = 0
        total_time_ms = 0

        # Confidence tracking
        all_parasite_confidences = defaultdict(list)
        all_wbc_confidences = []

        for result in results:
            if not result.get("success", False):
                continue

            # Add to detections
            detection_data = {
                "imageId": result["imageId"],
                "originalFilename": result["originalFilename"],
                "parasitesDetected": result["parasitesDetected"],
                "wbcsDetected": result["wbcsDetected"],
                "whiteBloodCellsDetected": result["whiteBloodCellsDetected"],
                "parasiteCount": result["parasiteCount"],
                "parasiteWbcRatio": result["parasiteWbcRatio"],
                "annotatedImagePath": result.get("annotatedImagePath"),
                "timing": result.get("timing", {}),
                "metadata": result.get("metadata", {})
            }
            detections.append(detection_data)

            # Aggregate counts
            total_parasite_count += result["parasiteCount"]
            total_wbc_count += result["whiteBloodCellsDetected"]

            # Aggregate timing
            timing = result.get("timing", {})
            total_preprocess_ms += timing.get("preprocess_ms", 0)
            total_inference_ms += timing.get("inference_ms", 0)
            total_postprocess_ms += timing.get("postprocess_ms", 0)
            total_time_ms += timing.get("total_ms", 0)

            # Track parasite confidences
            for parasite in result["parasitesDetected"]:
                parasite_type = parasite["type"].upper()
                if parasite_type in self.valid_parasite_types:
                    all_parasite_confidences[parasite_type].append(parasite["confidence"])

            # Track WBC confidences
            for wbc in result.get("wbcsDetected", []):
                if wbc["type"].upper() == "WBC":
                    all_wbc_confidences.append(wbc["confidence"])

        # Determine status and most probable parasite
        patient_status = "POSITIVE" if total_parasite_count > 0 else "NEGATIVE"

        most_probable_parasite = None
        if all_parasite_confidences:
            max_conf_species = None
            max_confidence = 0

            for parasite_type, confidences in all_parasite_confidences.items():
                max_type_confidence = max(confidences)
                if max_type_confidence > max_confidence:
                    max_confidence = max_type_confidence
                    max_conf_species = parasite_type

            if max_conf_species:
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

        parasite_wbc_ratio = total_parasite_count / total_wbc_count if total_wbc_count > 0 else 0.0
        num_images = len(detections)

        # Build final report
        analysis_report = {
            "status": patient_status,
            "modelType": self.model_type,
            "mostProbableParasite": most_probable_parasite,
            "parasiteWbcRatio": parasite_wbc_ratio,
            "detections": detections,
            "totalImagesAttempted": total_images,
            "totalParasites": total_parasite_count,
            "totalWbcs": total_wbc_count,
            "timing": {
                "totalPreprocess_ms": round(total_preprocess_ms, 2),
                "totalInference_ms": round(total_inference_ms, 2),
                "totalPostprocess_ms": round(total_postprocess_ms, 2),
                "total_ms": round(total_time_ms, 2),
                "avgPreprocess_ms": round(total_preprocess_ms / num_images, 2) if num_images > 0 else 0,
                "avgInference_ms": round(total_inference_ms / num_images, 2) if num_images > 0 else 0,
                "avgPostprocess_ms": round(total_postprocess_ms / num_images, 2) if num_images > 0 else 0,
                "avg_ms": round(total_time_ms / num_images, 2) if num_images > 0 else 0,
                "parallelWorkers": self.num_workers
            },
            "analysisSummary": {
                "parasiteTypesDetected": list(all_parasite_confidences.keys()),
                "avgWbcConfidence": sum(all_wbc_confidences) / len(all_wbc_confidences) if all_wbc_confidences else 0,
                "totalWbcDetections": len(all_wbc_confidences),
                "imagesProcessed": num_images,
                "processingMode": "parallel"
            }
        }

        logger.info(f"PARALLEL ANALYSIS COMPLETE:")
        logger.info(f"- Status: {patient_status}")
        logger.info(f"- Total Parasites: {total_parasite_count}")
        logger.info(f"- Total WBCs: {total_wbc_count}")
        logger.info(f"- Images processed: {num_images}/{total_images}")
        logger.info(f"- Workers used: {self.num_workers}")
        logger.info(f"- Total time: {total_time_ms:.2f}ms")

        return analysis_report
