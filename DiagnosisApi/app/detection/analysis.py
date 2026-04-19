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

            # Post-inference plausibility checks.
            # A genuine Giemsa-stained smear should contain multiple WBCs with
            # confident detections; random images may produce a handful of
            # low-confidence WBC false-positives.
            no_detections_warning = None
            wbc_detections = result.get("wbcsDetected", [])

            if result["parasiteCount"] == 0 and result["whiteBloodCellsDetected"] == 0:
                no_detections_warning = (
                    "No WBCs or parasites detected in this image. "
                    "Verify that it is a properly stained blood smear slide."
                )
                logger.warning(f"Zero detections for {image_id}: {no_detections_warning}")

            elif result["parasiteCount"] > 0 and result["whiteBloodCellsDetected"] == 0:
                # Parasites detected but zero WBCs — medically impossible in a
                # real blood smear.  WBCs are always present on a prepared slide;
                # their absence strongly indicates the image is not a blood smear.
                no_detections_warning = (
                    f"{result['parasiteCount']} parasite(s) detected but no WBCs found. "
                    "WBCs must always be present in a valid blood smear. "
                    "This image is very likely not a blood smear slide — "
                    "results should not be used clinically."
                )
                logger.warning(f"Parasites without WBCs for {image_id}: {no_detections_warning}")

            elif result["whiteBloodCellsDetected"] > 0 and result["parasiteCount"] == 0 and wbc_detections:
                avg_wbc_conf = sum(w["confidence"] for w in wbc_detections) / len(wbc_detections)
                few_wbcs = result["whiteBloodCellsDetected"] < 3
                low_confidence = avg_wbc_conf < 0.50

                if few_wbcs and low_confidence:
                    no_detections_warning = (
                        f"Only {result['whiteBloodCellsDetected']} WBC(s) detected with low average "
                        f"confidence ({avg_wbc_conf:.0%}). This image may not be a valid blood smear. "
                        "Please verify the slide preparation and staining."
                    )
                    logger.warning(f"Suspicious WBC detections for {image_id}: {no_detections_warning}")

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
                "warning": no_detections_warning,
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
        invalid_samples = []
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
                if result.get("invalidSample"):
                    invalid_samples.append({
                        "imageId": result.get("imageId", result.get("image_path", "unknown")),
                        "reason": result.get("validationReason", "Unknown validation failure")
                    })
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
                "warning": result.get("warning"),
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
        if len(invalid_samples) == total_images:
            patient_status = "INVALID_SAMPLE"
        elif total_parasite_count > 0 and total_wbc_count == 0:
            # Parasites found but zero WBCs across ALL images — medically
            # impossible on a real slide. Override to SUSPICIOUS rather than
            # POSITIVE to prevent a false clinical alarm.
            patient_status = "SUSPICIOUS"
        elif total_parasite_count > 0:
            patient_status = "POSITIVE"
        else:
            patient_status = "NEGATIVE"

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

        # ── WHO thick blood film parasitaemia (MM-SOP-09, Section 4.1) ────────
        #
        # Formula (thick film only):
        #   Parasite density (parasites/µL) = (parasites / WBCs) × 8,000
        #
        # Thin film uses a different formula (parasitised RBCs × 5,000,000 /
        # total RBCs) which cannot be applied here — this system does not
        # detect RBCs.
        #
        # Zero parasites → NEGATIVE result; quantification is skipped entirely.
        # Calculating 0 / WBCs × 8,000 = 0 p/µL and labelling it "low parasitaemia"
        # would be clinically misleading.
        #
        # For positive cases, WHO counting thresholds are applied retrospectively:
        #   Valid HIGH:  WBCs ≥ 200 AND parasites ≥ 100  → stop at 200 WBCs
        #   Valid LOW:   WBCs ≥ 500 AND parasites ≤  99  → stop at 500 WBCs
        #   P1  — parasites ≥ 100 but WBCs < 200
        #   P2  — parasites ≥ 1, ≤ 99 but WBCs ≥ 200 and < 500
        #   P1+P2 — parasites ≥ 1, ≤ 99 and WBCs < 200 (both thresholds unmet)
        #   P3  — parasites > 0 but WBCs = 0 (cannot calculate)
        # ────────────────────────────────────────────────────────────────────
        WHO_ASSUMED_WBC_PER_UL = 8000

        if total_parasite_count == 0:
            # NEGATIVE — no parasites detected; parasitaemia is not applicable
            parasite_density_per_ul = 0.0
            density_is_preliminary  = False
            density_flag            = None
            density_note            = None

        elif total_wbc_count == 0:
            # P3 — parasites found but no WBCs; denominator is zero
            parasite_density_per_ul = 0.0
            density_is_preliminary  = True
            density_flag            = "P3"
            density_note            = (
                f"Parasitaemia cannot be calculated: no white blood cells (WBCs) were detected "
                f"in this sample. A valid blood smear should contain WBCs alongside parasites. "
                f"Please check the sample quality and consider repeat testing. "
                f"({total_parasite_count} parasite(s) detected, 0 WBCs counted.)"
            )

        elif total_wbc_count >= 200 and total_parasite_count >= 100:
            # WHO valid — high parasitaemia (early exit at 200 WBCs)
            parasite_density_per_ul = round(
                (total_parasite_count / total_wbc_count) * WHO_ASSUMED_WBC_PER_UL, 2
            )
            density_is_preliminary  = False
            density_flag            = None
            density_note            = None

        elif total_wbc_count >= 500:
            # WHO valid — low parasitaemia (full exit at 500 WBCs)
            parasite_density_per_ul = round(
                (total_parasite_count / total_wbc_count) * WHO_ASSUMED_WBC_PER_UL, 2
            )
            density_is_preliminary  = False
            density_flag            = None
            density_note            = None

        elif total_parasite_count >= 100:
            # P1 — ≥100 parasites but batch ended before reaching 200 WBCs
            parasite_density_per_ul = round(
                (total_parasite_count / total_wbc_count) * WHO_ASSUMED_WBC_PER_UL, 2
            )
            density_is_preliminary  = True
            density_flag            = "P1"
            density_note            = (
                f"Preliminary estimate: For high-density infections (100 or more parasites detected), "
                f"WHO guidelines require at least 200 white blood cells (WBCs) to be counted. "
                f"Only {total_wbc_count} WBC(s) were detected in this sample. "
                f"The parasitaemia value of {parasite_density_per_ul:,.0f} p/uL is an estimate and should be interpreted with caution."
            )

        elif total_wbc_count >= 200:
            # P2 — passed the 200 WBC checkpoint, parasites < 100,
            # counting should have continued to 500 WBCs but batch ended early
            parasite_density_per_ul = round(
                (total_parasite_count / total_wbc_count) * WHO_ASSUMED_WBC_PER_UL, 2
            )
            density_is_preliminary  = True
            density_flag            = "P2"
            density_note            = (
                f"Preliminary estimate: For low-density infections (fewer than 100 parasites detected), "
                f"WHO guidelines require at least 500 white blood cells (WBCs) to be counted. "
                f"Only {total_wbc_count} WBCs were counted in this sample. "
                f"The parasitaemia value of {parasite_density_per_ul:,.0f} p/uL is an estimate and should be interpreted with caution."
            )

        else:
            # P1+P2 — WBCs < 200 AND parasites ≤ 99: both thresholds unmet simultaneously
            parasite_density_per_ul = round(
                (total_parasite_count / total_wbc_count) * WHO_ASSUMED_WBC_PER_UL, 2
            )
            density_is_preliminary  = True
            density_flag            = "P1+P2"
            density_note            = (
                f"Preliminary estimate: WHO guidelines require at least 200 WBCs for high-density infections "
                f"(100 or more parasites) or 500 WBCs for low-density infections (fewer than 100 parasites). "
                f"Only {total_wbc_count} WBC(s) were detected in this sample. "
                f"The parasitaemia value of {parasite_density_per_ul:,.0f} p/uL is an estimate and should be interpreted with caution."
            )

        if density_is_preliminary:
            logger.warning(
                "Parasite density flag %s: %s (parasites=%d, WBCs=%d)",
                density_flag, density_note, total_parasite_count, total_wbc_count
            )
        else:
            logger.info(
                "Parasite density WHO-valid: %.2f parasites/µL "
                "(parasites=%d, WBCs=%d)",
                parasite_density_per_ul, total_parasite_count, total_wbc_count
            )

        num_images = len(detections)

        # Build final report
        analysis_report = {
            "status": patient_status,
            "modelType": self.model_type,
            "mostProbableParasite": most_probable_parasite,
            "parasiteWbcRatio": parasite_wbc_ratio,
            "parasiteDensityPerUl": parasite_density_per_ul,
            "parasiteDensityIsPreliminary": density_is_preliminary,
            "parasiteDensityFlag": density_flag,
            "parasiteDensityNote": density_note,
            "detections": detections,
            "invalidSamples": invalid_samples,
            "totalInvalidSamples": len(invalid_samples),
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
