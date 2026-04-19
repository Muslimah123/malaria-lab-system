"""
Blood sample image validator.

Runs lightweight format and integrity checks before YOLO inference.
These checks catch clearly invalid submissions (wrong file type, corrupted
file, zero-byte upload, or unusably small resolution) without attempting
fragile colour-profile heuristics that do not generalise across staining
protocols, microscope lighting conditions, or film types.

Post-inference plausibility checks in MalariaAnalyzer handle the case
where a non-blood image slips through (zero WBCs → warning,
parasites with zero WBCs → SUSPICIOUS status).
"""

import logging
from pathlib import Path
from typing import Tuple

import cv2

logger = logging.getLogger(__name__)

VALID_EXTENSIONS  = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp"}
MIN_DIMENSION     = 64    # pixels — smaller images are unusable for cell detection
MAX_FILE_SIZE_MB  = 200


class BloodSampleValidator:
    """
    Validates that an uploaded file is a decodable image of usable size.

    Returns (is_valid: bool, reason: str).
    Content-level plausibility (is this actually a blood smear?) is
    determined by the YOLO model and post-inference checks.
    """

    def validate(self, image_path: str) -> Tuple[bool, str]:
        """
        Run format and integrity checks on *image_path*.

        Returns
        -------
        (True,  "OK")                       – image passes all checks
        (False, "<human-readable reason>")  – image is rejected
        """
        path = Path(image_path)

        # 1. File extension ------------------------------------------------
        if path.suffix.lower() not in VALID_EXTENSIONS:
            return False, (
                f"Unsupported file format '{path.suffix}'. "
                f"Accepted formats: {', '.join(sorted(VALID_EXTENSIONS))}."
            )

        # 2. File size -----------------------------------------------------
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
        except OSError as exc:
            return False, f"Cannot access file: {exc}"

        if size_mb > MAX_FILE_SIZE_MB:
            return False, (
                f"File is too large ({size_mb:.1f} MB). "
                f"Maximum allowed: {MAX_FILE_SIZE_MB} MB."
            )

        # 3. Decodable image -----------------------------------------------
        img = cv2.imread(str(image_path))
        if img is None:
            return False, (
                "File could not be decoded as an image. "
                "It may be corrupted or encoded in an unsupported format."
            )

        # 4. Minimum resolution --------------------------------------------
        h, w = img.shape[:2]
        if h < MIN_DIMENSION or w < MIN_DIMENSION:
            return False, (
                f"Image resolution ({w}×{h} px) is below the minimum "
                f"of {MIN_DIMENSION}×{MIN_DIMENSION} px required for reliable cell detection."
            )

        return True, "OK"
