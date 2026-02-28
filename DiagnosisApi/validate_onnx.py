#!/usr/bin/env python3
"""Validate ONNX model against ground truth test data."""

import os
import sys
from pathlib import Path

# Add app to path
sys.path.insert(0, '/app')

from app.detection.model_onnx import MalariaDetectorONNX

# Initialize detector
print("Loading ONNX detector...")
detector = MalariaDetectorONNX()
print(f"Detector loaded. Model input size: {detector.imgsz}")

# Test directories
test_images_dir = "/app/test/images"
test_labels_dir = "/app/test/labels"

# Class mapping
class_names = {0: 'PF', 1: 'PM', 2: 'PO', 3: 'PV', 4: 'WBC'}

def parse_yolo_labels(label_path):
    """Parse YOLO format labels."""
    labels = []
    if os.path.exists(label_path):
        with open(label_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 5:
                    class_id = int(parts[0])
                    labels.append({
                        'class_id': class_id,
                        'class_name': class_names.get(class_id, f'Class_{class_id}')
                    })
    return labels

# Get test images
test_images = sorted([f for f in os.listdir(test_images_dir) if f.endswith(('.jpg', '.jpeg', '.png'))])

# Use subset for quick test
sample_size = min(15, len(test_images))
test_images = test_images[:sample_size]

print(f"\nTesting {len(test_images)} images with confidence threshold 0.1...\n")
print("-" * 70)

total_gt_parasites = 0
total_gt_wbc = 0
total_pred_parasites = 0
total_pred_wbc = 0

for i, img_name in enumerate(test_images):
    img_path = os.path.join(test_images_dir, img_name)
    label_name = img_name.rsplit('.', 1)[0] + '.txt'
    label_path = os.path.join(test_labels_dir, label_name)

    # Parse ground truth
    gt_labels = parse_yolo_labels(label_path)
    gt_parasites = len([l for l in gt_labels if l['class_name'] in ['PF', 'PM', 'PO', 'PV']])
    gt_wbc = len([l for l in gt_labels if l['class_name'] == 'WBC'])

    # Run prediction
    result, error = detector.detectAndQuantify(img_path, confidence_threshold=0.1)

    if error:
        print(f"[{i+1}/{sample_size}] {img_name[:45]} - ERROR: {error}")
        continue

    pred_parasites = result['parasiteCount']
    pred_wbc = result['whiteBloodCellsDetected']

    total_gt_parasites += gt_parasites
    total_gt_wbc += gt_wbc
    total_pred_parasites += pred_parasites
    total_pred_wbc += pred_wbc

    # Status indicator
    para_ok = "OK" if pred_parasites >= gt_parasites * 0.5 else "LOW"

    print(f"[{i+1:2}/{sample_size}] {img_name[:40]:40} | GT: {gt_parasites:2}p {gt_wbc:1}w | Pred: {pred_parasites:2}p {pred_wbc:1}w | {para_ok}")

print("-" * 70)
print("\nSUMMARY")
print("=" * 70)
print(f"Ground Truth  - Parasites: {total_gt_parasites:4}, WBCs: {total_gt_wbc:3}")
print(f"Predictions   - Parasites: {total_pred_parasites:4}, WBCs: {total_pred_wbc:3}")
print("-" * 70)

if total_gt_parasites > 0:
    recall = total_pred_parasites / total_gt_parasites * 100
    print(f"Parasite Recall: {recall:.1f}% ({total_pred_parasites}/{total_gt_parasites})")

if total_gt_wbc > 0:
    wbc_recall = total_pred_wbc / total_gt_wbc * 100
    print(f"WBC Recall:      {wbc_recall:.1f}% ({total_pred_wbc}/{total_gt_wbc})")

print("\nNote: Low recall may indicate issues with:")
print("  - Confidence threshold (currently 0.1)")
print("  - Model output format parsing")
print("  - Preprocessing (image size, normalization)")
