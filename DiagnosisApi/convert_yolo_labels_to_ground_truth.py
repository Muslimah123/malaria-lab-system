#!/usr/bin/env python3
"""
Convert YOLO Format Labels to Ground Truth JSON
Converts YOLO annotation format to the format needed for ablation study
"""

import os
import json
from pathlib import Path
from PIL import Image
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ✅ Class mapping from your data.yaml
# names: ['pf', 'pm', 'po', 'pv', 'wbc']
CLASS_MAPPING = {
    0: 'PF',   # pf → Plasmodium Falciparum
    1: 'PM',   # pm → Plasmodium Malariae
    2: 'PO',   # po → Plasmodium Ovale
    3: 'PV',   # pv → Plasmodium Vivax
    4: 'WBC'   # wbc → White Blood Cell
}

def yolo_to_bbox(x_center, y_center, width, height, img_width, img_height):
    """
    Convert YOLO format (normalized center coords) to bbox format (pixel coords)
    
    Args:
        x_center, y_center, width, height: YOLO normalized coordinates (0-1)
        img_width, img_height: Image dimensions in pixels
    
    Returns:
        [x_min, y_min, x_max, y_max] in pixel coordinates
    """
    # Convert from normalized to pixel coordinates
    x_center_px = x_center * img_width
    y_center_px = y_center * img_height
    width_px = width * img_width
    height_px = height * img_height
    
    # Convert from center format to corner format
    x_min = x_center_px - (width_px / 2)
    y_min = y_center_px - (height_px / 2)
    x_max = x_center_px + (width_px / 2)
    y_max = y_center_px + (height_px / 2)
    
    return [int(x_min), int(y_min), int(x_max), int(y_max)]

def parse_yolo_label_file(label_path, image_path):
    """
    Parse a single YOLO label file and convert to our format
    
    Args:
        label_path: Path to .txt label file
        image_path: Path to corresponding image (to get dimensions)
    
    Returns:
        dict with 'parasites' and 'wbcs' lists
    """
    # Get image dimensions
    try:
        img = Image.open(image_path)
        img_width, img_height = img.size
        img.close()
    except Exception as e:
        logger.error(f"Could not read image {image_path}: {e}")
        return None
    
    parasites = []
    wbcs = []
    
    # Parse label file
    try:
        with open(label_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) != 5:
                logger.warning(f"Invalid line in {label_path}: {line}")
                continue
            
            class_id = int(parts[0])
            x_center = float(parts[1])
            y_center = float(parts[2])
            width = float(parts[3])
            height = float(parts[4])
            
            # Convert to bbox format
            bbox = yolo_to_bbox(x_center, y_center, width, height, img_width, img_height)
            
            # Get class name
            class_name = CLASS_MAPPING.get(class_id, f"UNKNOWN_{class_id}")
            
            # Separate parasites from WBCs
            if class_name == 'WBC':
                wbcs.append({
                    "type": "WBC",
                    "bbox": bbox
                })
            else:
                parasites.append({
                    "type": class_name,
                    "bbox": bbox
                })
        
        return {
            "parasites": parasites,
            "wbcs": wbcs
        }
    
    except Exception as e:
        logger.error(f"Error parsing {label_path}: {e}")
        return None

def convert_yolo_dataset_to_ground_truth(
    images_dir="images",
    labels_dir="labels",
    output_file="ground_truth.json"
):
    """
    Convert entire YOLO dataset to ground truth JSON format
    
    Args:
        images_dir: Directory containing images
        labels_dir: Directory containing YOLO .txt label files
        output_file: Output JSON file path
    """
    images_path = Path(images_dir)
    labels_path = Path(labels_dir)
    
    if not images_path.exists():
        logger.error(f"Images directory not found: {images_dir}")
        return
    
    if not labels_path.exists():
        logger.error(f"Labels directory not found: {labels_dir}")
        return
    
    logger.info("="*80)
    logger.info("CONVERTING YOLO LABELS TO GROUND TRUTH")
    logger.info("="*80)
    logger.info(f"Images directory: {images_dir}")
    logger.info(f"Labels directory: {labels_dir}")
    logger.info(f"Output file: {output_file}")
    
    ground_truth = {}
    processed_count = 0
    skipped_count = 0
    
    # Get all image files
    image_extensions = ['.jpg', '.jpeg', '.png', '.JPG', '.JPEG', '.PNG']
    image_files = []
    for ext in image_extensions:
        image_files.extend(list(images_path.glob(f"*{ext}")))
    
    logger.info(f"\nFound {len(image_files)} images")
    
    # Process each image
    for img_path in sorted(image_files):
        img_name = img_path.name
        
        # Find corresponding label file
        # YOLO label files have same name as image but .txt extension
        label_name = img_path.stem + '.txt'
        
        # Try different possible label file names (handle various naming conventions)
        possible_label_paths = [
            labels_path / label_name,
            labels_path / (img_path.stem + '_jpg.txt'),  # Handle .jpg in filename
            labels_path / (img_path.stem.replace('_jpg', '') + '.txt'),
        ]
        
        # Also try the format shown in your screenshot: pf_3_jpg.rf.xxx.txt
        # Extract the base name and try variations
        for label_file in labels_path.glob(f"{img_path.stem}*.txt"):
            possible_label_paths.append(label_file)
        
        label_path = None
        for path in possible_label_paths:
            if path.exists():
                label_path = path
                break
        
        if not label_path:
            logger.warning(f"No label file found for {img_name}")
            skipped_count += 1
            continue
        
        # Parse the label file
        annotations = parse_yolo_label_file(label_path, img_path)
        
        if annotations is None:
            logger.warning(f"Failed to parse labels for {img_name}")
            skipped_count += 1
            continue
        
        # Add to ground truth
        ground_truth[img_name] = annotations
        processed_count += 1
        
        # Log progress
        if processed_count % 10 == 0:
            logger.info(f"Processed {processed_count} images...")
        
        # Log details for first few images
        if processed_count <= 3:
            logger.info(f"\n✅ {img_name}:")
            logger.info(f"   Parasites: {len(annotations['parasites'])}")
            logger.info(f"   WBCs: {len(annotations['wbcs'])}")
            if annotations['parasites']:
                logger.info(f"   Parasite types: {set(p['type'] for p in annotations['parasites'])}")
    
    # Save to JSON
    logger.info("\n" + "="*80)
    logger.info("SAVING GROUND TRUTH")
    logger.info("="*80)
    
    with open(output_file, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    
    # Generate statistics
    total_parasites = sum(len(img['parasites']) for img in ground_truth.values())
    total_wbcs = sum(len(img['wbcs']) for img in ground_truth.values())
    
    logger.info(f"\n📊 Conversion Statistics:")
    logger.info(f"   Images processed: {processed_count}")
    logger.info(f"   Images skipped: {skipped_count}")
    logger.info(f"   Total parasites: {total_parasites}")
    logger.info(f"   Total WBCs: {total_wbcs}")
    logger.info(f"   Avg parasites per image: {total_parasites/max(processed_count, 1):.1f}")
    logger.info(f"   Avg WBCs per image: {total_wbcs/max(processed_count, 1):.1f}")
    
    # Parasite type distribution
    if total_parasites > 0:
        parasite_types = {}
        for img_data in ground_truth.values():
            for parasite in img_data['parasites']:
                ptype = parasite['type']
                parasite_types[ptype] = parasite_types.get(ptype, 0) + 1
        
        logger.info(f"\n📋 Parasite Type Distribution:")
        for ptype, count in sorted(parasite_types.items()):
            percentage = (count / total_parasites) * 100
            logger.info(f"   {ptype}: {count} ({percentage:.1f}%)")
    
    logger.info(f"\n✅ Ground truth saved to: {output_file}")
    logger.info("\n" + "="*80)
    logger.info("NEXT STEPS")
    logger.info("="*80)
    logger.info("1. Verify the ground_truth.json file looks correct")
    logger.info("2. Copy images to uploads/ directory (if not already there)")
    logger.info("3. Run ablation study with ground truth:")
    logger.info("   python sahi_ablation_study.py")
    logger.info("\n✅ You now have TRUE metrics (precision, recall, F1)!")

def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Convert YOLO labels to ground truth JSON')
    parser.add_argument('--images', default='images', help='Images directory (default: images)')
    parser.add_argument('--labels', default='labels', help='Labels directory (default: labels)')
    parser.add_argument('--output', default='ground_truth.json', help='Output JSON file (default: ground_truth.json)')
    parser.add_argument('--class-map', nargs='+', help='Class mapping: 0=PF 1=PM 2=PO 3=PV 4=WBC')
    
    args = parser.parse_args()
    
    # Update class mapping if provided
    if args.class_map:
        global CLASS_MAPPING
        CLASS_MAPPING = {}
        for mapping in args.class_map:
            class_id, class_name = mapping.split('=')
            CLASS_MAPPING[int(class_id)] = class_name
        logger.info(f"Using custom class mapping: {CLASS_MAPPING}")
    
    convert_yolo_dataset_to_ground_truth(
        images_dir=args.images,
        labels_dir=args.labels,
        output_file=args.output
    )

if __name__ == "__main__":
    main()