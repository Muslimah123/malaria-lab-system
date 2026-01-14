#!/usr/bin/env python3
"""
Create Balanced Test Subset
Selects first 5 images from each parasite type (PF, PM, PO, PV)
Resizes them to 2048×2048 to match training size
Creates corresponding ground truth subset
"""

import os
import json
import shutil
from pathlib import Path
from PIL import Image
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def resize_image_and_bboxes(image_path, output_path, target_size=2048):
    """
    Resize image to target_size and return scale factor for bbox adjustment
    """
    img = Image.open(image_path)
    original_width, original_height = img.size
    
    # Resize image
    img_resized = img.resize((target_size, target_size), Image.LANCZOS)
    img_resized.save(output_path, quality=95)
    
    # Calculate scale factors
    scale_x = target_size / original_width
    scale_y = target_size / original_height
    
    img.close()
    img_resized.close()
    
    return scale_x, scale_y

def scale_bbox(bbox, scale_x, scale_y):
    """Scale bounding box coordinates"""
    x_min, y_min, x_max, y_max = bbox
    return [
        int(x_min * scale_x),
        int(y_min * scale_y),
        int(x_max * scale_x),
        int(y_max * scale_y)
    ]

def create_balanced_subset(
    images_dir="test/images",
    ground_truth_file="ground_truth.json",
    output_images_dir="test/images_subset",
    output_gt_file="ground_truth_subset.json",
    images_per_type=5,
    target_size=2048
):
    """
    Create balanced test subset with images from each parasite type
    """
    logger.info("="*80)
    logger.info("CREATING BALANCED TEST SUBSET")
    logger.info("="*80)
    logger.info(f"Input: {images_dir}")
    logger.info(f"Output: {output_images_dir}")
    logger.info(f"Images per type: {images_per_type}")
    logger.info(f"Target size: {target_size}×{target_size}")
    
    # Load ground truth
    if not os.path.exists(ground_truth_file):
        logger.error(f"Ground truth file not found: {ground_truth_file}")
        return
    
    with open(ground_truth_file, 'r') as f:
        ground_truth = json.load(f)
    
    logger.info(f"Loaded ground truth with {len(ground_truth)} images")
    
    # Create output directory
    os.makedirs(output_images_dir, exist_ok=True)
    
    # Categorize images by parasite type
    images_by_type = {
        'pf': [],
        'pm': [],
        'po': [],
        'pv': []
    }
    
    images_path = Path(images_dir)
    
    for img_name in sorted(ground_truth.keys()):
        img_path = images_path / img_name
        
        if not img_path.exists():
            logger.warning(f"Image not found: {img_name}")
            continue
        
        # Determine parasite type from filename
        img_lower = img_name.lower()
        if img_lower.startswith('pf_'):
            images_by_type['pf'].append(img_name)
        elif img_lower.startswith('pm_'):
            images_by_type['pm'].append(img_name)
        elif img_lower.startswith('po_'):
            images_by_type['po'].append(img_name)
        elif img_lower.startswith('pv_'):
            images_by_type['pv'].append(img_name)
        else:
            logger.warning(f"Cannot determine parasite type for: {img_name}")
    
    # Log counts
    logger.info(f"\n📊 Available images by type:")
    for ptype, images in images_by_type.items():
        logger.info(f"   {ptype.upper()}: {len(images)} images")
    
    # Select images
    selected_images = []
    subset_ground_truth = {}
    
    logger.info(f"\n🎯 Selecting {images_per_type} images from each type...")
    
    for ptype, images in images_by_type.items():
        if not images:
            logger.warning(f"No images found for type: {ptype.upper()}")
            continue
        
        # Select first N images
        selected = images[:images_per_type]
        selected_images.extend(selected)
        
        logger.info(f"\n{ptype.upper()}: Selected {len(selected)} images")
        
        # Process each selected image
        for img_name in selected:
            img_path = images_path / img_name
            output_path = Path(output_images_dir) / img_name
            
            # Check original size
            img = Image.open(img_path)
            orig_width, orig_height = img.size
            img.close()
            
            logger.info(f"  Processing: {img_name} (original: {orig_width}×{orig_height})")
            
            # Resize image
            scale_x, scale_y = resize_image_and_bboxes(
                img_path, 
                output_path, 
                target_size=target_size
            )
            
            # Scale ground truth bboxes
            gt_data = ground_truth[img_name]
            
            # Scale parasite bboxes
            scaled_parasites = []
            for parasite in gt_data['parasites']:
                scaled_bbox = scale_bbox(parasite['bbox'], scale_x, scale_y)
                scaled_parasites.append({
                    'type': parasite['type'],
                    'bbox': scaled_bbox
                })
            
            # Scale WBC bboxes
            scaled_wbcs = []
            for wbc in gt_data['wbcs']:
                scaled_bbox = scale_bbox(wbc['bbox'], scale_x, scale_y)
                scaled_wbcs.append({
                    'type': wbc['type'],
                    'bbox': scaled_bbox
                })
            
            subset_ground_truth[img_name] = {
                'parasites': scaled_parasites,
                'wbcs': scaled_wbcs
            }
            
            logger.info(f"    ✅ Resized to {target_size}×{target_size}, {len(scaled_parasites)} parasites, {len(scaled_wbcs)} WBCs")
    
    # Save subset ground truth
    with open(output_gt_file, 'w') as f:
        json.dump(subset_ground_truth, f, indent=2)
    
    # Statistics
    total_parasites = sum(len(img['parasites']) for img in subset_ground_truth.values())
    total_wbcs = sum(len(img['wbcs']) for img in subset_ground_truth.values())
    
    logger.info("\n" + "="*80)
    logger.info("SUBSET CREATION COMPLETE")
    logger.info("="*80)
    logger.info(f"✅ Selected images: {len(selected_images)}")
    logger.info(f"✅ Output directory: {output_images_dir}")
    logger.info(f"✅ Ground truth file: {output_gt_file}")
    
    logger.info(f"\n📊 Subset statistics:")
    logger.info(f"   Total images: {len(subset_ground_truth)}")
    logger.info(f"   Total parasites: {total_parasites}")
    logger.info(f"   Total WBCs: {total_wbcs}")
    logger.info(f"   Avg parasites/image: {total_parasites/len(subset_ground_truth):.1f}")
    logger.info(f"   Avg WBCs/image: {total_wbcs/len(subset_ground_truth):.1f}")
    
    # Breakdown by type
    logger.info(f"\n📋 Breakdown by parasite type:")
    for ptype in ['pf', 'pm', 'po', 'pv']:
        type_images = [img for img in selected_images if img.lower().startswith(f'{ptype}_')]
        if type_images:
            type_parasites = sum(
                len(subset_ground_truth[img]['parasites'])
                for img in type_images
            )
            logger.info(f"   {ptype.upper()}: {len(type_images)} images, {type_parasites} parasites")
    
    logger.info("\n" + "="*80)
    logger.info("NEXT STEPS")
    logger.info("="*80)
    logger.info("1. Verify the subset looks good")
    logger.info("2. Update ablation script to use:")
    logger.info(f"   - Images: {output_images_dir}")
    logger.info(f"   - Ground truth: {output_gt_file}")
    logger.info("3. Run ablation study (estimated time: 1-2 hours)")
    logger.info(f"   python complete_sahi_ablation_study.py")
    
    return selected_images, subset_ground_truth

def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Create balanced test subset')
    parser.add_argument('--images', default='test/images', help='Input images directory')
    parser.add_argument('--gt', default='ground_truth.json', help='Input ground truth file')
    parser.add_argument('--output-images', default='test/images_subset', help='Output images directory')
    parser.add_argument('--output-gt', default='ground_truth_subset.json', help='Output ground truth file')
    parser.add_argument('--n', type=int, default=5, help='Images per parasite type (default: 5)')
    parser.add_argument('--size', type=int, default=2048, help='Target image size (default: 2048)')
    
    args = parser.parse_args()
    
    create_balanced_subset(
        images_dir=args.images,
        ground_truth_file=args.gt,
        output_images_dir=args.output_images,
        output_gt_file=args.output_gt,
        images_per_type=args.n,
        target_size=args.size
    )

if __name__ == "__main__":
    main()