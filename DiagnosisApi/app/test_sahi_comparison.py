#!/usr/bin/env python3
"""
SAHI vs Standard Inference Comparison Test
Tests malaria detection with and without SAHI to compare performance
"""

import os
import sys
import logging
import json
import time
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image
import numpy as np

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from detection.model import MalariaDetector
from detection.analysis import MalariaAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def visualize_comparison(image_path, standard_detections, sahi_detections, output_path=None):
    """
    Create side-by-side comparison of standard vs SAHI detections
    """
    try:
        # Load the image
        image = Image.open(image_path)
        
        # Create figure with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 10))
        
        # Colors for different classes
        colors = {
            'PF': 'red', 'PM': 'blue', 'PO': 'green', 'PV': 'orange', 'WBC': 'purple'
        }
        
        # Function to draw detections on an axis
        def draw_detections(ax, detections, title):
            ax.imshow(image)
            ax.set_title(title, fontsize=16, weight='bold', pad=20)
            
            if detections is None:
                ax.text(0.5, 0.5, 'DETECTION FAILED', 
                       transform=ax.transAxes, 
                       ha='center', va='center',
                       fontsize=20, color='red', weight='bold')
                return
            
            # Draw parasites
            if 'parasitesDetected' in detections:
                for parasite in detections['parasitesDetected']:
                    bbox = parasite['bbox']
                    parasite_type = parasite['type']
                    confidence = parasite['confidence']
                    
                    rect = patches.Rectangle(
                        (bbox[0], bbox[1]), 
                        bbox[2] - bbox[0], 
                        bbox[3] - bbox[1],
                        linewidth=2, 
                        edgecolor=colors.get(parasite_type, 'red'),
                        facecolor='none'
                    )
                    ax.add_patch(rect)
                    
                    ax.text(
                        bbox[0], bbox[1] - 10, 
                        f'{parasite_type} ({confidence:.2f})',
                        color=colors.get(parasite_type, 'red'),
                        fontsize=9, 
                        weight='bold',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8)
                    )
            
            # Draw WBCs
            if 'wbcsDetected' in detections:
                for wbc in detections['wbcsDetected']:
                    bbox = wbc['bbox']
                    confidence = wbc['confidence']
                    
                    rect = patches.Rectangle(
                        (bbox[0], bbox[1]), 
                        bbox[2] - bbox[0], 
                        bbox[3] - bbox[1],
                        linewidth=2, 
                        edgecolor=colors['WBC'],
                        facecolor='none',
                        linestyle='--'
                    )
                    ax.add_patch(rect)
                    
                    ax.text(
                        bbox[0], bbox[1] - 10, 
                        f'WBC ({confidence:.2f})',
                        color=colors['WBC'],
                        fontsize=9, 
                        weight='bold',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8)
                    )
            
            # Add detection summary
            summary_text = f"""
Parasites: {detections.get('parasiteCount', 0)}
WBCs: {detections.get('whiteBloodCellsDetected', 0)}
Ratio: {detections.get('parasiteWbcRatio', 0):.3f}
            """.strip()
            
            ax.text(
                0.02, 0.98, summary_text,
                transform=ax.transAxes,
                fontsize=11,
                verticalalignment='top',
                bbox=dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.9)
            )
            
            ax.set_xticks([])
            ax.set_yticks([])
        
        # Draw both comparisons
        draw_detections(ax1, standard_detections, 'Standard Inference (No SAHI)')
        draw_detections(ax2, sahi_detections, 'SAHI Inference')
        
        # Overall title
        fig.suptitle(f'Detection Comparison: {os.path.basename(image_path)}', 
                    fontsize=18, weight='bold', y=0.98)
        
        # Add comparison stats at bottom
        if standard_detections and sahi_detections:
            parasite_diff = sahi_detections.get('parasiteCount', 0) - standard_detections.get('parasiteCount', 0)
            wbc_diff = sahi_detections.get('whiteBloodCellsDetected', 0) - standard_detections.get('whiteBloodCellsDetected', 0)
            
            diff_text = f"SAHI Improvement: {parasite_diff:+d} parasites, {wbc_diff:+d} WBCs"
            fig.text(0.5, 0.02, diff_text, ha='center', fontsize=14, 
                    style='italic', weight='bold',
                    color='green' if parasite_diff > 0 else 'red')
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            logger.info(f"Comparison visualization saved to: {output_path}")
        
        plt.close(fig)
        
    except Exception as e:
        logger.error(f"Error creating comparison visualization: {e}")
        raise

def test_single_image_comparison(image_path, detector):
    """
    Test both standard and SAHI inference on a single image
    """
    logger.info(f"\n{'='*80}")
    logger.info(f"Testing: {os.path.basename(image_path)}")
    logger.info('='*80)
    
    results = {
        'image': os.path.basename(image_path),
        'standard': None,
        'sahi': None,
        'timing': {}
    }
    
    # Test 1: Standard Inference
    logger.info("\n--- STANDARD INFERENCE ---")
    start_time = time.time()
    standard_result, standard_error = detector.detectAndQuantify(
        image_path, 
        use_sahi=False
    )
    standard_time = time.time() - start_time
    
    if standard_error:
        logger.error(f"Standard inference failed: {standard_error}")
        results['standard'] = {'error': standard_error}
    else:
        logger.info(f"✅ Standard inference completed in {standard_time:.2f}s")
        logger.info(f"   Parasites: {standard_result['parasiteCount']}")
        logger.info(f"   WBCs: {standard_result['whiteBloodCellsDetected']}")
        results['standard'] = standard_result
        results['timing']['standard'] = standard_time
    
    # Test 2: SAHI Inference
    logger.info("\n--- SAHI INFERENCE ---")
    start_time = time.time()
    sahi_result, sahi_error = detector.detectAndQuantify(
        image_path, 
        use_sahi=True,
        slice_height=640,
        slice_width=640,
        overlap_ratio=0.2
    )
    sahi_time = time.time() - start_time
    
    if sahi_error:
        logger.error(f"SAHI inference failed: {sahi_error}")
        results['sahi'] = {'error': sahi_error}
    else:
        logger.info(f"✅ SAHI inference completed in {sahi_time:.2f}s")
        logger.info(f"   Parasites: {sahi_result['parasiteCount']}")
        logger.info(f"   WBCs: {sahi_result['whiteBloodCellsDetected']}")
        results['sahi'] = sahi_result
        results['timing']['sahi'] = sahi_time
    
    # Comparison
    if standard_result and sahi_result:
        logger.info("\n--- COMPARISON ---")
        parasite_diff = sahi_result['parasiteCount'] - standard_result['parasiteCount']
        wbc_diff = sahi_result['whiteBloodCellsDetected'] - standard_result['whiteBloodCellsDetected']
        time_diff = sahi_time - standard_time
        
        logger.info(f"Parasite detection improvement: {parasite_diff:+d} ({parasite_diff/max(standard_result['parasiteCount'], 1)*100:+.1f}%)")
        logger.info(f"WBC detection improvement: {wbc_diff:+d} ({wbc_diff/max(standard_result['whiteBloodCellsDetected'], 1)*100:+.1f}%)")
        logger.info(f"Time overhead: +{time_diff:.2f}s ({time_diff/standard_time*100:.1f}% slower)")
        
        results['comparison'] = {
            'parasite_diff': parasite_diff,
            'wbc_diff': wbc_diff,
            'time_diff': time_diff,
            'parasite_improvement_percent': parasite_diff/max(standard_result['parasiteCount'], 1)*100,
            'wbc_improvement_percent': wbc_diff/max(standard_result['whiteBloodCellsDetected'], 1)*100,
            'time_overhead_percent': time_diff/standard_time*100
        }
    
    return results

def test_multiple_images_comparison(image_paths):
    """
    Test multiple images and generate comprehensive comparison
    """
    logger.info("\n" + "="*80)
    logger.info("SAHI COMPARISON TEST - Multiple Images")
    logger.info("="*80)
    
    # Initialize detector
    detector = MalariaDetector()
    
    all_results = []
    
    # Test each image
    for i, image_path in enumerate(image_paths, 1):
        logger.info(f"\n📸 Image {i}/{len(image_paths)}")
        
        result = test_single_image_comparison(str(image_path), detector)
        all_results.append(result)
        
        # Create comparison visualization
        if result['standard'] and result['sahi']:
            if not isinstance(result['standard'], dict) or 'error' not in result['standard']:
                if not isinstance(result['sahi'], dict) or 'error' not in result['sahi']:
                    output_path = f"comparison_{os.path.basename(image_path)}"
                    visualize_comparison(
                        str(image_path),
                        result['standard'],
                        result['sahi'],
                        output_path
                    )
    
    # Generate summary statistics
    logger.info("\n" + "="*80)
    logger.info("OVERALL SUMMARY")
    logger.info("="*80)
    
    successful_comparisons = [r for r in all_results if 'comparison' in r]
    
    if successful_comparisons:
        avg_parasite_improvement = np.mean([r['comparison']['parasite_diff'] for r in successful_comparisons])
        avg_wbc_improvement = np.mean([r['comparison']['wbc_diff'] for r in successful_comparisons])
        avg_time_overhead = np.mean([r['comparison']['time_diff'] for r in successful_comparisons])
        
        total_standard_parasites = sum([r['standard']['parasiteCount'] for r in successful_comparisons])
        total_sahi_parasites = sum([r['sahi']['parasiteCount'] for r in successful_comparisons])
        total_standard_wbcs = sum([r['standard']['whiteBloodCellsDetected'] for r in successful_comparisons])
        total_sahi_wbcs = sum([r['sahi']['whiteBloodCellsDetected'] for r in successful_comparisons])
        
        logger.info(f"\n📊 Detection Statistics:")
        logger.info(f"   Total parasites (Standard): {total_standard_parasites}")
        logger.info(f"   Total parasites (SAHI): {total_sahi_parasites}")
        logger.info(f"   Total WBCs (Standard): {total_standard_wbcs}")
        logger.info(f"   Total WBCs (SAHI): {total_sahi_wbcs}")
        
        logger.info(f"\n📈 Average Improvements:")
        logger.info(f"   Parasites per image: {avg_parasite_improvement:+.1f}")
        logger.info(f"   WBCs per image: {avg_wbc_improvement:+.1f}")
        logger.info(f"   Time overhead: +{avg_time_overhead:.2f}s")
        
        summary = {
            'test_date': datetime.now().isoformat(),
            'images_tested': len(image_paths),
            'successful_comparisons': len(successful_comparisons),
            'total_parasites': {
                'standard': total_standard_parasites,
                'sahi': total_sahi_parasites,
                'improvement': total_sahi_parasites - total_standard_parasites
            },
            'total_wbcs': {
                'standard': total_standard_wbcs,
                'sahi': total_sahi_wbcs,
                'improvement': total_sahi_wbcs - total_standard_wbcs
            },
            'averages': {
                'parasite_improvement_per_image': float(avg_parasite_improvement),
                'wbc_improvement_per_image': float(avg_wbc_improvement),
                'time_overhead_seconds': float(avg_time_overhead)
            },
            'detailed_results': all_results
        }
        
        # Save results to JSON
        output_file = "sahi_comparison_results.json"
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        logger.info(f"\n💾 Results saved to: {output_file}")
        
        # Print recommendation
        logger.info("\n" + "="*80)
        logger.info("RECOMMENDATION")
        logger.info("="*80)
        if avg_parasite_improvement > 0:
            logger.info("✅ SAHI shows improvement in parasite detection!")
            logger.info(f"   Average improvement: {avg_parasite_improvement:+.1f} parasites per image")
            logger.info(f"   Time cost: +{avg_time_overhead:.2f}s per image")
            logger.info("   Recommendation: USE SAHI for better accuracy")
        else:
            logger.info("⚠️  SAHI shows no significant improvement")
            logger.info("   Recommendation: Standard inference may be sufficient")
    
    return all_results

def main():
    """
    Main test function
    """
    try:
        logger.info("Starting SAHI Comparison Test")
        
        # Get test images
        uploads_dir = Path("uploads")
        if not uploads_dir.exists():
            logger.error("Uploads directory not found!")
            return
        
        # Use a mix of test images
        test_image_names = [
            "pf_836.jpg", "pf_834.jpg", "pf_825.jpg",
            "pf_811.jpg", "pf_804.jpg"
        ]
        
        test_images = []
        for img_name in test_image_names:
            img_path = uploads_dir / img_name
            if img_path.exists():
                test_images.append(img_path)
                logger.info(f"Found test image: {img_name}")
            else:
                logger.warning(f"Test image not found: {img_name}")
        
        if not test_images:
            logger.error("No test images found!")
            return
        
        logger.info(f"\nTesting with {len(test_images)} images")
        
        # Run comparison test
        results = test_multiple_images_comparison(test_images)
        
        logger.info("\n" + "="*80)
        logger.info("TESTING COMPLETED")
        logger.info("="*80)
        logger.info(f"✅ Processed {len(test_images)} images")
        logger.info("📊 Check comparison_*.png files for visualizations")
        logger.info("💾 Check sahi_comparison_results.json for detailed results")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()