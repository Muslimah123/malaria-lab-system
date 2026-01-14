#!/usr/bin/env python3
"""
Complete SAHI Ablation Study with Ground Truth Validation
Tests Standard YOLO vs SAHI with comprehensive parameter sweep
Model trained on: 2048×2048 images
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from detection.model import MalariaDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# ABLATION CONFIGURATION - Comprehensive Parameter Sweep
# ============================================================================

ABLATION_CONFIGS = {
    "include_standard_yolo": True,  # Test baseline
    
    # ✅ Comprehensive slice sizes: from small (640) to training size (2048)
    "slice_sizes": [
        (640, 640),     # Small slices - objects appear larger
        (1024, 1024),   # Medium slices  
        (1536, 1536),   # 0.75x training size
        (2048, 2048),   # EXACT training size ⭐
        (2560, 2560),   # 1.25x training size
    ],
    
    # ✅ Overlap ratios: from none to high
    "overlap_ratios": [
        0.0,    # No overlap (fastest)
        0.1,    # 10% overlap
        0.15,   # 15% overlap
        0.2,    # 20% overlap (recommended)
        0.25,   # 25% overlap
        0.3,    # 30% overlap (high coverage)
    ],
    
    # ✅ Confidence thresholds
    "confidence_thresholds": [
        0.20,   # Lower threshold (more detections)
        0.26,   # Default
        0.30,   # Higher threshold (fewer false positives)
    ]
}

# ============================================================================
# GROUND TRUTH LOADING AND METRICS
# ============================================================================

def load_ground_truth(ground_truth_path: str = "ground_truth.json") -> dict:
    """Load ground truth annotations"""
    try:
        if not os.path.exists(ground_truth_path):
            logger.error(f"Ground truth file not found: {ground_truth_path}")
            return None
        
        with open(ground_truth_path, 'r') as f:
            ground_truth = json.load(f)
        
        logger.info(f"✅ Loaded ground truth for {len(ground_truth)} images")
        
        # Log statistics
        total_parasites = sum(len(img['parasites']) for img in ground_truth.values())
        total_wbcs = sum(len(img['wbcs']) for img in ground_truth.values())
        logger.info(f"   Total parasites: {total_parasites}")
        logger.info(f"   Total WBCs: {total_wbcs}")
        
        return ground_truth
    except Exception as e:
        logger.error(f"Error loading ground truth: {e}")
        return None

def calculate_iou(box1, box2):
    """Calculate Intersection over Union between two bounding boxes"""
    x1_min, y1_min, x1_max, y1_max = box1
    x2_min, y2_min, x2_max, y2_max = box2
    
    inter_x_min = max(x1_min, x2_min)
    inter_y_min = max(y1_min, y2_min)
    inter_x_max = min(x1_max, x2_max)
    inter_y_max = min(y1_max, y2_max)
    
    if inter_x_max < inter_x_min or inter_y_max < inter_y_min:
        return 0.0
    
    inter_area = (inter_x_max - inter_x_min) * (inter_y_max - inter_y_min)
    box1_area = (x1_max - x1_min) * (y1_max - y1_min)
    box2_area = (x2_max - x2_min) * (y2_max - y2_min)
    union_area = box1_area + box2_area - inter_area
    
    return inter_area / union_area if union_area > 0 else 0.0

def calculate_metrics(predictions, ground_truth, iou_threshold=0.5):
    """Calculate precision, recall, and F1 score"""
    if not ground_truth:
        return {
            'precision': 0.0, 'recall': 0.0, 'f1': 0.0,
            'tp': 0, 'fp': len(predictions), 'fn': 0
        }
    
    if not predictions:
        return {
            'precision': 0.0, 'recall': 0.0, 'f1': 0.0,
            'tp': 0, 'fp': 0, 'fn': len(ground_truth)
        }
    
    matched_gt = set()
    tp = 0
    
    for pred_box in predictions:
        best_iou = 0
        best_gt_idx = -1
        
        for gt_idx, gt_box in enumerate(ground_truth):
            if gt_idx in matched_gt:
                continue
            
            iou = calculate_iou(pred_box, gt_box)
            if iou > best_iou:
                best_iou = iou
                best_gt_idx = gt_idx
        
        if best_iou >= iou_threshold:
            tp += 1
            matched_gt.add(best_gt_idx)
    
    fp = len(predictions) - tp
    fn = len(ground_truth) - tp
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp': tp,
        'fp': fp,
        'fn': fn
    }

# ============================================================================
# TEST EXECUTION
# ============================================================================

def test_configuration(detector, image_path, config, ground_truth_data):
    """Test a single configuration on one image"""
    image_name = os.path.basename(image_path)
    
    try:
        # Determine if this is standard YOLO or SAHI
        use_sahi = config.get('use_sahi', True)
        
        # Run detection
        start_time = time.time()
        
        if use_sahi:
            result, error = detector.detectAndQuantify(
                image_path,
                confidence_threshold=config['confidence_threshold'],
                use_sahi=True,
                slice_height=config['slice_height'],
                slice_width=config['slice_width'],
                overlap_ratio=config['overlap_ratio']
            )
        else:
            result, error = detector.detectAndQuantify(
                image_path,
                confidence_threshold=config['confidence_threshold'],
                use_sahi=False
            )
        
        inference_time = time.time() - start_time
        
        if error or not result:
            logger.error(f"Detection failed for {image_name}: {error}")
            return None
        
        # Extract predictions
        parasite_predictions = [p['bbox'] for p in result['parasitesDetected']]
        wbc_predictions = [w['bbox'] for w in result['wbcsDetected']]
        
        # Calculate metrics if ground truth available
        metrics = {}
        if ground_truth_data and image_name in ground_truth_data:
            gt = ground_truth_data[image_name]
            
            gt_parasite_bboxes = [p['bbox'] for p in gt.get('parasites', [])]
            parasite_metrics = calculate_metrics(parasite_predictions, gt_parasite_bboxes)
            
            gt_wbc_bboxes = [w['bbox'] for w in gt.get('wbcs', [])]
            wbc_metrics = calculate_metrics(wbc_predictions, gt_wbc_bboxes)
            
            metrics = {
                'parasite_precision': parasite_metrics['precision'],
                'parasite_recall': parasite_metrics['recall'],
                'parasite_f1': parasite_metrics['f1'],
                'parasite_tp': parasite_metrics['tp'],
                'parasite_fp': parasite_metrics['fp'],
                'parasite_fn': parasite_metrics['fn'],
                'wbc_precision': wbc_metrics['precision'],
                'wbc_recall': wbc_metrics['recall'],
                'wbc_f1': wbc_metrics['f1'],
            }
        
        return {
            'image_name': image_name,
            'config': config,
            'parasite_count': result['parasiteCount'],
            'wbc_count': result['whiteBloodCellsDetected'],
            'inference_time': inference_time,
            'metrics': metrics,
        }
        
    except Exception as e:
        logger.error(f"Error testing {image_name}: {e}")
        import traceback
        traceback.print_exc()
        return None

def run_ablation_study(image_paths, ground_truth_path="ground_truth.json"):
    """Run complete ablation study"""
    logger.info("="*80)
    logger.info("COMPLETE SAHI ABLATION STUDY")
    logger.info("="*80)
    logger.info(f"Model training size: 2048×2048")
    logger.info(f"Images to test: {len(image_paths)}")
    
    # Load ground truth
    ground_truth_data = load_ground_truth(ground_truth_path)
    if not ground_truth_data:
        logger.warning("⚠️  No ground truth - will use detection counts as proxy")
    
    # Initialize detector with correct training size
    logger.info(f"\n🔧 Initializing detector with imgsz=2048...")
    detector = MalariaDetector(imgsz=2048)
    
    # Generate configurations
    all_results = []
    config_counter = 0
    
    # Standard YOLO configs
    if ABLATION_CONFIGS['include_standard_yolo']:
        standard_configs = [
            {'method': 'standard_yolo', 'use_sahi': False, 'confidence_threshold': ct}
            for ct in ABLATION_CONFIGS['confidence_thresholds']
        ]
        total_standard = len(standard_configs)
    else:
        standard_configs = []
        total_standard = 0
    
    # SAHI configs
    sahi_configs = []
    for slice_size in ABLATION_CONFIGS['slice_sizes']:
        for overlap in ABLATION_CONFIGS['overlap_ratios']:
            for conf in ABLATION_CONFIGS['confidence_thresholds']:
                sahi_configs.append({
                    'method': 'sahi',
                    'use_sahi': True,
                    'slice_height': slice_size[0],
                    'slice_width': slice_size[1],
                    'overlap_ratio': overlap,
                    'confidence_threshold': conf
                })
    
    total_configs = total_standard + len(sahi_configs)
    logger.info(f"\n📊 Total configurations: {total_configs}")
    logger.info(f"   Standard YOLO: {total_standard}")
    logger.info(f"   SAHI: {len(sahi_configs)}")
    logger.info(f"   Total tests: {total_configs * len(image_paths)}")
    
    # Test Standard YOLO
    if standard_configs:
        logger.info("\n" + "="*80)
        logger.info("BASELINE: STANDARD YOLO")
        logger.info("="*80)
        
        for config in standard_configs:
            config_counter += 1
            logger.info(f"\n[{config_counter}/{total_configs}] Standard YOLO - Conf: {config['confidence_threshold']}")
            
            config_results = []
            for img_path in image_paths:
                result = test_configuration(detector, str(img_path), config, ground_truth_data)
                if result:
                    config_results.append(result)
            
            if config_results:
                all_results.append({
                    'config': config,
                    'results': config_results
                })
    
    # Test SAHI configurations
    logger.info("\n" + "="*80)
    logger.info("SAHI CONFIGURATIONS")
    logger.info("="*80)
    
    for config in sahi_configs:
        config_counter += 1
        slice_info = f"{config['slice_height']}×{config['slice_width']}"
        logger.info(f"\n[{config_counter}/{total_configs}] SAHI - Slice: {slice_info}, Overlap: {config['overlap_ratio']}, Conf: {config['confidence_threshold']}")
        
        config_results = []
        for img_path in image_paths:
            result = test_configuration(detector, str(img_path), config, ground_truth_data)
            if result:
                config_results.append(result)
        
        if config_results:
            all_results.append({
                'config': config,
                'results': config_results
            })
    
    return all_results, ground_truth_data

# ============================================================================
# ANALYSIS AND VISUALIZATION
# ============================================================================

def analyze_results(all_results, ground_truth_data):
    """Analyze and compare all configurations"""
    logger.info("\n" + "="*80)
    logger.info("ANALYZING RESULTS")
    logger.info("="*80)
    
    # Calculate aggregate metrics for each configuration
    analysis = []
    
    for config_result in all_results:
        config = config_result['config']
        results = config_result['results']
        
        # Aggregate metrics
        total_parasites = sum(r['parasite_count'] for r in results)
        total_wbcs = sum(r['wbc_count'] for r in results)
        avg_time = np.mean([r['inference_time'] for r in results])
        
        agg = {
            'method': config.get('method', 'sahi'),
            'slice_size': f"{config.get('slice_height', 0)}×{config.get('slice_width', 0)}" if config.get('use_sahi') else 'N/A',
            'overlap': config.get('overlap_ratio', 0),
            'confidence': config['confidence_threshold'],
            'total_parasites': total_parasites,
            'total_wbcs': total_wbcs,
            'avg_parasites': total_parasites / len(results),
            'avg_wbcs': total_wbcs / len(results),
            'avg_time': avg_time,
        }
        
        # Add ground truth metrics if available
        if ground_truth_data and results[0]['metrics']:
            agg['avg_parasite_precision'] = np.mean([r['metrics']['parasite_precision'] for r in results])
            agg['avg_parasite_recall'] = np.mean([r['metrics']['parasite_recall'] for r in results])
            agg['avg_parasite_f1'] = np.mean([r['metrics']['parasite_f1'] for r in results])
        
        analysis.append(agg)
    
    # Convert to DataFrame
    df = pd.DataFrame(analysis)
    
    # Save detailed results
    output_dir = "ablation_results"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save full results as JSON
    with open(f"{output_dir}/complete_results.json", 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    
    # Save summary as CSV
    df.to_csv(f"{output_dir}/summary.csv", index=False)
    
    logger.info(f"✅ Results saved to {output_dir}/")
    
    return df

def create_visualizations(df, output_dir="ablation_results"):
    """Create comprehensive visualizations"""
    logger.info("\n📊 Creating visualizations...")
    
    # Separate standard from SAHI
    df_standard = df[df['method'] == 'standard_yolo']
    df_sahi = df[df['method'] == 'sahi']
    
    has_metrics = 'avg_parasite_f1' in df.columns and df['avg_parasite_f1'].sum() > 0
    
    # Plot 1: Performance vs Speed
    fig, ax = plt.subplots(figsize=(14, 8))
    
    if not df_standard.empty:
        ax.scatter(df_standard['avg_time'], df_standard['avg_parasites'],
                  s=200, c='red', marker='s', label='Standard YOLO',
                  edgecolors='black', linewidth=2, alpha=0.8)
    
    if not df_sahi.empty:
        if has_metrics:
            scatter = ax.scatter(df_sahi['avg_time'], df_sahi['avg_parasites'],
                               c=df_sahi['avg_parasite_recall'], s=100, cmap='RdYlGn',
                               label='SAHI', alpha=0.6)
            plt.colorbar(scatter, label='Parasite Recall', ax=ax)
        else:
            ax.scatter(df_sahi['avg_time'], df_sahi['avg_parasites'],
                      s=100, c='blue', label='SAHI', alpha=0.6)
    
    ax.set_xlabel('Inference Time (seconds)', fontsize=12)
    ax.set_ylabel('Average Parasites Detected', fontsize=12)
    ax.set_title('Detection Performance vs Speed', fontsize=14, weight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/performance_vs_speed.png", dpi=300)
    plt.close()
    
    # Plot 2: Top configurations
    metric_col = 'avg_parasite_f1' if has_metrics else 'avg_parasites'
    df_sorted = df.nlargest(15, metric_col)
    
    fig, ax = plt.subplots(figsize=(14, 10))
    colors = ['red' if m == 'standard_yolo' else 'green' for m in df_sorted['method']]
    
    labels = []
    for _, row in df_sorted.iterrows():
        if row['method'] == 'standard_yolo':
            labels.append(f"Baseline (C:{row['confidence']:.2f})")
        else:
            labels.append(f"SAHI {row['slice_size']}, O:{row['overlap']:.2f}, C:{row['confidence']:.2f}")
    
    bars = ax.barh(range(len(df_sorted)), df_sorted[metric_col], color=colors, alpha=0.7)
    ax.set_yticks(range(len(df_sorted)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel('F1 Score' if has_metrics else 'Parasites Detected', fontsize=12)
    ax.set_title(f'Top 15 Configurations (Red=Baseline, Green=SAHI)', fontsize=14, weight='bold')
    ax.grid(True, alpha=0.3, axis='x')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/top_configurations.png", dpi=300)
    plt.close()
    
    # Plot 3: Direct comparison table (if we have metrics)
    if has_metrics and not df_standard.empty and not df_sahi.empty:
        best_standard = df_standard.loc[df_standard['avg_parasite_f1'].idxmax()]
        best_sahi = df_sahi.loc[df_sahi['avg_parasite_f1'].idxmax()]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.axis('tight')
        ax.axis('off')
        
        comparison_data = [
            ['Metric', 'Standard YOLO', 'SAHI (Best)', 'Improvement'],
            ['Parasites Detected',
             f"{best_standard['avg_parasites']:.1f}",
             f"{best_sahi['avg_parasites']:.1f}",
             f"{((best_sahi['avg_parasites'] - best_standard['avg_parasites']) / best_standard['avg_parasites'] * 100):+.1f}%"],
            ['Recall',
             f"{best_standard['avg_parasite_recall']:.3f}",
             f"{best_sahi['avg_parasite_recall']:.3f}",
             f"{((best_sahi['avg_parasite_recall'] - best_standard['avg_parasite_recall']) * 100):+.1f}%"],
            ['Precision',
             f"{best_standard['avg_parasite_precision']:.3f}",
             f"{best_sahi['avg_parasite_precision']:.3f}",
             f"{((best_sahi['avg_parasite_precision'] - best_standard['avg_parasite_precision']) * 100):+.1f}%"],
            ['F1 Score',
             f"{best_standard['avg_parasite_f1']:.3f}",
             f"{best_sahi['avg_parasite_f1']:.3f}",
             f"{((best_sahi['avg_parasite_f1'] - best_standard['avg_parasite_f1']) * 100):+.1f}%"],
            ['Inference Time',
             f"{best_standard['avg_time']:.2f}s",
             f"{best_sahi['avg_time']:.2f}s",
             f"{best_sahi['avg_time'] / best_standard['avg_time']:.1f}x slower"],
        ]
        
        table = ax.table(cellText=comparison_data, cellLoc='center', loc='center',
                        colWidths=[0.3, 0.2, 0.2, 0.2])
        table.auto_set_font_size(False)
        table.set_fontsize(11)
        table.scale(1, 3)
        
        for i in range(4):
            table[(0, i)].set_facecolor('#4CAF50')
            table[(0, i)].set_text_props(weight='bold', color='white')
        
        fig.suptitle('Standard YOLO vs SAHI: Head-to-Head Comparison', fontsize=16, weight='bold')
        plt.savefig(f"{output_dir}/direct_comparison.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    logger.info(f"✅ Visualizations saved to {output_dir}/")

def print_final_recommendations(df, ground_truth_data):
    """Print final recommendations based on results"""
    logger.info("\n" + "="*80)
    logger.info("FINAL RECOMMENDATIONS FOR MEDICAL AI")
    logger.info("="*80)
    
    has_metrics = 'avg_parasite_f1' in df.columns and df['avg_parasite_f1'].sum() > 0
    
    df_standard = df[df['method'] == 'standard_yolo']
    df_sahi = df[df['method'] == 'sahi']
    
    if df_standard.empty or df_sahi.empty:
        logger.warning("⚠️  Incomplete results - cannot make recommendation")
        return
    
    # Find best configurations
    if has_metrics:
        best_standard = df_standard.loc[df_standard['avg_parasite_recall'].idxmax()]
        best_sahi = df_sahi.loc[df_sahi['avg_parasite_recall'].idxmax()]
        
        recall_diff = best_sahi['avg_parasite_recall'] - best_standard['avg_parasite_recall']
        f1_diff = best_sahi['avg_parasite_f1'] - best_standard['avg_parasite_f1']
        time_ratio = best_sahi['avg_time'] / best_standard['avg_time']
        
        logger.info(f"\n🔴 BEST STANDARD YOLO:")
        logger.info(f"   Confidence: {best_standard['confidence']}")
        logger.info(f"   Recall: {best_standard['avg_parasite_recall']:.3f}")
        logger.info(f"   Precision: {best_standard['avg_parasite_precision']:.3f}")
        logger.info(f"   F1: {best_standard['avg_parasite_f1']:.3f}")
        logger.info(f"   Time: {best_standard['avg_time']:.2f}s")
        
        logger.info(f"\n🟢 BEST SAHI:")
        logger.info(f"   Slice: {best_sahi['slice_size']}")
        logger.info(f"   Overlap: {best_sahi['overlap']}")
        logger.info(f"   Confidence: {best_sahi['confidence']}")
        logger.info(f"   Recall: {best_sahi['avg_parasite_recall']:.3f}")
        logger.info(f"   Precision: {best_sahi['avg_parasite_precision']:.3f}")
        logger.info(f"   F1: {best_sahi['avg_parasite_f1']:.3f}")
        logger.info(f"   Time: {best_sahi['avg_time']:.2f}s")
        
        logger.info(f"\n📊 IMPROVEMENT:")
        logger.info(f"   Recall: {recall_diff:+.3f} ({recall_diff/best_standard['avg_parasite_recall']*100:+.1f}%)")
        logger.info(f"   F1: {f1_diff:+.3f} ({f1_diff/best_standard['avg_parasite_f1']*100:+.1f}%)")
        logger.info(f"   Speed: {time_ratio:.1f}x slower")
        
        logger.info("\n" + "="*80)
        if recall_diff > 0.05:
            logger.info("✅ STRONG RECOMMENDATION: USE SAHI")
            logger.info(f"   Reason: {recall_diff*100:.1f}% better recall")
            logger.info(f"   Medical Impact: {recall_diff*100:.1f}% fewer missed parasites!")
            logger.info(f"   Trade-off: {time_ratio:.1f}x slower (WORTH IT for patient safety)")
            logger.info(f"\n   Deploy with: slice={best_sahi['slice_size']}, overlap={best_sahi['overlap']}")
        elif recall_diff > 0.02:
            logger.info("⚖️  MODERATE RECOMMENDATION: CONSIDER SAHI")
            logger.info(f"   Reason: {recall_diff*100:.1f}% better recall")
            logger.info(f"   Decision depends on your speed requirements")
        else:
            logger.info("❌ RECOMMENDATION: USE STANDARD YOLO")
            logger.info(f"   Reason: No significant improvement ({recall_diff*100:.1f}%)")
            logger.info(f"   Standard YOLO is faster and achieves similar accuracy")
    else:
        logger.warning("⚠️  No ground truth metrics - recommendations based on detection counts only")
        best_standard = df_standard.loc[df_standard['avg_parasites'].idxmax()]
        best_sahi = df_sahi.loc[df_sahi['avg_parasites'].idxmax()]
        
        logger.info(f"\n⚠️  Without ground truth, cannot make definitive recommendation")
        logger.info(f"   SAHI detects {best_sahi['avg_parasites'] - best_standard['avg_parasites']:+.1f} more parasites per image")
        logger.info(f"   But we don't know if these are true or false positives!")
        logger.info(f"\n🔬 Action: Manually verify some SAHI detections to validate")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Complete SAHI Ablation Study')
    parser.add_argument('--images', default='test/images_subset', help='Images directory (default: test/images_subset)')
    parser.add_argument('--gt', default='ground_truth_subset.json', help='Ground truth file (default: ground_truth_subset.json)')
    
    args = parser.parse_args()
    
    try:
        logger.info("Starting Complete SAHI Ablation Study")
        
        # ✅ UPDATED: Use provided images directory
        test_images_dir = Path(args.images)
        
        if not test_images_dir.exists():
            logger.error(f"Images directory not found: {test_images_dir}")
            return
        
        # Get all images
        test_images = list(test_images_dir.glob("*.jpg")) + list(test_images_dir.glob("*.png"))
        
        if not test_images:
            logger.error(f"No test images found in {test_images_dir}!")
            return
        
        logger.info(f"✅ Found {len(test_images)} test images in {test_images_dir}")
        
        # Run ablation study with specified ground truth
        all_results, ground_truth_data = run_ablation_study(test_images, ground_truth_path=args.gt)
        
        # Analyze results
        df = analyze_results(all_results, ground_truth_data)
        
        # Create visualizations
        create_visualizations(df)
        
        # Print recommendations
        print_final_recommendations(df, ground_truth_data)
        
        logger.info("\n" + "="*80)
        logger.info("ABLATION STUDY COMPLETE!")
        logger.info("="*80)
        logger.info("📁 Check ablation_results/ folder for:")
        logger.info("   - complete_results.json (full data)")
        logger.info("   - summary.csv (spreadsheet)")
        logger.info("   - *.png (visualizations)")
        
    except Exception as e:
        logger.error(f"Ablation study failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()