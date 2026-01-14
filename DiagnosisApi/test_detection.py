#!/usr/bin/env python3
"""
Test script for Malaria Detection System
This script tests the detection model, analysis pipeline, and visualizes results
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

def visualize_detections(image_path, detections, output_path=None, show_plot=False):
    """
    Visualize detections with bounding boxes on the image
    """
    try:
        # Load the image
        image = Image.open(image_path)
        fig, ax = plt.subplots(1, figsize=(12, 8))
        ax.imshow(image)
        
        # Colors for different classes
        colors = {
            'PF': 'red',      # Plasmodium Falciparum
            'PM': 'blue',     # Plasmodium Malariae
            'PO': 'green',    # Plasmodium Ovale
            'PV': 'orange',   # Plasmodium Vivax
            'WBC': 'purple'   # White Blood Cells
        }
        
        # Draw bounding boxes for parasites
        if 'parasitesDetected' in detections:
            for parasite in detections['parasitesDetected']:
                bbox = parasite['bbox']
                parasite_type = parasite['type']
                confidence = parasite['confidence']
                
                # Create rectangle patch
                rect = patches.Rectangle(
                    (bbox[0], bbox[1]), 
                    bbox[2] - bbox[0], 
                    bbox[3] - bbox[1],
                    linewidth=2, 
                    edgecolor=colors.get(parasite_type, 'red'),
                    facecolor='none'
                )
                ax.add_patch(rect)
                
                # Add label
                ax.text(
                    bbox[0], bbox[1] - 10, 
                    f'{parasite_type} ({confidence:.2f})',
                    color=colors.get(parasite_type, 'red'),
                    fontsize=10, 
                    weight='bold',
                    bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8)
                )
        
        # Draw bounding boxes for WBCs
        if 'wbcsDetected' in detections:
            for wbc in detections['wbcsDetected']:
                bbox = wbc['bbox']
                confidence = wbc['confidence']
                
                # Create rectangle patch
                rect = patches.Rectangle(
                    (bbox[0], bbox[1]), 
                    bbox[2] - bbox[0], 
                    bbox[3] - bbox[1],
                    linewidth=2, 
                    edgecolor=colors['WBC'],
                    facecolor='none',
                    linestyle='--'  # Dashed line for WBCs
                )
                ax.add_patch(rect)
                
                # Add label
                ax.text(
                    bbox[0], bbox[1] - 10, 
                    f'WBC ({confidence:.2f})',
                    color=colors['WBC'],
                    fontsize=10, 
                    weight='bold',
                    bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8)
                )
        
        # Set title and labels
        ax.set_title(f'Malaria Detection Results - {os.path.basename(image_path)}', fontsize=14, weight='bold')
        ax.set_xlabel('X coordinate (pixels)')
        ax.set_ylabel('Y coordinate (pixels)')
        
        # Remove axis ticks
        ax.set_xticks([])
        ax.set_yticks([])
        
        # Add detection summary
        summary_text = f"""
Detection Summary:
- Parasites: {detections.get('parasiteCount', 0)}
- WBCs: {detections.get('whiteBloodCellsDetected', 0)}
- Ratio: {detections.get('parasiteWbcRatio', 0):.3f}
        """.strip()
        
        ax.text(
            0.02, 0.98, summary_text,
            transform=ax.transAxes,
            fontsize=10,
            verticalalignment='top',
            bbox=dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.9)
        )
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            logger.info(f"Visualization saved to: {output_path}")
        
        # Only show plot if requested (for debugging)
        if show_plot:
            plt.show()
        else:
            plt.close(fig)  # Close the figure to free memory
        
    except Exception as e:
        logger.error(f"Error visualizing detections: {e}")
        raise

def create_combined_visualization(image_paths, detection_results, output_path="combined_detection_results.png"):
    """
    Create a combined visualization showing all images with their detections in a grid layout
    """
    try:
        n_images = len(image_paths)
        
        # Calculate grid dimensions: 3-4 images per row
        if n_images <= 3:
            cols = n_images
            rows = 1
        elif n_images <= 6:
            cols = 3
            rows = 2
        elif n_images <= 9:
            cols = 3
            rows = 3
        else:  # 10+ images
            cols = 4
            rows = (n_images + cols - 1) // cols  # Ceiling division
        
        # Create subplot grid
        fig, axes = plt.subplots(rows, cols, figsize=(6*cols, 6*rows))
        
        # Handle single row/column cases
        if rows == 1:
            if cols == 1:
                axes = [axes]
            else:
                axes = axes.reshape(1, -1)
        elif cols == 1:
            axes = axes.reshape(-1, 1)
        
        # Colors for different classes
        colors = {
            'PF': 'red', 'PM': 'blue', 'PO': 'green', 'PV': 'orange', 'WBC': 'purple'
        }
        
        for i, (image_path, detections) in enumerate(zip(image_paths, detection_results)):
            if detections is None:
                continue
                
            # Calculate grid position
            row = i // cols
            col = i % cols
            
            # Get the subplot
            if rows == 1:
                ax = axes[col] if cols > 1 else axes[0]
            else:
                ax = axes[row, col]
            
            # Load the image
            image = Image.open(image_path)
            ax.imshow(image)
            
            # Draw bounding boxes for parasites
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
                    
                    # Add label
                    ax.text(
                        bbox[0], bbox[1] - 10, 
                        f'{parasite_type} ({confidence:.2f})',
                        color=colors.get(parasite_type, 'red'),
                        fontsize=8, 
                        weight='bold',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8)
                    )
            
            # Draw bounding boxes for WBCs
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
                        fontsize=8, 
                        weight='bold',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8)
                    )
            
            # Set title and remove ticks
            ax.set_title(f'{os.path.basename(image_path)}\nParasites: {detections.get("parasiteCount", 0)}, WBCs: {detections.get("whiteBloodCellsDetected", 0)}', fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
        
        # Hide empty subplots
        for i in range(n_images, rows * cols):
            row = i // cols
            col = i % cols
            if rows == 1:
                if cols > 1:
                    axes[col].set_visible(False)
                else:
                    axes[0].set_visible(False)
            else:
                axes[row, col].set_visible(False)
        
        # Set overall figure title
        fig.suptitle(f'Malaria Detection Results - {n_images} Images', fontsize=16, weight='bold', y=0.98)
        
        # Add grid layout info
        fig.text(0.5, 0.02, f'Grid Layout: {rows} rows × {cols} columns', ha='center', fontsize=12, style='italic')
        
        plt.tight_layout()
        plt.subplots_adjust(top=0.92, bottom=0.08)  # Adjust for title and grid info
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"Grid visualization saved to: {output_path}")
        plt.show()  # Show the combined visualization
        
    except Exception as e:
        logger.error(f"Error creating combined visualization: {e}")
        raise

def test_single_image_detection(image_path):
    """
    Test detection on a single image
    """
    try:
        logger.info(f"Testing single image detection: {image_path}")
        
        # Initialize detector
        detector = MalariaDetector()
        
        # Run detection
        result, error = detector.detectAndQuantify(image_path)
        
        if error:
            logger.error(f"Detection failed: {error}")
            return None
        
        # Print results
        logger.info("Detection Results:")
        logger.info(f"- Parasites detected: {result['parasiteCount']}")
        logger.info(f"- WBCs detected: {result['whiteBloodCellsDetected']}")
        logger.info(f"- Parasite/WBC ratio: {result['parasiteWbcRatio']:.3f}")
        
        if result['parasitesDetected']:
            logger.info("Parasite details:")
            for parasite in result['parasitesDetected']:
                logger.info(f"  - {parasite['type']}: confidence {parasite['confidence']:.3f}, bbox {parasite['bbox']}")
        
        if result['wbcsDetected']:
            logger.info("WBC details:")
            for wbc in result['wbcsDetected']:
                logger.info(f"  - WBC: confidence {wbc['confidence']:.3f}, bbox {wbc['bbox']}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error testing single image: {e}")
        return None

def test_analysis_pipeline(image_paths):
    """
    Test the complete analysis pipeline
    """
    try:
        logger.info(f"Testing analysis pipeline with {len(image_paths)} images")
        
        # Initialize analyzer
        analyzer = MalariaAnalyzer()
        
        # Run analysis
        result = analyzer.analyze_patient_slides(image_paths)
        
        # Print results
        logger.info("Analysis Pipeline Results:")
        logger.info(f"- Status: {result['status']}")
        logger.info(f"- Total parasites: {result['totalParasites']}")
        logger.info(f"- Total WBCs: {result['totalWbcs']}")
        logger.info(f"- Images processed: {result['totalImagesAttempted']}")
        
        if result.get('mostProbableParasite'):
            parasite = result['mostProbableParasite']
            logger.info(f"- Most probable parasite: {parasite['type']} (confidence: {parasite['confidence']:.3f})")
        
        # Print detection details for each image
        for i, detection in enumerate(result['detections']):
            logger.info(f"\nImage {i+1} ({detection['imageId']}):")
            logger.info(f"  - Parasites: {detection['parasiteCount']}")
            logger.info(f"  - WBCs: {detection['whiteBloodCellsDetected']}")
            logger.info(f"  - Ratio: {detection['parasiteWbcRatio']:.3f}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error testing analysis pipeline: {e}")
        return None

def main():
    """
    Main test function
    """
    try:
        logger.info("Starting Malaria Detection System Test - PO Images")
        
        # Test image paths - specifically use PO images
        uploads_dir = Path("uploads")
        if not uploads_dir.exists():
            logger.error("Uploads directory not found!")
            return
        
        # Get specific PO test images
        test_images = ["po_837.jpg", "po_847.jpg", "po_849.jpg", "po_859.jpg", "po_879.jpg", "po_882.jpg", "po_883.jpg", "po_885.jpg", "po_886.jpg", "po_887.jpg"]  # 10 PO images
        sample_images = []
        
        for img_name in test_images:
            img_path = uploads_dir / img_name
            if img_path.exists():
                sample_images.append(img_path)
                logger.info(f"Found test image: {img_name}")
            else:
                logger.warning(f"Test image not found: {img_name}")
        
        if not sample_images:
            logger.error("No test images found!")
            return
        
        logger.info(f"Testing with {len(sample_images)} PO images")
        
        # Test 1: Individual image detection (without individual visualization)
        logger.info("\n" + "="*50)
        logger.info("TEST 1: Individual Image Detection (10 PO Images)")
        logger.info("="*50)
        
        individual_results = []
        start_time = time.time()
        
        for i, test_image in enumerate(sample_images):
            logger.info(f"\n--- Processing {test_image.name} ---")
            
            # Run detection on individual image
            detection_result = test_single_image_detection(str(test_image))
            
            if detection_result:
                # Store result for analysis (no individual visualization)
                individual_results.append(detection_result)
                logger.info(f"✅ {test_image.name} processed successfully")
            else:
                logger.error(f"❌ Failed to process {test_image.name}")
                individual_results.append(None)
        
        individual_time = time.time() - start_time
        logger.info(f"Individual detection completed in {individual_time:.2f} seconds")
        
        # Test 2: Analysis pipeline with both images
        logger.info("\n" + "="*50)
        logger.info("TEST 2: Analysis Pipeline (10 PO Images)")
        logger.info("="*50)
        
        pipeline_start_time = time.time()
        analysis_result = test_analysis_pipeline([str(img) for img in sample_images])
        pipeline_time = time.time() - pipeline_start_time
        
        # Test 3: Create combined side-by-side visualization
        if analysis_result and 'detections' in analysis_result:
            logger.info("\n" + "="*50)
            logger.info("TEST 3: Combined Side-by-Side Visualization")
            logger.info("="*50)
            
            # Extract individual detection results for visualization
            detection_results = []
            for detection in analysis_result['detections']:
                # Convert analysis format to detection format for visualization
                detection_data = {
                    'parasitesDetected': detection.get('parasitesDetected', []),
                    'wbcsDetected': detection.get('wbcsDetected', []),
                    'parasiteCount': detection.get('parasiteCount', 0),
                    'whiteBloodCellsDetected': detection.get('whiteBloodCellsDetected', 0),
                    'parasiteWbcRatio': detection.get('parasiteWbcRatio', 0)
                }
                detection_results.append(detection_data)
            
            # Create combined side-by-side visualization
            create_combined_visualization(
                [str(img) for img in sample_images], 
                detection_results,
                "po_10_images_combined_detection_results.png"
            )
        
        # Test 4: Save comprehensive results to JSON with timing
        if analysis_result:
            logger.info("\n" + "="*50)
            logger.info("TEST 4: Save Comprehensive Results to JSON")
            logger.info("="*50)
            
            # Add timing information to results
            comprehensive_results = {
                "analysis_results": analysis_result,
                "individual_detection_results": individual_results,
                "timing": {
                    "individual_detection_time": individual_time,
                    "pipeline_analysis_time": pipeline_time,
                    "total_time": individual_time + pipeline_time,
                    "timestamp": datetime.now().isoformat()
                },
                "test_images": [str(img.name) for img in sample_images],
                "summary": {
                    "total_images_processed": len(sample_images),
                    "successful_detections": len([r for r in individual_results if r is not None]),
                    "failed_detections": len([r for r in individual_results if r is None]),
                    "overall_status": "SUCCESS" if all(r is not None for r in individual_results) else "PARTIAL_SUCCESS"
                }
            }
            
            output_file = "po_10_images_comprehensive_test_results.json"
            with open(output_file, 'w') as f:
                json.dump(comprehensive_results, f, indent=2, default=str)
            logger.info(f"Comprehensive results saved to: {output_file}")
            
            # Print timing summary
            logger.info(f"\n⏱️ TIMING SUMMARY:")
            logger.info(f"- Individual detection: {individual_time:.2f}s")
            logger.info(f"- Pipeline analysis: {pipeline_time:.2f}s")
            logger.info(f"- Total time: {individual_time + pipeline_time:.2f}s")
        
        logger.info("\n" + "="*50)
        logger.info("TESTING COMPLETED - 10 PO Images")
        logger.info("="*50)
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
