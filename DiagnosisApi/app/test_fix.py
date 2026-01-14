#!/usr/bin/env python3
"""
Quick test script to verify YOLOv12 fix inside Docker container
Place this in your project root and run inside container
"""

import sys
import os
import json

# Add app to path
sys.path.insert(0, '/app')

def test_model_loading():
    """Test if model loads without AAttn error"""
    print("="*60)
    print("TEST 1: Model Loading")
    print("="*60)
    
    try:
        from app.detection.model import MalariaDetector
        detector = MalariaDetector(model_path="/app/app/models/V12.pt")
        print("✓ Model loaded successfully!")
        return detector
    except Exception as e:
        print(f"✗ Failed to load model: {e}")
        return None

def test_single_image(detector):
    """Test detection on a single image"""
    print("\n" + "="*60)
    print("TEST 2: Single Image Detection")
    print("="*60)
    
    # Use one of your test images
    test_image = "/app/shared_uploads/images/upload_1754798695594_yh7vrnovw_1754798792829_8e7d431ea38e8718.jpg"
    
    if not os.path.exists(test_image):
        print(f"Test image not found at {test_image}")
        print("Available images:")
        img_dir = "/app/shared_uploads/images/"
        if os.path.exists(img_dir):
            images = os.listdir(img_dir)[:5]  # Show first 5
            for img in images:
                print(f"  - {img}")
            if images:
                test_image = os.path.join(img_dir, images[0])
                print(f"\nUsing: {test_image}")
    
    try:
        result, error = detector.detect_and_quantify(test_image)
        if error:
            print(f"✗ Detection error: {error}")
        else:
            print(f"✓ Detection successful!")
            print(f"  - Parasites: {result['parasite_count']}")
            print(f"  - WBCs: {result['white_blood_cells_detected']}")
            print(f"  - Ratio: {result['parasite_wbc_ratio']:.3f}")
        return result
    except Exception as e:
        print(f"✗ Detection failed: {e}")
        return None

def test_api_endpoint():
    """Test the Flask API endpoint directly"""
    print("\n" + "="*60)
    print("TEST 3: API Endpoint")
    print("="*60)
    
    try:
        from app import create_app
        app = create_app()
        
        # Create test client
        client = app.test_client()
        
        # Test health endpoint
        response = client.get('/health')
        print(f"Health check: {response.status_code}")
        
        # Test diagnosis endpoint
        test_data = {
            "image_paths": [
                "/app/shared_uploads/images/upload_1754798695594_yh7vrnovw_1754798792829_8e7d431ea38e8718.jpg",
                "/app/shared_uploads/images/upload_1754798695594_yh7vrnovw_1754798792968_2635f92f57d3c667.jpg"
            ]
        }
        
        response = client.post('/diagnose', 
                              data=json.dumps(test_data),
                              content_type='application/json')
        
        print(f"Diagnosis endpoint: {response.status_code}")
        if response.status_code == 200:
            result = json.loads(response.data)
            print(f"✓ API working!")
            print(f"  - Status: {result.get('status')}")
            print(f"  - Total parasites: {result.get('total_parasites', 0)}")
            print(f"  - Total WBCs: {result.get('total_wbcs', 0)}")
        else:
            print(f"✗ API error: {response.data}")
            
    except Exception as e:
        print(f"✗ API test failed: {e}")

def main():
    print("\nYOLOv12 Fix Verification Tests")
    print("="*60)
    
    # Test 1: Load model
    detector = test_model_loading()
    if not detector:
        print("\n❌ Model loading failed - fix not working")
        return
    
    # Test 2: Single image
    result = test_single_image(detector)
    if not result:
        print("\n⚠️  Detection failed but model loaded")
    
    # Test 3: API endpoint
    test_api_endpoint()
    
    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)

if __name__ == "__main__":
    main()