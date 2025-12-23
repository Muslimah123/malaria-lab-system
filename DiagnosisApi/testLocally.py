import json
import os
from app import create_app
from app.detection.analysis import analyze_patient_slides

# Specify the folder containing your images
IMAGE_FOLDER = "C:/Users/robot/Documents/DiagnosisApi/images"  # Replace with your folder path

def get_image_paths(folder_path):
    """Get a list of image file paths from a folder."""
    supported_extensions = (".jpg", ".jpeg", ".png")  # Add more if needed
    image_paths = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(supported_extensions):
                full_path = os.path.join(root, file)
                image_paths.append(full_path)
    return image_paths

def test_api_locally():
    # Get all image paths from the folder
    image_paths = get_image_paths(IMAGE_FOLDER)
    if not image_paths:
        print(f"No images found in {IMAGE_FOLDER}")
        return

    print(f"Found {len(image_paths)} images in {IMAGE_FOLDER}")

    # Create the Flask app
    app = create_app()

    # Option 1: Test the analysis function directly
    print("\nDirect Analysis Result:")
    report = analyze_patient_slides(image_paths)
    print(json.dumps(report, indent=2))

    # Option 2: Test via the Flask API endpoint
    with app.test_client() as client:
        print("\nAPI Endpoint Result:")
        response = client.post(
            "/diagnose",
            json={"image_paths": image_paths},
            content_type="application/json"
        )
        print(response.get_data(as_text=True))

if __name__ == "__main__":
    test_api_locally()