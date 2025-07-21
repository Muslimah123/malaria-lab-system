# Malaria Diagnosis API

This is a Flask-based RESTful API designed to detect malaria parasites in blood slide images using a pre-trained YOLO model. The API processes uploaded images, identifies parasites (e.g., *Plasmodium Ovale*, *Plasmodium Falciparum*, *Plasmodium Malariae*), and white blood cells (WBCs), and generates a detailed report indicating the patient’s malaria status.

## Features
- **Image Processing**: Accepts multiple image uploads for analysis.
- **Parasite Detection**: Identifies malaria parasite types with confidence scores and bounding box coordinates.
- **Patient Status**: Determines if the patient is positive ("POS") or negative ("NEG") for malaria.
- **Structured Logging**: Logs processing details for monitoring and debugging.

## Project Structure
```
malaria_diagnosis/
├── app/
│   ├── __init__.py       # Initializes the Flask app
│   ├── routes.py         # Defines API endpoints
│   ├── detection/
│   │   ├── __init__.py   # Module initialization
│   │   ├── model.py      # YOLO model loading and detection logic
│   │   └── analysis.py   # Multi-image analysis and report generation
│   └── utils/
│       ├── __init__.py   # Utility initialization
│       └── logging.py    # Logging configuration
├── logs/                 # Directory for log files (created at runtime)
├── models/
│   └── best.pt           # Pre-trained YOLO model file
├── uploads/              # Temporary storage for uploaded images (created at runtime)
└── requirements.txt      # Python dependencies
```

## Prerequisites
- Python 3.9+
- Dependencies listed in `requirements.txt`

## Installation
### Clone the Repository:
```bash
git clone <repository-url>
cd malaria_diagnosis
```

### Install Dependencies:
```bash
pip install -r requirements.txt
```

### Ensure Model File:
Place the pre-trained YOLO model (`best.pt`) in the `models/` directory.

### Run the API:
```bash
python -m app
```
The API will start on `http://localhost:5000`.

## API Endpoint
### **POST /diagnose**
Analyzes uploaded blood slide images for malaria parasites.

#### Request
- **Method**: `POST`
- **Content-Type**: `multipart/form-data`
- **Body**:
  - `Key`: `images`
  - `Value`: Multiple image files (e.g., .jpg, .png)
  - **Maximum file size**: 16MB per image

#### Example (Using cURL)
```bash
curl -X POST http://localhost:5000/diagnose \
-F "images=@/path/to/po_52.jpg" \
-F "images=@/path/to/pf_8.jpg" \
-F "images=@/path/to/pm_3.jpg"
```

#### Response
- **Status Code**: `200 OK`
- **Content-Type**: `application/json`
- **Body**: JSON report with detection results.

#### Sample Response
```json
{
  "status": "POS",
  "most_probable_parasite": {
    "type": "PM",
    "confidence": 0.8650160431861877
  },
  "parasite_wbc_ratio": 0.0,
  "detections": [
    {
      "image_id": "po_52.jpg",
      "parasites_detected": [
        {
          "type": "PO",
          "confidence": 0.8561460375785828,
          "bbox": [2109.17, 1401.84, 2317.47, 1586.43]
        }
      ],
      "white_blood_cells_detected": 0,
      "parasite_count": 2,
      "parasite_wbc_ratio": 0.0
    }
  ]
}
```

## Error Responses
- **400 Bad Request**: If no images are provided or files are invalid.
```json
{"error": "No images provided"}
```

## Logging
- Logs are written to `logs/app.log` with details about requests, image processing, and errors.
- **Format**: `%(asctime)s - %(levelname)s - %(message)s`

**Example log entry:**
```text
2025-03-23 12:00:01,456 - INFO - Processed image /app/uploads/po_52.jpg: 2 parasites, 0 WBCs
```

## Usage Notes
- **Image Requirements**: Upload clear blood slide images in `.jpg` or `.png` format.
- **Model**: The API uses a pre-trained YOLO model (`best.pt`) to detect parasites (PO, PF, PM) and WBCs.
- **Temporary Storage**: Uploaded images are stored in `/app/uploads/` during processing and deleted afterward.

## Development
- **Modular Design**:
  - `detection/model.py`: Handles single-image detection.
  - `detection/analysis.py`: Aggregates results across multiple images.
  - `routes.py`: Defines the API endpoint.
  - `utils/logging.py`: Configures logging.
- **Extending**:
  - Add new endpoints in `routes.py` or enhance detection logic in `detection/`.

## Dependencies
- `Flask`: Web framework
- `ultralytics`: YOLO model implementation
- `torch`: Deep learning framework
- `werkzeug`: File handling utilities
- See `requirements.txt` for exact versions.
