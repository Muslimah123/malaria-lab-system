# Malaria Diagnosis API

This is a **Flask-based REST API** designed to **detect malaria parasites in blood slide images** using a **pre-trained YOLOv10 model**. The API parses uploaded images, identifies parasites (such as Plasmodium Ovale, Plasmodium Falciparum, Plasmodium Malariae) and White Blood Cells (WBCs), and generates a detailed report indicating the patient’s malaria status.

The application is **Dockerized** and integrates with the **ELK stack (Elasticsearch, Filebeat, Kibana)** for logging and monitoring.

---

## 🔹 Features

- **Image Processing:** Accepts **multiple image files or file paths**.
- **Parasite Detection:** Detects **Plasmodium Ovale, Malariae, Falciparum**, and **white blood cells**.
- **Patient Report:** Determines **positive or negative status**, **parasite to WBC ratio**, and **confidence score**.
- **Structured Logging:** Stores processing details in `app.log`.
- **Dockerized Deployment:** Easily deployable with Docker Compose.
- **ELK Integration:** Filebeat streams logs to Elasticsearch for visualization in Kibana.

---


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
│   |    ├── __init__.py   # Utility initialization
│   |    └── logging.py    # Logging configuration
|   |--- models/
|        |--malaria_yolov10.pt
├── logs/                 # Directory for log files (created at runtime)
├── uploads/              # Temporary storage for uploaded images (created at runtime)
└── requirements.txt      # Python dependencies
└── Dockerfile            # Python dependencies
└── docker-compose.yml            # Python dependencies

```

## Prerequisites
- Python 3.9+
- Dependencies listed in `requirements.txt`

## Installation
### Clone the Repository:
```bash
git clone <repository-url>
cd DiagnosisApi
```

### Install Dependencies:
```bash
pip install -r requirements.txt
```

### Ensure Model File:
Place the pre-trained YOLO model (`malaria_yolov10.pt`) in the `models/` directory.

### Run the API:
```bash
python run.py
```
The API will start on `http://localhost:5000`.

## API Endpoint
### **POST /diagnose**
Analyzes uploaded blood slide images for malaria parasites.

#### Request
1️⃣ Open Postman Application

2️⃣ Click "New" > "Request"

3️⃣ Name your request, e.g.: Malaria Diagnose (JSON)
4️⃣ Set Method: POST
5️⃣ Enter URL:http://localhost:5005/diagnose
6️⃣ Click on "Body" tab.
7️⃣ Select "raw".
8️⃣ Change content format to "JSON" (you should see "JSON" in the drop-down).
9️⃣ Paste the following sample JSON into the body editor:
{
  "image_paths": [
    "/app/uploads/pm_260.jpg",
    "/app/uploads/pm_261.jpg",
    "/app/uploads/pm_262.jpg",
    "/app/uploads/pm_263.jpg",
    "/app/uploads/pm_264.jpg",
    "/app/uploads/pm_265.jpg",
    "/app/uploads/pm_266.jpg",
    "/app/uploads/pm_267.jpg",
    "/app/uploads/pm_268.jpg",
    "/app/uploads/pm_269.jpg"
  ]
}
10️⃣ Click "Send".



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
