FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    git \
    libpq-dev \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install your Flask API dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 

# Clone YOLOv12
RUN git clone https://github.com/sunsmarterjie/yolov12.git /yolov12

# Install YOLOv12 dependencies but skip flash-attn and prefer CPU onnxruntime
# Replace `onnxruntime-gpu` with `onnxruntime` on-the-fly to avoid missing GPU wheels
RUN cd /yolov12 \
    && sed -e 's/onnxruntime-gpu/onnxruntime/g' requirements.txt \
       | grep -v "flash_attn" \
       | grep -v -E "onnxruntime(-gpu)?==" > req_no_flash.txt \
    && printf "onnxruntime==1.15.1\n" >> req_no_flash.txt \
    && pip install --no-cache-dir -r req_no_flash.txt \
    && pip install --no-cache-dir -e .

# Copy application code
COPY . .

RUN mkdir -p /app/logs /app/uploads \
    && chown -R nobody:nogroup /app/logs /app/uploads \
    && chmod -R 755 /app/logs /app/uploads

ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    YOLO_CONFIG_DIR=/app/config

EXPOSE 5000

CMD ["python", "run.py"]
