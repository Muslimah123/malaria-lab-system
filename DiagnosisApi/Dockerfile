# Dockerfile
# FROM python:3.9-slim
# WORKDIR /app
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt
# COPY app/ ./app/
# COPY app/models/best.pt ./models/best.pt
# RUN useradd -m appuser && chown -R appuser:appuser /app
# USER appuser
# EXPOSE 5000
# RUN mkdir -p /app/logs && chown appuser:appuser /app/logs
# CMD ["python", "-m", "app"]


FROM python:3.9-slim

WORKDIR /app

# Install system dependencies 
RUN apt-get update && apt-get install -y \
    gcc \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgl1 \
    libgl1-mesa-glx \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Copy model file
COPY app/models/best.pt ./models/best.pt

# Create user and set permissions
RUN useradd -m appuser && chown -R appuser:appuser /app

# Create logs directory
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs


# Expose port
EXPOSE 5001

# Run the application
CMD ["python","-m", "app"]