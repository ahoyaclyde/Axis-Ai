
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for OpenCV and other packages
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p uploads outputs detections object_snapshots

# Expose port
EXPOSE 8080

# Start the application
CMD ["python", "Master-Rust-Connect.py", "--host", "0.0.0.0", "--port", "8080"]
