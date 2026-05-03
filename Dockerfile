# Step 1 - Use lightweight Python base image
# Python 3.11 is widely supported by the ML and API dependencies used here.
FROM python:3.11-slim

# Step 2 - Set working directory inside the container
WORKDIR /app

# Step 3 - Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Step 4 - Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 5 - Copy the project files into the container
COPY . .

# Step 6 - Tell Docker which port the API uses
# Render injects PORT at runtime; 8000 is only the local/default fallback.
EXPOSE 8000

# Step 7 - Run the FastAPI app and bind to all interfaces for Render routing
CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-8000}"]
