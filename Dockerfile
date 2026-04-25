# Step 1 — Use lightweight Python base image
# python:3.11-slim = Python 3.11 with minimal OS (smaller = faster to deploy)
# We use 3.11 not 3.14 because all libraries support 3.11 reliably
FROM python:3.11-slim

# Step 2 — Set working directory inside the container
# All files will be placed here inside Docker
WORKDIR /app

# Step 3 — Copy requirements first (Docker caching trick)
# If requirements don't change, Docker skips re-installing — saves time
COPY requirements.txt .

# Step 4 — Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 5 — Copy ALL project files into the container
COPY . .

# Step 6 — Tell Docker which port the app uses
# Streamlit default port is 8501
EXPOSE 8501

# Step 7 — Run the app when container starts
# --server.address=0.0.0.0 = accept connections from outside the container
# --server.port=8501 = use port 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
