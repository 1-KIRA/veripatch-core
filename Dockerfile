# Use a lightweight, secure Python base image
FROM python:3.11-slim

# Install system dependencies required for handling code diffs
RUN apt-get update && apt-get install -y --no-install-recommends \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Set secure working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY sandbox_runner.py .
COPY agent_llm.py .
COPY remediation_graph.py .
COPY main.py .
# We will create provenance.py next
COPY provenance.py . 

# Change the final line of your existing Dockerfile from main.py to app.py
CMD ["python", "app.py"]