# ─── STEP 1: BASE PYTHON ENVIRONMENT ───
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and force unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# ─── STEP 2: INSTALL SYSTEM DEPENDENCIES & TRIVY ───
# ─── STEP 2: INSTALL SYSTEM DEPENDENCIES & TRIVY ───
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    apt-transport-https \
    gnupg \
    && curl -sfL https://get.trivy.dev/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://get.trivy.dev/deb generic main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─── STEP 3: INSTALL PYTHON DEPENDENCIES ───
# Copy requirements first to leverage Docker build caching optimization
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── STEP 4: COPIES APP SOURCE ASSETS ───
COPY . .

# Expose FastAPI's production engine port
EXPOSE 8080

# Run Uvicorn directly inside the container layout environment context
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]