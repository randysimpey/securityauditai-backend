FROM python:3.11-slim

# git = needed to clone repos. curl/tar = needed to install gitleaks/trivy binaries.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Install Gitleaks (secrets detection) ---
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# --- Install Trivy (dependency + IaC scanning) ---
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
