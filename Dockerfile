# Use full Python image (more stable networking than slim)
FROM python:3.11

# Prevent Python from buffering logs
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Increase pip reliability
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_DEFAULT_TIMEOUT=120

WORKDIR /app

# Upgrade pip first (critical)
RUN pip install --upgrade pip

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install dependencies with binary preference
RUN pip install --prefer-binary -r requirements.txt

# Copy application code + PDFs + storage
COPY . .

# Cloud Run port
ENV PORT=8080

# Start app
CMD ["python", "main.py"]