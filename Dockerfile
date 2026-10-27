# -------------------------------------------------------------
# AWS Infra Watchdog - Production Dockerfile
# Multi-stage security: non-root user, minimal base, zero secrets
# -------------------------------------------------------------
FROM python:3.13-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install security updates & pip dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create an unprivileged non-root user for container security
RUN groupadd -r watchdog && useradd -r -g watchdog -d /app -s /sbin/nologin watchdog

# Copy application files
COPY dashboard/ /app/dashboard/
COPY terraform/ /app/terraform/

# Set proper ownership
RUN chown -R watchdog:watchdog /app

# Switch to non-root user (DevSecOps best practice)
USER watchdog

WORKDIR /app/dashboard

EXPOSE 8000

# Start FastAPI with Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
