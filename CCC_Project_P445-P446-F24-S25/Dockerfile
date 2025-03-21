FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies including netcat and PostgreSQL client libraries
RUN apt-get update && \
    apt-get install -y netcat-openbsd gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the entire application code into the container
COPY . .
EXPOSE 9002
EXPOSE 5432
# CMD: Wait for the "db" service to resolve and for PostgreSQL to be ready, then start the app on port 80.
CMD ["sh", "-c", "\
  echo 'Waiting for DNS to resolve host db...'; \
  until getent hosts db > /dev/null 2>&1; do \
    echo 'db not resolvable yet'; \
    sleep 0.5; \
  done; \
  echo 'db resolved. Waiting for PostgreSQL to be ready...'; \
  until nc -z db 5432; do \
    sleep 0.5; \
  done; \
  echo 'PostgreSQL is up - starting the application'; \
  exec python run.py --port 9002"]