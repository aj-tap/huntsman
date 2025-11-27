# Dockerfile
FROM python:3.11-slim-bullseye

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=huntsman.settings

# Create a non-root user and group
RUN addgroup --system appgroup && adduser --system --group appuser

WORKDIR /app

# Install system dependencies
# libpq-dev is often needed for psycopg2 (Postgres)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Copy entrypoint and ensure it is executable
COPY ./entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Chown all the files to the app user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the Gunicorn port
EXPOSE 8080

ENTRYPOINT ["entrypoint.sh"]