# Use an official Python runtime as a parent image
FROM python:3.11-slim-bullseye

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . /app/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=core.settings

# Expose the port your Gunicorn app runs on (8080)
EXPOSE 8080
EXPOSE 5555

# Make the super binary and run.sh executable
RUN chmod +x /app/run.sh

# Run migrations and populate the database
RUN python manage.py makemigrations hunt
RUN python manage.py migrate
RUN python populateDB.py
RUN python manage.py collectstatic --noinput
RUN python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@shinkensec.local', 'admin') if not User.objects.filter(username='admin').exists() else print('Superuser already exists.')"

CMD export PYTHONPATH=/app && \
    celery -A core worker -E -l info & \
    celery -A core.celery_app flower --basic_auth=admin:admin --port=5555 & \
    gunicorn core.wsgi:application --bind 0.0.0.0:8080 --workers 3
