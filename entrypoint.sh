#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Function to wait for services (DB)
wait_for_service() {
    echo "Waiting for Database..."
    sleep 5
}

if echo "$@" | grep -q "gunicorn"; then
    wait_for_service
    
    echo "Running Database Migrations..."
    python manage.py makemigrations api
    python manage.py migrate --noinput
    
    echo "Updating System Configs..."
    python manage.py setup_pools
    python manage.py update_rules
    
    echo "Collecting Static Files..."
    python manage.py collectstatic --noinput

    echo "Creating Superuser (if not exists)..."
    python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); \
        User.objects.filter(username='admin').exists() or \
        User.objects.create_superuser('admin', 'admin@hunt.local', 'changeme')"
fi

exec "$@"