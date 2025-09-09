#!/bin/bash
echo "Collecting static files..."
python manage.py collectstatic --noinput
echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:8001 --workers 2 --timeout 300 --max-requests 1000 --preload demo_user.wsgi:application