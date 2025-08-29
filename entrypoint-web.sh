#!/bin/bash
echo "Collecting static files..."
python manage.py collectstatic --noinput
echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:8001 --workers 3 --timeout 30 demo_user.wsgi:application