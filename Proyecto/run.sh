#/usr/bin/env bash

sleep 10

python -u manage.py makemigrations
python -u manage.py migrate

gunicorn --bind :8000 proyecto.wsgi:application --reload --timeout 120
