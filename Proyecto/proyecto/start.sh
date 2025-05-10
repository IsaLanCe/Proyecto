#!/usr/bin/env bash

while read -r linea; do
    export "$linea"
done < <(ccdecrypt -c secrets.env.cpt)

echo $DB_PASS
#python3 manage.py makemigrations
#python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000
