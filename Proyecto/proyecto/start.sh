#!/usr/bin/env bash

while read -r linea; do
    export "$linea"
done < <(ccdecrypt -c secrets.env.cpt)

echo $DB_PASS

python manage.py runserver 0.0.0.0:8000
