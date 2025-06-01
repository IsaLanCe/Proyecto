#!/usr/bin/env bash

while read -r linea; do
    export "$linea"
done < <(ccdecrypt -c secrets.env.cpt)

#docker-compose up -d
docker compose up -d
