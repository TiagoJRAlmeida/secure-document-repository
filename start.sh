#!/bin/bash

sudo docker compose up -d --build server
sudo docker compose run --rm --build client
sudo docker compose down
