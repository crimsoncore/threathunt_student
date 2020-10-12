#!/bin/sh
cd /opt/threathunt
git pull
cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.portainer.yml pull 
sudo docker-compose -f docker-compose.portainer.yml up -d