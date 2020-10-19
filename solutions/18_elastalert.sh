#!/bin/sh

# Install Elastalert
cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.elastalert.yml up -d
sudo docker restart elastalert
