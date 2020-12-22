#!/bin/sh

# Install msf docker
cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.msf_host.yml up -d

