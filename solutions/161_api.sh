#!/bin/sh

# Install freqserver
cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.freqserver.yml up -d

# Install Domainstats
cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.domainstats.yml up -d

# Update Domainstats
cd /opt/threathunt/domain_stats
sudo ./UmbrellaTop1M.sh 
