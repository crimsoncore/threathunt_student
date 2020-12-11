#!/bin/sh
sudo mkdir /opt/neo4j
sudo mkdir /opt/neo4j/data

# Install neo4j docker
cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.neo4j.yml up -d