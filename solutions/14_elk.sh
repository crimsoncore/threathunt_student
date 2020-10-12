#!/bin/sh

# Install Elastic
sudo bash -c 'echo "vm.max_map_count=262144" >> /etc/sysctl.conf'
sudo sysctl -p
sysctl vm.max_map_count

cd /opt/threathunt/docker-compose
cat docker-compose.elastic.yml

cd /opt/threathunt/docker-compose
sudo docker-compose -f docker-compose.elastic.yml up -d

# Configure Logstash
queue = hostname | sed  's/AZ-KALI-/RabbitQueue_Student0/g'

sed -i "s/RabbitQueue_Student00/$queue/g" /opt/threathunt/logstash/pipeline/100_RabbitMQ_AZURE-input.conf
sed -i "s/PROVIDED_PASSWORD/Password1234!/g" /opt/threathunt/logstash/pipeline/100_RabbitMQ_AZURE-input.conf
