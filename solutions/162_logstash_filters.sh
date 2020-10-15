#!/bin/sh

# LOGSTASH configuration for FreqServer on DNS records
cd /opt/threathunt/logstash/logstash_enrich
cp 410_enrich_filter_windows_sysmon_dns_freq.conf /opt/threathunt/logstash/pipeline
cp 320_enrich_sourcedest_ip.conf /opt/threathunt/logstash/pipeline
cp 380_enrich_network.conf /opt/threathunt/logstash/pipeline
cp 390_enrich_geo.conf /opt/threathunt/logstash/pipeline
sudo docker restart logstash_rest
