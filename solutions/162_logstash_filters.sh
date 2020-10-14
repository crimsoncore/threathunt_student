#!/bin/sh

# LOGSTASH configuration for FreqServer on DNS records
cd /opt/threathunt/logstash/logstash_enrich
cp 410_enrich_filter_windows_sysmon_dns_freq.conf /opt/threathunt/logstash/pipeline
sudo docker restart logstash_rest
sudo docker container logs logstash_rest --follow


