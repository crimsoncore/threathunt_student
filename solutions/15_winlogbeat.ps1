cd 'C:\Program Files\winlogbeat-7.8.0-windows-x86_64\'
.\winlogbeat.exe setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["yourkalimachine:9200"]'
