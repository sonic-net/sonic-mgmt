sudo grep 'start-LogAnalyzer-' /var/log/syslog | grep -v ansible | tail -n 1 | awk -F 'INFO ' '{print $2}'
