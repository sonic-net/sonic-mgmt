sudo awk "/$1/{p=1; next} p{print}" /var/log/syslog  | grep "$2"
