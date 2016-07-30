#!/bin/bash

host=$(hostname)
subject="$host - Maldet Report"
address="[RECEIVER_EMAIL]"

# Requires apt-get install mailutils
/usr/local/sbin/maldet --scan-recent /home?/?/public_?/,/var/www/html/,/home/,/ 1 | /usr/bin/mail -s "$subject" "$address"
