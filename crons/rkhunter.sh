#!/bin/bash

host=$(hostname)
subject="$host - RKHunter Results"
address="[RECEIVER_EMAIL]"

# Requires apt-get install mailutils
/usr/bin/rkhunter -c --enable all --disable none --rwo | /usr/bin/mail -s "$subject" "$address"
