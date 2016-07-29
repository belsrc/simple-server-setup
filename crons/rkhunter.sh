#!/bin/bash

subject="RKHunter Results"
address="[RECEIVER_ADDRESS]"

# Requires apt-get install mailutils
/usr/bin/rkhunter -c --enable all --disable none --rwo | /usr/bin/mail -s "$subject" "$address"
