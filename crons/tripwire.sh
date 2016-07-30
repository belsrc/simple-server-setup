#!/bin/bash

host=$(hostname)
subject="$host - Tripwire Results"
address="[RECEIVER_EMAIL]"

# Requires apt-get install mailutils
/usr/sbin/tripwire --check | /usr/bin/mail -s "$subject" "$address"
