#!/bin/bash

subject="Tripwire Results"
address="[RECEIVER_ADDRESS]"

# Requires apt-get install mailutils
/usr/sbin/tripwire --check | /usr/bin/mail -s "$subject" "$address"
