#!/bin/bash

# The list of IPs to block, one per line
BLOCKDB="/root/block/blocked_ips"

# invert-matches lines that start with '#' or are empty
# Grabs all lines that AREN'T comments or empty lines
IPS=$(grep -Pv "^#|^$" $BLOCKDB)

# Loop through each and add iptable rule
for i in $IPS
do
iptables -A INPUT -s $i -j DROP
iptables -A OUTPUT -d $i -j DROP
done
