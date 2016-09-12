#!/bin/bash

# Ouptut colors
NC="\033[0m" # No Color
RED="\033[0;91m" # Light Red
BLUE="\033[0;34m" # Blue

# The list of IPs to block, one per line
BLOCKDB="/root/block/blocked_ips"

# invert-matches lines that start with '#' or are empty
# Grabs all lines that AREN'T comments or empty lines
IPS=$(grep -Pv "^#|^$" $BLOCKDB)

# Loop through each item from the file
for i in $IPS; do
  # If the value exists, do nothing, otherwise add
  if iptables -S | grep --quiet "\-A INPUT \-s $i\/32 \-j DROP"; then
    echo "'$i' already exists"
    echo -e "    ${BLUE}$(iptables -S | grep "\-A INPUT \-s $i\/32 \-j DROP")${NC}"
  else
    echo -e "${RED}'$i'${NC} not found, adding..."
    iptables -A INPUT -s $i -j DROP
    iptables -A OUTPUT -d $i -j DROP
  fi
done
