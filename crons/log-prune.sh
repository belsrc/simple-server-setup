#!/bin/bash

# Remove the log files that are older than 30 days
find /var/log/* -type f -mtime +30 -delete
