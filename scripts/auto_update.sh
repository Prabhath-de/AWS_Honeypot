#!/bin/bash

##################################################
# AWS Honeypot Automated Update Script
#
# Research:
# Dynamic Network Defense Rule Generation Using
# Cowrie Honeypot Data with Automated Cisco ACL Enforcement
##################################################

set -e

echo "========================================="
echo " AWS Honeypot Auto Update Started"
echo "========================================="

PROJECT="/home/cowrie/research/AWS_Honeypot"
COWRIE="/home/cowrie/cowrie"

cd "$PROJECT"

# -----------------------------------------
# Activate Python Virtual Environment
# -----------------------------------------

source venv/bin/activate

# -----------------------------------------
# Copy Latest Cowrie Log
# -----------------------------------------

cp "$COWRIE/var/log/cowrie/cowrie.json" \
"$PROJECT/data/raw/cowrie_live.json"

echo "Latest Cowrie log copied."

# -----------------------------------------
# Update Master Dataset
# -----------------------------------------

python scripts/dataset_manager.py

# -----------------------------------------
# Parse Threat Intelligence
# -----------------------------------------

python scripts/parse_logs.py

# -----------------------------------------
# Git Update
# -----------------------------------------

git add .gitignore
git add data/processed/

if ! git diff --cached --quiet
then
    git commit -m "Hourly threat intelligence update"
    git push
else
    echo "No processed data changes detected."
fi

echo "========================================="
echo " Auto Update Completed"
echo "========================================="
