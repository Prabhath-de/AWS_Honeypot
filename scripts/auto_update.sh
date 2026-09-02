#!/bin/bash

# =========================================
# AWS Honeypot Automatic Update Script
# =========================================

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

source "$PROJECT/venv/bin/activate"

echo "Python virtual environment activated."

# -----------------------------------------
# Copy Latest Cowrie Log
# -----------------------------------------

cp "$COWRIE/var/log/cowrie/cowrie.json" \
"$PROJECT/data/raw/cowrie_live.json"

echo "Latest Cowrie log copied."

# -----------------------------------------
# Update Master Dataset
# -----------------------------------------

echo "Updating master dataset..."

python scripts/dataset_manager.py || {
    echo "ERROR: Dataset manager failed."
    exit 1
}

echo "Master dataset updated successfully."

# -----------------------------------------
# Parse Threat Intelligence
# -----------------------------------------

echo "Parsing threat intelligence..."

python scripts/parse_logs.py || {
    echo "ERROR: Threat intelligence parser failed."
    exit 1
}

echo "Threat intelligence parsing completed successfully."

# -----------------------------------------
# Git Update
# -----------------------------------------

echo "Checking processed data changes..."

git add .gitignore
git add data/processed/

if ! git diff --cached --quiet
then
    echo "Changes detected."

    git commit -m "Hourly threat intelligence update"

    git push

    echo "GitHub update completed successfully."
else
    echo "No processed data changes detected."
fi

echo "========================================="
echo " Auto Update Completed"
echo "========================================="
