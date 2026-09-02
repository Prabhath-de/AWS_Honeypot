#!/bin/bash

# =========================================
# AWS Honeypot Automatic Update Script
# =========================================

set -e

# Prevent overlapping cron runs
LOCKFILE="/tmp/aws_honeypot_auto_update.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "Another auto-update process is already running. Exiting."
    exit 0
fi


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
git add data/processed/*.csv data/processed/generated_acl.cfg
git add scripts/auto_update.sh

if ! git diff --cached --quiet
then
    echo "Changes detected."

    if git commit -m "Hourly threat intelligence update"; then
        echo "Git commit completed."
    else
        echo "ERROR: Git commit failed."
        exit 1
    fi

    if git -c pack.threads=1 -c core.compression=0 push origin main; then
        echo "GitHub update completed successfully."
    else
        echo "ERROR: GitHub push failed."
        exit 1
    fi
else
    echo "No processed data changes detected."
fi

echo "========================================="
echo " Auto Update Completed"
echo "========================================="
