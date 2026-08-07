#!/bin/bash

echo "=========================================="
echo "Cowrie Research Auto Update"
echo "=========================================="

PROJECT=/home/cowrie/research/AWS_Honeypot
COWRIE=/home/cowrie/cowrie

echo "[1/6] Copying latest Cowrie log..."

cp $COWRIE/var/log/cowrie/cowrie.json \
   $PROJECT/data/raw/cowrie.json

echo "[2/6] Activating Python environment..."

source $PROJECT/venv/bin/activate

echo "[3/6] Running Threat Intelligence Engine..."

python $PROJECT/scripts/parse_logs.py

echo "[4/6] Backing up latest log..."

mkdir -p $PROJECT/backups/daily

cp $PROJECT/data/raw/cowrie.json \
   $PROJECT/backups/daily/cowrie_$(date +%F_%H-%M).json

echo "[5/6] Checking Git changes..."

cd $PROJECT

git add .

if git diff --cached --quiet
then
    echo "No changes detected."
else
    git commit -m "Auto Update $(date '+%Y-%m-%d %H:%M')"
    git push
fi

echo "[6/6] Completed Successfully."
echo "=========================================="
