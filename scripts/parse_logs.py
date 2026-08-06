#!/usr/bin/env python3

import json
import csv
from pathlib import Path

RAW_LOG = Path("../data/raw/cowrie.json")
OUTPUT_DIR = Path("../data/processed")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

failed_logins = []

print("=" * 60)
print("Cowrie Log Parser")
print("=" * 60)

with open(RAW_LOG, "r") as logfile:

    for line in logfile:

        if not line.strip():
            continue

        event = json.loads(line)

        if event.get("eventid") == "cowrie.login.failed":

            failed_logins.append({

                "timestamp": event.get("timestamp"),

                "src_ip": event.get("src_ip"),

                "username": event.get("username"),

                "password": event.get("password")

            })

print("Failed Login Events :", len(failed_logins))

csv_file = OUTPUT_DIR / "failed_logins.csv"

with open(csv_file, "w", newline="") as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "timestamp",
            "src_ip",
            "username",
            "password"
        ]
    )

    writer.writeheader()

    writer.writerows(failed_logins)

print("CSV Created :", csv_file)
