#!/usr/bin/env python3

"""
Cowrie Threat Intelligence Engine

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement

Author:
Prabhath De Silva
"""

import json
import sys
from pathlib import Path

# --------------------------------------------------
# Add Project Root
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

# --------------------------------------------------
# Import Modules
# --------------------------------------------------

from modules.failed import extract_failed
from modules.success import extract_success
from modules.commands import extract_commands
from modules.sessions import extract_sessions
from modules.file_transfer import extract_file_transfers
from modules.malware import extract_malware

# --------------------------------------------------
# Paths
# --------------------------------------------------

RAW_LOG = BASE_DIR / "data" / "raw" / "master_dataset.json"
OUTPUT_DIR = BASE_DIR / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# Banner
# --------------------------------------------------

print("=" * 60)
print(" Cowrie Threat Intelligence Engine ")
print("=" * 60)

# --------------------------------------------------
# Check Log File
# --------------------------------------------------

if not RAW_LOG.exists():
    print("ERROR : Log file not found.")
    print(RAW_LOG)
    sys.exit(1)

# --------------------------------------------------
# Load Events
# --------------------------------------------------

events = []

with open(RAW_LOG, "r") as logfile:

    for line in logfile:

        line = line.strip()

        if not line:
            continue

        try:
            events.append(json.loads(line))

        except json.JSONDecodeError:
            continue

print(f"\nLoaded Events : {len(events)}")

# --------------------------------------------------
# Run Modules
# --------------------------------------------------

failed_count = extract_failed(events, OUTPUT_DIR)
success_count = extract_success(events, OUTPUT_DIR)
command_count = extract_commands(events, OUTPUT_DIR)
file_transfer_count = extract_file_transfers(events, OUTPUT_DIR)
malware_count = extract_malware(events, OUTPUT_DIR)
session_count = extract_sessions(events, OUTPUT_DIR)

# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\n" + "=" * 60)
print("Threat Intelligence Summary")
print("=" * 60)

print(f"Failed Login Events      : {failed_count}")
print(f"Successful Login Events  : {success_count}")
print(f"Command Events           : {command_count}")

print("\nGenerated Files")
print("✔ failed_logins.csv")
print("✔ successful_logins.csv")
print("✔ commands.csv")

print("\nThreat Intelligence Engine Completed Successfully.")
print(f"Sessions                 : {session_count}")
print("✔ session_summary.csv")
print(f"File Transfers           : {file_transfer_count}")

print("✔ file_transfers.csv")
print(f"Malware Activities       : {malware_count}")
print("✔ malware_activity.csv")
