#!/usr/bin/env python3

"""
Dataset Manager

Synchronize Cowrie live log into a master dataset
without duplicate events.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

LIVE_LOG = BASE_DIR / "data/raw/cowrie_live.json"
MASTER_LOG = BASE_DIR / "data/raw/master_dataset.json"

# ----------------------------------------
# Read existing events
# ----------------------------------------

known_events = set()

if MASTER_LOG.exists():

    with open(MASTER_LOG, "r") as f:

        for line in f:

            line = line.strip()

            if line:

                known_events.add(line)

# ----------------------------------------
# Add only new events
# ----------------------------------------

new_events = 0

with open(LIVE_LOG, "r") as source, \
     open(MASTER_LOG, "a") as target:

    for line in source:

        line = line.strip()

        if not line:
            continue

        if line not in known_events:

            target.write(line + "\n")

            known_events.add(line)

            new_events += 1

print("=" * 50)
print("Dataset Manager")
print("=" * 50)

print("New Events Added :", new_events)
print("Total Events     :", len(known_events))
