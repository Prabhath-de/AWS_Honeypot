#!/usr/bin/env python3

"""
Cowrie Honeypot Log Parser

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement

Author:
Prabhath Rashmika
"""

import json
from pathlib import Path

# Input log file
RAW_LOG = Path("../data/raw/cowrie.json")


def main():

    print("=" * 50)
    print(" Cowrie Log Parser ")
    print("=" * 50)

    if not RAW_LOG.exists():
        print(f"ERROR : {RAW_LOG} not found.")
        return

    print(f"Log file found : {RAW_LOG}")

    total = 0

    with open(RAW_LOG, "r") as logfile:

        for line in logfile:

            if line.strip():

                json.loads(line)

                total += 1

    print(f"Total Events : {total}")


if __name__ == "__main__":
    main()
