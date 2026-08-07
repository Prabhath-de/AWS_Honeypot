#!/usr/bin/env python3

"""
Campaign Correlation Module

Extracts:
- TTY SHA256
- Duplicate Attacks
- Session Duration
- TTY Log Size
"""

import csv


def extract_campaign(events, output_dir):

    output_file = output_dir / "campaign_summary.csv"

    count = 0

    with open(output_file, "w", newline="") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "timestamp",
            "src_ip",
            "session",
            "ttylog",
            "sha256",
            "duplicate",
            "duration_ms",
            "tty_size"
        ])

        for event in events:

            if event.get("eventid") != "cowrie.log.closed":
                continue

            writer.writerow([
                event.get("timestamp", ""),
                event.get("src_ip", ""),
                event.get("session", ""),
                event.get("ttylog", ""),
                event.get("shasum", ""),
                event.get("duplicate", ""),
                event.get("duration_ms", ""),
                event.get("size", "")
            ])

            count += 1

    print(f"Campaign Records         : {count}")
    print("✔ campaign_summary.csv")

    return count
