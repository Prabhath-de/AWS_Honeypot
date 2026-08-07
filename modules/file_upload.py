#!/usr/bin/env python3

"""
File Upload Analysis Module

Extracts uploaded files transferred to the Cowrie honeypot.
"""

import csv


def extract_file_uploads(events, output_dir):

    output_file = output_dir / "file_uploads.csv"

    count = 0

    with open(output_file, "w", newline="") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "timestamp",
            "src_ip",
            "session",
            "filename",
            "sha256",
            "duplicate",
            "destination"
        ])

        for event in events:

            if event.get("eventid") != "cowrie.session.file_upload":
                continue

            writer.writerow([
                event.get("timestamp", ""),
                event.get("src_ip", ""),
                event.get("session", ""),
                event.get("filename", ""),
                event.get("shasum", ""),
                event.get("duplicate", ""),
                event.get("destfile", "")
            ])

            count += 1

    print(f"File Uploads            : {count}")
    print("✔ file_uploads.csv")

    return count
