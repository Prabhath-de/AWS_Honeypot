#!/usr/bin/env python3

"""
Client Fingerprinting Module
"""

import csv


def extract_client_fingerprint(events, output_dir):

    output_file = output_dir / "client_fingerprint.csv"

    fingerprints = {}

    for event in events:

        eventid = event.get("eventid")
        session = event.get("session")

        if not session:
            continue

        if session not in fingerprints:
            fingerprints[session] = {
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "session": session,
                "client_version": "",
                "hassh": "",
                "terminal_width": "",
                "terminal_height": ""
            }

        if eventid == "cowrie.client.version":

            fingerprints[session]["client_version"] = event.get("version", "")

        elif eventid == "cowrie.client.kex":

            fingerprints[session]["hassh"] = event.get("hassh", "")

        elif eventid == "cowrie.client.size":

            fingerprints[session]["terminal_width"] = event.get("width", "")

            fingerprints[session]["terminal_height"] = event.get("height", "")

    with open(output_file, "w", newline="") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "timestamp",
            "src_ip",
            "session",
            "client_version",
            "hassh",
            "terminal_width",
            "terminal_height"
        ])

        count = 0

        for row in fingerprints.values():

            if (
                row["client_version"]
                or row["hassh"]
                or row["terminal_width"]
            ):

                writer.writerow([
                    row["timestamp"],
                    row["src_ip"],
                    row["session"],
                    row["client_version"],
                    row["hassh"],
                    row["terminal_width"],
                    row["terminal_height"]
                ])

                count += 1

    print(f"Client Fingerprints      : {count}")
    print("✔ client_fingerprint.csv")

    return count
