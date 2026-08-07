import csv
import json
from collections import defaultdict


def extract_threat_scores(events, output_dir):
    """
    Deterministic Threat Scoring Engine

    Input:
        Cowrie event list

    Output:
        threat_scores.csv
    """

    # -----------------------------------------
    # Load Threat Weights
    # -----------------------------------------

    with open("config/threat_weights.json", "r", encoding="utf-8") as f:
        weights = json.load(f)

    # -----------------------------------------
    # Score Storage
    # -----------------------------------------

    scores = defaultdict(int)

    stats = defaultdict(lambda: {
        "failed_login": 0,
        "successful_login": 0,
        "commands": 0,
        "file_upload": 0,
        "file_transfer": 0,
        "malware": 0,
        "campaign": 0,
        "client_fingerprint": 0,
        "direct_tcpip": 0
    })

    # -----------------------------------------
    # Process Events
    # -----------------------------------------

    for event in events:

        ip = event.get("src_ip")

        if not ip:
            continue

        eventid = event.get("eventid", "")

        # Failed Login
        if eventid == "cowrie.login.failed":
            stats[ip]["failed_login"] += 1
            scores[ip] += weights["failed_login"]

        # Successful Login
        elif eventid == "cowrie.login.success":
            stats[ip]["successful_login"] += 1
            scores[ip] += weights["successful_login"]

        # Commands
        elif eventid == "cowrie.command.input":
            stats[ip]["commands"] += 1
            scores[ip] += weights["commands"]

        # File Upload
        elif eventid == "cowrie.session.file_upload":
            stats[ip]["file_upload"] += 1
            scores[ip] += weights["file_upload"]

        # File Download / Transfer
        elif eventid == "cowrie.session.file_download":
            stats[ip]["file_transfer"] += 1
            scores[ip] += weights["file_transfer"]

        # Malware Activity
        elif eventid == "cowrie.session.file_download.failed":
            stats[ip]["malware"] += 1
            scores[ip] += weights["malware"]

        # Campaign Detection
        elif eventid == "cowrie.log.closed":
            stats[ip]["campaign"] += 1
            scores[ip] += weights["campaign"]

        # Client Fingerprint
        elif eventid == "cowrie.client.version":
            stats[ip]["client_fingerprint"] += 1

        # Direct TCP/IP Pivot Attempt
        elif eventid == "cowrie.direct-tcpip.request":
            stats[ip]["direct_tcpip"] += 1
            scores[ip] += weights["direct_tcpip"]

    # -----------------------------------------
    # Calculate Risk Levels
    # -----------------------------------------

    rows = []

    for ip, score in scores.items():

        if score >= 80:
            risk = "Critical"
        elif score >= 60:
            risk = "High"
        elif score >= 30:
            risk = "Medium"
        else:
            risk = "Low"

        total_events = (
            stats[ip]["failed_login"] +
            stats[ip]["successful_login"] +
            stats[ip]["commands"] +
            stats[ip]["file_upload"] +
            stats[ip]["file_transfer"] +
            stats[ip]["malware"] +
            stats[ip]["campaign"] +
            stats[ip]["client_fingerprint"] +
            stats[ip]["direct_tcpip"]
        )

        rows.append({
            "src_ip": ip,
            "threat_score": score,
            "risk_level": risk,
            "total_events": total_events,
            "failed_login": stats[ip]["failed_login"],
            "successful_login": stats[ip]["successful_login"],
            "commands": stats[ip]["commands"],
            "file_upload": stats[ip]["file_upload"],
            "file_transfer": stats[ip]["file_transfer"],
            "malware": stats[ip]["malware"],
            "campaign": stats[ip]["campaign"],
            "client_fingerprint": stats[ip]["client_fingerprint"],
            "direct_tcpip": stats[ip]["direct_tcpip"]
        })

    rows.sort(
        key=lambda x: x["threat_score"],
        reverse=True
    )

    output_file = output_dir / "threat_scores.csv"

    # -----------------------------------------
    # CSV Output
    # -----------------------------------------

    fieldnames = [
        "src_ip",
        "threat_score",
        "risk_level",
        "total_events",
        "failed_login",
        "successful_login",
        "commands",
        "file_upload",
        "file_transfer",
        "malware",
        "campaign",
        "client_fingerprint",
        "direct_tcpip"
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    # -----------------------------------------
    # Summary
    # -----------------------------------------

    print(f"Threat Scores           : {len(rows)}")
    print("✔ threat_scores.csv")

    return len(rows)

