import csv
import json
from collections import defaultdict


def extract_threat_scores(events, output_dir):

    # Load threat weights
    with open("config/threat_weights.json", "r") as f:
        weights = json.load(f)

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

    for event in events:

        ip = event.get("src_ip")

        if not ip:
            continue

        eventid = event.get("eventid", "")

    if eventid == "cowrie.login.failed":
    stats[ip]["failed_login"] += 1
    scores[ip] += weights["failed_login"]

        elif eventid == "cowrie.login.success":
            scores[ip] += weights["successful_login"]

        elif eventid == "cowrie.command.input":
            scores[ip] += weights["commands"]

        elif eventid == "cowrie.session.file_upload":
            scores[ip] += weights["file_upload"]

        elif eventid == "cowrie.session.file_download":
            scores[ip] += weights["file_transfer"]

        elif eventid == "cowrie.session.file_download.failed":
            scores[ip] += weights["malware"]

        elif eventid == "cowrie.log.closed":
            scores[ip] += weights["campaign"]

        elif eventid == "cowrie.client.version":
            scores[ip] += weights["client_fingerprint"]

        elif eventid == "cowrie.direct-tcpip.request":
            scores[ip] += weights["direct_tcpip"]





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

        rows.append({
            "src_ip": ip,
            "threat_score": score,
            "risk_level": risk
        })

    rows.sort(key=lambda x: x["threat_score"], reverse=True)

    output_file = output_dir / "threat_scores.csv"

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:

        fieldnames = [
            "src_ip",
            "threat_score",
            "risk_level"
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(rows)

    print(f"Threat Scores           : {len(rows)}")
    print("✔ threat_scores.csv")

    return len(rows)

