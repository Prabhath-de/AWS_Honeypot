#!/usr/bin/env python3

"""
Cowrie Threat Intelligence Engine

Memory-efficient single-pass event processing.

Research:
Dynamic Network Defense Rule Generation Using Cowrie Honeypot Data
with Automated Cisco ACL Enforcement

Author:
Prabhath De Silva
"""

import csv
import ipaddress
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from modules.acl_generator import generate_acl


# --------------------------------------------------
# Paths
# --------------------------------------------------

RAW_LOG = BASE_DIR / "data" / "raw" / "master_dataset.json"
OUTPUT_DIR = BASE_DIR / "data" / "processed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

WEIGHTS_FILE = BASE_DIR / "config" / "threat_weights.json"

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

if not WEIGHTS_FILE.exists():
    print("ERROR : Threat weights file not found.")
    print(WEIGHTS_FILE)
    sys.exit(1)

# --------------------------------------------------
# Load Threat Weights
# --------------------------------------------------

with open(WEIGHTS_FILE, "r", encoding="utf-8") as f:
    weights = json.load(f)

# --------------------------------------------------
# Output Files
# --------------------------------------------------

failed_file = OUTPUT_DIR / "failed_logins.csv"
success_file = OUTPUT_DIR / "successful_logins.csv"
commands_file = OUTPUT_DIR / "commands.csv"
sessions_file = OUTPUT_DIR / "session_summary.csv"
transfers_file = OUTPUT_DIR / "file_transfers.csv"
malware_file = OUTPUT_DIR / "malware_activity.csv"
fingerprint_file = OUTPUT_DIR / "client_fingerprint.csv"
campaign_file = OUTPUT_DIR / "campaign_summary.csv"
uploads_file = OUTPUT_DIR / "file_uploads.csv"
geoip_file = OUTPUT_DIR / "geoip_asn.csv"
direct_tcpip_file = OUTPUT_DIR / "direct_tcpip.csv"
threat_file = OUTPUT_DIR / "threat_scores.csv"

# --------------------------------------------------
# Counters
# --------------------------------------------------

total_events = 0
invalid_events = 0

failed_count = 0
success_count = 0
command_count = 0
file_transfer_count = 0
malware_count = 0
file_upload_count = 0
campaign_count = 0
geoip_count = 0
direct_tcpip_count = 0

# --------------------------------------------------
# Session State
# --------------------------------------------------

sessions = {}

# --------------------------------------------------
# Client Fingerprint State
# --------------------------------------------------

fingerprints = {}

# --------------------------------------------------
# GeoIP State
# --------------------------------------------------

seen_ips = set()

# --------------------------------------------------
# Threat Score State
# --------------------------------------------------

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

# --------------------------------------------------
# Keyword Lists
# --------------------------------------------------

transfer_keywords = [
    "scp",
    "wget",
    "curl",
    "ftp",
    "tftp",
    "sftp"
]

malware_keywords = [
    "chmod +x",
    "bash -c",
    "nohup",
    "python ",
    "python3 ",
    "perl ",
    "sh ",
    "/bin/sh",
    "/bin/bash"
]

# --------------------------------------------------
# Open Output CSV Files
# --------------------------------------------------

with open(failed_file, "w", newline="", encoding="utf-8") as failed_csv, \
     open(success_file, "w", newline="", encoding="utf-8") as success_csv, \
     open(commands_file, "w", newline="", encoding="utf-8") as commands_csv, \
     open(transfers_file, "w", newline="", encoding="utf-8") as transfers_csv, \
     open(malware_file, "w", newline="", encoding="utf-8") as malware_csv, \
     open(uploads_file, "w", newline="", encoding="utf-8") as uploads_csv, \
     open(campaign_file, "w", newline="", encoding="utf-8") as campaign_csv, \
     open(geoip_file, "w", newline="", encoding="utf-8") as geoip_csv, \
     open(direct_tcpip_file, "w", newline="", encoding="utf-8") as direct_csv:

    failed_writer = csv.writer(failed_csv)
    success_writer = csv.writer(success_csv)
    commands_writer = csv.writer(commands_csv)
    transfers_writer = csv.writer(transfers_csv)
    malware_writer = csv.writer(malware_csv)
    uploads_writer = csv.writer(uploads_csv)
    campaign_writer = csv.writer(campaign_csv)
    geoip_writer = csv.writer(geoip_csv)
    direct_writer = csv.writer(direct_csv)

    # --------------------------------------------------
    # CSV Headers
    # --------------------------------------------------

    failed_writer.writerow([
        "timestamp",
        "src_ip",
        "username",
        "password"
    ])

    success_writer.writerow([
        "timestamp",
        "src_ip",
        "username",
        "password"
    ])

    commands_writer.writerow([
        "timestamp",
        "src_ip",
        "session",
        "command"
    ])

    transfers_writer.writerow([
        "timestamp",
        "src_ip",
        "session",
        "command"
    ])

    malware_writer.writerow([
        "timestamp",
        "src_ip",
        "session",
        "command"
    ])

    uploads_writer.writerow([
        "timestamp",
        "src_ip",
        "session",
        "filename",
        "sha256",
        "duplicate",
        "destination"
    ])

    campaign_writer.writerow([
        "timestamp",
        "src_ip",
        "session",
        "ttylog",
        "sha256",
        "duplicate",
        "duration_ms",
        "tty_size"
    ])

    geoip_writer.writerow([
        "timestamp",
        "src_ip",
        "country",
        "country_code",
        "asn",
        "organization"
    ])

    direct_writer.writerow([
        "timestamp",
        "src_ip",
        "session",
        "event_type",
        "dst_ip",
        "dst_port",
        "message",
        "ja4h"
    ])

    # --------------------------------------------------
    # GeoIP Database
    # --------------------------------------------------

    country_reader = None
    asn_reader = None

    try:
        import geoip2.database

        country_db = BASE_DIR / "databases" / "GeoLite2-Country.mmdb"
        asn_db = BASE_DIR / "databases" / "GeoLite2-ASN.mmdb"

        country_reader = geoip2.database.Reader(str(country_db))
        asn_reader = geoip2.database.Reader(str(asn_db))

    except Exception as exc:
        print(f"WARNING : GeoIP database unavailable: {exc}")

    # --------------------------------------------------
    # Single-Pass JSON Processing
    # --------------------------------------------------

    with open(RAW_LOG, "r", encoding="utf-8") as logfile:

        for line in logfile:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                invalid_events += 1
                continue

            total_events += 1

            eventid = event.get("eventid", "")
            timestamp = event.get("timestamp", "")
            ip = event.get("src_ip", "")
            session = event.get("session")

            # ==================================================
            # Failed Login
            # ==================================================

            if eventid == "cowrie.login.failed":

                failed_writer.writerow([
                    timestamp,
                    ip,
                    event.get("username", ""),
                    event.get("password", "")
                ])

                failed_count += 1

                if ip:
                    stats[ip]["failed_login"] += 1
                    scores[ip] += weights["failed_login"]

            # ==================================================
            # Successful Login
            # ==================================================

            elif eventid == "cowrie.login.success":

                success_writer.writerow([
                    timestamp,
                    ip,
                    event.get("username", ""),
                    event.get("password", "")
                ])

                success_count += 1

                if ip:
                    stats[ip]["successful_login"] += 1
                    scores[ip] += weights["successful_login"]

            # ==================================================
            # Command Input
            # ==================================================

            elif eventid == "cowrie.command.input":

                command = event.get("input", "") or ""

                commands_writer.writerow([
                    timestamp,
                    ip,
                    session or "",
                    command
                ])

                command_count += 1

                if ip:
                    stats[ip]["commands"] += 1
                    scores[ip] += weights["commands"]

                # ------------------------------------------
                # File Transfer Detection
                # ------------------------------------------

                command_lower = command.lower()

                if any(keyword in command_lower for keyword in transfer_keywords):

                    transfers_writer.writerow([
                        timestamp,
                        ip,
                        session or "",
                        command
                    ])

                    file_transfer_count += 1

                # ------------------------------------------
                # Malware Activity Detection
                # ------------------------------------------

                if any(keyword in command_lower for keyword in malware_keywords):

                    malware_writer.writerow([
                        timestamp,
                        ip,
                        session or "",
                        command
                    ])

                    malware_count += 1

            # ==================================================
            # Session Connect
            # ==================================================

            elif eventid == "cowrie.session.connect":

                if session:

                    if session not in sessions:
                        sessions[session] = {
                            "src_ip": ip,
                            "start_time": timestamp,
                            "end_time": "",
                            "commands": 0
                        }

            # ==================================================
            # Session Closed
            # ==================================================

            elif eventid == "cowrie.session.closed":

                if session:

                    if session not in sessions:
                        sessions[session] = {
                            "src_ip": ip,
                            "start_time": "",
                            "end_time": timestamp,
                            "commands": 0
                        }
                    else:
                        sessions[session]["end_time"] = timestamp

            # ==================================================
            # File Upload
            # ==================================================

            elif eventid == "cowrie.session.file_upload":

                uploads_writer.writerow([
                    timestamp,
                    ip,
                    session or "",
                    event.get("filename", ""),
                    event.get("shasum", ""),
                    event.get("duplicate", ""),
                    event.get("destfile", "")
                ])

                file_upload_count += 1

                if ip:
                    stats[ip]["file_upload"] += 1
                    scores[ip] += weights["file_upload"]

            # ==================================================
            # File Download
            # ==================================================

            elif eventid == "cowrie.session.file_download":

                if ip:
                    stats[ip]["file_transfer"] += 1
                    scores[ip] += weights["file_transfer"]

            # ==================================================
            # Failed File Download / Malware
            # ==================================================

            elif eventid == "cowrie.session.file_download.failed":

                if ip:
                    stats[ip]["malware"] += 1
                    scores[ip] += weights["malware"]

            # ==================================================
            # Campaign
            # ==================================================

            elif eventid == "cowrie.log.closed":

                campaign_writer.writerow([
                    timestamp,
                    ip,
                    session or "",
                    event.get("ttylog", ""),
                    event.get("shasum", ""),
                    event.get("duplicate", ""),
                    event.get("duration_ms", ""),
                    event.get("size", "")
                ])

                campaign_count += 1

                if ip:
                    stats[ip]["campaign"] += 1
                    scores[ip] += weights["campaign"]

            # ==================================================
            # Client Fingerprinting
            # ==================================================

            if session:

                if session not in fingerprints:

                    fingerprints[session] = {
                        "timestamp": timestamp,
                        "src_ip": ip,
                        "session": session,
                        "client_version": "",
                        "hassh": "",
                        "terminal_width": "",
                        "terminal_height": ""
                    }

                if eventid == "cowrie.client.version":

                    fingerprints[session]["client_version"] = event.get(
                        "version", ""
                    )

                    if ip:
                        stats[ip]["client_fingerprint"] += 1

                elif eventid == "cowrie.client.kex":

                    fingerprints[session]["hassh"] = event.get(
                        "hassh", ""
                    )

                elif eventid == "cowrie.client.size":

                    fingerprints[session]["terminal_width"] = event.get(
                        "width", ""
                    )

                    fingerprints[session]["terminal_height"] = event.get(
                        "height", ""
                    )

            # ==================================================
            # Direct TCP/IP
            # ==================================================

            if eventid in (
                "cowrie.direct-tcpip.request",
                "cowrie.direct-tcpip.data",
                "cowrie.direct-tcpip.ja4h"
            ):

                direct_writer.writerow([
                    timestamp,
                    ip,
                    session or "",
                    eventid,
                    event.get("dst_ip", ""),
                    event.get("dst_port", ""),
                    event.get("message", ""),
                    event.get("ja4h", "")
                ])

                direct_tcpip_count += 1

                if eventid == "cowrie.direct-tcpip.request" and ip:
                    stats[ip]["direct_tcpip"] += 1
                    scores[ip] += weights["direct_tcpip"]

            # ==================================================
            # GeoIP / ASN
            # ==================================================

            if ip and ip not in seen_ips:

                seen_ips.add(ip)

                country_name = "Unknown"
                country_code = ""
                asn_number = ""
                organization = ""

                if country_reader:

                    try:
                        country = country_reader.country(ip)
                        country_name = country.country.name or "Unknown"
                        country_code = country.country.iso_code or ""
                    except Exception:
                        pass

                if asn_reader:

                    try:
                        asn = asn_reader.asn(ip)
                        asn_number = asn.autonomous_system_number
                        organization = asn.autonomous_system_organization or ""
                    except Exception:
                        pass

                geoip_writer.writerow([
                    timestamp,
                    ip,
                    country_name,
                    country_code,
                    asn_number,
                    organization
                ])

                geoip_count += 1

    # --------------------------------------------------
    # Close GeoIP Readers
    # --------------------------------------------------

    if country_reader:
        country_reader.close()

    if asn_reader:
        asn_reader.close()


# --------------------------------------------------
# Complete Session Command Counts
# --------------------------------------------------

# The command events were already processed in the same pass.
# Count them per session from the command output without
# loading the original JSON dataset.

session_command_counts = defaultdict(int)

if commands_file.exists():

    with open(commands_file, "r", encoding="utf-8", newline="") as f:

        reader = csv.DictReader(f)

        for row in reader:
            session = row.get("session", "")

            if session:
                session_command_counts[session] += 1

for session, data in sessions.items():
    data["commands"] = session_command_counts.get(session, 0)


# --------------------------------------------------
# Write Session Summary
# --------------------------------------------------

with open(sessions_file, "w", newline="", encoding="utf-8") as csvfile:

    writer = csv.writer(csvfile)

    writer.writerow([
        "session",
        "src_ip",
        "start_time",
        "end_time",
        "commands"
    ])

    for session, data in sessions.items():

        writer.writerow([
            session,
            data["src_ip"],
            data["start_time"],
            data["end_time"],
            data["commands"]
        ])

session_count = len(sessions)


# --------------------------------------------------
# Write Client Fingerprints
# --------------------------------------------------

with open(fingerprint_file, "w", newline="", encoding="utf-8") as csvfile:

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

    client_count = 0

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

            client_count += 1


# --------------------------------------------------
# Write Threat Scores
# --------------------------------------------------

threat_fieldnames = [
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

    total_ip_events = (
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
        "total_events": total_ip_events,
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

with open(threat_file, "w", newline="", encoding="utf-8") as csvfile:

    writer = csv.DictWriter(
        csvfile,
        fieldnames=threat_fieldnames
    )

    writer.writeheader()
    writer.writerows(rows)

threat_score_count = len(rows)


# --------------------------------------------------
# Generate ACL
# --------------------------------------------------

generate_acl(
    threat_file,
    OUTPUT_DIR / "generated_acl.cfg"
)


# --------------------------------------------------
# Summary
# --------------------------------------------------

print(f"\nLoaded Events : {total_events}")

if invalid_events:
    print(f"Invalid JSON Lines : {invalid_events}")

print("\n" + "=" * 60)
print("Threat Intelligence Summary")
print("=" * 60)

print(f"Failed Login Events      : {failed_count}")
print(f"Successful Login Events  : {success_count}")
print(f"Command Events           : {command_count}")
print(f"Sessions                 : {session_count}")
print(f"File Transfers           : {file_transfer_count}")
print(f"Malware Activities       : {malware_count}")
print(f"Client Fingerprints      : {client_count}")
print(f"Campaign Records         : {campaign_count}")
print(f"File Uploads             : {file_upload_count}")
print(f"GeoIP / ASN Records      : {geoip_count}")
print(f"Direct TCP/IP Events     : {direct_tcpip_count}")
print(f"Threat Scores            : {threat_score_count}")

print("\nGenerated Files")

print("✔ failed_logins.csv")
print("✔ successful_logins.csv")
print("✔ commands.csv")
print("✔ session_summary.csv")
print("✔ file_transfers.csv")
print("✔ malware_activity.csv")
print("✔ client_fingerprint.csv")
print("✔ campaign_summary.csv")
print("✔ file_uploads.csv")
print("✔ geoip_asn.csv")
print("✔ direct_tcpip.csv")
print("✔ threat_scores.csv")
print("✔ generated_acl.cfg")

print("\nThreat Intelligence Engine Completed Successfully.")
