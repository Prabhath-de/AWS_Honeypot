import csv


def extract_direct_tcpip(events, output_dir):

    rows = []

    for event in events:

        eventid = event.get("eventid", "")

        if eventid not in (
            "cowrie.direct-tcpip.request",
            "cowrie.direct-tcpip.data",
            "cowrie.direct-tcpip.ja4h"
        ):
            continue

        row = {
            "timestamp": event.get("timestamp", ""),
            "src_ip": event.get("src_ip", ""),
            "session": event.get("session", ""),
            "event_type": eventid,
            "dst_ip": event.get("dst_ip", ""),
            "dst_port": event.get("dst_port", ""),
            "message": event.get("message", ""),
            "ja4h": event.get("ja4h", "")
        }

        rows.append(row)

    output_file = output_dir / "direct_tcpip.csv"

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:

        fieldnames = [
            "timestamp",
            "src_ip",
            "session",
            "event_type",
            "dst_ip",
            "dst_port",
            "message",
            "ja4h"
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        writer.writerows(rows)

    print(f"Direct TCP/IP Events      : {len(rows)}")
    print("✔ direct_tcpip.csv")

    return len(rows)
