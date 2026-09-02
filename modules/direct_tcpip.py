import csv

def extract_direct_tcpip(events, output_dir):
    output_file = output_dir / "direct_tcpip.csv"
    count = 0

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

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            eventid = event.get("eventid", "")

            if eventid not in (
                "cowrie.direct-tcpip.request",
                "cowrie.direct-tcpip.data",
                "cowrie.direct-tcpip.ja4h"
            ):
                continue

            writer.writerow({
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "session": event.get("session", ""),
                "event_type": eventid,
                "dst_ip": event.get("dst_ip", ""),
                "dst_port": event.get("dst_port", ""),
                "message": event.get("message", ""),
                "ja4h": event.get("ja4h", "")
            })

            count += 1

    print(f"Direct TCP/IP Events      : {count}")
    print("✔ direct_tcpip.csv")
    return count
