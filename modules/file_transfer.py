import csv

def extract_file_transfers(events, output_dir):
    output_file = output_dir / "file_transfers.csv"
    keywords = ["scp", "wget", "curl", "ftp", "tftp", "sftp"]
    count = 0

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            "timestamp",
            "src_ip",
            "session",
            "command"
        ])

        for event in events:
            if event.get("eventid") != "cowrie.command.input":
                continue

            command = event.get("input", "") or ""

            if not any(keyword.lower() in command.lower()
                       for keyword in keywords):
                continue

            writer.writerow([
                event.get("timestamp", ""),
                event.get("src_ip", ""),
                event.get("session", ""),
                command
            ])
            count += 1

    return count
