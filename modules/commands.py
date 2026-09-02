import csv

def extract_commands(events, output_dir):
    output_file = output_dir / "commands.csv"
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

            writer.writerow([
                event.get("timestamp", ""),
                event.get("src_ip", ""),
                event.get("session", ""),
                event.get("input", "")
            ])
            count += 1

    return count
