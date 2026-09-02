import csv

def extract_failed(events, output_dir):
    output_file = output_dir / "failed_logins.csv"
    count = 0

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "timestamp",
            "src_ip",
            "username",
            "password"
        ])

        for event in events:
            if event.get("eventid") != "cowrie.login.failed":
                continue

            writer.writerow([
                event.get("timestamp", ""),
                event.get("src_ip", ""),
                event.get("username", ""),
                event.get("password", "")
            ])
            count += 1

    return count
