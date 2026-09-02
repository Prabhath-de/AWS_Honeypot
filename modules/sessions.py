import csv

def extract_sessions(events, output_dir):
    output_file = output_dir / "session_summary.csv"

    sessions = {}

    for event in events:
        eventid = event.get("eventid", "")
        session = event.get("session")

        if not session:
            continue

        if session not in sessions:
            sessions[session] = {
                "src_ip": "",
                "start_time": "",
                "end_time": "",
                "commands": 0
            }

        if eventid == "cowrie.session.connect":
            sessions[session]["src_ip"] = event.get("src_ip", "")
            sessions[session]["start_time"] = event.get("timestamp", "")

        elif eventid == "cowrie.session.closed":
            sessions[session]["end_time"] = event.get("timestamp", "")

        elif eventid == "cowrie.command.input":
            sessions[session]["commands"] += 1

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
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

    return len(sessions)
