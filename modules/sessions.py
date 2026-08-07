"""
Session Analysis Module

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement
"""

import pandas as pd


def extract_sessions(events, output_dir):

    df = pd.DataFrame(events)

    if df.empty:
        print("No events found.")
        return 0

    # Session started
    connects = df[df["eventid"] == "cowrie.session.connect"].copy()

    # Session closed
    closes = df[df["eventid"] == "cowrie.session.closed"].copy()

    # Commands
    commands = df[df["eventid"] == "cowrie.command.input"].copy()

    summary = []

    for session in connects["session"].unique():

        connect = connects[connects["session"] == session]

        close = closes[closes["session"] == session]

        cmd = commands[commands["session"] == session]

        start = connect.iloc[0]["timestamp"]

        end = ""

        if not close.empty:
            end = close.iloc[-1]["timestamp"]

        src_ip = connect.iloc[0]["src_ip"]

        summary.append({

            "session": session,
            "src_ip": src_ip,
            "start_time": start,
            "end_time": end,
            "commands": len(cmd)

        })

    result = pd.DataFrame(summary)

    result.to_csv(
        output_dir / "session_summary.csv",
        index=False
    )

    return len(result)
