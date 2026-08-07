"""
Command Parser

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement
"""

import pandas as pd


def extract_commands(events, output_dir):

    df = pd.DataFrame(events)

    if df.empty:
        print("No events found.")
        return 0

    commands = df[df["eventid"] == "cowrie.command.input"].copy()

    if commands.empty:
        commands.to_csv(
            output_dir / "commands.csv",
            index=False
        )
        return 0

    columns = [
        "timestamp",
        "src_ip",
        "session",
        "input"
    ]

    commands = commands.reindex(columns=columns)

    commands = commands.rename(
        columns={
            "input": "command"
        }
    )

    commands.to_csv(
        output_dir / "commands.csv",
        index=False
    )

    return len(commands)
