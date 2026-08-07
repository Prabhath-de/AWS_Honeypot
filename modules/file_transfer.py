"""
File Transfer Detection Module

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement
"""

import pandas as pd


def extract_file_transfers(events, output_dir):

    df = pd.DataFrame(events)

    if df.empty:
        print("No events found.")
        return 0

    # Cowrie command events
    commands = df[df["eventid"] == "cowrie.command.input"].copy()

    if commands.empty:

        commands.to_csv(
            output_dir / "file_transfers.csv",
            index=False
        )

        return 0

    keywords = [
        "scp",
        "wget",
        "curl",
        "ftp",
        "tftp",
        "sftp"
    ]

    transfers = commands[
        commands["input"].fillna("").str.contains(
            "|".join(keywords),
            case=False,
            regex=True
        )
    ].copy()

    columns = [
        "timestamp",
        "src_ip",
        "session",
        "input"
    ]

    transfers = transfers.reindex(columns=columns)

    transfers.rename(
        columns={"input": "command"},
        inplace=True
    )

    transfers.to_csv(
        output_dir / "file_transfers.csv",
        index=False
    )

    return len(transfers)
