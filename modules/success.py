"""
Successful Login Parser

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement
"""

import pandas as pd


def extract_success(events, output_dir):

    df = pd.DataFrame(events)

    if df.empty:
        print("No events found.")
        return 0

    success = df[df["eventid"] == "cowrie.login.success"].copy()

    if success.empty:
        success.to_csv(
            output_dir / "successful_logins.csv",
            index=False
        )
        return 0

    columns = [
        "timestamp",
        "src_ip",
        "username",
        "password"
    ]

    success = success.reindex(columns=columns)

    success.to_csv(
        output_dir / "successful_logins.csv",
        index=False
    )

    return len(success)
