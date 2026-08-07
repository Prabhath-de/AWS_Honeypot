"""
Failed Login Parser

Research:
Dynamic Network Defense Rule Generation Using
Cowrie Honeypot Data with Automated Cisco ACL Enforcement
"""

import pandas as pd


def extract_failed(events, output_dir):

    df = pd.DataFrame(events)

    if df.empty:
        print("No events found.")
        return 0

    failed = df[df["eventid"] == "cowrie.login.failed"].copy()

    if failed.empty:
        failed.to_csv(
            output_dir / "failed_logins.csv",
            index=False
        )
        return 0

    columns = [
        "timestamp",
        "src_ip",
        "username",
        "password"
    ]

    failed = failed.reindex(columns=columns)

    failed.to_csv(
        output_dir / "failed_logins.csv",
        index=False
    )

    return len(failed)
