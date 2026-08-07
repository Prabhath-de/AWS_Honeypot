#!/usr/bin/env python3

import csv
import geoip2.database

COUNTRY_DB = "databases/GeoLite2-Country.mmdb"
ASN_DB = "databases/GeoLite2-ASN.mmdb"


def extract_geoip_asn(events, output_dir):

    country_reader = geoip2.database.Reader(COUNTRY_DB)
    asn_reader = geoip2.database.Reader(ASN_DB)

    output_file = output_dir / "geoip_asn.csv"

    count = 0

    with open(output_file, "w", newline="") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "timestamp",
            "src_ip",
            "country",
            "country_code",
            "asn",
            "organization"
        ])

        seen = set()

        for event in events:

            ip = event.get("src_ip")

            if not ip:
                continue

            if ip in seen:
                continue

            seen.add(ip)

            try:
                country = country_reader.country(ip)

                country_name = country.country.name or "Unknown"
                country_code = country.country.iso_code or ""

            except Exception:

                country_name = "Unknown"
                country_code = ""

            try:

                asn = asn_reader.asn(ip)

                asn_number = asn.autonomous_system_number
                organization = asn.autonomous_system_organization

            except Exception:

                asn_number = ""
                organization = ""

            writer.writerow([
                event.get("timestamp"),
                ip,
                country_name,
                country_code,
                asn_number,
                organization
            ])

            count += 1

    country_reader.close()
    asn_reader.close()

    print(f"GeoIP / ASN Records      : {count}")
    print("✔ geoip_asn.csv")

    return count
