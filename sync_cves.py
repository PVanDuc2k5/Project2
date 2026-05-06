#!/usr/bin/env python3
"""Sync CVEs from remote sources into PostgreSQL before running the scanner."""

import argparse
import time

from cve_service_collector import fetch_cves_multisource, init_db, upsert_cves


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch CVEs and store them in PostgreSQL.")
    parser.add_argument(
        "--services",
        required=True,
        help="Comma-separated service names, e.g. vsftpd,openssh,postfix,samba",
    )
    parser.add_argument("--start-year", type=int, default=2015)
    parser.add_argument("--end-year", type=int, default=2026)
    parser.add_argument("--pg-host", default="localhost")
    parser.add_argument("--pg-port", type=int, default=5432)
    parser.add_argument("--pg-db", default="My_Project")
    parser.add_argument("--pg-user", default="postgres")
    parser.add_argument("--pg-password", default="vanduc0201")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    services = [service.strip().lower() for service in args.services.split(",") if service.strip()]

    if not services:
        raise SystemExit("No valid services provided.")

    conn = init_db(args.pg_host, args.pg_port, args.pg_db, args.pg_user, args.pg_password)
    try:
        print(f"[*] Sync CVE cache for {len(services)} service(s)")
        print(f"[*] Year range: {args.start_year} -> {args.end_year}")

        total_fetched = 0
        total_saved = 0

        for service in services:
            print(f"\n[*] {service}")
            start = time.time()
            cves = fetch_cves_multisource(service)
            fetched = len(cves)
            saved = upsert_cves(conn, service, cves, args.start_year, args.end_year)
            elapsed = time.time() - start

            total_fetched += fetched
            total_saved += saved

            print(f"  - fetched: {fetched}")
            print(f"  - saved: {saved}")
            print(f"  - elapsed: {elapsed:.2f}s")

        print("\n[+] Sync complete")
        print(f"  - total fetched: {total_fetched}")
        print(f"  - total saved: {total_saved}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()