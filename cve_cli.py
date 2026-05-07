import argparse
import time

import requests

from cve_config import (
    DEFAULT_PGDATABASE,
    DEFAULT_PGHOST,
    DEFAULT_PGPASSWORD,
    DEFAULT_PGPORT,
    DEFAULT_PGUSER,
)
from cve_db import create_scan_run, finish_scan_run, init_db, upsert_cves
from cve_sources import fetch_cves_for_service


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect CVEs by service name and store them in PostgreSQL."
    )
    parser.add_argument(
        "--services",
        required=True,
        help="Comma-separated service names, e.g. samba,php,mysql,tomcat",
    )
    parser.add_argument("--start-year", type=int, default=2015)
    parser.add_argument("--end-year", type=int, default=2026)
    parser.add_argument("--pg-host", default=DEFAULT_PGHOST, help="PostgreSQL host")
    parser.add_argument("--pg-port", type=int, default=DEFAULT_PGPORT, help="PostgreSQL port")
    parser.add_argument("--pg-db", default=DEFAULT_PGDATABASE, help="PostgreSQL database name")
    parser.add_argument("--pg-user", default=DEFAULT_PGUSER, help="PostgreSQL username")
    parser.add_argument("--pg-password", default=DEFAULT_PGPASSWORD, help="PostgreSQL password")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.4,
        help="Delay in seconds between service API requests",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    services = [s.strip().lower() for s in args.services.split(",") if s.strip()]

    if not services:
        raise SystemExit("No valid services provided.")

    conn = init_db(
        args.pg_host,
        args.pg_port,
        args.pg_db,
        args.pg_user,
        args.pg_password,
    )

    print(f"[*] Start collecting CVEs for {len(services)} service(s)")
    print(f"[*] Year range: {args.start_year} -> {args.end_year}")
    print(f"[*] PostgreSQL: {args.pg_user}@{args.pg_host}:{args.pg_port}/{args.pg_db}")

    total_fetched = 0
    total_saved = 0

    for service in services:
        run_id = create_scan_run(conn, service)
        print(f"\n[*] Service: {service}")
        try:
            cves = fetch_cves_for_service(service)
            fetched = len(cves)
            saved = upsert_cves(conn, service, cves, args.start_year, args.end_year)
            finish_scan_run(conn, run_id, fetched, saved, "ok")

            total_fetched += fetched
            total_saved += saved
            print(f"    - fetched: {fetched}")
            print(f"    - saved in range: {saved}")
        except requests.RequestException as e:
            finish_scan_run(conn, run_id, 0, 0, "error", str(e))
            print(f"    - error: {e}")

        time.sleep(args.delay)

    print("\n[+] Done")
    print(f"    - total fetched: {total_fetched}")
    print(f"    - total saved: {total_saved}")
