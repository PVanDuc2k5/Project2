#!/usr/bin/env python3
"""Test NVD + CISA KEV integration with PostgreSQL"""

import time

from cve_service_collector import fetch_cves_multisource, init_db, upsert_cves


def main():
    print("=" * 60)
    print("NVD + CISA KEV Integration Test")
    print("=" * 60)

    # Init DB
    print("\n[1] Initializing PostgreSQL database...")
    try:
        conn = init_db("localhost", 5432, "My_Project", "postgres", "vanduc0201")
        print("  OK - Connected to My_Project database")
    except Exception as e:
        print(f"  ERROR: {e}")
        return

    # Test with one service (vsftpd has proven to work)
    service = "vsftpd"

    print(f"\n[2] Fetching CVEs for '{service}' from NVD+CISA...")
    start = time.time()
    cves = fetch_cves_multisource(service)
    elapsed = time.time() - start

    print(f"  Found: {len(cves)} CVE records in {elapsed:.2f}s")

    if cves:
        # Show stats
        refs_total = sum(len(c.get('reference_links', [])) for c in cves)
        kev_count = sum(1 for c in cves if c.get('cisa_kev'))
        nvd_count = sum(1 for c in cves if c.get('source') == 'nvd.nist.gov')
        version_scoped = sum(1 for c in cves if c.get('version_constraints'))

        print(f"  - Total reference links: {refs_total}")
        print(f"  - CISA KEV exploited: {kev_count}")
        print(f"  - From NVD: {nvd_count}")
        print(f"  - With version constraints: {version_scoped}")

        print(f"\n  First 3 records:")
        for i, cve in enumerate(cves[:3], 1):
            refs = len(cve.get('reference_links', []))
            kev = " [CISA KEV]" if cve.get('cisa_kev') else ""
            fixed = cve.get('fixed_version') or ""
            note = f" | fix >= {fixed}" if fixed else ""
            print(f"    {i}. {cve.get('cve_id')}: {refs} refs{kev}{note}")

        # Store in DB
        print(f"\n[3] Upserting {len(cves)} records into database...")
        inserted = upsert_cves(conn, service, cves, 2000, 2024)
        print(f"  Inserted/Updated: {inserted} records")

    conn.close()
    print("\n[4] Test completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
