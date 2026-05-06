#!/usr/bin/env python3
"""Quick test of DB schema and version matching on existing data"""

from cve_service_collector import init_db, find_matching_cves

def main():
    print("=" * 70)
    print("DB Schema & Version Matching Test (from existing data)")
    print("=" * 70)

    # Init DB
    print("\n[1] Connecting to database...")
    try:
        conn = init_db("localhost", 5432, "My_Project", "postgres", "vanduc0201")
        print("    OK - Connected and schema migrated")
    except Exception as e:
        print(f"    ERROR: {e}")
        return

    # Check table structure
    print("\n[2] Checking CVE table structure...")
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'cves' 
                ORDER BY ordinal_position
            """)
            cols = cur.fetchall()
            print(f"    Total columns: {len(cols)}")
            for col_name, col_type in cols[:10]:
                print(f"      - {col_name}: {col_type}")
            if len(cols) > 10:
                print(f"      ... and {len(cols) - 10} more")
    except Exception as e:
        print(f"    ERROR: {e}")

    # Check data in DB
    print("\n[3] Checking data in DB...")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cves")
            total = cur.fetchone()[0]
            print(f"    Total CVE records: {total}")
            
            cur.execute("""
                SELECT COUNT(*) FROM cves 
                WHERE version_constraints IS NOT NULL AND version_constraints != '[]'
            """)
            with_constraints = cur.fetchone()[0]
            print(f"    With version constraints: {with_constraints}")
    except Exception as e:
        print(f"    ERROR: {e}")

    # Test version matching on existing data
    print("\n[4] Testing version matching on existing data...")
    services_to_test = ["openssh", "vsftpd", "bind"]
    
    for service in services_to_test:
        print(f"\n    Service: {service}")
        try:
            # Get all CVEs for this service
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM cves WHERE service_name = %s",
                    (service,)
                )
                count = cur.fetchone()[0]
                print(f"      Total CVEs in DB: {count}")
            
            # Test version matching
            test_versions = ["1.0", "2.0", "4.7p1"]
            for version in test_versions:
                matches = find_matching_cves(conn, service, version)
                if matches:
                    print(f"      Version {version}: {len(matches)} match(es)")
                    for cve in matches[:1]:
                        print(f"        - {cve['cve_id']} | fix: {cve.get('fixed_version', 'unknown')}")
        except Exception as e:
            print(f"      ERROR: {e}")

    conn.close()
    print("\n" + "=" * 70)
    print("Test completed!")
    print("=" * 70)

if __name__ == "__main__":
    main()
