#!/usr/bin/env python3
"""Quick test of version matching logic without nmap"""

from cve_service_collector import init_db, find_matching_cves, fetch_cves_multisource, upsert_cves

def main():
    print("=" * 70)
    print("Version Matching Test (Quick)")
    print("=" * 70)

    # Init DB
    print("\n[1] Connecting to database...")
    try:
        conn = init_db("localhost", 5432, "My_Project", "postgres", "vanduc0201")
        print("    OK - Connected")
    except Exception as e:
        print(f"    ERROR: {e}")
        return

    # Fetch CVEs for a service
    print("\n[2] Fetching CVEs for 'openssh' from NVD...")
    try:
        cves = fetch_cves_multisource("openssh")
        print(f"    Found {len(cves)} CVEs")
        
        # Count those with version constraints
        with_constraints = sum(1 for c in cves if c.get("version_constraints") and c.get("version_constraints") != "[]")
        print(f"    With version constraints: {with_constraints}")
        
        # Upsert into DB
        print("\n[3] Upserting CVEs into database...")
        saved = upsert_cves(conn, "openssh", cves, 2000, 2024, service_version="")
        print(f"    Saved/Updated: {saved} records")
        
        # Test version matching
        print("\n[4] Testing version matching:")
        test_versions = ["4.6p1", "4.7p1", "5.0", "6.0", "7.0", "8.0"]
        
        for version in test_versions:
            matches = find_matching_cves(conn, "openssh", version)
            if matches:
                print(f"\n    Version {version}: {len(matches)} CVE(s) matching")
                for cve in matches[:2]:
                    rec = cve.get("recommendation", "")
                    fixed = cve.get("fixed_version", "")
                    print(f"      - {cve['cve_id']}")
                    if fixed:
                        print(f"        Fix: >= {fixed}")
                    if rec:
                        print(f"        Recommendation: {rec}")
            else:
                print(f"\n    Version {version}: No CVE found")
        
    except Exception as e:
        print(f"    ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

    print("\n" + "=" * 70)
    print("Test completed!")
    print("=" * 70)

if __name__ == "__main__":
    main()
