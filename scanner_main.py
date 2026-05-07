import my_scanner

from cve_db import find_matching_cves, init_db


def _format_port_line(port_info: dict) -> str:
    port = port_info.get("port", "?")
    product = port_info.get("product", "").strip() or "unknown"
    version = port_info.get("version", "").strip() or "unknown"
    return f"Port {port}: {product} | version {version}"


def _count_cached_cves(conn, service_name: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM cves WHERE service_name = %s", (service_name,))
        return int(cur.fetchone()[0])


def main():
    ip = input("Nhập địa chỉ IP cần quét: ")
    print(f"[*] Scan {ip}")
    ports = my_scanner.run_nmap_scan(ip)
    print(f"[*] Open services: {len(ports)}")

    if not ports:
        print("[-] No open services found.")
        return

    conn = init_db("localhost", 5432, "My_Project", "postgres", "vanduc0201")
    try:
        for port in ports:
            product = port.get("product", "").strip()
            service_name = product.split()[0].lower() if product else ""
            service_version = port.get("version", "").strip()

            print(_format_port_line(port))

            if not service_name:
                print("  - skipped: unknown service name")
                continue

            try:
                cached_count = _count_cached_cves(conn, service_name)
                if not cached_count:
                    print("  - no cached CVE data; run sync_cves.py first")
                    continue

                matches = find_matching_cves(conn, service_name, service_version)
                if matches:
                    top_matches = matches[:3]
                    cve_ids = ", ".join(cve.get("cve_id", "") for cve in top_matches)
                    print(f"  - CVE matches: {len(matches)} | top: {cve_ids}")
                    first = top_matches[0]
                    recommendation = first.get("recommendation") or ""
                    fixed_version = first.get("fixed_version") or ""
                    if fixed_version or recommendation:
                        note = fixed_version if fixed_version else recommendation
                        print(f"  - fix: {note}")
                else:
                    print(f"  - cached CVEs: {cached_count} | no exact version match")
            except Exception as db_error:
                print(f"  - error: {db_error}")

            #exploiter.check_and_exploit(ip, port['port'], product)
    finally:
        conn.close()


if __name__ == "__main__":
    main()