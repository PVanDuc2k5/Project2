import test_api
from exploits import exploiter

from cve_service_collector import fetch_cves_multisource, init_db, upsert_cves


def main():
    ip = input("Nhập địa chỉ IP cần quét: ")
    print(f"[*] Đang quét {ip}...")
    ports = test_api.my_scanner.run_nmap_scan(ip)
    print(f"[*] Quét xong, tìm thấy {len(ports)} cổng/dịch vụ mở.")

    if not ports:
        print("[-] Không tìm thấy dịch vụ mở nào. Kiểm tra lại IP, máy mục tiêu, hoặc mạng VM/lab.")
        return

    conn = init_db("localhost", 5432, "My_Project", "postgres", "vanduc0201")
    try:
        for port in ports:
            product = port.get("product", "").strip()
            service_name = product.split()[0].lower() if product else ""

            print(f"---------------\nCổng {port['port']} - {product}")
            test_api.check_cve(product)

            if service_name:
                try:
                    cves = fetch_cves_multisource(service_name)
                    saved = upsert_cves(conn, service_name, cves, 2015, 2026)
                    print(f"[+] Đồng bộ DB: {saved} CVE cho service '{service_name}'")
                except Exception as db_error:
                    print(f"[-] Không đồng bộ được CVE vào DB: {db_error}")

            #exploiter.check_and_exploit(ip, port['port'], product)
    finally:
        conn.close()


if __name__ == "__main__":
    main()