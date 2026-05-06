import time

from cve_service_collector import (
    _constraint_matches_version,
    _load_version_constraints,
    fetch_cves_multisource,
)


def check_cve(product, service_version=""):
    if not product:
        print("Bỏ qua vì không có tên dịch vụ.")
        return

    service_name = product.split()[0].lower()
    try:
        cves = fetch_cves_multisource(service_name)
        matched = []
        for cve in cves:
            constraints = _load_version_constraints(cve.get("version_constraints"))
            if service_version and constraints:
                if not any(_constraint_matches_version(service_version, constraint) for constraint in constraints):
                    continue
            matched.append(cve)

        if matched:
            for cve in matched:
                recommendation = cve.get("recommendation") or ""
                fixed_version = cve.get("fixed_version") or ""
                extra = f" | fix: {fixed_version}" if fixed_version else ""
                note = f" | {recommendation}" if recommendation else ""
                print(f"\n{cve.get('cve_id')}{extra}{note}")
        else:
            if service_version:
                print("Không tìm thấy CVE khớp version trong nguồn dữ liệu.")
            else:
                print("Không tìm thấy CVE phù hợp trong nguồn dữ liệu.")
    except Exception as e:
        print(f"Đã xảy ra sự cố mạng: {e}")
        time.sleep(1) 