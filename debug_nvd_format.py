import requests
import json

# Test NVD API response structure
keyword = "vsftpd"
params = {
    "keywordSearch": keyword,
    "resultsPerPage": 5,
}
resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=15)

if resp.status_code == 200:
    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    
    print(f"Found {len(vulnerabilities)} vulnerabilities")
    
    if vulnerabilities:
        vuln = vulnerabilities[0]
        print("\nFirst vulnerability structure:")
        print(f"  Keys: {list(vuln.keys())}")
        
        cve_meta = vuln.get("cve", {})
        print(f"\n  CVE keys: {list(cve_meta.keys())}")
        print(f"  CVE ID: {cve_meta.get('id')}")
        
        # Check configurations structure
        configs = cve_meta.get("configurations")
        print(f"\n  Configurations type: {type(configs)}")
        if configs:
            print(f"  Configurations length: {len(configs)}")
            if isinstance(configs, list) and len(configs) > 0:
                print(f"  First config structure: {json.dumps(configs[0], indent=2)[:500]}")
else:
    print(f"Error: {resp.status_code}")
