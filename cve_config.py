from typing import Any, Dict

API_TEMPLATE = "https://cve.circl.lu/api/search/{service}/{service}"
POC_KEYWORDS = (
    "poc",
    "exploit-db",
    "packetstorm",
    "metasploit",
    "github.com",
    "0day",
)

DEFAULT_PGHOST = "localhost"
DEFAULT_PGPORT = 5432
DEFAULT_PGDATABASE = "My_Project"
DEFAULT_PGUSER = "postgres"
DEFAULT_PGPASSWORD = "vanduc0201"

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/vulnerabilities.json"

# Cache for CISA KEV data (loaded once at startup).
CISA_KEV_CACHE: Dict[str, Dict[str, Any]] = {}
