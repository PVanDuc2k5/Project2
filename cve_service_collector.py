import argparse
import json
import re
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import psycopg2
import requests

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

# Cache for CISA KEV data (loaded once at startup)
_cisa_kev_cache: Dict[str, Dict[str, Any]] = {}


def fetch_from_nvd(keyword: str, timeout: int = 15) -> List[Dict[str, Any]]:
    """Search CVE from NVD API by keyword (service/product name). Returns list of CVE records."""
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 100,
        }
        resp = requests.get(NVD_API_BASE, params=params, timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        rows: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            cve_meta = vuln.get("cve", {})
            cve_id = cve_meta.get("id", "").strip()
            if not cve_id:
                continue

            desc_parts = []
            for desc_obj in cve_meta.get("descriptions", []):
                if desc_obj.get("lang") == "en":
                    desc_parts.append(desc_obj.get("value", ""))
            description = " ".join(desc_parts) if desc_parts else ""

            published = cve_meta.get("published", "")
            year = _to_year(cve_id, published)

            refs = []
            for ref in cve_meta.get("references", []):
                if isinstance(ref, dict) and "url" in ref:
                    refs.append(ref["url"])

            poc_refs = [r for r in refs if any(k in r.lower() for k in POC_KEYWORDS)]
            configurations = cve_meta.get("configurations", vuln.get("configurations", []))
            version_constraints = _extract_version_constraints(configurations)
            primary_constraint = version_constraints[0] if version_constraints else {}
            fixed_version = _extract_fixed_version(primary_constraint) if primary_constraint else ""
            recommendation = _build_recommendation("", primary_constraint) if primary_constraint else ""

            rows.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "published_date": published,
                    "year": year,
                    "affected_configurations": json.dumps(configurations, ensure_ascii=True),
                    "version_constraints": json.dumps(version_constraints, ensure_ascii=True),
                    "fixed_version": fixed_version,
                    "recommendation": recommendation,
                    "reference_links": refs,
                    "poc_references": poc_refs,
                    "source": "nvd.nist.gov",
                }
            )
        return rows
    except Exception:
        return []


def fetch_from_cisa_kev(cve_id: str, timeout: int = 10) -> Dict[str, Any]:
    """Check if a CVE is in CISA Known Exploited Vulnerabilities list (uses cache)."""
    if not _cisa_kev_cache:
        _init_cisa_kev_cache()
    return _cisa_kev_cache.get(cve_id.lower(), {})


def _init_cisa_kev_cache(timeout: int = 10) -> None:
    """Load all CISA KEV data into cache once."""
    global _cisa_kev_cache
    try:
        resp = requests.get(CISA_KEV_API, timeout=timeout)
        if resp.status_code != 200:
            return
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            cve_id = vuln.get("cveID", "").lower()
            if cve_id:
                _cisa_kev_cache[cve_id] = {
                    "dateAdded": vuln.get("dateAdded", ""),
                    "shortDescription": vuln.get("shortDescription", ""),
                    "requiredAction": vuln.get("requiredAction", ""),
                    "dueDate": vuln.get("dueDate", ""),
                }
    except Exception as e:
        print(f"[!] Failed to load CISA KEV cache: {e}")


def _version_key(version: str) -> List[int]:
    tokens = re.findall(r"\d+|[a-z]+", version.lower())
    key: List[int] = []
    for token in tokens:
        if token.isdigit():
            key.append(int(token))
        else:
            for char in token:
                key.append(100 + ord(char) - ord('a'))
    return key or [0]


def _compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    length = max(len(left_key), len(right_key))
    left_key = left_key + [0] * (length - len(left_key))
    right_key = right_key + [0] * (length - len(right_key))
    return (left_key > right_key) - (left_key < right_key)


def _extract_cpe_version(criteria: str) -> str:
    if not isinstance(criteria, str):
        return ""

    parts = criteria.split(":")
    if len(parts) > 5:
        version = parts[5].strip()
        if version and version not in {"*", "-"}:
            return version
    return ""


def _extract_version_constraints(nodes: Any) -> List[Dict[str, Any]]:
    constraints: List[Dict[str, Any]] = []

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return

        for match in node.get("cpeMatch", []):
            if not isinstance(match, dict):
                continue
            if match.get("vulnerable", True) is False:
                continue
            criteria = match.get("criteria", "")
            if not isinstance(criteria, str):
                criteria = str(criteria)
            constraints.append(
                {
                    "criteria": criteria,
                    "criteria_version": _extract_cpe_version(criteria),
                    "versionStartIncluding": match.get("versionStartIncluding", ""),
                    "versionStartExcluding": match.get("versionStartExcluding", ""),
                    "versionEndIncluding": match.get("versionEndIncluding", ""),
                    "versionEndExcluding": match.get("versionEndExcluding", ""),
                    "vulnerable": True,
                }
            )

        for child_nodes_key in ("nodes", "children"):
            for child in node.get(child_nodes_key, []):
                visit(child)

    if isinstance(nodes, list):
        for node in nodes:
            visit(node)

    return constraints


def _constraint_matches_version(version: str, constraint: Dict[str, Any]) -> bool:
    if not version:
        return False

    criteria_version = constraint.get("criteria_version") or ""
    start_including = constraint.get("versionStartIncluding") or ""
    start_excluding = constraint.get("versionStartExcluding") or ""
    end_including = constraint.get("versionEndIncluding") or ""
    end_excluding = constraint.get("versionEndExcluding") or ""

    if not any((start_including, start_excluding, end_including, end_excluding)):
        if criteria_version:
            return _compare_versions(version, str(criteria_version)) == 0
        return False

    if start_including and _compare_versions(version, str(start_including)) < 0:
        return False
    if start_excluding and _compare_versions(version, str(start_excluding)) <= 0:
        return False
    if end_including and _compare_versions(version, str(end_including)) > 0:
        return False
    if end_excluding and _compare_versions(version, str(end_excluding)) >= 0:
        return False
    return True


def _extract_fixed_version(constraint: Dict[str, Any]) -> str:
    fixed_version = constraint.get("versionEndExcluding") or constraint.get("versionEndIncluding") or ""
    return str(fixed_version)


def _build_recommendation(version: str, constraint: Dict[str, Any]) -> str:
    fixed_version = _extract_fixed_version(constraint)
    if fixed_version:
        comparator = ">" if constraint.get("versionEndIncluding") else ">="
        return f"Upgrade to version {comparator} {fixed_version}"
    if version:
        return f"Review vendor advisory for a fixed release newer than {version}"
    return "Review vendor advisory for a fixed release"


def init_db(host: str, port: int, database: str, user: str, password: str):
    conn = psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
    )
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                id BIGSERIAL PRIMARY KEY,
                cve_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                service_version TEXT,
                year INTEGER,
                description TEXT,
                affected_configurations TEXT,
                version_constraints TEXT,
                fixed_version TEXT,
                recommendation TEXT,
                match_status TEXT DEFAULT 'unknown',
                poc_code TEXT,
                poc_references TEXT,
                reference_links TEXT,
                published_date TEXT,
                last_modified TEXT,
                source TEXT NOT NULL,
                UNIQUE(cve_id, service_name)
            )
            """
        )
        # Add missing columns if they don't exist (migration for old schema)
        missing_columns = [
            ("service_version", "TEXT"),
            ("version_constraints", "TEXT"),
            ("fixed_version", "TEXT"),
            ("recommendation", "TEXT"),
            ("match_status", "TEXT DEFAULT 'unknown'"),
        ]
        for col_name, col_type in missing_columns:
            cur.execute(
                f"""
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'cves' AND column_name = '{col_name}'
                    ) THEN
                        ALTER TABLE cves ADD COLUMN {col_name} {col_type};
                    END IF;
                END $$;
                """
            )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id BIGSERIAL PRIMARY KEY,
                service_name TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                fetched_count INTEGER DEFAULT 0,
                inserted_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',
                note TEXT
            )
            """
        )
    conn.commit()
    return conn


def _extract_cve_id(item: Any) -> Optional[str]:
    if isinstance(item, list) and item:
        return str(item[0]).strip()

    if not isinstance(item, dict):
        return None

    for key in ("id", "cve", "cve_id", "CVE"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value.strip()

    metadata = item.get("cveMetadata")
    if isinstance(metadata, dict):
        value = metadata.get("cveId")
        if isinstance(value, str) and value:
            return value.strip()

    return None


def _extract_description(item: Any) -> str:
    if isinstance(item, list) and len(item) > 1:
        return str(item[1]).strip()

    if not isinstance(item, dict):
        return ""

    for key in ("summary", "description", "desc", "details"):
        value = item.get(key)
        if isinstance(value, str):
            return value.strip()

    descriptions = item.get("descriptions")
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, dict) and isinstance(entry.get("value"), str):
                return entry["value"].strip()

    return ""


def _extract_date(item: Any) -> str:
    if isinstance(item, list):
        return ""

    if not isinstance(item, dict):
        return ""

    for key in ("Published", "published", "published_date", "datePublished"):
        value = item.get(key)
        if isinstance(value, str):
            return value.strip()

    cve_meta = item.get("cveMetadata")
    if isinstance(cve_meta, dict):
        value = cve_meta.get("datePublished")
        if isinstance(value, str):
            return value.strip()

    return ""


def _extract_references(item: Any) -> List[str]:
    refs: List[str] = []

    if isinstance(item, list):
        return refs

    if not isinstance(item, dict):
        return refs

    ref_obj = item.get("references")
    if isinstance(ref_obj, list):
        for ref in ref_obj:
            if isinstance(ref, str):
                refs.append(ref.strip())
            elif isinstance(ref, dict):
                for key in ("url", "link", "href"):
                    value = ref.get(key)
                    if isinstance(value, str):
                        refs.append(value.strip())
    elif isinstance(ref_obj, dict):
        for value in ref_obj.values():
            if isinstance(value, list):
                for link in value:
                    if isinstance(link, str):
                        refs.append(link.strip())

    # Some feeds use this key for old CIRCL formats.
    vulnerable_refs = item.get("refmap")
    if isinstance(vulnerable_refs, dict):
        for values in vulnerable_refs.values():
            if isinstance(values, list):
                for link in values:
                    if isinstance(link, str):
                        refs.append(link.strip())

    clean_refs = []
    seen = set()
    for link in refs:
        if link and link not in seen:
            seen.add(link)
            clean_refs.append(link)
    return clean_refs


def _extract_configs(item: Any) -> str:
    if isinstance(item, list):
        return ""

    if not isinstance(item, dict):
        return ""

    for key in ("vulnerable_configuration", "vulnerable_product", "configurations"):
        value = item.get(key)
        if value is not None:
            try:
                return json.dumps(value, ensure_ascii=True)
            except TypeError:
                return str(value)

    return ""


def _to_year(cve_id: str, published_date: str) -> Optional[int]:
    # Prefer CVE format CVE-YYYY-NNNN..., then fallback to published date.
    parts = cve_id.split("-")
    if len(parts) >= 3 and parts[1].isdigit():
        return int(parts[1])

    if published_date:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return datetime.strptime(published_date[:26], fmt).year
            except ValueError:
                continue

    return None


def _extract_items(payload: Dict[str, Any]) -> Iterable[Any]:
    # CIRCL payloads have changed across versions, support common layouts.
    if "results" in payload and isinstance(payload["results"], dict):
        results = payload["results"]
        for key in ("cvelistv5", "cvelist", "items"):
            value = results.get(key)
            if isinstance(value, list):
                return value

    for key in ("cvelistv5", "cvelist", "items", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value

    return []


def fetch_cves_for_service(service_name: str, timeout: int = 25) -> List[Dict[str, Any]]:
    url = API_TEMPLATE.format(service=service_name)
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    payload = response.json()

    rows: List[Dict[str, Any]] = []
    for item in _extract_items(payload):
        cve_id = _extract_cve_id(item)
        if not cve_id:
            continue

        description = _extract_description(item)
        published_date = _extract_date(item)
        references = _extract_references(item)
        poc_refs = [link for link in references if any(k in link.lower() for k in POC_KEYWORDS)]

        rows.append(
            {
                "cve_id": cve_id,
                "description": description,
                "published_date": published_date,
                "year": _to_year(cve_id, published_date),
                "affected_configurations": _extract_configs(item),
                "version_constraints": "[]",
                "fixed_version": "",
                "recommendation": "",
                "reference_links": references,
                "poc_references": poc_refs,
                "source": "cve.circl.lu",
            }
        )

    return rows


def fetch_cve_details(cve_id: str, timeout: int = 10) -> Dict[str, Any]:
    """Fetch detailed CVE metadata from CIRCL API for a given CVE ID."""
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return {}
        data = resp.json()
        details: Dict[str, Any] = {}
        # published date
        for key in ("Published", "published", "PublishedDate", "published_date"):
            if key in data and isinstance(data[key], str):
                details["published_date"] = data[key]
                break

        # references - look inside containers.cna structure
        refs: List[str] = []
        containers = data.get("containers", {})
        if isinstance(containers, dict):
            cna = containers.get("cna", {})
            if isinstance(cna, dict):
                ref_list = cna.get("references")
                if isinstance(ref_list, list):
                    for r in ref_list:
                        if isinstance(r, str):
                            refs.append(r)
                        elif isinstance(r, dict):
                            url_val = r.get("url") or r.get("link") or r.get("href")
                            if isinstance(url_val, str):
                                refs.append(url_val)
        # cwe/configs
        configs = data.get("vulnerable_configuration") or data.get("configurations") or data.get("vulnerable_product")

        details["reference_links"] = refs
        try:
            details["affected_configurations"] = json.dumps(configs, ensure_ascii=True) if configs is not None else ""
        except TypeError:
            details["affected_configurations"] = str(configs) if configs is not None else ""

        # PoC heuristic
        poc_refs = [r for r in refs if any(k in r.lower() for k in POC_KEYWORDS)]
        details["poc_references"] = poc_refs
        details["version_constraints"] = "[]"
        details["fixed_version"] = ""
        details["recommendation"] = ""

        return details
    except Exception as e:
        return {}


def fetch_cves_multisource(service_name: str) -> List[Dict[str, Any]]:
    """Fetch CVEs using NVD as primary, CIRCL as fallback, and enrich with CISA KEV."""
    # Initialize CISA KEV cache if needed (one-time only)
    if not _cisa_kev_cache:
        _init_cisa_kev_cache()

    cves: Dict[str, Dict[str, Any]] = {}

    # Try NVD first
    nvd_results = fetch_from_nvd(service_name)
    for cve in nvd_results:
        cve_id = cve.get("cve_id")
        if cve_id:
            cves[cve_id] = cve

    # Also fetch from CIRCL to enrich version constraints (NVD uses CPE which is complex to parse)
    try:
        circl_results = fetch_cves_for_service(service_name)
        for cve in circl_results:
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue
            if cve_id in cves:
                # Merge: prefer NVD but use CIRCL for version constraints if available
                circl_vc = cve.get("version_constraints", "[]")
                if circl_vc and circl_vc != "[]":
                    cves[cve_id]["version_constraints"] = circl_vc
                circl_fixed = cve.get("fixed_version", "")
                if circl_fixed:
                    cves[cve_id]["fixed_version"] = circl_fixed
            else:
                cves[cve_id] = cve
    except Exception:
        pass  # If CIRCL fails, continue with NVD data only

    # Enrich each with CISA KEV data (from cache, no API calls)
    result = []
    for cve_id, cve_data in cves.items():
        kev_data = fetch_from_cisa_kev(cve_id)
        if kev_data:
            cve_data["cisa_kev"] = kev_data
            cve_data["cisa_dateAdded"] = kev_data.get("dateAdded", "")
        result.append(cve_data)

    return result


def _load_version_constraints(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    return []


def find_matching_cves(conn, service_name: str, service_version: str = "") -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT cve_id, service_name, service_version, year, description, affected_configurations,
                   version_constraints, fixed_version, recommendation, poc_references,
                   reference_links, published_date, source
            FROM cves
            WHERE service_name = %s
            ORDER BY year DESC, cve_id ASC
            """,
            (service_name,),
        )
        for record in cur.fetchall():
            version_constraints = _load_version_constraints(record[6])
            if service_version:
                if not version_constraints:
                    continue
                if not any(_constraint_matches_version(service_version, constraint) for constraint in version_constraints):
                    continue

            fixed_version = record[7] or ""
            recommendation = record[8] or ""
            if not recommendation and fixed_version:
                recommendation = f"Upgrade to version >= {fixed_version}"

            rows.append(
                {
                    "cve_id": record[0],
                    "service_name": record[1],
                    "service_version": record[2] or service_version,
                    "year": record[3],
                    "description": record[4],
                    "affected_configurations": record[5],
                    "version_constraints": version_constraints,
                    "fixed_version": fixed_version,
                    "recommendation": recommendation,
                    "poc_references": json.loads(record[9]) if record[9] else [],
                    "reference_links": json.loads(record[10]) if record[10] else [],
                    "published_date": record[11],
                    "source": record[12],
                    "match_status": "matched" if service_version else "unknown",
                }
            )

    return rows


def upsert_cves(
    conn,
    service_name: str,
    cves: List[Dict[str, Any]],
    start_year: int,
    end_year: int,
    service_version: str = "",
) -> int:
    inserted = 0
    for cve in cves:
        year = cve.get("year")
        if year is None or year < start_year or year > end_year:
            continue
        # Keep the main scan fast: persist the data we already fetched instead of
        # calling a second CVE detail endpoint for every row.
        affected = cve.get("affected_configurations", "")
        published = cve.get("published_date", "")
        refs = cve.get("reference_links", [])
        pocs = cve.get("poc_references", [])
        version_constraints = cve.get("version_constraints", "[]")
        fixed_version = cve.get("fixed_version", "")
        recommendation = cve.get("recommendation", "")
        stored_service_version = cve.get("service_version", "")
        match_status = cve.get("match_status", "unknown")

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cves (
                    cve_id,
                    service_name,
                    service_version,
                    year,
                    description,
                    affected_configurations,
                    version_constraints,
                    fixed_version,
                    recommendation,
                    match_status,
                    poc_code,
                    poc_references,
                    reference_links,
                    published_date,
                    last_modified,
                    source
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(cve_id, service_name) DO UPDATE SET
                    service_version=EXCLUDED.service_version,
                    year=EXCLUDED.year,
                    description=EXCLUDED.description,
                    affected_configurations=EXCLUDED.affected_configurations,
                    version_constraints=EXCLUDED.version_constraints,
                    fixed_version=EXCLUDED.fixed_version,
                    recommendation=EXCLUDED.recommendation,
                    match_status=EXCLUDED.match_status,
                    poc_references=EXCLUDED.poc_references,
                    reference_links=EXCLUDED.reference_links,
                    published_date=EXCLUDED.published_date,
                    last_modified=EXCLUDED.last_modified,
                    source=EXCLUDED.source
                """,
                (
                    cve["cve_id"],
                    service_name,
                    stored_service_version,
                    year,
                    cve.get("description", ""),
                    affected,
                    version_constraints,
                    fixed_version,
                    recommendation,
                    match_status,
                    None,
                    json.dumps(pocs, ensure_ascii=True),
                    json.dumps(refs, ensure_ascii=True),
                    published,
                    datetime.utcnow().isoformat(timespec="seconds"),
                    cve.get("source", "cve.circl.lu"),
                ),
            )
        inserted += 1

    conn.commit()
    return inserted


def create_scan_run(conn, service_name: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_runs (service_name, started_at, status)
            VALUES (%s, %s, 'running')
            RETURNING id
            """,
            (service_name, datetime.utcnow().isoformat(timespec="seconds")),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return int(run_id)


def finish_scan_run(
    conn,
    run_id: int,
    fetched_count: int,
    inserted_count: int,
    status: str,
    note: str = "",
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_runs
            SET finished_at=%s, fetched_count=%s, inserted_count=%s, status=%s, note=%s
            WHERE id=%s
            """,
            (
                datetime.utcnow().isoformat(timespec="seconds"),
                fetched_count,
                inserted_count,
                status,
                note,
                run_id,
            ),
        )
    conn.commit()


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


if __name__ == "__main__":
    main()
