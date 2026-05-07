import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import requests

from cve_config import API_TEMPLATE, CISA_KEV_API, CISA_KEV_CACHE, NVD_API_BASE, POC_KEYWORDS
from cve_versioning import _build_recommendation, _extract_fixed_version, _extract_version_constraints


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
    if not CISA_KEV_CACHE:
        _init_cisa_kev_cache(timeout=timeout)
    return CISA_KEV_CACHE.get(cve_id.lower(), {})


def _init_cisa_kev_cache(timeout: int = 10) -> None:
    """Load all CISA KEV data into cache once."""
    try:
        resp = requests.get(CISA_KEV_API, timeout=timeout)
        if resp.status_code != 200:
            return
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            cve_id = vuln.get("cveID", "").lower()
            if cve_id:
                CISA_KEV_CACHE[cve_id] = {
                    "dateAdded": vuln.get("dateAdded", ""),
                    "shortDescription": vuln.get("shortDescription", ""),
                    "requiredAction": vuln.get("requiredAction", ""),
                    "dueDate": vuln.get("dueDate", ""),
                }
    except Exception as e:
        print(f"[!] Failed to load CISA KEV cache: {e}")


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

        for key in ("Published", "published", "PublishedDate", "published_date"):
            if key in data and isinstance(data[key], str):
                details["published_date"] = data[key]
                break

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

        configs = data.get("vulnerable_configuration") or data.get("configurations") or data.get("vulnerable_product")

        details["reference_links"] = refs
        try:
            details["affected_configurations"] = json.dumps(configs, ensure_ascii=True) if configs is not None else ""
        except TypeError:
            details["affected_configurations"] = str(configs) if configs is not None else ""

        poc_refs = [r for r in refs if any(k in r.lower() for k in POC_KEYWORDS)]
        details["poc_references"] = poc_refs
        details["version_constraints"] = "[]"
        details["fixed_version"] = ""
        details["recommendation"] = ""

        return details
    except Exception:
        return {}


def fetch_cves_multisource(service_name: str) -> List[Dict[str, Any]]:
    """Fetch CVEs using NVD as primary, CIRCL as fallback, and enrich with CISA KEV."""
    if not CISA_KEV_CACHE:
        _init_cisa_kev_cache()

    cves: Dict[str, Dict[str, Any]] = {}

    nvd_results = fetch_from_nvd(service_name)
    for cve in nvd_results:
        cve_id = cve.get("cve_id")
        if cve_id:
            cves[cve_id] = cve

    try:
        circl_results = fetch_cves_for_service(service_name)
        for cve in circl_results:
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue
            if cve_id in cves:
                circl_vc = cve.get("version_constraints", "[]")
                if circl_vc and circl_vc != "[]":
                    cves[cve_id]["version_constraints"] = circl_vc
                circl_fixed = cve.get("fixed_version", "")
                if circl_fixed:
                    cves[cve_id]["fixed_version"] = circl_fixed
            else:
                cves[cve_id] = cve
    except Exception:
        pass

    result = []
    for cve_id, cve_data in cves.items():
        kev_data = fetch_from_cisa_kev(cve_id)
        if kev_data:
            cve_data["cisa_kev"] = kev_data
            cve_data["cisa_dateAdded"] = kev_data.get("dateAdded", "")
        result.append(cve_data)

    return result
