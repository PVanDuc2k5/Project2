import json
import re
from typing import Any, Dict, List


def _version_key(version: str) -> List[int]:
    tokens = re.findall(r"\d+|[a-z]+", version.lower())
    key: List[int] = []
    for token in tokens:
        if token.isdigit():
            key.append(int(token))
        else:
            for char in token:
                key.append(100 + ord(char) - ord("a"))
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
