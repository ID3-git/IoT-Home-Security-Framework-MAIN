"""
NVD REST API v2 CVE lookup.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limit: 5 req/30s without API key, 50 req/30s with key.
We cache results in-process to avoid hammering the API.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional
import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_LIMIT_DELAY = 6.5  # seconds between requests (safe without API key)

_cache: dict[str, list] = {}
_cache_lock = threading.Lock()
_last_request_time: float = 0.0
_rate_lock = threading.Lock()


@dataclass
class CVE:
    cve_id: str
    description: str
    cvss_score: float        # 0.0 if not available
    cvss_version: str        # "3.1", "3.0", "2.0", or ""
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / NONE
    published: str           # ISO date string
    references: list[str] = field(default_factory=list)


def _rate_limited_get(url: str, params: dict, api_key: Optional[str]) -> dict:
    """GET with simple rate limiting."""
    global _last_request_time

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    with _rate_lock:
        elapsed = time.monotonic() - _last_request_time
        if elapsed < _RATE_LIMIT_DELAY:
            time.sleep(_RATE_LIMIT_DELAY - elapsed)
        _last_request_time = time.monotonic()

    resp = requests.get(url, params=params, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()


def _parse_cve(item: dict) -> CVE:
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")

    # Description (prefer English)
    descriptions = cve_data.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS score — prefer v3.1 > v3.0 > v2.0
    metrics = cve_data.get("metrics", {})
    score, version, severity = 0.0, "", "NONE"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cv = m.get("cvssData", {})
            score = float(cv.get("baseScore", 0.0))
            version = cv.get("version", "")
            severity = (
                cv.get("baseSeverity", "")
                or m.get("baseSeverity", "")
                or _score_to_severity(score)
            )
            break

    published = cve_data.get("published", "")[:10]

    refs = [
        r.get("url", "")
        for r in cve_data.get("references", [])
        if r.get("url")
    ]

    return CVE(
        cve_id=cve_id,
        description=desc,
        cvss_score=score,
        cvss_version=version,
        severity=severity.upper(),
        published=published,
        references=refs[:5],
    )


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def lookup_cves(
    keyword: str,
    version: str = "",
    max_results: int = 10,
    api_key: Optional[str] = None,
) -> list[CVE]:
    """
    Query NVD for CVEs matching a service name and optional version.

    Args:
        keyword: Service/product name (e.g. "OpenSSH", "nginx").
        version: Version string to narrow results (used as versionStart filter).
        max_results: Maximum CVEs to return.
        api_key: Optional NVD API key for higher rate limits.

    Returns:
        List of CVE objects sorted by CVSS score descending.
        Returns [] on API error (graceful degradation).
    """
    cache_key = f"{keyword}:{version}:{max_results}"
    with _cache_lock:
        if cache_key in _cache:
            return _cache[cache_key]

    params: dict = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 20),
    }
    if version:
        params["versionStart"] = version
        params["versionStartType"] = "including"

    try:
        data = _rate_limited_get(NVD_BASE, params, api_key)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            result: list[CVE] = []
            with _cache_lock:
                _cache[cache_key] = result
            return result
        raise RuntimeError(f"NVD API error: {e}") from e
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Cannot reach NVD API. Check your internet connection."
        )
    except requests.exceptions.Timeout:
        raise RuntimeError("NVD API request timed out.")

    vulnerabilities = data.get("vulnerabilities", [])
    cves = [_parse_cve(item) for item in vulnerabilities]
    cves.sort(key=lambda c: c.cvss_score, reverse=True)

    with _cache_lock:
        _cache[cache_key] = cves

    return cves


def lookup_cves_for_services(
    services: list[dict],
    api_key: Optional[str] = None,
) -> dict[str, list[CVE]]:
    """
    Convenience wrapper: takes a list of dicts with 'product' and 'version' keys
    (matching ServiceInfo fields) and returns {product: [CVE, ...]} mapping.
    Skips services with no product name.
    """
    results: dict[str, list[CVE]] = {}
    seen: set[str] = set()

    for svc in services:
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()
        if not product or product in seen:
            continue
        seen.add(product)
        try:
            cves = lookup_cves(product, version, api_key=api_key)
            results[product] = cves
        except RuntimeError:
            results[product] = []  # degrade gracefully

    return results
