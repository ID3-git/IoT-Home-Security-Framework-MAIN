"""
Risk scoring engine.

Combines:
  - Highest CVSS score found for the device
  - Open dangerous/unencrypted ports
  - Default credentials flag from NSE scripts

Output: RiskLevel enum (CRITICAL / HIGH / MEDIUM / LOW / INFO)
        and a numeric risk_score (0–10) for sorting.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    def colour(self) -> str:
        """Qt-compatible colour hex string for UI badges."""
        return {
            RiskLevel.CRITICAL: "#c0392b",
            RiskLevel.HIGH:     "#e67e22",
            RiskLevel.MEDIUM:   "#f1c40f",
            RiskLevel.LOW:      "#27ae60",
            RiskLevel.INFO:     "#2980b9",
        }[self]

    def badge_text(self) -> str:
        return self.value.upper()


@dataclass
class RiskResult:
    level: RiskLevel
    score: float          # 0–10 composite
    reasons: list[str]    # Human-readable contributing factors


# Ports that add bonus risk if open
_DANGEROUS_PORT_BONUS: dict[int, float] = {
    22:   1.0,   # SSH — encrypted but a brute-force / credential-spray target;
                 #       raises score so devices with only SSH land on Low, not Info
    23:   3.0,   # Telnet — plaintext, trivially sniffable
    2323: 3.0,   # Alt-Telnet
    21:   2.0,   # FTP — plaintext credentials
    80:   1.0,   # HTTP — unencrypted web admin panel (common on routers/IoT)
    5900: 2.0,   # VNC
    5985: 1.5,   # WinRM HTTP
    1883: 1.5,   # MQTT (unencrypted IoT messaging)
    8080: 0.8,   # HTTP alternate
    8443: 0.3,   # HTTPS alternate (less risky than plain 8080)
    554:  0.5,   # RTSP (IP cameras)
    3389: 2.5,   # RDP — frequently brute-forced
    445:  2.0,   # SMB — EternalBlue class vulnerabilities
}

_UNENCRYPTED_NAMES = {"telnet", "ftp", "http"}


def _cvss_to_base_score(cvss: float) -> float:
    """CVSS is already 0-10; just return it."""
    return cvss


def score_device(
    services: list[dict],
    cves: list[dict],
    nse_warnings: list[str] | None = None,
) -> RiskResult:
    """
    Compute a composite risk score for a device.

    Args:
        services: List of service dicts (from db.get_services_for_device or
                  ServiceInfo-derived dicts). Must have 'port', 'name', 'state'.
        cves: List of CVE dicts (from db.get_cves_for_device).
              Must have 'cvss_score'.
        nse_warnings: Optional list of warning strings from nmap_scan.flag_dangerous_services.

    Returns:
        RiskResult with level, score, and reasons.
    """
    score = 0.0
    reasons: list[str] = []

    # 1. CVE contribution — highest CVSS drives the base
    if cves:
        top_cvss = max(c.get("cvss_score", 0.0) for c in cves)
        score = max(score, _cvss_to_base_score(top_cvss))
        critical_count = sum(1 for c in cves if c.get("severity") == "CRITICAL")
        high_count = sum(1 for c in cves if c.get("severity") == "HIGH")
        if critical_count:
            reasons.append(f"{critical_count} Critical CVE(s) found (CVSS ≥ 9.0)")
        if high_count:
            reasons.append(f"{high_count} High CVE(s) found (CVSS ≥ 7.0)")
        if not critical_count and not high_count and cves:
            reasons.append(f"{len(cves)} CVE(s) found")

    # 2. Dangerous open ports
    for svc in services:
        if svc.get("state") != "open":
            continue
        port = svc.get("port", 0)
        name = svc.get("name", "").lower()
        bonus = _DANGEROUS_PORT_BONUS.get(port, 0.0)
        if bonus:
            score = min(10.0, score + bonus)
            reasons.append(f"Port {port} ({name or 'unknown'}) is open and risky")
        if name in _UNENCRYPTED_NAMES:
            score = min(10.0, score + 1.5)
            reasons.append(f"{name.upper()} detected — unencrypted service")

    # 3. Default credentials (NSE)
    if nse_warnings:
        for w in nse_warnings:
            if "default credentials" in w.lower():
                score = min(10.0, score + 3.0)
                reasons.append("Default credentials detected!")

    # 4. No findings
    if not reasons:
        reasons.append("No significant vulnerabilities detected")

    # Map composite score → level
    if score >= 9.0:
        level = RiskLevel.CRITICAL
    elif score >= 7.0:
        level = RiskLevel.HIGH
    elif score >= 4.0:
        level = RiskLevel.MEDIUM
    elif score > 0.0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.INFO

    return RiskResult(level=level, score=round(score, 2), reasons=reasons)


def summarise_network(device_risks: list[RiskResult]) -> dict[str, Any]:
    """Return summary counts by risk level for the whole network."""
    counts: dict[str, int] = {lvl.value: 0 for lvl in RiskLevel}
    for r in device_risks:
        counts[r.level.value] += 1
    worst = max(device_risks, key=lambda r: r.score, default=None)
    return {
        "counts": counts,
        "worst_level": worst.level.value if worst else RiskLevel.INFO.value,
        "worst_score": worst.score if worst else 0.0,
        "total_devices": len(device_risks),
    }
