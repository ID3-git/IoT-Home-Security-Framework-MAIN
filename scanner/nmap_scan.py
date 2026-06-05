"""
python-nmap wrapper for service/version detection, OS fingerprinting,
and NSE-based vulnerability checks.

Flags used:
  -sS / -sT  SYN scan (admin) or TCP-connect (unprivileged)
  -sV        service + version detection
  -O         OS fingerprinting (admin only)
  -Pn        skip host-ping — hosts were already confirmed alive by discovery
  -T4        aggressive timing (safe on LAN; matches Advanced IP Scanner speed)
  --script   read-only NSE scripts for service info
"""

import os
import shutil
from dataclasses import dataclass, field
from typing import Optional

# Common nmap install paths — checked when `nmap` isn't on the admin PATH
_NMAP_SEARCH_PATHS = [
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
]


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    name: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    script_output: dict[str, str] = field(default_factory=dict)


@dataclass
class NmapResult:
    ip: str
    os_guess: str = "Unknown"
    os_accuracy: int = 0
    services: list[ServiceInfo] = field(default_factory=list)
    raw_nmap_output: str = ""


# ── NSE script set — comprehensive read-only information gathering ────────
_NSE_SCRIPTS = ",".join([
    # Service banners and web metadata
    "banner",
    "http-title",
    "http-headers",
    "http-auth-finder",
    "http-methods",
    # TLS/SSL details — cert, ciphers, known weaknesses
    "ssl-cert",
    "ssl-enum-ciphers",
    "ssl-heartbleed",
    "ssl-poodle",
    # File sharing / Windows
    "smb-os-discovery",
    "smb-security-mode",
    "smb-vuln-ms17-010",
    # Network management
    "snmp-info",
    "snmp-sysdescr",
    # Remote access
    "rdp-enum-encryption",
    "ftp-anon",
    "telnet-ntlm-info",
    # IoT / embedded
    "upnp-info",
    "rtsp-methods",
    # Credentials
    "default-creds",
])

# Full TCP port range — 1 to 65535
_PORT_RANGE = "1-65535"

# Ports flagged as risky on IoT/home devices
DANGEROUS_PORTS = {
    21, 23, 25, 80, 81, 82, 554,
    1883, 2323, 4840, 5683,
    5900, 5901, 5985, 7547,
    8080, 8081, 8082, 8083, 8443, 8883,
}
UNENCRYPTED_SERVICES = {"telnet", "ftp", "http", "mqtt", "rtsp"}


def _find_nmap() -> Optional[str]:
    """Return the nmap binary path, checking PATH and common install locations."""
    for candidate in _NMAP_SEARCH_PATHS:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    return None


def _parse_host(nm, ip: str, result: "NmapResult") -> None:
    """Merge port/service data from a PortScanner result into result."""
    if ip not in nm.all_hosts():
        return
    host_data = nm[ip]
    if "osmatch" in host_data and host_data["osmatch"]:
        best = host_data["osmatch"][0]
        result.os_guess = best.get("name", "Unknown")
        result.os_accuracy = int(best.get("accuracy", 0))
    existing_ports = {s.port for s in result.services}
    for proto in host_data.all_protocols():
        for port, port_data in host_data[proto].items():
            if port in existing_ports:
                # update existing service with version/script data
                for svc in result.services:
                    if svc.port == port:
                        svc.name    = svc.name    or port_data.get("name", "")
                        svc.product = svc.product or port_data.get("product", "")
                        svc.version = svc.version or port_data.get("version", "")
                        svc.extra_info = svc.extra_info or port_data.get("extrainfo", "")
                        svc.script_output.update(port_data.get("script", {}))
                        break
            else:
                service = ServiceInfo(
                    port=port,
                    protocol=proto,
                    state=port_data.get("state", ""),
                    name=port_data.get("name", ""),
                    product=port_data.get("product", ""),
                    version=port_data.get("version", ""),
                    extra_info=port_data.get("extrainfo", ""),
                    script_output=dict(port_data.get("script", {})),
                )
                result.services.append(service)


def scan_host(
    ip: str,
    privileged: bool = True,
    routed: bool = False,
    timeout: int = 600,
) -> NmapResult:
    """
    Two-phase Nmap scan against a single host on a trusted LAN.

    Phase 1 — fast port discovery across all 65535 ports.
    Phase 2 — deep probe on open ports only (fast because few ports).

    Args:
        ip:         Target IP address.
        privileged: True when running as Administrator / root.
        routed:     True when the host is on a gateway-discovered subnet
                    (not directly connected via ARP).  Forces TCP-connect
                    mode and drops --min-rate so the inter-VLAN router is
                    not overwhelmed — raw SYN floods across a router cause
                    packet loss that makes ports appear filtered.
        timeout:    Per-phase timeout in seconds.

    Raises:
        RuntimeError  nmap binary missing
        TimeoutError  scan exceeded timeout
    """
    nmap_path = _find_nmap()
    if not nmap_path:
        raise RuntimeError(
            "Nmap is not installed or not found. Please install from https://nmap.org/download.html"
        )

    import nmap

    search = (nmap_path,) if os.path.isabs(nmap_path) else ("nmap",)
    nm = nmap.PortScanner(nmap_search_path=search)

    result = NmapResult(ip=ip)

    # ── Phase 1: discover all open ports ─────────────────────────────────
    # Direct LAN: SYN scan at high rate is safe and fast (all 65535 ports).
    # Routed (cross-VLAN): TCP-connect on top 1000 ports only — full scan
    # times out crossing VLANs. Top 1000 ports cover ~99% of real services.
    if routed:
        phase1_args = "-sT -Pn -T4 --max-retries 2 --top-ports 1000"
    elif not privileged:
        phase1_args = "-sT -Pn -T4 --max-retries 2 -p 1-65535"
    else:
        phase1_args = "-sS -Pn -T4 --min-rate 2000 --max-retries 2 -p 1-65535"

    try:
        nm.scan(hosts=ip, arguments=phase1_args, timeout=timeout)
    except nmap.PortScannerTimeout:
        raise TimeoutError(f"Nmap port discovery of {ip} timed out after {timeout}s")
    except Exception as exc:
        raise RuntimeError(f"Nmap phase-1 scan failed: {exc}") from exc

    _parse_host(nm, ip, result)

    open_ports = [s.port for s in result.services if s.state == "open"]
    if not open_ports:
        return result  # nothing open — skip phase 2

    # ── Phase 2: version + script detection on open ports only ───────────
    port_spec = ",".join(str(p) for p in open_ports)
    if routed or not privileged:
        phase2_args = (
            f"-sT -sV --version-intensity 7 "
            f"-Pn -T4 --max-retries 2 "
            f"--script {_NSE_SCRIPTS} "
            f"-p {port_spec}"
        )
    else:
        phase2_args = (
            f"-sS -sV --version-intensity 9 -O --osscan-guess "
            f"-Pn -T4 --max-retries 2 "
            f"--script {_NSE_SCRIPTS} "
            f"-p {port_spec}"
        )

    try:
        nm.scan(hosts=ip, arguments=phase2_args, timeout=timeout)
    except nmap.PortScannerTimeout:
        pass  # phase 1 results still valid; phase 2 timed out
    except Exception:
        pass  # partial results are better than nothing

    _parse_host(nm, ip, result)
    result.raw_nmap_output = nm.get_nmap_last_output()
    return result


def flag_dangerous_services(result: NmapResult) -> list[str]:
    """
    Return a list of human-readable warnings for dangerous/unencrypted services.
    """
    warnings = []
    for svc in result.services:
        if svc.state != "open":
            continue
        if svc.port in DANGEROUS_PORTS:
            warnings.append(
                f"Port {svc.port} ({svc.name or 'unknown'}) is open — "
                "commonly targeted on IoT devices."
            )
        if svc.name in UNENCRYPTED_SERVICES:
            warnings.append(
                f"{svc.name.upper()} on port {svc.port} transmits data unencrypted."
            )
        # Check for default-creds hit in NSE output
        creds_output = svc.script_output.get("default-creds", "")
        if creds_output and "valid" in creds_output.lower():
            warnings.append(
                f"Default credentials detected on port {svc.port} ({svc.name})!"
            )
    return warnings
