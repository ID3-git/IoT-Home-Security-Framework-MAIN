"""
Multi-method host discovery: Scapy ARP + OS ARP cache + ICMP ping sweep.

Three-layer strategy (Implementation Section 5.7):
  1. Scapy ARP  — most accurate MACs, but Layer 2 only (single broadcast domain)
  2. OS ARP cache — free; populated by all prior network activity on this machine
  3. ICMP sweep  — Layer 3, crosses router hops; uses subprocess ping so no raw
                   socket privilege is required

This approach is deliberately non-aggressive:
  - One ARP broadcast per subnet (not per host)
  - One ICMP echo per host (polite, matches RFC 1122)
  - No TCP/UDP probing at this stage (that is Nmap's role in UC-02)
Results from all three methods are deduplicated by IP address before enrichment.
"""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

import requests

# Silence Scapy's "Unable to guess datalink type" and other runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

_oui_cache: dict[str, str] = {}
_oui_lock = threading.Lock()


@dataclass
class DiscoveredHost:
    ip: str
    mac: str
    vendor: str = "Unknown"
    hostname: str = ""


# ── Interface / subnet enumeration ────────────────────────────────────────

def _get_iface_subnets() -> list[tuple[str, object]]:
    """
    Return (cidr_subnet, scapy_iface_object) pairs for every active
    non-loopback, non-link-local interface Scapy can see.
    Passing the iface object to srp() ensures packets leave the right NIC.

    On Windows, also supplements with ipconfig output to catch VMware/VirtualBox
    virtual adapters that Scapy does not always enumerate.
    """
    results: list[tuple[str, object]] = []
    seen: set[str] = set()

    try:
        from scapy.config import conf
        for iface in conf.ifaces.values():
            ip = getattr(iface, "ip", "") or ""
            if (
                ip
                and ip != "0.0.0.0"
                and not ip.startswith("127.")
                and not ip.startswith("169.254.")
            ):
                prefix = ip.rsplit(".", 1)[0]
                subnet = f"{prefix}.0/24"
                if subnet not in seen:
                    seen.add(subnet)
                    results.append((subnet, iface))
    except Exception:
        pass

    # Supplement with ipconfig on Windows — catches VMware VMnet and VirtualBox
    # host-only/NAT adapters that Scapy may not enumerate on Windows.
    if platform.system() == "Windows":
        try:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10
            ).stdout
            for line in out.splitlines():
                m = re.search(
                    r'IPv4 Address[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})', line
                ) or re.search(
                    r'IP Address[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})', line
                )
                if m:
                    ip = m.group(1)
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        prefix = ip.rsplit(".", 1)[0]
                        subnet = f"{prefix}.0/24"
                        if subnet not in seen:
                            seen.add(subnet)
                            results.append((subnet, None))
        except Exception:
            pass

    # Fallback — at least get the default-route interface
    if not results:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            prefix = local_ip.rsplit(".", 1)[0]
            results.append((f"{prefix}.0/24", None))
        except Exception:
            results.append(("192.168.1.0/24", None))

    return results


# ── Method 2: OS ARP cache ────────────────────────────────────────────────

_SKIP_IPS  = re.compile(r'^(127\.|169\.254\.|22[4-9]\.|23[0-9]\.)')
_SKIP_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
_ARP_LINE  = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3})'           # IP address
    r'\s+'
    r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}'  # MAC (colon or dash separated)
    r'(?:[:\-][0-9a-fA-F]{2}){4})'
)


def _parse_arp_cache(
    log: Optional[Callable[[str], None]] = None,
) -> list["DiscoveredHost"]:
    """
    Read the OS ARP cache via `arp -a` and return DiscoveredHost entries.

    Why this source? The OS cache is populated by every network conversation
    the machine has had since boot — file shares, streaming, DNS — giving us
    host visibility that a fresh ARP broadcast would miss (e.g. hosts that
    are momentarily asleep or rate-limiting ARP replies).
    """
    hosts: list[DiscoveredHost] = []
    seen: set[str] = set()
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            m = _ARP_LINE.search(line)
            if not m:
                continue
            ip  = m.group(1)
            mac = m.group(2).replace("-", ":").lower()
            if (
                ip not in seen
                and not _SKIP_IPS.match(ip)
                and not ip.endswith(".255")
                and mac not in _SKIP_MACS
                and "<incomplete>" not in line.lower()
            ):
                seen.add(ip)
                hosts.append(DiscoveredHost(ip=ip, mac=mac))
                if log:
                    log(f"  cache  {ip}  ({mac})")
    except Exception as exc:
        if log:
            log(f"  ARP cache unavailable: {exc}")
    return hosts


# ── Method 3: ICMP ping sweep ─────────────────────────────────────────────

def _ping_host(ip: str, timeout_ms: int) -> bool:
    """
    Send a single ICMP echo to one host via the OS ping binary.

    Why subprocess ping instead of Scapy ICMP?
    Scapy ICMP requires raw socket access (Administrator/root). subprocess
    ping works for any user account and avoids an additional privilege
    requirement — important for the homeowner persona.
    """
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=(timeout_ms / 1000) + 2)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_sweep(
    subnet: str,
    ports: tuple[int, ...] = (
        80, 443, 22, 8080, 554, 8443, 8888,
        # Common non-standard web/admin ports on IoT and embedded devices
        81, 8000, 8001, 8081, 8090, 8888, 9000, 4443, 7080, 7443,
    ),
    timeout: float = 1.5,
    max_workers: int = 80,
    log: Optional[Callable[[str], None]] = None,
) -> list[str]:
    """
    TCP connect sweep of common ports across a subnet.

    Used for subnets discovered via gateway probe (different broadcast
    domain) where ICMP may be blocked by inter-VLAN firewall rules.
    Devices with web servers, SSH, or RTSP respond even if they drop ICMP.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return []

    targets = [str(h) for h in network.hosts()]
    responsive: set[str] = set()

    def _check(ip: str) -> Optional[str]:
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return ip
                s.close()
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for ip in pool.map(_check, targets):
            if ip and ip not in responsive:
                responsive.add(ip)
                if log:
                    log(f"  TCP   {ip}  responded")

    return sorted(responsive)


def _icmp_sweep(
    subnet: str,
    timeout_ms: int = 600,
    max_workers: int = 60,
    log: Optional[Callable[[str], None]] = None,
) -> list[str]:
    """
    Parallel ICMP ping sweep of a CIDR subnet. Returns responsive IPs only.

    Why threaded ping over Nmap -sn?
    Nmap host discovery requires elevated privileges on Windows for raw ICMP.
    A thread-pooled subprocess ping achieves equivalent coverage without
    requiring the user to run as Administrator — aligning with the homeowner
    threat model where running as admin is not guaranteed.

    Timing: /24 subnet (254 hosts), 60 workers, 600 ms timeout ≈ 3–4 seconds.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        if log:
            log(f"  Invalid subnet for ICMP sweep: {subnet}")
        return []

    targets = [str(h) for h in network.hosts()]
    if log:
        log(f"  ICMP sweeping {len(targets)} addresses in {subnet}…")

    responsive: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping_host, ip, timeout_ms): ip for ip in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            if fut.result():
                responsive.append(ip)
                if log:
                    log(f"  ICMP  {ip}  responded")

    return responsive


# ── Deduplication merge ────────────────────────────────────────────────────

def _merge_hosts(*sources: list["DiscoveredHost"]) -> list["DiscoveredHost"]:
    """
    Combine host lists from multiple discovery methods, deduplicated by IP.

    Priority rule: first source with a real MAC for a given IP wins.
    Sources should be passed in descending trust order:
        Scapy ARP (highest) → OS cache → ICMP-derived (lowest)
    """
    merged: dict[str, DiscoveredHost] = {}
    for source in sources:
        for host in source:
            if host.ip not in merged:
                merged[host.ip] = host
            else:
                existing = merged[host.ip]
                no_mac = existing.mac in ("", "unknown", "<incomplete>")
                has_mac = host.mac not in ("", "unknown", "<incomplete>")
                if no_mac and has_mac:
                    existing.mac = host.mac
    return list(merged.values())


# ── OUI / hostname enrichment ─────────────────────────────────────────────

def _lookup_vendor(mac: str) -> str:
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    with _oui_lock:
        if oui in _oui_cache:
            return _oui_cache[oui]

    # Primary: Scapy's bundled manufacturer database (local, instant, no rate-limit)
    vendor = "Unknown"
    try:
        from scapy.config import conf
        result = conf.manufdb._get_manuf(mac)
        if result:
            vendor = result
    except Exception:
        pass

    # Fallback: macvendors.com API — only if local lookup found nothing.
    # Validates response length and content to guard against rate-limit
    # messages being stored as vendor names.
    if vendor == "Unknown":
        try:
            resp = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
            if resp.status_code == 200:
                text = resp.text.strip()
                if text and len(text) < 80 and "macvendors.com" not in text.lower():
                    vendor = text
        except Exception:
            pass

    with _oui_lock:
        _oui_cache[oui] = vendor
    return vendor


def _resolve_hostname(ip: str) -> str:
    """
    Resolve a hostname for the given IP via multiple methods.

    1. Standard reverse DNS (gethostbyaddr) — works for devices registered
       in the local DNS server or the host's /etc/hosts file.
    2. mDNS via Resolve-DnsName (Windows) — catches devices that advertise
       only via multicast DNS (.local), such as Amazon Echo, Google Home,
       Apple devices, and most consumer IoT hardware.  Resolve-DnsName
       queries the Windows mDNS stack directly, unlike gethostbyaddr which
       goes through the system resolver and often misses .local names.
    """
    # Method 1 — standard reverse DNS
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass

    # Method 2 — mDNS via Resolve-DnsName (Windows 10/11)
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    f"(Resolve-DnsName -Name '{ip}' -Type PTR -ErrorAction Stop"
                    f").NameHost | Select-Object -First 1",
                ],
                capture_output=True, text=True, timeout=4,
            )
            name = result.stdout.strip().rstrip(".")
            if name and name != ip and result.returncode == 0:
                return name
        except Exception:
            pass

    return ""


# ── ARP scan ───────────────────────────────────────────────────────────────

def arp_scan(
    subnet: Optional[str] = None,
    timeout: float = 2.0,
    log: Optional[Callable[[str], None]] = None,
) -> list[DiscoveredHost]:
    """
    ARP-scan one subnet (if given) or every detected interface subnet.
    Binds each scan to the correct NIC via iface= so packets actually leave
    the right adapter.
    """
    from scapy.config import conf as _conf
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
    _conf.verb = 0  # suppress "Unable to guess datalink type" and other warnings

    if subnet:
        iface_subnets = [(subnet, None)]
    else:
        iface_subnets = _get_iface_subnets()

    if log:
        names = [sn for sn, _ in iface_subnets]
        log(f"Detected {len(names)} subnet(s): {', '.join(names)}")

    seen_ips: set[str] = set()
    hosts: list[DiscoveredHost] = []

    for sn, iface in iface_subnets:
        iface_desc = getattr(iface, "description", None) or getattr(iface, "name", str(iface))
        if log:
            log(f"ARP scanning {sn}  [{iface_desc}]…")
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=sn)
            kwargs: dict = {"timeout": timeout, "verbose": False}
            if iface is not None:
                kwargs["iface"] = iface
            answered, _ = srp(packet, **kwargs)
            count = 0
            for _, rcv in answered:
                ip  = rcv[ARP].psrc
                mac = rcv[ARP].hwsrc
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    hosts.append(DiscoveredHost(ip=ip, mac=mac))
                    count += 1
                    if log:
                        log(f"  ✓  {ip}  ({mac})")
            if log:
                log(f"  → {count} new host(s) on {sn}")
        except Exception as exc:
            if log:
                log(f"  ✗  {sn} failed: {exc}")
            continue

    return hosts


# ── Enrichment ────────────────────────────────────────────────────────────

def enrich_hosts(
    hosts: list[DiscoveredHost],
    log: Optional[Callable[[str], None]] = None,
) -> list[DiscoveredHost]:
    if log:
        log(f"Enriching {len(hosts)} host(s) with vendor/hostname…")
    threads = []

    def _enrich(host: DiscoveredHost) -> None:
        host.vendor   = _lookup_vendor(host.mac)
        host.hostname = _resolve_hostname(host.ip)
        if log:
            log(f"  {host.ip}  →  {host.vendor}  {host.hostname}")

    for host in hosts:
        t = threading.Thread(target=_enrich, args=(host,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=6)
    return hosts


# ── Common gateway repository ─────────────────────────────────────────────
#
# Used by probe_reachable_gateways() to detect adjacent VLANs the PC can
# route to but cannot ARP (different broadcast domain).

COMMON_GATEWAYS: list[str] = [
    # 192.168.0.x — Belkin, D-Link, many ISP-supplied routers
    "192.168.0.1",   "192.168.0.254",
    # 192.168.1.x — ASUS, Netgear, TP-Link, Linksys (most common worldwide)
    "192.168.1.1",   "192.168.1.254",
    # 192.168.2.x — Some Belkin, Cisco Linksys
    "192.168.2.1",
    # 192.168.8.x — Huawei HiLink routers/modems
    "192.168.8.1",   "192.168.8.254",
    # 192.168.10.x — Apple AirPort, some TP-Link, Sky (UK)
    "192.168.10.1",
    # 192.168.11.x — Motorola SURFboard
    "192.168.11.1",
    # 192.168.20.x — Some Zyxel, enterprise AP controllers
    "192.168.20.1",
    # 192.168.50.x — Some Zyxel
    "192.168.50.1",
    # 192.168.100.x — Arris, Motorola cable modems; some Virgin Media
    "192.168.100.1",
    # 192.168.123.1 — AVM Fritz!Box (Austria/Switzerland default)
    "192.168.123.1",
    # 192.168.178.1 — AVM Fritz!Box (German ISPs: Deutsche Telekom, 1&1)
    "192.168.178.1",
    # 192.168.254.x — Some Cisco, Buffalo
    "192.168.254.1", "192.168.254.254",
    # 10.x.x.x — Enterprise, Apple AirPort Extreme, Virgin Media (UK)
    "10.0.0.1",      "10.0.0.138",   # Sky Broadband UK
    "10.0.1.1",      "10.1.1.1",
    "10.10.0.1",
    # 172.16.x.x — RFC 1918, some enterprise VPN/WLAN controllers
    "172.16.0.1",    "172.16.1.1",
]


def get_local_subnets() -> list[str]:
    """Return /24 CIDR strings for every active local network interface."""
    return [sn for sn, _ in _get_iface_subnets()]


def probe_reachable_gateways(
    exclude_subnets: "set[str] | None" = None,
    timeout: float = 0.8,
    log: Optional[Callable[[str], None]] = None,
) -> list[tuple[str, str]]:
    """
    Probe COMMON_GATEWAYS via TCP and return (gateway_ip, /24_subnet) pairs
    for each that responds.

    This detects adjacent VLANs the PC can route to but not ARP — common when
    a wireless VLAN (e.g. 192.168.10.0/24) is on the same physical router as
    the wired VLAN (e.g. 10.10.1.0/24) but on a different broadcast domain.

    Uses TCP connection tests so no raw socket / admin privilege is required.

    Args:
        exclude_subnets: /24 subnets already covered (skips their gateways).
        timeout:         Per-port TCP connect timeout in seconds.
        log:             Optional log callback.
    Returns:
        Sorted list of (gateway_ip, subnet) tuples for responding gateways.
    """
    exclude_subnets = exclude_subnets or set()
    if log:
        log(f"Probing {len(COMMON_GATEWAYS)} common gateway addresses "
            f"(timeout {timeout}s per port)…")

    def _check(gw_ip: str) -> "tuple[str, str] | None":
        prefix = gw_ip.rsplit(".", 1)[0]
        subnet = f"{prefix}.0/24"
        if subnet in exclude_subnets:
            return None
        for port in (80, 443, 53, 8080, 22):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                connected = s.connect_ex((gw_ip, port)) == 0
                s.close()
                if connected:
                    return (gw_ip, subnet)
            except Exception:
                pass
        return None

    results: list[tuple[str, str]] = []
    seen_subnets: set[str] = set()
    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = {pool.submit(_check, gw): gw for gw in COMMON_GATEWAYS}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                gw_ip, subnet = res
                if subnet not in seen_subnets:
                    seen_subnets.add(subnet)
                    results.append(res)
                    if log:
                        log(f"  ✓  Gateway {gw_ip} responded → {subnet}")

    results.sort(key=lambda t: t[1])
    if log:
        log(f"Gateway probe complete — {len(results)} additional subnet(s) found.")
    return results


# ── Public entry point ────────────────────────────────────────────────────

def discover(
    subnet: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
    icmp: bool = True,
) -> list[DiscoveredHost]:
    """
    Multi-method discovery pipeline (Implementation Section 5.7).

    Order of operations:
      1. Scapy ARP scan     — highest MAC accuracy, Layer 2 only
      2. OS ARP cache read  — free historical coverage, all prior sessions
      3. ICMP ping sweep    — Layer 3, catches hosts ARP missed; pings also
                              refresh the OS cache so Step 2 MACs are current
      4. Merge + deduplicate by IP (Scapy MAC takes priority)
      5. Enrich with vendor OUI lookup + reverse DNS hostname

    Args:
        subnet: CIDR string, comma-separated list of CIDRs, or None for
                auto-detect.  Example: '10.10.1.0/24,192.168.10.0/24'.
        log:    Callback for live log lines (passed to GUI log panel).
        icmp:   Set False to skip the ICMP sweep (faster, but lower coverage).

    When subnet is None (auto-detect), the function automatically probes the
    COMMON_GATEWAYS list and adds any responding adjacent subnets to the ICMP
    sweep — so wireless VLANs on a different broadcast domain are discovered
    without any manual configuration.
    """
    # ── Multi-subnet: comma-separated list ────────────────────────────────
    if subnet and "," in subnet:
        all_results: list[DiscoveredHost] = []
        seen_ips: set[str] = set()
        subnets = [s.strip() for s in subnet.split(",") if s.strip()]
        for sn in subnets:
            if log:
                log(f"\n{'═'*48}\nScanning subnet: {sn}\n{'═'*48}")
            try:
                hosts = discover(subnet=sn, log=log, icmp=icmp)
                added = 0
                for h in hosts:
                    if h.ip not in seen_ips:
                        seen_ips.add(h.ip)
                        all_results.append(h)
                        added += 1
                if log:
                    log(f"  → {added} new host(s) from {sn}")
            except RuntimeError:
                if log:
                    log(f"  → No hosts found on {sn}")
            except Exception as exc:
                if log:
                    log(f"  ✗  {sn}: {exc}")
        if not all_results:
            raise RuntimeError(
                "No hosts found across the selected subnets. "
                "Check that the networks are reachable from this machine."
            )
        return all_results

    # ── Single subnet (or auto-detect) ────────────────────────────────────

    # Phase 0 — Gateway probe (always runs, before any scanning)
    # Detects adjacent VLANs the PC can route to but cannot ARP-reach.
    # Runs first so discovered subnets feed into every stage that follows.
    if log:
        log("=== Phase 0 — Common gateway probe ===")
    if subnet:
        known_subnets: set[str] = {subnet}
    else:
        known_subnets = {sn for sn, _ in _get_iface_subnets()}
    extra_gateways = probe_reachable_gateways(
        exclude_subnets=known_subnets,
        log=log,
    )
    extra_subnets = [sn for _, sn in extra_gateways]
    if log and extra_subnets:
        for gw_ip, sn in extra_gateways:
            log(f"  Adding adjacent subnet {sn} (gateway {gw_ip})")
        log(f"  → {len(extra_subnets)} additional subnet(s) will be scanned")

    if log:
        log("=== Stage 1/3 — Scapy ARP Discovery ===")
    arp_hosts = arp_scan(subnet, log=log)

    if log:
        log("=== Stage 2/3 — OS ARP Cache ===")
    cache_hosts = _parse_arp_cache(log=log)

    icmp_hosts: list[DiscoveredHost] = []
    if icmp:
        if log:
            log("=== Stage 3/3 — ICMP Ping Sweep ===")

        if subnet:
            subnets_to_sweep = [subnet]
        else:
            subnets_to_sweep = [sn for sn, _ in _get_iface_subnets()]

        # Always append gateway-discovered subnets
        for sn in extra_subnets:
            subnets_to_sweep.append(sn)

        pinged_ips: list[str] = []
        for sn in subnets_to_sweep:
            pinged_ips.extend(_icmp_sweep(sn, log=log))

        # For gateway-discovered subnets, also run a TCP sweep — many IoT
        # devices (cameras, smart speakers, hubs) block ICMP but respond on
        # port 80/443/554/8080.  ICMP won't see them; TCP will.
        tcp_ips: set[str] = set()
        if extra_subnets:
            if log:
                log("=== TCP sweep on gateway subnets (catches ICMP-blocking devices) ===")
            for sn in extra_subnets:
                for ip in _tcp_sweep(sn, log=log):
                    tcp_ips.add(ip)

        all_found_ips = list(dict.fromkeys(pinged_ips + list(tcp_ips)))

        if all_found_ips:
            # Re-read ARP cache — pings/TCP connects will have caused the OS
            # to ARP for each responding host, populating MACs.
            post_cache = {h.ip: h for h in _parse_arp_cache()}
            for ip in all_found_ips:
                if ip in post_cache:
                    icmp_hosts.append(post_cache[ip])
                else:
                    icmp_hosts.append(DiscoveredHost(ip=ip, mac=""))

    # Scapy results passed first so their MACs take priority in the merge
    merged = _merge_hosts(arp_hosts, cache_hosts, icmp_hosts)

    if log:
        log(
            f"Merge complete — {len(arp_hosts)} ARP  |  "
            f"{len(cache_hosts)} cache  |  {len(icmp_hosts)} ICMP/TCP  →  "
            f"{len(merged)} unique host(s)"
        )

    if not merged:
        raise RuntimeError(
            "No hosts found. Ensure you are connected to the network "
            "and running as Administrator (required for ARP)."
        )

    enrich_hosts(merged, log=log)
    return merged
