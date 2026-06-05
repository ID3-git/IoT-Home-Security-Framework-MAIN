"""
Verbose Nmap debug utility — Appendix B documentation tool.

Purpose: Capture raw Nmap output for a target host so that scan failures
can be precisely documented. Runs three escalating probe strategies and
writes results to a timestamped text file for inclusion in the appendix.

Run from repo root:
    py -3.14 -m iden_coop.scanner.debug_nmap --target 10.10.2.40
"""

import argparse
import datetime
import subprocess
import shutil
import sys
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────

def _nmap_path() -> str:
    path = shutil.which("nmap")
    if not path:
        sys.exit("[ERROR] Nmap not found on PATH. Install from https://nmap.org")
    return path


def _run(label: str, args: list[str]) -> str:
    """Run nmap and return combined stdout+stderr output."""
    print(f"\n{'='*60}")
    print(f"PROBE: {label}")
    print(f"CMD:   {' '.join(args)}")
    print("="*60)
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr
        print(output)
        return f"--- {label} ---\nCMD: {' '.join(args)}\n\n{output}\n"
    except subprocess.TimeoutExpired:
        msg = "[TIMEOUT] Nmap did not complete within 120 seconds.\n"
        print(msg)
        return f"--- {label} ---\n{msg}\n"


# ── Probe strategies ───────────────────────────────────────────────────────

def probe_standard(nmap: str, target: str) -> str:
    """
    Strategy 1 — mirror the framework's normal scan flags.
    Reproduces the exact failure to confirm it is consistent.
    Matches nmap_scan.py:95 port range and -sT timing.
    """
    return _run(
        "STRATEGY 1: Standard framework flags (reproducing failure)",
        [
            nmap, "-sT", "-sV", "-T3", "-v", "--reason",
            "-p", "1-1024,1883,2323,5900,8080,8443,8883",
            target,
        ],
    )


def probe_skip_discovery(nmap: str, target: str) -> str:
    """
    Strategy 2 — add -Pn to skip host-up detection.
    Nmap's default probes (ICMP echo, TCP SYN 443, TCP ACK 80) can be
    blocked by host firewalls, causing Nmap to mark the host as 'down'
    and skip all port scanning despite the host being reachable via ARP.
    -Pn forces scanning regardless.
    """
    return _run(
        "STRATEGY 2: -Pn (skip host discovery — treat as always-up)",
        [
            nmap, "-sT", "-sV", "-Pn", "-T3", "-v", "--reason",
            "-p", "443,80,8080,8443,22,23,21",
            target,
        ],
    )


def probe_targeted_443(nmap: str, target: str) -> str:
    """
    Strategy 3 — isolate port 443 with maximum verbosity and packet trace.
    --packet-trace prints every sent/received packet so we can see if
    TCP SYN is being sent and whether RST or no response is returned.
    This distinguishes 'filtered' (firewall drop) from 'closed' (RST).
    """
    return _run(
        "STRATEGY 3: Isolated port 443 with --packet-trace",
        [
            nmap, "-sT", "-Pn", "-p", "443", "-v",
            "--reason", "--packet-trace",
            target,
        ],
    )


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verbose Nmap debug tool for Appendix B documentation"
    )
    parser.add_argument("--target", required=True, help="Target IP (e.g. 10.10.2.40)")
    parser.add_argument("--out", default=".", help="Output directory for the report file")
    args = parser.parse_args()

    nmap = _nmap_path()
    target = args.target
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = Path(args.out) / f"nmap_debug_{target.replace('.', '_')}_{ts}.txt"

    header = (
        f"IdenCoop — Nmap Verbose Debug Report\n"
        f"Target  : {target}\n"
        f"Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Purpose : Appendix B — Assessment Module Failure Documentation\n"
        f"{'='*60}\n\n"
    )

    print(header)
    report = header

    report += probe_standard(nmap, target)
    report += probe_skip_discovery(nmap, target)
    report += probe_targeted_443(nmap, target)

    # Write report
    out_file.write_text(report, encoding="utf-8")
    print(f"\n[DONE] Full debug report written to: {out_file}")
    print("       Include this file as Appendix B in your submission.")


if __name__ == "__main__":
    main()
