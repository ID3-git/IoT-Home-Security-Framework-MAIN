"""
Ollama LLM integration for plain-language remediation advice.

Ollama must be running locally: https://ollama.com
Default model: llama3.2  (override with OLLAMA_MODEL env var)
Default host:  http://localhost:11434 (override with OLLAMA_HOST env var)

Uses /api/generate with stream=true — no API key required.
All data stays on-device.
"""

import json
import os
from typing import Callable, Optional

import requests

OLLAMA_HOST  = os.environ.get("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")

_SYSTEM_PROMPT = (
    "You are a home network security assistant. "
    "Explain security findings in plain English for a non-technical homeowner. "
    "Give specific, actionable steps to fix each issue. "
    "Keep responses simple, friendly, and under 400 words. "
    "Do not invent CVEs or vulnerabilities not listed in the user message."
)

_USER_TEMPLATE = """\
A scan has found the following on a device:

Device type: {device_type}
Open ports: {ports}
Detected services: {services}
CVEs confirmed from NVD: {cve_list}

Explain these findings in plain English for a non-technical homeowner.
Give specific, actionable steps to fix each issue. Keep it simple and friendly.
Do not invent CVEs or vulnerabilities not listed above.\
"""


def _format_ports(services: list[dict]) -> str:
    open_svcs = [s for s in services if s.get("state") == "open"]
    if not open_svcs:
        return "None detected"
    return ", ".join(
        f"{s['port']}/{s.get('protocol', 'tcp')} ({s.get('name', '')})"
        for s in open_svcs
    )


def _format_services(services: list[dict]) -> str:
    parts = []
    for s in services:
        if s.get("state") != "open":
            continue
        label = s.get("name", "unknown")
        product = s.get("product", "")
        version = s.get("version", "")
        if product:
            label += f" ({product} {version})".rstrip()
        parts.append(label)
    return ", ".join(parts) if parts else "None"


def _format_cves(cves: list[dict]) -> str:
    if not cves:
        return "None found"
    lines = []
    for c in cves[:10]:
        lines.append(
            f"- {c.get('cve_id', '')} "
            f"(CVSS {c.get('cvss_score', 0.0)} {c.get('severity', '')}): "
            f"{c.get('description', '')[:120]}"
        )
    return "\n".join(lines)


def is_ollama_running() -> bool:
    """Return True if the Ollama server is reachable."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def list_models() -> list[str]:
    """Return list of locally available Ollama model names."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


def get_advice(
    device_type: str,
    services: list[dict],
    cves: list[dict],
    model: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Stream remediation advice from Ollama.

    Args:
        device_type: e.g. "Smart TV", "IP Camera".
        services:    list of service dicts from nmap/db.
        cves:        list of CVE dicts from db.
        model:       Ollama model name (defaults to OLLAMA_MODEL env / llama3.2).
        on_chunk:    called with each streamed text chunk.

    Returns:
        Full advice string.

    Raises:
        RuntimeError on connection / model errors.
    """
    if not is_ollama_running():
        raise RuntimeError(
            f"Ollama is not running at {OLLAMA_HOST}.\n"
            "Start it with: ollama serve\n"
            "Install from: https://ollama.com"
        )

    chosen_model = model or OLLAMA_MODEL

    prompt = _USER_TEMPLATE.format(
        device_type=device_type or "Unknown IoT Device",
        ports=_format_ports(services),
        services=_format_services(services),
        cve_list=_format_cves(cves),
    )

    payload = {
        "model":  chosen_model,
        "system": _SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": True,
    }

    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json=payload,
            stream=True,
            timeout=120,
        )
        if resp.status_code == 404:
            raise RuntimeError(
                f"Model '{chosen_model}' not found in Ollama.\n"
                f"Pull it first: ollama pull {chosen_model}"
            )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Cannot connect to Ollama at {OLLAMA_HOST}. Is it running?"
        )

    full_text = ""
    for raw_line in resp.iter_lines():
        if not raw_line:
            continue
        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        chunk = data.get("response", "")
        if chunk:
            full_text += chunk
            if on_chunk:
                on_chunk(chunk)
        if data.get("done"):
            break

    return full_text


_NETWORK_SYSTEM = (
    "You are a home network security analyst. "
    "Give a plain-English overview of the entire network scan result for a non-technical homeowner. "
    "Be concise (under 350 words). Use a structured format: "
    "1) Overall risk rating (Critical/High/Medium/Low/Good) with one sentence why. "
    "2) Top 3 concerns. "
    "3) Two priority actions the homeowner should take today. "
    "Do not invent any data not present in the input."
)

_NETWORK_TEMPLATE = """\
Network scan summary:
Subnets scanned: {subnets}
Total devices found: {total}
Risk breakdown: {breakdown}

Devices (IP | vendor | risk | open ports):
{device_lines}

Give an overall network security assessment for a non-technical homeowner.\
"""


def get_network_summary(
    results: list[dict],
    model: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Stream a whole-network AI security summary from Ollama.

    Args:
        results:   List of device dicts from the scan pipeline.
        model:     Ollama model name (defaults to OLLAMA_MODEL / llama3.2).
        on_chunk:  Called with each streamed text chunk.
    Returns:
        Full summary string.
    """
    if not is_ollama_running():
        raise RuntimeError(
            f"Ollama is not running at {OLLAMA_HOST}.\n"
            "Start it with: ollama serve"
        )

    # Build subnet list from IPs
    seen: set[str] = set()
    for d in results:
        ip = d.get("ip", "")
        parts = ip.split(".")
        if len(parts) == 4:
            seen.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    subnets = ", ".join(sorted(seen)) or "unknown"

    # Risk breakdown counts
    counts: dict[str, int] = {}
    for d in results:
        lvl = d.get("risk_level", "Info")
        counts[lvl] = counts.get(lvl, 0) + 1
    breakdown = ", ".join(f"{lvl}: {n}" for lvl, n in sorted(counts.items()))

    # Per-device lines (top 20 to keep prompt size reasonable)
    lines = []
    for d in results[:20]:
        ip      = d.get("ip", "?")
        vendor  = d.get("vendor") or d.get("os_guess") or "Unknown"
        risk    = d.get("risk_level", "Info")
        ports   = ", ".join(
            str(s["port"]) for s in d.get("services", []) if s.get("state") == "open"
        ) or "none"
        lines.append(f"  {ip} | {vendor} | {risk} | ports: {ports}")

    prompt = _NETWORK_TEMPLATE.format(
        subnets=subnets,
        total=len(results),
        breakdown=breakdown,
        device_lines="\n".join(lines) or "  (no device detail available)",
    )

    chosen_model = model or OLLAMA_MODEL
    payload = {
        "model":  chosen_model,
        "system": _NETWORK_SYSTEM,
        "prompt": prompt,
        "stream": True,
    }

    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json=payload,
            stream=True,
            timeout=120,
        )
        if resp.status_code == 404:
            raise RuntimeError(
                f"Model '{chosen_model}' not found.\n"
                f"Pull it: ollama pull {chosen_model}"
            )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot connect to Ollama at {OLLAMA_HOST}.")

    full_text = ""
    for raw_line in resp.iter_lines():
        if not raw_line:
            continue
        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        chunk = data.get("response", "")
        if chunk:
            full_text += chunk
            if on_chunk:
                on_chunk(chunk)
        if data.get("done"):
            break

    return full_text


DISCLAIMER = (
    "AI-generated remediation advice may be incorrect; "
    "verify all steps independently. "
    "Powered by Ollama (local) — no data leaves your machine."
)
