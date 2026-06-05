# IoT Shield — Automated Vulnerability Assessment Framework for Home Networks

**Final Year Project — De Montfort University**  
**Module:** CSEC3100 | **Author:** Iden Coop (P2798257) | **Academic Year:** 2025-26

---

## Overview

IoT Shield is an automated vulnerability assessment framework designed to identify and analyze security risks on home networks. The tool discovers connected devices using multi-method network enumeration, performs comprehensive port scanning with service identification, correlates findings against the National Vulnerability Database (NVD), and provides plain-English remediation advice via a local LLM.

All scans remain on-device. No data is uploaded to external services.

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| **OS** | Windows 11 | Windows 10 minimum; Windows 11 recommended |
| **Python** | 3.14.3 | Must be added to PATH during installation |
| **Nmap** | 7.98+ | Requires Npcap 1.83+ for packet capture |
| **Npcap** | 1.83+ | WinPcap replacement; installed as part of Nmap |
| **Ollama** | Latest | Optional; for LLM-based remediation advice |
| **Ollama Model** | llama3.2 | Default model; can be overridden with OLLAMA_MODEL env var |
| **RAM** | 4 GB minimum | 8 GB recommended |

---

## Installation

### Step 1: Download Python

1. Download Python 3.14.3 from https://www.python.org/downloads/
2. Run the installer
3. **Important:** Check "Add Python to PATH" before clicking Install
4. Verify installation:
   ```powershell
   python --version
   ```

### Step 2: Download and Install Nmap

1. Download Nmap 7.98 from https://nmap.org/download.html
2. Run the installer
3. Install with default options (includes Npcap 1.83)
4. Verify installation:
   ```powershell
   nmap --version
   ```

### Step 3: (Optional) Install Ollama

1. Download Ollama from https://ollama.com
2. Run the installer
3. Pull the default model:
   ```powershell
   ollama pull llama3.2
   ```
4. Start Ollama server (runs in background):
   ```powershell
   ollama serve
   ```

### Step 4: Clone IoT Shield Repository

```powershell
# Clone the repository
git clone https://github.com/ID3-git/iot-shield.git
cd iot-shield

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 5: Run IoT Shield

```powershell
python launcher.py
```

The application will:
- Verify Nmap installation (required)
- Verify Ollama availability (optional)
- Initialize SQLite database
- Launch the GUI

---

## How to Run

### First Scan

```powershell
# From project root, with venv activated:
python launcher.py

# Application will start GUI
# Click "Scan Network" to begin
# Scans typically complete in 1-3 minutes
```

### Run Test Suite

```powershell
# Run all tests with verbose output
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_discovery.py -v

# Run with coverage report
python -m pytest tests/ --cov=. --cov-report=html
```

### Expected Test Results

- **Total Tests:** 363
- **Passing:** 314 (86.5%)
- **Failing:** 49 (13.5% — includes intentional failures for edge cases)
- **Execution Time:** ~5-10 seconds

---

## Project Structure

```
IoT Shield/
├── scanner/                 # Network enumeration & port scanning
│   ├── discovery.py        # Multi-method host discovery (ARP, ICMP, TCP)
│   ├── nmap_scan.py        # Nmap wrapper with two-phase scanning
│   └── cve_lookup.py       # NVD REST API v2 integration
├── database/               # Data persistence
│   └── db.py              # SQLite schema and CRUD operations
├── gui/                    # User interface
│   └── iot_scanner_gui.py # Tkinter GUI (splash screen + results dashboard)
├── llm/                    # LLM integration
│   └── advisor.py         # Ollama integration for remediation advice
├── analysis/               # Risk assessment
│   └── risk_engine.py     # CVSS-based composite risk scoring
├── tests/                  # Comprehensive test suite (363 tests)
│   ├── test_discovery.py
│   ├── test_nmap_scan.py
│   ├── test_database.py
│   ├── test_gui.py
│   ├── test_llm_grounding.py
│   ├── test_non_intrusive.py
│   ├── test_risk_engine.py
│   ├── test_known_issues.py
│   └── test_regression.py
├── launcher.py            # Application entry point with service management
├── requirements.txt       # Python package dependencies
├── APPENDIX_COMPREHENSIVE_TEST_RESULTS.md  # Full test results for dissertation
├── README.md             # This file
└── .gitignore
```

---

## Author & Attribution

**Developer:** Iden Coop  
**Student ID:** P2798257  
**Institution:** De Montfort University  
**Module:** CSEC3100 (Cybersecurity Project)  
**Academic Year:** 2025-26

This project represents original work completed as part of the final year cybersecurity degree programme.

---

## References

- **CVSS v3.1 Specification:** https://www.first.org/cvss/v3.1/
- **NVD API v2:** https://nvd.nist.gov/developers/vulnerabilities
- **Nmap Project:** https://nmap.org/
- **Ollama:** https://ollama.com/
- **Scapy Documentation:** https://scapy.readthedocs.io/

---

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users are responsible for:

- Obtaining explicit authorization before scanning any network they do not own
- Complying with applicable laws regarding network scanning and vulnerability assessment
- Verifying security recommendations independently before implementation
- Understanding that this tool is provided without warranty or guarantee of accuracy

**Unauthorized network scanning may violate local, state, or federal laws.**

---

**IoT Shield v1.0.0** | De Montfort University CSEC3100 Final Year Project | 2026
