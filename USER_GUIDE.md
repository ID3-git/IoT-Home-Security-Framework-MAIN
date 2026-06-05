# IoT Shield — User Guide for Home Network Security

## What This Tool Does

IoT Shield scans your home network to find:
- Every device connected to your WiFi and ethernet
- What services (web servers, SSH, etc.) each device is running
- Known security vulnerabilities affecting those devices
- Plain-English explanations and fixes for each problem

**All data stays on your computer.** Nothing is uploaded to the internet.

---

## Step 1: Download IoT Shield

1. Go to: https://github.com/ID3-git/IoT-Home-Security-Framework-MAIN
2. Click **Code** (green button)
3. Click **Download ZIP**
4. Extract the ZIP file to your Desktop or Documents folder
5. You'll see a folder named `IoT-Home-Security-Framework-MAIN-main`

---

## Step 2: Install Python

Python is the programming language IoT Shield runs on.

1. Go to: https://www.python.org/downloads/
2. Click **Download Python 3.14.3** (or latest version)
3. Run the installer
4. **IMPORTANT:** Check the box that says **"Add Python to PATH"**
5. Click **Install Now**
6. Wait for installation to complete

**Verify it worked:**
- Press `Windows Key + R`
- Type `cmd` and press Enter
- Type: `python --version`
- You should see: `Python 3.14.3` (or similar)

---

## Step 3: Install Nmap (Required for Scanning)

Nmap is the tool that actually scans your network for devices and vulnerabilities.

1. Go to: https://nmap.org/download.html
2. Download **Nmap Windows Installer** (latest version, e.g., nmap-7.98-setup.exe)
3. Run the installer
4. Click **Next** through all screens (use default options)
5. When asked about **Npcap**, click **Install** (this is required for network scanning)
6. Wait for installation to complete
7. Click **Finish**

**Verify it worked:**
- Press `Windows Key + R`
- Type `cmd` and press Enter
- Type: `nmap --version`
- You should see the Nmap version number

---

## Step 4: (Optional) Install Ollama for AI Advice

Ollama provides plain-English explanations of vulnerabilities found on your network. This step is **optional** — the tool works without it.

1. Go to: https://ollama.com
2. Click **Download** (for Windows)
3. Run the installer
4. Follow the installation steps
5. Once installed, Ollama will start automatically in the background

**To verify:** Look for an Ollama icon in your system tray (bottom right of taskbar).

---

## Step 5: Set Up IoT Shield

Now we'll prepare IoT Shield to run.

1. Open the folder `IoT-Home-Security-Framework-MAIN-main` that you extracted in Step 1
2. Right-click inside the empty folder
3. Select **Open in Terminal** (or **Open PowerShell window here**)
4. Type these commands one at a time, pressing Enter after each:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

This creates an isolated environment and installs all the tools IoT Shield needs.

**Wait for each command to finish** before typing the next one. You'll see text scroll by — this is normal.

---

## Step 6: Launch IoT Shield

1. In the same terminal window, type:

```powershell
python launcher.py
```

2. Press Enter

3. A **splash screen** will appear, checking for:
   - ✅ Python (should be OK)
   - ✅ Nmap (should be OK)
   - ⚠️ Ollama (optional — if not running, you can skip AI advice)

4. Wait 2-3 seconds, then the **GUI window** will open

You're ready to scan!

---

## Step 7: Scan Your Network

1. In the GUI window, click the **"Scan Network"** button
2. The application will:
   - Automatically detect your network
   - Find all connected devices
   - Scan each device for open ports and services
3. **This takes 1-5 minutes** depending on how many devices you have
4. A **progress bar** shows the status

Watch the log window to see what's being discovered in real-time.

---

## Step 8: Understanding the Results

### Color Coding (Traffic Light System)

When the scan completes, you'll see a **network map** with colored circles:

| Color | Meaning | Action |
|-------|---------|--------|
| 🔴 **Red** | Critical Risk | Fix immediately — serious vulnerabilities found |
| 🟠 **Orange** | High Risk | Review this week — significant vulnerabilities |
| 🟡 **Yellow** | Medium Risk | Review this month — moderate issues |
| 🟢 **Green** | Low Risk | Monitor — minor or old issues |
| 🔵 **Blue** | Info | No action needed — no major vulnerabilities |

### Example Results

**Your TV (Red — Critical):**
- Open ports: 80, 8080, 9200
- Problem: Running an old web server with known security hole
- Risk Score: 7.8/10

**Your Printer (Green — Low):**
- Open ports: 9100, 5353
- Problem: None detected
- Risk Score: 1.2/10

---

## Step 9: View Device Details

1. **Click on any colored circle** on the network map
2. A **detail panel** opens showing:
   - **Device Name/Vendor** (e.g., "LG Smart TV")
   - **IP Address** (e.g., 192.168.1.100)
   - **Open Ports** (e.g., ports 80, 443, 8080)
   - **Services Running** (e.g., "Apache Web Server v2.4.41")
   - **CVEs Found** (known security vulnerabilities)
   - **Risk Score** (0–10)

---

## Step 10: Read AI Advice (If Ollama is Running)

If you installed Ollama and it's running:

1. In the detail panel, scroll down to **"AI Remediation Advice"**
2. Read the plain-English explanation:

> "Your IP camera is running an outdated web server (nginx 1.25.3) that has a critical security vulnerability (CVE-2024-1234, severity 8.1/10).
>
> **What to do:**
> 1. Log into your camera at http://192.168.1.50
> 2. Look for Settings → System Update → Firmware Update
> 3. If an update exists, install it immediately
> 4. If not available, consider replacing the camera"

---

## Troubleshooting

### Problem: "Python not found"
**Solution:** You didn't add Python to PATH. Uninstall Python and reinstall, checking the "Add Python to PATH" box.

### Problem: "Nmap not found"
**Solution:** Nmap didn't install correctly. Go to https://nmap.org/download.html and reinstall.

### Problem: Scan times out or hangs
**Solution:** Some devices on your network are slow to respond. Close other programs using the network and try again.

### Problem: No devices found
**Solution:** 
- Make sure you're connected to your WiFi
- Run the terminal as Administrator (right-click → Run as Administrator)
- Check that your firewall isn't blocking Nmap

### Problem: Ollama showing "not running"
**Solution:** 
- Ollama is optional. Click OK to skip it.
- If you want AI advice, download Ollama from https://ollama.com and run it.

---

## Understanding Common Vulnerabilities

### HTTP on Port 80
- **What it means:** Your device has an unencrypted web server
- **Why it's bad:** Anyone on your network can see passwords transmitted in plain text
- **What to do:** Update the device's firmware or disable the web server

### SSH on Port 22
- **What it means:** Your device allows remote login
- **Why it's bad:** Hackers can try to guess the password
- **What to do:** Use a strong, unique password or disable SSH if you don't use it

### Default Credentials Detected
- **What it means:** Nmap found the device is using factory default username/password
- **Why it's bad:** Hackers know these credentials (they're public)
- **What to do:** Log in and change the password immediately

### Old Service Versions
- **What it means:** Your device is running old software with known bugs
- **Why it's bad:** Hackers know how to exploit old bugs
- **What to do:** Update the device's firmware/software

---

## Privacy & Security

- ✅ **All scanning is local** — data never leaves your computer
- ✅ **Non-intrusive** — we send polite pings, not aggressive probes
- ✅ **No telemetry** — we don't track what you scan
- ✅ **Offline capable** — works without internet connection (except initial NVD vulnerability lookup)

---

## Scanning Again Later

To scan again:

1. Open the folder `IoT-Home-Security-Framework-MAIN-main`
2. Right-click → **Open in Terminal**
3. Type: `venv\Scripts\activate`
4. Type: `python launcher.py`
5. Click **Scan Network**

---

## Need Help?

- Check **Troubleshooting** section above
- Go to: https://github.com/ID3-git/IoT-Home-Security-Framework-MAIN/issues
- Read the **README.md** in the folder for technical details

---

**Stay safe! 🔒**
