# 🛡️ Cyber Watchdog

**Cyber Watchdog** is a lightweight anti-cyberstalker toolkit for Windows.  
It scans your PC for suspicious processes, network activity, hidden executables, and malware using [VirusTotal](https://virustotal.com).

---

### 🚀 Features
- Real-time process + network monitoring
- Full disk `.exe` file scan
- Hidden file detection
- VirusTotal hash scan
- Discord or Local logging
- Auto-update via GitHub
- GUI dashboard for setup

---

### 🧪 How to Use

1. Clone or download the repo  
2. Run `dashboard.py` to set up where logs should go  
3. Launch `scan.py` — your watchdog starts monitoring immediately

---

### ⚙️ Requirements

- Python 3.8+
- Libraries:
  - `psutil`
  - `requests`

Install them with:

```bash
pip install psutil requests
