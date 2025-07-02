import psutil
import datetime
import os
import json
import ctypes
import time
import requests
import hashlib
import urllib.request

config_path = "log_config.json"
local_version = "1.0.0"
remote_version_url = "https://raw.githubusercontent.com/YOUR_GITHUB_REPO/main/version.txt"
remote_script_url = "https://raw.githubusercontent.com/YOUR_GITHUB_REPO/main/scan.py"
VT_API_KEY = "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# ====== CONFIG LOADING ====== #

def get_config():
    with open(config_path) as f:
        return json.load(f)

def send_to_discord(message, url):
    try:
        requests.post(url, json={"content": message})
    except:
        print("❌ Failed to send to Discord.")

def log_event(message):
    config = get_config()
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    full_msg = f"{timestamp} {message}"

    if config["log_type"] == "local":
        try:
            log_file = os.path.join(config["log_path"], "scan_log.txt")
            with open(log_file, 'a') as f:
                f.write(full_msg + '\n')
        except Exception as e:
            print("❌ Failed to write local log:", e)

    elif config["log_type"] == "discord":
        send_to_discord(full_msg, config["webhook_url"])

# ====== VIRUSTOTAL FILE HASHING ====== #

def get_file_hash(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        log_event(f"❌ Hash error: {e}")
        return None

def check_virustotal(file_path):
    file_hash = get_file_hash(file_path)
    if not file_hash:
        return
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(VT_URL + file_hash, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious = data['data']['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                log_event(f"☣️ VT ALERT: {file_path} flagged by {malicious} engines.")
        elif response.status_code == 404:
            log_event(f"❓ VT unknown hash: {file_path}")
        else:
            log_event(f"⚠️ VT error for {file_path}: {response.status_code}")
    except Exception as e:
        log_event(f"❌ VT scan failed: {e}")

# ====== AUTO-UPDATER ====== #

def check_for_update():
    try:
        online_version = urllib.request.urlopen(remote_version_url).read().decode().strip()
        if online_version != local_version:
            log_event(f"⬆️ Update available: {online_version}")
            update_script()
    except Exception as e:
        log_event(f"❌ Update check failed: {e}")

def update_script():
    try:
        new_code = urllib.request.urlopen(remote_script_url).read().decode()
        with open("scan.py", "w") as f:
            f.write(new_code)
        log_event("✅ Script updated successfully. Please restart the app.")
    except Exception as e:
        log_event(f"❌ Update failed: {e}")

# ====== SCANNERS ====== #

suspicious_keywords = ['keylogger', 'rat', 'spy', 'stealer', 'sniff', 'remote']
drives_to_scan = ["C:\\"]

def scan_processes():
    found = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(kw in name for kw in suspicious_keywords):
                found.append((proc.info['pid'], name))
        except:
            continue
    return found

def scan_network_connections():
    suspicious_ports = [4444, 1337, 6666, 31337, 5555]
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status == 'ESTABLISHED' and conn.laddr.port not in (80, 443):
                pid = conn.pid
                proc_name = psutil.Process(pid).name() if pid else "Unknown"
                line = f"{proc_name} (PID: {pid}) → {conn.raddr.ip}:{conn.raddr.port}"
                log_event(line)
                if conn.raddr.port in suspicious_ports:
                    log_event(f"⚠️ Suspicious port detected: {line}")
        except:
            continue

def scan_exe_files(paths):
    suspicious_files = []
    for path in paths:
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith(".exe"):
                    full_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(full_path)
                        if size < 10_000 or size > 500_000_000:
                            suspicious_files.append(full_path)
                        if any(kw in file.lower() for kw in suspicious_keywords):
                            suspicious_files.append(full_path)
                    except:
                        continue
    return suspicious_files

def is_hidden(filepath):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
        return bool(attrs & 2)
    except:
        return False

def scan_hidden_files(paths):
    hidden_files = []
    for path in paths:
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if is_hidden(full_path) and file.lower().endswith(".exe"):
                    hidden_files.append(full_path)
    return hidden_files

# ====== MAIN LOOP ====== #

if __name__ == "__main__":
    check_for_update()
    while True:
        log_event("🔍 Starting new scan...")

        suspicious = scan_processes()
        for pid, name in suspicious:
            log_event(f"⚠️ Suspicious Process: {name} (PID: {pid})")

        scan_network_connections()

        deep_files = scan_exe_files(drives_to_scan)
        for f in deep_files:
            log_event(f"⚠️ Suspicious EXE: {f}")
            check_virustotal(f)

        hidden_files = scan_hidden_files(drives_to_scan)
        for h in hidden_files:
            log_event(f"⚠️ Hidden EXE: {h}")
            check_virustotal(h)

        log_event("✅ Scan complete. Waiting 5 minutes...\n")
        time.sleep(300)
