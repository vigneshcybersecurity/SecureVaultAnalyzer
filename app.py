from flask import Flask, render_template, request, redirect, url_for
import os, hashlib, psutil, re, json

app = Flask(__name__)

# Directory to monitor
MONITOR_DIR = "./monitor_dir"
LOG_FILE = "./logs/alerts_log.json"

# Patterns to detect sensitive data
SENSITIVE_PATTERNS = [
    r"(?:password|passwd|secret)\s*[:=]\s*.+",
    r"[A-Za-z0-9]{32,}",
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
]

file_hashes = {}

# Initialize hashes
def initialize_hashes():
    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            file_hashes[path] = hash_file(path)

def hash_file(path):
    try:
        with open(path, "rb") as f:
            h = hashlib.sha256()
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def check_file_integrity():
    alerts = []
    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            current_hash = hash_file(path)
            if path not in file_hashes:
                alerts.append(f"New file detected: {path}")
                file_hashes[path] = current_hash
            elif current_hash != file_hashes[path]:
                alerts.append(f"File modified: {path}")
                file_hashes[path] = current_hash
    return alerts

def scan_sensitive_data():
    alerts = []
    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            try:
                with open(path, "r", errors="ignore") as f:
                    content = f.read()
                    for pattern in SENSITIVE_PATTERNS:
                        if re.search(pattern, content):
                            alerts.append(f"Sensitive data found in: {path}")
                            break
            except:
                continue
    return alerts

def check_processes():
    alerts = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and name.lower() not in ["python.exe","explorer.exe","cmd.exe"]:
                alerts.append(f"Unknown process detected: {name} (PID {proc.info['pid']})")
        except:
            continue
    return alerts

def log_alerts(alerts):
    os.makedirs("./logs", exist_ok=True)
    with open(LOG_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

@app.route("/")
def index():
    alerts = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            alerts = json.load(f)
    return render_template("index.html", alerts=alerts)

@app.route("/scan")
def scan():
    file_alerts = check_file_integrity()
    sensitive_alerts = scan_sensitive_data()
    process_alerts = check_processes()
    all_alerts = file_alerts + sensitive_alerts + process_alerts
    log_alerts(all_alerts)
    return redirect(url_for("index"))

if __name__ == "__main__":
    os.makedirs(MONITOR_DIR, exist_ok=True)
    initialize_hashes()
    app.run(debug=True)
