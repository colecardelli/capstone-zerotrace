import sys, os
from flask import Flask, request, jsonify, send_from_directory, Response
import subprocess, json, threading, time

# --- Fix Python path so we can import backend modules ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
sys.path.append(BACKEND_DIR)

app = Flask(__name__, static_folder="frontend", static_url_path="/")

# --- Paths for progress and results ---
SCAN_LOG_PATH = os.path.join(BACKEND_DIR, "scan_progress.json")
SCAN_RESULTS_PATH = os.path.join(BACKEND_DIR, "scan_results.json")
SCAN_PROCESS = None


@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

@app.route("/run_scan", methods=["POST"])
def run_scan():
    global SCAN_PROCESS
    data = request.get_json()
    mode = data.get("mode", "quick")
    discovery = data.get("discovery", "nmap")
    export = data.get("export", "excel")

    # clear last progress file
    if os.path.exists(SCAN_LOG_PATH):
        os.remove(SCAN_LOG_PATH)

    # Run scanner in background thread
    def run_scanner():
        cmd = ["python", os.path.join("backend", "zerotrace_scanner.py"), mode, discovery, export]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
            for line in proc.stdout:
                # Example: progress logs written by zerotrace_scanner
                if "PROGRESS" in line:
                    try:
                        # Expect JSON like: PROGRESS {"current":12,"total":85,"ip":"192.168.1.5"}
                        data = json.loads(line.split("PROGRESS")[-1].strip())
                        with open(SCAN_LOG_PATH, "w") as f:
                            json.dump(data, f)
                    except Exception:
                        pass
            proc.wait()

    thread = threading.Thread(target=run_scanner)
    thread.start()

    return jsonify({"status": "Scan started"})

@app.route("/progress")
def progress():
    def stream():
        last_data = None
        while True:
            if os.path.exists(SCAN_LOG_PATH):
                with open(SCAN_LOG_PATH, "r") as f:
                    try:
                        data = json.load(f)
                        if data != last_data:
                            last_data = data
                            yield f"data: {json.dumps(data)}\n\n"
                    except Exception:
                        pass
            time.sleep(1)
    return Response(stream(), mimetype="text/event-stream")


@app.route("/scan_results")
def scan_results():
    if os.path.exists(SCAN_RESULTS_PATH):
        with open(SCAN_RESULTS_PATH, "r", encoding="utf-8") as f:
            return Response(f.read(), mimetype="text/plain")
    return jsonify({"error": "No results yet"}), 404


if __name__ == "__main__":
    app.run(debug=True)


