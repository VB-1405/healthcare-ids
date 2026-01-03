import os
import json
import signal
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, jsonify

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Files
ALERTS_PATH = os.path.join(APP_DIR, "alerts.jsonl")
PID_FILE = os.path.join(APP_DIR, ".ids.pid")

CONFIG_DIR = os.path.join(APP_DIR, "config")
RULES_DIR = os.path.join(APP_DIR, "rules")
LOGS_DIR = os.path.join(APP_DIR, "logs")
TEMPLATES_DIR = os.path.join(APP_DIR, "templates")
STATIC_DIR = os.path.join(APP_DIR, "static")

CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
RULES_PATH = os.path.join(RULES_DIR, "rules.yaml")

# Separate logs to avoid permission issues
IDS_LOG_PATH = os.path.join(LOGS_DIR, "ids.stdout.log")
APP_LOG_PATH = os.path.join(LOGS_DIR, "app.stdout.log")

DEFAULT_ARGS = {
    "iface": "wlan0",
    "window": 30,
    "ping_threshold": 5,
    "cooldown": 60,
    "emulate": False,
    "sudo": False
}

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)


# ----------------------------
# Helpers
# ----------------------------
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _touch_file(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "a", encoding="utf-8"):
            pass
    # Try to make it writable by current user (won't fix root-owned, but helps new files)
    try:
        os.chmod(path, 0o664)
    except Exception:
        pass


def ensure_files_exist():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(RULES_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    os.makedirs(os.path.join(TEMPLATES_DIR, "partials"), exist_ok=True)

    _touch_file(ALERTS_PATH)
    _touch_file(IDS_LOG_PATH)
    _touch_file(APP_LOG_PATH)

    if not os.path.exists(CONFIG_PATH):
        default_config = {
            "allowlisted_subnets": ["192.168.0.0/16"],
            "allowlisted_ports": [22, 53, 80, 443, 5000, 8443],
            "known_devices": ["192.168.7.16"],
            "allowlisted_endpoints": ["192.168.7.0/24", "192.168.4.0/24"]
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2)

    if not os.path.exists(RULES_PATH):
        default_rules = """rules:
  - id: ping_scan_default
    enabled: true
    type: PING_SCAN
    severity: low
    ping_threshold: 5
    window_sec: 30
    cooldown_sec: 60

  - id: port_sweep_default
    enabled: true
    type: PORT_SWEEP
    severity: high
    unique_dst_port_threshold: 25
    window_sec: 30
    cooldown_sec: 60
"""
        with open(RULES_PATH, "w", encoding="utf-8") as f:
            f.write(default_rules)


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def read_pid():
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return None


def write_pid(pid: int):
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(pid))


def clear_pid():
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception:
        pass


def get_status():
    pid = read_pid()
    if pid and is_pid_running(pid):
        return {"running": True, "pid": pid}
    return {"running": False, "pid": None}


def append_app_log(msg: str):
    try:
        with open(APP_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{now_str()}] [APP] {msg}\n")
    except Exception:
        pass


def start_ids_process(args_override=None):
    st = get_status()
    if st["running"]:
        return False, f"IDS already running (pid={st['pid']})"

    args = dict(DEFAULT_ARGS)
    if isinstance(args_override, dict):
        args.update({k: v for k, v in args_override.items() if v is not None})

    ids_py = os.path.join(APP_DIR, "ids.py")
    if not os.path.exists(ids_py):
        return False, "ids.py not found in project folder"

    cmd = [
        "python3",
        ids_py,
        "--config", CONFIG_PATH,
        "--alerts", ALERTS_PATH,
        "--log", IDS_LOG_PATH,
        "--rules", RULES_PATH,
        "--iface", str(args["iface"]),
        "--window", str(args["window"]),
        "--ping-threshold", str(args["ping_threshold"]),
        "--cooldown", str(args["cooldown"])
    ]
    if args.get("emulate"):
        cmd.append("--emulate")

    # Optional sudo (only if capture requires it)
    if args.get("sudo"):
        cmd = ["sudo", "-n"] + cmd  # -n avoids hanging for password

    # Write a visible header in IDS log
    try:
        with open(IDS_LOG_PATH, "a", encoding="utf-8") as logf:
            logf.write(f"\n----- [{now_str()}] START IDS -----\n")
            logf.flush()
    except Exception as e:
        return False, f"Cannot write IDS log: {e}"

    try:
        with open(IDS_LOG_PATH, "a", encoding="utf-8") as logf:
            proc = subprocess.Popen(
                cmd,
                stdout=logf,
                stderr=logf,
                cwd=APP_DIR,
                preexec_fn=os.setsid
            )
    except PermissionError as e:
        return False, f"Permission error starting IDS (log file not writable): {e}"
    except Exception as e:
        return False, f"Failed to start IDS: {e}"

    write_pid(proc.pid)
    append_app_log(f"START IDS pid={proc.pid} iface={args['iface']} window={args['window']} sudo={args.get('sudo', False)} emulate={args.get('emulate', False)}")
    return True, f"Started IDS (pid={proc.pid})"


def stop_ids_process():
    st = get_status()
    if not st["running"]:
        clear_pid()
        return False, "IDS is not running"

    pid = st["pid"]
    try:
        os.killpg(pid, signal.SIGTERM)
        append_app_log(f"STOP IDS pid={pid}")
        clear_pid()
        return True, f"Stopped IDS (pid={pid})"
    except Exception as e:
        clear_pid()
        return False, f"Failed to stop IDS: {e}"


def reload_ids_process():
    stop_ids_process()
    return start_ids_process()


def read_jsonl(path, limit=800):
    items = []
    if not os.path.exists(path):
        return items
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return items
    items = items[-limit:]
    items.reverse()  # newest first
    return items


def read_tail(path, max_lines=500):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[-max_lines:])
    except Exception:
        return ""


# ----------------------------
# UI Routes
# ----------------------------
@app.route("/")
def dashboard():
    ensure_files_exist()
    return render_template("dashboard.html", status=get_status())


@app.route("/alerts")
def alerts_page():
    ensure_files_exist()
    return render_template("alerts.html", status=get_status(), alerts_path=ALERTS_PATH)


@app.route("/logs")
def logs_page():
    ensure_files_exist()
    return render_template(
        "logs.html",
        status=get_status(),
        ids_log_path=IDS_LOG_PATH,
        app_log_path=APP_LOG_PATH
    )


@app.route("/rules")
def rules_page():
    ensure_files_exist()
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            rules_text = f.read()
    except Exception:
        rules_text = "rules:\n"
    return render_template("rules.html", status=get_status(), rules_text=rules_text, rules_path=RULES_PATH)


# ----------------------------
# API Routes
# ----------------------------
@app.route("/api/status", methods=["GET"])
def api_status():
    ensure_files_exist()
    return jsonify(get_status())


@app.route("/api/start", methods=["POST"])
def api_start():
    ensure_files_exist()
    payload = request.get_json(silent=True) or {}
    ok, msg = start_ids_process(payload)
    return jsonify({"ok": ok, "msg": msg, "status": get_status()}), (200 if ok else 400)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    ensure_files_exist()
    ok, msg = stop_ids_process()
    return jsonify({"ok": ok, "msg": msg, "status": get_status()}), (200 if ok else 400)


@app.route("/api/reload", methods=["POST"])
def api_reload():
    ensure_files_exist()
    ok, msg = reload_ids_process()
    return jsonify({"ok": ok, "msg": msg, "status": get_status()}), (200 if ok else 400)


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    ensure_files_exist()
    return jsonify({"ok": True, "alerts": read_jsonl(ALERTS_PATH, limit=800)})


@app.route("/api/logs", methods=["GET"])
def api_logs():
    ensure_files_exist()
    which = request.args.get("which", "ids")
    if which == "app":
        return jsonify({"ok": True, "log_tail": read_tail(APP_LOG_PATH, max_lines=700)})
    return jsonify({"ok": True, "log_tail": read_tail(IDS_LOG_PATH, max_lines=700)})


@app.route("/api/clear_alerts", methods=["POST"])
def api_clear_alerts():
    ensure_files_exist()
    try:
        with open(ALERTS_PATH, "w", encoding="utf-8"):
            pass
        append_app_log("Cleared alerts.jsonl from UI")
        return jsonify({"ok": True, "msg": "Alerts cleared"}), 200
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400


@app.route("/api/clear_logs", methods=["POST"])
def api_clear_logs():
    ensure_files_exist()
    which = request.args.get("which", "ids")
    try:
        path = APP_LOG_PATH if which == "app" else IDS_LOG_PATH
        with open(path, "w", encoding="utf-8"):
            pass
        append_app_log(f"Cleared logs ({which}) from UI")
        return jsonify({"ok": True, "msg": "Logs cleared"}), 200
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400


@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    ensure_files_exist()
    if request.method == "GET":
        try:
            with open(RULES_PATH, "r", encoding="utf-8") as f:
                return jsonify({"ok": True, "rules_text": f.read()})
        except Exception as e:
            return jsonify({"ok": False, "msg": str(e), "rules_text": "rules:\n"}), 200

    payload = request.get_json(silent=True) or {}
    rules_text = payload.get("rules_text", "")
    if not isinstance(rules_text, str) or not rules_text.strip():
        return jsonify({"ok": False, "msg": "Rules cannot be empty"}), 400

    try:
        with open(RULES_PATH, "w", encoding="utf-8") as f:
            f.write(rules_text)
        append_app_log("Saved rules.yaml from UI")
        return jsonify({"ok": True, "msg": "Rules saved"}), 200
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400


if __name__ == "__main__":
    ensure_files_exist()
    app.run(host="0.0.0.0", port=5000, debug=False)
