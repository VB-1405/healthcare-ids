#!/usr/bin/env python3
"""
app.py — Healthcare IDS Dashboard (Flask) with:
- Alerts page (/)
- Logs page (/logs)
- Rules Editor page (/rules)  ✅ edit/add/delete rule files from the UI

What the Rules Editor can do:
- List rule/config files (rules/*.py, rules/*.yaml, rules/*.yml, config.yaml)
- Open and edit a file in a textarea
- Validate before saving:
  - .py: syntax check via compile()
  - .yaml/.yml: YAML parse check (requires pyyaml)
- Create a new rules file
- Delete a rules file (only inside ./rules)
- (Optional) Reload IDS (Stop + Start) after changes

IMPORTANT:
- Your ids.py imports rules.healthcare_rules at runtime. If you edit rule code, you may need to Reload IDS.
- Keep sudoers NOPASSWD rule for starting IDS with sudo.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

from flask import Flask, jsonify, request, render_template_string

APP_DIR = Path(__file__).resolve().parent
RULES_DIR = APP_DIR / "rules"

IDS_SCRIPT = APP_DIR / "ids.py"
CONFIG_PATH = APP_DIR / "config.yaml"
ALERTS_JSONL = APP_DIR / "alerts.jsonl"

PID_FILE = APP_DIR / "ids.pid"
IDS_LOG = APP_DIR / "ids.stdout.log"

ids_proc: Optional[subprocess.Popen] = None

app = Flask(__name__)


# -------------------------
# Helpers (process)
# -------------------------

def _read_pid() -> Optional[int]:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _write_pid(pid: int) -> None:
    PID_FILE.write_text(str(pid), encoding="utf-8")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _venv_python() -> str:
    venv_python = APP_DIR / "venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    # If you used .venv instead of venv, uncomment:
    # venv_python2 = APP_DIR / ".venv" / "bin" / "python"
    # if venv_python2.exists():
    #     return str(venv_python2)
    return sys.executable


def is_ids_running() -> bool:
    global ids_proc
    if ids_proc is not None and ids_proc.poll() is None:
        return True
    pid = _read_pid()
    return bool(pid and _pid_alive(pid))


def _kill_process_tree_unix(pgid: int) -> None:
    """Kill a process group cleanly (SIGTERM then SIGKILL)."""
    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        try:
            os.kill(pgid, signal.SIGTERM)
        except Exception:
            pass

    for _ in range(20):
        if not _pid_alive(pgid):
            return
        time.sleep(0.1)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        try:
            os.kill(pgid, signal.SIGKILL)
        except Exception:
            pass


def start_ids() -> Dict[str, Any]:
    """
    Starts ids.py with sudo non-interactively:
      sudo -n <python> -u ids.py config.yaml
    Requires sudoers NOPASSWD entry.
    """
    global ids_proc

    if is_ids_running():
        pid = _read_pid() or (ids_proc.pid if ids_proc else None)
        return {"status": "already_running", "pid": pid}

    if not IDS_SCRIPT.exists():
        return {"status": "error", "error": f"Missing {IDS_SCRIPT}"}
    if not CONFIG_PATH.exists():
        return {"status": "error", "error": f"Missing {CONFIG_PATH}"}

    python_bin = _venv_python()

    IDS_LOG.touch(exist_ok=True)

    cmd = ["sudo", "-n", python_bin, "-u", str(IDS_SCRIPT), str(CONFIG_PATH)]

    try:
        log_f = open(IDS_LOG, "a", encoding="utf-8")
        ids_proc = subprocess.Popen(
            cmd,
            cwd=str(APP_DIR),
            stdout=log_f,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )
    except Exception as e:
        return {"status": "error", "error": str(e)}

    _write_pid(ids_proc.pid)  # pid == pgid because of setsid()
    return {"status": "started", "pid": ids_proc.pid, "cmd": " ".join(cmd)}


def stop_ids() -> Dict[str, Any]:
    global ids_proc

    pid = _read_pid()
    if ids_proc is not None and ids_proc.poll() is None:
        pid = ids_proc.pid

    if not pid:
        return {"status": "not_running"}

    if os.name == "nt":
        try:
            if ids_proc:
                ids_proc.terminate()
        except Exception:
            pass
    else:
        _kill_process_tree_unix(pid)

    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        try:
            if PID_FILE.exists():
                PID_FILE.unlink()
        except Exception:
            pass

    ids_proc = None
    return {"status": "stopped", "pid": pid}


def restart_ids() -> Dict[str, Any]:
    """Convenience: stop then start."""
    stop_ids()
    time.sleep(0.2)
    return start_ids()


# -------------------------
# Helpers (files / tail)
# -------------------------

def tail_jsonl(path: Path, limit: int = 200) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]
    except Exception:
        return []
    out = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            import json
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def tail_text(path: Path, limit_lines: int = 200) -> str:
    if not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit_lines:]
        return "\n".join(lines)
    except Exception:
        return ""


def _safe_rules_path(rel: str) -> Path:
    """
    Restrict rule editor to:
    - ./rules/*.(py|yaml|yml)
    - ./config.yaml
    Prevents path traversal.
    """
    rel = (rel or "").strip()

    if rel == "config.yaml":
        return CONFIG_PATH

    p = (RULES_DIR / rel).resolve()
    if not str(p).startswith(str(RULES_DIR.resolve()) + os.sep):
        raise ValueError("Invalid path")

    if p.is_dir():
        raise ValueError("Path is a directory")

    if p.suffix.lower() not in {".py", ".yaml", ".yml"}:
        raise ValueError("Only .py/.yaml/.yml files are allowed in rules editor")

    return p


def _list_rule_files() -> List[str]:
    RULES_DIR.mkdir(exist_ok=True)
    files = []
    for p in sorted(RULES_DIR.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".py", ".yaml", ".yml"}:
            files.append(str(p.relative_to(RULES_DIR)))
    # allow editing config.yaml too
    return ["config.yaml"] + files


def _validate_content(path: Path, content: str) -> Optional[str]:
    """
    Returns None if ok, else an error string.
    """
    suffix = path.suffix.lower()
    if path.name == "config.yaml":
        suffix = ".yaml"

    if suffix == ".py":
        try:
            compile(content, str(path), "exec")
            return None
        except Exception as e:
            return f"Python syntax error: {e}"

    if suffix in {".yaml", ".yml"}:
        try:
            import yaml
            yaml.safe_load(content)
            return None
        except Exception as e:
            return f"YAML parse error: {e}"

    return "Unsupported file type"


# -------------------------
# UI Templates
# -------------------------

BASE_STYLE = """
<style>
  body { font-family: sans-serif; margin: 0; }
  .container { padding: 18px; }
  .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  button { padding: 8px 12px; cursor: pointer; }
  .pill { padding: 3px 10px; border-radius: 999px; display: inline-block; }
  .ok { background: #e8ffe8; }
  .bad { background: #ffe8e8; }
  table { border-collapse: collapse; width: 100%; margin-top: 14px; }
  th, td { border: 1px solid #ddd; padding: 8px; font-size: 13px; vertical-align: top; }
  th { background: #f5f5f5; text-align: left; }
  .sev-high { font-weight: bold; }
  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; }
  textarea { width: 100%; height: 560px; }
  .muted { color:#555; }
  .nav {
    display:flex; align-items:center; justify-content:space-between;
    padding: 12px 18px; background:#111827; color:white;
  }
  .nav a { color:white; text-decoration:none; margin-right:14px; }
  .nav a:hover { text-decoration:underline; }
  .nav-left { display:flex; align-items:center; gap:14px; }
  .brand { font-weight:700; letter-spacing:0.2px; }
  .nav-right { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .small { font-size: 12px; opacity: 0.9; }
  .msg { padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; margin-top: 10px; }
  .msg.ok { background: #f0fff4; border-color: #b7ebc6; }
  .msg.err { background: #fff5f5; border-color: #f5b5b5; }
  select, input[type="text"] { padding: 6px 8px; }
</style>
"""

NAVBAR = """
<div class="nav">
  <div class="nav-left">
    <div class="brand">Healthcare IDS</div>
    <a href="/">Alerts</a>
    <a href="/logs">Logs</a>
    <a href="/rules">Rules</a>
  </div>
  <div class="nav-right">
    <div class="small">Status:</div>
    <span id="statusPill" class="pill {{ 'ok' if running else 'bad' }}">{{ 'RUNNING' if running else 'STOPPED' }}</span>
    <span id="pidText" class="mono small">{{ pid_text }}</span>
    <button onclick="startIDS()">Start IDS</button>
    <button onclick="stopIDS()">Stop IDS</button>
    <button onclick="reloadIDS()">Reload IDS</button>
  </div>
</div>
"""

ALERTS_PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Healthcare IDS - Alerts</title>
  {{ style|safe }}
</head>
<body>
  {{ navbar|safe }}
  <div class="container">
    <div class="row">
      <label>Refresh (sec):
        <input id="refreshSec" type="number" value="2" min="1" style="width:60px;">
      </label>
      <button onclick="clearAlerts()">Clear Alerts</button>
    </div>

    <p class="muted" style="margin-top: 8px;">
      Alerts read from <span class="mono">{{ alerts_path }}</span>
    </p>

    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Type</th>
          <th>Flow</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody id="alertsBody"></tbody>
    </table>
  </div>

<script>
function fmtTime(ts){
  if(!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

async function refreshStatus(){
  const r = await fetch("/api/status");
  const j = await r.json();
  const pill = document.getElementById("statusPill");
  const pidText = document.getElementById("pidText");
  pill.textContent = j.running ? "RUNNING" : "STOPPED";
  pill.className = "pill " + (j.running ? "ok" : "bad");
  pidText.textContent = j.pid ? ("pid=" + j.pid) : "";
}

async function refreshAlerts(){
  const r = await fetch("/api/alerts?limit=200");
  const j = await r.json();
  const body = document.getElementById("alertsBody");
  body.innerHTML = "";

  for (const a of j.alerts){
    const tr = document.createElement("tr");

    const tdT = document.createElement("td");
    tdT.textContent = fmtTime(a.ts);
    tr.appendChild(tdT);

    const tdS = document.createElement("td");
    tdS.textContent = a.severity || "";
    if ((a.severity || "").toLowerCase() === "high") tdS.className = "sev-high";
    tr.appendChild(tdS);

    const tdTy = document.createElement("td");
    tdTy.textContent = a.alert_type || "";
    tr.appendChild(tdTy);

    const tdF = document.createElement("td");
    tdF.className = "mono";
    tdF.textContent =
      (a.src_ip || "") + ":" + (a.src_port ?? "") +
      " → " +
      (a.dst_ip || "") + ":" + (a.dst_port ?? "") +
      " (" + (a.proto || "") + ")";
    tr.appendChild(tdF);

    const tdD = document.createElement("td");
    tdD.className = "mono";
    tdD.textContent = JSON.stringify(a.details || {}, null, 2);
    tr.appendChild(tdD);

    body.appendChild(tr);
  }
}

async function startIDS(){
  const r = await fetch("/api/start", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Start failed: " + (j.error || "unknown") + "\\n\\nTip: ensure sudoers NOPASSWD rule exists.");
  }
  await refreshStatus();
}

async function stopIDS(){
  const r = await fetch("/api/stop", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Stop failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function reloadIDS(){
  const r = await fetch("/api/restart", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Reload failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function clearAlerts(){
  const r = await fetch("/api/clear_alerts", {method:"POST"});
  const j = await r.json();
  if (j.status !== "cleared") alert("Failed to clear alerts: " + (j.error || "unknown"));
  await refreshAlerts();
}

async function loop(){
  await refreshStatus();
  await refreshAlerts();
  const sec = Math.max(1, parseInt(document.getElementById("refreshSec").value || "2"));
  setTimeout(loop, sec * 1000);
}
loop();
</script>
</body>
</html>
"""

LOGS_PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Healthcare IDS - Logs</title>
  {{ style|safe }}
</head>
<body>
  {{ navbar|safe }}
  <div class="container">
    <div class="row">
      <label>Refresh (sec):
        <input id="refreshSec" type="number" value="2" min="1" style="width:60px;">
      </label>
      <button onclick="clearLogs()">Clear Errors</button>
    </div>

    <p class="muted" style="margin-top: 8px;">
      IDS logs read from <span class="mono">{{ ids_log_path }}</span>
    </p>

    <textarea id="logBox" class="mono" readonly></textarea>
  </div>

<script>
async function refreshStatus(){
  const r = await fetch("/api/status");
  const j = await r.json();
  const pill = document.getElementById("statusPill");
  const pidText = document.getElementById("pidText");
  pill.textContent = j.running ? "RUNNING" : "STOPPED";
  pill.className = "pill " + (j.running ? "ok" : "bad");
  pidText.textContent = j.pid ? ("pid=" + j.pid) : "";
}

async function refreshLogs(){
  const r = await fetch("/api/logs?lines=800");
  const j = await r.json();
  const box = document.getElementById("logBox");
  box.value = j.text || "";
  box.scrollTop = box.scrollHeight;
}

async function startIDS(){
  const r = await fetch("/api/start", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Start failed: " + (j.error || "unknown") + "\\n\\nTip: ensure sudoers NOPASSWD rule exists.");
  }
  await refreshStatus();
}

async function stopIDS(){
  const r = await fetch("/api/stop", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Stop failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function reloadIDS(){
  const r = await fetch("/api/restart", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Reload failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function clearLogs(){
  const r = await fetch("/api/clear_logs", {method:"POST"});
  const j = await r.json();
  if (j.status !== "cleared") alert("Failed to clear logs: " + (j.error || "unknown"));
  await refreshLogs();
}

async function loop(){
  await refreshStatus();
  await refreshLogs();
  const sec = Math.max(1, parseInt(document.getElementById("refreshSec").value || "2"));
  setTimeout(loop, sec * 1000);
}
loop();
</script>
</body>
</html>
"""

RULES_PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Healthcare IDS - Rules Editor</title>
  {{ style|safe }}
</head>
<body>
  {{ navbar|safe }}
  <div class="container">
    <div class="row">
      <label>File:
        <select id="fileSelect"></select>
      </label>
      <button onclick="loadFile()">Open</button>
      <button onclick="saveFile()">Save</button>
      <button onclick="deleteFile()">Delete</button>
      <button onclick="newFile()">New File</button>
    </div>

    <div id="msgBox" class="msg" style="display:none;"></div>

    <p class="muted" style="margin-top: 8px;">
      You can edit <span class="mono">rules/*.py</span>, <span class="mono">rules/*.yaml</span>, or <span class="mono">config.yaml</span>.
      After saving rule code, click <b>Reload IDS</b> in the navbar.
    </p>

    <textarea id="editor" class="mono" placeholder="Select a file and click Open..."></textarea>
  </div>

<script>
function showMsg(kind, text){
  const box = document.getElementById("msgBox");
  box.style.display = "block";
  box.className = "msg " + (kind === "ok" ? "ok" : "err");
  box.textContent = text;
}

async function refreshStatus(){
  const r = await fetch("/api/status");
  const j = await r.json();
  const pill = document.getElementById("statusPill");
  const pidText = document.getElementById("pidText");
  pill.textContent = j.running ? "RUNNING" : "STOPPED";
  pill.className = "pill " + (j.running ? "ok" : "bad");
  pidText.textContent = j.pid ? ("pid=" + j.pid) : "";
}

async function startIDS(){
  const r = await fetch("/api/start", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Start failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function stopIDS(){
  const r = await fetch("/api/stop", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Stop failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function reloadIDS(){
  const r = await fetch("/api/restart", {method:"POST"});
  const j = await r.json();
  if (j.status === "error"){
    alert("Reload failed: " + (j.error || "unknown"));
  }
  await refreshStatus();
}

async function listFiles(){
  const r = await fetch("/api/rules/list");
  const j = await r.json();
  const sel = document.getElementById("fileSelect");
  sel.innerHTML = "";
  for (const f of j.files){
    const opt = document.createElement("option");
    opt.value = f;
    opt.textContent = f;
    sel.appendChild(opt);
  }
}

async function loadFile(){
  const f = document.getElementById("fileSelect").value;
  const r = await fetch("/api/rules/get?file=" + encodeURIComponent(f));
  const j = await r.json();
  if (j.status !== "ok"){
    showMsg("err", "Open failed: " + (j.error || "unknown"));
    return;
  }
  document.getElementById("editor").value = j.content || "";
  showMsg("ok", "Opened: " + f);
}

async function saveFile(){
  const f = document.getElementById("fileSelect").value;
  const content = document.getElementById("editor").value;
  const r = await fetch("/api/rules/save", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({file: f, content})
  });
  const j = await r.json();
  if (j.status !== "ok"){
    showMsg("err", "Save failed: " + (j.error || "unknown"));
    return;
  }
  showMsg("ok", "Saved: " + f + " (validated)");
}

async function deleteFile(){
  const f = document.getElementById("fileSelect").value;
  if (f === "config.yaml"){
    showMsg("err", "Refusing to delete config.yaml");
    return;
  }
  if (!confirm("Delete file: " + f + " ?")) return;

  const r = await fetch("/api/rules/delete", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({file: f})
  });
  const j = await r.json();
  if (j.status !== "ok"){
    showMsg("err", "Delete failed: " + (j.error || "unknown"));
    return;
  }
  showMsg("ok", "Deleted: " + f);
  await listFiles();
  document.getElementById("editor").value = "";
}

async function newFile(){
  const name = prompt("New file name inside rules/ (example: custom_rules.yaml or my_rules.py):");
  if (!name) return;

  const r = await fetch("/api/rules/new", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({file: name})
  });
  const j = await r.json();
  if (j.status !== "ok"){
    showMsg("err", "Create failed: " + (j.error || "unknown"));
    return;
  }
  showMsg("ok", "Created: rules/" + name);
  await listFiles();
  // auto-select new file
  document.getElementById("fileSelect").value = name;
  await loadFile();
}

async function init(){
  await refreshStatus();
  await listFiles();
}
init();
</script>
</body>
</html>
"""


# -------------------------
# Routes (Pages)
# -------------------------

@app.get("/")
def page_alerts():
    running = is_ids_running()
    pid = _read_pid()
    pid_text = f"pid={pid}" if (pid and _pid_alive(pid)) else ""
    return render_template_string(
        ALERTS_PAGE,
        style=BASE_STYLE,
        navbar=render_template_string(NAVBAR, running=running, pid_text=pid_text),
        running=running,
        pid_text=pid_text,
        alerts_path=str(ALERTS_JSONL),
    )


@app.get("/logs")
def page_logs():
    running = is_ids_running()
    pid = _read_pid()
    pid_text = f"pid={pid}" if (pid and _pid_alive(pid)) else ""
    return render_template_string(
        LOGS_PAGE,
        style=BASE_STYLE,
        navbar=render_template_string(NAVBAR, running=running, pid_text=pid_text),
        running=running,
        pid_text=pid_text,
        ids_log_path=str(IDS_LOG),
    )


@app.get("/rules")
def page_rules():
    running = is_ids_running()
    pid = _read_pid()
    pid_text = f"pid={pid}" if (pid and _pid_alive(pid)) else ""
    return render_template_string(
        RULES_PAGE,
        style=BASE_STYLE,
        navbar=render_template_string(NAVBAR, running=running, pid_text=pid_text),
        running=running,
        pid_text=pid_text,
    )


# -------------------------
# Routes (APIs)
# -------------------------

@app.get("/api/status")
def api_status():
    pid = _read_pid()
    alive = bool(pid and _pid_alive(pid))
    return jsonify({"running": alive, "pid": pid if alive else None})


@app.post("/api/start")
def api_start():
    return jsonify(start_ids())


@app.post("/api/stop")
def api_stop():
    return jsonify(stop_ids())


@app.post("/api/restart")
def api_restart():
    return jsonify(restart_ids())


@app.get("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", "200"))
    limit = max(1, min(limit, 2000))
    return jsonify({"alerts": tail_jsonl(ALERTS_JSONL, limit=limit)})


@app.get("/api/logs")
def api_logs():
    lines = int(request.args.get("lines", "800"))
    lines = max(20, min(lines, 5000))
    return jsonify({"text": tail_text(IDS_LOG, limit_lines=lines)})


@app.post("/api/clear_logs")
def api_clear_logs():
    try:
        IDS_LOG.write_text("", encoding="utf-8")
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.post("/api/clear_alerts")
def api_clear_alerts():
    try:
        ALERTS_JSONL.write_text("", encoding="utf-8")
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# -------- Rules Editor API --------

@app.get("/api/rules/list")
def api_rules_list():
    try:
        return jsonify({"files": _list_rule_files()})
    except Exception as e:
        return jsonify({"files": [], "error": str(e)}), 500


@app.get("/api/rules/get")
def api_rules_get():
    file = request.args.get("file", "")
    try:
        path = _safe_rules_path(file)
        if not path.exists():
            return jsonify({"status": "error", "error": "File does not exist"}), 404
        content = path.read_text(encoding="utf-8", errors="ignore")
        return jsonify({"status": "ok", "file": file, "content": content})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.post("/api/rules/save")
def api_rules_save():
    data = request.get_json(force=True, silent=True) or {}
    file = (data.get("file") or "").strip()
    content = data.get("content") or ""

    try:
        path = _safe_rules_path(file)
        if not path.exists():
            return jsonify({"status": "error", "error": "File does not exist"}), 404

        err = _validate_content(path, content)
        if err:
            return jsonify({"status": "error", "error": err}), 400

        # Backup first
        bak = path.with_suffix(path.suffix + ".bak")
        try:
            if path.exists():
                bak.write_text(path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        except Exception:
            pass

        path.write_text(content, encoding="utf-8")
        return jsonify({"status": "ok", "file": file})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.post("/api/rules/delete")
def api_rules_delete():
    data = request.get_json(force=True, silent=True) or {}
    file = (data.get("file") or "").strip()
    if file == "config.yaml":
        return jsonify({"status": "error", "error": "Refusing to delete config.yaml"}), 400

    try:
        path = _safe_rules_path(file)
        if not path.exists():
            return jsonify({"status": "error", "error": "File does not exist"}), 404

        path.unlink()
        return jsonify({"status": "ok", "file": file})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.post("/api/rules/new")
def api_rules_new():
    data = request.get_json(force=True, silent=True) or {}
    file = (data.get("file") or "").strip()

    try:
        # Only allow creating inside rules/
        p = (RULES_DIR / file).resolve()
        if not str(p).startswith(str(RULES_DIR.resolve()) + os.sep):
            return jsonify({"status": "error", "error": "Invalid path"}), 400
        if p.suffix.lower() not in {".py", ".yaml", ".yml"}:
            return jsonify({"status": "error", "error": "Only .py/.yaml/.yml allowed"}), 400
        if p.exists():
            return jsonify({"status": "error", "error": "File already exists"}), 400

        RULES_DIR.mkdir(exist_ok=True)

        # Starter templates
        if p.suffix.lower() == ".py":
            stub = (
                "# Custom rules file\n"
                "# Define rule functions like: def rule_x(row, ctx): ...\n"
                "# Return a dict like {'alert_type':..., 'severity':..., 'msg':...} or None\n\n"
                "def rule_example(row, ctx):\n"
                "    return None\n"
            )
        else:
            stub = (
                "# Custom YAML rules (template)\n"
                "# - name: EXAMPLE_RULE\n"
                "#   severity: low\n"
                "#   match:\n"
                "#     proto: TCP\n"
                "#     dst_port: 1883\n"
                "#   msg: \"Example YAML rule\"\n"
            )

        p.write_text(stub, encoding="utf-8")
        return jsonify({"status": "ok", "file": file})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


if __name__ == "__main__":
    # Access from your Mac: http://192.168.7.16:5000
    app.run(host="0.0.0.0", port=5000, debug=True)

