import os
import json
import time
import signal
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from flask import Flask, jsonify, request, render_template_string

APP_DIR = Path(__file__).resolve().parent
IDS_SCRIPT = APP_DIR / "ids.py"
CONFIG_PATH = APP_DIR / "config.yaml"

# Must match config.yaml alerts.jsonl_path
ALERTS_JSONL = APP_DIR / "alerts.jsonl"

# In-memory handle for the IDS process
ids_proc: Optional[subprocess.Popen] = None

app = Flask(__name__)


def is_ids_running() -> bool:
    global ids_proc
    return ids_proc is not None and ids_proc.poll() is None


def start_ids() -> Dict[str, Any]:
    global ids_proc
    if is_ids_running():
        return {"status": "already_running", "pid": ids_proc.pid}

    if not IDS_SCRIPT.exists():
        return {"status": "error", "error": f"Missing {IDS_SCRIPT}"}
    if not CONFIG_PATH.exists():
        return {"status": "error", "error": f"Missing {CONFIG_PATH}"}

    # Start IDS in unbuffered mode so logs appear immediately if you watch stdout
    ids_proc = subprocess.Popen(
        ["python", "-u", str(IDS_SCRIPT)],
        cwd=str(APP_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    return {"status": "started", "pid": ids_proc.pid}


def stop_ids() -> Dict[str, Any]:
    global ids_proc
    if not is_ids_running():
        return {"status": "not_running"}

    try:
        if os.name == "nt":
            ids_proc.terminate()
        else:
            ids_proc.send_signal(signal.SIGTERM)

        # Give it a moment to exit gracefully
        for _ in range(20):
            if ids_proc.poll() is not None:
                break
            time.sleep(0.1)

        if ids_proc.poll() is None:
            ids_proc.kill()

        pid = ids_proc.pid
        ids_proc = None
        return {"status": "stopped", "pid": pid}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def tail_alerts(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Reads the last N alerts from a JSONL file. Safe for modest files.
    If your alerts file gets large, switch to a DB or rotate logs.
    """
    if not ALERTS_JSONL.exists():
        return []

    # Read last ~limit lines efficiently
    lines = ALERTS_JSONL.read_text(encoding="utf-8", errors="ignore").splitlines()
    lines = lines[-limit:]

    out = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Healthcare IDS Dashboard</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
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
  </style>
</head>
<body>
  <h2>Healthcare IDS Dashboard</h2>

  <div class="row">
    <div>Status:
      <span id="statusPill" class="pill {{ 'ok' if running else 'bad' }}">
        {{ 'RUNNING' if running else 'STOPPED' }}
      </span>
      <span id="pidText" class="mono">{{ pid_text }}</span>
    </div>

    <button onclick="startIDS()">Start IDS</button>
    <button onclick="stopIDS()">Stop IDS</button>

    <label>Refresh (sec):
      <input id="refreshSec" type="number" value="2" min="1" style="width:60px;">
    </label>
  </div>

  <p style="margin-top: 8px; color:#555;">
    Alerts shown are read from <span class="mono">{{ alerts_path }}</span>.
    If sniffing packets, run the IDS with appropriate capture privileges and/or on a SPAN/mirror port.
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
    <tbody id="alertsBody">
      <!-- filled by JS -->
    </tbody>
  </table>

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
  await r.json();
  await refreshStatus();
}

async function stopIDS(){
  const r = await fetch("/api/stop", {method:"POST"});
  await r.json();
  await refreshStatus();
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


@app.get("/")
def index():
    running = is_ids_running()
    pid_text = f"pid={ids_proc.pid}" if running and ids_proc else ""
    return render_template_string(
        PAGE,
        running=running,
        pid_text=pid_text,
        alerts_path=str(ALERTS_JSONL),
    )


@app.get("/api/status")
def api_status():
    return jsonify({
        "running": is_ids_running(),
        "pid": (ids_proc.pid if is_ids_running() and ids_proc else None),
    })


@app.post("/api/start")
def api_start():
    return jsonify(start_ids())


@app.post("/api/stop")
def api_stop():
    return jsonify(stop_ids())


@app.get("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", "200"))
    limit = max(1, min(limit, 2000))
    return jsonify({"alerts": tail_alerts(limit=limit)})


if __name__ == "__main__":
    # For LAN access: host="0.0.0.0" (be mindful of security)
    app.run(host="0.0.0.0", port=5000, debug=True)
