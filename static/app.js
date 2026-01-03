function toast(msg, ok=true){
  const t = document.getElementById("toast");
  if(!t) return;
  t.textContent = msg;
  t.classList.remove("hidden");
  t.style.borderColor = ok ? "rgba(34,197,94,0.45)" : "rgba(239,68,68,0.55)";
  setTimeout(()=>t.classList.add("hidden"), 2400);
}

async function postJSON(url, data){
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type":"application/json" },
    body: data ? JSON.stringify(data) : "{}"
  });
  const js = await res.json().catch(()=>({ok:false,msg:"Bad JSON"}));
  if(!res.ok) throw new Error(js.msg || "Request failed");
  return js;
}

async function getJSON(url){
  const res = await fetch(url);
  const js = await res.json().catch(()=>({ok:false}));
  if(!res.ok) throw new Error(js.msg || "Request failed");
  return js;
}

// --- Navbar buttons (work on all pages) ---
async function wireNavbar(){
  const s = document.getElementById("btnStart");
  const p = document.getElementById("btnStop");
  const r = document.getElementById("btnReload");

  if(s){
    s.addEventListener("click", async ()=>{
      try{
        const out = await postJSON("/api/start", {});
        toast(out.msg, true);
        location.reload();
      }catch(e){
        toast(String(e.message || e), false);
      }
    });
  }

  if(p){
    p.addEventListener("click", async ()=>{
      try{
        const out = await postJSON("/api/stop", {});
        toast(out.msg, true);
        location.reload();
      }catch(e){
        toast(String(e.message || e), false);
      }
    });
  }

  if(r){
    r.addEventListener("click", async ()=>{
      try{
        const out = await postJSON("/api/reload", {});
        toast(out.msg, true);
        location.reload();
      }catch(e){
        toast(String(e.message || e), false);
      }
    });
  }
}

// --- Alerts page ---
function parseFlow(flow){
  // Examples:
  // "192.168.7.65:0 -> 192.168.7.16:0 (ICMP)"
  // "192.168.7.65:64228 -> 192.168.7.16:22 (TCP)"
  const out = { src_ip:"-", src_port:"-", dst_ip:"-", dst_port:"-", protocol:"-" };
  if(!flow || typeof flow !== "string") return out;

  const protoMatch = flow.match(/\(([^)]+)\)\s*$/);
  if(protoMatch) out.protocol = protoMatch[1];

  const arrow = flow.split("->");
  if(arrow.length >= 2){
    const left = arrow[0].trim();
    const right = arrow[1].trim().replace(/\([^)]+\)\s*$/, "").trim();

    const [sip, sport] = left.split(":");
    const [dip, dport] = right.split(":");
    out.src_ip = (sip||"-").trim();
    out.src_port = (sport||"-").trim();
    out.dst_ip = (dip||"-").trim();
    out.dst_port = (dport||"-").trim();
  }
  return out;
}

function severityClass(sev){
  const s = (sev||"").toLowerCase();
  if(s.includes("high")) return "high";
  if(s.includes("med")) return "medium";
  return "low";
}

function alertMessage(a){
  // Prefer details.msg then a.msg then type fallback
  if(a?.details?.msg) return String(a.details.msg);
  if(a?.msg) return String(a.msg);
  return String(a?.type || "-");
}

function detailsCompact(a){
  try{
    return JSON.stringify(a.details || {}, null, 0);
  }catch{
    return "{}";
  }
}

function rowText(a, flowObj){
  const parts = [
    a.time, a.severity, a.type,
    flowObj.src_ip, flowObj.src_port, flowObj.dst_ip, flowObj.dst_port, flowObj.protocol,
    alertMessage(a),
    detailsCompact(a)
  ];
  return parts.join(" ").toLowerCase();
}

async function loadAlerts(){
  const body = document.getElementById("alertsBody");
  const search = document.getElementById("alertSearch");
  const count = document.getElementById("alertCount");
  if(!body) return;

  let alerts = [];
  try{
    const out = await getJSON("/api/alerts");
    alerts = out.alerts || [];
  }catch(e){
    toast(String(e.message || e), false);
  }

  // render
  body.innerHTML = "";
  const rows = [];

  for(const a of alerts){
    const flowObj = parseFlow(a.flow);
    const tr = document.createElement("tr");

    const sev = document.createElement("td");
    sev.innerHTML = `<span class="badge ${severityClass(a.severity)}">${a.severity || "-"}</span>`;

    tr.innerHTML = `
      <td class="mono">${a.time || "-"}</td>
      <td></td>
      <td class="mono">${a.type || "-"}</td>
      <td class="mono">${flowObj.src_ip}</td>
      <td class="mono">${flowObj.src_port}</td>
      <td class="mono">${flowObj.dst_ip}</td>
      <td class="mono">${flowObj.dst_port}</td>
      <td class="mono">${flowObj.protocol}</td>
      <td>${alertMessage(a)}</td>
      <td class="mono">${detailsCompact(a)}</td>
    `;
    tr.children[1].replaceWith(sev);

    const text = rowText(a, flowObj);
    rows.push({ tr, text });
    body.appendChild(tr);
  }

  function applyFilter(){
    const q = (search?.value || "").trim().toLowerCase();
    let shown = 0;
    for(const r of rows){
      const ok = !q || r.text.includes(q);
      r.tr.style.display = ok ? "" : "none";
      if(ok) shown++;
    }
    if(count) count.textContent = `${shown} / ${rows.length} shown`;
  }

  if(search){
    search.addEventListener("input", applyFilter);
  }
  applyFilter();
}

async function wireClearAlerts(){
  const b = document.getElementById("btnClearAlerts");
  if(!b) return;
  b.addEventListener("click", async ()=>{
    try{
      const out = await postJSON("/api/clear_alerts", {});
      toast(out.msg, true);
      await loadAlerts();
    }catch(e){
      toast(String(e.message || e), false);
    }
  });
}

// --- Logs page ---
async function loadLogs(){
  const box = document.getElementById("logBox");
  const whichSel = document.getElementById("logWhich");
  if(!box) return;

  async function refresh(){
    const which = whichSel ? whichSel.value : "ids";
    try{
      const out = await getJSON(`/api/logs?which=${encodeURIComponent(which)}`);
      box.textContent = out.log_tail || "";
    }catch(e){
      box.textContent = "";
      toast(String(e.message || e), false);
    }
  }

  if(whichSel){
    whichSel.addEventListener("change", refresh);
  }
  await refresh();

  // auto refresh
  setInterval(refresh, 2000);
}

async function wireClearLogs(){
  const b = document.getElementById("btnClearLogs");
  const whichSel = document.getElementById("logWhich");
  if(!b) return;
  b.addEventListener("click", async ()=>{
    const which = whichSel ? whichSel.value : "ids";
    try{
      const out = await postJSON(`/api/clear_logs?which=${encodeURIComponent(which)}`, {});
      toast(out.msg, true);
    }catch(e){
      toast(String(e.message || e), false);
    }
  });
}

// --- Rules page ---
async function wireSaveRules(){
  const btn = document.getElementById("btnSaveRules");
  const ta = document.getElementById("rulesText");
  if(!btn || !ta) return;

  btn.addEventListener("click", async ()=>{
    try{
      const out = await postJSON("/api/rules", { rules_text: ta.value });
      toast(out.msg, true);
    }catch(e){
      toast(String(e.message || e), false);
    }
  });
}

document.addEventListener("DOMContentLoaded", async ()=>{
  await wireNavbar();
  await wireClearAlerts();
  await wireClearLogs();
  await wireSaveRules();

  await loadAlerts();
  await loadLogs();
});

