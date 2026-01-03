(function () {
  const page = window.__PAGE__ || "";

  function qs(id) { return document.getElementById(id); }

  async function apiPost(url, bodyObj) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyObj || {})
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = (data && data.msg) ? data.msg : "Request failed";
      throw new Error(msg);
    }
    return data;
  }

  async function apiGet(url) {
    const res = await fetch(url);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = (data && data.msg) ? data.msg : "Request failed";
      throw new Error(msg);
    }
    return data;
  }

  // --- IDS Buttons (used across pages) ---
  async function wireGlobalButtons() {
    const btnStart = qs("btnStart");
    const btnStop = qs("btnStop");
    const btnReload = qs("btnReload");

    if (btnStart) btnStart.addEventListener("click", async () => {
      try {
        await apiPost("/api/start", {});
        // optional: reload page to show status badge updated
        window.location.reload();
      } catch (e) {
        alert(e.message || "Request failed");
      }
    });

    if (btnStop) btnStop.addEventListener("click", async () => {
      try {
        await apiPost("/api/stop", {});
        window.location.reload();
      } catch (e) {
        alert(e.message || "Request failed");
      }
    });

    if (btnReload) btnReload.addEventListener("click", async () => {
      try {
        await apiPost("/api/reload", {});
        window.location.reload();
      } catch (e) {
        alert(e.message || "Request failed");
      }
    });
  }

  // --- Alerts page: render + search ---
  function normalizeText(s) {
    return String(s || "").toLowerCase();
  }

  function rowText(alertObj) {
    // searchable fields
    const parts = [
      alertObj.time,
      alertObj.severity,
      alertObj.type,
      alertObj.flow,
      JSON.stringify(alertObj.details || {})
    ];
    return normalizeText(parts.join(" "));
  }

  function pillClass(sev) {
    sev = normalizeText(sev);
    if (sev === "high") return "pill pill-high";
    if (sev === "medium") return "pill pill-medium";
    return "pill pill-low";
  }

  function renderAlerts(alerts) {
    const tbody = qs("alertsTbody");
    if (!tbody) return;

    tbody.innerHTML = "";
    for (const a of alerts) {
      const tr = document.createElement("tr");
      tr.className = "alert-row";
      tr.dataset.search = rowText(a);

      const tdTime = document.createElement("td");
      tdTime.className = "mono";
      tdTime.textContent = a.time || "";
      tr.appendChild(tdTime);

      const tdSev = document.createElement("td");
      const sevSpan = document.createElement("span");
      sevSpan.className = pillClass(a.severity || "low");
      sevSpan.textContent = (a.severity || "low").toLowerCase();
      tdSev.appendChild(sevSpan);
      tr.appendChild(tdSev);

      const tdType = document.createElement("td");
      tdType.className = "mono";
      tdType.textContent = a.type || "";
      tr.appendChild(tdType);

      const tdFlow = document.createElement("td");
      tdFlow.className = "mono";
      tdFlow.textContent = a.flow || "";
      tr.appendChild(tdFlow);

      const tdDetails = document.createElement("td");
      const pre = document.createElement("pre");
      pre.className = "json";
      pre.textContent = JSON.stringify(a.details || {}, null, 2);
      tdDetails.appendChild(pre);
      tr.appendChild(tdDetails);

      tbody.appendChild(tr);
    }
  }

  function applyAlertSearchFilter() {
    const input = qs("alertSearch");
    const countEl = qs("searchCount");
    if (!input) return;

    const q = normalizeText(input.value).trim();
    const rows = Array.from(document.querySelectorAll("#alertsTbody .alert-row"));

    let shown = 0;
    for (const r of rows) {
      const hay = r.dataset.search || "";
      const ok = (q.length === 0) || hay.includes(q);
      r.style.display = ok ? "" : "none";
      if (ok) shown++;
    }

    if (countEl) {
      if (q.length === 0) {
        countEl.textContent = rows.length ? `${rows.length} total` : "";
      } else {
        countEl.textContent = `${shown} / ${rows.length} shown`;
      }
    }
  }

  async function refreshAlertsOnce() {
    try {
      const data = await apiGet("/api/alerts");
      const alerts = (data && data.alerts) ? data.alerts : [];
      renderAlerts(alerts);
      applyAlertSearchFilter(); // keep your filter active after refresh
    } catch (e) {
      // If fetch fails, don’t break UI; show simple popup
      alert(e.message || "Request failed");
    }
  }

  async function wireAlertsPage() {
    const refreshSec = qs("refreshSec");
    const btnRefreshNow = qs("btnRefreshNow");
    const btnClearAlerts = qs("btnClearAlerts");
    const alertSearch = qs("alertSearch");

    if (btnRefreshNow) btnRefreshNow.addEventListener("click", refreshAlertsOnce);

    if (btnClearAlerts) btnClearAlerts.addEventListener("click", async () => {
      try {
        await apiPost("/api/clear_alerts", {});
        await refreshAlertsOnce();
      } catch (e) {
        alert(e.message || "Request failed");
      }
    });

    if (alertSearch) {
      alertSearch.addEventListener("input", applyAlertSearchFilter);
      // initial count
      applyAlertSearchFilter();
    }

    // auto refresh interval
    let timer = null;
    function resetTimer() {
      if (timer) clearInterval(timer);
      const sec = Math.max(1, parseInt((refreshSec && refreshSec.value) || "2", 10));
      timer = setInterval(refreshAlertsOnce, sec * 1000);
    }

    if (refreshSec) refreshSec.addEventListener("change", resetTimer);

    // initial load + start timer
    await refreshAlertsOnce();
    resetTimer();
  }

  // --- Boot ---
  (async function init() {
    await wireGlobalButtons();
    if (page === "alerts") {
      await wireAlertsPage();
    }
  })();
})();
