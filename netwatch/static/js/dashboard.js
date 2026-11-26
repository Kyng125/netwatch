/* Dashboard: periodic refresh from /api/dashboard (stored results only) */
(function () {
  "use strict";
  const cfg = document.getElementById("dash-config");
  if (!cfg) return;
  const { esc, fmt, palette } = window.NW;
  const devUrl = (id) => cfg.dataset.deviceUrl.replace(/0$/, id);
  const alertUrl = (id) => cfg.dataset.alertUrl.replace(/0$/, id);
  const loading = document.getElementById("dash-loading");
  const updated = document.getElementById("dash-updated");
  const labels = { up: "Up", down: "Down", unknown: "Pending", disabled: "Disabled" };
  let chart = null, lastOk = Date.now();

  function pill(s) { return '<span class="status-pill status-' + s + '">' + (labels[s] || s) + "</span>"; }
  function site(name) { return name ? '<span class="site-badge" title="Checked by the on-site agent for ' + esc(name) + '"><i class="bi bi-building" aria-hidden="true"></i>' + esc(name) + "</span>" : ""; }
  function sim(isSim) { return isSim ? '<span class="sim-badge" title="Simulated demonstration device"><i class="bi bi-cpu" aria-hidden="true"></i>Simulated</span>' : ""; }

  function renderStats(o) {
    const set = (k, v) => document.querySelectorAll('[data-k="' + k + '"]').forEach((el) => { el.textContent = v; });
    document.querySelector('[data-k="enabled"]').innerHTML = (o.total - o.disabled) + "<small>/ " + o.total + "</small>";
    set("disabled", o.disabled); set("up", o.up); set("down", o.down); set("unknown", o.unknown);
    document.querySelector('[data-k="down"]').classList.toggle("text-down", o.down > 0);
    set("uptime_24h", fmt(o.uptime_24h, 2, "%")); set("avg_latency_1h", fmt(o.avg_latency_1h, 1, " ms"));
    set("alerts_active", o.alerts_open + o.alerts_ack); set("alerts_critical", o.alerts_critical);
    set("alerts_warning", o.alerts_warning); set("alerts_ack", o.alerts_ack);
  }

  function renderDevices(list) {
    const grid = document.getElementById("dev-grid");
    if (!grid) return;
    grid.innerHTML = list.map((d) =>
      '<a class="dev-tile is-' + d.status + '" href="' + devUrl(d.id) + '">' +
      '<div class="d-flex justify-content-between align-items-start gap-2"><div><div class="name">' + esc(d.name) +
      '</div><div class="meta mono">' + esc(d.ip) + "</div></div>" + pill(d.status) + "</div>" +
      '<div class="meta mt-1">' + esc(d.type) + " " + sim(d.simulated) + " " + site(d.site) + "</div>" +
      '<div class="metrics"><div>Latency<b>' + fmt(d.latency, 1) + "</b></div><div>Loss<b>" + fmt(d.loss, 0, "%") +
      "</b></div><div>Uptime<b>" + fmt(d.uptime, 1, "%") + "</b></div></div>" +
      '<div class="meta mt-2">' + (d.checked ? "Checked " + esc(d.checked_ago) : "Not checked yet") +
      (d.error ? ' · <span class="text-down">' + esc(d.error) + "</span>" : "") + "</div></a>").join("");
  }

  function renderAlerts(list) {
    const feed = document.getElementById("alert-feed");
    if (!list.length) {
      feed.innerHTML = '<li class="justify-content-center text-muted py-4"><i class="bi bi-check-circle text-up" aria-hidden="true"></i> No active alerts — all monitored devices are within their thresholds.</li>';
      return;
    }
    feed.innerHTML = list.map((a) => {
      const crit = a.severity === "critical";
      return '<li><span class="ico" style="background:' + (crit ? "#fdeaea" : "#fef3e2") + ";color:" + (crit ? "#c81e1e" : "#b45309") +
        '"><i class="bi bi-' + (crit ? "exclamation-octagon" : "exclamation-triangle") + '" aria-hidden="true"></i></span>' +
        '<div class="flex-grow-1"><a href="' + alertUrl(a.id) + '" class="fw-semibold text-decoration-none">' + esc(a.device) + "</a> " + sim(a.simulated) +
        '<div class="text-muted small">' + esc(a.message) + '</div><div class="when">' + esc(a.opened_ago) +
        ' · <span class="astatus astatus-' + a.status + '">' + (a.status === "open" ? "Open" : "Acknowledged") + "</span></div></div></li>";
    }).join("");
  }

  function renderChart(series) {
    const box = document.getElementById("fleet-chart-box");
    const datasets = series.filter((s) => s.points.length).map((s, i) => ({
      label: s.name + (s.simulated ? " (simulated)" : ""),
      data: s.points.map((p) => ({ x: p.t, y: p.latency })),
      borderColor: palette[i % palette.length], backgroundColor: palette[i % palette.length],
      borderWidth: 1.8, pointRadius: 0, tension: 0.25, spanGaps: false,
      borderDash: s.simulated ? [5, 3] : [],
    }));
    box.classList.toggle("is-empty", datasets.length === 0);
    if (!window.Chart) return;
    if (!chart) {
      chart = new Chart(document.getElementById("fleet-chart"), {
        type: "line", data: { datasets },
        options: {
          responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "nearest", intersect: false },
          scales: {
            x: { type: "time", time: { tooltipFormat: "dd MMM HH:mm", displayFormats: { minute: "HH:mm", hour: "HH:mm" } }, grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
            y: { beginAtZero: true, title: { display: true, text: "Latency (ms)" }, grid: { color: "#edf1f6" } },
          },
          plugins: { legend: { position: "bottom", labels: { boxWidth: 12, usePointStyle: true } },
            tooltip: { callbacks: { label: (c) => c.dataset.label + ": " + (c.parsed.y == null ? "no reply" : c.parsed.y.toFixed(1) + " ms") } } },
        },
      });
    } else {
      chart.data.datasets = datasets;
      chart.update("none");
    }
  }

  async function refresh() {
    loading.classList.add("on");
    try {
      const r = await fetch(cfg.dataset.api, { headers: { Accept: "application/json" }, credentials: "same-origin" });
      if (r.status === 401 || r.redirected) { window.location.reload(); return; }
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      renderStats(j.overview); renderDevices(j.devices); renderAlerts(j.alerts); renderChart(j.chart);
      lastOk = Date.now();
      updated.textContent = "Updated " + new Date().toLocaleTimeString();
      updated.classList.remove("text-danger");
    } catch (e) {
      updated.textContent = "Could not refresh — last update " + Math.round((Date.now() - lastOk) / 1000) + "s ago";
      updated.classList.add("text-danger");
    } finally {
      loading.classList.remove("on");
    }
  }

  document.getElementById("dash-refresh").addEventListener("click", refresh);
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 15000);
})();
