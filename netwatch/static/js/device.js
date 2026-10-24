/* Device detail: latency + packet-loss chart and availability strip from stored results */
(function () {
  "use strict";
  const cfg = document.getElementById("dev-config");
  if (!cfg || !window.Chart) return;
  const simulated = cfg.dataset.simulated === "true";
  const box = document.getElementById("dev-chart-box");
  const loading = document.getElementById("chart-loading");
  const bar = document.getElementById("avail-bar");
  const note = document.getElementById("chart-note");
  const legend = document.getElementById("avail-legend");
  let chart = null;

  function build(points) {
    const lat = points.map((p) => ({ x: p.t, y: p.latency }));
    const loss = points.map((p) => ({ x: p.t, y: p.loss }));
    const down = points.filter((p) => !p.up).map((p) => ({ x: p.t, y: 0 }));
    const sets = [
      { type: "line", label: "Latency (ms)" + (simulated ? " — simulated" : ""), data: lat, yAxisID: "y",
        borderColor: "#1d6fe0", backgroundColor: "rgba(29,111,224,.10)", fill: true, borderWidth: 1.8,
        pointRadius: points.length < 80 ? 2 : 0, tension: 0.25, spanGaps: false },
      { type: "bar", label: "Packet loss (%)", data: loss, yAxisID: "y2", backgroundColor: "rgba(217,119,6,.55)",
        borderWidth: 0, barPercentage: 1, categoryPercentage: 1, maxBarThickness: 8 },
      { type: "scatter", label: "Unreachable", data: down, yAxisID: "y", pointStyle: "triangle", pointRadius: 5,
        backgroundColor: "#c81e1e", borderColor: "#c81e1e" },
    ];
    if (chart) { chart.data.datasets = sets; chart.update("none"); return; }
    chart = new Chart(document.getElementById("dev-chart"), {
      data: { datasets: sets },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "nearest", intersect: false },
        scales: {
          x: { type: "time", time: { tooltipFormat: "dd MMM HH:mm:ss", displayFormats: { minute: "HH:mm", hour: "dd MMM HH:mm", day: "dd MMM" } }, grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
          y: { beginAtZero: true, position: "left", title: { display: true, text: "Latency (ms)" }, grid: { color: "#edf1f6" } },
          y2: { beginAtZero: true, max: 100, position: "right", title: { display: true, text: "Packet loss (%)" }, grid: { display: false } },
        },
        plugins: { legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 10 } } },
      },
    });
  }

  function availability(points) {
    // Group into at most 48 cells across the period
    bar.innerHTML = "";
    if (!points.length) { legend.textContent = ""; return; }
    const n = Math.min(48, points.length), size = Math.ceil(points.length / n);
    let okTotal = 0, total = 0;
    for (let i = 0; i < points.length; i += size) {
      const g = points.slice(i, i + size);
      const w = g.reduce((a, p) => a + (p.n || 1), 0);
      const ok = g.reduce((a, p) => a + (p.uptime != null ? p.uptime / 100 * (p.n || 1) : (p.up ? 1 : 0)), 0);
      okTotal += ok; total += w;
      const ratio = ok / w;
      const cell = document.createElement("span");
      cell.className = ratio >= 0.999 ? "ok" : ratio > 0 ? "part" : "bad";
      cell.title = new Date(g[0].t).toLocaleString() + " — " + (ratio * 100).toFixed(1) + "% available";
      bar.appendChild(cell);
    }
    legend.textContent = (okTotal / total * 100).toFixed(2) + "% of checks succeeded";
  }

  async function load(range) {
    loading.classList.add("on");
    try {
      const r = await fetch(cfg.dataset.series + "?range=" + encodeURIComponent(range), { headers: { Accept: "application/json" } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      box.classList.toggle("is-empty", j.points.length === 0);
      build(j.points);
      availability(j.points);
      note.textContent = j.count + " stored result" + (j.count === 1 ? "" : "s") + " in this period" +
        (j.bucket_seconds ? " · averaged into " + (j.bucket_seconds / 60) + "-minute intervals" : " · every individual check shown") +
        (simulated ? " · SIMULATED data" : "");
    } catch (e) {
      box.classList.add("is-empty");
      box.querySelector(".chart-empty").textContent = "Could not load chart data. Please refresh the page.";
    } finally {
      loading.classList.remove("on");
    }
  }

  document.querySelectorAll("#range-seg button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#range-seg button").forEach((x) => { x.classList.remove("active"); x.setAttribute("aria-pressed", "false"); });
    b.classList.add("active"); b.setAttribute("aria-pressed", "true");
    load(b.dataset.range);
  }));
  load("24h");
})();
