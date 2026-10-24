/* Netwatch — shared UI behaviour (no inline scripts: CSP script-src 'self') */
(function () {
  "use strict";

  // Mobile sidebar
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  const toggle = document.getElementById("sidebar-toggle");
  function setSidebar(open) {
    if (!sidebar) return;
    sidebar.classList.toggle("show", open);
    backdrop && backdrop.classList.toggle("show", open);
    toggle && toggle.setAttribute("aria-expanded", String(open));
  }
  toggle && toggle.addEventListener("click", () => setSidebar(!sidebar.classList.contains("show")));
  backdrop && backdrop.addEventListener("click", () => setSidebar(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") setSidebar(false); });

  // Confirmation dialog for destructive POST forms: <form data-confirm="...">
  const modalEl = document.getElementById("confirmModal");
  let pendingForm = null;
  if (modalEl && window.bootstrap) {
    const modal = new bootstrap.Modal(modalEl);
    document.addEventListener("submit", (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement) || !form.dataset.confirm || form.dataset.confirmed === "1") return;
      e.preventDefault();
      pendingForm = form;
      document.getElementById("confirmTitle").textContent = form.dataset.confirmTitle || "Are you sure?";
      document.getElementById("confirmBody").textContent = form.dataset.confirm;
      modal.show();
    });
    document.getElementById("confirmGo").addEventListener("click", () => {
      if (!pendingForm) return;
      pendingForm.dataset.confirmed = "1";
      modal.hide();
      const f = pendingForm; pendingForm = null;
      f.requestSubmit ? f.requestSubmit() : f.submit();
    });
  }

  // Auto-submit filter forms when a select / date changes
  document.querySelectorAll("form[data-autosubmit] select, form[data-autosubmit] input[type=date]").forEach((el) => {
    el.addEventListener("change", () => {
      const page = el.form.querySelector("input[name=page]");
      if (page) page.value = 1;
      el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit();
    });
  });

  // Buttons that show a spinner while their form submits (e.g. "Check now")
  document.querySelectorAll("form[data-busy]").forEach((f) => {
    f.addEventListener("submit", () => {
      if (f.dataset.confirm && f.dataset.confirmed !== "1") return;
      const btn = f.querySelector("button[type=submit]");
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span> ' + f.dataset.busy; }
    });
  });

  // Auto-dismiss success/info toasts
  document.querySelectorAll(".toast-zone .alert-success, .toast-zone .alert-info").forEach((el) => {
    setTimeout(() => { try { bootstrap.Alert.getOrCreateInstance(el).close(); } catch (_) { el.remove(); } }, 6000);
  });

  // Collector / database health indicator in the sidebar
  const sched = document.getElementById("sched-state");
  async function health() {
    if (!sched) return;
    try {
      const r = await fetch(sched.dataset.url, { headers: { Accept: "application/json" } });
      const j = await r.json();
      const ok = j.database === "ok" && j.scheduler === "running";
      const colour = ok ? "#3fb36b" : (j.database === "ok" ? "#f0b443" : "#e05252");
      const text = j.database !== "ok" ? "Database unavailable" :
        (j.scheduler === "running" ? "Collector running" : "Collector stopped");
      sched.innerHTML = '<span class="dot" style="background:' + colour + '"></span>' + text;
    } catch (_) {
      sched.innerHTML = '<span class="dot" style="background:#e05252"></span>Server unreachable';
    }
  }
  health(); setInterval(health, 30000);

  // Shared helpers for page scripts
  window.NW = {
    esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); },
    fmt(v, d, suffix) { return v == null ? "—" : Number(v).toFixed(d) + (suffix || ""); },
    palette: ["#1d6fe0", "#18a0c9", "#7c3aed", "#d97706", "#15803d", "#db2777", "#0f766e", "#64748b"],
  };
})();
