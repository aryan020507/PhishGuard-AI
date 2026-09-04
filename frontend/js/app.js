/**
 * Core Application Controller for PhishGuard-AI.
 * Manages SPA Tab Switching, System Health Polling, Toasts, and Utilities.
 */

// Utility: HTML Escaping for XSS Prevention
function escapeHtml(str) {
  if (typeof str !== "string") return str;
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Utility: Toast Notifications
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Tab Switching Function
function switchTab(tabId) {
  // Update nav buttons
  const navBtns = document.querySelectorAll(".nav-btn");
  navBtns.forEach((btn) => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Update tab panes
  const panes = document.querySelectorAll(".tab-pane");
  panes.forEach((pane) => {
    if (pane.id === tabId) {
      pane.classList.add("active");
    } else {
      pane.classList.remove("active");
    }
  });

  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.addEventListener("DOMContentLoaded", () => {
  // Setup Navigation Clicks
  const navBtns = document.querySelectorAll(".nav-btn");
  navBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      switchTab(targetTab);
    });
  });

  // Check Backend Health
  checkSystemHealth();
  setInterval(checkSystemHealth, 30000); // Check every 30s
});

async function checkSystemHealth() {
  const statusPill = document.getElementById("system-status-pill");
  if (!statusPill) return;

  const dot = statusPill.querySelector(".status-dot");
  const text = statusPill.querySelector(".status-text");

  try {
    const res = await fetch("/health");
    if (!res.ok) throw new Error("Unhealthy");
    const data = await res.json();

    const urlLoaded = data.models_loaded && data.models_loaded.url_ann;
    const msgLoaded = data.models_loaded && data.models_loaded.message_rnn;

    dot.classList.remove("pulsing", "offline");
    dot.classList.add("online");

    if (urlLoaded && msgLoaded) {
      text.textContent = "Pipelines Active (ANN+RNN)";
      statusPill.title = `Uptime: ${data.uptime_seconds}s | All models online`;
    } else {
      text.textContent = "Partial Pipeline Active";
      dot.style.background = "var(--risk-med)";
    }
  } catch (err) {
    dot.classList.remove("pulsing", "online");
    dot.classList.add("offline");
    text.textContent = "Backend Offline";
    statusPill.title = "Could not connect to FastAPI server.";
  }
}
