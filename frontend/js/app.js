/**
 * Core Application Controller for PhishGuard-AI.
 * Manages 4-view SPA tab routing, active nav tracking, health polling, clipboard pasting, and toasts.
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
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Map tabId to hash & vice versa
const TAB_TO_HASH = {
  "tab-home": "home",
  "tab-url": "url",
  "tab-message": "message",
  "tab-history": "history"
};

const HASH_TO_TAB = {
  "home": "tab-home",
  "url": "tab-url",
  "message": "tab-message",
  "history": "tab-history"
};

// Tab Switching Function (Supports all 4 pages)
function switchTab(tabId) {
  // Validate tabId
  if (!document.getElementById(tabId)) {
    tabId = "tab-home";
  }

  // Update navigation buttons active state
  const navBtns = document.querySelectorAll(".nav-btn");
  navBtns.forEach((btn) => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Update tab panes visibility
  const panes = document.querySelectorAll(".tab-pane");
  panes.forEach((pane) => {
    if (pane.id === tabId) {
      pane.classList.add("active");
    } else {
      pane.classList.remove("active");
    }
  });

  // Update URL hash without scrolling
  const hash = TAB_TO_HASH[tabId] || "home";
  if (window.location.hash.replace("#", "") !== hash) {
    history.pushState(null, "", `#${hash}`);
  }

  // If history tab, trigger fresh load
  if (tabId === "tab-history" && typeof loadHistory === "function") {
    loadHistory();
  }

  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.addEventListener("DOMContentLoaded", () => {
  // Setup Navigation Clicks for the 4 options
  const navBtns = document.querySelectorAll(".nav-btn");
  navBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      switchTab(targetTab);
    });
  });

  // Handle Initial Hash on Page Load (e.g. /#url, /#history)
  const initialHash = window.location.hash.replace("#", "").toLowerCase();
  if (initialHash && HASH_TO_TAB[initialHash]) {
    switchTab(HASH_TO_TAB[initialHash]);
  } else {
    // Check pathname fallback (e.g. /url, /history)
    const path = window.location.pathname.replace(/^\//, "").toLowerCase();
    if (HASH_TO_TAB[path]) {
      switchTab(HASH_TO_TAB[path]);
    }
  }

  // Handle Browser Back/Forward navigation
  window.addEventListener("popstate", () => {
    const hash = window.location.hash.replace("#", "").toLowerCase();
    if (hash && HASH_TO_TAB[hash]) {
      switchTab(HASH_TO_TAB[hash]);
    } else {
      switchTab("tab-home");
    }
  });

  // Clipboard Paste Helper for URL Scanner
  const pasteUrlBtn = document.getElementById("paste-url-btn");
  const clearUrlBtn = document.getElementById("clear-url-btn");
  const urlInput = document.getElementById("url-input");

  if (pasteUrlBtn && urlInput) {
    pasteUrlBtn.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          urlInput.value = text.trim();
          urlInput.focus();
          showToast("URL pasted from clipboard.", "info");
        } else {
          showToast("Clipboard is empty.", "info");
        }
      } catch (err) {
        urlInput.focus();
        showToast("Use Ctrl+V / Cmd+V to paste.", "info");
      }
    });
  }

  if (clearUrlBtn && urlInput) {
    clearUrlBtn.addEventListener("click", () => {
      urlInput.value = "";
      const resultContainer = document.getElementById("url-result-container");
      if (resultContainer) resultContainer.classList.add("hidden");
      urlInput.focus();
    });
  }

  // Clipboard Paste & Clear Helpers for Message Scanner
  const pasteMsgBtn = document.getElementById("paste-message-btn");
  const clearMsgBtn = document.getElementById("clear-message-btn");
  const msgInput = document.getElementById("message-input");
  const charCounter = document.getElementById("char-counter");

  if (pasteMsgBtn && msgInput) {
    pasteMsgBtn.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          msgInput.value = text.trim();
          if (charCounter) {
            charCounter.textContent = `${msgInput.value.length} / 5000 chars`;
          }
          msgInput.focus();
          showToast("Message pasted from clipboard.", "info");
        } else {
          showToast("Clipboard is empty.", "info");
        }
      } catch (err) {
        msgInput.focus();
        showToast("Use Ctrl+V / Cmd+V to paste.", "info");
      }
    });
  }

  if (clearMsgBtn && msgInput) {
    clearMsgBtn.addEventListener("click", () => {
      msgInput.value = "";
      if (charCounter) charCounter.textContent = "0 / 5000 chars";
      const resultContainer = document.getElementById("message-result-container");
      if (resultContainer) resultContainer.classList.add("hidden");
      msgInput.focus();
    });
  }

  if (msgInput && charCounter) {
    msgInput.addEventListener("input", () => {
      const len = msgInput.value.length;
      charCounter.textContent = `${len} / 5000 chars`;
      if (len > 4500) {
        charCounter.style.color = "var(--risk-med)";
      } else {
        charCounter.style.color = "var(--text-dim)";
      }
    });
  }

  // Check Backend Health on load and every 30s
  checkSystemHealth();
  setInterval(checkSystemHealth, 30000);
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
      statusPill.title = `Uptime: ${data.uptime_seconds}s | Zero-contact static inference active`;
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
