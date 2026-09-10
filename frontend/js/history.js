/**
 * Scan Audit History Controller for PhishGuard-AI.
 * Fetches recent scans from SQLite via /api/v1/history, computes live summary stats,
 * and enables 1-click re-scanning of historical inputs.
 */

async function loadHistory() {
  const tbody = document.getElementById("history-tbody");
  if (!tbody) return;

  const statTotal = document.getElementById("stat-total-scans");
  const statSafe = document.getElementById("stat-safe-scans");
  const statThreat = document.getElementById("stat-threat-scans");

  try {
    const res = await fetch("/api/v1/history?limit=50");
    if (!res.ok) throw new Error("Failed to load history.");
    const data = await res.json();

    const scans = data.scans || [];

    // Calculate Summary Stats
    let safeCount = 0;
    let threatCount = 0;

    scans.forEach((s) => {
      const lvl = (s.risk_level || "").toUpperCase();
      if (lvl === "LOW") {
        safeCount++;
      } else {
        threatCount++;
      }
    });

    if (statTotal) statTotal.textContent = scans.length;
    if (statSafe) statSafe.textContent = safeCount;
    if (statThreat) statThreat.textContent = threatCount;

    if (scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center" style="padding: 3rem 1.5rem; color: var(--text-muted);">
            <div style="font-size: 2.2rem; margin-bottom: 0.5rem;">🛡️</div>
            <div style="font-weight: 700; font-size: 1.1rem; color: var(--text-main); margin-bottom: 0.35rem;">No Scans Recorded Yet</div>
            <p style="font-size: 0.88rem; color: var(--text-dim); max-width: 420px; margin: 0 auto 1.25rem auto;">
              Analyze a URL or SMS message to begin logging confidential threat assessments locally.
            </p>
            <button type="button" class="btn btn-primary" onclick="switchTab('tab-url')" style="padding: 0.5rem 1.2rem; font-size: 0.84rem;">
              Start First Scan
            </button>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans
      .map((s) => {
        const riskLevel = (s.risk_level || "UNKNOWN").toUpperCase();
        const riskClass = riskLevel === "LOW" ? "low" : (riskLevel === "MEDIUM" ? "medium" : "high");
        const probPercent = (s.probability * 100).toFixed(1);
        const typeClass = (s.scan_type || "URL").toLowerCase();

        // Format timestamp safely
        let formattedDate = s.timestamp;
        try {
          const d = new Date(s.timestamp);
          if (!isNaN(d.getTime())) {
            formattedDate = d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          }
        } catch (e) {}

        const encodedInput = encodeURIComponent(s.input_preview || "");

        return `
          <tr>
            <td><code>#${s.id}</code></td>
            <td>
              <span class="type-pill ${typeClass}">${escapeHtml(s.scan_type)}</span>
            </td>
            <td style="max-width: 320px; word-break: break-all; font-family: var(--font-mono); font-size: 0.82rem;">
              ${escapeHtml(s.input_preview)}
            </td>
            <td>
              <span class="history-badge ${riskClass}">${riskLevel}</span>
            </td>
            <td><code>${probPercent}%</code></td>
            <td><code>${s.confidence_percentage}%</code></td>
            <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(formattedDate)}</td>
            <td style="text-align: center;">
              <button
                type="button"
                class="btn-rescan"
                onclick="rescanHistoryItem('${escapeHtml(s.scan_type)}', '${encodedInput}')"
                title="Re-run this scan"
              >
                Re-scan
              </button>
            </td>
          </tr>
        `;
      })
      .join("");
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center" style="color: var(--risk-high); padding: 2rem;">
          Error loading history records: ${escapeHtml(err.message)}
        </td>
      </tr>
    `;
  }
}

// Re-scan a historical item directly in the respective tool
function rescanHistoryItem(scanType, encodedInput) {
  const rawText = decodeURIComponent(encodedInput);
  if (!rawText) return;

  if (scanType.toUpperCase() === "URL") {
    switchTab("tab-url");
    const urlInput = document.getElementById("url-input");
    const urlForm = document.getElementById("url-scan-form");
    if (urlInput && urlForm) {
      urlInput.value = rawText;
      urlInput.focus();
      urlForm.dispatchEvent(new Event("submit"));
      showToast("Re-scanning historical URL...", "info");
    }
  } else {
    switchTab("tab-message");
    const msgInput = document.getElementById("message-input");
    const msgForm = document.getElementById("message-scan-form");
    const counter = document.getElementById("char-counter");
    if (msgInput && msgForm) {
      msgInput.value = rawText;
      if (counter) counter.textContent = `${rawText.length} / 5000 chars`;
      msgInput.focus();
      msgForm.dispatchEvent(new Event("submit"));
      showToast("Re-scanning historical message...", "info");
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const refreshBtn = document.getElementById("refresh-history-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadHistory();
      showToast("History audit trail refreshed.", "info");
    });
  }

  // Pre-load history stats
  loadHistory();
});
