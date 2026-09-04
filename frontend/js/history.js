/**
 * Scan Audit History Controller for PhishGuard-AI.
 */

async function loadHistory() {
  const tbody = document.getElementById("history-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/v1/history?limit=50");
    if (!res.ok) throw new Error("Failed to load history.");
    const data = await res.json();

    if (!data.scans || data.scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding: 2rem; color: var(--text-dim);">No scans recorded yet. Perform a URL or Message analysis to see history.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.scans
      .map((s) => {
        const riskClass = s.risk_level.toLowerCase();
        const probPercent = (s.probability * 100).toFixed(1);

        return `
          <tr>
            <td><code>#${s.id}</code></td>
            <td><strong>${escapeHtml(s.scan_type)}</strong></td>
            <td style="max-width: 320px; word-break: break-all; font-family: var(--font-mono); font-size: 0.8rem;">
              ${escapeHtml(s.input_preview)}
            </td>
            <td>
              <span class="history-badge ${riskClass}">${s.risk_level}</span>
            </td>
            <td><code>${probPercent}%</code></td>
            <td><code>${s.confidence_percentage}%</code></td>
            <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(s.timestamp)}</td>
          </tr>
        `;
      })
      .join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--risk-high); padding: 1.5rem;">Error loading history: ${escapeHtml(err.message)}</td></tr>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const refreshBtn = document.getElementById("refresh-history-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadHistory();
      showToast("History refreshed.", "info");
    });
  }

  loadHistory();
});
