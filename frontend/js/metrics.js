/**
 * Model Performance Metrics Controller for PhishGuard-AI.
 * Fetches verified metrics from /api/v1/models/metrics and renders tables and confusion matrices.
 */

document.addEventListener("DOMContentLoaded", () => {
  const urlPane = document.getElementById("metrics-url");
  const msgPane = document.getElementById("metrics-message");
  const subnavBtns = document.querySelectorAll(".subnav-btn");

  // Subnav tab switching
  subnavBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      subnavBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      const targetId = btn.getAttribute("data-subtab");
      document.querySelectorAll(".subtab-pane").forEach((p) => p.classList.remove("active"));
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });

  loadMetrics();

  async function loadMetrics() {
    try {
      const res = await fetch("/api/v1/models/metrics");
      if (!res.ok) throw new Error("Failed to fetch model metrics.");
      const data = await res.json();

      if (data.url_model) renderUrlMetrics(data.url_model);
      if (data.message_model) renderMessageMetrics(data.message_model);
    } catch (err) {
      if (urlPane) urlPane.innerHTML = `<div class="error-msg">Error loading URL model metrics: ${escapeHtml(err.message)}</div>`;
      if (msgPane) msgPane.innerHTML = `<div class="error-msg">Error loading Message model metrics: ${escapeHtml(err.message)}</div>`;
    }
  }

  function renderUrlMetrics(m) {
    if (!urlPane) return;
    if (m.error || !m.test_metrics) {
      urlPane.innerHTML = `<div class="metrics-card"><p>${escapeHtml(m.error || m.status || "Metrics unavailable.")}</p></div>`;
      return;
    }

    const t = m.test_metrics;
    const cm = m.confusion_matrix;
    const split = m.split_counts;

    urlPane.innerHTML = `
      <div class="metrics-card">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem;">
          <div>
            <h3>${escapeHtml(m.model_name)}</h3>
            <span style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(m.model_type)}</span>
          </div>
          <div class="card-meta-pill">Split: 70% Train / 15% Val / 15% Test (${split.total} samples)</div>
        </div>

        <div class="metrics-stats-grid">
          <div class="stat-box">
            <div class="stat-val">${(t.accuracy * 100).toFixed(2)}%</div>
            <div class="stat-label">Accuracy</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.precision * 100).toFixed(2)}%</div>
            <div class="stat-label">Precision</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.recall * 100).toFixed(2)}%</div>
            <div class="stat-label">Recall</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.f1_score * 100).toFixed(2)}%</div>
            <div class="stat-label">F1-Score</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.roc_auc).toFixed(4)}</div>
            <div class="stat-label">ROC-AUC</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.loss).toFixed(4)}</div>
            <div class="stat-label">Test Loss</div>
          </div>
        </div>

        <div class="cm-section">
          <h4>Holdout Test Set Confusion Matrix (${split.test} Samples)</h4>
          <div class="cm-grid-wrapper">
            <div class="confusion-matrix-grid">
              <div class="cm-header"></div>
              <div class="cm-header">Pred Legit</div>
              <div class="cm-header">Pred Phish</div>

              <div class="cm-label-y">Actual Legit</div>
              <div class="cm-cell true-negative">
                <div class="cm-count">${cm.true_negatives}</div>
                <div class="cm-tag">True Negative</div>
              </div>
              <div class="cm-cell false-positive">
                <div class="cm-count">${cm.false_positives}</div>
                <div class="cm-tag">False Positive</div>
              </div>

              <div class="cm-label-y">Actual Phish</div>
              <div class="cm-cell false-negative">
                <div class="cm-count">${cm.false_negatives}</div>
                <div class="cm-tag">False Negative</div>
              </div>
              <div class="cm-cell true-positive">
                <div class="cm-count">${cm.true_positives}</div>
                <div class="cm-tag">True Positive</div>
              </div>
            </div>
          </div>
        </div>

        <div style="margin-top: 2rem;">
          <h4>16 Extracted Numerical Features</h4>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.75rem;">
            ${(m.input_features || []).map(f => `<span class="card-meta-pill" style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(f)}</span>`).join("")}
          </div>
        </div>
      </div>
    `;
  }

  function renderMessageMetrics(m) {
    if (!msgPane) return;
    if (m.error || !m.test_metrics) {
      msgPane.innerHTML = `<div class="metrics-card"><p>${escapeHtml(m.error || m.status || "Metrics unavailable.")}</p></div>`;
      return;
    }

    const t = m.test_metrics;
    const cm = m.confusion_matrix;
    const split = m.split_counts;

    msgPane.innerHTML = `
      <div class="metrics-card">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem;">
          <div>
            <h3>${escapeHtml(m.model_name)}</h3>
            <span style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(m.model_type)}</span>
          </div>
          <div class="card-meta-pill">Split: 70% Train / 15% Val / 15% Test (${split.total} samples)</div>
        </div>

        <div class="metrics-stats-grid">
          <div class="stat-box">
            <div class="stat-val">${(t.accuracy * 100).toFixed(2)}%</div>
            <div class="stat-label">Accuracy</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.precision * 100).toFixed(2)}%</div>
            <div class="stat-label">Precision</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.recall * 100).toFixed(2)}%</div>
            <div class="stat-label">Recall</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.f1_score * 100).toFixed(2)}%</div>
            <div class="stat-label">F1-Score</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.roc_auc).toFixed(4)}</div>
            <div class="stat-label">ROC-AUC</div>
          </div>
          <div class="stat-box">
            <div class="stat-val">${(t.loss).toFixed(4)}</div>
            <div class="stat-label">Test Loss</div>
          </div>
        </div>

        <div class="cm-section">
          <h4>Holdout Test Set Confusion Matrix (${split.test} Samples)</h4>
          <div class="cm-grid-wrapper">
            <div class="confusion-matrix-grid">
              <div class="cm-header"></div>
              <div class="cm-header">Pred Legit</div>
              <div class="cm-header">Pred Phish</div>

              <div class="cm-label-y">Actual Legit</div>
              <div class="cm-cell true-negative">
                <div class="cm-count">${cm.true_negatives}</div>
                <div class="cm-tag">True Negative</div>
              </div>
              <div class="cm-cell false-positive">
                <div class="cm-count">${cm.false_positives}</div>
                <div class="cm-tag">False Positive</div>
              </div>

              <div class="cm-label-y">Actual Phish</div>
              <div class="cm-cell false-negative">
                <div class="cm-count">${cm.false_negatives}</div>
                <div class="cm-tag">False Negative</div>
              </div>
              <div class="cm-cell true-positive">
                <div class="cm-count">${cm.true_positives}</div>
                <div class="cm-tag">True Positive</div>
              </div>
            </div>
          </div>
        </div>

        <div style="margin-top: 2rem;">
          <h4>Vocabulary & Sequence Parameters</h4>
          <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.75rem;">
            <div class="card-meta-pill">Vocab Size: ${m.vocab_size} tokens</div>
            <div class="card-meta-pill">Max Sequence Length: ${m.max_sequence_length} tokens</div>
            <div class="card-meta-pill">Tokenizer: Fitted on Training Split</div>
          </div>
        </div>
      </div>
    `;
  }
});
