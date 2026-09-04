/**
 * Message Threat Scanner Controller for PhishGuard-AI.
 */

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("message-scan-form");
  const messageInput = document.getElementById("message-input");
  const charCounter = document.getElementById("char-counter");
  const clearBtn = document.getElementById("clear-message-btn");
  const submitBtn = document.getElementById("message-submit-btn");
  const btnText = submitBtn.querySelector(".btn-text");
  const btnSpinner = submitBtn.querySelector(".btn-spinner");
  const resultContainer = document.getElementById("message-result-container");
  const chipsContainer = document.getElementById("message-sample-chips");

  // Character Counter
  messageInput.addEventListener("input", () => {
    const len = messageInput.value.length;
    charCounter.textContent = `${len} / 5000 chars`;
    if (len > 4500) {
      charCounter.style.color = "var(--risk-med)";
    } else {
      charCounter.style.color = "var(--text-dim)";
    }
  });

  // Clear Button
  clearBtn.addEventListener("click", () => {
    messageInput.value = "";
    charCounter.textContent = "0 / 5000 chars";
    resultContainer.classList.add("hidden");
    messageInput.focus();
  });

  // Render Sample Chips
  if (chipsContainer && typeof MESSAGE_SAMPLES !== "undefined") {
    MESSAGE_SAMPLES.forEach((sample) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `chip-btn ${sample.type === "phish" ? "phish" : ""}`;
      btn.textContent = sample.label;
      btn.addEventListener("click", () => {
        messageInput.value = sample.text;
        charCounter.textContent = `${sample.text.length} / 5000 chars`;
        messageInput.focus();
        form.dispatchEvent(new Event("submit"));
      });
      chipsContainer.appendChild(btn);
    });
  }

  // Handle Form Submission
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();

    if (!message) {
      showToast("Please enter a message to analyze.", "error");
      return;
    }

    // Set Loading State
    submitBtn.disabled = true;
    btnText.textContent = "Analyzing NLP Patterns...";
    btnSpinner.classList.remove("hidden");

    try {
      const response = await fetch("/api/v1/predict/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.error || "Failed to analyze message.");
      }

      renderMessageResults(data);
      showToast("Message Threat Analysis Completed.", "success");

      // Auto-refresh scan history if on page
      if (typeof loadHistory === "function") {
        loadHistory();
      }
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = "Analyze Message";
      btnSpinner.classList.add("hidden");
    }
  });

  function renderMessageResults(data) {
    const risk = data.risk;
    const riskClass = risk.risk_level.toLowerCase();
    const probPercent = (risk.probability * 100).toFixed(1);

    // Build Indicators HTML
    let indicatorsHtml = "";
    if (data.indicators && data.indicators.length > 0) {
      indicatorsHtml = data.indicators
        .map((ind) => {
          let icon = "ℹ️";
          if (ind.severity === "danger") icon = "🚨";
          else if (ind.severity === "warning") icon = "⚠️";

          return `
            <div class="indicator-item ${ind.severity}">
              <div class="indicator-badge-icon">${icon}</div>
              <div>
                <div class="indicator-name">${escapeHtml(ind.name)}</div>
                <div class="indicator-desc">${escapeHtml(ind.description)}</div>
              </div>
            </div>
          `;
        })
        .join("");
    } else {
      indicatorsHtml = `<p class="text-muted">No threat triggers detected.</p>`;
    }

    resultContainer.innerHTML = `
      <div class="result-card ${riskClass}">
        <div class="result-header">
          <div class="target-preview-box">
            <div class="target-preview-label">Analyzed Text Body</div>
            <div class="target-preview-text">"${escapeHtml(data.input_message)}"</div>
          </div>
          <div class="risk-badge ${riskClass}">
            <span>${risk.risk_level} THREAT RISK</span>
          </div>
        </div>

        <div class="threat-meter-grid">
          <div class="metric-box">
            <div class="metric-title">Social Engineering Probability</div>
            <div class="metric-value-lg" style="color: ${risk.risk_color}">${probPercent}%</div>
            <div class="metric-bar-track">
              <div class="metric-bar-fill" style="width: ${probPercent}%; background-color: ${risk.risk_color}"></div>
            </div>
          </div>

          <div class="metric-box">
            <div class="metric-title">Assessment Confidence</div>
            <div class="metric-value-lg" style="color: ${risk.risk_color}">${risk.confidence_percentage}%</div>
            <div class="metric-bar-track">
              <div class="metric-bar-fill" style="width: ${risk.confidence_percentage}%; background-color: ${risk.risk_color}"></div>
            </div>
          </div>

          <div class="metric-box">
            <div class="metric-title">Model Pipeline</div>
            <div style="font-size: 0.95rem; font-weight: 700; margin-top: 0.25rem;">
              ${escapeHtml(data.model_used)}
            </div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.4rem;">
              Sequence Embedding &bull; SimpleRNN
            </div>
          </div>
        </div>

        <div class="recommendation-box ${riskClass}">
          <div class="recommendation-title">Security Guidance</div>
          <div class="recommendation-text">${escapeHtml(risk.recommendation)}</div>
        </div>

        <div class="indicators-section">
          <h4>Social Engineering Indicators (${data.indicators.length})</h4>
          <div class="indicators-list">
            ${indicatorsHtml}
          </div>
        </div>

        <div class="details-toggle" id="msg-clean-toggle">
          <span>&gt; Inspect Normalized Model Input Token Stream</span>
        </div>

        <div id="msg-clean-details" class="features-table-wrapper hidden" style="padding: 1rem; font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-muted); background: rgba(0,0,0,0.3);">
          <strong>Cleaned &amp; Normalized Text:</strong><br>
          <span style="color: var(--color-primary);">${escapeHtml(data.cleaned_text)}</span>
        </div>
      </div>
    `;

    resultContainer.classList.remove("hidden");

    // Toggle Normalized Text
    const toggle = document.getElementById("msg-clean-toggle");
    const details = document.getElementById("msg-clean-details");
    if (toggle && details) {
      toggle.addEventListener("click", () => {
        const isHidden = details.classList.contains("hidden");
        details.classList.toggle("hidden");
        toggle.querySelector("span").textContent = isHidden
          ? "v Hide Normalized Model Input Token Stream"
          : "> Inspect Normalized Model Input Token Stream";
      });
    }

    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
});
