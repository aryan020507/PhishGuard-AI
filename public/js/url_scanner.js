/**
 * URL Threat Scanner Controller for PhishGuard-AI.
 */

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("url-scan-form");
  const urlInput = document.getElementById("url-input");
  const submitBtn = document.getElementById("url-submit-btn");
  const btnText = submitBtn.querySelector(".btn-text");
  const btnSpinner = submitBtn.querySelector(".btn-spinner");
  const resultContainer = document.getElementById("url-result-container");
  const chipsContainer = document.getElementById("url-sample-chips");

  // Render Sample Chips
  if (chipsContainer && typeof URL_SAMPLES !== "undefined") {
    URL_SAMPLES.forEach((sample) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `chip-btn ${sample.type === "phish" ? "phish" : ""}`;
      btn.textContent = sample.label;
      btn.addEventListener("click", () => {
        urlInput.value = sample.url;
        urlInput.focus();
        form.dispatchEvent(new Event("submit"));
      });
      chipsContainer.appendChild(btn);
    });
  }

  // Handle Form Submission
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();

    if (!url) {
      showToast("Please enter a valid URL.", "error");
      return;
    }

    // Set Loading State
    submitBtn.disabled = true;
    btnText.textContent = "Analyzing Locally...";
    btnSpinner.classList.remove("hidden");

    try {
      const response = await fetch("/api/v1/predict/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.error || "Failed to analyze URL.");
      }

      renderUrlResults(data);
      showToast("URL Threat Analysis Completed.", "success");

      // Auto-refresh scan history if on page
      if (typeof loadHistory === "function") {
        loadHistory();
      }
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = "Analyze URL";
      btnSpinner.classList.add("hidden");
    }
  });

  function renderUrlResults(data) {
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
      indicatorsHtml = `<p class="text-muted">No heuristic triggers detected.</p>`;
    }

    // Build Features Rows
    let featuresHtml = "";
    if (data.features) {
      featuresHtml = Object.entries(data.features)
        .map(([key, val]) => `
          <tr>
            <td><strong>${escapeHtml(key)}</strong></td>
            <td>${typeof val === "number" ? val.toFixed(3) : escapeHtml(String(val))}</td>
          </tr>
        `)
        .join("");
    }

    resultContainer.innerHTML = `
      <div class="result-card ${riskClass}">
        <div class="result-header">
          <div class="target-preview-box">
            <div class="target-preview-label">Inspected Destination URL (Zero-Contact)</div>
            <div class="target-preview-text">${escapeHtml(data.input_url)}</div>
          </div>
          <div class="risk-badge ${riskClass}">
            <span>${risk.risk_level} THREAT RISK</span>
          </div>
        </div>

        <div class="threat-meter-grid">
          <div class="metric-box">
            <div class="metric-title">ML Threat Probability</div>
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
              16 Static Local Features &bull; ANN
            </div>
          </div>
        </div>

        <div class="recommendation-box ${riskClass}">
          <div class="recommendation-title">Security Guidance</div>
          <div class="recommendation-text">${escapeHtml(risk.recommendation)}</div>
        </div>

        <div class="indicators-section">
          <h4>Heuristic Threat Explanations (${data.indicators.length})</h4>
          <div class="indicators-list">
            ${indicatorsHtml}
          </div>
        </div>

        <div class="details-toggle" id="url-features-toggle">
          <span>&gt; Inspect 16 Static Numerical Features</span>
        </div>

        <div id="url-features-details" class="features-table-wrapper hidden">
          <table class="features-table">
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Calculated Local Value</th>
              </tr>
            </thead>
            <tbody>
              ${featuresHtml}
            </tbody>
          </table>
        </div>
      </div>
    `;

    resultContainer.classList.remove("hidden");

    // Toggle Feature Table Visibility
    const toggle = document.getElementById("url-features-toggle");
    const details = document.getElementById("url-features-details");
    if (toggle && details) {
      toggle.addEventListener("click", () => {
        const isHidden = details.classList.contains("hidden");
        details.classList.toggle("hidden");
        toggle.querySelector("span").textContent = isHidden
          ? "v Hide 16 Static Numerical Features"
          : "> Inspect 16 Static Numerical Features";
      });
    }

    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
});
