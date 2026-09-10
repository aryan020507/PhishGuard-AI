/**
 * URL Threat Scanner Controller for PhishGuard-AI.
 * Manages zero-contact URL static threat analysis, prominent Safe/Not Safe verdict banner,
 * detailed reasons list, and actionable security suggestions.
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
      showToast("Please enter a valid URL to analyze.", "error");
      return;
    }

    // Set Loading State
    submitBtn.disabled = true;
    btnText.textContent = "Analyzing Statically...";
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

      // Auto-refresh scan history if loaded
      if (typeof loadHistory === "function") {
        loadHistory();
      }
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = "Scan URL";
      btnSpinner.classList.add("hidden");
    }
  });

  function renderUrlResults(data) {
    const risk = data.risk;
    const riskLevel = risk.risk_level.toUpperCase();
    const probPercent = (risk.probability * 100).toFixed(1);

    // Determine Verdict Status & Suggestions
    let verdictClass = "safe";
    let verdictTitle = "VERIFIED SAFE (Low Threat Risk)";
    let verdictDesc = "This destination URL demonstrates legitimate syntax and authentic structural characteristics.";
    let verdictBadge = "SAFE TO VISIT";
    let verdictIconSvg = `
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    `;

    let suggestionsBadge = "Recommended Security Practices";
    let suggestions = [
      { icon: "✅", text: "<strong>Safe Destination:</strong> The URL exhibits authentic domain structures and matches trusted benchmarks." },
      { icon: "🔒", text: "<strong>Verify Padlock:</strong> Ensure your browser displays the cryptographic HTTPS lock icon before submitting any login credentials." },
      { icon: "💡", text: "<strong>General Caution:</strong> Never enter financial credentials on web pages you were prompted to visit from unexpected messages." }
    ];

    if (riskLevel === "HIGH") {
      verdictClass = "danger";
      verdictTitle = "NOT SAFE - PHISHING ATTACK DETECTED";
      verdictDesc = "High threat probability! Deceptive markers indicate an attempt to harvest credentials or distribute malware.";
      verdictBadge = "CRITICAL THREAT";
      verdictIconSvg = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      `;

      suggestionsBadge = "Critical Immediate Action Required";
      suggestions = [
        { icon: "🚫", text: "<strong>DO NOT OPEN OR CLICK THIS LINK:</strong> Do not navigate to this destination in any web browser." },
        { icon: "🛑", text: "<strong>DO NOT ENTER CREDENTIALS:</strong> Never input passwords, credit card numbers, social security digits, or personal details." },
        { icon: "🛡️", text: "<strong>BLOCK & REPORT SENDER:</strong> Delete the message containing this link and report it as a phishing scam to your IT security team." },
        { icon: "⚠️", text: "<strong>IF ALREADY OPENED:</strong> Close the browser window immediately, do NOT download any files, and clear browser cache and cookies." }
      ];
    } else if (riskLevel === "MEDIUM") {
      verdictClass = "warning";
      verdictTitle = "SUSPICIOUS - PROCEED WITH CAUTION";
      verdictDesc = "Ambiguous threat signals detected. The URL contains patterns frequently observed in fraudulent campaigns.";
      verdictBadge = "SUSPICIOUS LINK";
      verdictIconSvg = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      `;

      suggestionsBadge = "Heightened Caution Recommended";
      suggestions = [
        { icon: "⚠️", text: "<strong>DO NOT SUBMIT SENSITIVE DATA:</strong> Avoid entering passwords, banking information, or private identity data." },
        { icon: "🔍", text: "<strong>INSPECT DOMAIN NAME CLOSELY:</strong> Check the exact spelling in the address bar for spoofed brand lookalikes (typosquatting)." },
        { icon: "📞", text: "<strong>VERIFY INDEPENDENTLY:</strong> If an organization sent you this link, visit their verified official website directly instead of clicking." }
      ];
    }

    // Build Actionable Suggestions HTML
    const suggestionsHtml = suggestions
      .map(s => `
        <div class="suggestion-item">
          <span class="suggestion-icon">${s.icon}</span>
          <div>${s.text}</div>
        </div>
      `)
      .join("");

    // Build Indicators / Reasons HTML
    let indicatorsHtml = "";
    if (data.indicators && data.indicators.length > 0) {
      indicatorsHtml = data.indicators
        .map((ind) => {
          let icon = "ℹ️";
          let sevText = "Safe / Info";
          if (ind.severity === "danger") {
            icon = "🚨";
            sevText = "Critical Indicator";
          } else if (ind.severity === "warning") {
            icon = "⚠️";
            sevText = "Warning Signal";
          }

          return `
            <div class="indicator-item ${ind.severity}">
              <div class="indicator-badge-icon">${icon}</div>
              <div style="flex: 1;">
                <div class="indicator-name-row">
                  <span class="indicator-name">${escapeHtml(ind.name)}</span>
                  <span class="indicator-severity-tag">${sevText}</span>
                </div>
                <div class="indicator-desc">${escapeHtml(ind.description)}</div>
              </div>
            </div>
          `;
        })
        .join("");
    } else {
      indicatorsHtml = `<p class="text-muted">No anomalous threat triggers detected. Standard structural syntax verified.</p>`;
    }

    // Build 16 Numerical Features Rows
    let featuresHtml = "";
    if (data.features) {
      featuresHtml = Object.entries(data.features)
        .map(([key, val]) => `
          <tr>
            <td><strong>${escapeHtml(key)}</strong></td>
            <td><code>${typeof val === "number" ? val.toFixed(3) : escapeHtml(String(val))}</code></td>
          </tr>
        `)
        .join("");
    }

    resultContainer.innerHTML = `
      <div class="result-card">
        <!-- 1. Prominent Verdict Banner (Safe / Not Safe) -->
        <div class="verdict-banner ${verdictClass}">
          <div class="verdict-main">
            <div class="verdict-icon">
              ${verdictIconSvg}
            </div>
            <div>
              <div class="verdict-status-title">${escapeHtml(verdictTitle)}</div>
              <div class="verdict-status-desc">${escapeHtml(verdictDesc)}</div>
            </div>
          </div>
          <div class="verdict-badge-pill">${escapeHtml(verdictBadge)}</div>
        </div>

        <!-- 2. Target URL Inspected Preview -->
        <div class="inspected-input-preview">
          <div class="preview-label">Inspected Target URL (Zero-Contact Analysis)</div>
          <div class="preview-box-text">${escapeHtml(data.input_url)}</div>
        </div>

        <!-- 3. What You Should Do: Actionable Security Suggestions -->
        <div class="suggestions-box ${verdictClass}">
          <div class="suggestions-header">
            <span class="suggestions-title">What Should You Do With This URL?</span>
            <span class="suggestions-badge">${escapeHtml(suggestionsBadge)}</span>
          </div>
          <div class="suggestions-list">
            ${suggestionsHtml}
          </div>
        </div>

        <!-- 4. Threat Metrics Gauges -->
        <div class="threat-meter-grid">
          <div class="metric-box">
            <div class="metric-title">ML Threat Probability</div>
            <div class="metric-value-lg" style="color: ${risk.risk_color}">${probPercent}%</div>
            <div class="metric-bar-track">
              <div class="metric-bar-fill" style="width: ${probPercent}%; background-color: ${risk.risk_color}"></div>
            </div>
          </div>

          <div class="metric-box">
            <div class="metric-title">Model Confidence</div>
            <div class="metric-value-lg" style="color: ${risk.risk_color}">${risk.confidence_percentage}%</div>
            <div class="metric-bar-track">
              <div class="metric-bar-fill" style="width: ${risk.confidence_percentage}%; background-color: ${risk.risk_color}"></div>
            </div>
          </div>

          <div class="metric-box">
            <div class="metric-title">Detection Pipeline</div>
            <div style="font-size: 0.95rem; font-weight: 700; margin-top: 0.25rem;">
              ${escapeHtml(data.model_used)}
            </div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.4rem;">
              16 Static Local Features &bull; Fully Zero-Contact
            </div>
          </div>
        </div>

        <!-- 5. Reasons Why It Is Safe or Not Safe (Heuristic Indicators) -->
        <div class="indicators-section">
          <div class="indicators-header">
            <h4>Reasons &amp; Threat Indicators (${data.indicators.length} Signals Evaluated)</h4>
            <p>Detailed heuristic explanation of detected security markers and domain syntax</p>
          </div>
          <div class="indicators-list">
            ${indicatorsHtml}
          </div>
        </div>

        <!-- 6. Collapsible 16 Numerical Static Features Table -->
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
