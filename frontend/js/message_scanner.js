/**
 * Message Threat Scanner Controller for PhishGuard-AI.
 * Manages zero-contact SMS and message threat analysis, prominent Safe/Not Safe verdict banner,
 * detailed reasons list, and actionable security suggestions.
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

  // Render Sample Chips
  if (chipsContainer && typeof MESSAGE_SAMPLES !== "undefined") {
    MESSAGE_SAMPLES.forEach((sample) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `chip-btn ${sample.type === "phish" ? "phish" : ""}`;
      btn.textContent = sample.label;
      btn.addEventListener("click", () => {
        messageInput.value = sample.text;
        if (charCounter) charCounter.textContent = `${sample.text.length} / 5000 chars`;
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
      showToast("Please enter a message or SMS to analyze.", "error");
      return;
    }

    // Set Loading State
    submitBtn.disabled = true;
    btnText.textContent = "Analyzing Linguistic Patterns...";
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

      // Auto-refresh scan history if loaded
      if (typeof loadHistory === "function") {
        loadHistory();
      }
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = "Scan Message";
      btnSpinner.classList.add("hidden");
    }
  });

  function renderMessageResults(data) {
    const risk = data.risk;
    const riskLevel = risk.risk_level.toUpperCase();
    const probPercent = (risk.probability * 100).toFixed(1);

    // Determine Verdict Status & Suggestions
    let verdictClass = "safe";
    let verdictTitle = "VERIFIED SAFE (Low Threat Risk)";
    let verdictDesc = "Natural conversational structure detected. No coercive urgency deadlines, fake prizes, or smishing triggers found.";
    let verdictBadge = "BENIGN MESSAGE";
    let verdictIconSvg = `
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    `;

    let suggestionsBadge = "Recommended Security Practices";
    let suggestions = [
      { icon: "✅", text: "<strong>Safe Communication:</strong> The text exhibits standard conversational patterns without social engineering triggers." },
      { icon: "🔒", text: "<strong>Never Disclose OTPs:</strong> Never share One-Time Passwords (2FA codes) with anyone, even if an unexpected sender claims to be official support." },
      { icon: "💡", text: "<strong>Routine Caution:</strong> If someone asks for unexpected financial assistance or gift cards, verify by voice call." }
    ];

    if (riskLevel === "HIGH") {
      verdictClass = "danger";
      verdictTitle = "NOT SAFE - SMISHING / SCAM ATTACK DETECTED";
      verdictDesc = "High threat alert! The text exhibits manipulative psychological urgency, brand impersonation, or coercive lures.";
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
        { icon: "🚫", text: "<strong>DO NOT REPLY TO THIS SENDER:</strong> Do not text 'STOP', 'YES', or reply in any way—replying confirms your phone number is active to cybercriminals." },
        { icon: "🛑", text: "<strong>DO NOT CLICK LINKS OR CALL NUMBERS:</strong> Never open links, download attachments, or dial phone numbers provided in the text body." },
        { icon: "🛡️", text: "<strong>BLOCK SENDER & REPORT SPAM:</strong> Block the sender's phone number on your device and report it to your carrier (forward SMS to 7726)." },
        { icon: "📞", text: "<strong>CONTACT INSTITUTION DIRECTLY:</strong> If the message claims to be your bank, postal courier, or doctor, open their official mobile app or call the verified number printed on your card." }
      ];
    } else if (riskLevel === "MEDIUM") {
      verdictClass = "warning";
      verdictTitle = "SUSPICIOUS - PROCEED WITH CAUTION";
      verdictDesc = "Suspicious social engineering indicators identified. Language creates artificial urgency or references sensitive brands.";
      verdictBadge = "SUSPICIOUS SMS";
      verdictIconSvg = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      `;

      suggestionsBadge = "Heightened Caution Recommended";
      suggestions = [
        { icon: "⚠️", text: "<strong>DO NOT PROVIDE PRIVATE DATA:</strong> Avoid sending personal account details, passwords, or identification numbers." },
        { icon: "🔍", text: "<strong>BEWARE OF ARTIFICIAL DEADLINES:</strong> Attackers create fake deadlines ('within 24 hours') to bypass your critical thinking." },
        { icon: "📞", text: "<strong>INDEPENDENT VERIFICATION:</strong> Contact the alleged sender via their known public support website, not links in this text." }
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
      indicatorsHtml = `<p class="text-muted">No threat triggers detected. Standard conversational syntax verified.</p>`;
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

        <!-- 2. Analyzed Message Preview -->
        <div class="inspected-input-preview">
          <div class="preview-label">Analyzed Text Body (Zero-Contact Analysis)</div>
          <div class="preview-box-text">"${escapeHtml(data.input_message)}"</div>
        </div>

        <!-- 3. What You Should Do: Actionable Security Suggestions -->
        <div class="suggestions-box ${verdictClass}">
          <div class="suggestions-header">
            <span class="suggestions-title">What Should You Do With This Message?</span>
            <span class="suggestions-badge">${escapeHtml(suggestionsBadge)}</span>
          </div>
          <div class="suggestions-list">
            ${suggestionsHtml}
          </div>
        </div>

        <!-- 4. Threat Metrics Gauges -->
        <div class="threat-meter-grid">
          <div class="metric-box">
            <div class="metric-title">Social Engineering Probability</div>
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
            <div class="metric-title">NLP Detection Pipeline</div>
            <div style="font-size: 0.95rem; font-weight: 700; margin-top: 0.25rem;">
              ${escapeHtml(data.model_used)}
            </div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.4rem;">
              Sequence Embedding &bull; SimpleRNN Neural Network
            </div>
          </div>
        </div>

        <!-- 5. Reasons Why It Is Safe or Not Safe (Linguistic Indicators) -->
        <div class="indicators-section">
          <div class="indicators-header">
            <h4>Reasons &amp; Threat Indicators (${data.indicators.length} Signals Evaluated)</h4>
            <p>Linguistic pattern analysis and social engineering psychological triggers</p>
          </div>
          <div class="indicators-list">
            ${indicatorsHtml}
          </div>
        </div>

        <!-- 6. Collapsible Normalized Token Stream -->
        <div class="details-toggle" id="msg-clean-toggle">
          <span>&gt; Inspect Normalized Model Input Token Stream</span>
        </div>

        <div id="msg-clean-details" class="features-table-wrapper hidden" style="padding: 1.25rem; font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-muted); background: var(--bg-input);">
          <div style="color: var(--text-dim); margin-bottom: 0.4rem; font-weight: 700; text-transform: uppercase; font-size: 0.72rem;">Cleaned &amp; Normalized Text Passed to Neural Network:</div>
          <span style="color: var(--accent-cyan-light); word-break: break-all;">${escapeHtml(data.cleaned_text)}</span>
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
