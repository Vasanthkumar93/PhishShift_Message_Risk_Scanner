/**
 * PhishShift Client-Side Controller & UI Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  const scanForm = document.getElementById("scanForm");
  const messageInput = document.getElementById("messageInput");
  const charCountSpan = document.getElementById("charCount");
  const wordCountSpan = document.getElementById("wordCount");
  const btnClear = document.getElementById("btnClear");
  const btnSubmitScan = document.getElementById("btnSubmitScan");

  const resultsContainer = document.getElementById("resultsContainer");
  const bannerCard = document.getElementById("bannerCard");
  const resultBadge = document.getElementById("resultBadge");
  const resultIcon = document.getElementById("resultIcon");
  const resultClassification = document.getElementById("resultClassification");
  const scoreValue = document.getElementById("scoreValue");
  const meterBarFill = document.getElementById("meterBarFill");
  const confidenceText = document.getElementById("confidenceText");

  const signalCountBadge = document.getElementById("signalCountBadge");
  const signalsList = document.getElementById("signalsList");
  const adviceSummary = document.getElementById("adviceSummary");
  const recommendedActionsList = document.getElementById("recommendedActionsList");
  const educationalTipsList = document.getElementById("educationalTipsList");

  const statCaps = document.getElementById("statCaps");
  const statExcl = document.getElementById("statExcl");
  const statUrls = document.getElementById("statUrls");
  const statCurrency = document.getElementById("statCurrency");

  // Metrics Modal Elements
  const metricsModal = document.getElementById("metricsModal");
  const btnOpenMetricsModal = document.getElementById("btnOpenMetricsModal");
  const btnCloseModal = document.getElementById("btnCloseModal");
  const btnDismissModal = document.getElementById("btnDismissModal");

  // Sample Scenarios
  const PRESET_SAMPLES = {
    "obvious-phish": "URGENT: Your Bank of America account is suspended due to suspicious activity. Verify your identity immediately at http://bit.ly/boa-verify-login or your account will be permanently closed within 24 hours.",
    "subtle-phish": "Hi Alex, please review the attached quarterly performance sheet for your team when you get a chance: http://tinyurl.com/q3-review-doc. Thanks, HR Operations.",
    "benign-sensitive": "Reminder from IT Helpdesk: The company-wide password expiration policy is scheduled for next Monday. Please change your password directly in Windows settings (Ctrl+Alt+Del). We will never ask you for your password via email or link.",
    "benign-payroll": "Hello team, your monthly payroll slip for October has been processed and is now available on the internal Workday employee portal. Have a great weekend!",
    "benign-casual": "Hey bro, are we still meeting for lunch at 1pm near the library?"
  };

  // Live text counter
  function updateCounters() {
    const text = messageInput.value.trim();
    charCountSpan.textContent = text.length;
    wordCountSpan.textContent = text.length === 0 ? 0 : text.split(/\s+/).length;
  }

  messageInput.addEventListener("input", updateCounters);

  // Clear button
  btnClear.addEventListener("click", () => {
    messageInput.value = "";
    updateCounters();
    resultsContainer.classList.add("hidden");
    messageInput.focus();
  });

  // Preset sample buttons
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const type = btn.getAttribute("data-type");
      if (PRESET_SAMPLES[type]) {
        messageInput.value = PRESET_SAMPLES[type];
        updateCounters();
        // Trigger automated scan
        scanForm.dispatchEvent(new Event("submit"));
      }
    });
  });

  // Modal event listeners
  btnOpenMetricsModal.addEventListener("click", () => {
    metricsModal.classList.remove("hidden");
  });

  btnCloseModal.addEventListener("click", () => {
    metricsModal.classList.add("hidden");
  });

  btnDismissModal.addEventListener("click", () => {
    metricsModal.classList.add("hidden");
  });

  metricsModal.addEventListener("click", (e) => {
    if (e.target === metricsModal) {
      metricsModal.classList.add("hidden");
    }
  });

  // Form Submission & API Call
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawText = messageInput.value.trim();

    if (!rawText) {
      alert("Please enter or paste a message to analyze.");
      return;
    }

    // Visual loading state
    btnSubmitScan.disabled = true;
    const originalBtnText = btnSubmitScan.innerHTML;
    btnSubmitScan.innerHTML = `<span class="btn-icon">⏳</span> Analyzing...`;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: rawText })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.error || "Failed to scan message");
      }

      const data = await response.json();
      renderScanResults(data);

      // Smooth scroll to results
      resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (error) {
      alert("Error scanning message: " + error.message);
    } finally {
      btnSubmitScan.disabled = false;
      btnSubmitScan.innerHTML = originalBtnText;
    }
  });

  function renderScanResults(data) {
    resultsContainer.classList.remove("hidden");

    const classification = data.classification;
    const score = data.risk_score;
    const signals = data.signals || [];
    const stats = data.statistics || {};
    const advice = data.safety_advice || {};

    // 1. Classification Badge & Colors
    resultBadge.className = "result-badge";
    meterBarFill.className = "meter-bar-fill";

    if (classification === "Likely Phishing") {
      resultBadge.classList.add("badge-phishing");
      resultIcon.textContent = "🚨";
      meterBarFill.classList.add("fill-phishing");
    } else if (classification === "Suspicious") {
      resultBadge.classList.add("badge-suspicious");
      resultIcon.textContent = "⚠️";
      meterBarFill.classList.add("fill-suspicious");
    } else {
      resultBadge.classList.add("badge-legitimate");
      resultIcon.textContent = "🛡️";
      meterBarFill.classList.add("fill-legitimate");
    }

    resultClassification.textContent = classification;
    scoreValue.textContent = score.toFixed(1);

    // Animate meter fill
    setTimeout(() => {
      meterBarFill.style.width = `${Math.min(100, Math.max(3, score))}%`;
    }, 50);

    confidenceText.textContent = `Confidence: ${data.confidence_text} (Raw ML: ${data.ml_probability}%)`;

    // 2. Warning Signals
    signalsList.innerHTML = "";
    signalCountBadge.textContent = `${signals.length} Found`;

    if (signals.length === 0) {
      signalsList.innerHTML = `
        <div class="no-signals-msg">
          ✓ No deceptive warning signals or coercive patterns identified in heuristic scan.
        </div>
      `;
    } else {
      signals.forEach(sig => {
        const item = document.createElement("div");
        const sevClass = sig.severity.toLowerCase();
        item.className = `signal-item sev-${sevClass}`;

        item.innerHTML = `
          <div class="signal-top">
            <span class="signal-title">${sig.title}</span>
            <span class="signal-sev-tag tag-${sevClass === 'high' ? 'high' : sevClass === 'medium' ? 'med' : sevClass === 'low' ? 'low' : 'info'}">${sig.severity}</span>
          </div>
          <div class="signal-desc">${sig.description}</div>
        `;
        signalsList.appendChild(item);
      });
    }

    // 3. Safety Advice
    adviceSummary.className = "advice-alert";
    if (classification === "Likely Phishing") {
      adviceSummary.classList.add("alert-danger");
    } else if (classification === "Suspicious") {
      adviceSummary.classList.add("alert-warning");
    } else {
      adviceSummary.classList.add("alert-success");
    }
    adviceSummary.textContent = advice.summary || "";

    // Recommended Actions
    recommendedActionsList.innerHTML = "";
    (advice.recommended_actions || []).forEach(act => {
      const li = document.createElement("li");
      li.textContent = act;
      recommendedActionsList.appendChild(li);
    });

    // Security Insights
    educationalTipsList.innerHTML = "";
    (advice.educational_tips || []).forEach(tip => {
      const li = document.createElement("li");
      li.textContent = tip;
      educationalTipsList.appendChild(li);
    });

    // 4. NLP Telemetry
    statCaps.textContent = `${((stats.caps_ratio || 0) * 100).toFixed(1)}%`;
    statExcl.textContent = stats.exclamation_count || 0;
    statUrls.textContent = (data.urls_detected || []).length;
    statCurrency.textContent = stats.has_currency ? "Yes" : "None";
  }
});
