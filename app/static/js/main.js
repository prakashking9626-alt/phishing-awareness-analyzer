/**
 * Phishing Awareness Analyzer - Frontend Controller (ES6)
 * Enterprise-grade offline threat triage interface.
 * Handles tab navigation, asynchronous API requests, and dynamic dashboard rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Current Active Mode ('url' or 'email')
    let activeMode = "url";

    // Asynchronous Request Concurrency & Cancellation Control
    let activeAbortController = null;
    let currentRequestId = 0;

    // Navigation & Mode Switchers
    const navBtnUrl = document.getElementById("nav-btn-url");
    const navBtnEmail = document.getElementById("nav-btn-email");
    const tabUrlBtn = document.getElementById("tab-url-btn");
    const tabEmailBtn = document.getElementById("tab-email-btn");
    const panelUrl = document.getElementById("panel-url");
    const panelEmail = document.getElementById("panel-email");

    // Forms & Inputs
    const urlForm = document.getElementById("url-form");
    const urlInput = document.getElementById("url-input");
    const btnAnalyzeUrl = document.getElementById("btn-analyze-url");
    const btnResetUrl = document.getElementById("btn-reset-url");

    const emailForm = document.getElementById("email-form");
    const emailSenderInput = document.getElementById("email-sender-input");
    const emailBodyInput = document.getElementById("email-body-input");
    const btnAnalyzeEmail = document.getElementById("btn-analyze-email");
    const btnResetEmail = document.getElementById("btn-reset-email");

    // Feedback & Error Elements
    const errorAlert = document.getElementById("error-alert");
    const errorMessage = document.getElementById("error-message");
    const btnCloseAlert = document.getElementById("btn-close-alert");

    // Results Dashboard Elements
    const resultsCard = document.getElementById("results-card");
    const resultsSummaryTitle = document.getElementById("results-summary-title");
    const riskBadge = document.getElementById("risk-badge");
    const scoreValue = document.getElementById("score-value");
    const scoreVerdictText = document.getElementById("score-verdict-text");
    const scoreBarFill = document.getElementById("score-bar-fill");
    const metadataGrid = document.getElementById("metadata-grid");
    const indicatorsList = document.getElementById("indicators-list");
    const indicatorsCountPill = document.getElementById("indicators-count-pill");
    const sectionEmbeddedLinks = document.getElementById("section-embedded-links");
    const embeddedLinksList = document.getElementById("embedded-links-list");
    const linksCountPill = document.getElementById("links-count-pill");
    const remediationList = document.getElementById("remediation-list");
    const disclaimerText = document.getElementById("disclaimer-text");
    const advisorySubtext = document.getElementById("advisory-subtext");

    // -------------------------------------------------------------------------
    // Helper: Escape HTML to prevent XSS
    // -------------------------------------------------------------------------
    function escapeHTML(str) {
        if (!str && str !== 0) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // -------------------------------------------------------------------------
    // Alert & Feedback Management
    // -------------------------------------------------------------------------
    function showError(message) {
        errorMessage.textContent = message;
        errorAlert.classList.remove("hidden");
        errorAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    function hideError() {
        errorAlert.classList.add("hidden");
        errorMessage.textContent = "";
    }

    if (btnCloseAlert) {
        btnCloseAlert.addEventListener("click", hideError);
    }

    function setFormLoading(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector(".btn-spinner");
        const btnText = button.querySelector(".btn-text");
        if (isLoading) {
            button.disabled = true;
            if (spinner) spinner.classList.remove("hidden");
        } else {
            button.disabled = false;
            if (spinner) spinner.classList.add("hidden");
        }
    }

    // -------------------------------------------------------------------------
    // Reset & Clear Operations
    // -------------------------------------------------------------------------
    function resetDashboard() {
        // Cancel any pending network fetch requests immediately
        if (activeAbortController) {
            activeAbortController.abort();
            activeAbortController = null;
        }
        currentRequestId++;

        hideError();
        setFormLoading(btnAnalyzeUrl, false);
        setFormLoading(btnAnalyzeEmail, false);

        if (urlInput) urlInput.value = "";
        if (emailSenderInput) emailSenderInput.value = "";
        if (emailBodyInput) emailBodyInput.value = "";
        if (resultsCard) resultsCard.classList.add("hidden");
    }

    if (btnResetUrl) btnResetUrl.addEventListener("click", resetDashboard);
    if (btnResetEmail) btnResetEmail.addEventListener("click", resetDashboard);

    // -------------------------------------------------------------------------
    // Mode & Tab Switching (Synchronized between Navbar and Card Tabs)
    // -------------------------------------------------------------------------
    function switchMode(targetMode) {
        activeMode = targetMode;
        hideError();

        if (targetMode === "url") {
            // Navbar state
            if (navBtnUrl) navBtnUrl.classList.add("active");
            if (navBtnEmail) navBtnEmail.classList.remove("active");

            // Scanner card tab state
            if (tabUrlBtn) {
                tabUrlBtn.classList.add("active");
                tabUrlBtn.setAttribute("aria-selected", "true");
                tabUrlBtn.tabIndex = 0;
            }
            if (tabEmailBtn) {
                tabEmailBtn.classList.remove("active");
                tabEmailBtn.setAttribute("aria-selected", "false");
                tabEmailBtn.tabIndex = -1;
            }

            // Panel visibility
            if (panelUrl) {
                panelUrl.classList.remove("hidden");
                panelUrl.classList.add("active");
            }
            if (panelEmail) {
                panelEmail.classList.add("hidden");
                panelEmail.classList.remove("active");
            }

            if (urlInput) urlInput.focus();
        } else {
            // Navbar state
            if (navBtnEmail) navBtnEmail.classList.add("active");
            if (navBtnUrl) navBtnUrl.classList.remove("active");

            // Scanner card tab state
            if (tabEmailBtn) {
                tabEmailBtn.classList.add("active");
                tabEmailBtn.setAttribute("aria-selected", "true");
                tabEmailBtn.tabIndex = 0;
            }
            if (tabUrlBtn) {
                tabUrlBtn.classList.remove("active");
                tabUrlBtn.setAttribute("aria-selected", "false");
                tabUrlBtn.tabIndex = -1;
            }

            // Panel visibility
            if (panelEmail) {
                panelEmail.classList.remove("hidden");
                panelEmail.classList.add("active");
            }
            if (panelUrl) {
                panelUrl.classList.add("hidden");
                panelUrl.classList.remove("active");
            }

            if (emailBodyInput) emailBodyInput.focus();
        }
    }

    // Attach Tab listeners
    if (tabUrlBtn) tabUrlBtn.addEventListener("click", () => switchMode("url"));
    if (tabEmailBtn) tabEmailBtn.addEventListener("click", () => switchMode("email"));

    // Attach Navbar listeners
    if (navBtnUrl) navBtnUrl.addEventListener("click", () => switchMode("url"));
    if (navBtnEmail) navBtnEmail.addEventListener("click", () => switchMode("email"));

    // -------------------------------------------------------------------------
    // API Submission Handlers (Race-condition protected with sequence tracking)
    // -------------------------------------------------------------------------
    if (urlForm) {
        urlForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideError();

            const rawUrl = urlInput.value.trim();
            if (!rawUrl) {
                showError("Please enter a valid URL or IP address to inspect.");
                urlInput.focus();
                return;
            }

            // Abort prior in-flight request if user submits again
            if (activeAbortController) {
                activeAbortController.abort();
            }
            activeAbortController = new AbortController();
            const thisRequestId = ++currentRequestId;

            // Instantly clear stale results while evaluating new target
            if (resultsCard) resultsCard.classList.add("hidden");
            setFormLoading(btnAnalyzeUrl, true);

            try {
                const resp = await fetch("/api/analyze-url", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: rawUrl }),
                    cache: "no-store",
                    signal: activeAbortController.signal
                });

                // Ignore response if a newer submission or reset was triggered
                if (thisRequestId !== currentRequestId) return;

                const data = await resp.json();
                if (!resp.ok || !data.is_valid) {
                    showError(data.error || "The URL could not be parsed or analyzed.");
                } else {
                    renderResults("url", data);
                }
            } catch (err) {
                if (err.name === "AbortError") {
                    // Suppress abort errors from cancelled obsolete requests
                    return;
                }
                if (thisRequestId === currentRequestId) {
                    showError("Network connection error while contacting local analyzer API: " + err.message);
                }
            } finally {
                if (thisRequestId === currentRequestId) {
                    setFormLoading(btnAnalyzeUrl, false);
                }
            }
        });
    }

    if (emailForm) {
        emailForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideError();

            const bodyText = emailBodyInput.value.trim();
            const senderText = emailSenderInput.value.trim();

            if (!bodyText) {
                showError("Please enter or paste email message text to inspect.");
                emailBodyInput.focus();
                return;
            }

            // Abort prior in-flight request
            if (activeAbortController) {
                activeAbortController.abort();
            }
            activeAbortController = new AbortController();
            const thisRequestId = ++currentRequestId;

            // Clear stale results while evaluating
            if (resultsCard) resultsCard.classList.add("hidden");
            setFormLoading(btnAnalyzeEmail, true);

            try {
                const resp = await fetch("/api/analyze-email", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        email_body: bodyText,
                        sender: senderText || null
                    }),
                    cache: "no-store",
                    signal: activeAbortController.signal
                });

                // Ignore response if request has been superseded
                if (thisRequestId !== currentRequestId) return;

                const data = await resp.json();
                if (!resp.ok || !data.is_valid) {
                    showError(data.error || "The email content could not be analyzed.");
                } else {
                    renderResults("email", data);
                }
            } catch (err) {
                if (err.name === "AbortError") {
                    return;
                }
                if (thisRequestId === currentRequestId) {
                    showError("Network connection error while contacting local analyzer API: " + err.message);
                }
            } finally {
                if (thisRequestId === currentRequestId) {
                    setFormLoading(btnAnalyzeEmail, false);
                }
            }
        });
    }

    // -------------------------------------------------------------------------
    // Render Results Dashboard
    // -------------------------------------------------------------------------
    function renderResults(mode, data) {
        if (!resultsCard) return;
        resultsCard.classList.remove("hidden");

        const scoring = data.scoring || {};
        const score = typeof scoring.score === "number" ? scoring.score : 0;
        const categoryRaw = scoring.category || scoring.tier || "No Obvious Threat Detected";
        const hexColor = scoring.hex_color || "#10b981";

        // Determine Category Label & Badge Class
        let categoryText = "NO OBVIOUS THREAT DETECTED";
        let categoryClass = "badge-clean";

        const upperCategory = categoryRaw.toUpperCase();
        if (upperCategory.includes("HIGH") || score >= 60) {
            categoryText = "HIGH RISK";
            categoryClass = "badge-danger";
        } else if (upperCategory.includes("SUSPICIOUS") || upperCategory.includes("MEDIUM") || score >= 25) {
            categoryText = "SUSPICIOUS";
            categoryClass = "badge-warning";
        } else {
            categoryText = "NO OBVIOUS THREAT DETECTED";
            categoryClass = "badge-clean";
        }

        // Title & Category Badge
        if (resultsSummaryTitle) {
            resultsSummaryTitle.textContent = mode === "url" 
                ? "URL Static Risk Assessment" 
                : "Email Lure Risk Assessment";
        }

        if (riskBadge) {
            riskBadge.textContent = categoryText;
            riskBadge.className = `risk-category-badge ${categoryClass}`;
        }

        // Score Meter & Narrative
        if (scoreValue) scoreValue.textContent = score;
        if (scoreVerdictText) scoreVerdictText.textContent = scoring.verdict || "";
        if (scoreBarFill) {
            scoreBarFill.style.width = `${score}%`;
            scoreBarFill.style.backgroundColor = hexColor;
        }

        // Render Assessment Reasons & Metadata Breakdown
        renderMetadata(mode, data.parsed_components || {});

        // Render Detected Suspicious Indicators
        const indicators = scoring.deduplicated_indicators || [];
        renderIndicators(indicators);

        // Render Discovered Embedded Links (Email Mode Only)
        if (mode === "email" && data.extracted_urls && data.extracted_urls.length > 0) {
            if (sectionEmbeddedLinks) sectionEmbeddedLinks.classList.remove("hidden");
            renderEmbeddedLinks(data.extracted_urls);
        } else {
            if (sectionEmbeddedLinks) sectionEmbeddedLinks.classList.add("hidden");
            if (embeddedLinksList) embeddedLinksList.innerHTML = "";
        }

        // Render Recommended Next Steps
        renderRemediation(scoring.remediations || []);

        // Disclaimers & Advisory
        if (disclaimerText) {
            disclaimerText.textContent = scoring.disclaimer || 
                "This score is generated using heuristic rule-based detection for awareness and educational screening. It does not provide definitive threat attribution or prove an artifact is completely safe.";
        }
        if (advisorySubtext) {
            advisorySubtext.textContent = data.advisory_notice || 
                "Heuristic algorithms evaluate lexical and structural patterns offline. Always verify with your security department.";
        }

        // Smooth Scroll to Results
        resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // -------------------------------------------------------------------------
    // Render Assessment Reasons & Metadata Breakdown
    // -------------------------------------------------------------------------
    function renderMetadata(mode, meta) {
        if (!metadataGrid) return;
        metadataGrid.innerHTML = "";
        let items = [];

        if (mode === "url") {
            items = [
                { label: "Scheme / Protocol", value: meta.scheme ? `${meta.scheme.toUpperCase()}://` : "None" },
                { label: "Host Address", value: meta.host || "None" },
                { label: "Registered Domain", value: meta.registered_domain || "None" },
                { label: "Service Port", value: meta.port ? `:${meta.port}` : "Standard Default (80/443)" },
                { label: "Subdomain Count", value: meta.subdomains && meta.subdomains.length ? `${meta.subdomains.length} (${meta.subdomains.join(".")})` : "0 (Direct Domain)" },
                { label: "Resource Path", value: meta.path || "/" }
            ];
        } else {
            const sender = meta.sender || {};
            items = [
                { label: "Sender Display Name", value: sender.display_name || "Unspecified / Not Provided" },
                { label: "Sender Email Address", value: sender.email_address || "Unspecified" },
                { label: "Sender Domain", value: sender.domain || "Unspecified" },
                { label: "Message Length", value: `${meta.body_length_chars || 0} characters` },
                { label: "Total Line Count", value: `${meta.line_count || 0} lines` },
                { label: "Discovered Links", value: `${meta.url_count || 0} embedded URL(s)` }
            ];
        }

        items.forEach(item => {
            const div = document.createElement("div");
            div.className = "metadata-item";
            div.innerHTML = `
                <div class="metadata-label">${escapeHTML(item.label)}</div>
                <div class="metadata-value">${escapeHTML(item.value)}</div>
            `;
            metadataGrid.appendChild(div);
        });
    }

    // -------------------------------------------------------------------------
    // Render Indicators List
    // -------------------------------------------------------------------------
    function renderIndicators(indicators) {
        if (!indicatorsList) return;
        indicatorsList.innerHTML = "";

        if (indicatorsCountPill) {
            indicatorsCountPill.textContent = `${indicators.length} detected`;
        }

        if (indicators.length === 0) {
            indicatorsList.innerHTML = `
                <div class="indicator-card severity-low">
                    <div class="indicator-top">
                        <span class="indicator-title">No Suspicious Indicators Flagged</span>
                        <span class="severity-pill low">CLEAN</span>
                    </div>
                    <p class="indicator-desc">No heuristic threat triggers matched during static rule evaluation.</p>
                </div>
            `;
            return;
        }

        indicators.forEach(ind => {
            const card = document.createElement("div");
            const severityLower = (ind.severity || "low").toLowerCase();
            card.className = `indicator-card severity-${severityLower}`;

            card.innerHTML = `
                <div class="indicator-top">
                    <span class="indicator-title">${escapeHTML(ind.title || "Risk Trigger")}</span>
                    <span class="severity-pill ${severityLower}">${escapeHTML(ind.severity || "LOW")}</span>
                </div>
                <p class="indicator-desc">${escapeHTML(ind.description || "")}</p>
                ${ind.evidence ? `<div class="indicator-evidence"><strong>Evidence:</strong> ${escapeHTML(ind.evidence)}</div>` : ""}
            `;
            indicatorsList.appendChild(card);
        });
    }

    // -------------------------------------------------------------------------
    // Render Embedded Hyperlinks (Email Mode)
    // -------------------------------------------------------------------------
    function renderEmbeddedLinks(links) {
        if (!embeddedLinksList) return;
        embeddedLinksList.innerHTML = "";

        if (linksCountPill) {
            linksCountPill.textContent = `${links.length} links`;
        }

        links.forEach(item => {
            const row = document.createElement("div");
            row.className = "embedded-link-row";

            const count = item.indicators_count || 0;
            const badgeClass = count > 0 ? "critical" : "low";
            const badgeText = count > 0 ? `${count} Triggers Flagged` : "Clean Pattern";

            row.innerHTML = `
                <span class="embedded-link-url">${escapeHTML(item.url)}</span>
                <span class="severity-pill ${badgeClass}">${badgeText}</span>
            `;
            embeddedLinksList.appendChild(row);
        });
    }

    // -------------------------------------------------------------------------
    // Render Recommended Next Steps
    // -------------------------------------------------------------------------
    function renderRemediation(remediations) {
        if (!remediationList) return;
        remediationList.innerHTML = "";

        if (remediations.length === 0) {
            remediationList.innerHTML = `
                <li class="remediation-step">
                    <span class="step-marker">&#10004;</span>
                    <span>No specific mitigations required. Continue observing standard cyber hygiene.</span>
                </li>
            `;
            return;
        }

        remediations.forEach(rec => {
            const li = document.createElement("li");
            li.className = "remediation-step";
            li.innerHTML = `
                <span class="step-marker">&#10004;</span>
                <span>${escapeHTML(rec)}</span>
            `;
            remediationList.appendChild(li);
        });
    }
});
