/* CloudGuardAI - Enterprise Application Controller
   Connects the coastal frontend to real backend REST APIs.
   Features real progress events, asynchronous polling, zero mock data,
   and clean error handling.
*/

document.addEventListener("DOMContentLoaded", () => {
  // --- STATE ---
  let activeScan = null;
  let allFindings = [];
  let selectedFile = null;

  // --- DOM REFERENCES ---
  const navItems = document.querySelectorAll(".nav-item");
  const viewSections = document.querySelectorAll(".view-section");
  const awsHeaderStatus = document.getElementById("awsHeaderStatus");
  const storageStatusText = document.getElementById("storageStatusText");
  const refreshStatusBtn = document.getElementById("refreshStatusBtn");

  // Global Metrics
  const metricTotalScans = document.getElementById("metricTotalScans");
  const metricAvgScore = document.getElementById("metricAvgScore");
  const metricTotalCritical = document.getElementById("metricTotalCritical");
  const metricTotalHigh = document.getElementById("metricTotalHigh");

  // Ingestion / Upload View
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const selectedFilePane = document.getElementById("selectedFilePane");
  const selectedFileName = document.getElementById("selectedFileName");
  const selectedFileSize = document.getElementById("selectedFileSize");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const progressContainer = document.getElementById("progressContainer");
  const progressBar = document.getElementById("progressBar");
  const progressPercent = document.getElementById("progressPercent");
  const progressText = document.getElementById("progressText");
  const uploadStatusBox = document.getElementById("uploadStatusBox");

  // Dashboard View
  const dashTargetSubtitle = document.getElementById("dashTargetSubtitle");
  const dashOverallScore = document.getElementById("dashOverallScore");
  const dashGradeBadge = document.getElementById("dashGradeBadge");
  const dashScanId = document.getElementById("dashScanId");
  const dashTargetName = document.getElementById("dashTargetName");
  const dashStorageType = document.getElementById("dashStorageType");
  const dashUnsupportedBox = document.getElementById("dashUnsupportedBox");
  const dimensionBarsContainer = document.getElementById("dimensionBarsContainer");
  const dashCountCritical = document.getElementById("dashCountCritical");
  const dashCountHigh = document.getElementById("dashCountHigh");
  const dashCountMedium = document.getElementById("dashCountMedium");
  const dashCountLow = document.getElementById("dashCountLow");
  const dashExportMdBtn = document.getElementById("dashExportMdBtn");
  const dashExportJsonBtn = document.getElementById("dashExportJsonBtn");
  const dashExportHtmlBtn = document.getElementById("dashExportHtmlBtn");

  // Findings View
  const findingsCountBadge = document.getElementById("findingsCountBadge");
  const findingSearchInput = document.getElementById("findingSearchInput");
  const findingDimensionFilter = document.getElementById("findingDimensionFilter");
  const findingSeverityFilter = document.getElementById("findingSeverityFilter");
  const findingsTableBody = document.getElementById("findingsTableBody");

  // Detail Drawer
  let currentDrawerFinding = null;
  const drawerBackdrop = document.getElementById("drawerBackdrop");
  const findingDrawer = document.getElementById("findingDrawer");
  const closeDrawerBtn = document.getElementById("closeDrawerBtn");
  const drawerSeverityTag = document.getElementById("drawerSeverityTag");
  const drawerRuleId = document.getElementById("drawerRuleId");
  const drawerTitle = document.getElementById("drawerTitle");
  const drawerResourceInfo = document.getElementById("drawerResourceInfo");
  const drawerEvidenceBlock = document.getElementById("drawerEvidenceBlock");
  const drawerDescription = document.getElementById("drawerDescription");
  const drawerImpact = document.getElementById("drawerImpact");
  const drawerRemediationSummary = document.getElementById("drawerRemediationSummary");
  const drawerCodeContainer = document.getElementById("drawerCodeContainer");
  const drawerCodeBlock = document.getElementById("drawerCodeBlock");
  const copyCodeBtn = document.getElementById("copyCodeBtn");
  const drawerCliContainer = document.getElementById("drawerCliContainer");
  const drawerCliBlock = document.getElementById("drawerCliBlock");
  const copyCliBtn = document.getElementById("copyCliBtn");
  const triggerAiRemediationBtn = document.getElementById("triggerAiRemediationBtn");
  const drawerAiStatus = document.getElementById("drawerAiStatus");
  const drawerAiBlock = document.getElementById("drawerAiBlock");

  // Live AWS Audit View
  const liveAwsIdentityDetails = document.getElementById("liveAwsIdentityDetails");
  const triggerLiveAuditBtn = document.getElementById("triggerLiveAuditBtn");
  const liveAuditStatusBox = document.getElementById("liveAuditStatusBox");

  // History View
  const historyTableBody = document.getElementById("historyTableBody");
  const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");

  // --- NAVIGATION ---
  navItems.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetView = btn.getAttribute("data-view");
      switchView(targetView);
    });
  });

  function switchView(viewId) {
    navItems.forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-view") === viewId);
    });
    viewSections.forEach(v => {
      v.classList.toggle("active", v.id === viewId);
    });

    if (viewId === "view-history") {
      fetchHistory();
    } else if (viewId === "view-live") {
      refreshLiveIdentity();
    }
  }

  // --- HEALTH & METRICS ---
  async function loadHealthAndMetrics() {
    try {
      const healthRes = await fetch("/api/v1/health");
      if (healthRes.ok) {
        const h = await healthRes.json();
        const aws = h.aws || {};
        if (aws.authenticated) {
          const mode = aws.is_lab_role ? "AWS Connected (LabRole)" : "AWS Connected";
          awsHeaderStatus.innerHTML = `<span class="status-indicator-dot verified"></span> <span>${mode}</span>`;
          awsHeaderStatus.style.color = "var(--color-primary)";
        } else if (aws.status === "EXPIRED_CREDENTIALS") {
          awsHeaderStatus.innerHTML = `<span class="status-indicator-dot warning"></span> <span>AWS Session Expired</span>`;
          awsHeaderStatus.style.color = "var(--color-critical)";
        } else if (aws.status === "MISSING_SESSION_TOKEN") {
          awsHeaderStatus.innerHTML = `<span class="status-indicator-dot warning"></span> <span>AWS Token Missing</span>`;
          awsHeaderStatus.style.color = "var(--color-critical)";
        } else {
          awsHeaderStatus.innerHTML = `<span class="status-indicator-dot"></span> <span>Local Resilient Storage Active</span>`;
          awsHeaderStatus.style.color = "var(--color-text-secondary)";
        }
      }

      const storageRes = await fetch("/api/v1/storage/status");
      if (storageRes.ok) {
        const s = await storageRes.json();
        const s3 = s.s3_health || {};
        if (s.active_backend === "s3" && s3.accessible) {
          storageStatusText.innerHTML = `<strong>Amazon S3 Connected:</strong> Bucket <code>${s3.bucket}</code> (${s3.region}). Server-side AES256 encryption active.`;
        } else if (s3.configured && !s3.accessible) {
          storageStatusText.innerHTML = `<strong>Amazon S3 Notice:</strong> Bucket <code>${s3.bucket}</code> configured but inaccessible (${s3.error_code || 'Offline'}). Falling back to Local Resilient Storage.`;
        } else {
          storageStatusText.innerHTML = `<strong>Local Resilient Storage Active:</strong> Blueprints stored safely under <code>${s.local_storage_path}</code>.`;
        }
      }

      const metricRes = await fetch("/api/v1/scan/metrics/summary");
      if (metricRes.ok) {
        const m = await metricRes.json();
        metricTotalScans.textContent = m.total_scans;
        metricAvgScore.textContent = m.average_risk_score;
        metricTotalCritical.textContent = m.total_critical;
        metricTotalHigh.textContent = m.total_high;
      }
    } catch (e) {
      console.warn("Telemetry loading error:", e);
    }
  }

  refreshStatusBtn.addEventListener("click", loadHealthAndMetrics);
  loadHealthAndMetrics();

  // --- UPLOAD & INGESTION ---
  function formatBytes(bytes) {
    if (!bytes) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  ["dragenter", "dragover"].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleSelectedFile(e.target.files[0]);
    }
  });

  function handleSelectedFile(file) {
    selectedFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = `(${formatBytes(file.size)})`;
    selectedFilePane.style.display = "flex";
    uploadStatusBox.style.display = "none";
  }

  analyzeBtn.addEventListener("click", () => {
    if (!selectedFile) return;

    analyzeBtn.disabled = true;
    progressContainer.style.display = "block";
    progressBar.style.width = "0%";
    progressPercent.textContent = "0%";
    progressText.textContent = "Uploading template and evaluating 7-dimension rules...";
    uploadStatusBox.style.display = "none";

    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("template_type", "auto");

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/scan/upload", true);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 60);
        progressBar.style.width = pct + "%";
        progressPercent.textContent = pct + "%";
      }
    };

    xhr.onload = () => {
      analyzeBtn.disabled = false;
      progressBar.style.width = "100%";
      progressPercent.textContent = "100%";

      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const res = JSON.parse(xhr.responseText);
          const scan = res.data;
          
          uploadStatusBox.className = "status-box success";
          uploadStatusBox.innerHTML = `<strong>Analysis Complete:</strong> Assessed <code>${scan.target_name}</code> with Risk Score <strong>${scan.overall_risk_score}</strong> (Grade ${scan.risk_grade}). Found ${scan.total_findings} issues. <button type="button" class="btn btn-secondary" id="viewDashQuickBtn" style="padding: 2px 8px; margin-left: 8px;">View Dashboard</button>`;
          uploadStatusBox.style.display = "block";

          document.getElementById("viewDashQuickBtn").addEventListener("click", () => {
            loadScanIntoDashboard(scan);
            switchView("view-dashboard");
          });

          loadScanIntoDashboard(scan);
          loadHealthAndMetrics();
        } catch (err) {
          showUploadError("Failed to parse analysis results.");
        }
      } else {
        let msg = "Analysis failed.";
        try {
          const err = JSON.parse(xhr.responseText);
          msg = err.detail || msg;
        } catch (_) {}
        showUploadError(msg);
      }
    };

    xhr.onerror = () => {
      analyzeBtn.disabled = false;
      progressContainer.style.display = "none";
      showUploadError("Network connection error to backend analysis server.");
    };

    xhr.send(formData);
  });

  function showUploadError(msg) {
    uploadStatusBox.className = "status-box error";
    uploadStatusBox.textContent = `Error: ${msg}`;
    uploadStatusBox.style.display = "block";
  }

  // --- DASHBOARD RENDERING ---
  function loadScanIntoDashboard(scan) {
    activeScan = scan;
    allFindings = scan.findings || [];

    dashTargetSubtitle.textContent = `Target: ${scan.target_name} | Evaluated: ${scan.created_at.slice(0, 19).replace('T', ' ')} UTC`;
    dashOverallScore.textContent = scan.overall_risk_score;
    dashGradeBadge.textContent = `Grade ${scan.risk_grade}`;
    dashScanId.textContent = scan.scan_id;
    dashTargetName.textContent = scan.target_name;
    dashStorageType.textContent = scan.scan_type === "LIVE_AWS" ? "LIVE AWS DISCOVERY" : scan.storage_backend.toUpperCase();
    if (scan.scan_type === "LIVE_AWS") {
      dashTargetSubtitle.innerHTML = `<span class="severity-tag MEDIUM" style="margin-right: 6px;">Live AWS Audit</span> Target: <code>${scan.target_name}</code> | Scanned: ${scan.created_at.slice(0, 19).replace('T', ' ')} UTC`;
    } else {
      dashTargetSubtitle.innerHTML = `<span class="severity-tag LOW" style="margin-right: 6px;">Static IaC Blueprint</span> Target: <code>${scan.target_name}</code> | Scanned: ${scan.created_at.slice(0, 19).replace('T', ' ')} UTC`;
    }

    // Check for unsupported constructs notice
    if (scan.unsupported_constructs && scan.unsupported_constructs.length > 0) {
      let unHtml = `<strong>Parser Notice:</strong> ${scan.unsupported_constructs.length} construct(s) skipped (e.g. third-party external module references). Evaluated static resources directly.`;
      dashUnsupportedBox.innerHTML = unHtml;
      dashUnsupportedBox.style.display = "block";
    } else {
      dashUnsupportedBox.style.display = "none";
    }

    // Severity distribution
    dashCountCritical.textContent = scan.critical_count;
    dashCountHigh.textContent = scan.high_count;
    dashCountMedium.textContent = scan.medium_count;
    dashCountLow.textContent = scan.low_count;

    // Report Links
    dashExportMdBtn.href = `/api/v1/scan/${scan.scan_id}/report?format=markdown`;
    dashExportJsonBtn.href = `/api/v1/scan/${scan.scan_id}/report?format=json`;
    dashExportHtmlBtn.href = `/api/v1/scan/${scan.scan_id}/report?format=html`;

    // Render Dimension Subtotals
    const dims = [
      { key: "security", label: "Security" },
      { key: "iam", label: "IAM" },
      { key: "network", label: "Network" },
      { key: "configuration", label: "Configuration" },
      { key: "reliability", label: "Reliability" },
      { key: "performance", label: "Performance" },
      { key: "cost", label: "Cost" }
    ];

    let dimHtml = "";
    dims.forEach(d => {
      const score = (scan.dimension_scores && scan.dimension_scores[d.key]) || 0;
      dimHtml += `
        <div class="dimension-item">
          <div class="dimension-header">
            <span class="dimension-name">${d.label}</span>
            <span class="dimension-score-val">${score} / 100</span>
          </div>
          <div class="dimension-bar-track">
            <div class="dimension-bar-fill" style="width: ${Math.min(100, score)}%;"></div>
          </div>
        </div>
      `;
    });
    dimensionBarsContainer.innerHTML = dimHtml;

    // Render findings
    renderFindingsTable(allFindings);
  }

  // --- FINDINGS PANEL & FILTERS ---
  function renderFindingsTable(findings) {
    findingsCountBadge.textContent = `${findings.length} findings displayed`;

    if (!findings || findings.length === 0) {
      if (activeScan && activeScan.overall_risk_score === 0) {
        findingsTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--color-low); padding: 24px; font-weight: 500;">✓ Clean Architecture: No security or compliance risks detected across all 7 Well-Architected dimensions (Risk Score 0.0, Grade A).</td></tr>`;
      } else {
        findingsTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--color-text-muted); padding: 24px;">No findings match the current criteria.</td></tr>`;
      }
      return;
    }

    let rows = "";
    findings.forEach(f => {
      rows += `
        <tr>
          <td><span class="severity-tag ${f.severity}">${f.severity}</span></td>
          <td><code style="font-size: 11.5px; padding: 2px 6px; background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: 3px;">${f.rule_id}</code></td>
          <td style="font-weight: 600; color: var(--color-text-main);">${f.title}</td>
          <td><code style="font-size: 11px; color: var(--color-text-secondary);">${f.resource_id}</code></td>
          <td><span style="font-size: 12px; font-weight: 500; color: var(--color-text-secondary);">${f.dimension}</span></td>
          <td style="text-align: center;">
            <button type="button" class="btn btn-secondary inspect-btn" data-id="${f.finding_id}" style="padding: 3px 10px; font-size: 11.5px;">Inspect &rarr;</button>
          </td>
        </tr>
      `;
    });
    findingsTableBody.innerHTML = rows;

    document.querySelectorAll(".inspect-btn").forEach(b => {
      b.addEventListener("click", () => {
        const id = b.getAttribute("data-id");
        const found = allFindings.find(item => item.finding_id === id);
        if (found) openFindingDrawer(found);
      });
    });
  }

  function filterFindings() {
    const query = findingSearchInput.value.toLowerCase().trim();
    const dim = findingDimensionFilter.value;
    const sev = findingSeverityFilter.value;

    const filtered = allFindings.filter(f => {
      const matchQuery = !query || f.title.toLowerCase().includes(query) || f.rule_id.toLowerCase().includes(query) || f.resource_id.toLowerCase().includes(query);
      const matchDim = (dim === "ALL") || (f.dimension.toUpperCase() === dim);
      const matchSev = (sev === "ALL") || (f.severity.toUpperCase() === sev);
      return matchQuery && matchDim && matchSev;
    });

    renderFindingsTable(filtered);
  }

  findingSearchInput.addEventListener("input", filterFindings);
  findingDimensionFilter.addEventListener("change", filterFindings);
  findingSeverityFilter.addEventListener("change", filterFindings);

  // --- DETAIL DRAWER ---
  function openFindingDrawer(f) {
    currentDrawerFinding = f;
    drawerSeverityTag.className = `severity-tag ${f.severity}`;
    drawerSeverityTag.textContent = f.severity;
    drawerRuleId.textContent = f.rule_id;
    drawerTitle.textContent = f.title;
    drawerResourceInfo.textContent = `Target Resource: ${f.resource_id} (${f.resource_type})`;
    
    // Display structured evidence
    drawerEvidenceBlock.textContent = JSON.stringify(f.evidence || {}, null, 2);

    drawerDescription.textContent = f.description;
    drawerImpact.textContent = f.impact;
    drawerRemediationSummary.textContent = f.remediation_summary;

    if (f.remediation_code) {
      drawerCodeBlock.textContent = f.remediation_code;
      drawerCodeContainer.style.display = "block";
    } else {
      drawerCodeContainer.style.display = "none";
    }

    if (f.cli_command) {
      drawerCliBlock.textContent = f.cli_command;
      drawerCliContainer.style.display = "block";
    } else {
      drawerCliContainer.style.display = "none";
    }

    // AI Remediation Section
    if (f.ai_remediation) {
      drawerAiStatus.style.display = "block";
      drawerAiStatus.textContent = f.remediation_source === "BEDROCK_AI" ? "Source: Amazon Bedrock Foundation Model" : "Source: Deterministic Rule Baseline";
      drawerAiBlock.textContent = f.ai_remediation;
      drawerAiBlock.style.display = "block";
      triggerAiRemediationBtn.textContent = "Re-synthesize";
    } else {
      drawerAiStatus.style.display = "none";
      drawerAiBlock.style.display = "none";
      drawerAiBlock.textContent = "";
      triggerAiRemediationBtn.textContent = "Synthesize Plan";
    }

    drawerBackdrop.style.display = "block";
    findingDrawer.classList.add("open");
  }

  function closeFindingDrawer() {
    findingDrawer.classList.remove("open");
    drawerBackdrop.style.display = "none";
    currentDrawerFinding = null;
  }

  closeDrawerBtn.addEventListener("click", closeFindingDrawer);
  drawerBackdrop.addEventListener("click", closeFindingDrawer);

  copyCodeBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(drawerCodeBlock.textContent);
    copyCodeBtn.textContent = "Copied!";
    setTimeout(() => { copyCodeBtn.textContent = "Copy Code"; }, 1500);
  });

  copyCliBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(drawerCliBlock.textContent);
    copyCliBtn.textContent = "Copied!";
    setTimeout(() => { copyCliBtn.textContent = "Copy Command"; }, 1500);
  });

  triggerAiRemediationBtn.addEventListener("click", async () => {
    if (!currentDrawerFinding) return;
    const scanId = (activeScan && activeScan.scan_id) || currentDrawerFinding.scan_id;
    if (!scanId) {
      alert("No active scan associated with this finding.");
      return;
    }

    triggerAiRemediationBtn.disabled = true;
    triggerAiRemediationBtn.textContent = "Contacting Bedrock...";
    drawerAiStatus.style.display = "block";
    drawerAiStatus.textContent = "Invoking Amazon Bedrock foundation model...";

    try {
      const res = await fetch(`/api/v1/scan/${scanId}/findings/${currentDrawerFinding.finding_id}/ai-remediation`, {
        method: "POST"
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.detail || "Bedrock remediation synthesis failed.");
      }

      const rem = data.remediation;
      currentDrawerFinding.ai_remediation = rem.content;
      currentDrawerFinding.remediation_source = rem.source;

      drawerAiBlock.textContent = rem.content;
      drawerAiBlock.style.display = "block";
      drawerAiStatus.textContent = rem.source === "BEDROCK_AI"
        ? `Synthesized by Amazon Bedrock (${rem.model_id})`
        : `Fallback applied: ${rem.reason || 'Deterministic Rule Baseline'}`;
      triggerAiRemediationBtn.textContent = "Re-synthesize";
    } catch (err) {
      drawerAiStatus.textContent = `Bedrock error: ${err.message}`;
    } finally {
      triggerAiRemediationBtn.disabled = false;
    }
  });

  // --- LIVE AWS AUDIT ---
  async function refreshLiveIdentity(force = false) {
    try {
      const endpoint = force ? "/api/v1/aws/status?refresh=true" : "/api/v1/aws/status";
      const res = await fetch(endpoint);
      const aws = await res.json();

      if (aws.authenticated) {
        liveAwsIdentityDetails.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="badge" style="background: rgba(40,127,163,0.12); color: var(--color-primary); border: 1px solid var(--color-primary); padding: 2px 8px; border-radius: 3px; font-weight: 600;">CONFIGURED & VERIFIED</span>
            <span style="color: var(--color-text-muted); font-size: 12px;">Provider: <strong>${aws.provider_type || 'AWS SDK'}</strong></span>
          </div>
          <div><strong>Authenticated Caller ARN:</strong> <code>${aws.arn}</code></div>
          <div><strong>Account ID:</strong> <code>${aws.account_id}</code> | <strong>Region:</strong> <code>${aws.region}</code></div>
          <div><strong>Permission Mode:</strong> ${aws.is_lab_role ? "AWS Academy Learner Lab (LabRole active)" : "Standard IAM User / Role"}</div>
          <p style="margin-top: 8px; color: var(--color-text-muted);">CloudGuardAI performs strictly read-only Describe / List operations without creating or modifying AWS resources.</p>
        `;
        triggerLiveAuditBtn.disabled = false;
      } else if (aws.status === "EXPIRED_CREDENTIALS") {
        liveAwsIdentityDetails.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="badge" style="background: rgba(184,51,42,0.12); color: var(--color-critical); border: 1px solid var(--color-critical); padding: 2px 8px; border-radius: 3px; font-weight: 600;">CREDENTIALS EXPIRED</span>
            <span style="color: var(--color-critical); font-size: 12px;">${aws.error_code}</span>
          </div>
          <div style="color: var(--color-critical); font-weight: 600; margin-bottom: 4px;">AWS Academy Learner Lab Session Has Expired</div>
          <p style="margin-top: 4px; color: var(--color-text-main); font-size: 13px;">${aws.actionable_guidance}</p>
          <div style="background: #202A30; color: #F3F1EB; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin-top: 8px; overflow-x: auto;">
            # Copy new credentials from AWS Details modal into your server terminal:<br>
            $env:AWS_ACCESS_KEY_ID="&lt;your-access-key-id&gt;"<br>
            $env:AWS_SECRET_ACCESS_KEY="&lt;your-secret-access-key&gt;"<br>
            $env:AWS_SESSION_TOKEN="&lt;your-session-token&gt;"<br>
            $env:AWS_DEFAULT_REGION="us-east-1"
          </div>
        `;
        triggerLiveAuditBtn.disabled = true;
      } else if (aws.status === "MISSING_SESSION_TOKEN") {
        liveAwsIdentityDetails.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="badge" style="background: rgba(184,51,42,0.12); color: var(--color-critical); border: 1px solid var(--color-critical); padding: 2px 8px; border-radius: 3px; font-weight: 600;">SESSION TOKEN REQUIRED</span>
          </div>
          <div style="color: var(--color-critical); font-weight: 600; margin-bottom: 4px;">Temporary AWS Credentials Detected Without Session Token</div>
          <p style="margin-top: 4px; color: var(--color-text-main); font-size: 13px;">${aws.actionable_guidance}</p>
          <div style="background: #202A30; color: #F3F1EB; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin-top: 8px; overflow-x: auto;">
            $env:AWS_SESSION_TOKEN="&lt;paste-session-token-from-aws-details&gt;"
          </div>
        `;
        triggerLiveAuditBtn.disabled = true;
      } else if (aws.status === "PERMISSION_DENIED") {
        liveAwsIdentityDetails.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="badge" style="background: rgba(184,51,42,0.12); color: var(--color-critical); border: 1px solid var(--color-critical); padding: 2px 8px; border-radius: 3px; font-weight: 600;">PERMISSION DENIED</span>
          </div>
          <div style="color: var(--color-critical); font-weight: 600; margin-bottom: 4px;">STS GetCallerIdentity Denied</div>
          <p style="margin-top: 4px; color: var(--color-text-main); font-size: 13px;">${aws.actionable_guidance}</p>
        `;
        triggerLiveAuditBtn.disabled = true;
      } else if (aws.status === "CONNECTION_ERROR") {
        liveAwsIdentityDetails.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="badge" style="background: rgba(220,201,168,0.3); color: #735930; border: 1px solid #DCC9A8; padding: 2px 8px; border-radius: 3px; font-weight: 600;">ENDPOINT UNREACHABLE</span>
          </div>
          <div style="color: var(--color-text-main); font-weight: 600; margin-bottom: 4px;">AWS STS Endpoint Connectivity Error</div>
          <p style="margin-top: 4px; color: var(--color-text-main); font-size: 13px;">${aws.actionable_guidance}</p>
        `;
        triggerLiveAuditBtn.disabled = true;
      } else {
        liveAwsIdentityDetails.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="badge" style="background: rgba(32,42,48,0.08); color: var(--color-text-muted); border: 1px solid var(--color-border); padding: 2px 8px; border-radius: 3px; font-weight: 600;">NO CREDENTIALS DETECTED</span>
          </div>
          <div style="color: var(--color-text-main); font-weight: 600; margin-bottom: 4px;">Local Resilient Mode Active</div>
          <p style="margin-top: 4px; color: var(--color-text-muted); font-size: 13px;">${aws.actionable_guidance}</p>
          <div style="background: #202A30; color: #F3F1EB; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin-top: 8px; overflow-x: auto;">
            # Option A: In the PowerShell terminal running CloudGuardAI:<br>
            $env:AWS_ACCESS_KEY_ID="&lt;your-key&gt;"<br>
            $env:AWS_SECRET_ACCESS_KEY="&lt;your-secret&gt;"<br>
            $env:AWS_SESSION_TOKEN="&lt;session-token-if-temporary-lab&gt;"<br>
            $env:AWS_DEFAULT_REGION="us-east-1"<br><br>
            # Option B: Or create a .env file in the project folder with these variables.<br>
            # Then click 'Refresh Credentials' below without restarting the server.
          </div>
        `;
        triggerLiveAuditBtn.disabled = true;
      }
    } catch (e) {
      liveAwsIdentityDetails.textContent = "Failed to query STS identity.";
    }
  }

  // Refresh Credentials Button
  const refreshAwsCredentialsBtn = document.getElementById("refreshAwsCredentialsBtn");
  if (refreshAwsCredentialsBtn) {
    refreshAwsCredentialsBtn.addEventListener("click", async () => {
      refreshAwsCredentialsBtn.disabled = true;
      refreshAwsCredentialsBtn.textContent = "Checking...";
      try {
        await fetch("/api/v1/aws/refresh", { method: "POST" });
        await refreshLiveIdentity(true);
        await loadHealthAndMetrics();
      } catch (e) {
        console.error("Failed to refresh AWS credentials", e);
      } finally {
        refreshAwsCredentialsBtn.disabled = false;
        refreshAwsCredentialsBtn.textContent = "Refresh Credentials";
      }
    });
  }

  triggerLiveAuditBtn.addEventListener("click", async () => {
    const regionSelect = document.getElementById("liveRegionSelect");
    const selectedRegion = regionSelect ? regionSelect.value : "us-east-1";

    triggerLiveAuditBtn.disabled = true;
    liveAuditStatusBox.className = "status-box info";
    liveAuditStatusBox.textContent = `Initiating read-only discovery of S3, EC2, VPC, IAM, and RDS in ${selectedRegion}...`;
    liveAuditStatusBox.style.display = "block";

    try {
      const formData = new FormData();
      formData.append("region", selectedRegion);

      const res = await fetch("/api/v1/scan/live", { method: "POST", body: formData });
      const data = await res.json();

      if (res.ok && data.success) {
        const scan = data.data;
        const totalDiscovered = scan.discovered_resources ? scan.discovered_resources.length : 0;
        liveAuditStatusBox.className = "status-box success";
        liveAuditStatusBox.innerHTML = `<strong>Live Discovery Completed:</strong> Audited ${totalDiscovered} resources; detected ${scan.total_findings} security/compliance risks. <button type="button" class="btn btn-secondary" id="viewLiveDashBtn" style="padding: 2px 8px; margin-left: 8px;">View In Assessment Dashboard</button>`;
        
        document.getElementById("viewLiveDashBtn").addEventListener("click", () => {
          loadScanIntoDashboard(scan);
          switchView("view-dashboard");
        });

        // Render Discovered Resources Inventory Table
        const inventoryCard = document.getElementById("liveInventoryCard");
        const inventoryBody = document.getElementById("liveInventoryTableBody");
        const inventoryBadge = document.getElementById("liveInventoryCountBadge");

        if (inventoryCard && inventoryBody) {
          inventoryCard.style.display = "block";
          inventoryBadge.textContent = `${totalDiscovered} live resources inspected`;

          if (scan.discovered_resources && scan.discovered_resources.length > 0) {
            let invRows = "";
            scan.discovered_resources.forEach(r => {
              const statusTag = r.status === "COMPLIANT"
                ? `<span class="severity-tag LOW" style="font-size: 11px;">Compliant</span>`
                : `<span class="severity-tag CRITICAL" style="font-size: 11px;">Risk Detected</span>`;
              invRows += `
                <tr>
                  <td><code style="font-size: 11px;">${r.resource_type}</code></td>
                  <td><strong>${r.resource_name}</strong><br><small style="color: var(--color-text-muted); font-size: 11px;">${r.resource_id}</small></td>
                  <td>${r.region}</td>
                  <td>${statusTag}</td>
                  <td style="text-align: center; font-weight: 600;">${r.findings_count}</td>
                </tr>
              `;
            });
            inventoryBody.innerHTML = invRows;
          } else {
            inventoryBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-text-muted); padding: 18px;">No supported resources found in region ${selectedRegion}.</td></tr>`;
          }
        }

        // Render Limitations Card if boundaries were encountered (e.g. AWS Academy LabRole)
        const limitationsCard = document.getElementById("liveLimitationsCard");
        const limitationsBody = document.getElementById("liveLimitationsBody");
        if (limitationsCard && limitationsBody) {
          const limits = (scan.discovery_summary && scan.discovery_summary.limitations_recorded) || scan.unsupported_constructs || [];
          if (limits.length > 0) {
            let limitHtml = `<p style="margin-bottom: 8px;"><strong>AWS Account Service Boundaries Detected:</strong> The following read-only API calls were restricted by your account permissions boundary or AWS Academy LabRole policy:</p><ul style="padding-left: 20px;">`;
            limits.forEach(l => {
              limitHtml += `<li><strong>${l.service || 'AWS'}</strong> (<code>${l.api || 'API'}</code>): ${l.message}</li>`;
            });
            limitHtml += `</ul><p style="margin-top: 8px; color: var(--color-text-muted);">CloudGuardAI handled these restrictions gracefully and evaluated all remaining accessible services.</p>`;
            limitationsBody.innerHTML = limitHtml;
            limitationsCard.style.display = "block";
          } else {
            limitationsCard.style.display = "none";
          }
        }

        loadScanIntoDashboard(scan);
        loadHealthAndMetrics();
      } else {
        liveAuditStatusBox.className = "status-box error";
        liveAuditStatusBox.textContent = `Audit Failed: ${data.detail || 'Access denied or service failure'}`;
      }
    } catch (e) {
      liveAuditStatusBox.className = "status-box error";
      liveAuditStatusBox.textContent = `Network error during live scan: ${e.message}`;
    } finally {
      triggerLiveAuditBtn.disabled = false;
    }
  });

  // --- HISTORY VIEW ---
  async function fetchHistory() {
    try {
      const res = await fetch("/api/v1/scan/scans?limit=25");
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      const scans = data.scans || [];

      if (scans.length === 0) {
        historyTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--color-text-muted); padding: 24px;">No past scans found. Upload a blueprint to start.</td></tr>`;
        return;
      }

      let rows = "";
      scans.forEach(s => {
        rows += `
          <tr>
            <td style="font-size: 12px; color: var(--color-text-muted);">${s.created_at.slice(0, 19).replace("T", " ")}</td>
            <td style="font-weight: 500;">${s.target_name}</td>
            <td><code style="font-size: 11px;">${s.scan_type}</code></td>
            <td style="font-weight: 700; color: var(--color-primary);">${s.overall_risk_score}</td>
            <td><span class="score-grade" style="padding: 1px 6px; font-size: 11px;">${s.risk_grade}</span></td>
            <td>${s.total_findings} (Crit: ${s.critical_count})</td>
            <td style="text-align: right;">
              <button type="button" class="btn btn-secondary load-history-btn" data-id="${s.scan_id}" style="padding: 2px 8px; font-size: 11px;">Dashboard</button>
              <a href="/api/v1/scan/${s.scan_id}/report?format=html" target="_blank" class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;">Report</a>
              <button type="button" class="btn btn-secondary presigned-s3-history-btn" data-id="${s.scan_id}" style="padding: 2px 8px; font-size: 11px;">S3 Link</button>
            </td>
          </tr>
        `;
      });
      historyTableBody.innerHTML = rows;

      document.querySelectorAll(".load-history-btn").forEach(b => {
        b.addEventListener("click", async () => {
          const scanId = b.getAttribute("data-id");
          const getRes = await fetch(`/api/v1/scan/${scanId}`);
          if (getRes.ok) {
            const scanData = await getRes.json();
            loadScanIntoDashboard(scanData.data);
            switchView("view-dashboard");
          }
        });
      });

      document.querySelectorAll(".presigned-s3-history-btn").forEach(b => {
        b.addEventListener("click", async () => {
          const scanId = b.getAttribute("data-id");
          b.textContent = "...";
          try {
            const res = await fetch(`/api/v1/scan/${scanId}/report/url?format=markdown`);
            const data = await res.json();
            if (res.ok && data.success) {
              await navigator.clipboard.writeText(data.data.download_url);
              b.textContent = "Copied!";
              setTimeout(() => { b.textContent = "S3 Link"; }, 2000);
            } else {
              b.textContent = "Error";
            }
          } catch (e) {
            b.textContent = "Error";
          }
        });
      });

    } catch (e) {
      historyTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--color-critical); padding: 24px;">Failed to fetch history: ${e.message}</td></tr>`;
    }
  }

  // Dashboard Presigned S3 Link
  const dashPresignedS3Btn = document.getElementById("dashPresignedS3Btn");
  if (dashPresignedS3Btn) {
    dashPresignedS3Btn.addEventListener("click", async () => {
      if (!activeScan) {
        alert("Select or run a scan first to generate a presigned report URL.");
        return;
      }
      dashPresignedS3Btn.textContent = "Generating...";
      try {
        const res = await fetch(`/api/v1/scan/${activeScan.scan_id}/report/url?format=markdown`);
        const data = await res.json();
        if (res.ok && data.success) {
          const url = data.data.download_url;
          await navigator.clipboard.writeText(url);
          dashPresignedS3Btn.textContent = "S3 URL Copied (15m)!";
          setTimeout(() => { dashPresignedS3Btn.textContent = "Presigned S3 Link"; }, 2500);
        } else {
          alert("Could not generate presigned report URL: " + (data.detail || "Error"));
          dashPresignedS3Btn.textContent = "Presigned S3 Link";
        }
      } catch (e) {
        alert("Presigned URL error: " + e.message);
        dashPresignedS3Btn.textContent = "Presigned S3 Link";
      }
    });
  }

  refreshHistoryBtn.addEventListener("click", fetchHistory);
});
