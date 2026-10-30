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
  const loadSampleBlueprintBtn = document.getElementById("loadSampleBlueprintBtn");

  // Live Analysis Workspace
  const liveAnalysisWorkspace = document.getElementById("liveAnalysisWorkspace");
  const pipelineStepper = document.getElementById("pipelineStepper");
  const currentStageBadge = document.getElementById("currentStageBadge");
  const skipAnimationBtn = document.getElementById("skipAnimationBtn");
  const liveDiscoveredCount = document.getElementById("liveDiscoveredCount");
  const liveDiscoveredSub = document.getElementById("liveDiscoveredSub");
  const liveInspectionStatus = document.getElementById("liveInspectionStatus");
  const liveInspectionSub = document.getElementById("liveInspectionSub");
  const liveChecksCount = document.getElementById("liveChecksCount");
  const livePassedChecks = document.getElementById("livePassedChecks");
  const liveFailedChecks = document.getElementById("liveFailedChecks");
  const liveFindingsCount = document.getElementById("liveFindingsCount");
  const liveFindingsSub = document.getElementById("liveFindingsSub");
  const liveScoreValue = document.getElementById("liveScoreValue");
  const liveGradeValue = document.getElementById("liveGradeValue");
  const resourceGraphGrid = document.getElementById("resourceGraphGrid");
  const eventStreamList = document.getElementById("eventStreamList");
  const eventCountBadge = document.getElementById("eventCountBadge");
  const pipelineCompletionBar = document.getElementById("pipelineCompletionBar");
  const pcSummaryTitle = document.getElementById("pcSummaryTitle");
  const pcSummaryDetails = document.getElementById("pcSummaryDetails");
  const pcViewFindingsBtn = document.getElementById("pcViewFindingsBtn");
  const pcViewDashboardBtn = document.getElementById("pcViewDashboardBtn");
  const pcDownloadHtmlBtn = document.getElementById("pcDownloadHtmlBtn");

  // Resource Detail Inspector Modal
  const resourceModalBackdrop = document.getElementById("resourceModalBackdrop");
  const resModalCloseBtn = document.getElementById("resModalCloseBtn");
  const resModalService = document.getElementById("resModalService");
  const resModalId = document.getElementById("resModalId");
  const resModalType = document.getElementById("resModalType");
  const resModalLine = document.getElementById("resModalLine");
  const resModalStatus = document.getElementById("resModalStatus");
  const resModalRelations = document.getElementById("resModalRelations");
  const resModalChecksList = document.getElementById("resModalChecksList");
  const resModalProps = document.getElementById("resModalProps");

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
  const drawerStatusPill = document.getElementById("drawerStatusPill");
  const drawerConfidencePill = document.getElementById("drawerConfidencePill");
  const drawerLocationInfo = document.getElementById("drawerLocationInfo");
  const drawerActualConfig = document.getElementById("drawerActualConfig");
  const drawerExpectedConfig = document.getElementById("drawerExpectedConfig");
  const verifyFindingBtn = document.getElementById("verifyFindingBtn");
  const drawerVerificationBox = document.getElementById("drawerVerificationBox");
  const scoreExplanationCard = document.getElementById("scoreExplanationCard");
  const scoreExplanationContent = document.getElementById("scoreExplanationContent");
  const compoundRisksCard = document.getElementById("compoundRisksCard");
  const compoundRisksContent = document.getElementById("compoundRisksContent");
  const drawerRemediationLifecycleContainer = document.getElementById("drawerRemediationLifecycleContainer");
  const drawerRemStatusBadge = document.getElementById("drawerRemStatusBadge");
  const generateFixPreviewBtn = document.getElementById("generateFixPreviewBtn");
  const drawerRemPreviewContent = document.getElementById("drawerRemPreviewContent");
  const drawerRemValidationBox = document.getElementById("drawerRemValidationBox");
  const drawerRemExplanation = document.getElementById("drawerRemExplanation");
  const drawerRemSecurityGain = document.getElementById("drawerRemSecurityGain");
  const drawerRemSideEffects = document.getElementById("drawerRemSideEffects");
  const drawerRemDiffBlock = document.getElementById("drawerRemDiffBlock");
  const copyDiffBtn = document.getElementById("copyDiffBtn");
  const approveFixBtn = document.getElementById("approveFixBtn");
  const dashExportRemediatedBtn = document.getElementById("dashExportRemediatedBtn");
  const dashRescanRemediatedBtn = document.getElementById("dashRescanRemediatedBtn");
  const remediationComparisonCard = document.getElementById("remediationComparisonCard");
  const remediationComparisonContent = document.getElementById("remediationComparisonContent");
  const remediationDeltaBadge = document.getElementById("remediationDeltaBadge");

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

  // Restore persisted active scan from sessionStorage if available
  const savedScanId = sessionStorage.getItem("cloudguard_active_scan_id");
  if (savedScanId) {
    fetch(`/api/v1/scan/${savedScanId}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.data) {
          loadScanIntoDashboard(data.data);
        }
      })
      .catch(e => console.debug("Could not restore saved scan:", e));
  }

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
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleSelectedFile(e.target.files[0]);
    }
  });

  if (loadSampleBlueprintBtn) {
    loadSampleBlueprintBtn.addEventListener("click", async () => {
      try {
        loadSampleBlueprintBtn.disabled = true;
        const res = await fetch("/api/v1/scan/sample-blueprint");
        if (!res.ok) throw new Error("Could not fetch safe sample blueprint.");
        const data = await res.json();

        const blob = new Blob([data.content], { type: "text/plain" });
        const sampleFile = new File([blob], data.filename, { type: "text/plain" });

        handleSelectedFile(sampleFile);
        uploadStatusBox.className = "status-box info";
        uploadStatusBox.innerHTML = `<strong>Safe Sample Blueprint Loaded:</strong> <code>${data.filename}</code> (${formatBytes(data.size_bytes)}). Multi-tier AWS blueprint comprising VPC, Subnet, Security Group, EC2, S3, RDS, and IAM ready for analysis. Click <strong>Analyze Architecture</strong> to begin live inspection.`;
        uploadStatusBox.style.display = "block";
      } catch (err) {
        showUploadError("Failed to load sample blueprint: " + err.message);
      } finally {
        loadSampleBlueprintBtn.disabled = false;
      }
    });
  }

  function handleSelectedFile(file) {
    selectedFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = `(${formatBytes(file.size)})`;
    selectedFilePane.style.display = "flex";
    uploadStatusBox.style.display = "none";
    if (liveAnalysisWorkspace) {
      liveAnalysisWorkspace.style.display = "none";
    }
    if (progressContainer) {
      progressContainer.style.display = "none";
    }
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
          
          // Hydrate dashboard and application state immediately
          loadScanIntoDashboard(scan);
          loadHealthAndMetrics();

          uploadStatusBox.className = "status-box success";
          uploadStatusBox.innerHTML = `<strong>Analysis Complete:</strong> Assessed <code>${scan.target_name}</code> with Risk Score <strong>${scan.overall_risk_score}</strong> (Grade ${scan.risk_grade}). Found ${scan.total_findings} issues. <button type="button" class="btn btn-secondary" id="viewDashQuickBtn" style="padding: 2px 8px; margin-left: 8px;">View Dashboard</button>`;
          uploadStatusBox.style.display = "block";

          const quickBtn = document.getElementById("viewDashQuickBtn");
          if (quickBtn) {
            quickBtn.addEventListener("click", () => {
              loadScanIntoDashboard(scan);
              switchView("view-dashboard");
            });
          }

          // Run interactive live pipeline visualizer
          runInteractiveLivePipeline(scan);
        } catch (err) {
          showUploadError("Failed to parse analysis results: " + err.message);
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

  // --- INTERACTIVE PIPELINE & LIVE VISUALIZATION HELPERS ---
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  function sanitizeId(id) {
    return String(id || "item").replace(/[^a-zA-Z0-9_-]/g, "_");
  }

  function formatServiceName(svc) {
    const s = String(svc || "OTHER_AWS").toUpperCase();
    if (s === "SECURITY_GROUP") return "Security Groups";
    if (s === "S3") return "Amazon S3 Storage";
    if (s === "EC2") return "Amazon EC2 Compute";
    if (s === "RDS") return "Amazon RDS Database";
    if (s === "IAM") return "AWS IAM & Security";
    if (s === "VPC") return "Amazon VPC Networking";
    if (s === "EBS") return "Elastic Block Store (EBS)";
    if (s === "LAMBDA") return "AWS Lambda Serverless";
    if (s === "DYNAMODB") return "Amazon DynamoDB";
    if (s === "API_GATEWAY") return "Amazon API Gateway";
    return "AWS Cloud Infrastructure";
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function renderTopologyGrid(resources, initialStatus = "PENDING") {
    if (!resourceGraphGrid) return;
    const groups = {};
    resources.forEach(r => {
      const svc = r.service || "OTHER_AWS";
      if (!groups[svc]) groups[svc] = [];
      groups[svc].push(r);
    });

    let html = "";
    for (const [svc, resList] of Object.entries(groups)) {
      html += `
        <div class="rg-service-group">
          <div class="rg-service-title">
            <span>${formatServiceName(svc)}</span>
            <span style="font-size: 11px; font-weight: 600; color: var(--color-text-muted);">${resList.length} resource${resList.length > 1 ? "s" : ""}</span>
          </div>
          <div class="rg-cards-list">`;
      resList.forEach(r => {
        const sId = sanitizeId(r.resource_id);
        const relStr = (r.relationships && r.relationships.length > 0)
          ? `References: ${r.relationships.join(", ")}`
          : "Independent baseline resource";
        html += `
          <div class="resource-card status-${initialStatus.toLowerCase()}" id="resCard_${sId}" data-resid="${escapeHtml(r.resource_id)}">
            <div class="rc-top">
              <span class="rc-id" title="${escapeHtml(r.resource_id)}">${escapeHtml(r.resource_id)}</span>
              <span class="rc-badge ${initialStatus}" id="resBadge_${sId}">${initialStatus}</span>
            </div>
            <div style="font-size: 11px; color: var(--color-text-secondary); margin-top: 2px;">
              <code>${escapeHtml(r.resource_type)}</code> &bull; Line ${r.line_number || 1}
            </div>
            <div class="rc-relationships" title="${escapeHtml(relStr)}">${escapeHtml(relStr)}</div>
          </div>`;
      });
      html += `</div></div>`;
    }
    resourceGraphGrid.innerHTML = html;

    // Attach click listeners to cards
    resources.forEach(r => {
      const sId = sanitizeId(r.resource_id);
      const card = document.getElementById(`resCard_${sId}`);
      if (card) {
        card.addEventListener("click", () => {
          openResourceInspector(r);
        });
      }
    });
  }

  function updateResourceCardStatus(resourceId, status, findingsCount = 0) {
    const sId = sanitizeId(resourceId);
    const card = document.getElementById(`resCard_${sId}`);
    const badge = document.getElementById(`resBadge_${sId}`);
    if (card && badge) {
      card.className = `resource-card status-${status.toLowerCase()}`;
      badge.className = `rc-badge ${status}`;
      if (status === "FAILED" && findingsCount > 0) {
        badge.textContent = `${findingsCount} ISSUE${findingsCount > 1 ? "S" : ""}`;
      } else {
        badge.textContent = status;
      }
    }
  }

  function addEventToStream(ev) {
    if (!eventStreamList) return;
    const row = document.createElement("div");
    row.className = `event-row ${ev.status || "INFO"}`;
    const timeStr = (ev.timestamp ? ev.timestamp.slice(11, 19) : new Date().toLocaleTimeString());
    row.innerHTML = `
      <span class="event-time">${timeStr}</span>
      <span class="event-stage">${escapeHtml(ev.stage || "AUDIT")}</span>
      <span class="event-msg">${escapeHtml(ev.message || "")}</span>
    `;
    eventStreamList.appendChild(row);
    eventStreamList.scrollTop = eventStreamList.scrollHeight;

    const count = eventStreamList.querySelectorAll(".event-row").length;
    if (eventCountBadge) {
      eventCountBadge.textContent = `${count} events`;
    }
  }

  function runInteractiveLivePipeline(scan) {
    if (!liveAnalysisWorkspace) {
      loadScanIntoDashboard(scan);
      loadHealthAndMetrics();
      return;
    }

    const resources = scan.discovered_resources || [];
    const summary = scan.discovery_summary || {};
    const events = summary.pipeline_events || [];

    liveAnalysisWorkspace.style.display = "block";
    pipelineCompletionBar.style.display = "none";

    // Scroll workspace into view smoothly
    liveAnalysisWorkspace.scrollIntoView({ behavior: "smooth", block: "start" });

    // Reset counters
    liveDiscoveredCount.textContent = resources.length;
    liveDiscoveredSub.textContent = `${Object.keys(summary.services_summary || {}).length} AWS services mapped`;
    liveInspectionStatus.textContent = "Initializing inspection queue...";
    liveInspectionSub.textContent = `Target: ${scan.target_name}`;
    liveChecksCount.textContent = "0";
    livePassedChecks.textContent = "0 passed";
    liveFailedChecks.textContent = "0 failed";
    liveFindingsCount.textContent = "0";
    liveFindingsSub.textContent = "0 Critical / 0 High";
    liveScoreValue.textContent = "--";
    liveGradeValue.textContent = "Grade --";
    eventCountBadge.textContent = "0 events";
    eventStreamList.innerHTML = "";

    // Render initial resource topology graph with PENDING cards
    renderTopologyGrid(resources, "PENDING");

    let fastForward = false;
    if (skipAnimationBtn) {
      skipAnimationBtn.onclick = () => {
        fastForward = true;
      };
    }

    function setStepper(stepNum) {
      document.querySelectorAll(".pipeline-step").forEach(el => {
        const n = parseInt(el.getAttribute("data-step"));
        el.classList.toggle("completed", n < stepNum);
        el.classList.toggle("active", n === stepNum);
      });
      document.querySelectorAll(".pipeline-step-divider").forEach((el, idx) => {
        el.classList.toggle("completed", idx + 1 < stepNum);
      });
      const stageNames = ["Validation", "AST Parsing", "Resource Inventory", "Sequential Audit", "Findings", "Risk Scoring", "Reports Ready"];
      if (currentStageBadge) {
        currentStageBadge.textContent = `Stage ${stepNum}: ${stageNames[stepNum - 1] || "Complete"}`;
      }
    }

    async function runStepSequence() {
      // Step 1: Validation
      setStepper(1);
      addEventToStream(events.find(e => e.stage === "VALIDATION") || {
        timestamp: new Date().toISOString(), stage: "VALIDATION", service: "SYSTEM", message: `Syntax diagnostics verified for ${scan.target_name}`, status: "SUCCESS"
      });
      if (!fastForward) await sleep(220);

      // Step 2: AST Parsing
      setStepper(2);
      addEventToStream(events.find(e => e.stage === "PARSING") || {
        timestamp: new Date().toISOString(), stage: "PARSING", service: "PARSER", message: `Parsed ${resources.length} normalized resources into AST graph`, status: "SUCCESS"
      });
      if (!fastForward) await sleep(220);

      // Step 3: Inventory
      setStepper(3);
      addEventToStream(events.find(e => e.stage === "INVENTORY") || {
        timestamp: new Date().toISOString(), stage: "INVENTORY", service: "TOPOLOGY", message: "Built AWS service topology with dependency connectors", status: "SUCCESS"
      });
      if (!fastForward) await sleep(220);

      // Step 4: Sequential Audit of each resource
      setStepper(4);
      let evaluatedChecksTotal = 0;
      let passedChecksTotal = 0;
      let failedChecksTotal = 0;
      let accumulatedFindings = 0;
      let criticalCount = 0;
      let highCount = 0;

      for (let i = 0; i < resources.length; i++) {
        const res = resources[i];
        liveInspectionStatus.textContent = `Auditing ${res.resource_id}`;
        liveInspectionSub.textContent = `Resource ${i + 1} of ${resources.length} (${res.resource_type})`;

        // Pulse card
        updateResourceCardStatus(res.resource_id, "ANALYSING");

        addEventToStream({
          timestamp: new Date().toISOString(),
          stage: "INSPECTION",
          service: res.service,
          message: `Auditing ${res.resource_id} (${res.resource_type}) on line ${res.line_number || 1}`,
          status: "INFO"
        });

        if (!fastForward) await sleep(160);

        const checks = res.checks_evaluated || [];
        for (const chk of checks) {
          evaluatedChecksTotal++;
          if (chk.status === "PASSED") {
            passedChecksTotal++;
          } else {
            failedChecksTotal++;
            accumulatedFindings++;
            if (chk.severity === "CRITICAL") criticalCount++;
            if (chk.severity === "HIGH") highCount++;
          }
          liveChecksCount.textContent = evaluatedChecksTotal;
          livePassedChecks.textContent = `${passedChecksTotal} passed`;
          liveFailedChecks.textContent = `${failedChecksTotal} failed`;
          liveFindingsCount.textContent = accumulatedFindings;
          liveFindingsSub.textContent = `${criticalCount} Critical / ${highCount} High`;

          addEventToStream({
            timestamp: new Date().toISOString(),
            stage: "EVALUATION",
            service: res.service,
            message: `[${chk.rule_id}] ${chk.rule_name}: ${chk.status}`,
            status: chk.status === "FAILED" ? "WARNING" : "SUCCESS"
          });

          if (!fastForward) await sleep(50);
        }

        updateResourceCardStatus(res.resource_id, res.status, res.findings_count || 0);
      }

      // Step 5: Findings
      setStepper(5);
      addEventToStream({
        timestamp: new Date().toISOString(),
        stage: "FINDINGS",
        service: "SECURITY",
        message: `Compiled ${scan.total_findings} security & posture findings with structured evidence`,
        status: scan.total_findings > 0 ? "WARNING" : "SUCCESS"
      });
      if (!fastForward) await sleep(180);

      // Step 6: Risk Scoring
      setStepper(6);
      liveScoreValue.textContent = scan.overall_risk_score;
      liveGradeValue.textContent = `Grade ${scan.risk_grade}`;
      addEventToStream({
        timestamp: new Date().toISOString(),
        stage: "SCORING",
        service: "ANALYTICS",
        message: `Calculated Well-Architected Risk Score: ${scan.overall_risk_score} (Grade ${scan.risk_grade})`,
        status: "SUCCESS"
      });
      if (!fastForward) await sleep(180);

      // Step 7: Reports Ready
      setStepper(7);
      addEventToStream({
        timestamp: new Date().toISOString(),
        stage: "REPORTING",
        service: "REPORTS",
        message: "Audit records persisted. Downloadable HTML, Markdown, and JSON reports compiled.",
        status: "SUCCESS"
      });

      // Complete!
      document.querySelectorAll(".pipeline-step").forEach(el => el.classList.add("completed"));
      document.querySelectorAll(".pipeline-step-divider").forEach(el => el.classList.add("completed"));
      if (currentStageBadge) {
        currentStageBadge.textContent = "Pipeline Completed";
        currentStageBadge.className = "stage-pill active";
      }
      liveInspectionStatus.textContent = "Inspection Finished";
      liveInspectionSub.textContent = `Assessed ${resources.length} resources across 7 dimensions`;

      // Show Completion Bar
      if (pipelineCompletionBar) {
        pipelineCompletionBar.style.display = "flex";
        pcSummaryTitle.textContent = `Assessment Complete: Grade ${scan.risk_grade} (${scan.overall_risk_score}/100)`;
        pcSummaryDetails.textContent = `${resources.length} resources audited &bull; ${evaluatedChecksTotal} checks &bull; ${scan.total_findings} findings detected`;

        pcViewFindingsBtn.onclick = () => {
          loadScanIntoDashboard(scan);
          switchView("view-findings");
        };

        pcViewDashboardBtn.onclick = () => {
          loadScanIntoDashboard(scan);
          switchView("view-dashboard");
        };

        pcDownloadHtmlBtn.href = `/api/v1/scan/${scan.scan_id}/report?format=html`;
      }

      loadScanIntoDashboard(scan);
      loadHealthAndMetrics();
    }

    runStepSequence();
  }

  function openResourceInspector(res) {
    if (!res || !resourceModalBackdrop) return;

    resModalService.textContent = formatServiceName(res.service);
    resModalId.textContent = res.resource_id;
    resModalType.textContent = res.resource_type;
    resModalLine.textContent = res.line_number || "1";
    resModalStatus.className = `rc-badge ${res.status}`;
    resModalStatus.textContent = res.status;
    resModalRelations.textContent = (res.relationships && res.relationships.length > 0)
      ? res.relationships.join(", ")
      : "None";

    const checks = res.checks_evaluated || [];
    let checksHtml = "";
    if (checks.length === 0) {
      checksHtml = '<div style="font-size: 12px; color: var(--color-text-muted);">No specific rule failures. Baseline compliance checks satisfied.</div>';
    } else {
      checks.forEach(c => {
        const isFail = c.status === "FAILED";
        checksHtml += `
          <div style="display: flex; align-items: flex-start; justify-content: space-between; padding: 10px 12px; border-radius: var(--radius-xs); border: 1px solid var(--color-border); background: ${isFail ? "var(--color-critical-bg)" : "#FAF8F5"};">
            <div>
              <div style="font-weight: 700; font-size: 12px; color: ${isFail ? "var(--color-critical)" : "var(--color-text-main)"};">[${escapeHtml(c.rule_id)}] ${escapeHtml(c.rule_name)}</div>
              <div style="font-size: 11px; color: var(--color-text-secondary); margin-top: 3px;">${escapeHtml(c.details || "")}</div>
            </div>
            <span class="severity-tag ${isFail ? c.severity : "LOW"}">${escapeHtml(c.status)}</span>
          </div>`;
      });
    }
    resModalChecksList.innerHTML = checksHtml;

    resModalProps.textContent = JSON.stringify(res.properties || {}, null, 2);
    resourceModalBackdrop.style.display = "flex";
  }

  if (resModalCloseBtn) {
    resModalCloseBtn.addEventListener("click", () => {
      resourceModalBackdrop.style.display = "none";
    });
  }

  if (resourceModalBackdrop) {
    resourceModalBackdrop.addEventListener("click", (e) => {
      if (e.target === resourceModalBackdrop) {
        resourceModalBackdrop.style.display = "none";
      }
    });
  }

  function showUploadError(msg) {
    uploadStatusBox.className = "status-box error";
    uploadStatusBox.textContent = `Error: ${msg}`;
    uploadStatusBox.style.display = "block";
  }

  // --- DASHBOARD RENDERING ---
  function loadScanIntoDashboard(scan) {
    activeScan = scan;
    allFindings = scan.findings || [];
    if (scan && scan.scan_id) {
      sessionStorage.setItem("cloudguard_active_scan_id", scan.scan_id);
    }

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

    // Render Transparent Score Calculation Breakdown
    if (scan.score_explanation && scoreExplanationCard && scoreExplanationContent) {
      const se = scan.score_explanation;
      const sb = se.status_breakdown || {};
      const sevb = se.severity_breakdown || {};
      let critWarning = se.critical_override_applied 
        ? `<div style="background: #fbeae5; border: 1px solid #e2a698; border-radius: 4px; padding: 10px; margin-bottom: 12px; font-size: 12px; color: #8b0000;">
             <strong>Critical Risk Guardrail Activated:</strong> An explicit confirmed critical vulnerability was detected. Per Well-Architected governance standards, the overall risk score is pinned to 70.0 (Grade D/F) to prevent low-severity findings from concealing severe security openings.
           </div>`
        : "";

      scoreExplanationContent.innerHTML = `
        ${critWarning}
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 14px;">
          <div style="background: var(--color-surface-muted); padding: 12px; border-radius: 4px; border: 1px solid var(--color-border);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Mathematical Formula</div>
            <div style="font-size: 12px; font-family: var(--font-mono); margin-top: 4px; color: var(--color-text-main);">Score = min(100, &sum; (Severity Weight &times; Status Multiplier))</div>
            <div style="font-size: 11px; color: var(--color-text-muted); margin-top: 4px;">Raw Points: <strong>${se.raw_weighted_points !== undefined ? se.raw_weighted_points : scan.overall_risk_score}</strong> &bull; Deduplicated: <strong>${se.deduplicated_findings_count || 0}</strong></div>
          </div>
          <div style="background: var(--color-surface-muted); padding: 12px; border-radius: 4px; border: 1px solid var(--color-border);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Status Multipliers</div>
            <div style="display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap;">
              <span style="font-size: 11px; background: #fbeae5; color: #8b0000; padding: 2px 6px; border-radius: 3px;">Confirmed (1.0x): ${sb.CONFIRMED || 0}</span>
              <span style="font-size: 11px; background: #fdf3d8; color: #8c6b12; padding: 2px 6px; border-radius: 3px;">Potential (0.65x): ${sb.POTENTIAL || 0}</span>
              <span style="font-size: 11px; background: #eef4f8; color: #1d5872; padding: 2px 6px; border-radius: 3px;">Requires Verif (0.35x): ${sb.REQUIRES_VERIFICATION || 0}</span>
            </div>
          </div>
          <div style="background: var(--color-surface-muted); padding: 12px; border-radius: 4px; border: 1px solid var(--color-border);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Severity Base Points</div>
            <div style="font-size: 11.5px; color: var(--color-text-secondary); margin-top: 4px;">
              Crit: 25pt (${sevb.CRITICAL || 0}) &bull; High: 15pt (${sevb.HIGH || 0}) &bull; Med: 8pt (${sevb.MEDIUM || 0}) &bull; Low: 3pt (${sevb.LOW || 0})
            </div>
          </div>
        </div>
      `;
      scoreExplanationCard.style.display = "block";
    } else if (scoreExplanationCard) {
      scoreExplanationCard.style.display = "none";
    }

    // Render Compound Risks
    if (scan.compound_risks && scan.compound_risks.length > 0 && compoundRisksCard && compoundRisksContent) {
      let crHtml = "";
      scan.compound_risks.forEach(cr => {
        crHtml += `
          <div style="background: #faf7f5; border: 1px solid #ebd9d2; border-left: 4px solid #8b0000; border-radius: 4px; padding: 12px 14px; margin-bottom: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-weight: 600; color: #8b0000; font-size: 13.5px;">${cr.title}</span>
              <span class="severity-tag CRITICAL" style="font-size: 10px;">COMPOUND THREAT</span>
            </div>
            <div style="font-size: 12px; font-family: var(--font-mono); color: var(--color-text-secondary); margin: 4px 0;">Vector: ${cr.vector}</div>
            <p style="font-size: 12.5px; color: var(--color-text-main); margin: 6px 0; line-height: 1.5;">${cr.description}</p>
            <div style="font-size: 12px; color: #287fa3; font-weight: 500;">Action: ${cr.recommended_action}</div>
          </div>
        `;
      });
      compoundRisksContent.innerHTML = crHtml;
      compoundRisksCard.style.display = "block";
    } else if (compoundRisksCard) {
      compoundRisksCard.style.display = "none";
    }

    // Show / hide Export & Rescan buttons for remediated blueprint
    const hasStagedOrCorrected = (scan.staged_remediations && Object.keys(scan.staged_remediations).length > 0) || scan.corrected_content || scan.corrected_file_key;
    if (dashExportRemediatedBtn) dashExportRemediatedBtn.style.display = hasStagedOrCorrected ? "inline-flex" : "none";
    if (dashRescanRemediatedBtn) dashRescanRemediatedBtn.style.display = hasStagedOrCorrected ? "inline-flex" : "none";

    // Render Before-and-After Remediation Comparison Card
    if (scan.comparison_data && remediationComparisonCard && remediationComparisonContent) {
      const cmp = scan.comparison_data;
      if (remediationDeltaBadge) {
        remediationDeltaBadge.textContent = `Net Risk Reduction: -${cmp.score_delta || 0} pts`;
      }

      let resolvedRows = "";
      (cmp.resolved_findings || []).forEach(rf => {
        resolvedRows += `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid #e2ddd5; font-size:12px;">
            <span><code style="color:#287fa3; font-weight:600;">${rf.rule_id}</code>: ${rf.title} (<strong>${rf.resource_id}</strong>)</span>
            <span style="color:#2d5a27; font-weight:600; background:#e8f4ec; padding:2px 8px; border-radius:3px;">✓ Verified Resolved</span>
          </div>`;
      });

      let partiallyRows = "";
      (cmp.partially_resolved_findings || []).forEach(pf => {
        partiallyRows += `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid #e2ddd5; font-size:12px;">
            <span><code style="color:#8c6b12; font-weight:600;">${pf.rule_id}</code>: ${pf.title} (<strong>${pf.resource_id}</strong>)</span>
            <span style="color:#8c6b12; font-weight:600; background:#fdf3d8; padding:2px 8px; border-radius:3px;">Partially Resolved (${pf.severity_before} &rarr; ${pf.severity_after})</span>
          </div>`;
      });

      let unresolvedRows = "";
      (cmp.unresolved_findings || []).forEach(uf => {
        unresolvedRows += `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid #e2ddd5; font-size:12px;">
            <span><code style="color:#8b0000; font-weight:600;">${uf.rule_id}</code>: ${uf.title} (<strong>${uf.resource_id}</strong>)</span>
            <span style="color:#8b0000; font-weight:600; background:#fbeae5; padding:2px 8px; border-radius:3px;">Unresolved</span>
          </div>`;
      });

      remediationComparisonContent.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 16px;">
          <div style="background: var(--color-surface-muted); padding: 12px; border-radius: 4px; border: 1px solid var(--color-border); text-align: center;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--color-text-muted);">Risk Score Before</div>
            <div style="font-size: 22px; font-weight: 700; color: #8b0000; margin-top: 4px;">${cmp.score_before} <span style="font-size: 14px;">(Grade ${cmp.grade_before})</span></div>
          </div>
          <div style="background: var(--color-surface-muted); padding: 12px; border-radius: 4px; border: 1px solid var(--color-border); text-align: center;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--color-text-muted);">Remediated Risk Score</div>
            <div style="font-size: 22px; font-weight: 700; color: #2d5a27; margin-top: 4px;">${cmp.score_after} <span style="font-size: 14px;">(Grade ${cmp.grade_after})</span></div>
          </div>
          <div style="background: var(--color-surface-muted); padding: 12px; border-radius: 4px; border: 1px solid var(--color-border); text-align: center;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--color-text-muted);">Resolved Findings</div>
            <div style="font-size: 22px; font-weight: 700; color: #287fa3; margin-top: 4px;">${cmp.resolved_count || 0} / ${cmp.counts_before ? cmp.counts_before.total : 0}</div>
          </div>
        </div>
        ${resolvedRows ? `<div style="margin-top:12px;"><strong style="font-size:12px; color:#2d5a27;">Resolved Findings (${cmp.resolved_count || 0}):</strong>${resolvedRows}</div>` : ''}
        ${partiallyRows ? `<div style="margin-top:12px;"><strong style="font-size:12px; color:#8c6b12;">Partially Resolved Findings:</strong>${partiallyRows}</div>` : ''}
        ${unresolvedRows ? `<div style="margin-top:12px;"><strong style="font-size:12px; color:#8b0000;">Remaining Unresolved Findings (${cmp.unresolved_count || 0}):</strong>${unresolvedRows}</div>` : ''}
      `;
      remediationComparisonCard.style.display = "block";
    } else if (remediationComparisonCard) {
      remediationComparisonCard.style.display = "none";
    }

    // Render findings
    renderFindingsTable(allFindings);
  }

  // --- FINDINGS PANEL & FILTERS ---
  function renderFindingsTable(findings) {
    findingsCountBadge.textContent = `${findings.length} findings displayed`;

    if (!findings || findings.length === 0) {
      if (activeScan && activeScan.overall_risk_score === 0) {
        findingsTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--color-low); padding: 24px; font-weight: 500;">✓ Clean Architecture: No security or compliance risks detected across all 7 Well-Architected dimensions (Risk Score 0.0, Grade A).</td></tr>`;
      } else {
        findingsTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--color-text-muted); padding: 24px;">No findings match the current criteria.</td></tr>`;
      }
      return;
    }

    let rows = "";
    findings.forEach(f => {
      const status = (f.finding_status || "CONFIRMED").toUpperCase();
      const statusStyle = status === "CONFIRMED"
        ? "background: #fbeae5; color: #8b0000; border: 1px solid rgba(139, 0, 0, 0.2);"
        : status === "POTENTIAL"
        ? "background: #fdf3d8; color: #8c6b12; border: 1px solid rgba(140, 107, 18, 0.2);"
        : "background: #eef4f8; color: #1d5872; border: 1px solid rgba(29, 88, 114, 0.2);";

      const remStatus = f.remediation_status;
      let statusBadge = "";
      if (remStatus === "Resolved") {
        statusBadge = `<span style="font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; display: inline-block; background: #e8f4ec; color: #2d5a27; border: 1px solid rgba(45, 90, 39, 0.25);">✓ RESOLVED</span>`;
      } else if (remStatus === "Partially Resolved") {
        statusBadge = `<span style="font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; display: inline-block; background: #fdf3d8; color: #8c6b12; border: 1px solid rgba(140, 107, 18, 0.25);">PARTIAL</span>`;
      } else if (remStatus === "Verification Failed") {
        statusBadge = `<span style="font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; display: inline-block; background: #fbeae5; color: #8b0000; border: 1px solid rgba(139, 0, 0, 0.25);">VERIF FAILED</span>`;
      } else {
        statusBadge = `<span style="font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 3px; display: inline-block; ${statusStyle}">${status.replace(/_/g, ' ')}</span>`;
      }

      const isResolved = remStatus === "Resolved";
      const actionButtons = isResolved
        ? `<span style="font-size: 11px; font-weight: 600; color: #2d5a27; margin-right: 6px;">✓ Resolved</span><button type="button" class="btn btn-secondary inspect-btn" data-id="${f.finding_id}" style="padding: 3px 8px; font-size: 11px;">Inspect &rarr;</button>`
        : `<button type="button" class="btn btn-secondary preview-fix-btn" data-id="${f.finding_id}" style="padding: 3px 8px; font-size: 11px; margin-right: 4px;">Preview Fix</button><button type="button" class="btn btn-secondary inspect-btn" data-id="${f.finding_id}" style="padding: 3px 8px; font-size: 11px;">Inspect &rarr;</button>`;

      rows += `
        <tr ${isResolved ? 'style="opacity: 0.9; background: rgba(45, 90, 39, 0.04);"' : ''}>
          <td><span class="severity-tag ${f.severity}">${f.severity}</span></td>
          <td>${statusBadge}</td>
          <td><code style="font-size: 11.5px; padding: 2px 6px; background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: 3px;">${f.rule_id}</code></td>
          <td style="font-weight: 600; color: var(--color-text-main);">${f.title}</td>
          <td><code style="font-size: 11px; color: var(--color-text-secondary);">${f.resource_id}</code></td>
          <td><span style="font-size: 12px; font-weight: 500; color: var(--color-text-secondary);">${f.dimension}</span></td>
          <td style="text-align: center; white-space: nowrap;">
            ${actionButtons}
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

    document.querySelectorAll(".preview-fix-btn").forEach(b => {
      b.addEventListener("click", () => {
        const id = b.getAttribute("data-id");
        const found = allFindings.find(item => item.finding_id === id);
        if (found) {
          openFindingDrawer(found);
          triggerRemediationPreview(found);
        }
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

    // Status & Confidence pills
    const status = (f.finding_status || "CONFIRMED").toUpperCase();
    if (drawerStatusPill) {
      drawerStatusPill.textContent = status.replace(/_/g, " ");
      if (status === "CONFIRMED") {
        drawerStatusPill.style.background = "#fbeae5";
        drawerStatusPill.style.color = "#8b0000";
      } else if (status === "POTENTIAL") {
        drawerStatusPill.style.background = "#fdf3d8";
        drawerStatusPill.style.color = "#8c6b12";
      } else {
        drawerStatusPill.style.background = "#eef4f8";
        drawerStatusPill.style.color = "#1d5872";
      }
    }

    if (drawerConfidencePill) {
      drawerConfidencePill.textContent = `${(f.confidence || "HIGH").toUpperCase()} CONFIDENCE`;
    }

    // Source Location
    if (drawerLocationInfo) {
      const srcFile = f.file_name || (activeScan && activeScan.target_name) || "template.tf";
      const lineNum = f.line_number || "1";
      drawerLocationInfo.textContent = `Source File: ${srcFile} • Line: ${lineNum}`;
    }

    // Actual vs Expected Config
    if (drawerActualConfig) {
      let actVal = f.actual_config;
      if (!actVal && f.evidence && f.evidence.detected_value !== undefined) {
        actVal = typeof f.evidence.detected_value === "object" ? JSON.stringify(f.evidence.detected_value) : String(f.evidence.detected_value);
      }
      drawerActualConfig.textContent = actVal || "Not declared in blueprint";
    }

    if (drawerExpectedConfig) {
      let expVal = f.expected_config;
      if (!expVal && f.evidence && f.evidence.expected_value !== undefined) {
        expVal = typeof f.evidence.expected_value === "object" ? JSON.stringify(f.evidence.expected_value) : String(f.evidence.expected_value);
      }
      drawerExpectedConfig.textContent = expVal || "Standard secure baseline";
    }

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

    // Render verification panel
    renderDrawerVerificationDetails(f);

    // Render remediation lifecycle panel
    renderRemediationLifecycleDrawer(f);

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

  function renderDrawerVerificationDetails(f) {
    if (!drawerVerificationBox) return;
    if (f.verification_details) {
      const vd = f.verification_details;
      drawerVerificationBox.innerHTML = `
        <div style="background: #fff; border: 1px solid var(--color-border); border-radius: 4px; padding: 10px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-weight: 600; color: #287fa3;">Verified Status: ${vd.status || f.finding_status}</span>
            <span style="font-size: 11px; color: var(--color-text-muted);">${(vd.verification_timestamp || '').slice(0, 19).replace('T', ' ')} UTC</span>
          </div>
          <p style="font-size: 12px; color: var(--color-text-main); line-height: 1.4; margin: 4px 0;">${vd.verification_narrative || 'AST re-examination confirmed finding.'}</p>
          ${vd.compensating_controls && vd.compensating_controls.length ? `<div style="font-size: 11.5px; color: #8c6b12; margin-top: 4px;"><strong>Compensating Controls:</strong> ${vd.compensating_controls.join(', ')}</div>` : ''}
          <div style="font-size: 11px; color: var(--color-text-muted); border-top: 1px dashed var(--color-border); margin-top: 6px; padding-top: 6px;">
            <em>${vd.live_aws_notice || 'Static Blueprint Verification evaluates declared IaC. Live runtime status requires live AWS scanning.'}</em>
          </div>
        </div>
      `;
      drawerVerificationBox.style.display = "block";
    } else {
      drawerVerificationBox.style.display = "none";
      drawerVerificationBox.innerHTML = "";
    }
  }

  if (verifyFindingBtn) {
    verifyFindingBtn.addEventListener("click", async () => {
      if (!currentDrawerFinding) return;
      const scanId = (activeScan && activeScan.scan_id) || currentDrawerFinding.scan_id;
      if (!scanId) {
        alert("No active scan associated with this finding.");
        return;
      }

      verifyFindingBtn.disabled = true;
      verifyFindingBtn.innerHTML = "<span>Analyzing AST...</span>";
      if (drawerVerificationBox) {
        drawerVerificationBox.style.display = "block";
        drawerVerificationBox.innerHTML = `<div style="padding: 8px; color: var(--color-text-muted);">Re-evaluating blueprint AST, line references and graph dependencies...</div>`;
      }

      try {
        const res = await fetch(`/api/v1/scan/${scanId}/findings/${currentDrawerFinding.finding_id}/verify`, {
          method: "POST"
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.detail || "Finding verification failed.");
        }

        const v = data.verification;
        currentDrawerFinding.finding_status = v.status;
        currentDrawerFinding.confidence = v.confidence;
        currentDrawerFinding.verification_details = v;

        // Update active scan if available
        if (data.updated_score !== undefined && activeScan) {
          activeScan.overall_risk_score = data.updated_score;
          activeScan.risk_grade = data.updated_grade;
          if (dashOverallScore) dashOverallScore.textContent = data.updated_score;
          if (dashGradeBadge) dashGradeBadge.textContent = `Grade ${data.updated_grade}`;
        }

        // Re-render drawer elements
        openFindingDrawer(currentDrawerFinding);
        renderFindingsTable(allFindings);
      } catch (err) {
        if (drawerVerificationBox) {
          drawerVerificationBox.innerHTML = `<div style="padding: 8px; color: #8b0000;">Verification error: ${err.message}</div>`;
        }
      } finally {
        verifyFindingBtn.disabled = false;
        verifyFindingBtn.innerHTML = "<span>🔍 Verify Finding</span>";
      }
    });
  }

  function renderRemediationLifecycleDrawer(f) {
    if (!drawerRemStatusBadge) return;
    const remStatus = f.remediation_status || "Not Started";
    drawerRemStatusBadge.textContent = remStatus;

    if (remStatus === "Resolved") {
      drawerRemStatusBadge.style.background = "#e8f4ec";
      drawerRemStatusBadge.style.color = "#2d5a27";
      drawerRemStatusBadge.style.border = "1px solid rgba(45, 90, 39, 0.25)";
    } else if (remStatus === "Validated") {
      drawerRemStatusBadge.style.background = "#eef4f8";
      drawerRemStatusBadge.style.color = "#287fa3";
      drawerRemStatusBadge.style.border = "1px solid rgba(40, 127, 163, 0.25)";
    } else if (remStatus === "Awaiting Approval" || remStatus === "Fix Generated") {
      drawerRemStatusBadge.style.background = "#fdf3d8";
      drawerRemStatusBadge.style.color = "#8c6b12";
      drawerRemStatusBadge.style.border = "1px solid rgba(140, 107, 18, 0.25)";
    } else if (remStatus === "Exported") {
      drawerRemStatusBadge.style.background = "#eef4f8";
      drawerRemStatusBadge.style.color = "#1d5872";
      drawerRemStatusBadge.style.border = "1px solid rgba(29, 88, 114, 0.25)";
    } else if (remStatus === "Unresolved" || remStatus === "Verification Failed") {
      drawerRemStatusBadge.style.background = "#fbeae5";
      drawerRemStatusBadge.style.color = "#8b0000";
      drawerRemStatusBadge.style.border = "1px solid rgba(139, 0, 0, 0.25)";
    } else {
      drawerRemStatusBadge.style.background = "var(--color-surface-muted)";
      drawerRemStatusBadge.style.color = "var(--color-text-secondary)";
      drawerRemStatusBadge.style.border = "1px solid var(--color-border)";
    }

    if (f.remediation_preview) {
      const p = f.remediation_preview;
      const v = p.validation || {};

      if (drawerRemExplanation) drawerRemExplanation.textContent = p.explanation || f.description;
      if (drawerRemSecurityGain) drawerRemSecurityGain.textContent = p.security_improvement || f.remediation_summary;
      if (drawerRemSideEffects) drawerRemSideEffects.textContent = p.side_effects || "None identified.";
      if (drawerRemDiffBlock) drawerRemDiffBlock.textContent = p.diff || p.proposed_snippet;

      if (drawerRemValidationBox) {
        if (v.security_correctness) {
          drawerRemValidationBox.style.background = "#e8f4ec";
          drawerRemValidationBox.style.border = "1px solid #c2e2cc";
          drawerRemValidationBox.style.color = "#2d5a27";
          drawerRemValidationBox.innerHTML = `<strong>✓ Validated Safe:</strong> Syntactically valid AST; target finding eliminated with zero regressions. Candidate score: <strong>${v.candidate_risk_score !== undefined ? v.candidate_risk_score : '--'} (Grade ${v.candidate_risk_grade || '--'})</strong>.`;
        } else {
          drawerRemValidationBox.style.background = "#fdf3d8";
          drawerRemValidationBox.style.border = "1px solid #ebd9a8";
          drawerRemValidationBox.style.color = "#8c6b12";
          drawerRemValidationBox.innerHTML = `<strong>⚠️ Validation Notice:</strong> ${v.validation_errors && v.validation_errors.length ? v.validation_errors.join('; ') : 'Review diff carefully prior to applying.'}`;
        }
      }

      if (drawerRemPreviewContent) drawerRemPreviewContent.style.display = "block";
    } else {
      if (drawerRemPreviewContent) drawerRemPreviewContent.style.display = "none";
    }
  }

  async function triggerRemediationPreview(f) {
    if (!f) return;
    const scanId = (activeScan && activeScan.scan_id) || f.scan_id;
    if (!scanId) {
      alert("No active scan associated with this finding.");
      return;
    }

    if (generateFixPreviewBtn) {
      generateFixPreviewBtn.disabled = true;
      generateFixPreviewBtn.textContent = "Analyzing AST...";
    }

    try {
      const res = await fetch(`/api/v1/scan/${scanId}/findings/${f.finding_id}/remediation/preview`, {
        method: "POST"
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.detail || "Failed to generate remediation preview.");
      }

      f.remediation_preview = data.preview;
      f.remediation_status = data.remediation_status;

      renderRemediationLifecycleDrawer(f);
      renderFindingsTable(allFindings);
    } catch (err) {
      alert(`Remediation Preview Error: ${err.message}`);
    } finally {
      if (generateFixPreviewBtn) {
        generateFixPreviewBtn.disabled = false;
        generateFixPreviewBtn.textContent = "Preview Fix →";
      }
    }
  }

  async function triggerApproveFix(f) {
    if (!f) return;
    const scanId = (activeScan && activeScan.scan_id) || f.scan_id;
    if (!scanId) {
      alert("No active scan associated with this finding.");
      return;
    }

    if (approveFixBtn) {
      approveFixBtn.disabled = true;
      approveFixBtn.textContent = "Staging Fix...";
    }

    try {
      const res = await fetch(`/api/v1/scan/${scanId}/findings/${f.finding_id}/remediation/approve`, {
        method: "POST"
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.detail || "Failed to approve remediation.");
      }

      f.remediation_status = data.remediation_status;
      if (activeScan) {
        if (!activeScan.staged_remediations) activeScan.staged_remediations = {};
        activeScan.staged_remediations[f.finding_id] = f.remediation_preview;
        if (dashExportRemediatedBtn) dashExportRemediatedBtn.style.display = "inline-flex";
        if (dashRescanRemediatedBtn) dashRescanRemediatedBtn.style.display = "inline-flex";
      }

      renderRemediationLifecycleDrawer(f);
      renderFindingsTable(allFindings);
      alert(`Fix approved and staged into corrected blueprint (${data.staged_count} staged). You can export the blueprint or run Rescan & Verify from the Dashboard.`);
    } catch (err) {
      alert(`Approval Error: ${err.message}`);
    } finally {
      if (approveFixBtn) {
        approveFixBtn.disabled = false;
        approveFixBtn.textContent = "Approve & Stage Fix";
      }
    }
  }

  if (generateFixPreviewBtn) {
    generateFixPreviewBtn.addEventListener("click", () => {
      if (currentDrawerFinding) triggerRemediationPreview(currentDrawerFinding);
    });
  }

  if (approveFixBtn) {
    approveFixBtn.addEventListener("click", () => {
      if (currentDrawerFinding) triggerApproveFix(currentDrawerFinding);
    });
  }

  if (copyDiffBtn) {
    copyDiffBtn.addEventListener("click", () => {
      if (drawerRemDiffBlock) {
        navigator.clipboard.writeText(drawerRemDiffBlock.textContent);
        copyDiffBtn.textContent = "Copied!";
        setTimeout(() => { copyDiffBtn.textContent = "Copy Diff"; }, 1500);
      }
    });
  }

  if (dashExportRemediatedBtn) {
    dashExportRemediatedBtn.addEventListener("click", () => {
      if (!activeScan || !activeScan.scan_id) {
        alert("No active scan selected.");
        return;
      }
      window.open(`/api/v1/scan/${activeScan.scan_id}/remediation/export?download=true`, "_blank");
    });
  }

  if (dashRescanRemediatedBtn) {
    dashRescanRemediatedBtn.addEventListener("click", async () => {
      if (!activeScan || !activeScan.scan_id) {
        alert("No active scan selected.");
        return;
      }
      dashRescanRemediatedBtn.disabled = true;
      dashRescanRemediatedBtn.textContent = "Rescanning...";

      try {
        const res = await fetch(`/api/v1/scan/${activeScan.scan_id}/remediation/verify-rescan`, {
          method: "POST"
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.detail || "Rescan and verification failed.");
        }

        activeScan = data.remediated_scan;
        if (activeScan && activeScan.scan_id) {
          sessionStorage.setItem("cloudguard_active_scan_id", activeScan.scan_id);
        }
        loadScanIntoDashboard(activeScan);
        loadHealthAndMetrics();
        alert(`Rescan complete! Risk score improved from ${data.comparison.score_before} to ${data.comparison.score_after} (${data.comparison.resolved_count} findings resolved).`);
      } catch (err) {
        alert(`Rescan Error: ${err.message}`);
      } finally {
        dashRescanRemediatedBtn.disabled = false;
        dashRescanRemediatedBtn.textContent = "Rescan & Compare Fixes";
      }
    });
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
