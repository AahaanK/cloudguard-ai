/* CloudGuardAI - Blueprint Upload & Ingestion Controller
   Handles drag-and-drop, real progress events, presigned URL display,
   and clean status notifications without AI gimmicks.
*/

document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const selectedFilePane = document.getElementById("selectedFilePane");
  const fileName = document.getElementById("fileName");
  const fileSize = document.getElementById("fileSize");
  const uploadBtn = document.getElementById("uploadBtn");
  const progressContainer = document.getElementById("progressContainer");
  const progressBar = document.getElementById("progressBar");
  const progressPercent = document.getElementById("progressPercent");
  const statusBox = document.getElementById("statusBox");
  const resultContainer = document.getElementById("resultContainer");
  const storageStatusText = document.getElementById("storageStatusText");
  const refreshStatusBtn = document.getElementById("refreshStatusBtn");

  let currentFile = null;

  // Format bytes helper
  function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  // Check Storage Backend Status
  async function checkStorageStatus() {
    try {
      const res = await fetch("/api/v1/storage/status");
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      
      const s3Health = data.s3_health || {};
      let desc = "";
      if (data.active_backend === "s3" && s3Health.accessible) {
        desc = `<strong>Amazon S3 Connected:</strong> Bucket <code>${s3Health.bucket}</code> (${s3Health.region}). Server-side AES256 encryption enforced.`;
      } else if (s3Health.configured && !s3Health.accessible) {
        desc = `<strong>Amazon S3 Notice:</strong> Configured for bucket <code>${s3Health.bucket}</code>, but inaccessible (${s3Health.error_code || 'unreachable'}). Using Local Resilient Storage fallback.`;
      } else {
        desc = `<strong>Local Resilient Storage Active:</strong> Preserving templates and reports in <code>${data.local_storage_path}</code>.`;
      }
      storageStatusText.innerHTML = desc;
    } catch (e) {
      storageStatusText.innerHTML = "Offline Mode: Storing blueprints locally.";
    }
  }

  refreshStatusBtn.addEventListener("click", checkStorageStatus);
  checkStorageStatus();

  // Drag and drop handlers
  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function handleFileSelected(file) {
    currentFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = `(${formatBytes(file.size)})`;
    selectedFilePane.style.display = "flex";
    statusBox.style.display = "none";
    resultContainer.style.display = "none";
  }

  // Upload handler with real progress
  uploadBtn.addEventListener("click", () => {
    if (!currentFile) return;

    uploadBtn.disabled = true;
    progressContainer.style.display = "block";
    progressBar.style.width = "0%";
    progressPercent.textContent = "0%";
    statusBox.style.display = "none";
    resultContainer.style.display = "none";

    const formData = new FormData();
    formData.append("file", currentFile);
    formData.append("template_type", "auto");

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/storage/upload", true);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 100);
        progressBar.style.width = percent + "%";
        progressPercent.textContent = percent + "%";
      }
    };

    xhr.onload = () => {
      uploadBtn.disabled = false;
      progressContainer.style.display = "none";

      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const res = JSON.parse(xhr.responseText);
          const meta = res.data;

          statusBox.className = "status-box success";
          statusBox.textContent = `Success: ${meta.filename} securely uploaded (${meta.storage_backend.toUpperCase()}). Ready for risk evaluation.`;
          statusBox.style.display = "block";

          // Populate metadata
          document.getElementById("resAnalysisId").textContent = meta.analysis_id;
          document.getElementById("resFileKey").textContent = meta.file_key;
          document.getElementById("resBackend").textContent = meta.storage_backend === "s3" ? `Amazon S3 (${meta.bucket})` : "Local Resilient Storage";
          document.getElementById("resEncryption").textContent = meta.encrypted ? "AES256 (Server-Side Encryption)" : "Filesystem Protected";
          document.getElementById("resSha256").textContent = meta.sha256;

          const dlLink = document.getElementById("resDownloadLink");
          dlLink.href = meta.presigned_url;
          dlLink.textContent = meta.storage_backend === "s3" ? "Presigned S3 URL (Valid 15m)" : "Download Local File";

          resultContainer.style.display = "block";
        } catch (err) {
          showError("Invalid response from server.");
        }
      } else {
        let msg = "Upload failed.";
        try {
          const err = JSON.parse(xhr.responseText);
          msg = err.detail || msg;
        } catch (_) {}
        showError(msg);
      }
    };

    xhr.onerror = () => {
      uploadBtn.disabled = false;
      progressContainer.style.display = "none";
      showError("Network connection error while uploading to backend.");
    };

    xhr.send(formData);
  });

  function showError(msg) {
    statusBox.className = "status-box error";
    statusBox.textContent = `Error: ${msg}`;
    statusBox.style.display = "block";
  }
});
