"""
CloudGuardAI - Multi-Format Report Generator
Exports audit reports in Markdown, JSON, and clean printable HTML/PDF formats
with rich evidence, verification status, confidence levels, and transparent scoring breakdowns.
"""

import json
from typing import Dict, Any
from ..db.models import ScanJob
from ..storage.manager import storage_manager

class ReportExporter:

    @staticmethod
    def export_and_persist(scan: ScanJob, format_type: str = "markdown", expires_in: int = 900) -> Dict[str, Any]:
        """
        Generates the audit report in the requested format, stores it privately
        in Amazon S3 (with AES256 server-side encryption) or local storage fallback,
        and generates an authorized, short-lived presigned download URL.
        """
        fmt = format_type.lower()
        if fmt == "json":
            content_str = ReportExporter.export_json(scan)
            filename = f"report_{scan.scan_id}.json"
        elif fmt == "html":
            content_str = ReportExporter.export_html(scan)
            filename = f"report_{scan.scan_id}.html"
        else:
            content_str = ReportExporter.export_markdown(scan)
            filename = f"report_{scan.scan_id}.md"

        content_bytes = content_str.encode("utf-8")
        store_res = storage_manager.store_file(
            content=content_bytes,
            filename=filename,
            analysis_id=scan.scan_id,
            is_report=True
        )

        file_key = store_res["file_key"]
        download_url = storage_manager.get_download_url(file_key, expiration_seconds=expires_in)

        return {
            "scan_id": scan.scan_id,
            "format": fmt,
            "filename": filename,
            "file_key": file_key,
            "storage_backend": store_res["storage_backend"],
            "download_url": download_url,
            "expires_in_seconds": expires_in,
            "generated_at": scan.completed_at or scan.created_at,
            "byte_size": len(content_bytes)
        }

    @staticmethod
    def export_json(scan: ScanJob) -> str:
        return json.dumps(scan.model_dump(), indent=2)

    @staticmethod
    def export_markdown(scan: ScanJob) -> str:
        md = []
        md.append(f"# CloudGuardAI Security & Architecture Audit Report")
        md.append(f"\n**Target:** `{scan.target_name}` | **Scan ID:** `{scan.scan_id}` | **Date:** `{scan.created_at}`")
        md.append(f"\n## Executive Summary")
        md.append(f"- **Overall Risk Score:** `{scan.overall_risk_score} / 100` (Grade **{scan.risk_grade}**)")
        md.append(f"- **Total Findings:** {scan.total_findings} (Critical: {scan.critical_count}, High: {scan.high_count}, Medium: {scan.medium_count}, Low: {scan.low_count})")

        if scan.score_explanation:
            se = scan.score_explanation
            md.append(f"\n### Transparent Scoring Breakdown")
            md.append(f"- **Formula:** {se.get('formula', 'Deterministic Multi-Dimensional Scoring')}")
            md.append(f"- **Raw Weighted Points:** {se.get('raw_weighted_points', scan.overall_risk_score)}")
            if se.get("critical_override_applied"):
                md.append(f"- **Critical Override:** Active (Score adjusted to critical floor of 70.0 due to confirmed critical vulnerability)")
            if se.get("status_breakdown"):
                sb = se["status_breakdown"]
                md.append(f"- **Finding Verification Statuses:** Confirmed: {sb.get('CONFIRMED', 0)}, Potential: {sb.get('POTENTIAL', 0)}, Requires Verification: {sb.get('REQUIRES_VERIFICATION', 0)}")

        md.append(f"\n### Well-Architected Dimension Scores")
        for dim, score in scan.dimension_scores.items():
            md.append(f"- **{dim.capitalize()}:** {score} / 100")

        if scan.compound_risks:
            md.append(f"\n## Compound Attack Vectors ({len(scan.compound_risks)})")
            for cr in scan.compound_risks:
                md.append(f"\n### [{cr.get('severity', 'CRITICAL')}] {cr.get('title', 'Compound Risk')}")
                md.append(f"- **Vector:** `{cr.get('vector', '')}`")
                md.append(f"- **Description:** {cr.get('description', '')}")
                md.append(f"- **Action:** {cr.get('recommended_action', '')}")

        if scan.discovered_resources:
            md.append(f"\n## Inspected Infrastructure Resources ({len(scan.discovered_resources)})")
            md.append("| Resource Type | Identifier | Line | Posture Status | Issues |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for r in scan.discovered_resources:
                ident = r.get("resource_id", r.get("resource_name", "unknown"))
                md.append(f"| `{r.get('resource_type')}` | `{ident}` | {r.get('line_number', '-')} | **{r.get('status')}** | {r.get('findings_count', 0)} |")

        md.append(f"\n## Detailed Security Findings & Mitigations")
        if not scan.findings:
            md.append("\n*No architectural weaknesses or security misconfigurations detected. Infrastructure conforms to Well-Architected baselines.*")
        else:
            for idx, f in enumerate(scan.findings, start=1):
                status_label = getattr(f, "finding_status", "CONFIRMED")
                conf_label = getattr(f, "confidence", "HIGH")
                line_info = f" (line {f.line_number})" if f.line_number else ""

                md.append(f"\n### {idx}. [{f.severity}] {f.title}")
                md.append(f"- **Rule ID:** `{f.rule_id}` ({f.rule_name})")
                md.append(f"- **Status:** `{status_label}` | **Confidence:** `{conf_label}` | **Method:** `{getattr(f, 'verification_method', 'STATIC_ANALYSIS_BLUEPRINT')}`")
                md.append(f"- **Dimension:** `{f.dimension}` | **Resource:** `{f.resource_id}` (`{f.resource_type}`){line_info}")
                if getattr(f, "actual_config", None):
                    md.append(f"- **Detected Config:** `{f.actual_config}`")
                if getattr(f, "expected_config", None):
                    md.append(f"- **Expected Config:** `{f.expected_config}`")
                md.append(f"- **Description:** {f.description}")
                md.append(f"- **Impact:** {f.impact}")
                md.append(f"- **Remediation:** {f.remediation_summary}")
                if f.remediation_code:
                    md.append(f"```terraform\n{f.remediation_code}\n```")
                if f.cli_command:
                    md.append(f"```bash\n{f.cli_command}\n```")

        md.append("\n---\n*Generated by CloudGuardAI Security & Posture Management Platform*")
        return "\n".join(md)

    @staticmethod
    def export_html(scan: ScanJob) -> str:
        rows = ""
        for idx, f in enumerate(scan.findings, start=1):
            sev_color = "#8B0000" if f.severity == "CRITICAL" else "#944800" if f.severity == "HIGH" else "#1D5872" if f.severity == "MEDIUM" else "#2D5A27"
            status_label = getattr(f, "finding_status", "CONFIRMED")
            status_bg = "#fbeae5" if status_label == "CONFIRMED" else "#fdf3d8" if status_label == "POTENTIAL" else "#eef4f8"
            status_color = "#8B0000" if status_label == "CONFIRMED" else "#8c6b12" if status_label == "POTENTIAL" else "#1D5872"

            code_block = f"<pre style='background:#f4efe6;padding:8px;font-size:12px;overflow-x:auto;border-radius:3px;'>{f.remediation_code}</pre>" if f.remediation_code else ""
            cli_block = f"<pre style='background:#f4efe6;padding:8px;font-size:12px;overflow-x:auto;border-radius:3px;'>{f.cli_command}</pre>" if f.cli_command else ""
            actual_cfg = f"<p style='font-size:12px;background:#faf8f5;padding:6px;border-left:3px solid #287fa3;margin:6px 0;'><strong>Detected:</strong> <code>{getattr(f, 'actual_config', '')}</code> | <strong>Expected:</strong> <code>{getattr(f, 'expected_config', '')}</code></p>" if getattr(f, "actual_config", None) else ""

            rows += f"""
            <div style="border:1px solid #e2ddd5;margin-bottom:14px;padding:16px;border-radius:4px;background:#fff;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <span style="font-weight:600;font-size:14px;">{idx}. {f.title}</span>
                <div>
                  <span style="background:{status_bg};color:{status_color};font-weight:600;font-size:11px;padding:3px 8px;border-radius:3px;margin-right:6px;">{status_label}</span>
                  <span style="color:{sev_color};font-weight:700;font-size:12px;">{f.severity}</span>
                </div>
              </div>
              <p style="font-size:12px;color:#5a6872;margin-bottom:6px;">Rule: <code>{f.rule_id}</code> | Resource: <code>{f.resource_id}</code> | Line: {f.line_number or '-'}</p>
              {actual_cfg}
              <p style="font-size:13px;margin-bottom:6px;"><strong>Impact:</strong> {f.impact}</p>
              <p style="font-size:13px;margin-bottom:6px;"><strong>Fix:</strong> {f.remediation_summary}</p>
              {code_block}
              {cli_block}
            </div>
            """

        compound_html = ""
        if scan.compound_risks:
            compound_rows = ""
            for cr in scan.compound_risks:
                compound_rows += f"""
                <div style="border:1px solid #dcc9a8;background:#faf7f0;padding:12px;border-radius:4px;margin-bottom:10px;">
                  <div style="font-weight:600;color:#8B0000;font-size:13px;">[{cr.get('severity')}] {cr.get('title')}</div>
                  <div style="font-size:12px;color:#5a6872;margin:4px 0;">Vector: <code>{cr.get('vector')}</code></div>
                  <div style="font-size:13px;">{cr.get('description')}</div>
                </div>
                """
            compound_html = f"""
            <h2 style="font-size:16px;margin-top:24px;border-bottom:1px solid #e2ddd5;padding-bottom:6px;">Compound Threat Chains</h2>
            {compound_rows}
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CloudGuardAI Audit Report - {scan.scan_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f1eb; color: #202a30; padding: 24px; line-height: 1.5; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #fff; padding: 32px; border: 1px solid #e2ddd5; border-radius: 4px; }}
    h1 {{ font-size: 20px; color: #202a30; margin-bottom: 4px; }}
    .badge {{ display: inline-block; padding: 4px 10px; background: #287fa3; color: #fff; font-weight: 600; border-radius: 3px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 13px; }}
    th, td {{ padding: 8px 12px; border: 1px solid #e2ddd5; text-align: left; }}
    th {{ background: #faf9f6; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>CloudGuardAI Security & Architecture Audit</h1>
    <p style="color:#5a6872;font-size:13px;">Target: {scan.target_name} | Generated: {scan.created_at}</p>

    <div style="margin: 20px 0; padding: 16px; background: #f4efe6; border-radius: 4px; display: flex; justify-content: space-around; text-align: center;">
      <div><div style="font-size:24px;font-weight:700;color:#287fa3;">{scan.overall_risk_score}</div><div style="font-size:12px;color:#5a6872;">Overall Risk Score</div></div>
      <div><div style="font-size:24px;font-weight:700;">{scan.risk_grade}</div><div style="font-size:12px;color:#5a6872;">Risk Grade</div></div>
      <div><div style="font-size:24px;font-weight:700;color:#8B0000;">{scan.critical_count}</div><div style="font-size:12px;color:#5a6872;">Critical Risks</div></div>
      <div><div style="font-size:24px;font-weight:700;">{scan.total_findings}</div><div style="font-size:12px;color:#5a6872;">Total Findings</div></div>
    </div>

    {compound_html}

    <h2 style="font-size:16px;margin-top:24px;border-bottom:1px solid #e2ddd5;padding-bottom:6px;">Detailed Findings ({scan.total_findings})</h2>
    {rows if rows else '<p style="color:#5a6872;font-size:13px;">No security vulnerabilities or architectural violations detected.</p>'}

    <div style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2ddd5; font-size: 11px; color: #5a6872; text-align: center;">
      Generated by CloudGuardAI Enterprise Posture Management Platform
    </div>
  </div>
</body>
</html>"""
        return html
