"""
CloudGuardAI - Domain Models & Schemas
Defines core data models for Scans, Findings, Severity Counts, and Reports.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class Finding(BaseModel):
    finding_id: str
    scan_id: str
    rule_id: str
    rule_name: str
    dimension: str  # SECURITY, IAM, NETWORK, CONFIGURATION, RELIABILITY, PERFORMANCE, COST
    severity: str   # CRITICAL, HIGH, MEDIUM, LOW
    resource_id: str
    resource_type: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    title: str
    description: str  # Rationale
    impact: str
    remediation_summary: str
    remediation_code: Optional[str] = None
    cli_command: Optional[str] = None
    ai_remediation: Optional[str] = None
    remediation_source: str = "DETERMINISTIC"  # DETERMINISTIC or BEDROCK_AI
    line_number: Optional[int] = None
    created_at: str = Field(default_factory=utc_now_iso)

class ScanJob(BaseModel):
    scan_id: str
    scan_type: str = "IAC_STATIC"  # IAC_STATIC, LIVE_AWS
    target_name: str
    status: str = "COMPLETED"      # PENDING, PROCESSING, COMPLETED, FAILED
    overall_risk_score: float = 0.0
    risk_grade: str = "A"          # A, B, C, D, F
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    dimension_scores: Dict[str, float] = Field(default_factory=dict)
    unsupported_constructs: List[Dict[str, Any]] = Field(default_factory=list)
    discovered_resources: List[Dict[str, Any]] = Field(default_factory=list)
    discovery_summary: Dict[str, Any] = Field(default_factory=dict)
    file_key: Optional[str] = None
    storage_backend: str = "local"
    created_at: str = Field(default_factory=utc_now_iso)
    completed_at: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)
    error_message: Optional[str] = None
