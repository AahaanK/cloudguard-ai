"""
CloudGuardAI - Unified Persistence Repository
Coordinates between Amazon DynamoDB and Local SQLite persistence.
Automatically falls back to SQLite when DynamoDB is offline or table is unprovisioned.
"""

import sqlite3
import os
import json
import logging
from typing import List, Optional, Dict, Any

from .models import ScanJob, Finding
from .dynamodb_service import DynamoDBService
from ..config import settings
from ..aws.session_manager import aws_session_manager

logger = logging.getLogger("cloudguard.database")

class SQLiteRepository:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            storage_dir = os.path.abspath(settings.storage_local_dir)
            os.makedirs(storage_dir, exist_ok=True)
            self.db_path = os.path.join(storage_dir, "cloudguard.db")
        else:
            self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                status TEXT NOT NULL,
                overall_risk_score REAL NOT NULL,
                risk_grade TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                dimension_scores TEXT NOT NULL,
                unsupported_constructs TEXT DEFAULT '[]',
                discovered_resources TEXT DEFAULT '[]',
                discovery_summary TEXT DEFAULT '{}',
                file_key TEXT,
                storage_backend TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT
            )
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                dimension TEXT NOT NULL,
                severity TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                evidence TEXT DEFAULT '{}',
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                impact TEXT NOT NULL,
                remediation_summary TEXT NOT NULL,
                remediation_code TEXT,
                cli_command TEXT,
                line_number INTEGER,
                ai_remediation TEXT,
                remediation_source TEXT DEFAULT 'DETERMINISTIC',
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
            """)

            # Auto-migrate columns if missing
            cursor.execute("PRAGMA table_info(scans)")
            scan_cols = [c["name"] for c in cursor.fetchall()]
            if "unsupported_constructs" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN unsupported_constructs TEXT DEFAULT '[]'")
            if "discovered_resources" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN discovered_resources TEXT DEFAULT '[]'")
            if "discovery_summary" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN discovery_summary TEXT DEFAULT '{}'")
            if "score_explanation" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN score_explanation TEXT DEFAULT '{}'")
            if "check_statistics" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN check_statistics TEXT DEFAULT '{}'")
            if "compound_risks" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN compound_risks TEXT DEFAULT '[]'")
            if "corrected_file_key" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN corrected_file_key TEXT")
            if "corrected_content" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN corrected_content TEXT")
            if "staged_remediations" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN staged_remediations TEXT DEFAULT '{}'")
            if "comparison_data" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN comparison_data TEXT DEFAULT '{}'")
            if "parent_scan_id" not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN parent_scan_id TEXT")

            cursor.execute("PRAGMA table_info(findings)")
            find_cols = [c["name"] for c in cursor.fetchall()]
            if "evidence" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN evidence TEXT DEFAULT '{}'")
            if "ai_remediation" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN ai_remediation TEXT")
            if "remediation_source" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN remediation_source TEXT DEFAULT 'DETERMINISTIC'")
            if "remediation_status" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN remediation_status TEXT DEFAULT 'Not Started'")
            if "remediation_preview" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN remediation_preview TEXT DEFAULT '{}'")
            if "remediation_history" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN remediation_history TEXT DEFAULT '[]'")
            if "file_name" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN file_name TEXT")
            if "actual_config" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN actual_config TEXT")
            if "expected_config" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN expected_config TEXT")
            if "confidence" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'HIGH'")
            if "finding_status" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN finding_status TEXT DEFAULT 'CONFIRMED'")
            if "verification_method" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN verification_method TEXT DEFAULT 'STATIC_ANALYSIS_BLUEPRINT'")
            if "verification_details" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN verification_details TEXT DEFAULT '{}'")
            if "related_resources" not in find_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN related_resources TEXT DEFAULT '[]'")

            conn.commit()
        finally:
            conn.close()

    def save_scan(self, scan: ScanJob) -> ScanJob:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, scan_type, target_name, status, overall_risk_score, risk_grade,
                total_findings, critical_count, high_count, medium_count, low_count,
                dimension_scores, unsupported_constructs, discovered_resources, discovery_summary,
                score_explanation, check_statistics, compound_risks,
                corrected_file_key, corrected_content, staged_remediations, comparison_data, parent_scan_id,
                file_key, storage_backend, created_at, completed_at, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.scan_id, scan.scan_type, scan.target_name, scan.status, scan.overall_risk_score,
                scan.risk_grade, scan.total_findings, scan.critical_count, scan.high_count,
                scan.medium_count, scan.low_count, json.dumps(scan.dimension_scores),
                json.dumps(scan.unsupported_constructs),
                json.dumps(scan.discovered_resources),
                json.dumps(scan.discovery_summary),
                json.dumps(scan.score_explanation or {}),
                json.dumps(scan.check_statistics or {}),
                json.dumps(scan.compound_risks or []),
                scan.corrected_file_key,
                scan.corrected_content,
                json.dumps(scan.staged_remediations or {}),
                json.dumps(scan.comparison_data or {}),
                scan.parent_scan_id,
                scan.file_key,
                scan.storage_backend, scan.created_at, scan.completed_at, scan.error_message
            ))

            for f in scan.findings:
                cursor.execute("""
                INSERT OR REPLACE INTO findings (
                    finding_id, scan_id, rule_id, rule_name, dimension, severity,
                    resource_id, resource_type, evidence, title, description, impact,
                    remediation_summary, remediation_code, cli_command, line_number,
                    created_at, ai_remediation, remediation_source,
                    remediation_status, remediation_preview, remediation_history,
                    file_name, actual_config, expected_config, confidence, finding_status,
                    verification_method, verification_details, related_resources
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.finding_id, scan.scan_id, f.rule_id, f.rule_name, f.dimension, f.severity,
                    f.resource_id, f.resource_type, json.dumps(f.evidence), f.title, f.description, f.impact,
                    f.remediation_summary, f.remediation_code, f.cli_command, f.line_number,
                    f.created_at, f.ai_remediation, f.remediation_source,
                    f.remediation_status, json.dumps(f.remediation_preview or {}), json.dumps(f.remediation_history or []),
                    f.file_name, f.actual_config, f.expected_config, f.confidence, f.finding_status,
                    f.verification_method, json.dumps(f.verification_details or {}), json.dumps(f.related_resources or [])
                ))
            conn.commit()
        finally:
            conn.close()
        return scan

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END", (scan_id,))
            finding_rows = cursor.fetchall()
            findings = []
            for fr in finding_rows:
                f_data = dict(fr)
                for json_col in ("evidence", "verification_details", "related_resources", "remediation_preview", "remediation_history"):
                    if isinstance(f_data.get(json_col), str):
                        try:
                            f_data[json_col] = json.loads(f_data[json_col])
                        except Exception:
                            f_data[json_col] = [] if json_col in ("related_resources", "remediation_history") else {}
                findings.append(Finding(**f_data))

            data = dict(row)
            data["dimension_scores"] = json.loads(data["dimension_scores"])
            for col, default_val in [
                ("unsupported_constructs", []),
                ("discovered_resources", []),
                ("discovery_summary", {}),
                ("score_explanation", {}),
                ("check_statistics", {}),
                ("compound_risks", []),
                ("staged_remediations", {}),
                ("comparison_data", {})
            ]:
                if isinstance(data.get(col), str):
                    try:
                        data[col] = json.loads(data[col])
                    except Exception:
                        data[col] = default_val
                elif data.get(col) is None:
                    data[col] = default_val

            data["findings"] = findings
            return ScanJob(**data)
        finally:
            conn.close()

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[ScanJob]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
            rows = cursor.fetchall()
            scans = []
            for r in rows:
                data = dict(r)
                data["dimension_scores"] = json.loads(data["dimension_scores"])
                for col, default_val in [
                    ("unsupported_constructs", []),
                    ("discovered_resources", []),
                    ("discovery_summary", {}),
                    ("score_explanation", {}),
                    ("check_statistics", {}),
                    ("compound_risks", []),
                    ("staged_remediations", {}),
                    ("comparison_data", {})
                ]:
                    if isinstance(data.get(col), str):
                        try:
                            data[col] = json.loads(data[col])
                        except Exception:
                            data[col] = default_val
                    elif data.get(col) is None:
                        data[col] = default_val
                data["findings"] = []
                scans.append(ScanJob(**data))
            return scans
        finally:
            conn.close()

    def get_summary_metrics(self) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS total_scans, AVG(overall_risk_score) AS avg_score, SUM(critical_count) AS total_critical, SUM(high_count) AS total_high, SUM(medium_count) AS total_medium, SUM(low_count) AS total_low FROM scans")
            row = cursor.fetchone()

            cursor.execute("SELECT rule_id, rule_name, dimension, severity, COUNT(*) as count FROM findings GROUP BY rule_id ORDER BY count DESC LIMIT 5")
            top_findings = [dict(r) for r in cursor.fetchall()]

            total_scans = row["total_scans"] or 0
            avg_score = round(row["avg_score"] or 0.0, 1)

            return {
                "total_scans": total_scans,
                "average_risk_score": avg_score,
                "total_critical": row["total_critical"] or 0,
                "total_high": row["total_high"] or 0,
                "total_medium": row["total_medium"] or 0,
                "total_low": row["total_low"] or 0,
                "top_breach_vectors": top_findings
            }
        finally:
            conn.close()

class DatabaseManager:
    """Coordinates persistence between DynamoDB and SQLite."""

    def __init__(self):
        self.sqlite = SQLiteRepository()
        self.dynamodb = DynamoDBService(table_name=settings.aws.dynamodb_table)

    @property
    def should_use_dynamodb(self) -> bool:
        if settings.database_backend != "dynamodb":
            return False
        health = self.dynamodb.check_table_health()
        return bool(health.get("accessible"))

    def save_scan(self, scan: ScanJob) -> ScanJob:
        # Always save to SQLite for local fast querying & metrics aggregation
        self.sqlite.save_scan(scan)

        if self.should_use_dynamodb:
            try:
                owner = aws_session_manager.verify_identity().get("account_id", "default_user")
                self.dynamodb.save_scan(scan, owner_id=owner)
            except Exception as e:
                logger.warning(f"DynamoDB save skipped: {str(e)}")
        return scan

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        # If DynamoDB is active, attempt retrieval
        if self.should_use_dynamodb:
            try:
                scan = self.dynamodb.get_scan(scan_id)
                if scan:
                    return scan
            except Exception:
                pass
        return self.sqlite.get_scan(scan_id)

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[ScanJob]:
        if self.should_use_dynamodb:
            try:
                scans, _ = self.dynamodb.list_scans(limit=limit)
                if scans:
                    return scans
            except Exception:
                pass
        return self.sqlite.list_scans(limit=limit, offset=offset)

    def get_summary_metrics(self) -> Dict[str, Any]:
        return self.sqlite.get_summary_metrics()

    def status(self) -> Dict[str, Any]:
        ddb_health = self.dynamodb.check_table_health()
        return {
            "active_backend": "dynamodb" if self.should_use_dynamodb else "sqlite",
            "configured_backend": settings.database_backend,
            "dynamodb_health": ddb_health,
            "sqlite_db_path": self.sqlite.db_path
        }

repository = DatabaseManager()
