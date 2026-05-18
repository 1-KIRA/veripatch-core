import sqlite3
import json
import os
from datetime import datetime

DB_PATH = "/tmp/veripatch_workspace/veripatch_enterprise.db"

class EnterpriseAuditLogger:
    def __init__(self):
        # Ensure workspace path exists
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(DB_PATH)

    def _init_db(self):
        """Initializes the structural compliance logging ledger table."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    target_file TEXT NOT NULL,
                    sandbox_status TEXT NOT NULL,
                    patch_sha256 TEXT,
                    kms_signature TEXT,
                    pr_url TEXT,
                    full_log_summary TEXT
                )
            """)
            conn.commit()

    def log_remediation_event(self, cve_id: str, target_file: str, sandbox_status: str, patch_sha256: str, kms_signature: str, pr_url: str, log_summary: str):
        """Commits an immutable record of an AI remediation execution trace."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, full_log_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.utcnow().isoformat(),
                cve_id,
                target_file,
                sandbox_status,
                patch_sha256,
                kms_signature,
                pr_url,
                log_summary
            ))
            conn.commit()

    def fetch_all_logs(self):
        """Queries database rows formatted as clean dictionary models for API consumption."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]