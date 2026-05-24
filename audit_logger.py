import os
import sqlite3
from contextlib import contextmanager

class EnterpriseAuditLogger:
    def __init__(self):
        self.db_url = os.getenv("DATABASE_URL", "sqlite:////app/data/veripatch.db").strip()

        if self.db_url.startswith(("postgres://", "postgresql://")):
            self.engine_mode = "POSTGRES"
            import psycopg2
            from psycopg2.extras import RealDictCursor
            self._pg = psycopg2
            self._pg_cursor_factory = RealDictCursor
        else:
            self.engine_mode = "SQLITE"
            self.sqlite_path = self.db_url.replace("sqlite:///", "").replace("sqlite://", "")
            if not self.sqlite_path:
                self.sqlite_path = "/app/data/veripatch.db"

        self._init_db()

    @contextmanager
    def _get_connection(self):
        if self.engine_mode == "POSTGRES":
            conn = self._pg.connect(self.db_url)
        else:
            conn = sqlite3.connect(self.sqlite_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        try:
            if self.engine_mode == "POSTGRES":
                with self._get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            CREATE TABLE IF NOT EXISTS remediation_logs (
                                id SERIAL PRIMARY KEY,
                                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                cve_id VARCHAR(255) NOT NULL,
                                target_file VARCHAR(255) NOT NULL,
                                sandbox_status VARCHAR(50) NOT NULL,
                                patch_sha256 VARCHAR(64) NOT NULL,
                                kms_signature VARCHAR(255) NOT NULL,
                                pr_url TEXT NOT NULL,
                                log_summary TEXT
                            );
                        """)
                print("🐘 [DB INIT] PostgreSQL connection verified.")
            else:
                db_dir = os.path.dirname(self.sqlite_path)
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)
                with self._get_connection() as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                            cve_id TEXT NOT NULL,
                            target_file TEXT NOT NULL,
                            sandbox_status TEXT NOT NULL,
                            patch_sha256 TEXT NOT NULL,
                            kms_signature TEXT NOT NULL,
                            pr_url TEXT NOT NULL,
                            log_summary TEXT
                        );
                    """)
                print("💾 [DB INIT] SQLite data volume verified.")
        except Exception as e:
            print(f"⚠️ [DB INIT ERROR] {e}")

    def log_remediation_event(
        self,
        cve_id: str,
        target_file: str,
        sandbox_status: str,
        patch_sha256: str,
        kms_signature: str,
        pr_url: str,
        log_summary: str,
    ):
        try:
            if self.engine_mode == "POSTGRES":
                with self._get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """INSERT INTO remediation_logs
                               (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary)
                               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                            (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary),
                        )
            else:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT INTO logs
                           (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary),
                    )
            print(f"💾 [AUDIT] Event recorded for {cve_id}")
        except Exception as e:
            print(f"❌ [AUDIT ERROR] Database write failed: {e}")

    def fetch_all_logs(self) -> list:
        try:
            if self.engine_mode == "POSTGRES":
                with self._get_connection() as conn:
                    with conn.cursor(cursor_factory=self._pg_cursor_factory) as cur:
                        cur.execute(
                            "SELECT timestamp::text, cve_id, target_file, sandbox_status, "
                            "kms_signature, pr_url FROM remediation_logs ORDER BY timestamp DESC;"
                        )
                        return [dict(row) for row in cur.fetchall()]
            else:
                with sqlite3.connect(self.sqlite_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cur = conn.execute(
                        "SELECT timestamp, cve_id, target_file, sandbox_status, "
                        "kms_signature, pr_url FROM logs ORDER BY timestamp DESC;"
                    )
                    return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            print(f"❌ [DB ERROR] Failed to fetch logs: {e}")
            return []
