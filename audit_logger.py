import os
import re
import sqlite3

class EnterpriseAuditLogger:
    def __init__(self):
        # Default to a local SQLite database path if no Cloud DB is supplied
        self.db_url = os.getenv("DATABASE_URL", "sqlite:////app/data/veripatch.db").strip()
        
        # Detect engine mode dynamically
        if self.db_url.startswith("postgres://") or self.db_url.startswith("postgresql://"):
            self.engine_mode = "POSTGRES"
            import psycopg2
            from psycopg2.extras import RealDictCursor
            self.pg_driver = psycopg2
            self.pg_cursor_factory = RealDictCursor
        else:
            self.engine_mode = "SQLITE"
            # Extract raw absolute file path out of the URI scheme string
            self.sqlite_path = self.db_url.replace("sqlite://", "").replace("sqlite:///", "")
            if not self.sqlite_path:
                self.sqlite_path = "/app/data/veripatch.db"

        self._init_db()

    def _init_db(self):
        """Creates table tracking parameters adaptively based on the active compute driver."""
        if self.engine_mode == "POSTGRES":
            try:
                conn = self.pg_driver.connect(self.db_url)
                cursor = conn.cursor()
                cursor.execute("""
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
                conn.commit()
                cursor.close()
                conn.close()
                print("🐘 [DB INIT] PostgreSQL Cluster Connection Verified.")
            except Exception as e:
                print(f"⚠️ [DATABASE INITIALIZATION ERROR] Cluster unreachable: {e}")
        else:
            # Fall back to localized zero-config SQLite mode execution
            os.makedirs(os.path.dirname(self.sqlite_path), exist_ok=True)
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            cursor.execute("""
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
            conn.commit()
            cursor.close()
            conn.close()
            print("💾 [DB INIT] Local SQLite data volume verified.")

    def log_remediation_event(self, cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary):
        """Streams cryptographic receipts into whichever data plane is currently active."""
        try:
            if self.engine_mode == "POSTGRES":
                conn = self.pg_driver.connect(self.db_url)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO remediation_logs (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary)
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                """, (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary))
            else:
                conn = sqlite3.connect(self.sqlite_path)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO logs (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """, (cve_id, target_file, sandbox_status, patch_sha256, kms_signature, pr_url, log_summary))
            
            conn.commit()
            cursor.close()
            conn.close()
            print(f"💾 [TELEMETRY COMMITTED] Audit row secured for {cve_id}")
        except Exception as e:
            print(f"❌ [TELEMETRY LOSS ERROR] Database write aborted: {e}")

    def fetch_all_logs(self):
        """Gathers records adaptively across either SQLite or Postgres storage contexts."""
        try:
            if self.engine_mode == "POSTGRES":
                conn = self.pg_driver.connect(self.db_url, cursor_factory=self.pg_cursor_factory)
                cursor = conn.cursor()
                cursor.execute("SELECT timestamp::text, cve_id, target_file, sandbox_status, kms_signature, pr_url FROM remediation_logs ORDER BY timestamp DESC;")
                records = [dict(row) for row in cursor.fetchall()]
            else:
                conn = sqlite3.connect(self.sqlite_path)
                conn.row_factory = sqlite3.Row  # Dict-like row mapping extraction helper
                cursor = conn.cursor()
                cursor.execute("SELECT timestamp, cve_id, target_file, sandbox_status, kms_signature, pr_url FROM logs ORDER BY timestamp DESC;")
                records = []
                for row in cursor.fetchall():
                    records.append({
                        "timestamp": str(row["timestamp"]),
                        "cve_id": row["cve_id"],
                        "target_file": row["target_file"],
                        "sandbox_status": row["sandbox_status"],
                        "kms_signature": row["kms_signature"],
                        "pr_url": row["pr_url"]
                    })
            cursor.close()
            conn.close()
            return records
        except Exception as e:
            print(f"❌ [DATABASE ERROR] Failed to extract logging stream: {e}")
            return []