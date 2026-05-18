from pydantic import BaseModel
from typing import Dict, Any

class UnifiedCVEPayload(BaseModel):
    cve_id: str
    source_provider: str          # e.g., "snyk", "trivy", "github_alerts"
    repository_url: str           # e.g., "git@github.com:org/repo.git"
    target_branch: str            # e.g., "main"
    vulnerable_file_path: str     # Matched file path if provided by scanner
    vulnerability_details: str    # Description of the flaw and reachability vector
    raw_metadata: Dict[str, Any]  # Fallback for debugging vendor-specific data