import os
import json
import hmac
import hashlib
from fastapi import FastAPI, Request, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

# Import our LangGraph engine core from main.py
from main import VeriPatchEngine
from ingestion_router import UnifiedCVEPayload # Assumes defined in models or locally

app = FastAPI(title="VeriPatch Multi-Source Ingestion Gateway")
patch_engine = VeriPatchEngine(max_loops=3)
executable_graph = patch_engine.assemble_workflow()

# Enterprise Secrets Configuration (Normally from KMS / Vault)
WEBHOOK_SECRETS = {
    "snyk": os.getenv("SNYK_WEBHOOK_SECRET", "secret_snyk_token"),
    "github": os.getenv("GITHUB_WEBHOOK_SECRET", "secret_github_token"),
    "trivy": os.getenv("TRIVY_AUTH_TOKEN", "secret_trivy_token")
}

def trigger_remediation(payload: UnifiedCVEPayload):
    """Feeds the standardized payload directly into the LangGraph loop."""
    print(f"\n[ORCHESTRATOR ACTIVATED] Processing standardized payload from {payload.source_provider.upper()}")
    
    graph_input = {
        "cve_id": payload.cve_id,
        "repository_path": payload.repository_url,
        "max_iterations": 3,
        "verification_status": "PENDING",
        "human_approved": False,
        "vulnerability_details": payload.vulnerability_details,
        "current_patch_diff": "",
        "verification_logs": "",
        "iteration_count": 0
    }
    executable_graph.invoke(graph_input)

# ──────────────────────────────────────────────────────────────────────
# 1. SNYK ADAPTER ENDPOINT
# ──────────────────────────────────────────────────────────────────────
@app.post("/webhooks/v1/snyk")
async def handle_snyk_alert(request: Request, background_tasks: BackgroundTasks, x_hub_signature: Optional[str] = Header(None)):
    body_bytes = await request.body()
    
    # Signature Verification
    computed_hmac = hmac.new(WEBHOOK_SECRETS["snyk"].encode(), msg=body_bytes, digestmod=hashlib.sha256).hexdigest()
    if not x_hub_signature or not hmac.compare_digest(x_hub_signature.replace("sha256=", ""), computed_hmac):
        raise HTTPException(status_code=401, detail="Invalid Snyk Signature")

    data = json.loads(body_bytes.decode())
    new_issues = data.get("newIssues", [])
    if not new_issues: return {"status": "ignored", "reason": "No new issues reported"}

    issue = new_issues[0]
    cves = issue.get("pkgVulnerabilityMedical", {}).get("identifiers", {}).get("CVE", [])
    
    # Normalize to Unified Schema
    unified_payload = UnifiedCVEPayload(
        cve_id=cves[0] if cves else "CVE-UNKNOWN",
        source_provider="snyk",
        repository_url=f"git@github.com:{data.get('project', {}).get('name')}.git",
        target_branch="main",
        vulnerable_file_path="", 
        vulnerability_details=issue.get("title", "Dependency Vulnerability"),
        raw_metadata=data
    )
    
    background_tasks.add_task(trigger_remediation, unified_payload)
    return {"status": "accepted"}

# ──────────────────────────────────────────────────────────────────────
# 2. GITHUB DEPENDABOT / ADVISORY ADAPTER ENDPOINT
# ──────────────────────────────────────────────────────────────────────
@app.post("/webhooks/v1/github")
async def handle_github_alert(request: Request, background_tasks: BackgroundTasks, x_hub_signature_256: Optional[str] = Header(None)):
    body_bytes = await request.body()
    
    # Signature Verification (GitHub uses HMAC-SHA256 signature prefixing)
    computed_hmac = hmac.new(WEBHOOK_SECRETS["github"].encode(), msg=body_bytes, digestmod=hashlib.sha256).hexdigest()
    if not x_hub_signature_256 or not hmac.compare_digest(x_hub_signature_256.replace("sha256=", ""), computed_hmac):
        raise HTTPException(status_code=401, detail="Invalid GitHub Signature")

    data = json.loads(body_bytes.decode())
    action = data.get("action")
    
    # Focus only on newly opened vulnerability alerts
    if action not in ["created", "opened"]:
        return {"status": "ignored", "reason": "Action not targeted for remediation"}

    alert = data.get("repository_vulnerability_alert", {})
    security_advisory = alert.get("security_advisory", {})
    cves = security_advisory.get("identifiers", [])
    cve_id = next((idx["value"] for idx in cves if idx["type"] == "CVE"), "CVE-UNKNOWN")

    # Normalize to Unified Schema
    unified_payload = UnifiedCVEPayload(
        cve_id=cve_id,
        source_provider="github_alerts",
        repository_url=data.get("repository", {}).get("ssh_url", ""),
        target_branch=data.get("repository", {}).get("default_branch", "main"),
        vulnerable_file_path=alert.get("dependency", {}).get("manifest_path", ""),
        vulnerability_details=security_advisory.get("description", "GitHub Security Advisory"),
        raw_metadata=data
    )

    background_tasks.add_task(trigger_remediation, unified_payload)
    return {"status": "accepted"}

# ──────────────────────────────────────────────────────────────────────
# 3. TRIVY (CI/CD PIPELINE REPORT) ENDPOINT
# ──────────────────────────────────────────────────────────────────────
@app.post("/webhooks/v1/trivy")
async def handle_trivy_report(payload: dict, background_tasks: BackgroundTasks, authorization: Optional[str] = Header(None)):
    # Simple Token Token Auth (Commonly used inside private CI pipelines via curl/webhooks)
    if not authorization or authorization != f"Bearer {WEBHOOK_SECRETS['trivy']}":
        raise HTTPException(status_code=401, detail="Unauthorized Trivy Payload Submission")

    # Trivy reports vulnerabilities inside structures matching target objects
    results = payload.get("Results", [])
    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
            if not cve_id or not cve_id.startswith("CVE"): continue

            # Normalize to Unified Schema
            unified_payload = UnifiedCVEPayload(
                cve_id=cve_id,
                source_provider="trivy",
                repository_url=payload.get("ArtifactName", "unknown/image-context"),
                target_branch="main",
                vulnerable_file_path=result.get("Target", ""),
                vulnerability_details=f"Package: {vuln.get('PkgName')} -> Fixed Version: {vuln.get('FixedVersion')}. Title: {vuln.get('Title')}",
                raw_metadata=vuln
            )
            
            # Fire remediation execution threads for target alerts immediately
            background_tasks.add_task(trigger_remediation, unified_payload)
            
    return {"status": "accepted", "message": "Trivy scan findings processed successfully"}