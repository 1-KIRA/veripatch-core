import os
import json
import hmac
import hashlib
from fastapi import FastAPI, Request, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

from main import VeriPatchEngine
from ingestion_router import UnifiedCVEPayload

app = FastAPI(title="VeriPatch Multi-Source Ingestion Gateway")
patch_engine = VeriPatchEngine(max_loops=3)
executable_graph = patch_engine.assemble_workflow()

WEBHOOK_SECRETS = {
    "snyk": os.getenv("SNYK_WEBHOOK_SECRET", ""),
    "github": os.getenv("GITHUB_WEBHOOK_SECRET", ""),
    "trivy": os.getenv("TRIVY_AUTH_TOKEN", ""),
}


def trigger_remediation(payload: UnifiedCVEPayload):
    print(f"\n[ORCHESTRATOR] Processing payload from {payload.source_provider.upper()}")
    graph_input = {
        "cve_id": payload.cve_id,
        "repository_path": payload.repository_url,
        "vulnerable_file": payload.vulnerable_file_path,
        "vulnerability_details": payload.vulnerability_details,
        "max_iterations": 3,
        "iteration_count": 0,
        "verification_status": "PENDING",
        "human_approved": False,
        "current_patch_diff": "",
        "verification_logs": "",
        "patched_code": "",
        "original_code": "",
    }
    executable_graph.invoke(graph_input)


def _verify_hmac(secret: str, body: bytes, signature_header: Optional[str]) -> bool:
    if not secret:
        raise HTTPException(status_code=500, detail="Webhook secret not configured on server.")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header.")
    expected = hmac.new(secret.encode(), msg=body, digestmod=hashlib.sha256).hexdigest()
    provided = signature_header.replace("sha256=", "")
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")


# ── SNYK ──────────────────────────────────────────────────────────────────────
@app.post("/webhooks/v1/snyk")
async def handle_snyk_alert(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature: Optional[str] = Header(None),
):
    body_bytes = await request.body()
    _verify_hmac(WEBHOOK_SECRETS["snyk"], body_bytes, x_hub_signature)

    data = json.loads(body_bytes.decode())
    new_issues = data.get("newIssues", [])
    if not new_issues:
        return {"status": "ignored", "reason": "No new issues reported"}

    issue = new_issues[0]
    cves = issue.get("pkgVulnerabilityMedical", {}).get("identifiers", {}).get("CVE", [])

    unified = UnifiedCVEPayload(
        cve_id=cves[0] if cves else "CVE-UNKNOWN",
        source_provider="snyk",
        repository_url=f"git@github.com:{data.get('project', {}).get('name')}.git",
        target_branch="main",
        vulnerable_file_path="",
        vulnerability_details=issue.get("title", "Dependency vulnerability"),
        raw_metadata=data,
    )
    background_tasks.add_task(trigger_remediation, unified)
    return {"status": "accepted"}


# ── GITHUB DEPENDABOT / ADVISORY ───────────────────────────────────────────────
@app.post("/webhooks/v1/github")
async def handle_github_alert(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
):
    body_bytes = await request.body()
    _verify_hmac(WEBHOOK_SECRETS["github"], body_bytes, x_hub_signature_256)

    data = json.loads(body_bytes.decode())
    action = data.get("action")
    if action not in ["created", "opened"]:
        return {"status": "ignored", "reason": "Action not targeted for remediation"}

    alert = data.get("repository_vulnerability_alert", {})
    security_advisory = alert.get("security_advisory", {})
    identifiers = security_advisory.get("identifiers", [])
    cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "CVE-UNKNOWN")

    unified = UnifiedCVEPayload(
        cve_id=cve_id,
        source_provider="github_alerts",
        repository_url=data.get("repository", {}).get("ssh_url", ""),
        target_branch=data.get("repository", {}).get("default_branch", "main"),
        vulnerable_file_path=alert.get("dependency", {}).get("manifest_path", ""),
        vulnerability_details=security_advisory.get("description", "GitHub Security Advisory"),
        raw_metadata=data,
    )
    background_tasks.add_task(trigger_remediation, unified)
    return {"status": "accepted"}


# ── TRIVY ─────────────────────────────────────────────────────────────────────
@app.post("/webhooks/v1/trivy")
async def handle_trivy_report(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: Optional[str] = Header(None),
):
    secret = WEBHOOK_SECRETS["trivy"]
    if not secret:
        raise HTTPException(status_code=500, detail="TRIVY_AUTH_TOKEN not configured.")

    provided_token = ""
    if authorization:
        parts = authorization.split(" ", 1)
        provided_token = parts[1] if len(parts) == 2 else ""

    if not hmac.compare_digest(provided_token, secret):
        raise HTTPException(status_code=401, detail="Unauthorized Trivy payload.")

    payload = await request.json()
    results = payload.get("Results", [])

    for result in results:
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id.startswith("CVE"):
                continue
            unified = UnifiedCVEPayload(
                cve_id=cve_id,
                source_provider="trivy",
                repository_url=payload.get("ArtifactName", "unknown/image"),
                target_branch="main",
                vulnerable_file_path=result.get("Target", ""),
                vulnerability_details=(
                    f"Package: {vuln.get('PkgName')} "
                    f"— Fixed Version: {vuln.get('FixedVersion')}. "
                    f"{vuln.get('Title', '')}"
                ),
                raw_metadata=vuln,
            )
            background_tasks.add_task(trigger_remediation, unified)

    return {"status": "accepted", "message": "Trivy scan findings queued for remediation."}
