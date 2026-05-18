import os
import sys
import re
import hmac
import hashlib
import uvicorn
from fastapi import FastAPI, Request, BackgroundTasks, Header, HTTPException
from fastapi.responses import HTMLResponse

# ---- CRITICAL INTERNAL MODULE IMPORTS ----
from audit_logger import EnterpriseAuditLogger
from main import VeriPatchEngine

# 1. Fetch secrets directly from the host system environment (NO hardcoded fallbacks!)
TRIVY_AUTH_TOKEN = os.getenv("TRIVY_AUTH_TOKEN")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_OWNER = os.getenv("GITHUB_OWNER")

# 2. Strict Configuration Audit: Fail-Fast if ANY critical key is missing
critical_secrets = {
    "TRIVY_AUTH_TOKEN": TRIVY_AUTH_TOKEN,
    "GITHUB_WEBHOOK_SECRET": GITHUB_WEBHOOK_SECRET,
    "OPENROUTER_API_KEY": OPENROUTER_API_KEY,
    "GITHUB_TOKEN": GITHUB_TOKEN,
    "GITHUB_OWNER": GITHUB_OWNER
}

missing_secrets = [key for key, value in critical_secrets.items() if not value]

if missing_secrets:
    print("\n" + "="*60)
    print("🚨 CRITICAL CONFIGURATION ERROR: ENVIRONMENT VARIABLES MISSING")
    print("="*60)
    for missing in missing_secrets:
        print(f"❌ Missing: Ensure 'export {missing}=\"your_value\"' is executed.")
    print("="*60)
    print("FATAL: Server startup aborted due to unconfigured security controls.\n")
    sys.exit(1) # Kill the server process instantly

# Initialize app ONLY if all validations pass cleanly
app = FastAPI(title="VeriPatch Autonomous Security Platform")

# @app.post("/webhooks/v1/snyk")
# async def handle_snyk_webhook(request: Request, background_tasks: BackgroundTasks, x_snyk_signature: str = Header(None)):
#     """
#     Production Ingestion for Snyk Enterprise Alerts.
#     Validates authenticity using Snyk HMAC keys.
#     """
#     raw_payload = await request.body()
    
#     if not verify_hmac_signature(raw_payload, SNYK_WEBHOOK_SECRET, x_snyk_signature, prefix=""):
#         raise HTTPException(status_code=401, detail="Invalid Snyk cryptographic signature handshake.")
        
#     payload = await request.json()
    
#     # Extract structural Snyk vulnerability details context models
#     # (Tailor this extraction block based on your specific Snyk webhook payload settings)
    
#     return {"status": "accepted"}

app = FastAPI(title="VeriPatch Autonomous Security Platform")
db_logger = EnterpriseAuditLogger()
engine = VeriPatchEngine(max_loops=3)
workflow_graph = engine.assemble_workflow()

def verify_hmac_signature(payload: bytes, secret: str, signature_header: str, prefix: str = "sha256=") -> bool:
    """Verifies that the incoming payload signature matches our stored enterprise secret."""
    if not secret or not signature_header:
        return False
    
    # Strip prefixes if provided (e.g., 'sha256=abcdef...' -> 'abcdef...')
    actual_signature = signature_header.replace(prefix, "")
    
    # Compute expected signature using HMAC-SHA256
    expected_signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # Use secure constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_signature, actual_signature)

@app.post("/webhooks/v1/github")
async def handle_github_webhook(request: Request, background_tasks: BackgroundTasks, x_hub_signature_256: str = Header(None)):
    """
    Production Ingestion for GitHub Organization Alerts (Dependabot/CodeQL).
    Validates payload authenticity using SHA256 HMAC keys.
    """
    raw_payload = await request.body()
    
    if not verify_hmac_signature(raw_payload, GITHUB_WEBHOOK_SECRET, x_hub_signature_256, prefix="sha256="):
        raise HTTPException(status_code=401, detail="Invalid GitHub cryptographic signature handshake.")
        
    payload = await request.json()
    
    # Filter for dependabot alert creation events
    if payload.get("action") == "created" and "alert" in payload:
        alert = payload["alert"]
        cve_id = alert.get("security_advisory", {}).get("cve_id", "CVE-UNKNOWN")
        target_file = alert.get("dependency", {}).get("manifest_path", "requirements.txt")
        repo_name = payload["repository"]["full_name"]
        
        background_tasks.add_task(
            run_async_remediation, 
            cve_id=cve_id, 
            target_file=target_file, 
            repository_path=f"git@github.com:{repo_name}.git"
        )
        
    return {"status": "processed"}

def run_async_remediation(cve_id: str, target_file: str, repository_path: str, vulnerability_details: str = None):
    """
    Background worker thread that prepares the sandbox workspace FIRST,
    injects live file context into the LangGraph state, and executes remediation.
    """
    repo_name_clean = repository_path.split("/")[-1].replace(".git", "")
    workspace_path = f"/tmp/veripatch_scratchpad/{repo_name_clean}"
    
    print(f"\n[BACKGROUND WORKER] Preparing sandbox environment for {cve_id}...")
    
    # 1. Pre-clone the target repository branch history tree structure 
    if os.path.exists(workspace_path):
        import shutil
        shutil.rmtree(workspace_path)
        
    github_token = os.getenv("GITHUB_TOKEN")
    github_owner = os.getenv("GITHUB_OWNER")
    repo_url = f"https://x-access-token:{github_token}@github.com/{github_owner}/{repo_name_clean}.git"
    
    print(f"📥 [WORKSPACE] Cloning {repo_name_clean} to fetch live configuration state...")
    os.system(f"git clone {repo_url} {workspace_path}")
    
    # 2. Read the existing target file content so the AI doesn't work in a vacuum
    # 2. 🛡️ Read the existing target file content defensively against encoding variances
    file_full_path = os.path.join(workspace_path, target_file)
    current_file_content = ""
    
    if os.path.exists(file_full_path):
        try:
            # 1st Attempt: Try standard UTF-8 (handling potential hidden BOM signatures safely)
            with open(file_full_path, "r", encoding="utf-8-sig") as f:
                current_file_content = f.read()
        except UnicodeDecodeError:
            try:
                # 2nd Attempt: Fallback to UTF-16 (fixes the exact 0xff byte start issue)
                print(f"🔄 [ENCODING] UTF-8 failed. Attempting UTF-16 decoder path for {target_file}...")
                with open(file_full_path, "r", encoding="utf-16") as f:
                    current_file_content = f.read()
            except UnicodeDecodeError:
                # Final Catch-All: Read as UTF-8 but drop/ignore unparseable bytes instead of crashing
                print(f"⚠️ [ENCODING] Binary anomalies detected. Reading with strict error stripping...")
                with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
                    current_file_content = f.read()
                    
        print(f"📖 [CONTEXT] Successfully ingested active baseline layout for {target_file}")
    else:
        print(f"⚠️ [WARN] Target path context {target_file} does not exist in target tree root.")

    # 3. Construct the state payload equipped with the actual file text
    execution_payload = {
        "cve_id": cve_id,
        "repository_path": repository_path,
        "max_iterations": 3,
        "verification_status": "PENDING",
        "human_approved": False,
        "vulnerable_file": target_file,
        "vulnerability_details": vulnerability_details or "Upgrade vulnerable package versions.",
        "current_patch_diff": "",
        "verification_logs": "",
        "iteration_count": 0,
        # ✨ PASS THE ACTUAL FILE TEXT CONTEXT AS THE STARTING POINT FOR THE AI
        "patched_code": current_file_content 
    }
    
    # 4. Execute the self-healing LangGraph agent loop with full context visibility
    print(f"🔮 [LANGGRAPH] Launching multi-agent patching loop...")
    final_state = workflow_graph.invoke(execution_payload)
    
    if final_state.get("verification_status") == "PASSED":
       print(f"✅ [SUCCESS] Patch passed sandbox verification checks. Deploying to GitHub...")

    else:
        print("\n" + "❌"*30)
        print(f"🚨 [PATCH REJECTED BY SANDBOX]: Verification Status: {final_state.get('verification_status')}")
        print(f"Target File: {final_state.get('vulnerable_file')}")
        print("═"*60)
        print("📝 [AGENT VERIFICATION LOGS]:")
        print(final_state.get("verification_logs", "No logs provided by the agent engine."))
        print("═"*60)
        print("❌"*30 + "\n")
        # 5. Generate immutable security tracking metrics
    signed_receipt = engine.signer.generate_verified_manifest(
        cve_id=final_state["cve_id"],
        repo=final_state["repository_path"],
        patch_diff=final_state["current_patch_diff"],
        log_summary=final_state["verification_logs"]
    )
    
    # 6. Commit code state locally inside the validation scratch folder workspace
    git_package = engine.git_provider.create_remediation_branch(
        repo_name=repo_name_clean,
        cve_id=final_state["cve_id"],
        target_file=final_state["vulnerable_file"],
        patched_code=final_state.get("patched_code", current_file_content),
        signed_manifest=signed_receipt
    )
    
    # 7. Push upstream and fire the GitHub API creation request endpoint
    pr_transaction = engine.git_provider.push_and_open_pr(
        repo_name=repo_name_clean,
        branch_name=git_package["target_branch"],
        pr_title=f"🛡️ [VeriPatch] Security Remediation for {final_state['cve_id']}",
        pr_body=git_package["pull_request_markdown"]
    )
    
    final_pr_url = pr_transaction.get("url") if pr_transaction.get("success") else "LOCAL_SIMULATION_MODE"
    
    # 8. Commit the immutable verification data straight to SQLite
    db_logger.log_remediation_event(
            cve_id=final_state["cve_id"],
            target_file=final_state["vulnerable_file"],
            sandbox_status=final_state.get("verification_status", "FAILED"),
            patch_sha256="FAILED_VERIFICATION",
            kms_signature="UNSIGNED",
            pr_url="REJECTED_BY_SANDBOX",
            log_summary=final_state.get("verification_logs", "Sandbox validation failed.")
        )
    print(f"[BACKGROUND WORKER] Completed processing event logs for {cve_id}. Database committed.")

@app.post("/webhooks/v1/trivy")
async def handle_trivy_webhook(request: Request, background_tasks: BackgroundTasks):
    # 1. Token Validation Gate
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed token")
    
    incoming_token = auth_header.split(" ")[1]
    if incoming_token != TRIVY_AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized token")
        
    # 2. Extract JSON Payload
    payload = await request.json()
    raw_artifact = payload.get("ArtifactName", "").strip()
    
    if not raw_artifact:
        return {"status": "ignored", "message": "Missing 'ArtifactName' identifier."}

    # 🔄 DYNAMIC PARSING CORE: Extract clean repo name from any Trivy format
    # Normalize paths (handles Windows vs Linux slashes) and strip trailing slashes
    normalized_path = raw_artifact.replace("\\", "/").rstrip("/")
    
    # Extract the last block of the path/string (e.g., "/workspaces/auth-service" -> "auth-service")
    base_name = normalized_path.split("/")[-1]
    
    # Clean off container tags or shas if present (e.g., "auth-service:latest" -> "auth-service")
    base_name = base_name.split(":")[0]
    base_name = base_name.split("@")[0]
    
    # Clean off '.git' extensions if scanned via repo URL
    base_name = base_name.replace(".git", "")

    # Construct the full target repository path slug using the environment owner context
    artifact_name = f"{GITHUB_OWNER}/{base_name}"
    print(f"🎯 [DYNAMIC INGESTION] Computed Destination Target: {artifact_name}")

    # 3. Pull out vulnerability vectors
    results = payload.get("Results", [])
    if not results:
        return {"status": "ignored", "message": "No scan results found in payload data."}
        
    first_target = results[0]
    target_file = first_target.get("Target", "requirements.txt")
    vulnerabilities = first_target.get("Vulnerabilities", [])
    
    if not vulnerabilities:
        return {"status": "ignored", "message": "Zero active CVE signatures detected."}
        
    cve_id = vulnerabilities[0].get("VulnerabilityID", "CVE-UNKNOWN")
    repository_path = f"git@github.com:{artifact_name}.git"

    # 4. Hand off to the background thread worker
    background_tasks.add_task(
        run_async_remediation, 
        cve_id=cve_id, 
        target_file=target_file, 
        repository_path=repository_path
    )
    
    return {
        "status": "accepted", 
        "message": f"Autonomous remediation loop safely spawned for target {cve_id} in {artifact_name}."
    }

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    logs = db_logger.fetch_all_logs()
    log_rows_html = ""
    for item in logs:
        status_color = "bg-green-900/40 text-green-400 border-green-500/30" if item["sandbox_status"] == "PASSED" else "bg-red-900/40 text-red-400 border-red-500/30"
        
        # UI LOGIC: Check if it's a real live GitHub link or running in local simulation scratch folders
        # Replace the link element generation block inside serve_dashboard() in app.py:
        pr_url = item["pr_url"]
        if pr_url == "LOCAL_SIMULATION_MODE":
            link_element = '<span class="text-slate-500 italic text-xs">Local Dev Mode</span>'
        elif pr_url.startswith("GITHUB_ERROR:"):
            error_reason = pr_url.replace("GITHUB_ERROR:", "")
            link_element = f'<span class="text-red-400 font-semibold text-xs" title="{error_reason}">Failed: Check Logs</span>'
        else:
            link_element = f'<a href="{pr_url}" target="_blank" class="text-indigo-400 hover:underline font-semibold flex items-center gap-1">Open PR ↗</a>'
            
        log_rows_html += f"""
        <tr class="border-b border-slate-800 hover:bg-slate-900/50 transition">
            <td class="p-4 text-xs font-mono text-slate-400">{item["timestamp"][:19]}</td>
            <td class="p-4"><span class="px-2 py-1 text-xs font-bold font-mono bg-slate-800 text-indigo-400 rounded border border-slate-700">{item["cve_id"]}</span></td>
            <td class="p-4 text-sm font-mono text-slate-300">{item["target_file"]}</td>
            <td class="p-4"><span class="px-2 py-0.5 text-xs font-semibold rounded border {status_color}">{item["sandbox_status"]}</span></td>
            <td class="p-4 text-xs font-mono text-amber-500 max-w-xs truncate" title="{item["kms_signature"]}">{item["kms_signature"][:20]}...</td>
            <td class="p-4 text-sm">{link_element}</td>
        </tr>
        """
    if not log_rows_html:
        log_rows_html = '<tr><td colspan="6" class="p-8 text-center text-sm text-slate-500">No logs matching tracking records found.</td></tr>'

    dashboard_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>VeriPatch | Enterprise AI Security Console</title>
        <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen font-sans">
        <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur px-6 py-4 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <span class="text-xl font-black tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">VERIPATCH</span>
                <span class="text-xs px-2 py-0.5 font-bold uppercase bg-indigo-950 text-indigo-400 rounded-full border border-indigo-500/30">Management Plane</span>
            </div>
            <div class="text-xs text-slate-400 font-mono">System Engine Status: <span class="text-green-400 font-bold">● ONLINE</span></div>
        </nav>
        <main class="max-w-7xl mx-auto px-6 py-10">
            <header class="mb-8">
                <h1 class="text-2xl font-bold tracking-tight">Immutable Compliance Audit Logs</h1>
                <p class="text-sm text-slate-400 mt-1">SIEM-ready execution logs representing cryptographic verification and compile-pass receipts.</p>
            </header>
            <div class="bg-slate-900/40 rounded-xl border border-slate-800 shadow-xl overflow-hidden">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-900 border-b border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-400">
                            <th class="p-4">Timestamp</th>
                            <th class="p-4">Vulnerability ID</th>
                            <th class="p-4">Remediation Source File</th>
                            <th class="p-4">Sandbox Test</th>
                            <th class="p-4">KMS Cryptographic Proof</th>
                            <th class="p-4">Upstream Target</th>
                        </tr>
                    </thead>
                    <tbody>{log_rows_html}</tbody>
                </table>
            </div>
        </main>
    </body>
    </html>
    """
    return HTMLResponse(content=dashboard_html, status_code=200)

if __name__ == "__main__":
    server_port = int(os.getenv("PORT", 8080))
    server_host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app:app", host=server_host, port=server_port, reload=True)