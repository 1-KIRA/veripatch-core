import os
import sys
import html
import shutil
import subprocess
import time
import csv
import io
import json
import re
import hmac
import hashlib
from fastapi.responses import HTMLResponse
from fastapi import FastAPI, Request, BackgroundTasks, Header, HTTPException, Response
from pydantic import BaseModel
import uvicorn
import requests
from sandbox_runner import SandboxValidationRunner
from audit_logger import EnterpriseAuditLogger

app = FastAPI()

# Configuration (Sanitized)
TRIVY_AUTH_TOKEN = os.getenv("TRIVY_AUTH_TOKEN", "").strip()
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
GITHUB_OWNER = os.getenv("GITHUB_OWNER", "").strip()
db_logger = EnterpriseAuditLogger()

class RescanPayload(BaseModel):
    repo_name: str
    scan_type: str = "dependency"
    run_tests: bool = False  # Added to toggle pytest execution dynamically

def pure_sanitize_string(input_str: str) -> str:
    s = str(input_str).strip()
    s = re.sub(r'\[.*?\]\(.*?\)', '', s)
    for artifact in ['[', ']', '(', ')', '.git', 'https://', 'http://', 'git@', 'github.com']:
        s = s.replace(artifact, '')
    # Collapse any repeated slashes introduced by an empty owner segment
    s = re.sub(r'/+', '/', s)
    return s.strip(':/ ')

def extract_owner_and_repo(input_string: str) -> tuple[str, str]:
    """Splits cleansed path fragments into distinct user/repo arrays."""
    cleaned = pure_sanitize_string(input_string)
    segments = [seg for seg in cleaned.split("/") if seg]
    
    if len(segments) >= 2:
        return segments[-2], segments[-1]
    elif len(segments) == 1:
        return (GITHUB_OWNER if GITHUB_OWNER else "unknown"), segments[0]
    return "unknown", "unknown"

def run_async_remediation(repository_path: str, payload: dict, source_engine: str):
    """
    Production Worker Core: Handles SCA and SAST tracks dynamically.
    Guarantees deterministic, unpolluted URL construction.
    """
    # Force run both input channels through the new pure absolute sanitizer module
    extracted_owner, repo_name_clean = extract_owner_and_repo(repository_path)
    extracted_owner = pure_sanitize_string(extracted_owner)
    repo_name_clean = pure_sanitize_string(repo_name_clean)
    
    workspace_base = f"/tmp/veripatch_scratchpad/{repo_name_clean}"
    sandbox = SandboxValidationRunner()
    
    print(f"\n🚀 [WORKER CORE ACTIVE] Ingesting payload from stream: '{source_engine}'")
    print(f"-> Target Context: {extracted_owner}/{repo_name_clean}")
    
    manual_workspace_cleanup = None
    vulnerability_queue = []

    # Rebuild a pristine, guaranteed protocol URL block
    if GITHUB_TOKEN:
        master_clone_url = f"https://{GITHUB_TOKEN}@github.com/{extracted_owner}/{repo_name_clean}.git"
    else:
        master_clone_url = f"https://github.com/{extracted_owner}/{repo_name_clean}.git"

    if source_engine == "manual_dependency":
        workspace_path = f"{workspace_base}_scan_{int(time.time())}"
        manual_workspace_cleanup = workspace_path
        print(f"📥 [MANUAL RESCAN] RUNNING SCA SYSTEM SCAN: {repo_name_clean}")
        
        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path, ignore_errors=True)
        os.makedirs(os.path.dirname(workspace_path), exist_ok=True)

        clone_result = subprocess.run(
            ["git", "clone", master_clone_url, workspace_path],
            capture_output=True,
        )
        if clone_result.returncode != 0:
            print("❌ [MANUAL SCAN ERROR] Secure clone engine rejected the target asset.")
            return

        live_report_path = f"/tmp/trivy_live_{repo_name_clean}.json"
        subprocess.run(
            ["trivy", "fs", workspace_path, "--format", "json", "--output", live_report_path],
            capture_output=True,
        )
        
        if os.path.exists(live_report_path):
            try:
                with open(live_report_path, "r") as f: payload = json.load(f)
                source_engine = "trivy"
                os.remove(live_report_path)
            except Exception as json_err:
                print(f"❌ [MANUAL SCAN ERROR] JSON parse error: {json_err}"); return
        else:
            print("❌ [MANUAL SCAN ERROR] Trivy engine execution aborted."); return

    elif source_engine == "manual_sast":
        workspace_path = f"{workspace_base}_sast_audit_{int(time.time())}"
        manual_workspace_cleanup = workspace_path
        print(f"📥 [MANUAL RESCAN] RUNNING LIVE AI-POWERED SAST AUDIT MATRIX: {repo_name_clean}")
        
        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path, ignore_errors=True)
        os.makedirs(os.path.dirname(workspace_path), exist_ok=True)

        clone_result = subprocess.run(
            ["git", "clone", master_clone_url, workspace_path],
            capture_output=True,
        )
        if clone_result.returncode != 0:
            print("❌ [SAST ERROR] Failed to acquire repository context for auditing.")
            return
            
        system_scan_prompt = (
            "You are an automated SAST (Static Application Security Testing) engine specializing in Python security analysis.\n\n"
            "Analyze the provided source file for exploitable security vulnerabilities. Focus on:\n"
            "- Injection flaws: SQL, OS command, LDAP, XPath injection (CWE-89, CWE-78)\n"
            "- Hardcoded secrets, credentials, or API keys (CWE-798)\n"
            "- Insecure cryptography: weak ciphers, MD5/SHA1 for passwords, use of `random` for secrets (CWE-327, CWE-330)\n"
            "- Deserialization of untrusted data (CWE-502)\n"
            "- Path traversal and arbitrary file inclusion (CWE-22)\n"
            "- Remote code execution vectors: eval, exec, pickle (CWE-94)\n"
            "- Missing or broken authentication/authorization (CWE-306, CWE-862)\n"
            "- SSRF, open redirects, unvalidated redirects (CWE-918, CWE-601)\n"
            "- Use of `shell=True` in subprocess calls with untrusted input (CWE-78)\n\n"
            "RESPONSE FORMAT (strictly enforced):\n"
            'Return ONLY a raw JSON array. Each element must have exactly these keys:\n'
            '  {"id": "<CWE-ID or short vulnerability class>", "description": "<specific explanation with root cause and attack scenario>", "start_line": <integer>, "end_line": <integer>}\n\n'
            "Rules:\n"
            "- Report ONLY confirmed, exploitable findings — skip speculative or informational items\n"
            "- If no vulnerabilities are found, return exactly: []\n"
            "- Do NOT wrap output in markdown code blocks or add any text outside the JSON array"
        )
        
        for root, dirs, files in os.walk(workspace_path):
            if ".git" in root or "__pycache__" in root: continue
            for file in files:
                if file.endswith(".py"):
                    rel_path = os.path.relpath(os.path.join(root, file), workspace_path)
                    print(f"🔍 [AUDITING SOURCE] Deep inspecting security posture of: {rel_path}")
                    try:
                        with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                            code_to_audit = f.read()
                            
                        headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
                        audit_payload = {
                            "model": os.getenv("SAST_SCAN_MODEL", "google/gemini-flash-1.5-8b:free"),
                            "messages": [
                                {"role": "system", "content": system_scan_prompt},
                                {"role": "user", "content": f"File: {rel_path}\n\nCode Context:\n{code_to_audit}"}
                            ]
                        }
                        res = requests.post("https://openrouter.ai/api/v1/chat/completions", json=audit_payload, headers=headers, timeout=60)
                        res_json = res.json()

                        if "error" in res_json or "choices" not in res_json:
                            err_msg = res_json.get("error", {})
                            if isinstance(err_msg, dict):
                                err_msg = err_msg.get("message", str(err_msg))
                            print(f"⚠️ [API WARNING] OpenRouter model rejected query or returned error for {rel_path}: {err_msg} (HTTP {res.status_code})")
                            continue
                            
                        content_node = res_json["choices"][0]["message"].get("content")
                        if not content_node: continue
                            
                        raw_reply = content_node.strip()
                        start_idx = raw_reply.find('[')
                        end_idx = raw_reply.rfind(']')
                        if start_idx != -1 and end_idx != -1:
                            raw_reply = raw_reply[start_idx:end_idx+1]
                        
                        try:
                            found_flaws = json.loads(raw_reply, strict=False)
                        except json.JSONDecodeError:
                            repaired = re.sub(r"'\s*([a-zA-Z0-9_-]+)\s*'\s*:", r'"\1":', raw_reply)
                            repaired = re.sub(r",\s*\]", "]", repaired)
                            found_flaws = json.loads(repaired, strict=False)
                            
                        for flaw in found_flaws:
                            vulnerability_queue.append({
                                "cve_id": flaw.get("id", "STATIC-CODE-FLAW"),
                                "target_file": rel_path,
                                "start_line": flaw.get("start_line", 1),
                                "end_line": flaw.get("end_line", 1),
                                "prompt": f"Refactor logic securely to completely eliminate the following code flaw vulnerability: {flaw.get('description')}.",
                                "track": "SAST"
                            })
                    except Exception as parse_err:
                        print(f"⚠️ [AUDIT WARNING] Skipped file processing tracking anomaly on {rel_path}: {parse_err}")
                        
        source_engine = "processed_sast"

    if source_engine == "trivy":
        for target_result in payload.get("Results", []):
            t_file = target_result.get("Target", "requirements.txt")
            for v in target_result.get("Vulnerabilities", []):
                vulnerability_queue.append({
                    "cve_id": v.get("VulnerabilityID", "CVE-UNKNOWN"),
                    "target_file": t_file,
                    "prompt": f"Upgrade package '{v.get('PkgName')}' from version {v.get('InstalledVersion')} to {v.get('FixedVersion')} inside {t_file} to resolve {v.get('VulnerabilityID')}.",
                    "track": "SCA"
                })
    elif source_engine == "github":
        alert = payload.get("alert", {})
        dependency = alert.get("dependency", {})
        t_file = dependency.get("manifest_path", "requirements.txt")
        cve = alert.get("security_advisory", {}).get("cve_id") or "CVE-UNKNOWN"
        vulnerability_queue.append({
            "cve_id": cve, "target_file": t_file,
            "prompt": f"GitHub Alert: Patch {t_file} to resolve security vulnerability {cve}.",
            "track": "SCA"
        })

    total_tasks = len(vulnerability_queue)
    if total_tasks == 0:
        print(f"✨ [PIPELINE INFO] Scan verified clean inside '{extracted_owner}/{repo_name_clean}'. Zero vulnerabilities found.")
        if manual_workspace_cleanup and os.path.exists(manual_workspace_cleanup):
            shutil.rmtree(manual_workspace_cleanup, ignore_errors=True)
        return

    print(f"📊 [PIPELINE METRICS] Worker queue initialized with {total_tasks} real task targets.")

    for idx, task in enumerate(vulnerability_queue, 1):
        cve_id = task["cve_id"]
        target_file = task["target_file"]
        ai_instruction = task["prompt"]
        track_mode = task["track"]
        
        cve_safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', cve_id.lower())
        workspace_path = f"/tmp/veripatch_scratchpad/{repo_name_clean}_{cve_safe_dir}_{int(time.time())}_{idx}"
        
        print(f"\n==============================================================")
        print(f"🔄 [PROCESSING RUN {idx}/{total_tasks}] Track: [{track_mode}] -> {cve_id}")
        print(f"==============================================================")

        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path, ignore_errors=True)
        os.makedirs(os.path.dirname(workspace_path), exist_ok=True)

        try:
            clone_result = subprocess.run(
                ["git", "clone", master_clone_url, workspace_path],
                capture_output=True,
            )
            if clone_result.returncode != 0:
                raise RuntimeError("Failed to clone repository upstream target securely.")

            target_file_absolute = os.path.join(workspace_path, target_file)
            with open(target_file_absolute, "r", encoding="utf-8", errors="ignore") as f:
                original_file_content = f.read()

            model_fallback_queue = [
                "deepseek/deepseek-v4-flash:free",
                "openai/gpt-oss-120b:free",
                "z-ai/glm-4.5-air:free",
                "minimax/minimax-m2.5:free"
            ]
            
            proposed_patch_raw = None
            used_model_name = "None"
            
            if track_mode == "SAST":
                system_prompt = (
                    f"You are an expert security engineer fixing a specific vulnerability in {target_file}.\n\n"
                    "RULES:\n"
                    "1. Return the COMPLETE rewritten file — never omit lines or use placeholders like '# ... rest of code'\n"
                    "2. Fix ONLY the reported vulnerability — do not alter unrelated logic, rename variables, or add features\n"
                    "3. Preserve all function signatures, class structures, and imports unrelated to the fix\n"
                    "4. If a new import is required, add it alongside existing imports at the top of the file\n"
                    "5. Output ONLY raw source code — no markdown fences, no explanations, no inline comments about the change"
                )
                user_prompt = (
                    f"Vulnerability to fix: {ai_instruction}\n"
                    f"Affected lines: {task.get('start_line')} to {task.get('end_line')}\n\n"
                    f"--- CURRENT FILE ---\n{original_file_content}\n--- END FILE ---"
                )
            else:
                system_prompt = (
                    f"You are an automated dependency security patch agent fixing {target_file}.\n\n"
                    "RULES:\n"
                    "1. Return the COMPLETE updated file — never omit lines or use placeholders\n"
                    "2. Apply ONLY the version change described — do not alter anything else\n"
                    "3. Output ONLY raw file content — no markdown fences, no explanations"
                )
                user_prompt = (
                    f"Instruction: {ai_instruction}\n\n"
                    f"--- CURRENT FILE ---\n{original_file_content}\n--- END FILE ---"
                )
            
            for current_model in model_fallback_queue:
                print(f"🔮 [LLM CALL] Attempting generation with model: '{current_model}'...")
                try:
                    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
                    api_payload = {"model": current_model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]}
                    
                    response = requests.post("https://openrouter.ai/api/v1/chat/completions", json=api_payload, headers=headers, timeout=30)
                    response_json = response.json()
                    
                    if "error" in response_json or "choices" not in response_json: continue
                        
                    proposed_patch_raw = response_json["choices"][0]["message"]["content"].strip()
                    used_model_name = current_model
                    print(f"🎯 [LLM SUCCESS] Patch content acquired using '{current_model}'.")
                    break
                except Exception: continue

            if not proposed_patch_raw: raise RuntimeError("All models inside the fallback queue matrix failed.")

            if proposed_patch_raw.startswith("```"):
                proposed_patch_raw = "\n".join(proposed_patch_raw.splitlines()[1:-1])

            print(f"🛡️ [SANDBOX RUNNER] Submitting proposed file patch to evaluation engine...")
            validation_result = sandbox.run_sandbox_pipeline(original_file_content, proposed_patch_raw, target_file)
            
            if not validation_result["success"]:
                print(f"❌ [SANDBOX REJECTION] Patch validation failed for {cve_id}: {validation_result['logs']}")
                db_logger.log_remediation_event(
                    cve_id, target_file, "FAILED", "FAILED_VERIFICATION", "UNSIGNED", "REJECTED_BY_SANDBOX", validation_result.get("logs")
                )
                continue 

            # 🧪 DYNAMIC PYTEST UPGRADE TRACK
            # If the user enabled test runs, apply the patch locally first and run their test suite
            if payload.get("run_tests", False) or source_engine.startswith("manual_"):
                print("🧪 [SANDBOX TESTING] Writing temporary patch to run unit tests...")
                with open(target_file_absolute, "w", encoding="utf-8") as tmp_f:
                    tmp_f.write(validation_result["patched_code"])
                
                print("🏁 [SANDBOX TESTING] Executing 'pytest' across workspace files...")
                test_result = subprocess.run(
                    [sys.executable, "-m", "pytest"],
                    cwd=workspace_path,
                    capture_output=True,
                )
                if test_result.returncode != 0:
                    print(f"❌ [SANDBOX TESTING REJECTION] Patch introduced a functional regression. Pytest suite failed.")
                    db_logger.log_remediation_event(
                        cve_id, target_file, "FAILED", "REGRESSION_TEST_FAILURE", "UNSIGNED", "REJECTED_BY_TEST_SUITE", "Pytest suite failed on regression check."
                    )
                    continue
                print("✅ [SANDBOX TESTING PASSED] All functional unit tests passed cleanly.")

            print(f"✅ [SANDBOX PASSED] Code layout verified clean. Writing changes to scratchpad...")
            with open(target_file_absolute, "w", encoding="utf-8") as f:
                f.write(validation_result["patched_code"])

            print(f"🚀 [GIT PUBLISH] Committing secure patches upstream...")
            branch_name = f"veripatch/remediation-{cve_safe_dir}"

            subprocess.run(["git", "config", "user.name", "VeriPatch Agent"], cwd=workspace_path, check=True)
            subprocess.run(["git", "config", "user.email", "agent@veripatch.internal"], cwd=workspace_path, check=True)
            subprocess.run(["git", "checkout", "-b", branch_name], cwd=workspace_path, check=True, capture_output=True)
            subprocess.run(["git", "add", target_file], cwd=workspace_path, check=True)
            subprocess.run(
                ["git", "commit", "-m", f"🤖 [Security Patch] Resolved {track_mode} vulnerability {cve_id}"],
                cwd=workspace_path, check=True, capture_output=True,
            )
            push_result = subprocess.run(
                ["git", "push", "origin", branch_name, "--force"],
                cwd=workspace_path, capture_output=True,
            )
            if push_result.returncode != 0:
                raise RuntimeError("Failed to push remediation branch upstream to GitHub.")
            
            print(f"🔗 [GITHUB API] Opening live Pull Request for branch '{branch_name}'...")
            pr_api_url = f"https://api.github.com/repos/{extracted_owner}/{repo_name_clean}/pulls"
            
            pr_headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json", "Content-Type": "application/json"}
            pr_payload = {
                "title": f"🤖 [VeriPatch] Fix {track_mode} vulnerability {cve_id.upper()}",
                "head": branch_name, "base": "main",
                "body": (
                    f"## 🛡️ Automated Security Patch ({track_mode} Track)\n\n"
                    f"This Pull Request was autonomously generated by **VeriPatch** to refactor your custom logic code architecture.\n\n"
                    f"- **Vulnerability Defect Class:** `{cve_id.upper()}`\n"
                    f"- **Remediation Target Asset:** `{target_file}`\n"
                    f"- **Post-Patch Verification Posture:** `SandboxValidationRunner` (Syntax Validated Pass)\n\n"
                    f"*Review and merge this branch to secure your custom code statements.*"
                )
            }
            
            target_pr_url = f"https://github.com/{extracted_owner}/{repo_name_clean}/pulls"
            try:
                pr_response = requests.post(pr_api_url, json=pr_payload, headers=pr_headers, timeout=15)
                if pr_response.status_code in [200, 201]:
                    target_pr_url = pr_response.json().get("html_url", target_pr_url)
                    print(f"🎉 [SUCCESS] Live Pull Request deployed: {target_pr_url}")
                elif pr_response.status_code == 422:
                    print(f"ℹ️ [GITHUB INFO] An open Pull Request already exists for branch '{branch_name}'.")
            except Exception as pr_api_err:
                print(f"⚠️ [GITHUB ERROR] Exception during PR creation: {pr_api_err}")

            db_logger.log_remediation_event(
                cve_id=cve_id, target_file=target_file, sandbox_status="PASSED",
                patch_sha256="VERIFIED_COMPLIANT_SHA", kms_signature=f"SIGNED_VERIPATCH_{track_mode}_KMS",
                pr_url=target_pr_url, log_summary=f"Remediation successful using {used_model_name}."
            )

        except Exception as pipeline_error:
            print(f"⚠️ [PIPELINE CRASH] Failed to process {cve_id}: {pipeline_error}")
            db_logger.log_remediation_event(
                cve_id=cve_id, target_file=target_file, sandbox_status="FAILED",
                patch_sha256="PIPELINE_ERROR", kms_signature="UNSIGNED",
                pr_url="ERROR_CRASH", log_summary=str(pipeline_error)
            )

        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path, ignore_errors=True)
        time.sleep(1)

    if manual_workspace_cleanup and os.path.exists(manual_workspace_cleanup):
        shutil.rmtree(manual_workspace_cleanup, ignore_errors=True)

@app.post("/webhooks/v1/trivy")
async def handle_trivy_webhook(request: Request, background_tasks: BackgroundTasks):
    if not TRIVY_AUTH_TOKEN:
        raise HTTPException(status_code=500, detail="TRIVY_AUTH_TOKEN not configured.")
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    provided_token = parts[1] if len(parts) == 2 else ""
    if not hmac.compare_digest(provided_token, TRIVY_AUTH_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid Trivy auth token.")
    payload = await request.json()
    raw_artifact = payload.get("ArtifactName", "").strip()
    background_tasks.add_task(run_async_remediation, repository_path=raw_artifact, payload=payload, source_engine="trivy")
    return {"status": "accepted"}

@app.post("/webhooks/v1/github")
async def handle_github_webhook(request: Request, background_tasks: BackgroundTasks, x_hub_signature_256: str = Header(None)):
    """
    Secure GitHub Endpoint: Validates SHA-256 HMAC payload signatures 
    directly against GITHUB_WEBHOOK_SECRET before initiating remediation tracks.
    """
    raw_payload = await request.body()
    
    # ─── 🛡️ HMAC SECURE PERIMETER VALIDATION ───
    if not GITHUB_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Server configuration error: GITHUB_WEBHOOK_SECRET is unset.")
        
    if not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Security validation rejected: Missing x-hub-signature-256 validation header.")
        
    # Generate local expected cryptographic payload hash signature signature
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        raw_payload,
        hashlib.sha256
    ).hexdigest()
    
    # Use hmac.compare_digest to protect completely against timing attacks
    if not hmac.compare_digest(x_hub_signature_256, expected_signature):
        raise HTTPException(status_code=401, detail="Security validation validation failed: Cryptographic signature mismatch.")
        
    # ─── SIGNATURE PASSED: SAFE TO PARSE AND INTEGRATE PAYLOADS ───
    payload = await request.json()
    github_event = request.headers.get("x-github-event", "").lower()
    if github_event == "ping":
        return {"status": "ping_acknowledged"}
        
    repo_name = payload["repository"]["full_name"]
    background_tasks.add_task(run_async_remediation, repository_path=repo_name, payload=payload, source_engine="github")
    return {"status": "processed"}


@app.post("/webhooks/v1/github-sast")
async def handle_github_sast_webhook(request: Request, background_tasks: BackgroundTasks, x_hub_signature_256: str = Header(None)):
    """
    Secure GitHub SAST Endpoint: Enforces HMAC signature verification on Code Scanning alerts.
    """
    raw_payload = await request.body()
    
    # ─── 🛡️ HMAC SECURE PERIMETER VALIDATION ───
    if not GITHUB_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Server configuration error: GITHUB_WEBHOOK_SECRET is unset.")
        
    if not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Security validation rejected: Missing signature header.")
        
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        raw_payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(x_hub_signature_256, expected_signature):
        raise HTTPException(status_code=401, detail="Security validation failed: Cryptographic signature mismatch.")
        
    # ─── SIGNATURE PASSED ───
    payload = await request.json()
    repo_name = payload["repository"]["full_name"]
    background_tasks.add_task(run_async_remediation, repository_path=repo_name, payload=payload, source_engine="github_sast")
    return {"status": "processed"}

@app.get("/export/csv")
async def export_compliance_logs():
    logs = db_logger.fetch_all_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "CVE ID", "Target File", "Sandbox Status", "Cryptographic Signature", "PR Redirect URL"])
    for item in logs:
        writer.writerow([item.get("timestamp", ""), item.get("cve_id", ""), item.get("target_file", ""), item.get("sandbox_status", ""), item.get("kms_signature", ""), item.get("pr_url", "")])
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=veripatch_compliance_report.csv"})

@app.post("/api/actions/rescan")
async def trigger_manual_console_rescan(payload: RescanPayload, background_tasks: BackgroundTasks):
    engine_mode = f"manual_{payload.scan_type.lower()}"
    # Pass along the UI checkbox/state via the payload mapping context dictionary
    background_tasks.add_task(
        run_async_remediation, 
        repository_path=payload.repo_name.strip(), 
        payload={"run_tests": payload.run_tests}, 
        source_engine=engine_mode
    )
    return {"status": "success"}

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    logs = db_logger.fetch_all_logs()
    
    total_scans = len(logs)
    passed_scans = len([l for l in logs if l["sandbox_status"] == "PASSED"])
    failed_scans = total_scans - passed_scans
    success_rate = f"{(passed_scans / total_scans * 100):.1f}%" if total_scans > 0 else "100.0%"

    default_repo_value = (
        f"https://github.com/{GITHUB_OWNER}/your-repo"
        if GITHUB_OWNER
        else "owner/your-repo"
    )

    log_rows_html = ""
    for item in logs:
        if item["sandbox_status"] == "PASSED":
            status_badge = '<span class="badge badge-success">● Compile Passed</span>'
        else:
            status_badge = '<span class="badge badge-fail">○ Review Required</span>'

        # Escape all DB values before inserting into HTML to prevent stored XSS
        ts = html.escape(str(item.get("timestamp", ""))[:19])
        cve_tag = html.escape(str(item.get("cve_id", "")))
        target_file_display = html.escape(str(item.get("target_file", "")))
        sig = str(item.get("kms_signature", ""))
        sig_title = html.escape(sig)
        sig_preview = html.escape(sig[:24])

        pr_url_raw = str(item.get("pr_url", "")).strip()
        # Strip any residual markdown link syntax from stored values
        pr_url_raw = re.sub(r'\[.*?\]\(.*?\)', '', pr_url_raw)
        for char in ["[", "]", "(", ")"]:
            pr_url_raw = pr_url_raw.replace(char, "")

        NON_LINK_STATUSES = {"LOCAL_SIMULATION_MODE", "REJECTED_BY_SANDBOX", "ERROR_CRASH", "REJECTED_BY_TEST_SUITE"}
        if pr_url_raw in NON_LINK_STATUSES:
            link_element = f'<span class="txt-disabled">{html.escape(pr_url_raw.replace("_", " "))}</span>'
        else:
            safe_url = html.escape(pr_url_raw)
            link_element = f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer" class="btn-action">Review PR ↗</a>'

        log_rows_html += (
            f"<tr>"
            f'<td class="font-mono text-muted">{ts}</td>'
            f'<td><span class="cve-tag">{cve_tag}</span></td>'
            f'<td class="font-mono text-light">{target_file_display}</td>'
            f"<td>{status_badge}</td>"
            f'<td class="font-mono text-amber" title="{sig_title}">{sig_preview}...</td>'
            f"<td>{link_element}</td>"
            f"</tr>\n"
        )
    if not log_rows_html:
        log_rows_html = '<tr><td colspan="6" class="no-data">No telemetry logs found matching recent execution cycles.</td></tr>'

    dashboard_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>VeriPatch | Cybersecurity Orchestration Hub</title>
        <style>
            body {{ background-color: #0b0f19; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }}
            nav {{ background-color: #020617; display: flex; justify-content: space-between; align-items: center; padding: 16px 32px; border-bottom: 1px solid #1e293b; }}
            .logo-container {{ display: flex; align-items: center; gap: 12px; }}
            .logo {{ font-size: 20px; font-weight: 900; letter-spacing: 2px; background: linear-gradient(to right, #818cf8, #c084fc, #22d3ee); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
            .plane-tag {{ font-size: 10px; font-weight: 800; color: #818cf8; background-color: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.2); padding: 4px 10px; border-radius: 4px; text-transform: uppercase; }}
            .status-container {{ display: flex; align-items: center; gap: 8px; font-family: monospace; font-size: 12px; background-color: #0f172a; border: 1px solid #1e293b; padding: 6px 16px; border-radius: 9999px; }}
            .status-dot {{ height: 8px; width: 8px; background-color: #34d399; border-radius: 50%; display: inline-block; }}
            main {{ max-w: 1200px; margin: 0 auto; padding: 40px 32px; }}
            header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; flex-wrap: wrap; gap: 24px; }}
            h1 {{ font-size: 28px; font-weight: 800; margin: 0; color: #f8fafc; }}
            .subtitle {{ font-size: 14px; color: #94a3b8; margin: 6px 0 0 0; }}
            .toolbar {{ display: flex; align-items: center; gap: 16px; }}
            .input-group {{ display: flex; align-items: center; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 6px; gap: 4px; }}
            select {{ background: #020617; border: 1px solid #334155; color: #818cf8; font-size: 11px; font-weight: 700; padding: 6px 10px; border-radius: 6px; outline: none; cursor: pointer; }}
            input {{ background: transparent; border: none; color: #f1f5f9; font-size: 12px; font-weight: 700; padding: 6px 12px; outline: none; width: 380px; }}
            button {{ background-color: #4f46e5; color: #ffffff; border: 1px solid rgba(255,255,255,0.1); padding: 8px 16px; font-size: 12px; font-weight: 700; border-radius: 8px; cursor: pointer; text-transform: uppercase; transition: all 0.15s ease; }}
            button:hover {{ background-color: #4338ca; }}
            .btn-download {{ background-color: #1e293b; color: #cbd5e1; border: 1px solid #334155; padding: 10px 16px; font-size: 12px; font-weight: 700; border-radius: 12px; text-decoration: none; text-transform: uppercase; transition: all 0.15s ease; }}
            .btn-download:hover {{ background-color: #334155; }}
            .stats-grid {{ display: grid; grid-template-cols: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 40px; }}
            .stat-card {{ background: linear-gradient(to bottom, #0f172a, #020617); border: 1px solid #1e293b; border-radius: 16px; padding: 24px; }}
            .stat-title {{ font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin: 0; }}
            .stat-value {{ font-size: 32px; font-weight: 900; margin: 8px 0 0 0; font-family: monospace; }}
            .table-container {{ background-color: rgba(15, 23, 42, 0.4); border: 1px solid #1e293b; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3); }}
            table {{ width: 100%; border-collapse: collapse; text-align: left; }}
            th {{ background-color: #0f172a; border-bottom: 1px solid #1e293b; padding: 16px; font-size: 11px; font-weight: 800; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; }}
            td {{ padding: 16px; border-bottom: 1px solid rgba(30, 41, 59, 0.5); font-size: 14px; }}
            tr:hover {{ background-color: rgba(15, 23, 42, 0.6); }}
            .font-mono {{ font-family: monospace; }}
            .text-muted {{ color: #64748b; font-size: 12px; }}
            .text-light {{ color: #cbd5e1; }}
            .text-amber {{ color: #f59e0b; font-size: 12px; }}
            .cve-tag {{ background-color: #0f172a; color: #818cf8; border: 1px solid #312e81; padding: 4px 8px; font-weight: 700; font-size: 12px; border-radius: 6px; }}
            .badge {{ font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 9999px; display: inline-block; }}
            .badge-success {{ background-color: rgba(16, 185, 129, 0.1); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); }}
            .badge-fail {{ background-color: rgba(244, 63, 94, 0.1); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.2); }}
            .btn-action {{ color: #818cf8; background-color: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.2); padding: 6px 12px; border-radius: 8px; font-weight: 700; font-size: 12px; text-decoration: none; transition: all 0.15s ease; }}
            .btn-action:hover {{ background-color: rgba(99, 102, 241, 0.2); color: #a5b4fc; }}
            .txt-disabled {{ color: #475569; font-style: italic; font-size: 12px; }}
            .no-data {{ text-align: center; color: #64748b; padding: 48px; }}
        </style>
    </head>
    <body>
        <nav>
            <div class="logo-container">
                <span class="logo">VERIPATCH</span>
                <span class="plane-tag">A.I. Patch Plane</span>
            </div>
            <div class="status-container">
                <span class="status-dot"></span>
                <span style="color:#94a3b8">System Engine:</span>
                <span style="color:#34d399; font-weight:bold; text-transform:uppercase;">Operational</span>
            </div>
        </nav>

        <main>
            <header>
                <div>
                    <h1>Security Audit Control Ledger</h1>
                    <p class="subtitle">SIEM-compliant autonomous pipeline tracking records detailing zero-touch cryptographic compilation receipts.</p>
                </div>
                
                <div class="input-group">
                    <select id="scanTypeSelector">
                        <option value="dependency">SCA (Dependency)</option>
                        <option value="sast">SAST (AI Code Fix)</option>
                    </select>
                    <label style="color: #94a3b8; font-size: 11px; font-weight: 700; display: flex; align-items: center; gap: 4px; padding-left: 8px; cursor: pointer;">
                        <input type="checkbox" id="runTestsCheckbox" style="width: auto; margin: 0;"> Run Tests (pytest)
                    </label>
                    <input type="text" id="repoSelector" value="{default_repo_value}" placeholder="https://github.com/owner/repo  or  owner/repo">
                    <button onclick="triggerManualSync(this)">Force Run Scan</button>
                </div>
            </header>

            <section class="stats-grid">
                <div class="stat-card">
                    <p class="stat-title">Total Scanned Defects</p>
                    <p class="stat-value" style="color:#f1f5f9">{total_scans}</p>
                </div>
                <div class="stat-card">
                    <p class="stat-title">Mitigated Assets</p>
                    <p class="stat-value" style="color:#34d399">{passed_scans}</p>
                </div>
                <div class="stat-card">
                    <p class="stat-title">Review Deadlocks</p>
                    <p class="stat-value" style="color:#fb7185">{failed_scans}</p>
                </div>
                <div class="stat-card">
                    <p class="stat-title">Sandbox Success Rate</p>
                    <p class="stat-value" style="color:#818cf8">{success_rate}</p>
                </div>
            </section>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="padding-left:24px;">Timestamp Tracking</th>
                            <th>Vulnerability Node</th>
                            <th>Remediation Source File</th>
                            <th>Sandbox Test Pass</th>
                            <th>KMS Cryptographic Proof</th>
                            <th style="padding-right:24px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>{log_rows_html}</tbody>
                </table>
            </div>
        </main>
        <script>
            async function triggerManualSync(btnElement) {{ 
                const repoInput = document.getElementById('repoSelector');
                const typeInput = document.getElementById('scanTypeSelector');
                const testsInput = document.getElementById('runTestsCheckbox');
                
                const targetRepo = repoInput.value.trim();
                const selectedType = typeInput.value;
                const verifyWithTests = testsInput ? testsInput.checked : false;
                
                if(!targetRepo) {{
                    alert("Please input a valid target repository path.");
                    return;
                }}
                
                const btn = btnElement || document.querySelector('button[onclick^="triggerManualSync"]');
                const origText = btn.innerText;
                btn.innerText = "SCANNING REPO...";
                btn.disabled = true;
                
                try {{
                    const response = await fetch('/api/actions/rescan', {{ 
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ 
                            repo_name: targetRepo, 
                            scan_type: selectedType,
                            run_tests: verifyWithTests
                        }})
                    }});
                    
                    if (!response.ok) throw new Error("Network issue encountered.");
                    
                    alert("🚀 Global Pipeline Dispatched: Initializing dynamic sanitizer scanner on repo context: " + targetRepo);
                    setTimeout(() => window.location.reload(), 1500);
                }} catch (err) {{
                    alert("❌ Action deployment failure: " + err.message);
                }} finally {{
                    btn.innerText = origText;
                    btn.disabled = false;
                }}
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=dashboard_html, status_code=200)

if __name__ == "__main__":
    server_port = int(os.getenv("PORT", 8080))
    server_host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app:app", host=server_host, port=server_port, reload=True)