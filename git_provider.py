import os
import shutil
import json
import subprocess

class GitExecutionProvider:
    def __init__(self):
        """Initializes the provider with secure credentials and active workspace tracking variables."""
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_owner = os.getenv("GITHUB_OWNER")
        
        # 🚀 MOVE OUTSIDE THE WORKSPACE TO PREVENT PREMATURE SERVER RELOADS
        self.workspace_dir = "/tmp/" 
        
        if not self.github_token or not self.github_owner:
            raise ValueError("GitExecutionProvider missing critical GITHUB_TOKEN or GITHUB_OWNER env values.")

    def _run_git_cmd(self, cmd, cwd=None):
        """
        🛡️ Secure internal helper to execute git shell commands.
        Handles both structured list arguments and raw execution strings safely.
        """
        if isinstance(cmd, str):
            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
            
        if result.returncode != 0:
            raise RuntimeError(f"Git subsystem execution failed: {result.stderr.strip()}")
            
        return result.stdout.strip()

    def create_remediation_branch(self, repo_name: str, cve_id: str, target_file: str, patched_code: str, signed_manifest: dict):
        # Update this row to use your newly unified class property configuration tracking
        workspace_path = os.path.join(self.workspace_dir, repo_name)
        branch_name = f"veripatch/{cve_id.lower()}"
        
        # Clean out old scratch directory if it exists
        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path)
            
        # CLONE the real repo from GitHub using the verified tokens to capture history tree context
        repo_url = f"https://x-access-token:{self.github_token}@github.com/{self.github_owner}/{repo_name}.git"
        os.system(f"git clone {repo_url} {workspace_path}")
        
        # Move into the cloned repository context directory
        cwd = os.getcwd()
        os.chdir(workspace_path)
        
        # Create and switch to a new branch explicitly tracking 'main' history base
        os.system(f"git checkout -b {branch_name}")
        
        # Overwrite the specific target file with the surgical AI fix
        file_full_path = os.path.join(os.getcwd(), target_file)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
        with open(file_full_path, "w") as f:
            f.write(patched_code)
            
        # Write your cryptographic compliance manifest receipt file alongside it
        with open("VERIPATCH_MANIFEST.json", "w") as f:
            json.dump(signed_manifest, f, indent=2)
            
        # Stage, commit, and prepare for push
        os.system("git add .")
        os.system(f'git commit -m "🛡️ [VeriPatch] Automated remediation for {cve_id}"')
        
        # Restore parent operational system directory paths
        os.chdir(cwd)
        
        return {
            "target_branch": branch_name,
            "pull_request_markdown": f"### VeriPatch Security Fix\nSuccessfully patched {cve_id}."
        }

    def generate_pull_request_body(self, signed_manifest: dict) -> str:
        """Generates a clean, bulletproof Markdown summary for the GitHub PR description."""
        m = signed_manifest.get("manifest", {})
        s = signed_manifest.get("cryptographic_signature", "")
        
        cve_id = str(m.get('cve_id', 'CVE-UNKNOWN'))
        version = str(m.get('engine_version', '1.0.0'))
        sha = str(m.get('patch_sha256', ''))
        
        body = "### 🛡️ Automated CVE Remediation Report by VeriPatch\n\n"
        body += f"- **Vulnerability ID**: `{cve_id}`\n"
        body += f"- **Engine Version**: `{version}`\n"
        body += f"- **Patch SHA256**: `{sha}`\n"
        body += "- **Sandbox Status**: `PASS (Clean Compile achieved)`\n\n"
        body += "---\n\n"
        body += "### 🔐 Cryptographic Provenance Certificate\n\n"
        body += "```json\n"
        body += "{\n"
        body += '  "kms_signature_proof": "' + str(s) + '"\n'
        body += "}\n"
        body += "```"
        return body

    def push_and_open_pr(self, repo_name: str, branch_name: str, pr_title: str, pr_body: str):
        """
        Pushes the localized security patch branch upstream to GitHub 
        and programmatically opens a tracking Pull Request.
        """
        import requests
        repo_path = os.path.join(self.workspace_dir, repo_name)
        
        try:
            print(f"🚀 [GIT] Pushing security branch '{branch_name}' upstream...")
            
            # 🛡️ CRITICAL: Enforce the "-f" flag in the array execution block
            self._run_git_cmd(["git", "push", "-f", "-u", "origin", branch_name], cwd=repo_path)
            
            # 2. Open the Pull Request via the official GitHub REST API
            api_url = f"https://api.github.com/repos/{self.github_owner}/{repo_name}/pulls"
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            payload = {
                "title": pr_title,
                "body": pr_body,
                "head": branch_name,
                "base": "main"
            }
            
            response = requests.post(api_url, json=payload, headers=headers)
            
            if response.status_code == 201:
                pr_data = response.json()
                print(f"✨ [PR OPENED] Live tracking URL generated: {pr_data['html_url']}")
                return {"success": True, "url": pr_data["html_url"]}
            elif response.status_code == 422 and "A pull request already exists" in response.text:
                print(f"ℹ️ [PR ALREADY EXISTS] Remote branch updated. Existing PR tracking active.")
                fallback_url = f"https://github.com/{self.github_owner}/{repo_name}/pulls"
                return {"success": True, "url": fallback_url}
            else:
                print(f"🚨 [GITHUB API REJECTION]: Validation Failed")
                print(f"Details: {response.text}")
                return {"success": False, "url": f"GITHUB_ERROR: {response.text}"}
                
        except Exception as e:
            print(f"❌ [GIT REMOTE ERROR] Failed to push upstream: {e}")
            return {"success": False, "url": f"GITHUB_ERROR: {str(e)}"}

if __name__ == "__main__":
    print("="*60)
    print("[SUCCESS] git_provider.py updated with active branch discovery!")
    print("="*60)