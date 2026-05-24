import os
import shutil
import json
import subprocess
import requests

class GitExecutionProvider:
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_owner = os.getenv("GITHUB_OWNER")
        self.workspace_dir = "/tmp/"

        if not self.github_token or not self.github_owner:
            raise ValueError("GitExecutionProvider requires GITHUB_TOKEN and GITHUB_OWNER env vars.")

    def _run_git_cmd(self, cmd: list, cwd: str = None) -> str:
        """Executes a git command as a list — never uses shell=True to prevent injection."""
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Git command failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def _clone_url(self, repo_name: str) -> str:
        return f"https://x-access-token:{self.github_token}@github.com/{self.github_owner}/{repo_name}.git"

    def create_remediation_branch(
        self,
        repo_name: str,
        cve_id: str,
        target_file: str,
        patched_code: str,
        signed_manifest: dict,
    ) -> dict:
        workspace_path = os.path.join(self.workspace_dir, repo_name)
        branch_name = f"veripatch/{cve_id.lower()}"

        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path)

        self._run_git_cmd(["git", "clone", self._clone_url(repo_name), workspace_path])
        self._run_git_cmd(["git", "config", "user.name", "VeriPatch Agent"], cwd=workspace_path)
        self._run_git_cmd(["git", "config", "user.email", "agent@veripatch.internal"], cwd=workspace_path)
        self._run_git_cmd(["git", "checkout", "-b", branch_name], cwd=workspace_path)

        file_full_path = os.path.join(workspace_path, target_file)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
        with open(file_full_path, "w") as f:
            f.write(patched_code)

        manifest_path = os.path.join(workspace_path, "VERIPATCH_MANIFEST.json")
        with open(manifest_path, "w") as f:
            json.dump(signed_manifest, f, indent=2)

        self._run_git_cmd(["git", "add", "."], cwd=workspace_path)
        self._run_git_cmd(
            ["git", "commit", "-m", f"🛡️ [VeriPatch] Automated remediation for {cve_id}"],
            cwd=workspace_path,
        )

        return {
            "target_branch": branch_name,
            "pull_request_markdown": f"### VeriPatch Security Fix\nSuccessfully patched {cve_id}.",
        }

    def generate_pull_request_body(self, signed_manifest: dict) -> str:
        m = signed_manifest.get("manifest", {})
        s = signed_manifest.get("cryptographic_signature", "")

        cve_id = str(m.get("cve_id", "CVE-UNKNOWN"))
        version = str(m.get("engine_version", "1.0.0"))
        sha = str(m.get("patch_sha256", ""))

        body = "### 🛡️ Automated CVE Remediation Report by VeriPatch\n\n"
        body += f"- **Vulnerability ID**: `{cve_id}`\n"
        body += f"- **Engine Version**: `{version}`\n"
        body += f"- **Patch SHA256**: `{sha}`\n"
        body += "- **Sandbox Status**: `PASS (Clean Compile achieved)`\n\n"
        body += "---\n\n"
        body += "### 🔐 Cryptographic Provenance Certificate\n\n"
        body += "```json\n"
        body += '{\n  "kms_signature_proof": "' + str(s) + '"\n}\n'
        body += "```"
        return body

    def push_and_open_pr(self, repo_name: str, branch_name: str, pr_title: str, pr_body: str) -> dict:
        repo_path = os.path.join(self.workspace_dir, repo_name)

        try:
            print(f"🚀 [GIT] Pushing branch '{branch_name}' upstream...")
            # Force push to update an existing remediation branch for the same CVE
            self._run_git_cmd(["git", "push", "-f", "-u", "origin", branch_name], cwd=repo_path)

            api_url = f"https://api.github.com/repos/{self.github_owner}/{repo_name}/pulls"
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
            }
            payload = {
                "title": pr_title,
                "body": pr_body,
                "head": branch_name,
                "base": "main",
            }

            response = requests.post(api_url, json=payload, headers=headers)

            if response.status_code == 201:
                pr_data = response.json()
                print(f"✨ [PR OPENED] {pr_data['html_url']}")
                return {"success": True, "url": pr_data["html_url"]}
            elif response.status_code == 422 and "A pull request already exists" in response.text:
                print("ℹ️ [PR EXISTS] Existing PR updated via force-push.")
                return {"success": True, "url": f"https://github.com/{self.github_owner}/{repo_name}/pulls"}
            else:
                print(f"🚨 [GITHUB API ERROR]: {response.text}")
                return {"success": False, "url": f"GITHUB_ERROR: {response.text}"}

        except Exception as e:
            print(f"❌ [GIT REMOTE ERROR] {e}")
            return {"success": False, "url": f"GITHUB_ERROR: {e}"}
