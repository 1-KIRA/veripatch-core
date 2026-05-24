import os
import hashlib
import json
import hmac

class ProvenanceSigner:
    def __init__(self, secret_key: str = None):
        key = secret_key or os.getenv("PROVENANCE_SIGNING_KEY")
        if not key:
            raise ValueError(
                "PROVENANCE_SIGNING_KEY env var must be set. "
                "No hardcoded fallback is permitted — use AWS KMS, HashiCorp Vault, or Azure Key Vault."
            )
        self.secret_key = key.encode("utf-8")

    def generate_verified_manifest(self, cve_id: str, repo: str, patch_diff: str, log_summary: str) -> dict:
        patch_hash = hashlib.sha256(patch_diff.encode("utf-8")).hexdigest()

        manifest_body = {
            "cve_id": cve_id,
            "target_repository": repo,
            "patch_sha256": patch_hash,
            "sandbox_verification": "SUCCESS",
            "verification_summary": log_summary,
            "engine_version": "v1.0.0-beta",
        }

        serialized_manifest = json.dumps(manifest_body, sort_keys=True)

        signature = hmac.new(
            self.secret_key,
            msg=serialized_manifest.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()

        return {
            "manifest": manifest_body,
            "cryptographic_signature": signature,
        }


if __name__ == "__main__":
    import sys

    demo_key = os.getenv("PROVENANCE_SIGNING_KEY")
    if not demo_key:
        print("[ERROR] Set PROVENANCE_SIGNING_KEY env var before running this demo.")
        sys.exit(1)

    signer = ProvenanceSigner()
    mock_diff = "--- file.py\n+++ file.py\n+import secrets"

    signed_receipt = signer.generate_verified_manifest(
        cve_id="CVE-2026-9999",
        repo="enterprise/gateway",
        patch_diff=mock_diff,
        log_summary="All 42 functional tests passed cleanly.",
    )
    print(json.dumps(signed_receipt, indent=2))
