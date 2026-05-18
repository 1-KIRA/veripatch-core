import os
import sys
from typing import TypedDict, Literal
from langgraph.graph import StateGraph, START, END

# Import updated production helper modules
from sandbox_runner import SandboxValidationRunner
from agent_llm import PatchGenerationEngine
from provenance import ProvenanceSigner
from git_provider import GitExecutionProvider

# 1. Enhanced State Schema to preserve baseline content tracking
class RemediationState(TypedDict):
    cve_id: str
    vulnerability_details: str
    repository_path: str
    vulnerable_file: str
    current_patch_diff: str
    verification_status: Literal["PENDING", "PASSED", "FAILED"]
    verification_logs: str
    iteration_count: int
    max_iterations: int
    human_approved: bool
    patched_code: str
    original_code: str  # ✨ Added to pass down the real file baseline cleanly

class VeriPatchEngine:
    def __init__(self, max_loops: int = 3):
        self.max_loops = max_loops
        self.sandbox = SandboxValidationRunner()
        self.llm_engine = PatchGenerationEngine()
        self.signer = ProvenanceSigner()
        self.git_provider = GitExecutionProvider()
        
        # Local development fallback context canvas
        self.fallback_source_code = (
            "import random\n\n"
            "def generate_session_token():\n"
            "    import random\n"
            "    print('LOG: Creating cryptographically insecure session configuration')\n"
            "    return str(random.randint(100000, 999999))\n"
        )

    def triage_node(self, state: RemediationState) -> dict:
        print(f"\n[TRIAGE AGENT] Mapping exploit signatures for target: {state['cve_id']}\n" + "-"*50)
        
        # 🔄 DYNAMIC SEEDING: Keep the incoming parameters passed from the ingestion router
        return {
            "vulnerable_file": state.get("vulnerable_file") or "src/auth/session.py",
            "vulnerability_details": state.get("vulnerability_details") or "CWE-330: Use of Insufficiently Random Values.",
            "iteration_count": 0,
            "verification_status": "PENDING"
        }

    def remediate_node(self, state: RemediationState) -> dict:
        current_attempt = state.get("iteration_count", 0) + 1
        previous_fail_logs = state.get("verification_logs", None) if state.get("verification_status") == "FAILED" else None
        
        # Use live file text passed from workspace, or drop back to development canvas if empty
        active_baseline = state.get("original_code") or state.get("patched_code") or self.fallback_source_code
        
        # Requests full context-aware remediation from the LLM client engine
        full_file_code = self.llm_engine.generate_patch(
            cve_id=state["cve_id"],
            file_path=state["vulnerable_file"],
            file_content=active_baseline,
            vulnerability_details=state["vulnerability_details"],
            previous_error=previous_fail_logs
        )
        
        print(f"[REMEDIATION AGENT] Attempt {current_attempt} -> Complete source file text context generated.")
        return {
            "patched_code": full_file_code,
            "iteration_count": current_attempt
        }

    def verify_node(self, state: RemediationState) -> dict:
        print(f"[VERIFICATION AGENT] Executing syntax validation checks on proposed solution...")
        
        active_baseline = state.get("original_code") or self.fallback_source_code
        
        # Evaluate syntax integrity and build programmatic diff layouts inside the runner execution profile
        run_results = self.sandbox.run_sandbox_pipeline(
            original_code=active_baseline,
            proposed_code=state["patched_code"],
            file_path=state["vulnerable_file"]
        )
        
        if run_results["success"]:
            print(f"[VERIFICATION SUCCESS] Code compiled safely. Flawless patch diff programmatically generated.")
            return {
                "verification_status": "PASSED",
                "verification_logs": run_results["logs"],
                "current_patch_diff": run_results["generated_diff"],
                "patched_code": run_results["patched_code"]
            }
        else:
            print(f"\n🚨 [SANDBOX REJECTION LOGS]:\n{run_results['logs']}\n")
            return {
                "verification_status": "FAILED",
                "verification_logs": run_results["logs"]
            }

    def route_evaluation(self, state: RemediationState) -> Literal["remediate", "human_review", "fail"]:
        if state["verification_status"] == "PASSED":
            return "human_review"
        if state["iteration_count"] >= self.max_loops:
            return "fail"
        return "remediate"

    def assemble_workflow(self):
        builder = StateGraph(RemediationState)
        builder.add_node("triage", self.triage_node)
        builder.add_node("remediate", self.remediate_node)
        builder.add_node("verify", self.verify_node)
        
        builder.add_edge(START, "triage")
        builder.add_edge("triage", "remediate")
        builder.add_edge("remediate", "verify")
        
        builder.add_conditional_edges(
            "verify",
            self.route_evaluation,
            {"remediate": "remediate", "human_review": END, "fail": END}
        )
        return builder.compile()

if __name__ == "__main__":
    if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        print("[CRITICAL] Missing access keys. Please export your environment key token.\n")
        sys.exit(1)

    engine = VeriPatchEngine(max_loops=3)
    graph = engine.assemble_workflow()
    
    execution_payload = {
        "cve_id": "CVE-2026-9999",
        "repository_path": "git@github.com:enterprise/auth-layer.git",
        "max_iterations": 3,
        "verification_status": "PENDING",
        "human_approved": False,
        "vulnerable_file": "src/auth/session.py",
        "vulnerability_details": "",
        "current_patch_diff": "",
        "verification_logs": "",
        "iteration_count": 0,
        "patched_code": "",
        "original_code": ""
    }
    
    final_state = graph.invoke(execution_payload)
    print(f"\nExecution terminated with Status: {final_state['verification_status']}")