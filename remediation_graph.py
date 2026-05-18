import os
from typing import TypedDict, Literal
from langgraph.graph import StateGraph, START, END

# 1. Define the Shared Enterprise State Schema
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

# 2. Node: The Triage Agent
def triage_agent(state: RemediationState) -> dict:
    """Analyzes the CVE vector and determines file paths and exploit contexts."""
    print(f"\n[Triage Agent] Analyzing vulnerability vector for: {state['cve_id']}")
    # In production: Pulls down file maps, matches dependencies, run local abstract syntax tree (AST) matching.
    return {
        "vulnerable_file": "src/auth/session.py",
        "vulnerability_details": "Insecure session token generation strategy allowing predictability via random module.",
        "iteration_count": 0
    }

# 3. Node: The Remediation Agent (The Coder)
def remediation_agent(state: RemediationState) -> dict:
    """Generates the targeted code patch or dependency updates."""
    attempt = state.get("iteration_count", 0) + 1
    print(f"\n[Remediation Agent] Generating patch code for {state['vulnerable_file']} (Attempt {attempt})")
    
    # In production: Issues a structured system prompt to models like Claude 3.5 Sonnet / Gemini Pro
    # For demonstration, let's simulate an AI that makes an indentation error on the first attempt, then fixes it.
    if attempt == 1:
        mock_diff = "--- src/auth/session.py\n+++ src/auth/session.py\n import random\n- return random.randint(1000, 9999)\n+   import secrets\n+   return secrets.token_hex(32)" # Malformed indentation
    else:
        mock_diff = "--- src/auth/session.py\n+++ src/auth/session.py\n-import random\n-return random.randint(1000, 9999)\n+import secrets\n+return secrets.token_hex(32)" # Correct code
        
    return {
        "current_patch_diff": mock_diff,
        "iteration_count": attempt
    }

# 4. Node: The Verification Agent (The Sandbox Interface)
def verification_agent(state: RemediationState) -> dict:
    """Simulates testing the patch inside an isolated sandbox execution layer."""
    print(f"\n[Verification Agent] Simulating execution of isolated sandbox tests...")
    diff = state["current_patch_diff"]
    
    # In production: This node communicates with your container engine/K8s API to build the patch.
    if "   import secrets" in diff: # Detecting the malformed indentation
        return {
            "verification_status": "FAILED",
            "verification_logs": "IndentationError: unexpected indent on line 11 during sandbox build execution."
        }
    else:
        return {
            "verification_status": "PASSED",
            "verification_logs": "All 42 functional unit tests passed. SAST scan returns CLEAN status."
        }

# 5. Conditional Routing Logic (The Self-Healing Loop Controller)
def route_after_verification(state: RemediationState) -> Literal["remediate", "human_review", "fail"]:
    """Evaluates metrics to branch the workflow graph paths dynamically."""
    if state["verification_status"] == "PASSED":
        print("\n[System Router] Verification PASSED. Moving to Human-in-the-Loop review queue.")
        return "human_review"
    
    if state["iteration_count"] >= state["max_iterations"]:
        print("\n[System Router] Target exceeded maximum iterations. Flagging execution as failed.")
        return "fail"
    
    print(f"\n[System Router] Verification FAILED. Rerouting context logs to developer agent for repair.")
    return "remediate"

# 6. Graph Compilation Engine
def build_remediation_workflow():
    workflow = StateGraph(RemediationState)
    
    # Map nodes to the state engine
    workflow.add_node("triage", triage_agent)
    workflow.add_node("remediate", remediation_agent)
    workflow.add_node("verify", verification_agent)
    
    # Trace the deterministic boundaries
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "remediate")
    workflow.add_edge("remediate", "verify")
    
    # Bind the conditional cyclic routing rules
    workflow.add_conditional_edges(
        "verify",
        route_after_verification,
        {
            "remediate": "remediate",  # Loops back to agent for adjustment
            "human_review": END,       # Breaks flow, checkpoints state for UI approval
            "fail": END                # Terminates run with alert tracking
        }
    )
    
    return workflow.compile()

if __name__ == "__main__":
    # Simulate an automated CVE triage pipeline initialization
    remediation_engine = build_remediation_workflow()
    
    job_input = {
        "cve_id": "CVE-2026-40192",
        "repository_path": "git@github.com:enterprise/secure-auth-api.git",
        "max_iterations": 3,
        "verification_status": "PENDING",
        "human_approved": False
    }
    
    result = remediation_engine.invoke(job_input)
    
    print("\n" + "="*50)
    print("FINAL REMEDIATION ENGINE EXECUTOR SUMMARY")
    print(f"Target CVE: {result['cve_id']}")
    print(f"Final Build Validation: {result['verification_status']}")
    print(f"Total Self-Healing Attempts Needed: {result['iteration_count']}")
    print(f"Final Signed Patch Output:\n{result['current_patch_diff']}")
    print("="*50)