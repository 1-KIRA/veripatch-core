import difflib

class SandboxValidationRunner:
    def __init__(self):
        pass

    def generate_perfect_diff(self, original_code: str, patched_code: str, file_path: str) -> str:
        """
        Mathematically generates a flawless unified diff format from the full file states.
        This is completely immune to LLM text-formatting syntax bugs.
        """
        orig_lines = original_code.splitlines(keepends=True)
        patch_lines = patched_code.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            orig_lines, 
            patch_lines, 
            fromfile=f"a/{file_path}", 
            tofile=f"b/{file_path}"
        )
        return "".join(diff)

    def validate_code_syntax(self, code_source: str) -> bool:
        """
        Compiles the post-patch source code into an Abstract Syntax Tree (AST) 
        to verify that no syntax or indentation errors exist.
        """
        try:
            compile(code_source, "<sandbox_clean_compile>", "exec")
            return True
        except SyntaxError as e:
            raise SyntaxError(f"Line {e.lineno}: {e.msg} -> code context: '{e.text.strip() if e.text else ''}'")

    def run_sandbox_pipeline(self, original_code: str, proposed_code: str, file_path: str) -> dict:
        if not proposed_code.strip():
            return {"success": False, "logs": "LLM returned an empty code string.", "patched_code": None}

        try:
            # Step 1: Validate syntax structures of the new full code directly
            self.validate_code_syntax(proposed_code)
            
            # Step 2: Generate a flawless tracking diff patch programmatically
            perfect_diff = self.generate_perfect_diff(original_code, proposed_code, file_path)
            
            return {
                "success": True,
                "logs": "Sandbox verification successful. Clean compilation achieved.",
                "patched_code": proposed_code,
                "generated_diff": perfect_diff
            }
        except Exception as validation_failure:
            return {
                "success": False,
                "logs": str(validation_failure),
                "patched_code": None,
                "generated_diff": None
            }