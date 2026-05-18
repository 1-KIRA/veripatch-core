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

    def validate_code_syntax(self, code_source: str, file_path: str) -> bool:
        """
        Validates structural syntax based on destination file signatures.
        Compiles Python source files into an AST block, or validates pip constraints text formatting.
        """
        target_clean = file_path.lower()
        
        # 📦 EXTENSION CHECK 1: If it is a package configuration map, use text structural validation
        if "requirements.txt" in target_clean or target_clean.endswith(".txt"):
            for i, line in enumerate(code_source.splitlines(), 1):
                clean_line = line.strip()
                # Skip comments and empty whitespace slots smoothly
                if not clean_line or clean_line.startswith("#"):
                    continue
                
                # Verify the LLM didn't leak raw Python statements into the requirements text matrix
                if any(clean_line.startswith(x) for x in ["def ", "import ", "class ", "return ", "print("]):
                    raise SyntaxError(f"Line {i}: requirements.txt format leaked Python code logic: '{clean_line}'")
            return True
            
        # 🐍 EXTENSION CHECK 2: Standard Python source execution file code checking
        else:
            try:
                compile(code_source, "<sandbox_clean_compile>", "exec")
                return True
            except SyntaxError as e:
                raise SyntaxError(f"Line {e.lineno}: {e.msg} -> code context: '{e.text.strip() if e.text else ''}'")

    def run_sandbox_pipeline(self, original_code: str, proposed_code: str, file_path: str) -> dict:
        if not proposed_code.strip():
            return {"success": False, "logs": "LLM returned an empty code string.", "patched_code": None}

        try:
            # 🛡️ Step 1: Validate syntax structures passing down the specific file context target
            self.validate_code_syntax(proposed_code, file_path)
            
            # Step 2: Generate a flawless tracking diff patch programmatically
            perfect_diff = self.generate_perfect_diff(original_code, proposed_code, file_path)
            
            return {
                "success": True,
                "logs": "Sandbox verification successful. Clean configuration achieved.",
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