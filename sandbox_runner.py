import difflib

class SandboxValidationRunner:
    def __init__(self):
        pass

    def generate_perfect_diff(self, original_code: str, patched_code: str, file_path: str) -> str:
        orig_lines = original_code.splitlines(keepends=True)
        patch_lines = patched_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            patch_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def validate_code_syntax(self, code_source: str, file_path: str) -> bool:
        # Catch markdown wrapper leaking from the LLM response before doing anything else
        stripped = code_source.strip()
        if stripped.startswith("```"):
            raise SyntaxError(
                "LLM output contains a markdown code-fence wrapper (```). "
                "Return raw source code only — strip all backtick fences."
            )

        target_clean = file_path.lower()

        if "requirements.txt" in target_clean or target_clean.endswith(".txt"):
            for i, line in enumerate(code_source.splitlines(), 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                if any(clean_line.startswith(x) for x in ["def ", "import ", "class ", "return ", "print("]):
                    raise SyntaxError(
                        f"Line {i}: requirements.txt contains Python code: '{clean_line}'"
                    )
            return True

        try:
            compile(code_source, "<sandbox_validate>", "exec")
            return True
        except SyntaxError as e:
            context = e.text.strip() if e.text else ""
            raise SyntaxError(f"Line {e.lineno}: {e.msg} — context: '{context}'")

    def run_sandbox_pipeline(self, original_code: str, proposed_code: str, file_path: str) -> dict:
        if not proposed_code or not proposed_code.strip():
            return {
                "success": False,
                "logs": "LLM returned an empty response.",
                "patched_code": None,
                "generated_diff": None,
            }

        try:
            self.validate_code_syntax(proposed_code, file_path)
            perfect_diff = self.generate_perfect_diff(original_code, proposed_code, file_path)
            return {
                "success": True,
                "logs": "Sandbox verification passed — syntax is valid.",
                "patched_code": proposed_code,
                "generated_diff": perfect_diff,
            }
        except Exception as e:
            return {
                "success": False,
                "logs": str(e),
                "patched_code": None,
                "generated_diff": None,
            }
