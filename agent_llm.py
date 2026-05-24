import os
from openai import OpenAI

class PatchGenerationEngine:
    def __init__(self):
        openrouter_url = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
        openrouter_key = os.getenv("OPENROUTER_API_KEY", os.getenv("OPENAI_API_KEY"))
        self.model_name = os.getenv("LLM_MODEL_NAME", "openai/gpt-oss-120b:free")

        self.client = OpenAI(
            api_key=openrouter_key,
            base_url=openrouter_url,
            default_headers={
                "HTTP-Referer": "https://github.com/veripatch/veripatch-core",
                "X-Title": "VeriPatch Remediation Agent",
            }
        )

    def _get_system_prompt(self) -> str:
        return (
            "You are an elite automated security patch engineer. "
            "Your task is to fix a specific CVE vulnerability in a source code file.\n\n"

            "SECURITY REASONING PROCESS (apply silently before writing code):\n"
            "1. Identify the root cause: which function, pattern, or missing control enables the vulnerability\n"
            "2. Determine the minimal, targeted fix — avoid touching unrelated logic\n"
            "3. Verify your fix does not break existing function signatures, return types, or business logic\n"
            "4. Confirm the fix follows language-specific security best practices "
            "(e.g., use `secrets` instead of `random` for tokens, parameterized queries for SQL, "
            "`subprocess` list args instead of shell=True, `hmac.compare_digest` for constant-time comparison)\n\n"

            "OUTPUT RULES (strictly enforced):\n"
            "- Return ONLY the complete updated source file inside a single ```<language> ... ``` block\n"
            "- Fix ONLY the reported vulnerability — do not refactor, rename, or improve unrelated code\n"
            "- Preserve all existing function names, class names, and comments\n"
            "- Keep all imports unrelated to the fix exactly as-is\n"
            "- If the fix requires a new import, add it at the top alongside existing imports\n"
            "- Never omit lines — do not use '# ... rest of code' or any placeholder\n"
            "- Do not add explanatory text, TODOs, or inline comments about your changes outside the code block"
        )

    def _detect_language(self, file_path: str) -> str:
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        return {
            "py": "python", "js": "javascript", "ts": "typescript",
            "go": "go", "java": "java", "rb": "ruby", "rs": "rust",
            "txt": "text", "yml": "yaml", "yaml": "yaml", "json": "json",
        }.get(ext, "text")

    def generate_patch(
        self,
        cve_id: str,
        file_path: str,
        file_content: str,
        vulnerability_details: str,
        previous_error: str = None,
    ) -> str:
        language = self._detect_language(file_path)

        user_payload = (
            f"CVE ID: {cve_id}\n"
            f"File: {file_path}\n"
            f"Language: {language}\n"
            f"Vulnerability: {vulnerability_details}\n\n"
            f"--- CURRENT FILE CONTENT ---\n{file_content}\n--- END FILE CONTENT ---"
        )

        if previous_error:
            user_payload += (
                f"\n\n[PREVIOUS ATTEMPT FAILED]\n"
                f"Validation error: {previous_error}\n\n"
                "Common causes of failure:\n"
                "- Indentation error: new code must align with the surrounding block's indent level\n"
                "- Missing import: add required imports at the top with existing imports\n"
                "- Syntax error: re-read surrounding context carefully before writing the fix\n"
                "- Incomplete output: never truncate — include every line of the original file\n\n"
                "Fix the error above and return the complete corrected file."
            )

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": user_payload},
                ],
            )
            raw_output = response.choices[0].message.content.strip()

            # Extract code from markdown wrapper — try language-specific fence first
            if f"```{language}" in raw_output:
                raw_output = raw_output.split(f"```{language}")[1].split("```")[0].strip()
            elif "```python" in raw_output:
                raw_output = raw_output.split("```python")[1].split("```")[0].strip()
            elif "```" in raw_output:
                raw_output = raw_output.split("```")[1].split("```")[0].strip()

            return raw_output

        except Exception as e:
            raise RuntimeError(f"OpenRouter connection error: {e}")
