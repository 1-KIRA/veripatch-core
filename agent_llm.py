import os
from openai import OpenAI

class PatchGenerationEngine:
    def __init__(self):
        openrouter_url = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
        openrouter_key = os.getenv("OPENROUTER_API_KEY", os.getenv("OPENAI_API_KEY"))
        self.model_name = os.getenv("LLM_MODEL_NAME", "openai/gpt-oss-120b:free")

        extra_headers = {
            "HTTP-Referer": "https://github.com/veripatch/veripatch-core", 
            "X-Title": "VeriPatch Remediation Agent",
        }

        self.client = OpenAI(
            api_key=openrouter_key,
            base_url=openrouter_url,
            default_headers=extra_headers
        )

    def _get_system_prompt(self) -> str:
        return """You are an automated, elite enterprise software security patch engineer.
Your sole job is to resolve the provided CVE vulnerability by rewriting the target source code file.

CRITICAL RULES:
1. Return the ENTIRE updated source code file. Do not omit any lines, do not use placeholders like '# ... rest of code'.
2. Fix ONLY the security vulnerability. Do not alter unrelated business logic.
3. Output ONLY the raw updated code inside a single ```python ... ``` markdown block.
4. Do not include any conversational text, explanations, or commentary outside the markdown block.
"""

    def generate_patch(self, cve_id: str, file_path: str, file_content: str, vulnerability_details: str, previous_error: str = None) -> str:
        """
        Dispatches context to OpenRouter, returning the full updated file code string.
        """
        user_payload = f"Target CVE: {cve_id}\n"
        user_payload += f"Target File Path: {file_path}\n"
        user_payload += f"Vulnerability Details: {vulnerability_details}\n\n"
        user_payload += f"--- CURRENT FILE CONTENT TO REMEDIATE ---\n{file_content}\n"
        
        if previous_error:
            user_payload += f"\n[CRITICAL FAILURE] Your previous attempt failed compilation with this error:\n{previous_error}\n"
            user_payload += "Please fix the code syntax and output the complete corrected file content."

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                temperature=0.0, 
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": user_payload}
                ]
            )
            raw_output = response.choices[0].message.content.strip()
            
            # Programmatically extract the clean code from the markdown wrapper blocks
            if "```python" in raw_output:
                raw_output = raw_output.split("```python")[1].split("```")[0].strip()
            elif "```" in raw_output:
                raw_output = raw_output.split("```")[1].split("```")[0].strip()
                
            return raw_output
            
        except Exception as e:
            raise RuntimeError(f"OpenRouter Connection Error: {str(e)}")