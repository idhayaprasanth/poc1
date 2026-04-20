"""Optimized Gemini-powered security chatbot helpers."""

import time

from security_dashboard.services.gemini_base import (
    GeminiRateLimitError,
    _TruncatedResponseError,
    _should_skip_gemini,
    get_gemini_pause_status,
)

# 🔹 Faster lookup (tuple + lowercase once)
SECURITY_KEYWORDS = tuple(k.lower() for k in [
    "security", "cyber", "cybersecurity", "infosec", "vulnerability", "vuln",
    "cve", "risk", "threat", "incident", "malware", "ransomware", "phishing",
    "exploit", "patch", "edr", "siem", "soc", "ids", "ips", "waf", "firewall",
    "splunk", "tenable", "defender", "bigfix", "ioc", "attack", "breach",
    "mitre", "tactic", "remediation", "remediate", "severity", "critical",
    "high", "medium", "low", "asset", "hostname", "server", "virus",
    "antivirus", "secure", "protect", "endpoint", "windows defender",
])


def is_security_question(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(k in lowered for k in SECURITY_KEYWORDS)


# 🔹 Shorter system prompt (token optimized)
SYSTEM_PROMPT = (
    "You are a cybersecurity assistant. Answer only security-related questions. "
    "Use provided context. Be concise and actionable. Do not invent data."
)


def _fallback_security_answer(question: str, context_text: str) -> str:
    q = (question or "").lower()

    if not q:
        return "Please ask a cybersecurity-related question."

    if any(x in q for x in ("high risk", "critical", "top risk")):
        return "Focus on high-risk assets and active threats first."

    if any(x in q for x in ("remediation", "fix", "mitigate")):
        return (
            "1) Isolate affected systems\n"
            "2) Patch vulnerabilities\n"
            "3) Remove threats\n"
            "4) Harden configs\n"
            "5) Monitor via SIEM/EDR"
        )

    if "patch" in q:
        return "Prioritize assets with missing patches, especially Critical/High severity."

    return (
        "Gemini unavailable. Provide a more specific security question.\n\n"
        f"Context:\n{context_text}"
    )


class GeminiChatbotMixin:
    # 🔹 Unified Gemini call (removes duplicate loops)
    def _ask_gemini(self, payload):
        tried = []
        first_error = ""

        for api_version in self._preferred_versions():
            for model_name in self._preferred_models():
                tried.append(f"{api_version}:{model_name}")
                try:
                    text, ok = self._attempt(
                        api_version=api_version,
                        model_name=model_name,
                        payload=payload,
                    )
                    if ok:
                        return text
                    if text:
                        first_error = first_error or text
                except GeminiRateLimitError:
                    raise
                except _TruncatedResponseError:
                    continue

        return first_error or None

    def generate_security_answer(
        self,
        *,
        question: str,
        context_text: str,
        history: list[dict] | None = None,
    ) -> str:
        if not self.enabled():
            return "Gemini is not configured. Set GEMINI_API_KEY."

        if not is_security_question(question):
            return "Ask a cybersecurity-related question."

        # 🔹 Rate limit handling
        if _should_skip_gemini():
            wait = float(get_gemini_pause_status().get("remaining_seconds", 0.0) or 0.0)
            if wait > 2:
                return _fallback_security_answer(question, context_text)
            time.sleep(wait)

        # 🔹 Trim history (reduce tokens)
        contents = []
        for item in (history or [])[-6:]:
            role = "model" if item.get("role") in ("assistant", "model") else "user"
            text = item.get("text")
            if text:
                contents.append({"role": role, "parts": [{"text": text}]})

        # 🔹 Main prompt
        contents.append({
            "role": "user",
            "parts": [{
                "text": f"Context:\n{context_text}\n\nQuestion:\n{question}"
            }],
        })

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": contents,
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 400,  # 🔹 reduced (was 512)
                "responseMimeType": "text/plain",
            },
        }

        try:
            response = self._ask_gemini(payload)
            if response:
                return response
        except GeminiRateLimitError:
            return _fallback_security_answer(question, context_text)

        return "AI response unavailable. Please try again."