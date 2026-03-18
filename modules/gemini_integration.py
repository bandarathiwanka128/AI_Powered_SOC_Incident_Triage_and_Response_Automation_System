"""
Gemini AI Integration
Generates human-readable incident summaries and remediation tips
"""

import google.generativeai as genai
from config import GEMINI_API_KEY


class GeminiAnalyst:
    """Uses Gemini to generate incident summaries and remediation advice."""

    def __init__(self):
        self.enabled = bool(GEMINI_API_KEY)
        if self.enabled:
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel("gemini-1.5-flash")

    def generate_summary(self, incident: dict) -> str:
        """Generate a plain-English incident summary."""
        if not self.enabled:
            return self._fallback_summary(incident)

        prompt = f"""You are a senior SOC analyst assistant. Write a brief, professional incident summary for a SOC dashboard.

Incident details:
- Attack Type: {incident['attack_type']}
- Severity: {incident['severity_level']} (Score: {incident['severity_score']}/100)
- Source IP: {incident['src_ip']}
- Destination IP: {incident['dst_ip']}
- Destination Port: {incident['dst_port']}
- MITRE ATT&CK: {incident['mitre_id']} - {incident['mitre_name']}
- Confidence: {incident['confidence']:.0%}

Write:
1. A 2-sentence plain-English description of what happened
2. The top 3 immediate recommended actions
Keep it concise and professional. Use bullet points for actions."""

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return self._fallback_summary(incident) + f"\n\n_(Gemini unavailable: {e})_"

    def _fallback_summary(self, incident: dict) -> str:
        """Fallback summary when Gemini is not configured."""
        return f"""**{incident['severity_level']} Alert: {incident['attack_type']} Detected**

A {incident['attack_type']} attack was detected from IP **{incident['src_ip']}** targeting **{incident['dst_ip']}:{incident['dst_port']}**.
This maps to MITRE ATT&CK technique **{incident['mitre_id']}** ({incident['mitre_name']}) under the **{incident.get('mitre_tactic', 'N/A')}** tactic.

**Recommended immediate actions:**
- Review the source IP reputation in threat intelligence platforms
- Check for related activity from the same source
- Follow your role-based playbook below

_Configure your Gemini API key in `.env` for AI-generated summaries._"""
