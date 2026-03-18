"""
Role-Based Playbook Engine
Provides L1/L2/L3 SOC analyst guidance based on incident type and severity
"""

PLAYBOOKS = {
    "Brute Force": {
        "L1": {
            "title": "Brute Force Attack — L1 Response",
            "steps": [
                "Document the incident: source IP, target account, timestamp",
                "Check if any login attempts SUCCEEDED (look for success after failures)",
                "If Critical severity: Escalate to L2 immediately — do NOT attempt to resolve",
                "If High severity: Block source IP at firewall and escalate to L2",
                "If Medium severity: Log the incident and monitor for 30 minutes",
                "Complete incident ticket with all observed details",
            ],
            "escalate_if": "Critical or High severity, or if any login succeeded",
            "tools": ["SIEM", "Firewall Console", "Ticketing System"],
        },
        "L2": {
            "title": "Brute Force Attack — L2 Response",
            "steps": [
                "Verify L1 report and review full authentication logs",
                "Determine if any accounts were compromised (check for successful logins post-attack)",
                "Block source IP at perimeter firewall and WAF",
                "Force password reset on all targeted accounts",
                "Enable account lockout policy if not active (lock after 5 failed attempts)",
                "Enable MFA on affected accounts",
                "Check for lateral movement from the source IP in other logs",
                "Search threat intel platforms for the attacker IP reputation",
                "Document findings and remediation actions",
                "Escalate to L3 if compromise confirmed or if part of coordinated campaign",
            ],
            "escalate_if": "Successful compromise confirmed, or multi-target campaign detected",
            "tools": ["SIEM", "EDR", "Firewall", "Threat Intel Platform", "AD Console"],
        },
        "L3": {
            "title": "Brute Force Attack — L3 Response",
            "steps": [
                "Full forensic analysis of compromised accounts",
                "Review all systems accessed from attacker IP in last 30 days",
                "Hunt for persistence mechanisms (new accounts, scheduled tasks, registry keys)",
                "Determine if data exfiltration occurred",
                "Coordinate with IT to rotate all potentially exposed credentials",
                "Review and harden authentication policies globally",
                "Prepare incident report for management",
                "Update detection rules to catch similar future attacks",
                "Consider threat intelligence sharing with ISACs",
            ],
            "escalate_if": "Evidence of data breach — notify legal/compliance team",
            "tools": ["SIEM", "EDR", "DFIR Tools", "Threat Intel", "Network Forensics"],
        },
    },
    "Port Scan": {
        "L1": {
            "title": "Port Scan Detected — L1 Response",
            "steps": [
                "Log source IP and scan details (ports targeted, scan type)",
                "Check if source IP is internal or external",
                "If external: This is reconnaissance — document and escalate to L2",
                "If internal: Could be authorized scan — verify with IT team first",
                "Monitor source IP for follow-up attack activity",
            ],
            "escalate_if": "External source, or if followed by intrusion attempt",
            "tools": ["SIEM", "Network Monitor", "Ticketing System"],
        },
        "L2": {
            "title": "Port Scan Detected — L2 Response",
            "steps": [
                "Identify all ports/services discovered by attacker",
                "Check vulnerability databases for discovered open services",
                "Block source IP if confirmed malicious",
                "Review firewall rules — close unnecessary open ports",
                "Check for follow-up exploitation attempts from same IP",
                "Update IDS/IPS signatures for this scanner pattern",
            ],
            "escalate_if": "Follow-up exploitation detected",
            "tools": ["SIEM", "Vulnerability Scanner", "Firewall", "IDS/IPS"],
        },
        "L3": {
            "title": "Port Scan — L3 Threat Hunting",
            "steps": [
                "Correlate scan with known threat actor TTPs",
                "Hunt for exploitation attempts on discovered services",
                "Review patch status of all exposed services",
                "Consider deception technology (honeypots) to track attacker",
                "Update threat model with newly discovered attack surface",
            ],
            "escalate_if": "Part of APT campaign",
            "tools": ["Threat Intel", "SIEM", "Honeypot", "DFIR Tools"],
        },
    },
    "DoS": {
        "L1": {
            "title": "DoS Attack — L1 Response",
            "steps": [
                "Confirm service degradation or outage",
                "Immediately notify L2 and on-call network team",
                "Document attack start time, source IP, targeted service",
                "Do NOT attempt to resolve — this requires L2/L3 intervention",
                "Monitor for service restoration",
            ],
            "escalate_if": "Always — DoS requires immediate L2 escalation",
            "tools": ["SIEM", "Network Monitor", "Ticketing System"],
        },
        "L2": {
            "title": "DoS Attack — L2 Response",
            "steps": [
                "Activate DDoS mitigation service (Cloudflare, AWS Shield, etc.)",
                "Apply rate limiting rules on edge routers",
                "Block attacking IP ranges at upstream provider if possible",
                "Engage ISP for traffic scrubbing if volumetric attack",
                "Isolate affected systems if necessary",
                "Communicate service status to stakeholders",
                "Document attack vectors and mitigation steps",
            ],
            "escalate_if": "Service remains down after mitigation attempts",
            "tools": ["DDoS Mitigation Platform", "Router/Firewall", "ISP NOC Contact"],
        },
        "L3": {
            "title": "DoS Attack — L3 Response",
            "steps": [
                "Full post-incident analysis",
                "Review network architecture for DDoS resilience gaps",
                "Update runbooks and response procedures",
                "Conduct tabletop exercise for future DDoS scenarios",
                "Evaluate permanent DDoS protection solutions",
            ],
            "escalate_if": "Business impact assessment requires executive briefing",
            "tools": ["Network Architecture Review", "Business Continuity Planning"],
        },
    },
    "DDoS": {
        "L1": {
            "title": "DDoS Attack — L1 Response",
            "steps": [
                "Immediately escalate to L2 and network on-call — this is Critical",
                "Document attack start time and affected services",
                "Notify stakeholders of potential service disruption",
            ],
            "escalate_if": "Always — immediate L2 escalation required",
            "tools": ["Ticketing System", "Communication Channels"],
        },
        "L2": {
            "title": "DDoS Attack — L2 Response",
            "steps": [
                "Activate upstream DDoS scrubbing service immediately",
                "Implement geo-blocking if attack originates from specific regions",
                "Enable anycast routing to distribute attack traffic",
                "Contact ISP for BGP blackholing if needed",
                "Redirect traffic through CDN with DDoS protection",
                "Continuously monitor attack vector and adapt mitigation",
                "Provide 30-minute status updates to management",
            ],
            "escalate_if": "Critical infrastructure affected, or attack > 2 hours",
            "tools": ["CDN/DDoS Mitigation", "BGP Console", "ISP NOC", "Network Monitoring"],
        },
        "L3": {
            "title": "DDoS — L3 Strategic Response",
            "steps": [
                "Conduct forensic analysis of attack vectors",
                "Review and update DDoS response playbooks",
                "Evaluate long-term DDoS protection architecture",
                "Coordinate with law enforcement if attack is sustained campaign",
                "Prepare executive briefing and business impact report",
            ],
            "escalate_if": "Legal/law enforcement involvement needed",
            "tools": ["Architecture Review", "Legal/Compliance", "Executive Communication"],
        },
    },
    "Web Attack": {
        "L1": {
            "title": "Web Attack Detected — L1 Response",
            "steps": [
                "Identify attacked URL/endpoint and attack type (SQLi, XSS, etc.)",
                "Check if attack was blocked by WAF or if it succeeded",
                "Document source IP and attack payload",
                "Escalate to L2 if attack appears to have succeeded",
                "Block source IP in WAF",
            ],
            "escalate_if": "Attack bypassed WAF or application returned error/sensitive data",
            "tools": ["WAF Console", "Web Server Logs", "SIEM"],
        },
        "L2": {
            "title": "Web Attack — L2 Response",
            "steps": [
                "Review web server and application logs for successful exploitation",
                "Check for data extraction (look for large response sizes to attacker IP)",
                "Update WAF rules to block the specific attack pattern",
                "Patch the vulnerable application component if identified",
                "Review application for similar vulnerabilities",
                "Check for web shells or backdoors if exploitation confirmed",
                "Notify application development team",
            ],
            "escalate_if": "Data breach suspected or web shell detected",
            "tools": ["WAF", "Application Logs", "SAST/DAST Tools", "EDR"],
        },
        "L3": {
            "title": "Web Attack — L3 Response",
            "steps": [
                "Full application security assessment",
                "Review OWASP Top 10 compliance",
                "Conduct penetration test on affected application",
                "Review secure coding practices with development team",
                "Implement bug bounty program if not existing",
            ],
            "escalate_if": "PII/sensitive data confirmed exfiltrated — GDPR/compliance notification required",
            "tools": ["Pentest Tools", "Code Review", "Compliance Framework"],
        },
    },
    "Bot": {
        "L1": {
            "title": "Bot Traffic Detected — L1 Response",
            "steps": [
                "Identify bot behavior pattern (scraping, credential stuffing, spam)",
                "Document source IPs and traffic volume",
                "Block known bot IPs in WAF",
                "Escalate to L2 for bot network analysis",
            ],
            "escalate_if": "Credential stuffing or large-scale scraping detected",
            "tools": ["WAF", "SIEM", "Web Analytics"],
        },
        "L2": {
            "title": "Bot Traffic — L2 Response",
            "steps": [
                "Implement CAPTCHA on targeted endpoints",
                "Enable rate limiting per IP",
                "Add bot management solution if not present",
                "Check for successful credential stuffing (password spray check)",
                "Block entire ASN if bot traffic from cloud/VPS providers",
                "Update bot signatures in WAF",
            ],
            "escalate_if": "Credential stuffing yielded successful logins",
            "tools": ["Bot Management Platform", "WAF", "Rate Limiter"],
        },
        "L3": {
            "title": "Bot Network — L3 Analysis",
            "steps": [
                "Analyze bot network infrastructure",
                "Correlate with threat intelligence (known botnets)",
                "Evaluate long-term bot protection strategy",
                "Consider threat intelligence sharing",
            ],
            "escalate_if": "Part of known botnet — share with threat intel community",
            "tools": ["Threat Intel", "Network Forensics", "ISAC Portals"],
        },
    },
    "Infiltration": {
        "L1": {
            "title": "Infiltration Detected — L1 Response",
            "steps": [
                "IMMEDIATELY escalate to L2 — do not attempt to resolve",
                "Document all observed indicators: IP addresses, accounts, timestamps",
                "Do NOT alert the attacker by changing passwords yet (L2 will coordinate)",
                "Preserve all logs — do not clear or rotate logs",
            ],
            "escalate_if": "Always — Infiltration is always Critical",
            "tools": ["Ticketing System", "SIEM (read-only)"],
        },
        "L2": {
            "title": "Infiltration — L2 Incident Response",
            "steps": [
                "Immediately contain affected systems (network isolation)",
                "Preserve forensic evidence before any remediation",
                "Identify compromised accounts and revoke credentials",
                "Trace lateral movement paths",
                "Identify data that may have been accessed or exfiltrated",
                "Activate incident response plan",
                "Engage L3 and management immediately",
            ],
            "escalate_if": "Always escalate to L3 — confirmed breach",
            "tools": ["EDR", "DFIR Tools", "Network Forensics", "SIEM"],
        },
        "L3": {
            "title": "Infiltration — L3 Full IR",
            "steps": [
                "Full digital forensics investigation",
                "Scope the breach completely",
                "Eradicate all attacker presence",
                "Coordinate with legal and compliance teams",
                "Notify affected parties if data breach confirmed (GDPR/local law)",
                "Coordinate with law enforcement if required",
                "Full system rebuild of compromised hosts",
                "Post-incident review and lessons learned",
                "Update detection and prevention controls",
            ],
            "escalate_if": "Regulatory notification required — engage legal team",
            "tools": ["DFIR Tools", "Legal/Compliance", "Law Enforcement", "Executive Team"],
        },
    },
    "Benign": {
        "L1": {
            "title": "No Threat Detected",
            "steps": ["Normal traffic. No action required.", "Continue monitoring."],
            "escalate_if": "None",
            "tools": [],
        },
        "L2": {
            "title": "No Threat Detected",
            "steps": ["Normal traffic. No action required."],
            "escalate_if": "None",
            "tools": [],
        },
        "L3": {
            "title": "No Threat Detected",
            "steps": ["Normal traffic. No action required."],
            "escalate_if": "None",
            "tools": [],
        },
    },
}


class PlaybookEngine:
    """Retrieves role-based playbook for a given incident."""

    def get_playbook(self, attack_type: str, analyst_role: str) -> dict:
        attack_playbooks = PLAYBOOKS.get(attack_type, PLAYBOOKS["Benign"])
        return attack_playbooks.get(analyst_role, attack_playbooks["L1"])
