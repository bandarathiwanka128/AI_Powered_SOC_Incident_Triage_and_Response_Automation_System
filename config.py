import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Severity thresholds
SEVERITY_LEVELS = {
    "Low": {"color": "#28a745", "priority": 1, "min_score": 0},
    "Medium": {"color": "#ffc107", "priority": 2, "min_score": 30},
    "High": {"color": "#fd7e14", "priority": 3, "min_score": 60},
    "Critical": {"color": "#dc3545", "priority": 4, "min_score": 80},
}

# Attack type to MITRE ATT&CK mapping
MITRE_MAPPING = {
    "Brute Force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Attacker attempts to gain access by systematically trying many passwords.",
    },
    "Port Scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Attacker probes network to discover open ports and running services.",
    },
    "DoS": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Attacker floods network to make services unavailable.",
    },
    "DDoS": {
        "id": "T1498.001",
        "name": "Direct Network Flood",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
        "description": "Multiple systems flood target with traffic.",
    },
    "Web Attack": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Attacker exploits weakness in internet-facing application.",
    },
    "Infiltration": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": "Attacker uses legitimate credentials to maintain access.",
    },
    "Bot": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Attacker uses standard protocols for C2 communication.",
    },
    "Benign": {
        "id": "N/A",
        "name": "No Threat",
        "tactic": "N/A",
        "url": "",
        "description": "Normal network traffic. No action required.",
    },
}
