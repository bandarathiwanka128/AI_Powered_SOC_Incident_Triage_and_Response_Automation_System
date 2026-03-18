"""
Expert System for SOC Alert Classification
Uses rule-based reasoning + MITRE ATT&CK mapping
"""

from config import MITRE_MAPPING


class ExpertSystem:
    """Rule-based expert system for classifying security events."""

    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self):
        """Define expert rules for attack classification."""
        return [
            # Brute Force rules
            {
                "name": "SSH Brute Force",
                "conditions": lambda f: (
                    f.get("dst_port") == 22
                    and f.get("failed_logins", 0) > 5
                    and f.get("protocol") == "TCP"
                ),
                "attack_type": "Brute Force",
                "confidence": 0.92,
            },
            {
                "name": "FTP Brute Force",
                "conditions": lambda f: (
                    f.get("dst_port") == 21
                    and f.get("failed_logins", 0) > 5
                ),
                "attack_type": "Brute Force",
                "confidence": 0.88,
            },
            {
                "name": "General Brute Force",
                "conditions": lambda f: f.get("failed_logins", 0) > 10,
                "attack_type": "Brute Force",
                "confidence": 0.85,
            },
            # Port Scan rules
            {
                "name": "Port Scan",
                "conditions": lambda f: (
                    f.get("unique_ports", 0) > 10
                    and f.get("pkt_count", 0) < 5
                ),
                "attack_type": "Port Scan",
                "confidence": 0.90,
            },
            # DoS/DDoS rules
            {
                "name": "DoS Attack",
                "conditions": lambda f: (
                    f.get("pkt_count", 0) > 10000
                    and f.get("unique_src_ips", 1) == 1
                ),
                "attack_type": "DoS",
                "confidence": 0.87,
            },
            {
                "name": "DDoS Attack",
                "conditions": lambda f: (
                    f.get("pkt_count", 0) > 10000
                    and f.get("unique_src_ips", 1) > 10
                ),
                "attack_type": "DDoS",
                "confidence": 0.93,
            },
            # Web Attack rules
            {
                "name": "Web Attack",
                "conditions": lambda f: (
                    f.get("dst_port") in [80, 443, 8080]
                    and f.get("anomaly_score", 0) > 0.7
                ),
                "attack_type": "Web Attack",
                "confidence": 0.80,
            },
            # Bot traffic
            {
                "name": "Bot Traffic",
                "conditions": lambda f: (
                    f.get("flow_duration", 0) > 3600
                    and f.get("pkt_count", 0) > 500
                    and f.get("anomaly_score", 0) > 0.5
                ),
                "attack_type": "Bot",
                "confidence": 0.75,
            },
        ]

    def classify(self, features: dict) -> dict:
        """
        Classify a security event using expert rules.
        Returns attack type, MITRE mapping, and confidence.
        """
        matched_rules = []

        for rule in self.rules:
            try:
                if rule["conditions"](features):
                    matched_rules.append(rule)
            except Exception:
                continue

        if not matched_rules:
            return {
                "attack_type": "Benign",
                "confidence": 0.95,
                "rule_name": "No threat detected",
                "mitre": MITRE_MAPPING["Benign"],
            }

        # Pick highest confidence match
        best = max(matched_rules, key=lambda r: r["confidence"])
        return {
            "attack_type": best["attack_type"],
            "confidence": best["confidence"],
            "rule_name": best["name"],
            "mitre": MITRE_MAPPING.get(best["attack_type"], MITRE_MAPPING["Benign"]),
        }
