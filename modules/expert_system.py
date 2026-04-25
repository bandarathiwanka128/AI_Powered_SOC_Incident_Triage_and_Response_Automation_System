"""
Expert System for SOC Alert Classification
Uses rule-based reasoning + MITRE ATT&CK mapping

Pipeline order (app.py / api_server.py):
  Stage 1 — MLPredictor  : ANN model runs FIRST on every row (most accurate)
  Stage 2 — PreFilter    : only runs when ANN confidence < 0.7 — resolves
                           clear-cut cases the model was uncertain about
  Stage 3 — ExpertSystem : final fallback when both ANN and PreFilter give
                           no high-confidence answer

Why ANN comes before PreFilter:
  • Pre-filter rules are deterministic and have no nuance — a legitimate user
    mistyping their SSH password 6 times would be permanently mis-labeled as
    Brute Force if pre-filter ran first.
  • ANN cross-validates every result; pre-filter only acts as a tie-breaker.
  • Attack types not covered by any pre-filter rule (Infiltration, DoS Hulk,
    Heartbleed…) go straight ANN → Expert System without wasting a rule scan.
"""

from config import MITRE_MAPPING


class PreFilter:
    """
    Stage 2: Deterministic rules used ONLY when the ANN model is uncertain
    (confidence < 0.7).  Resolves clear-cut, high-volume patterns the model
    may under-score due to limited training class coverage.

    Runs AFTER the ANN, not before.  This means:
      - ANN always gets the first say → no rule can silently override it.
      - False-positive risk is contained: a rule can only fire when the ANN
        itself already failed to classify with confidence.
      - Attack types not covered by any rule (Infiltration, DoS Hulk, etc.)
        cost nothing extra — the rule scan is never reached for ANN-confident rows.

    Thresholds are deliberately strict (high packet counts, many source IPs)
    so only unambiguous volumetric / obvious-pattern events are caught here.
    """

    # flow_duration from CICIDS2017 is in microseconds → 10 s = 10_000_000 µs
    _RULES = [
        {
            "name": "SSH Brute Force (Pre-filter)",
            "conditions": lambda f: (
                f.get("dst_port") == 22
                and f.get("failed_logins", 0) > 5
            ),
            "attack_type": "Brute Force",
            "confidence": 0.97,
        },
        {
            "name": "FTP Brute Force (Pre-filter)",
            "conditions": lambda f: (
                f.get("dst_port") == 21
                and f.get("failed_logins", 0) > 5
            ),
            "attack_type": "Brute Force",
            "confidence": 0.95,
        },
        {
            "name": "Volumetric DDoS (Pre-filter)",
            "conditions": lambda f: (
                f.get("pkt_count", 0) > 50000
                and f.get("unique_src_ips", 1) > 50
            ),
            "attack_type": "DDoS",
            "confidence": 0.98,
        },
        {
            "name": "Aggressive Port Scan (Pre-filter)",
            "conditions": lambda f: (
                f.get("unique_ports", 0) > 50
                and f.get("flow_duration", 0) < 10_000_000   # < 10 s in µs
            ),
            "attack_type": "Port Scan",
            "confidence": 0.96,
        },
    ]

    def detect(self, features: dict):
        """
        Returns a classification dict (with stage='Pre-filter') if any rule
        matches, otherwise returns None so the caller can move to Stage 2.
        """
        for rule in self._RULES:
            try:
                if rule["conditions"](features):
                    return {
                        "attack_type": rule["attack_type"],
                        "confidence":  rule["confidence"],
                        "rule_name":   rule["name"],
                        "mitre":       MITRE_MAPPING.get(rule["attack_type"], MITRE_MAPPING["Benign"]),
                        "stage":       "Pre-filter",
                    }
            except Exception:
                continue
        return None


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
                "confidence":  0.95,
                "rule_name":   "No threat detected",
                "mitre":       MITRE_MAPPING["Benign"],
                "stage":       "Expert System",
            }

        # Pick highest confidence match
        best = max(matched_rules, key=lambda r: r["confidence"])
        return {
            "attack_type": best["attack_type"],
            "confidence":  best["confidence"],
            "rule_name":   best["name"],
            "mitre":       MITRE_MAPPING.get(best["attack_type"], MITRE_MAPPING["Benign"]),
            "stage":       "Expert System",
        }
