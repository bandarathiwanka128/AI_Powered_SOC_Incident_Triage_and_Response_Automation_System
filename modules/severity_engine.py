"""
Severity Scoring Engine
Classifies alerts as Low / Medium / High / Critical
"""


class SeverityEngine:
    """Scores and classifies alert severity."""

    SEVERITY_MATRIX = {
        "Brute Force": {"base_score": 65, "escalation_factor": 1.3},
        "Port Scan": {"base_score": 35, "escalation_factor": 1.1},
        "DoS": {"base_score": 80, "escalation_factor": 1.4},
        "DDoS": {"base_score": 90, "escalation_factor": 1.5},
        "Web Attack": {"base_score": 70, "escalation_factor": 1.2},
        "Infiltration": {"base_score": 85, "escalation_factor": 1.4},
        "Bot": {"base_score": 55, "escalation_factor": 1.2},
        "Benign": {"base_score": 0, "escalation_factor": 1.0},
    }

    def score(self, attack_type: str, features: dict, confidence: float) -> dict:
        """Calculate severity score and level for an incident."""
        matrix = self.SEVERITY_MATRIX.get(attack_type, {"base_score": 0, "escalation_factor": 1.0})
        base = matrix["base_score"]
        factor = matrix["escalation_factor"]

        # Adjust score based on features
        score = base * confidence

        # Boost score for high packet counts (volumetric attacks)
        if features.get("pkt_count", 0) > 50000:
            score *= factor

        # Boost for multiple failed logins
        if features.get("failed_logins", 0) > 20:
            score = min(score * 1.2, 100)

        score = min(round(score, 1), 100)

        if score >= 80:
            level = "Critical"
        elif score >= 60:
            level = "High"
        elif score >= 30:
            level = "Medium"
        else:
            level = "Low"

        return {"score": score, "level": level}

    def should_show(self, severity_level: str, filter_level: str) -> bool:
        """Check if alert passes the noise filter threshold."""
        order = ["Low", "Medium", "High", "Critical"]
        return order.index(severity_level) >= order.index(filter_level)
