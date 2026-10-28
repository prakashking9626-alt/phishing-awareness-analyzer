"""
Unit tests for the Centralized Risk Scoring Engine.
Verifies score weighting, deduplication, boundaries, and tier classifications.
"""
import unittest
from app.analyzers.scoring_engine import (
    calculate_risk_score,
    evaluate_artifact,
    TIER_LOW,
    TIER_MEDIUM,
    TIER_HIGH,
    MANDATORY_DISCLAIMER
)


class TestScoringEngine(unittest.TestCase):

    def test_empty_indicators_low_risk(self):
        """Empty indicators should yield a score of 0 and LOW RISK tier."""
        result = calculate_risk_score([])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["tier"], TIER_LOW)
        self.assertEqual(result["category"], "No Obvious Threat Detected")
        self.assertEqual(result["badge_color"], "emerald")
        self.assertIn("No obvious static threat indicators detected", result["verdict"])
        self.assertNotIn("Guaranteed Safe", result["verdict"])
        self.assertEqual(result["disclaimer"], MANDATORY_DISCLAIMER)

    def test_score_boundaries_max_100(self):
        """Compounding multiple high-severity indicators must never exceed 100."""
        indicators = [
            {"id": f"CRIT_{i}", "severity": "CRITICAL", "recommendation": f"Rec {i}"}
            for i in range(10)  # 10 * 35 = 350 points raw
        ]
        result = calculate_risk_score(indicators)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["tier"], TIER_HIGH)
        self.assertEqual(result["category"], "High Risk")
        self.assertEqual(result["badge_color"], "crimson")

    def test_deduplication_anti_inflation(self):
        """Duplicate occurrences of the exact same indicator ID should not inflate score."""
        duplicate_indicators = [
            {"id": "URL_HTTP_CLEARTEXT", "severity": "MEDIUM", "recommendation": "Use HTTPS"},
            {"id": "URL_HTTP_CLEARTEXT", "severity": "MEDIUM", "recommendation": "Use HTTPS"},
            {"id": "URL_HTTP_CLEARTEXT", "severity": "MEDIUM", "recommendation": "Use HTTPS"}
        ]
        result = calculate_risk_score(duplicate_indicators)
        # MEDIUM weight is 10. Without deduplication it would be 30.
        self.assertEqual(result["score"], 10)
        self.assertEqual(len(result["deduplicated_indicators"]), 1)
        self.assertEqual(result["tier"], TIER_LOW)

    def test_tier_thresholds(self):
        """Verify tier boundaries: Low (0-24), Medium (25-59), High (60-100)."""
        # Low Tier: 10 points
        low_res = calculate_risk_score([{"id": "IND_1", "severity": "MEDIUM"}])
        self.assertEqual(low_res["score"], 10)
        self.assertEqual(low_res["tier"], TIER_LOW)
        self.assertEqual(low_res["category"], "No Obvious Threat Detected")

        # Medium Tier: 20 + 10 = 30 points
        med_res = calculate_risk_score([
            {"id": "IND_1", "severity": "HIGH"},
            {"id": "IND_2", "severity": "MEDIUM"}
        ])
        self.assertEqual(med_res["score"], 30)
        self.assertEqual(med_res["tier"], TIER_MEDIUM)
        self.assertEqual(med_res["category"], "Suspicious")

        # High Tier: 35 + 20 + 10 = 65 points
        high_res = calculate_risk_score([
            {"id": "IND_1", "severity": "CRITICAL"},
            {"id": "IND_2", "severity": "HIGH"},
            {"id": "IND_3", "severity": "MEDIUM"}
        ])
        self.assertEqual(high_res["score"], 65)
        self.assertEqual(high_res["tier"], TIER_HIGH)
        self.assertEqual(high_res["category"], "High Risk")

    def test_high_indicator_floor_never_low_risk(self):
        """Any HIGH severity indicator must elevate score to at least 25 (MEDIUM RISK)."""
        res = calculate_risk_score([{"id": "HIGH_TYPO", "severity": "HIGH"}])
        self.assertGreaterEqual(res["score"], 25)
        self.assertEqual(res["tier"], TIER_MEDIUM)
        self.assertIn("Suspicious indicators detected", res["verdict"])

    def test_low_risk_verdict_with_minor_indicators(self):
        """When minor indicators exist, verdict must not claim zero indicators."""
        res = calculate_risk_score([{"id": "LOW_IND", "severity": "LOW"}])
        self.assertEqual(res["score"], 5)
        self.assertEqual(res["tier"], TIER_LOW)
        self.assertIn("Low risk index: Minor potential indicator(s) noted", res["verdict"])
        self.assertNotIn("No obvious static threat indicators detected", res["verdict"])

    def test_evaluate_artifact_wrapper(self):
        """evaluate_artifact should package analyzer output with scoring results."""
        analysis_payload = {
            "is_valid": True,
            "error": None,
            "indicators": [{"id": "URL_IP_HOST", "severity": "CRITICAL", "recommendation": "Avoid IP hosts"}],
            "parsed_components": {"host": "1.2.3.4"}
        }
        evaluated = evaluate_artifact(analysis_payload)
        self.assertTrue(evaluated["is_valid"])
        self.assertIn("scoring", evaluated)
        self.assertEqual(evaluated["scoring"]["score"], 35)
        self.assertEqual(evaluated["scoring"]["tier"], TIER_MEDIUM)


if __name__ == "__main__":
    unittest.main()
