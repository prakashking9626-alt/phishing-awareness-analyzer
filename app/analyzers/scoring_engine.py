"""
Centralized Risk Scoring Engine for Phishing Awareness Analyzer.
Computes deterministic, deduplicated risk scores, severity classifications,
and educational remediation guidance.
"""
from typing import List, Dict, Any

SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFORMATIONAL": 0
}

TIER_LOW = "LOW RISK"
TIER_MEDIUM = "MEDIUM RISK"
TIER_HIGH = "HIGH RISK"

MANDATORY_DISCLAIMER = (
    "This assessment is generated through offline heuristic rule-based detection for awareness and educational screening. "
    "It does not provide definitive threat attribution or prove an artifact is benign. "
    "'No obvious threat detected' does NOT mean the destination is verified safe."
)


def calculate_risk_score(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes a deduplicated, weighted risk score (0 to 100) from detected indicators.
    Prevents artificial score inflation by deduplicating indicators with identical IDs.
    """
    if not indicators:
        return {
            "score": 0,
            "tier": TIER_LOW,
            "category": "No Obvious Threat Detected",
            "badge_color": "emerald",
            "hex_color": "#10b981",
            "verdict": "No obvious static threat indicators detected. This does not confirm the destination is safe. Always verify independently before entering credentials.",
            "deduplicated_indicators": [],
            "remediations": [
                "Always verify destination web addresses before submitting sensitive data.",
                "Keep software, browsers, and multifactor authentication tokens up-to-date.",
                "Remember that newly registered or targeted phishing sites may lack obvious static indicators."
            ],
            "disclaimer": MANDATORY_DISCLAIMER
        }

    seen_ids = set()
    deduped_indicators = []
    raw_score = 0
    has_critical = False
    has_high = False
    has_suspicious = False

    for ind in indicators:
        ind_id = ind.get("id", "UNKNOWN")
        if ind_id in seen_ids:
            continue
        seen_ids.add(ind_id)
        deduped_indicators.append(ind)

        severity = ind.get("severity", "LOW").upper()
        if severity == "CRITICAL":
            has_critical = True
            has_suspicious = True
        elif severity == "HIGH":
            has_high = True
            has_suspicious = True
        elif severity in ("MEDIUM", "LOW"):
            has_suspicious = True

        weight = SEVERITY_WEIGHTS.get(severity, 5)
        raw_score += weight

    # Security Floor: If a HIGH or CRITICAL severity indicator is detected (e.g. typosquatting, shortener, brand spoofing),
    # the artifact cannot be classified as "LOW RISK" (0-24). It must be elevated to at least MEDIUM RISK (min 25).
    if has_critical and raw_score < 35:
        raw_score = 35
    elif has_high and raw_score < 25:
        raw_score = 25

    # Enforce score boundaries strictly between 0 and 100
    final_score = max(0, min(100, raw_score))

    # Determine Risk Classification Tier & Category
    if final_score == 0 or not has_suspicious:
        tier = TIER_LOW
        category = "No Obvious Threat Detected"
        badge_color = "emerald"
        hex_color = "#10b981"
        verdict = "No obvious static threat indicators detected. This does not confirm the destination is safe. Always verify independently before entering credentials."
    elif final_score <= 24:
        tier = TIER_LOW
        category = "No Obvious Threat Detected"
        badge_color = "emerald"
        hex_color = "#10b981"
        verdict = "Low risk index: Minor potential indicator(s) noted, but insufficient to establish active phishing. Does not confirm safety; review findings below."
    elif final_score <= 59:
        tier = TIER_MEDIUM
        category = "Suspicious"
        badge_color = "amber"
        hex_color = "#f59e0b"
        verdict = "Suspicious indicators detected. Exercise caution and verify via independent channels."
    else:
        tier = TIER_HIGH
        category = "High Risk"
        badge_color = "crimson"
        hex_color = "#ef4444"
        verdict = "Multiple high-severity phishing indicators detected. Do not interact, click links, or supply credentials."

    # Extract deduplicated actionable remediation recommendations
    remediations = []
    for ind in deduped_indicators:
        rec = ind.get("recommendation")
        if rec and rec not in remediations:
            remediations.append(rec)

    if not remediations:
        remediations.append("Exercise routine cyber hygiene and verify unexpected communications.")

    return {
        "score": final_score,
        "tier": tier,
        "category": category,
        "badge_color": badge_color,
        "hex_color": hex_color,
        "verdict": verdict,
        "deduplicated_indicators": deduped_indicators,
        "remediations": remediations,
        "disclaimer": MANDATORY_DISCLAIMER
    }


def evaluate_artifact(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combines analyzer output (URL or Email) with centralized risk scoring.
    """
    indicators = analysis_result.get("indicators", [])
    scoring_result = calculate_risk_score(indicators)

    return {
        "is_valid": analysis_result.get("is_valid", False),
        "error": analysis_result.get("error"),
        "scoring": scoring_result,
        "parsed_components": analysis_result.get("parsed_components", {}),
        "extracted_urls": analysis_result.get("extracted_urls", []),
        "advisory_notice": analysis_result.get("advisory_notice")
    }
