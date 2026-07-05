def calculate_risk_score(cvss_score: float, business_criticality: str) -> float:
    multipliers = {
        "Critical": 1.5,
        "High": 1.2,
        "Medium": 1.0,
        "Low": 0.7
    }
    multiplier = multipliers.get(business_criticality, 1.0)
    adjusted_score = cvss_score * multiplier
    return min(10.0, max(0.0, round(adjusted_score, 2)))
