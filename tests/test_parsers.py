from core.parsers import ThreatDataParser


def test_tier1_weighted_scoring():
    parser = ThreatDataParser()

    # Case 1: Multiple Tier-1 detections must yield CRITICAL RISK
    res_critical = parser._calculate_weighted_threat_level(
        malicious_count=2, 
        suspicious_count=0, 
        tier1_flagged=["crowdstrike", "microsoft"]
    )
    assert "CRITICAL" in res_critical

    # Case 2: Only 1 non-tier-1 engine detection must yield LOW RISK (False positive tolerance)
    res_low = parser._calculate_weighted_threat_level(
        malicious_count=1, 
        suspicious_count=0, 
        tier1_flagged=[]
    )
    assert "LOW" in res_low