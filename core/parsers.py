from datetime import datetime
from typing import Dict, Any, List

# Industry-standard enterprise EDR and AV engines
TIER1_SECURITY_ENGINES = {
    "crowdstrike",
    "microsoft",
    "kaspersky",
    "sentinelone",
    "symantec",
    "sophos",
    "palo alto networks",
    "bitdefender"
}


class ThreatDataParser:
    """Parses and normalizes raw JSON responses from the VirusTotal v3 API."""

    @staticmethod
    def _calculate_weighted_threat_level(
        malicious_count: int, 
        suspicious_count: int, 
        tier1_flagged: List[str]
    ) -> str:
        """
        Determines the risk classification using weighted scoring.
        Flags from Tier-1 enterprise vendors carry critical weight.
        """
        total_threats = malicious_count + suspicious_count

        # If 2 or more Tier-1 enterprise vendors detect it, it's immediately CRITICAL
        if len(tier1_flagged) >= 2 or total_threats >= 10:
            return "CRITICAL RISK (Malicious)"
        elif len(tier1_flagged) == 1 or (4 <= total_threats < 10):
            return "HIGH RISK"
        elif 1 <= total_threats < 4:
            return "LOW RISK (Potential False Positive)"
        else:
            return "CLEAN"

    @staticmethod
    def _format_timestamp(epoch_time: int) -> str:
        if not epoch_time:
            return "N/A"
        return datetime.utcfromtimestamp(epoch_time).strftime("%Y-%m-%d %H:%M:%S UTC")

    def parse_file_report(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        if "error" in raw_data:
            return raw_data

        data_attributes = raw_data.get("data", {}).get("attributes", {})
        stats = data_attributes.get("last_analysis_stats", {})
        results = data_attributes.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        detections: List[Dict[str, Any]] = []
        tier1_flagged: List[str] = []

        for engine, res in results.items():
            category = res.get("category")
            is_tier1 = engine.lower() in TIER1_SECURITY_ENGINES

            if category in ("malicious", "suspicious"):
                if is_tier1:
                    tier1_flagged.append(engine)

                detections.append({
                    "engine": engine,
                    "category": category.upper(),
                    "result": res.get("result") or "Generic Threat",
                    "is_tier1": is_tier1
                })

        # Sort detections so that Tier-1 engines appear at the very top of the report
        detections.sort(key=lambda x: x["is_tier1"], reverse=True)

        return {
            "target_type": "FILE HASH",
            "sha256": data_attributes.get("sha256", "N/A"),
            "md5": data_attributes.get("md5", "N/A"),
            "file_type": data_attributes.get("type_description", "Unknown"),
            "file_size_bytes": data_attributes.get("size", 0),
            "meaningful_name": data_attributes.get("meaningful_name", "N/A"),
            "first_submission": self._format_timestamp(data_attributes.get("first_submission_date")),
            "last_analysis_date": self._format_timestamp(data_attributes.get("last_analysis_date")),
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total_engines
            },
            "tier1_flagged": tier1_flagged,
            "threat_level": self._calculate_weighted_threat_level(malicious, suspicious, tier1_flagged),
            "detections": detections
        }

    def parse_url_report(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        
        if "error" in raw_data:
            return raw_data

        data_attributes = raw_data.get("data", {}).get("attributes", {})
        stats = data_attributes.get("last_analysis_stats", {})
        results = data_attributes.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        detections: List[Dict[str, Any]] = []
        tier1_flagged: List[str] = []

        for engine, res in results.items():
            category = res.get("category")
            is_tier1 = engine.lower() in TIER1_SECURITY_ENGINES

            if category in ("malicious", "suspicious"):
                if is_tier1:
                    tier1_flagged.append(engine)

                detections.append({
                    "engine": engine,
                    "category": category.upper(),
                    "result": res.get("result") or "Malicious Activity",
                    "is_tier1": is_tier1
                })

        detections.sort(key=lambda x: x["is_tier1"], reverse=True)

        return {
            "target_type": "URL",
            "url": data_attributes.get("url", "N/A"),
            "last_final_url": data_attributes.get("last_final_url", "N/A"),
            "reputation": data_attributes.get("reputation", 0),
            "last_analysis_date": self._format_timestamp(data_attributes.get("last_analysis_date")),
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total_engines
            },
            "tier1_flagged": tier1_flagged,
            "threat_level": self._calculate_weighted_threat_level(malicious, suspicious, tier1_flagged),
            "detections": detections
        }
    def parse_ip_report(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts threat intelligence indicators from an AbuseIPDB check response."""
        if "error" in raw_data:
            return raw_data

        ip_data = raw_data.get("data", {})
        abuse_score = ip_data.get("abuseConfidenceScore", 0)

        # Threat classification based on Abuse Confidence Score
        if abuse_score == 0:
            threat_level = "CLEAN"
        elif 1 <= abuse_score <= 25:
            threat_level = "LOW RISK"
        elif 26 <= abuse_score <= 75:
            threat_level = "MEDIUM RISK"
        else:
            threat_level = "CRITICAL RISK (Malicious)"

        return {
            "target_type": "IP ADDRESS",
            "ip_address": ip_data.get("ipAddress", "N/A"),
            "is_public": ip_data.get("isPublic", True),
            "ip_version": ip_data.get("ipVersion", 4),
            "is_whitelisted": ip_data.get("isWhitelisted", False),
            "abuse_score": abuse_score,
            "country_code": ip_data.get("countryCode", "N/A"),
            "usage_type": ip_data.get("usageType", "Unknown"),
            "isp": ip_data.get("isp", "Unknown"),
            "domain": ip_data.get("domain", "N/A"),
            "total_reports": ip_data.get("totalReports", 0),
            "distinct_users": ip_data.get("numDistinctUsers", 0),
            "last_reported_at": ip_data.get("lastReportedAt", "N/A"),
            "threat_level": threat_level
        }