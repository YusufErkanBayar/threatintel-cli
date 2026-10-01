import requests
from typing import Dict, Any
from config.settings import ABUSEIPDB_BASE_URL, ABUSEIPDB_API_KEY, REQUEST_TIMEOUT


class AbuseIPDBClient:
    """Client for interacting with the AbuseIPDB v2 REST API."""

    def __init__(self, api_key: str = ABUSEIPDB_API_KEY) -> None:
        self.api_key = api_key
        self.headers = {
            "Key": self.api_key or "",
            "Accept": "application/json"
        }

    def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """Queries AbuseIPDB for reputation and abuse reports on a specific IP."""
        if not self.api_key:
            return {"error": "ABUSEIPDB_API_KEY is missing in your .env file."}

        url = f"{ABUSEIPDB_BASE_URL}/check"
        params = {
            "ipAddress": ip_address.strip(),
            "maxAgeInDays": max_age_in_days,
            "verbose": True
        }

        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                params=params, 
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                return {"error": "Invalid AbuseIPDB API key."}
            elif response.status_code == 429:
                return {"error": "AbuseIPDB daily limit reached (Free tier allows 1,000 queries/day)."}
            else:
                return {"error": f"AbuseIPDB request failed ({response.status_code}): {response.text}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Network error during AbuseIPDB check: {str(e)}"}