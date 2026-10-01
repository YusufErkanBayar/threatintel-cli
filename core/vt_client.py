import base64
import requests
from typing import Dict, Any, Optional
from config.settings import VT_BASE_URL, VT_API_KEY, REQUEST_TIMEOUT


class VirusTotalClient:
    """Client for interacting with the VirusTotal v3 REST API."""

    def __init__(self, api_key: str = VT_API_KEY) -> None:
        self.api_key = api_key
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """Handles common HTTP GET requests with exception handling."""
        url = f"{VT_BASE_URL}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Target not found in VirusTotal database (Clean or Unseen)."}
            elif response.status_code == 401:
                return {"error": "Invalid API Key. Please verify your VT_API_KEY credentials."}
            elif response.status_code == 429:
                return {"error": "API rate limit reached (Free tier allows 4 requests/min)."}
            else:
                return {"error": f"API request failed with status code {response.status_code}: {response.text}"}

        except requests.exceptions.Timeout:
            return {"error": "Request timed out. Please check your network connection."}
        except requests.exceptions.RequestException as e:
            return {"error": f"A network error occurred: {str(e)}"}

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal for a file hash (MD5, SHA-1, SHA-256)."""
        clean_hash = file_hash.strip().lower()
        return self._make_request(f"files/{clean_hash}")

    def get_url_report(self, target_url: str) -> Dict[str, Any]:
        """
        Query VirusTotal for a URL.
        Note: VT v3 requires the URL identifier to be base64url encoded without trailing '=' padding.
        """
        clean_url = target_url.strip()
        encoded_url = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        return self._make_request(f"urls/{encoded_url}")