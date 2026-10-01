import os
import sys
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not VT_API_KEY:
    print("[ERROR] VT_API_KEY is not set in .env file.", file=sys.stderr)
    sys.exit(1)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
REQUEST_TIMEOUT = 15