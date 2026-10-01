import hashlib
import ipaddress
import os
import re
from typing import Dict, Tuple

# Hash length regexes (MD5: 32, SHA-1: 40, SHA-256: 64 hex chars)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def defang_ioc(ioc: str) -> str:
    """
    Neutralizes IoCs to prevent accidental execution or browser hyperlinking.
    Example: http://evil.com -> hxxp[://]evil[.]com, 1.1.1.1 -> 1.1.1[.]1
    """
    ioc = str(ioc)
    # Neutralize schemes
    ioc = re.sub(r"^https://", "hxxps[://]", ioc, flags=re.IGNORECASE)
    ioc = re.sub(r"^http://", "hxxp[://]", ioc, flags=re.IGNORECASE)
    # Neutralize dots
    ioc = ioc.replace(".", "[.]")
    return ioc


def identify_ioc_type(target: str) -> Tuple[str, str]:
    """
    Identifies target type: 'ip', 'hash', 'url', or 'unknown'.
    Returns a tuple of (detected_type, cleaned_value).
    """
    cleaned = target.strip()

    # 1. Check IP address
    try:
        ipaddress.ip_address(cleaned)
        return "ip", cleaned
    except ValueError:
        pass

    # 2. Check File Hash
    if MD5_REGEX.match(cleaned) or SHA1_REGEX.match(cleaned) or SHA256_REGEX.match(cleaned):
        return "hash", cleaned.lower()

    # 3. Assume URL/Domain if has dot or scheme
    if cleaned.startswith(("http://", "https://")) or "." in cleaned:
        return "url", cleaned

    return "unknown", cleaned


def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """Computes MD5 and SHA-256 hashes of a local file in memory chunks."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    buffer_size = 65536  # 64 KB

    with open(file_path, "rb") as f:
        while chunk := f.read(buffer_size):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "file_name": os.path.basename(file_path),
        "file_size_bytes": os.path.getsize(file_path)
    }