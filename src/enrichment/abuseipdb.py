"""AbuseIPDB lookups for IP reputation scoring."""
import logging

import requests

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 15


class AbuseIPDBClient:
    def __init__(self, api_key: str):
        self._headers = {"Key": api_key, "Accept": "application/json"}

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        try:
            resp = requests.get(
                _BASE_URL,
                headers=self._headers,
                params={"ipAddress": ip, "maxAgeInDays": max_age_days},
                timeout=_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB request failed for %s: %s", ip, exc)
            return {"error": str(exc)}

        if not resp.ok:
            logger.warning("AbuseIPDB returned %s for %s", resp.status_code, ip)
            return {"error": f"HTTP {resp.status_code}"}

        data = resp.json().get("data", {})
        return {
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_tor": data.get("isTor"),
        }
