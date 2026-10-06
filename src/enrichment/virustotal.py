"""VirusTotal v3 lookups for URLs, domains, IPs, and file hashes."""
import base64
import logging
import time

import requests

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15
# Free-tier VirusTotal accounts are limited to 4 requests/minute.
_MIN_SECONDS_BETWEEN_CALLS = 16


class VirusTotalClient:
    def __init__(self, api_key: str):
        self._headers = {"x-apikey": api_key}
        self._last_call_ts = 0.0

    def _throttle(self):
        elapsed = time.monotonic() - self._last_call_ts
        if elapsed < _MIN_SECONDS_BETWEEN_CALLS:
            time.sleep(_MIN_SECONDS_BETWEEN_CALLS - elapsed)

    def _get(self, path: str) -> dict:
        self._throttle()
        try:
            resp = requests.get(f"{_BASE_URL}{path}", headers=self._headers, timeout=_TIMEOUT)
            self._last_call_ts = time.monotonic()
        except requests.RequestException as exc:
            logger.warning("VirusTotal request failed for %s: %s", path, exc)
            return {"error": str(exc)}

        if resp.status_code == 404:
            return {"found": False}
        if not resp.ok:
            logger.warning("VirusTotal returned %s for %s", resp.status_code, path)
            return {"error": f"HTTP {resp.status_code}"}

        return {"found": True, "data": resp.json().get("data", {})}

    @staticmethod
    def _stats_summary(result: dict) -> dict:
        if not result.get("found") or "data" not in result:
            return result
        attributes = result["data"].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        summary = {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
        }
        # File lookups (hashes) also carry a family label and file type; include them when present.
        label = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            summary["threat_label"] = label
        if attributes.get("type_description"):
            summary["file_type"] = attributes["type_description"]
        return summary

    def check_url(self, url: str) -> dict:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._stats_summary(self._get(f"/urls/{url_id}"))

    def check_domain(self, domain: str) -> dict:
        return self._stats_summary(self._get(f"/domains/{domain}"))

    def check_ip(self, ip: str) -> dict:
        return self._stats_summary(self._get(f"/ip_addresses/{ip}"))

    def check_hash(self, file_hash: str) -> dict:
        return self._stats_summary(self._get(f"/files/{file_hash}"))
