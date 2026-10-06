"""urlscan.io sandboxed URL scanning.

Visits a URL in an isolated browser and reports what it actually does --
catches freshly-registered or never-indexed malicious pages that a pure
reputation lookup (VirusTotal) has no history for yet. Requires a free API
key from https://urlscan.io/user/signup.

Scanning is not instant: submit, then poll for the result. That makes this
much slower than a VirusTotal lookup (seconds, not milliseconds), so callers
should scan fewer URLs per email than they'd send to VirusTotal.
"""
import logging
import time

import requests

logger = logging.getLogger(__name__)

_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
_RESULT_URL = "https://urlscan.io/api/v1/result/{scan_id}/"
_TIMEOUT = 15
_POLL_INTERVAL_SECONDS = 5
_MAX_WAIT_SECONDS = 45


class UrlscanClient:
    def __init__(self, api_key: str):
        self._headers = {"API-Key": api_key, "Content-Type": "application/json"}

    def scan_url(self, url: str) -> dict:
        """Submit a URL and wait (up to _MAX_WAIT_SECONDS) for the scan to
        finish. Returns {"error": ...} rather than raising on any failure --
        a sandboxing outage shouldn't take down the enrichment pipeline."""
        try:
            resp = requests.post(
                _SUBMIT_URL, headers=self._headers,
                json={"url": url, "visibility": "unlisted"},
                timeout=_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.warning("urlscan.io submission failed for %s: %s", url, exc)
            return {"error": str(exc)}

        if resp.status_code == 400:
            # Malformed/unreachable URL, or a free-tier scan-limit rejection.
            return {"error": f"submission rejected: {resp.text[:200]}"}
        if not resp.ok:
            logger.warning("urlscan.io returned %s for %s", resp.status_code, url)
            return {"error": f"HTTP {resp.status_code}"}

        scan_id = resp.json().get("uuid")
        if not scan_id:
            return {"error": "no scan id returned"}

        return self._poll_result(scan_id)

    def _poll_result(self, scan_id: str) -> dict:
        deadline = time.monotonic() + _MAX_WAIT_SECONDS
        result_url = _RESULT_URL.format(scan_id=scan_id)

        while time.monotonic() < deadline:
            time.sleep(_POLL_INTERVAL_SECONDS)
            try:
                # Unlisted-visibility results require the API key on the
                # read too, not just the submission -- without it urlscan.io
                # returns 403 "You're not logged in!" even for your own scan.
                resp = requests.get(result_url, headers=self._headers, timeout=_TIMEOUT)
            except requests.RequestException as exc:
                logger.warning("urlscan.io result fetch failed: %s", exc)
                return {"error": str(exc)}

            if resp.status_code == 404:
                continue  # scan still processing

            if not resp.ok:
                return {"error": f"HTTP {resp.status_code}"}

            data = resp.json()
            verdicts = data.get("verdicts", {}).get("overall", {})
            page = data.get("page", {})
            return {
                "found": True,
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
                "categories": verdicts.get("categories", []),
                "final_url": page.get("url"),
                "final_domain": page.get("domain"),
                "report_url": f"https://urlscan.io/result/{scan_id}/",
            }

        return {"error": "timed out waiting for scan result"}
