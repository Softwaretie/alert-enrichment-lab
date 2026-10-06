"""Parses SPF/DKIM/DMARC verdicts out of the Authentication-Results header.

Re-verifying SPF/DKIM/DMARC ourselves would mean redoing DNS lookups and
signature checks the receiving mail server (Gmail/Yahoo) already did
authoritatively. Both stamp an Authentication-Results header with the
results, so we just parse that instead of re-deriving it.
"""
import re

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)


def parse_authentication_results(header_value: str) -> dict:
    """Extract {"spf": "pass"|"fail"|"none"|..., "dkim": ..., "dmarc": ...}
    from a raw Authentication-Results header value. Missing checks are
    simply absent from the returned dict, not filled with a default --
    treat an absent check as unknown, not passing."""
    if not header_value:
        return {}
    results = {}
    for key, value in _RESULT_RE.findall(header_value):
        key = key.lower()
        if key not in results:  # first match is the outermost/most recent hop
            results[key] = value.lower()
    return results
