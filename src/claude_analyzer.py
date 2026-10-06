"""Sends the alert + enrichment data to Claude for triage analysis."""
import json
import logging

import anthropic

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a SOC analyst assistant that triages phishing reports forwarded \
by employees. You are given the reported email's metadata and body, plus threat-intel \
enrichment results for any URLs, domains, IPs, and file hashes found in it:
- VirusTotal / AbuseIPDB: reputation lookups (may return "found": false; treat that as \
unknown, not benign -- a brand-new or rarely-seen malicious domain often has no history yet).
- urlscan.io (enrichment.urls.<url>.urlscan, when present): an actual sandboxed visit to the \
URL, reporting what it really does (final landing page/domain, verdict, categories). This \
catches pages a reputation lookup alone would miss, and generally deserves more weight than \
VirusTotal for a URL when both are present, since it's direct observation rather than history.
- Sender authentication (enrichment.sender_authentication): SPF/DKIM/DMARC results the \
receiving mail server already computed. A missing key means that check wasn't reported, not \
that it passed. A "fail" on any of these is a real spoofing signal, but a legitimate sender \
can still fail alignment for benign reasons (e.g. forwarded mail, misconfigured but genuine \
senders) -- weigh it alongside content and links, don't treat it alone as decisive.
- Attachments (enrichment.attachments): the email's attachments were downloaded into memory and \
statically analysed -- never opened or executed. For each file you get its SHA-256, the type \
detected from its bytes (not its name), a static_risk level (none/low/medium/high) with `signals` \
explaining each red flag, `urls` found inside the file (those were also checked with VirusTotal/\
urlscan.io like links in the body), `members` for archives/attached emails (analysed the same way), \
and `virustotal`, which is a hash LOOKUP only. A `found: false` hash means VirusTotal has never seen \
the file: that is unknown, NOT benign, since freshly built malware is usually unseen. Several engines \
flagging a hash is strong evidence. Static checks cannot see inside password-protected files, \
RAR/7z archives or disk images, and `analyzed: false` means the file was not inspected at all -- \
never read "no signals" as proof a file is safe. Strong malicious indicators include: a macro that \
runs on open and downloads/launches things, executables, scripts or shortcuts, double or disguised \
extensions, remote-template or network-path (UNC) links, HTML pages with password forms or file \
smuggling, and an encrypted attachment whose password is given in the email body \
(`email_signals`). A plain document or PDF with no signals is weak evidence either way. Cite the \
file name and the specific signal in key_indicators when attachments influence your verdict.

Respond with ONLY a JSON object, no other text, matching this shape:
{
  "verdict": "malicious" | "suspicious" | "likely_benign" | "unknown",
  "confidence": "low" | "medium" | "high",
  "summary": "1-3 sentence summary of what this email is and why it matters",
  "key_indicators": ["short bullet strings citing the specific evidence"],
  "recommended_action": "short next step for the analyst, e.g. block domain X, quarantine, no action"
}"""


_MAX_PROMPT_MEMBERS = 15
_MAX_PROMPT_URLS = 10


def _trim_attachment_entry(entry: dict) -> dict:
    """Shrink an attachment report entry for the prompt: drop the redundant hashes
    and cap long lists, so one big archive can't swamp the context window."""
    trimmed = {k: v for k, v in entry.items() if k not in ("md5", "sha1", "members", "declared_content_type")}
    if "urls" in trimmed:
        trimmed["urls"] = trimmed["urls"][:_MAX_PROMPT_URLS]
    members = entry.get("members") or []
    if members:
        trimmed["members"] = [_trim_attachment_entry(m) for m in members[:_MAX_PROMPT_MEMBERS]]
        if len(members) > _MAX_PROMPT_MEMBERS:
            trimmed["members_omitted"] = len(members) - _MAX_PROMPT_MEMBERS
    return trimmed


def _prompt_enrichment(enrichment: dict) -> dict:
    report = enrichment.get("attachments")
    if not report:
        return enrichment
    slim = dict(enrichment)
    slim["attachments"] = {**report, "files": [_trim_attachment_entry(f) for f in report.get("files", [])]}
    return slim


class ClaudeAnalyzer:
    def __init__(self, api_key: str, model: str):
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def analyze(self, email, iocs, enrichment: dict) -> dict:
        user_content = json.dumps(
            {
                "email": {
                    "subject": email.subject,
                    "sender": email.sender,
                    "date": email.date,
                    "body": email.body_text[:6000],
                    "attachment_names": email.attachment_names,
                },
                "extracted_iocs": {
                    "urls": iocs.urls,
                    "domains": iocs.domains,
                    "ips": iocs.ips,
                    "hashes": iocs.hashes,
                    "sender_domain": iocs.sender_domain,
                },
                "enrichment": _prompt_enrichment(enrichment),
            },
            indent=2,
        )

        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        text = "".join(block.text for block in response.content if block.type == "text")
        return self._parse_json(text)

    @staticmethod
    def _parse_json(text: str) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end != -1:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    pass
            logger.warning("Could not parse Claude response as JSON: %s", text[:200])
            return {
                "verdict": "unknown",
                "confidence": "low",
                "summary": "Claude response could not be parsed as JSON.",
                "key_indicators": [],
                "recommended_action": "Manual review required.",
                "raw_response": text,
            }
