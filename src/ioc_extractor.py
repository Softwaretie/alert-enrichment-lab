"""Pull IOCs (URLs, domains, IPs, file hashes) out of a forwarded phishing report."""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_URL_CHARS = r"""[^\s\[\]<>"']+"""
_URL_RE = re.compile(rf"\bhxxps?://{_URL_CHARS}|\bhttps?://{_URL_CHARS}", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# Domains that show up in every email and add no enrichment value.
_DOMAIN_ALLOWLIST = {
    "gmail.com", "google.com", "googlemail.com", "w3.org",
}

# Common filenames (e.g. "invoice.exe") match the loose domain regex but
# aren't domains; skip single-label "hostnames" ending in these extensions.
_FILE_EXTENSIONS = {
    "exe", "doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "zip", "rar",
    "js", "vbs", "bat", "scr", "jar", "png", "jpg", "jpeg", "gif", "txt",
    "csv", "html", "htm", "msi", "dll", "ps1", "hta", "lnk", "iso", "7z",
}

_PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.2", "172.30.", "172.31.", "192.168.", "127.")


def refang(text: str) -> str:
    """Undo common IOC defanging so regexes can match normally."""
    text = re.sub(r"hxxps?://", lambda m: m.group(0).replace("xx", "tt"), text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = text.replace("[:]", ":")
    text = text.replace("[@]", "@")
    return text


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(_PRIVATE_IP_PREFIXES)


_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""


def _strip_trailing_punctuation(url: str) -> str:
    """Drop punctuation picked up from markdown links / sentence endings, e.g.
    "(http://evil.com)" or "see http://evil.com." shouldn't include the ")"/"."."""
    while url and url[-1] in _TRAILING_PUNCTUATION:
        if url[-1] == ")" and url.count("(") > url.count(")"):
            break
        url = url[:-1]
    return url


@dataclass
class ExtractedIOCs:
    urls: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    hashes: list = field(default_factory=list)
    sender_domain: str = ""

    def is_empty(self) -> bool:
        return not (self.urls or self.domains or self.ips or self.hashes)


def _sender_domain(sender: str) -> str:
    match = re.search(r"@([\w.-]+)", sender)
    return match.group(1).lower() if match else ""


def extract(body_text: str, sender: str = "") -> ExtractedIOCs:
    clean = refang(body_text)

    urls = sorted({_strip_trailing_punctuation(u) for u in _URL_RE.findall(clean)})

    domains = set()
    for url in urls:
        host = urlparse(url).netloc.split(":")[0].lower()
        if host and host not in _DOMAIN_ALLOWLIST and not _IPV4_RE.fullmatch(host):
            domains.add(host)
    for candidate in _DOMAIN_RE.findall(clean):
        candidate = candidate.lower().rstrip(".")
        label, _, ext = candidate.rpartition(".")
        is_filename = "." not in label and ext in _FILE_EXTENSIONS
        if candidate not in _DOMAIN_ALLOWLIST and not _IPV4_RE.fullmatch(candidate) and not is_filename:
            domains.add(candidate)

    ips = sorted({ip for ip in _IPV4_RE.findall(clean) if not _is_private_ip(ip)})

    hashes = set()
    hashes.update(_SHA256_RE.findall(clean))
    hashes.update(_SHA1_RE.findall(clean))
    hashes.update(_MD5_RE.findall(clean))

    return ExtractedIOCs(
        urls=urls,
        domains=sorted(domains),
        ips=ips,
        hashes=sorted(hashes),
        sender_domain=_sender_domain(sender),
    )
