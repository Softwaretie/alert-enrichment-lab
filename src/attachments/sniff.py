"""File-type sniffing, filename tricks, string extraction and URL helpers.

All of this works on bytes in memory and never opens or runs a file.
"""
import hashlib
import math
import re
import unicodedata
from collections import Counter

from src import ioc_extractor
from src.attachments.models import MAX_SCAN_TEXT_BYTES, MAX_URLS_PER_FILE
from src.attachments.cfb import CFB_MAGIC

# --- Extension groups ------------------------------------------------------

EXEC_EXT = {"exe", "scr", "com", "pif", "dll", "cpl", "msi", "msp", "sys", "ocx", "drv", "xll", "wll"}
SCRIPT_EXT = {"js", "jse", "vbs", "vbe", "wsf", "wsh", "ws", "vb", "ps1", "psm1", "psd1", "ps1xml",
              "bat", "cmd", "hta", "sh", "jar", "reg", "msc", "gadget", "inf", "sct", "chm"}
SHORTCUT_EXT = {"lnk", "url", "scf", "appref-ms", "settingcontent-ms", "library-ms", "search-ms"}
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx", "udf"}
MACRO_OFFICE_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam", "sldm", "xlsb"}
OFFICE_EXT = {"doc", "docx", "dot", "dotx", "xls", "xlsx", "xlt", "xltx", "ppt", "pptx", "pps", "ppsx",
              "pot", "potx"} | MACRO_OFFICE_EXT
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "z", "arj", "ace", "lzh", "lha"}
HTML_EXT = {"html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml", "hta"}
INSTALLER_EXT = {"appx", "msix", "msixbundle", "appxbundle", "appinstaller", "application", "deploy", "mst"}
DOC_LIKE_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg",
                "png", "gif", "zip", "htm", "html", "msg", "eml"}
RUNNABLE_EXT = EXEC_EXT | SCRIPT_EXT | SHORTCUT_EXT | INSTALLER_EXT

# Hosts that appear inside file formats as XML namespaces / boilerplate, not as real links.
_NOISE_HOSTS = {
    "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org", "www.w3.org", "w3.org",
    "ns.adobe.com", "www.adobe.com", "schemas.xmlsoap.org", "www.openoffice.org", "openoffice.org",
    "xmlns.com", "www.xmlsoap.org", "docs.oasis-open.org", "relaxng.org", "www.iana.org",
    "schemas.android.com", "ns.useplus.org", "www.npes.org", "purl.oclc.org",
}

_DOUBLE_EXT_RE = re.compile(
    r"\.(" + "|".join(sorted(DOC_LIKE_EXT)) + r")[\s. _-]*\.([a-z0-9]{2,8})\s*$", re.IGNORECASE
)


# --- Hashing / entropy ------------------------------------------------------

def hashes(data: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def entropy(data: bytes, sample: int = 4 * 1024 * 1024) -> float:
    """Shannon entropy in bits/byte (0-8) over the first `sample` bytes.
    Compressed or encrypted content sits near 8; ordinary code is 5-7."""
    data = data[:sample]
    if not data:
        return 0.0
    total = len(data)
    return round(-sum((n / total) * math.log2(n / total) for n in Counter(data).values()), 2)


# --- Filenames --------------------------------------------------------------

_NAME_TAIL_RE = re.compile(r"[\w\\:. $~-]*\Z")
_RUNNABLE_EXT_RE = re.compile(r"\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|hta|lnk|jar|dll|wsf|cpl|msi|pif)\b", re.IGNORECASE)


def runnable_names(text: str, limit: int = 20) -> list:
    """File names ending in a runnable extension (setup.exe, C:\\temp\\x.js) found in text.
    Finds the extension first, then looks a short way back for the name, so a huge
    run of name-like characters can't make the match slow."""
    names = []
    for match in _RUNNABLE_EXT_RE.finditer(text):
        start = max(0, match.start() - 80)
        tail = _NAME_TAIL_RE.search(text[start:match.start()])
        names.append((tail.group() if tail else "") + match.group())
        if len(names) >= limit:
            break
    return names


_TAG_RE = re.compile(r"<[^<>]{0,500}>")


def strip_tags(text: str) -> str:
    """Remove HTML tags with a bounded pattern (the naive `<[^>]+>` is quadratic on
    input like '<<<<<<...')."""
    return _TAG_RE.sub(" ", text)


def safe_filename(name: str) -> str:
    """Make invisible/format characters visible. The right-to-left override
    (U+202E) is the classic trick that makes 'invoice_exe.pdf' display as
    'invoice_fdp.exe'; showing it as <U+202E> keeps that visible downstream."""
    out = []
    for ch in (name or "")[:500]:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


def extension(name: str) -> str:
    name = (name or "")[:500].strip().rstrip(". ").lower()
    return name.rsplit(".", 1)[-1] if "." in name else ""


def filename_signals(name: str) -> list:
    """Signals from the filename alone. Returns [(severity, signal, detail)]."""
    signals = []
    raw = (name or "")[:500]
    if any(ord(c) in (0x202E, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069, 0x202A, 0x202B) for c in raw):
        signals.append(("high", "bidi_filename_trick",
                        "Filename contains a Unicode direction-override character, used to disguise the real extension."))
    visible = re.sub(r"[‪-‮⁦-⁩]", "", raw)
    match = _DOUBLE_EXT_RE.search(visible)
    if match and match.group(2).lower() in RUNNABLE_EXT | MACRO_OFFICE_EXT | HTML_EXT:
        signals.append(("high", "double_extension",
                        f"Looks like a .{match.group(1).lower()} but actually ends in .{match.group(2).lower()}."))
    if re.search(r"\.[a-z0-9]{2,5}\s{3,}\.[a-z0-9]{2,5}$", visible, re.IGNORECASE):
        signals.append(("high", "padded_extension", "Long run of spaces hides the real extension."))
    if visible != visible.rstrip(". "):
        signals.append(("medium", "trailing_dots_or_spaces", "Filename ends in dots/spaces (Windows strips them)."))
    return signals


# --- Content type detection -------------------------------------------------

_LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
_ONENOTE_MAGIC = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
_EML_HEADER_RE = re.compile(
    rb"\A\s*(?:Received|From|Date|Subject|MIME-Version|Return-Path|Message-ID|To|Delivered-To|X-[\w-]+|Content-Type):",
    re.IGNORECASE,
)


def detect_kind(data: bytes, filename: str = "", content_type: str = "") -> str:
    """Identify what a file really is from its bytes (not its name).

    Returns one of: pe, dos_exe, elf, macho, pdf, zip, ole, rtf, lnk, rar, 7z,
    gzip, bzip2, xz, cab, iso, vhd, onenote, png, jpeg, gif, webp, tiff, eml,
    html, svg, text, unknown (or 'empty')."""
    if not data:
        return "empty"
    head = data[:8192]

    if head[:2] == b"MZ":
        if len(data) >= 0x40:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return "pe"
        return "dos_exe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        return "macho"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:8] == CFB_MAGIC:
        return "ole"
    if head[:20] == _LNK_HEADER[:20]:
        return "lnk"
    if head[:16] == _ONENOTE_MAGIC:
        return "onenote"
    if head[:6] == b"Rar!\x1a\x07":
        return "rar"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"MSCF":
        return "cab"
    if head[:8] == b"conectix" or head[:8] == b"vhdxfile":
        return "vhd"
    if len(data) > 0x8006 and data[0x8001:0x8006] in (b"CD001", b"BEA01"):
        return "iso"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:4] == b"GIF8":
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"

    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped[:4] == b"{\\rt":
        return "rtf"

    text = _decode_text_prefix(head)
    if text is not None:
        if _EML_HEADER_RE.match(head) and (extension(filename) == "eml" or "rfc822" in content_type.lower()
                                           or b"\nSubject:" in head or b"\nFrom:" in head):
            return "eml"
        low = text.lower()
        if "<svg" in low[:2000]:
            return "svg"
        if any(tag in low for tag in ("<html", "<!doctype html", "<script", "<form", "<body", "<iframe", "<meta ")):
            return "html"
        return "text"
    if "rfc822" in content_type.lower():
        return "eml"
    return "unknown"


def _decode_text_prefix(head: bytes):
    """Return decoded text if the prefix looks like text (UTF-8/ASCII/UTF-16), else None."""
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return head.decode("utf-16", errors="strict")
        except UnicodeDecodeError:
            try:
                return head[:len(head) // 2 * 2].decode("utf-16", errors="replace")
            except Exception:
                return None
    if b"\x00" in head:
        return None
    sample = head[:4096]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    if sample and printable / len(sample) < 0.95:
        return None
    return head.decode("utf-8", errors="replace")


def decode_text(data: bytes, limit: int = MAX_SCAN_TEXT_BYTES) -> str:
    data = data[:limit]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


# --- Strings and URLs --------------------------------------------------------

_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def extract_strings(data: bytes, limit_bytes: int = 8 * 1024 * 1024, max_strings: int = 20000) -> list:
    """Printable ASCII and UTF-16LE runs (like the `strings` tool), so URLs and
    command lines hiding inside binaries, shortcuts and OneNote files surface."""
    data = data[:limit_bytes]
    out = []
    for match in _ASCII_RE.finditer(data):
        out.append(match.group().decode("ascii", errors="replace"))
        if len(out) >= max_strings:
            return out
    for match in _UTF16_RE.finditer(data):
        out.append(match.group().decode("utf-16-le", errors="replace"))
        if len(out) >= max_strings * 2:
            break
    return out


def urls_from_text(text: str) -> list:
    """Real-looking URLs in text, minus namespace/boilerplate hosts."""
    text = ioc_extractor.refang(text[:MAX_SCAN_TEXT_BYTES])
    found = sorted({ioc_extractor._strip_trailing_punctuation(u) for u in ioc_extractor._URL_RE.findall(text)})
    clean = []
    for url in found:
        host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
        if host in _NOISE_HOSTS or host.endswith(".w3.org"):
            continue
        clean.append(url)
        if len(clean) >= MAX_URLS_PER_FILE:
            break
    return clean


def keyword_hits(text: str, patterns: dict) -> list:
    """patterns: {label: compiled_regex}. Returns labels whose regex matches."""
    return [label for label, regex in patterns.items() if regex.search(text)]
