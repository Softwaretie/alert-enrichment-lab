"""Shared HTML-body-to-text conversion for mail clients.

Naively stripping HTML tags to get "plain text" throws away every link, since
a URL in `<a href="...">` lives in an attribute, not the tag's visible text.
For phishing/scam detection the links are often the whole point, so pull them
out first and append them to the text before stripping tags.
"""
import re

# [^<>] (not just [^>]) keeps this linear: "<<<<<<..." or an unclosed "<a <a <a ..." can't make it rescan the rest of the text from every "<".
_TAG_RE = re.compile(r"<[^<>]+>")
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def html_to_text(html: str) -> str:
    links = _HREF_RE.findall(html)
    text = _TAG_RE.sub(" ", html)
    if links:
        text += "\n\nLinks:\n" + "\n".join(links)
    return text
