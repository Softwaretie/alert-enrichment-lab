"""Mail-source-agnostic representation of a forwarded phishing report."""
from dataclasses import dataclass, field


@dataclass
class EmailMessage:
    id: str
    thread_id: str
    subject: str
    sender: str
    date: str
    body_text: str
    source: str
    attachment_names: list = field(default_factory=list)
    mailbox: str = ""  # the receiving account's address, e.g. "you@gmail.com"
    auth_results: dict = field(default_factory=dict)  # {"spf": "pass"|"fail"|..., "dkim": ..., "dmarc": ...}
    # Downloaded attachment bytes (src.attachments.RawAttachment), held in memory only
    # while the email is being analysed; the pipeline clears this once a report exists.
    attachments: list = field(default_factory=list)
