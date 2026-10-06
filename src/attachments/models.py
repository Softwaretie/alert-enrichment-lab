"""Shared types and limits for attachment analysis."""
from dataclasses import dataclass

# --- Safety limits --------------------------------------------------------
# Attachments are only ever held in memory: never written to disk, never
# opened by another program, never executed. These caps keep a hostile file
# (zip bomb, giant PDF, endless nesting) from exhausting memory or time.
MAX_FILES_PER_EMAIL = 10
MAX_TOTAL_BYTES_PER_EMAIL = 60 * 1024 * 1024
MAX_MEMBER_BYTES = 10 * 1024 * 1024        # largest archive member we'll unpack
MAX_UNPACKED_BYTES_PER_EMAIL = 50 * 1024 * 1024  # total unpacked across nesting
MAX_MEMBERS_LISTED = 50
MAX_NESTING_DEPTH = 2                      # zip-in-zip, eml-in-eml, ...
MAX_URLS_PER_FILE = 25
MAX_SCAN_TEXT_BYTES = 4 * 1024 * 1024      # text we'll regex over per file
MAX_RATIO = 1000                           # compressed->uncompressed ratio flagged as a bomb


@dataclass
class RawAttachment:
    """An attachment as downloaded from a mailbox, before analysis.

    `data` is the file's bytes (empty if it was skipped). `skipped_reason` is
    set instead when it wasn't downloaded (too large, too many attachments,
    download failed) so the report can still say the file existed."""
    filename: str
    content_type: str = ""
    data: bytes = b""
    size: int = 0
    skipped_reason: str = ""
