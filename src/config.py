"""Environment-backed configuration for the alert enrichment pipeline."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

# Service name secrets are filed under in the OS credential store (Windows
# Credential Manager / macOS Keychain / Linux Secret Service) via `keyring`.
# Run scripts/setup_secrets.py to move a secret out of plaintext .env and
# into there -- it's encrypted at rest and tied to your OS login, rather
# than sitting as readable text in a file.
SERVICE_NAME = "alert-enrichment"

try:
    import keyring
except ImportError:
    keyring = None


def _get_secret(name: str, default: str = "") -> str:
    """Prefer the OS credential store over a plaintext .env value; fall back
    to .env for anything not yet migrated via scripts/setup_secrets.py."""
    if keyring is not None:
        try:
            value = keyring.get_password(SERVICE_NAME, name)
        except Exception:
            value = None  # no backend available (e.g. headless Linux with no keyring daemon)
        if value:
            return value
    return os.environ.get(name, default)


def _require_secret(name: str) -> str:
    value = _get_secret(name)
    if not value:
        raise RuntimeError(
            f"Missing required secret: {name}. Run `python scripts/setup_secrets.py` "
            f"to store it securely (recommended), or set it in .env."
        )
    return value


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "")))
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    anthropic_api_key: str
    virustotal_api_key: str
    abuseipdb_api_key: str
    gmail_query: str
    gmail_credentials_path: str
    gmail_token_path: str
    claude_model: str
    findings_db_path: str
    slack_bot_token: str
    slack_channel_id: str
    yahoo_email: str
    yahoo_app_password: str
    yahoo_folder: str
    yahoo_search_criteria: str
    urlscan_api_key: str
    attachment_analysis: bool = True
    attachment_max_mb: int = 25

    @property
    def yahoo_configured(self) -> bool:
        return bool(self.yahoo_email and self.yahoo_app_password)

    @property
    def urlscan_configured(self) -> bool:
        return bool(self.urlscan_api_key)

    @property
    def max_attachment_bytes(self) -> int:
        """Per-file download cap in bytes; 0 means attachment analysis is off."""
        return self.attachment_max_mb * 1024 * 1024 if self.attachment_analysis else 0

    @classmethod
    def load(cls) -> "Config":
        return cls(
            # Secrets: checked in the OS credential store first, .env as fallback.
            anthropic_api_key=_require_secret("ANTHROPIC_API_KEY"),
            virustotal_api_key=_require_secret("VIRUSTOTAL_API_KEY"),
            abuseipdb_api_key=_require_secret("ABUSEIPDB_API_KEY"),
            slack_bot_token=_get_secret("SLACK_BOT_TOKEN"),
            yahoo_app_password=_get_secret("YAHOO_APP_PASSWORD"),
            urlscan_api_key=_get_secret("URLSCAN_API_KEY"),
            attachment_analysis=_env_flag("ATTACHMENT_ANALYSIS", True),
            attachment_max_mb=_env_int("ATTACHMENT_MAX_MB", 25),
            # Plain config: not sensitive, fine to keep in .env.
            gmail_query=os.environ.get("GMAIL_QUERY", "label:phishing-reports is:unread"),
            gmail_credentials_path=os.environ.get("GMAIL_CREDENTIALS_PATH", "credentials.json"),
            gmail_token_path=os.environ.get("GMAIL_TOKEN_PATH", "token.json"),
            claude_model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5"),
            findings_db_path=os.environ.get("FINDINGS_DB_PATH", "findings.db"),
            slack_channel_id=os.environ.get("SLACK_CHANNEL_ID", ""),
            yahoo_email=os.environ.get("YAHOO_EMAIL", ""),
            yahoo_folder=os.environ.get("YAHOO_FOLDER", "INBOX"),
            yahoo_search_criteria=os.environ.get("YAHOO_SEARCH_CRITERIA", "UNSEEN"),
        )
