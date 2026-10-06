"""Accumulator that each format analyzer writes its findings into."""
from src.attachments.models import MAX_URLS_PER_FILE

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


class Report:
    def __init__(self):
        self.signals = []   # [{"severity", "signal", "detail"}]
        self.urls = []
        self.notes = []
        self.details = {}
        self.members = []

    def add(self, severity: str, signal: str, detail: str) -> None:
        # One entry per signal name; keep the most severe version if repeated.
        for existing in self.signals:
            if existing["signal"] == signal:
                if SEVERITY_ORDER[severity] > SEVERITY_ORDER[existing["severity"]]:
                    existing["severity"] = severity
                    existing["detail"] = detail
                return
        self.signals.append({"severity": severity, "signal": signal, "detail": detail})

    def add_urls(self, urls) -> None:
        for url in urls:
            if url not in self.urls and len(self.urls) < MAX_URLS_PER_FILE:
                self.urls.append(url)

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def risk(self) -> str:
        level = "none"
        for s in self.signals:
            if SEVERITY_ORDER[s["severity"]] > SEVERITY_ORDER[level]:
                level = s["severity"]
        for m in self.members:
            if SEVERITY_ORDER.get(m.get("static_risk", "none"), 0) > SEVERITY_ORDER[level]:
                level = m["static_risk"]
        return level
