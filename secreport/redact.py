"""Redaction for client-facing copies of a report.

Masks IP addresses, e-mail addresses, common secret formats and any custom
terms (client names, hostnames, people). Applied to the finished report
content, so every output format (HTML, Markdown, DOCX, PDF) is covered.

This is pattern based. It reduces accidental leaks but cannot guarantee that
nothing sensitive remains: always read a redacted report before sending it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MASK = "[REDACTED]"

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}(?![\w:])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_AUTH = re.compile(r"(?i)(\bAuthorization\s*:\s*(?:Bearer|Basic|Token)\s+)[A-Za-z0-9._~+/=\-]+")
_KV_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|session(?:id)?|cookie)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GH = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


@dataclass
class RedactionConfig:
    ips: bool = True
    emails: bool = True
    secrets: bool = True
    custom_terms: list = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {"ips": 0, "emails": 0, "secrets": 0, "custom": 0})

    def __post_init__(self):
        self.custom_terms = [t.strip() for t in self.custom_terms if t and t.strip()]

    def describe(self) -> str:
        parts = []
        if self.ips:
            parts.append("IP addresses")
        if self.emails:
            parts.append("e-mail addresses")
        if self.secrets:
            parts.append("credentials and tokens")
        if self.custom_terms:
            parts.append(f"{len(self.custom_terms)} custom term(s)")
        return ", ".join(parts) or "nothing"

    def _sub(self, pattern, repl, text, key):
        text, n = pattern.subn(repl, text)
        self.stats[key] += n
        return text

    def text(self, value: str) -> str:
        if not isinstance(value, str) or not value:
            return value
        out = value
        if self.secrets:
            out = self._sub(_PRIVKEY, MASK, out, "secrets")
            out = self._sub(_AUTH, lambda m: m.group(1) + MASK, out, "secrets")
            out = self._sub(_KV_SECRET, lambda m: m.group(1) + m.group(2) + MASK, out, "secrets")
            out = self._sub(_JWT, MASK, out, "secrets")
            out = self._sub(_AWS, MASK, out, "secrets")
            out = self._sub(_GH, MASK, out, "secrets")
        if self.emails:
            out = self._sub(_EMAIL, MASK, out, "emails")
        if self.ips:
            def ipv4(m):
                if all(int(p) <= 255 for p in m.group(0).split(".")):
                    self.stats["ips"] += 1
                    return MASK
                return m.group(0)
            out = _IPV4.sub(ipv4, out)
            out = self._sub(_IPV6, MASK, out, "ips")
        for term in sorted(self.custom_terms, key=len, reverse=True):
            out = self._sub(re.compile(re.escape(term), re.I), MASK, out, "custom")
        return out


def apply(obj, cfg: RedactionConfig):
    """Recursively redact every string inside lists, tuples and dicts."""
    if isinstance(obj, str):
        return cfg.text(obj)
    if isinstance(obj, list):
        return [apply(x, cfg) for x in obj]
    if isinstance(obj, tuple):
        return tuple(apply(x, cfg) for x in obj)
    if isinstance(obj, dict):
        return {k: (v if k in ("t", "sev", "kind") else apply(v, cfg)) for k, v in obj.items()}
    return obj
