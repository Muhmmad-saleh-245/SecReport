"""Scope and authorization guard.

Every engagement carries written authorization info and an in-scope /
out-of-scope list. check() tells you whether a target is allowed.
Out-of-scope always wins over in-scope.

Rules may be: exact domain, wildcard domain (*.example.com), single IP, or CIDR.
Targets may be: host, host:port, URL, IP, or a CIDR range (a range is allowed only
if it sits fully inside an in-scope network and touches no out-of-scope rule).
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


def _parse_network(text: str):
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def _host_of(target: str) -> str:
    """Extract the bare host from a URL, host:port, user@host or [ipv6]:port."""
    target = (target or "").strip()
    if not target:
        return ""
    if "://" not in target:
        target = "//" + target
    try:
        host = urlparse(target).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _matches_host(host: str, rule: str) -> bool:
    rule = rule.strip().lower()
    if not rule:
        return False
    net = _parse_network(rule)
    if net is not None:
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or fnmatch.fnmatchcase(host, rule)
    return host == rule


def _parse_date(text: str):
    try:
        return dt.date.fromisoformat(text)
    except (TypeError, ValueError):
        return None


@dataclass
class Scope:
    in_scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    start_date: str = ""   # YYYY-MM-DD
    end_date: str = ""     # YYYY-MM-DD
    authorization_ref: str = ""  # contract / permission letter / program URL
    rules_of_engagement: str = ""

    def validate(self) -> list:
        problems = []
        for label, value in (("start_date", self.start_date), ("end_date", self.end_date)):
            if value and _parse_date(value) is None:
                problems.append(f"{label} must be YYYY-MM-DD (got {value!r})")
        s, e = _parse_date(self.start_date), _parse_date(self.end_date)
        if s and e and e < s:
            problems.append("end_date is before start_date")
        return problems

    def check(self, target: str, on_date: dt.date | None = None):
        """Return (allowed: bool, reason: str)."""
        problems = self.validate()
        if problems:
            return False, "Invalid scope: " + "; ".join(problems)
        target = (target or "").strip()
        if not self.authorization_ref.strip():
            return False, "No authorization reference recorded for this engagement"
        today = on_date or dt.date.today()
        start, end = _parse_date(self.start_date), _parse_date(self.end_date)
        if start and today < start:
            return False, f"Engagement has not started (starts {self.start_date})"
        if end and today > end:
            return False, f"Engagement window ended on {self.end_date}"

        if "/" in target and "://" not in target and _parse_network(target) is not None:
            return self._check_network(_parse_network(target))

        host = _host_of(target)
        if not host:
            return False, "Could not read a host from the target"
        for rule in self.out_of_scope:
            if _matches_host(host, rule):
                return False, f"Explicitly out of scope (rule: {rule})"
        for rule in self.in_scope:
            if _matches_host(host, rule):
                return True, f"In scope (rule: {rule})"
        return False, "Not listed in scope"

    def _check_network(self, net):
        for rule in self.out_of_scope:
            other = _parse_network(rule)
            if other is not None and other.version == net.version and net.overlaps(other):
                return False, f"Range overlaps an out-of-scope rule ({rule})"
        for rule in self.in_scope:
            other = _parse_network(rule)
            if other is not None and other.version == net.version and net.subnet_of(other):
                return True, f"In scope (rule: {rule})"
        return False, "Range is not fully inside an in-scope network"

    def to_dict(self) -> dict:
        return {
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "start_date": self.start_date,
            "end_date": self.end_date,
            "authorization_ref": self.authorization_ref,
            "rules_of_engagement": self.rules_of_engagement,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        data = data or {}
        return cls(
            in_scope=[str(x) for x in data.get("in_scope", [])],
            out_of_scope=[str(x) for x in data.get("out_of_scope", [])],
            start_date=str(data.get("start_date", "") or ""),
            end_date=str(data.get("end_date", "") or ""),
            authorization_ref=str(data.get("authorization_ref", "") or ""),
            rules_of_engagement=str(data.get("rules_of_engagement", "") or ""),
        )
