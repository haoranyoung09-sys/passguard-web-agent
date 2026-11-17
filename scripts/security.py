"""Core security policy, task contract, anti-injection, and taint tracking engine.

Provides deterministic, code-level guardrails that the LLM cannot talk its way around:
- Domain allowlist enforcement
- OAuth-style Task Contract (scoped actions, write budget, TTL, ephemeral mode)
- Login/authentication page detection
- High-risk UI element detection
- Output secret redaction
- Prompt-injection heuristic scanning & untrusted content framing
- Cross-domain taint tracking (anti-exfiltration)
- Isolated profile path sanitization
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import yaml


@dataclass(frozen=True)
class RedactionRule:
    """A single regex-based redaction rule."""

    name: str
    pattern: re.Pattern[str]
    replacement: str


@dataclass(frozen=True)
class TaintPattern:
    """Pattern used to detect sensitive data for cross-domain taint tracking."""

    name: str
    pattern: re.Pattern[str]


@dataclass
class SecurityPolicy:
    """Loaded security rules for browser automation."""

    login_url_patterns: list[str] = field(default_factory=list)
    high_risk_keywords: list[str] = field(default_factory=list)
    read_only_blocked_methods: set[str] = field(
        default_factory=lambda: {"POST", "PUT", "PATCH", "DELETE"}
    )
    redaction_rules: list[RedactionRule] = field(default_factory=list)
    prompt_injection_patterns: list[re.Pattern[str]] = field(default_factory=list)
    taint_patterns: list[TaintPattern] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> "SecurityPolicy":
        """Load security policy from a YAML file."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        redaction_rules: list[RedactionRule] = []
        for entry in raw.get("redaction_patterns", []):
            redaction_rules.append(
                RedactionRule(
                    name=str(entry.get("name", "unnamed")),
                    pattern=re.compile(entry["pattern"]),
                    replacement=str(entry.get("replacement", "[REDACTED]")),
                )
            )
        injection_patterns = [
            re.compile(str(p)) for p in raw.get("prompt_injection_patterns", [])
        ]
        taint_patterns = [
            TaintPattern(name=str(e.get("name", "pii")), pattern=re.compile(e["pattern"]))
            for e in raw.get("taint_patterns", [])
        ]
        return cls(
            login_url_patterns=[str(p).lower() for p in raw.get("login_url_patterns", [])],
            high_risk_keywords=[str(k).lower() for k in raw.get("high_risk_keywords", [])],
            read_only_blocked_methods={
                str(m).upper() for m in raw.get("read_only_blocked_methods", [])
            }
            or {"POST", "PUT", "PATCH", "DELETE"},
            redaction_rules=redaction_rules,
            prompt_injection_patterns=injection_patterns,
            taint_patterns=taint_patterns,
        )


VALID_CONTRACT_ACTIONS = {"navigate", "read", "click", "fill", "write"}


@dataclass
class TaskContract:
    """OAuth-style scoped capability contract bound to a browser session."""

    task: str = "General browser session"
    domains: list[str] = field(default_factory=list)
    allow: set[str] = field(default_factory=lambda: set(VALID_CONTRACT_ACTIONS))
    max_write_requests: int | None = None
    confirm_writes: bool = True
    expires_in_seconds: int | None = None
    ephemeral: bool = False
    created_at: float = field(default_factory=time.time)
    write_count: int = 0

    @classmethod
    def from_yaml(cls, path: Path) -> "TaskContract":
        """Load a TaskContract from a YAML file."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        allow_raw = raw.get("allow")
        if allow_raw is None:
            allow = set(VALID_CONTRACT_ACTIONS)
        else:
            allow = {str(a).strip().lower() for a in allow_raw}
            unknown = allow - VALID_CONTRACT_ACTIONS
            if unknown:
                raise ValueError(f"Unknown contract action(s): {', '.join(sorted(unknown))}")

        max_writes = raw.get("max_write_requests")
        ttl = raw.get("expires_in_seconds")
        return cls(
            task=str(raw.get("task", "Scoped browser task")),
            domains=[str(d).strip().lower() for d in raw.get("domains", []) if str(d).strip()],
            allow=allow,
            max_write_requests=int(max_writes) if max_writes is not None else None,
            confirm_writes=bool(raw.get("confirm_writes", True)),
            expires_in_seconds=int(ttl) if ttl is not None else None,
            ephemeral=bool(raw.get("ephemeral", False)),
        )

    def is_expired(self, now: float | None = None) -> bool:
        """Return True if the contract TTL has elapsed."""
        if self.expires_in_seconds is None:
            return False
        current = time.time() if now is None else now
        return (current - self.created_at) >= self.expires_in_seconds

    def check_action(self, action: str, now: float | None = None) -> str | None:
        """Return an error reason if the action violates the contract, else None."""
        if self.is_expired(now=now):
            return (
                f"CONTRACT_EXPIRED: Session TTL ({self.expires_in_seconds}s) expired. "
                "Stop and start a new session with user approval."
            )
        normalized = action.lower()
        if normalized not in self.allow:
            return (
                f"CONTRACT_DENIED: Action '{normalized}' is not permitted by task contract "
                f"(allowed: {', '.join(sorted(self.allow))})."
            )
        if normalized == "write" and self.max_write_requests is not None:
            if self.write_count >= self.max_write_requests:
                return (
                    f"CONTRACT_WRITE_BUDGET_EXCEEDED: Max write requests "
                    f"({self.max_write_requests}) reached."
                )
        return None

    def record_write(self) -> None:
        """Increment write counter after an approved write request."""
        self.write_count += 1


class TaintTracker:
    """Tracks sensitive values read from one origin to prevent cross-domain exfiltration."""

    def __init__(self) -> None:
        # Maps extracted sensitive value -> (source_host, pattern_name)
        self._tainted: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _host_of(url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    @staticmethod
    def _site_root(host: str) -> str:
        parts = host.lower().split(".")
        if len(parts) <= 2:
            return host.lower()
        two_part_tlds = {"co.uk", "org.uk", "ac.uk", "com.cn", "net.cn", "org.cn", "gov.cn", "com.au"}
        if ".".join(parts[-2:]) in two_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @classmethod
    def _same_site(cls, host_a: str, host_b: str) -> bool:
        if not host_a or not host_b:
            return False
        return cls._site_root(host_a) == cls._site_root(host_b)

    def observe(self, text: str, source_url: str, policy: SecurityPolicy) -> int:
        """Scan extracted page text and record sensitive values with their source origin."""
        host = self._host_of(source_url)
        if not host or not text:
            return 0
        added = 0
        for tp in policy.taint_patterns:
            for match in tp.pattern.finditer(text):
                val = match.group(0).strip()
                if len(val) >= 6 and val not in self._tainted:
                    self._tainted[val] = (host, tp.name)
                    added += 1
        return added

    def check_egress(self, value: str, target_url: str) -> tuple[str, str] | None:
        """Return (source_host, taint_type) if `value` contains tainted data from another site."""
        target_host = self._host_of(target_url)
        if not value or not target_host:
            return None
        for tainted_val, (source_host, kind) in self._tainted.items():
            if tainted_val in value and not self._same_site(source_host, target_host):
                return (source_host, kind)
        return None


def sanitize_profile_name(name: str) -> str:
    """Sanitize a profile name so it cannot escape the profiles directory."""
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "-", name.strip())
    cleaned = cleaned.strip("-")
    if not cleaned:
        raise ValueError("Profile name must contain at least one alphanumeric character.")
    return cleaned


def is_domain_allowed(url: str, allowed_domains: Iterable[str]) -> bool:
    """Check whether a URL's hostname matches the domain allowlist.

    An empty allowlist permits all http/https URLs. Non-http(s) internal URLs
    such as about:blank, data:, and blob: are always permitted.
    """
    domains = [d.strip().lower().lstrip(".") for d in allowed_domains if d.strip()]
    parsed = urlparse(url)
    if parsed.scheme in {"about", "data", "blob"}:
        return True
    if not domains:
        return parsed.scheme in {"http", "https"}
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return any(host == d or host.endswith(f".{d}") for d in domains)


def is_login_url(url: str, policy: SecurityPolicy) -> bool:
    """Return True if the URL path or query looks like a login/auth endpoint."""
    parsed = urlparse(url)
    target = f"{parsed.path}?{parsed.query}".lower()
    return any(pattern in target for pattern in policy.login_url_patterns)


def match_high_risk_keyword(
    text: str, aria_label: str, title: str, policy: SecurityPolicy
) -> str | None:
    """Return the matched high-risk keyword if the element looks dangerous, else None."""
    combined = " ".join(part for part in (text, aria_label, title) if part).lower()
    if not combined:
        return None
    for kw in policy.high_risk_keywords:
        if kw in combined:
            return kw
    return None


def redact_text(text: str, policy: SecurityPolicy) -> str:
    """Redact sensitive tokens and secrets from text before returning to the LLM."""
    result = text
    for rule in policy.redaction_rules:
        result = rule.pattern.sub(rule.replacement, result)
    return result


def detect_prompt_injection(text: str, policy: SecurityPolicy) -> list[str]:
    """Return matched prompt-injection snippets found in untrusted web text."""
    hits: list[str] = []
    for pattern in policy.prompt_injection_patterns:
        match = pattern.search(text)
        if match:
            hits.append(match.group(0))
    return hits


def wrap_untrusted_content(text: str, source_url: str, warnings: list[str] | None = None) -> str:
    """Frame web-derived text with explicit untrusted-data boundaries for the LLM."""
    header = f'<untrusted_web_content source="{source_url}">'
    if warnings:
        header += f'\n[SECURITY_WARNING: Potential prompt injection detected: {"; ".join(warnings)}]'
    return f"{header}\n{text}\n</untrusted_web_content>"
