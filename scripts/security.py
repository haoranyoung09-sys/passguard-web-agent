"""Core security policy, task contract, anti-injection, and taint tracking engine.

Provides deterministic, code-level guardrails:
- Domain allowlist enforcement across all resource types (with optional asset domains)
- OAuth-style Task Contract (scoped actions, write budget, TTL, ephemeral mode)
- Path-boundary login URL & OTP/QR/Passkey text detection
- Word-boundary ASCII & CJK high-risk UI element detection
- Output secret redaction and human-readable write-payload summarization
- Unicode-normalized prompt-injection heuristic scanning & untrusted framing
- Cross-domain taint tracking across fill, URL query strings, and network bodies
- Isolated profile path sanitization
"""

from __future__ import annotations

import base64
import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, unquote_plus, urlparse

import yaml

ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


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
    login_text_indicators: list[str] = field(default_factory=list)
    high_risk_keywords: list[str] = field(default_factory=list)
    read_only_blocked_methods: set[str] = field(
        default_factory=lambda: {"POST", "PUT", "PATCH", "DELETE"}
    )
    benign_write_url_patterns: list[str] = field(default_factory=list)
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
            login_text_indicators=[str(p).lower() for p in raw.get("login_text_indicators", [])],
            high_risk_keywords=[str(k).lower() for k in raw.get("high_risk_keywords", [])],
            read_only_blocked_methods={
                str(m).upper() for m in raw.get("read_only_blocked_methods", [])
            }
            or {"POST", "PUT", "PATCH", "DELETE"},
            benign_write_url_patterns=[
                str(p).lower() for p in raw.get("benign_write_url_patterns", [])
            ],
            redaction_rules=redaction_rules,
            prompt_injection_patterns=injection_patterns,
            taint_patterns=taint_patterns,
        )


VALID_CONTRACT_ACTIONS = {"navigate", "read", "click", "fill", "write"}
VALID_CONFIRM_WRITE_MODES = {"strict", "smart", "none"}


@dataclass
class TaskContract:
    """OAuth-style scoped capability contract bound to a browser session."""

    task: str = "General browser session"
    domains: list[str] = field(default_factory=list)
    asset_domains: list[str] = field(default_factory=list)
    allow: set[str] = field(default_factory=lambda: set(VALID_CONTRACT_ACTIONS))
    max_write_requests: int | None = None
    confirm_writes: bool = True
    confirm_writes_mode: str = "strict"
    expires_in_seconds: int | None = None
    ephemeral: bool = False
    created_at: float = field(default_factory=time.time)
    write_count: int = 0

    def __post_init__(self) -> None:
        if not self.confirm_writes:
            self.confirm_writes_mode = "none"
        if self.confirm_writes_mode not in VALID_CONFIRM_WRITE_MODES:
            raise ValueError(f"Invalid confirm_writes_mode: {self.confirm_writes_mode}")

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

        confirm_writes = bool(raw.get("confirm_writes", True))
        mode = str(raw.get("confirm_writes_mode", "strict" if confirm_writes else "none")).lower()

        max_writes = raw.get("max_write_requests")
        ttl = raw.get("expires_in_seconds")
        return cls(
            task=str(raw.get("task", "Scoped browser task")),
            domains=[str(d).strip().lower() for d in raw.get("domains", []) if str(d).strip()],
            asset_domains=[
                str(d).strip().lower() for d in raw.get("asset_domains", []) if str(d).strip()
            ],
            allow=allow,
            max_write_requests=int(max_writes) if max_writes is not None else None,
            confirm_writes=confirm_writes,
            confirm_writes_mode=mode,
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

    TWO_PART_SUFFIXES = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.hk",
        "com.tw",
        "com.sg",
    }

    def __init__(self) -> None:
        self._tainted: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _host_of(url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    @classmethod
    def _site_root(cls, host: str) -> str:
        parts = host.lower().split(".")
        if len(parts) <= 2:
            return host.lower()
        if ".".join(parts[-2:]) in cls.TWO_PART_SUFFIXES and len(parts) >= 3:
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

    def check_egress(self, payload: str, target_url: str) -> tuple[str, str] | None:
        """Return (source_host, taint_type) if `payload` leaks tainted data to another site.

        Checks raw, URL-decoded, and Base64-encoded variants of each tainted value.
        """
        target_host = self._host_of(target_url)
        if not payload or not target_host:
            return None
        decoded = unquote_plus(payload)
        for tainted_val, (source_host, kind) in self._tainted.items():
            if self._same_site(source_host, target_host):
                continue
            b64_val = base64.b64encode(tainted_val.encode("utf-8")).decode("ascii").rstrip("=")
            if (
                tainted_val in payload
                or tainted_val in decoded
                or (len(b64_val) >= 8 and b64_val in payload)
            ):
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

    An empty allowlist permits all http/https/ws/wss URLs. Non-network internal
    URLs such as about:blank, data:, and blob: are always permitted.
    """
    domains = [d.strip().lower().lstrip(".") for d in allowed_domains if d.strip()]
    parsed = urlparse(url)
    if parsed.scheme in {"about", "data", "blob"}:
        return True
    allowed_schemes = {"http", "https", "ws", "wss"}
    if not domains:
        return parsed.scheme in allowed_schemes
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return any(host == d or host.endswith(f".{d}") for d in domains)


def is_login_url(url: str, policy: SecurityPolicy) -> bool:
    """Return True if the URL path matches a login/auth route on segment boundaries."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for pattern in policy.login_url_patterns:
        escaped = re.escape(pattern.lower())
        if re.search(rf"(?:^|/){escaped.lstrip('/')}(?:/|$)", path):
            return True
    return False


def is_login_text(text: str, policy: SecurityPolicy) -> bool:
    """Return True if visible text contains QR, OTP, or Passkey login prompts."""
    if not text:
        return False
    lowered = normalize_for_detection(text).lower()
    return any(ind in lowered for ind in policy.login_text_indicators)


def match_high_risk_keyword(
    text: str, aria_label: str, title: str, policy: SecurityPolicy
) -> str | None:
    """Return the matched high-risk keyword if the element looks dangerous, else None.

    Pure ASCII keywords require word boundaries so 'wire' does not match 'wireless'.
    Non-ASCII (e.g., CJK) keywords match as substrings.
    """
    combined = " ".join(part for part in (text, aria_label, title) if part).lower()
    if not combined:
        return None
    for kw in policy.high_risk_keywords:
        if kw.isascii():
            if re.search(rf"\b{re.escape(kw)}\b", combined):
                return kw
        elif kw in combined:
            return kw
    return None


def is_benign_write_url(url: str, policy: SecurityPolicy) -> bool:
    """Return True if the URL path matches a known benign telemetry/analytics pattern."""
    path = urlparse(url).path.lower()
    return any(pat in path for pat in policy.benign_write_url_patterns)


def summarize_write_payload(post_data: str | None, policy: SecurityPolicy) -> str:
    """Format JSON or URL-encoded write payloads into a readable, redacted summary."""
    if not post_data:
        return "(empty body)"

    sensitive_keys = ("password", "passwd", "token", "secret", "api_key", "authorization", "cookie")

    def _fmt_kv(key: str, val: str) -> str:
        low = key.lower()
        if any(s in low for s in sensitive_keys):
            return f"  - {key}: [REDACTED]"
        return f"  - {key}: {redact_text(val[:120], policy)}"

    trimmed = post_data[:1200]
    try:
        parsed = json.loads(trimmed)
        if isinstance(parsed, dict):
            lines = [_fmt_kv(str(k), str(v)) for k, v in list(parsed.items())[:12]]
            return "JSON fields:\n" + "\n".join(lines)
    except (json.JSONDecodeError, TypeError):
        pass

    if "=" in trimmed and "&" in trimmed:
        qs = parse_qs(trimmed, keep_blank_values=True)
        if qs:
            lines = [_fmt_kv(str(k), ", ".join(vs)) for k, vs in list(qs.items())[:12]]
            return "Form fields:\n" + "\n".join(lines)

    return redact_text(trimmed[:400], policy)


def redact_text(text: str, policy: SecurityPolicy) -> str:
    """Redact sensitive tokens and secrets from text before returning to the LLM."""
    result = text
    for rule in policy.redaction_rules:
        result = rule.pattern.sub(rule.replacement, result)
    return result


def normalize_for_detection(text: str) -> str:
    """Apply NFKC normalization and strip zero-width characters."""
    normalized = unicodedata.normalize("NFKC", text)
    return ZERO_WIDTH_RE.sub("", normalized)


def detect_prompt_injection(text: str, policy: SecurityPolicy) -> list[str]:
    """Return matched prompt-injection snippets found in untrusted web text."""
    cleaned = normalize_for_detection(text)
    hits: list[str] = []
    for pattern in policy.prompt_injection_patterns:
        match = pattern.search(cleaned)
        if match:
            hits.append(match.group(0))
    return hits


def wrap_untrusted_content(text: str, source_url: str, warnings: list[str] | None = None) -> str:
    """Frame web-derived text with explicit untrusted-data boundaries for the LLM."""
    header = f'<untrusted_web_content source="{source_url}">'
    if warnings:
        header += f'\n[SECURITY_WARNING: Potential prompt injection detected: {"; ".join(warnings)}]'
    return f"{header}\n{text}\n</untrusted_web_content>"
