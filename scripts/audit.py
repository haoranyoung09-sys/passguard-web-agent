"""Tamper-evident hash-chain and optional HMAC-SHA256 audit logger for PassGuard Web Agent."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security import SecurityPolicy, redact_text

GENESIS_HASH = "0" * 64


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _redact_value(value: Any, policy: SecurityPolicy) -> Any:
    if isinstance(value, str):
        return redact_text(value, policy)
    if isinstance(value, dict):
        return {str(k): _redact_value(v, policy) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, policy) for v in value]
    return value


def _compute_tag(body: dict[str, Any], hmac_key: bytes | None) -> str:
    raw = _canonical_json(body).encode("utf-8")
    if hmac_key:
        return hmac.new(hmac_key, raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def resolve_hmac_key(key_file: Path | None = None) -> bytes | None:
    """Load HMAC key from explicit key_file or PASSGUARD_AUDIT_KEY env var."""
    if key_file is not None and key_file.exists():
        raw = key_file.read_bytes().strip()
        return raw if raw else None
    env_key = os.environ.get("PASSGUARD_AUDIT_KEY", "").strip()
    return env_key.encode("utf-8") if env_key else None


class AuditLogger:
    """Append-only hash-chained (or HMAC-SHA256 chained) JSONL audit log."""

    def __init__(
        self,
        log_path: Path,
        policy: SecurityPolicy,
        hmac_key: bytes | None = None,
    ) -> None:
        self.log_path = log_path
        self.policy = policy
        self.hmac_key = hmac_key if hmac_key is not None else resolve_hmac_key()
        self.mode = "hmac-sha256" if self.hmac_key else "sha256-unkeyed"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev_hash = self._resume_tail()

    def _resume_tail(self) -> tuple[int, str]:
        if not self.log_path.exists():
            return 0, GENESIS_HASH
        lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not lines:
            return 0, GENESIS_HASH
        last = json.loads(lines[-1])
        return int(last["seq"]), str(last["hash"])

    def record(self, action: str, outcome: str, details: dict[str, Any] | None = None) -> str:
        """Append a redacted, chained audit record and return its digest/HMAC."""
        self._seq += 1
        body = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "mode": self.mode,
            "action": action,
            "outcome": outcome,
            "details": _redact_value(details or {}, self.policy),
            "prev_hash": self._prev_hash,
        }
        digest = _compute_tag(body, self.hmac_key)
        entry = {**body, "hash": digest}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical_json(entry) + "\n")
        self._prev_hash = digest
        return digest


def verify_audit_log(
    log_path: Path,
    hmac_key: bytes | None = None,
    require_hmac: bool = False,
) -> tuple[bool, int, str]:
    """Verify hash-chain / HMAC-SHA256 integrity of an audit log file."""
    if not log_path.exists():
        return False, 0, f"Audit log not found: {log_path}"

    key = hmac_key if hmac_key is not None else resolve_hmac_key()
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    expected_prev = GENESIS_HASH
    modes_seen: set[str] = set()

    for idx, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, idx - 1, f"Corrupt JSON at line {idx}: {exc}"

        if entry.get("seq") != idx:
            return False, idx - 1, f"Sequence mismatch at line {idx}: got {entry.get('seq')}"
        if entry.get("prev_hash") != expected_prev:
            return False, idx - 1, f"Broken chain at seq {idx}: prev_hash mismatch"

        mode = entry.get("mode", "sha256-unkeyed")
        modes_seen.add(mode)
        if require_hmac and mode != "hmac-sha256":
            return False, idx - 1, f"Record seq {idx} is unkeyed ({mode}); HMAC required."
        if mode == "hmac-sha256" and not key:
            return False, idx - 1, f"Record seq {idx} requires an HMAC key to verify."

        body = {
            "seq": entry["seq"],
            "ts": entry["ts"],
            "mode": mode,
            "action": entry["action"],
            "outcome": entry["outcome"],
            "details": entry["details"],
            "prev_hash": entry["prev_hash"],
        }
        expected_tag = _compute_tag(body, key if mode == "hmac-sha256" else None)
        if not hmac.compare_digest(str(entry.get("hash", "")), expected_tag):
            return False, idx - 1, f"Tampered record detected at seq {idx}: digest mismatch"

        expected_prev = expected_tag

    if "hmac-sha256" in modes_seen and len(modes_seen) == 1:
        return True, len(lines), f"Verified {len(lines)} HMAC-SHA256 audit record(s)."
    return (
        True,
        len(lines),
        f"Verified {len(lines)} unkeyed SHA-256 record(s) (detects accidental corruption; "
        "set PASSGUARD_AUDIT_KEY / --key-file for cryptographic tamper resistance).",
    )
