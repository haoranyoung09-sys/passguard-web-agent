"""Tamper-evident SHA-256 hash-chain audit logger for PassGuard Web Agent."""

from __future__ import annotations

import hashlib
import json
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


class AuditLogger:
    """Append-only hash-chained JSONL audit log."""

    def __init__(self, log_path: Path, policy: SecurityPolicy) -> None:
        self.log_path = log_path
        self.policy = policy
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
        """Append a redacted, hash-chained audit record and return its hash."""
        self._seq += 1
        body = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "outcome": outcome,
            "details": _redact_value(details or {}, self.policy),
            "prev_hash": self._prev_hash,
        }
        digest = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
        entry = {**body, "hash": digest}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical_json(entry) + "\n")
        self._prev_hash = digest
        return digest


def verify_audit_log(log_path: Path) -> tuple[bool, int, str]:
    """Verify hash-chain integrity of an audit log file.

    Returns (is_valid, entry_count, message).
    """
    if not log_path.exists():
        return False, 0, f"Audit log not found: {log_path}"

    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    expected_prev = GENESIS_HASH

    for idx, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, idx - 1, f"Corrupt JSON at line {idx}: {exc}"

        if entry.get("seq") != idx:
            return False, idx - 1, f"Sequence mismatch at line {idx}: got {entry.get('seq')}"
        if entry.get("prev_hash") != expected_prev:
            return False, idx - 1, f"Broken hash chain at seq {idx}: prev_hash mismatch"

        body = {
            "seq": entry["seq"],
            "ts": entry["ts"],
            "action": entry["action"],
            "outcome": entry["outcome"],
            "details": entry["details"],
            "prev_hash": entry["prev_hash"],
        }
        expected_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
        if entry.get("hash") != expected_hash:
            return False, idx - 1, f"Tampered record detected at seq {idx}: hash mismatch"

        expected_prev = expected_hash

    return True, len(lines), f"Verified {len(lines)} intact audit record(s)."
