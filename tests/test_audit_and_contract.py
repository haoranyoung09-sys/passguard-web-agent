"""Unit tests for TaskContract enforcement and HMAC-SHA256 / SHA-256 audit logging."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from audit import AuditLogger, verify_audit_log  # noqa: E402
from security import SecurityPolicy, TaskContract  # noqa: E402


class TestTaskContractAndAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = SecurityPolicy.from_yaml(REPO_ROOT / "rules.yaml")

    def test_contract_yaml_loading_and_budget(self) -> None:
        contract = TaskContract.from_yaml(REPO_ROOT / "contracts" / "safe-form-fill.yaml")
        self.assertTrue(contract.ephemeral)
        self.assertEqual(contract.max_write_requests, 1)
        self.assertIsNone(contract.check_action("write"))
        contract.record_write()
        err = contract.check_action("write")
        self.assertIsNotNone(err)
        self.assertIn("CONTRACT_WRITE_BUDGET_EXCEEDED", err or "")

    def test_contract_expiration(self) -> None:
        contract = TaskContract(expires_in_seconds=60, created_at=1000.0)
        self.assertIsNone(contract.check_action("read", now=1059.0))
        err = contract.check_action("read", now=1060.0)
        self.assertIsNotNone(err)
        self.assertIn("CONTRACT_EXPIRED", err or "")

    def test_contract_disallowed_action(self) -> None:
        contract = TaskContract.from_yaml(REPO_ROOT / "contracts" / "readonly-research.yaml")
        err = contract.check_action("fill")
        self.assertIsNotNone(err)
        self.assertIn("CONTRACT_DENIED", err or "")

    def test_audit_unkeyed_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "session.jsonl"
            logger = AuditLogger(log_path, self.policy, hmac_key=b"")
            logger.record("session_start", "ok", {"token": "Bearer secret_abc_123456789"})
            logger.record("goto", "ok", {"url": "https://example.com"})

            ok, count, msg = verify_audit_log(log_path)
            self.assertTrue(ok, msg)
            self.assertEqual(count, 2)

            # require_hmac must reject unkeyed logs
            ok_req, _, _ = verify_audit_log(log_path, require_hmac=True)
            self.assertFalse(ok_req)

            # Tamper with record #2
            lines = log_path.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[1])
            tampered["outcome"] = "tampered"
            lines[1] = json.dumps(tampered)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            ok_after, _, msg_after = verify_audit_log(log_path)
            self.assertFalse(ok_after)
            self.assertIn("Tampered record detected", msg_after)

    def test_audit_hmac_keyed_verification(self) -> None:
        secret_key = b"operator-held-hmac-secret-2026"
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "hmac.jsonl"
            logger = AuditLogger(log_path, self.policy, hmac_key=secret_key)
            logger.record("session_start", "ok", {"profile": "bank"})
            logger.record("route_write_oob", "denied", {"url": "https://bank.example.com/pay"})

            ok, count, msg = verify_audit_log(log_path, hmac_key=secret_key, require_hmac=True)
            self.assertTrue(ok, msg)
            self.assertEqual(count, 2)
            self.assertIn("HMAC-SHA256", msg)

            # Wrong key must fail verification
            ok_wrong, _, _ = verify_audit_log(log_path, hmac_key=b"wrong-key", require_hmac=True)
            self.assertFalse(ok_wrong)


if __name__ == "__main__":
    unittest.main()
