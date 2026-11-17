"""PassGuard Web Agent CLI — Fast, isolated, credential-safe browser driver.

Key security guarantees enforced in the local daemon (never bypassable by the LLM):
- Isolated Chromium persistent profile per task (+ optional --ephemeral wipe on stop)
- OAuth-style Task Contract (scoped actions, domain allowlist, write budget, TTL)
- Password-field circuit breaker (stripped from snapshots, blocked from fill)
- Out-of-band (OOB) native OS confirmation for high-risk clicks & network writes
- Prompt-injection DOM filtering (hidden/invisible/off-screen text) & untrusted framing
- Cross-domain taint tracking to stop data exfiltration across websites
- Tamper-evident SHA-256 hash-chain audit log (`verify-log`)
- Deterministic site-memory recipe replay (`save-recipe` / `replay`)
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_RULES_PATH = REPO_ROOT / "rules.yaml"
STATE_HOME = Path.home() / ".passguard-web-agent"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit import AuditLogger, verify_audit_log  # noqa: E402
from oob_confirm import ConfirmCallback, native_oob_confirm  # noqa: E402
from security import (  # noqa: E402
    SecurityPolicy,
    TaintTracker,
    TaskContract,
    detect_prompt_injection,
    is_domain_allowed,
    is_login_url,
    match_high_risk_keyword,
    redact_text,
    sanitize_profile_name,
    wrap_untrusted_content,
)

SNAPSHOT_JS = r"""
() => {
  const isHumanVisible = (el) => {
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    if (rect.right <= 0 || rect.bottom <= 0) return false;
    const style = window.getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (parseFloat(style.opacity || '1') <= 0.05) return false;
    if (parseFloat(style.fontSize || '12') < 2) return false;
    if (style.color && style.backgroundColor && style.color === style.backgroundColor) {
      return false;
    }
    return true;
  };

  const selectorFor = (el) => {
    if (el.id) return '#' + CSS.escape(el.id);
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && cur !== document.body) {
      let idx = 1;
      let sib = cur.previousElementSibling;
      while (sib) {
        if (sib.tagName === cur.tagName) idx++;
        sib = sib.previousElementSibling;
      }
      parts.unshift(cur.tagName.toLowerCase() + ':nth-of-type(' + idx + ')');
      cur = cur.parentElement;
    }
    return 'body > ' + parts.join(' > ');
  };

  const candidates = document.querySelectorAll(
    'a[href], button, input, select, textarea, [role="button"], [role="link"], [role="textbox"]'
  );

  const elements = [];
  let passwordCount = 0;
  let hiddenSkipped = 0;
  let refIdx = 1;

  for (const el of candidates) {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || '').toLowerCase();
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();

    if (tag === 'input' && (type === 'password' || ac.includes('password'))) {
      if (isHumanVisible(el)) passwordCount++;
      continue;
    }

    if (!isHumanVisible(el)) {
      hiddenSkipped++;
      continue;
    }

    const text = (el.innerText || el.value || el.getAttribute('placeholder') || '')
      .trim().replace(/\s+/g, ' ').slice(0, 120);
    const aria = (el.getAttribute('aria-label') || '').trim().slice(0, 120);
    const title = (el.getAttribute('title') || '').trim().slice(0, 120);
    const role = el.getAttribute('role') || tag;

    elements.push({
      ref: '@e' + refIdx,
      tag,
      type,
      role,
      text,
      aria_label: aria,
      title,
      selector: selectorFor(el),
    });
    refIdx++;
    if (refIdx > 150) break;
  }

  return {
    url: window.location.href,
    title: document.title || '',
    password_fields: passwordCount,
    hidden_skipped: hiddenSkipped,
    elements,
  };
}
"""

VISIBLE_TEXT_JS = r"""
() => {
  if (!document.body) return '';
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const chunks = [];
  let node;
  while ((node = walker.nextNode())) {
    const parent = node.parentElement;
    if (!parent) continue;
    const tag = parent.tagName.toLowerCase();
    if (tag === 'script' || tag === 'style' || tag === 'noscript') continue;
    const rect = parent.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1 || rect.right <= 0 || rect.bottom <= 0) continue;
    const style = window.getComputedStyle(parent);
    if (style.visibility === 'hidden' || style.display === 'none') continue;
    if (parseFloat(style.opacity || '1') <= 0.05) continue;
    if (parseFloat(style.fontSize || '12') < 2) continue;
    if (style.color && style.backgroundColor && style.color === style.backgroundColor) continue;
    const val = (node.nodeValue || '').trim();
    if (val) chunks.push(val);
  }
  return chunks.join(' ').replace(/\s+/g, ' ').trim();
}
"""


def session_file_for(profile: str) -> Path:
    safe = sanitize_profile_name(profile)
    return STATE_HOME / "sessions" / f"{safe}.json"


def profile_dir_for(profile: str) -> Path:
    safe = sanitize_profile_name(profile)
    return STATE_HOME / "profiles" / safe


def audit_log_for(profile: str) -> Path:
    safe = sanitize_profile_name(profile)
    return STATE_HOME / "logs" / f"{safe}.jsonl"


def load_session(profile: str) -> dict[str, Any]:
    path = session_file_for(profile)
    if not path.exists():
        raise RuntimeError(
            f"No active session for profile '{profile}'. Run 'start --profile {profile}' first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def rpc_call(profile: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    session = load_session(profile)
    url = f"http://127.0.0.1:{session['port']}{endpoint}"
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {session['token']}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=150) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError(f"Daemon HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Failed to reach browser session '{profile}' ({exc.reason}). "
            "It may have closed; run 'start' again."
        ) from exc


class BrowserController:
    """Owns the Playwright persistent context and enforces all security guardrails."""

    def __init__(
        self,
        profile: str,
        contract: TaskContract,
        headless: bool,
        policy: SecurityPolicy,
        confirm_fn: ConfirmCallback = native_oob_confirm,
    ) -> None:
        from playwright.sync_api import sync_playwright

        self.profile = sanitize_profile_name(profile)
        self.contract = contract
        self.policy = policy
        self.confirm_fn = confirm_fn
        self.taint = TaintTracker()
        self.audit = AuditLogger(audit_log_for(self.profile), policy)
        self.refs: dict[str, dict[str, Any]] = {}
        self.recorded_steps: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()

        self.user_data_dir = profile_dir_for(self.profile)
        self.user_data_dir.mkdir(parents=True, exist_ok=True)

        self._pw = sync_playwright().start()
        self.context = self._pw.chromium.launch_persistent_context(
            user_data_dir=str(self.user_data_dir),
            headless=headless,
        )
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
        self.context.route("**/*", self._route_guard)

        self.audit.record(
            "session_start",
            "ok",
            {
                "profile": self.profile,
                "task": contract.task,
                "domains": contract.domains,
                "allow": sorted(contract.allow),
                "max_write_requests": contract.max_write_requests,
                "ephemeral": contract.ephemeral,
            },
        )

    def _route_guard(self, route: Any) -> None:
        request = route.request
        url = request.url
        resource_type = request.resource_type
        method = request.method.upper()

        if self.contract.domains and resource_type in {"document", "xhr", "fetch"}:
            if not is_domain_allowed(url, self.contract.domains):
                self.audit.record("route_domain_block", "blocked", {"method": method, "url": url})
                route.abort("blockedbyclient")
                return

        if (
            resource_type in {"document", "xhr", "fetch"}
            and method in self.policy.read_only_blocked_methods
        ):
            violation = self.contract.check_action("write")
            if violation:
                self.audit.record(
                    "route_write_block",
                    "blocked",
                    {"method": method, "url": url, "reason": violation},
                )
                route.abort("blockedbyclient")
                return

            if self.contract.confirm_writes:
                body_preview = redact_text((request.post_data or "")[:400], self.policy)
                detail = (
                    f"Allow network write request?\n\n"
                    f"Method: {method}\n"
                    f"URL: {redact_text(url, self.policy)}\n"
                    f"Body preview: {body_preview or '(empty)'}"
                )
                approved = self.confirm_fn("Network Write Request", detail)
                if not approved:
                    self.audit.record(
                        "route_write_oob",
                        "denied",
                        {"method": method, "url": url},
                    )
                    route.abort("blockedbyclient")
                    return

            self.contract.record_write()
            self.audit.record(
                "route_write_oob",
                "approved",
                {"method": method, "url": url, "write_count": self.contract.write_count},
            )

        route.continue_()

    def _check_contract(self, action: str) -> dict[str, Any] | None:
        violation = self.contract.check_action(action)
        if violation:
            self.audit.record(action, "contract_denied", {"reason": violation})
            return {"ok": False, "code": 4, "error": violation}
        return None

    def goto(self, url: str) -> dict[str, Any]:
        err = self._check_contract("navigate")
        if err:
            return err
        if self.contract.domains and not is_domain_allowed(url, self.contract.domains):
            msg = f"BLOCKED_DOMAIN: '{url}' is outside allowed domains ({', '.join(self.contract.domains)})."
            self.audit.record("goto", "blocked_domain", {"url": url})
            return {"ok": False, "code": 2, "error": msg}

        self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
        self.page.wait_for_timeout(450)
        self.recorded_steps.append({"action": "goto", "url": url})
        self.audit.record("goto", "ok", {"url": self.page.url})
        return {
            "ok": True,
            "url": self.page.url,
            "title": redact_text(self.page.title(), self.policy),
        }

    def snapshot(self) -> dict[str, Any]:
        err = self._check_contract("read")
        if err:
            return err

        raw = self.page.evaluate(SNAPSHOT_JS)
        url = raw.get("url", self.page.url)
        pw_count = int(raw.get("password_fields", 0))
        self.refs = {el["ref"]: el for el in raw.get("elements", [])}

        if pw_count > 0 or is_login_url(url, self.policy):
            self.audit.record(
                "snapshot", "login_required", {"url": url, "password_fields": pw_count}
            )
            return {
                "ok": False,
                "code": 3,
                "login_required": True,
                "url": url,
                "password_fields": pw_count,
                "message": (
                    f"LOGIN_REQUIRED: Detected authentication page or {pw_count} password field(s) at {url}. "
                    "Pause and ask the user to log in manually in the visible browser window, then re-run 'snapshot'."
                ),
            }

        lines = []
        for el in raw.get("elements", []):
            label = el["text"] or el["aria_label"] or el["title"] or "(unlabeled)"
            self.taint.observe(label, url, self.policy)
            label = redact_text(label, self.policy)
            kind = f"{el['tag']}[{el['type']}]" if el["type"] else el["role"]
            lines.append(f"[{el['ref']}] {kind}: {label}")

        joined = "\n".join(lines)
        warnings = detect_prompt_injection(joined, self.policy)
        framed = wrap_untrusted_content(joined, url, warnings=warnings)
        self.audit.record(
            "snapshot",
            "ok",
            {
                "url": url,
                "element_count": len(lines),
                "hidden_skipped": raw.get("hidden_skipped", 0),
                "injection_warnings": len(warnings),
            },
        )
        return {
            "ok": True,
            "url": url,
            "title": redact_text(raw.get("title", ""), self.policy),
            "framed_snapshot": framed,
            "injection_warnings": warnings,
        }

    def click(self, ref: str) -> dict[str, Any]:
        err = self._check_contract("click")
        if err:
            return err

        el = self.refs.get(ref)
        if not el:
            return {"ok": False, "code": 1, "error": f"Unknown element ref '{ref}'. Run 'snapshot' first."}

        return self._click_selector(
            selector=el["selector"],
            text=el.get("text", ""),
            aria_label=el.get("aria_label", ""),
            title=el.get("title", ""),
            ref_label=ref,
        )

    def _click_selector(
        self, selector: str, text: str, aria_label: str, title: str, ref_label: str
    ) -> dict[str, Any]:
        matched_kw = match_high_risk_keyword(text, aria_label, title, self.policy)
        if matched_kw:
            label = redact_text(text or aria_label or title or ref_label, self.policy)
            approved = self.confirm_fn(
                "High-Risk Click",
                f"Allow clicking '{label}' on {self.page.url}?\n\nMatched keyword: '{matched_kw}'",
            )
            if not approved:
                self.audit.record(
                    "click",
                    "oob_denied",
                    {"ref": ref_label, "label": label, "keyword": matched_kw, "url": self.page.url},
                )
                return {
                    "ok": False,
                    "code": 2,
                    "error": f"BLOCKED_HIGH_RISK: User denied high-risk click '{label}' (keyword: '{matched_kw}').",
                }
            self.audit.record(
                "click_oob",
                "approved",
                {"ref": ref_label, "label": label, "keyword": matched_kw, "url": self.page.url},
            )

        self.page.locator(selector).first.click(timeout=10000)
        self.page.wait_for_timeout(400)
        self.recorded_steps.append(
            {
                "action": "click",
                "selector": selector,
                "label": text or aria_label or title,
            }
        )
        self.audit.record("click", "ok", {"ref": ref_label, "url": self.page.url})
        return {
            "ok": True,
            "url": self.page.url,
            "title": redact_text(self.page.title(), self.policy),
        }

    def fill(self, ref: str, value: str) -> dict[str, Any]:
        err = self._check_contract("fill")
        if err:
            return err

        el = self.refs.get(ref)
        if not el:
            return {"ok": False, "code": 1, "error": f"Unknown element ref '{ref}'. Run 'snapshot' first."}
        return self._fill_selector(el["selector"], el.get("tag", ""), el.get("type", ""), value, ref)

    def _fill_selector(
        self, selector: str, tag: str, el_type: str, value: str, ref_label: str
    ) -> dict[str, Any]:
        if tag == "input" and el_type == "password":
            self.audit.record("fill", "blocked_password", {"ref": ref_label, "url": self.page.url})
            return {
                "ok": False,
                "code": 3,
                "error": "BLOCKED_PASSWORD_FIELD: Agent is forbidden from filling password inputs.",
            }

        locator = self.page.locator(selector).first
        input_type = locator.evaluate("node => (node.type || '').toLowerCase()")
        if input_type == "password":
            self.audit.record("fill", "blocked_password_dom", {"ref": ref_label, "url": self.page.url})
            return {
                "ok": False,
                "code": 3,
                "error": "BLOCKED_PASSWORD_FIELD: Live DOM check detected a password input.",
            }

        taint_hit = self.taint.check_egress(value, self.page.url)
        if taint_hit:
            source_host, kind = taint_hit
            approved = self.confirm_fn(
                "Cross-Domain Data Transfer",
                f"Allow entering sensitive {kind} read from '{source_host}' into '{self.page.url}'?",
            )
            if not approved:
                self.audit.record(
                    "fill",
                    "blocked_taint",
                    {"source_host": source_host, "kind": kind, "target_url": self.page.url},
                )
                return {
                    "ok": False,
                    "code": 5,
                    "error": (
                        f"BLOCKED_TAINT_EXFILTRATION: Sensitive {kind} from '{source_host}' "
                        f"cannot be submitted to '{self.page.url}' without user approval."
                    ),
                }

        locator.fill(value, timeout=10000)
        self.recorded_steps.append({"action": "fill", "selector": selector, "value": value})
        self.audit.record("fill", "ok", {"ref": ref_label, "url": self.page.url})
        return {"ok": True, "ref": ref_label}

    def text(self, max_chars: int = 12000) -> dict[str, Any]:
        err = self._check_contract("read")
        if err:
            return err

        raw_text = self.page.evaluate(VISIBLE_TEXT_JS)[:max_chars]
        url = self.page.url
        self.taint.observe(raw_text, url, self.policy)
        redacted = redact_text(raw_text, self.policy)
        warnings = detect_prompt_injection(redacted, self.policy)
        framed = wrap_untrusted_content(redacted, url, warnings=warnings)
        self.audit.record(
            "text", "ok", {"url": url, "chars": len(redacted), "injection_warnings": len(warnings)}
        )
        return {
            "ok": True,
            "url": url,
            "title": redact_text(self.page.title(), self.policy),
            "text": framed,
            "injection_warnings": warnings,
        }

    def save_recipe(self, path: str) -> dict[str, Any]:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {"task": self.contract.task, "steps": self.recorded_steps}
        out.write_text(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), encoding="utf-8")
        self.audit.record("save_recipe", "ok", {"path": str(out), "steps": len(self.recorded_steps)})
        return {"ok": True, "path": str(out), "steps": len(self.recorded_steps)}

    def replay(self, path: str) -> dict[str, Any]:
        recipe_path = Path(path)
        if not recipe_path.exists():
            return {"ok": False, "code": 1, "error": f"Recipe not found: {path}"}
        data = yaml.safe_load(recipe_path.read_text(encoding="utf-8")) or {}
        steps = data.get("steps", [])
        executed = 0
        for idx, step in enumerate(steps, start=1):
            action = step.get("action")
            if action == "goto":
                res = self.goto(step["url"])
            elif action == "fill":
                err = self._check_contract("fill")
                if err:
                    return err
                res = self._fill_selector(
                    step["selector"], "", "", step["value"], f"recipe#{idx}"
                )
            elif action == "click":
                err = self._check_contract("click")
                if err:
                    return err
                res = self._click_selector(
                    step["selector"], step.get("label", ""), "", "", f"recipe#{idx}"
                )
            else:
                return {"ok": False, "code": 1, "error": f"Unknown recipe action '{action}'."}
            if not res.get("ok"):
                return res
            executed += 1

        self.audit.record("replay", "ok", {"path": path, "executed": executed})
        return {"ok": True, "executed": executed, "url": self.page.url}

    def close(self) -> None:
        try:
            self.context.close()
        finally:
            self._pw.stop()
            if self.contract.ephemeral and self.user_data_dir.exists():
                shutil.rmtree(self.user_data_dir, ignore_errors=True)
                self.audit.record("session_stop", "ephemeral_wiped", {"profile": self.profile})
            else:
                self.audit.record("session_stop", "ok", {"profile": self.profile})
            self.shutdown_event.set()


def _build_contract_from_args(args: argparse.Namespace) -> TaskContract:
    if args.contract:
        contract = TaskContract.from_yaml(Path(args.contract))
    else:
        contract = TaskContract()

    cli_domains = [d.strip().lower() for d in args.allow_domains.split(",") if d.strip()]
    if cli_domains:
        if contract.domains:
            allowed_set = set(contract.domains)
            contract.domains = [d for d in cli_domains if d in allowed_set] or cli_domains
        else:
            contract.domains = cli_domains

    if args.read_only:
        contract.allow.discard("write")
        contract.max_write_requests = 0
    if args.ephemeral:
        contract.ephemeral = True
    if args.ttl is not None:
        contract.expires_in_seconds = args.ttl
    if args.no_confirm_writes:
        contract.confirm_writes = False
    return contract


def run_daemon(args: argparse.Namespace) -> int:
    policy = SecurityPolicy.from_yaml(Path(args.rules))
    contract = _build_contract_from_args(args)
    controller = BrowserController(
        profile=args.profile,
        contract=contract,
        headless=args.headless,
        policy=policy,
    )
    token = secrets.token_hex(24)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {token}":
                self._send(403, {"ok": False, "error": "Unauthorized"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(raw.decode("utf-8"))

            with controller.lock:
                if self.path == "/goto":
                    res = controller.goto(payload["url"])
                elif self.path == "/snapshot":
                    res = controller.snapshot()
                elif self.path == "/click":
                    res = controller.click(payload["ref"])
                elif self.path == "/fill":
                    res = controller.fill(payload["ref"], payload["value"])
                elif self.path == "/text":
                    res = controller.text(int(payload.get("max_chars", 12000)))
                elif self.path == "/save-recipe":
                    res = controller.save_recipe(payload["path"])
                elif self.path == "/replay":
                    res = controller.replay(payload["path"])
                elif self.path == "/stop":
                    self._send(200, {"ok": True})
                    threading.Thread(target=controller.close, daemon=True).start()
                    return
                else:
                    self._send(404, {"ok": False, "error": f"Unknown endpoint {self.path}"})
                    return

            self._send(200 if res.get("ok") else 400, res)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]

    sess_path = session_file_for(args.profile)
    sess_path.parent.mkdir(parents=True, exist_ok=True)
    sess_path.write_text(
        json.dumps(
            {
                "profile": controller.profile,
                "port": port,
                "token": token,
                "pid": os.getpid(),
                "task": contract.task,
                "allow_domains": contract.domains,
                "ephemeral": contract.ephemeral,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if os.name == "posix":
        os.chmod(sess_path, 0o600)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        while not controller.shutdown_event.is_set():
            controller.shutdown_event.wait(0.5)
    finally:
        server.shutdown()
        server.server_close()
        if sess_path.exists():
            sess_path.unlink(missing_ok=True)
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    sess_path = session_file_for(args.profile)
    if sess_path.exists():
        try:
            res = rpc_call(args.profile, "/text", {"max_chars": 1})
            if res.get("ok"):
                print(f"Session '{args.profile}' is already running.")
                return 0
        except RuntimeError:
            sess_path.unlink(missing_ok=True)

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_serve",
        "--profile",
        args.profile,
        "--rules",
        args.rules,
    ]
    if args.contract:
        cmd.extend(["--contract", args.contract])
    if args.allow_domains:
        cmd.extend(["--allow-domains", args.allow_domains])
    if args.read_only:
        cmd.append("--read-only")
    if args.ephemeral:
        cmd.append("--ephemeral")
    if args.ttl is not None:
        cmd.extend(["--ttl", str(args.ttl)])
    if args.no_confirm_writes:
        cmd.append("--no-confirm-writes")
    if args.headless:
        cmd.append("--headless")

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP

    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
        start_new_session=(sys.platform != "win32"),
    )

    for _ in range(40):
        if sess_path.exists():
            print(f"Started isolated session '{sanitize_profile_name(args.profile)}'.")
            return 0
        time.sleep(0.25)

    print("ERROR: Timed out waiting for browser session to start.", file=sys.stderr)
    return 1


def _add_session_flags(parser: argparse.ArgumentParser, include_profile_required: bool = False) -> None:
    parser.add_argument("--profile", default="default", required=include_profile_required)
    parser.add_argument("--contract", default="", help="Path to YAML task contract.")
    parser.add_argument("--allow-domains", default="", help="Comma-separated domain allowlist.")
    parser.add_argument("--read-only", action="store_true", help="Block POST/PUT/PATCH/DELETE.")
    parser.add_argument("--ephemeral", action="store_true", help="Wipe profile directory on stop.")
    parser.add_argument("--ttl", type=int, default=None, help="Session expiration TTL in seconds.")
    parser.add_argument(
        "--no-confirm-writes",
        action="store_true",
        help="Disable OOB confirmation for non-keyword write requests.",
    )
    parser.add_argument("--headless", action="store_true", help="Run headless (OOB GUI may fail closed).")
    parser.add_argument("--rules", default=str(DEFAULT_RULES_PATH), help="Path to rules.yaml.")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="safe_browser.py",
        description="PassGuard Web Agent: isolated, credential-safe browser CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="Start an isolated browser session.")
    _add_session_flags(p_start)

    p_serve = sub.add_parser("_serve")
    _add_session_flags(p_serve, include_profile_required=True)

    p_goto = sub.add_parser("goto", help="Navigate to a URL.")
    p_goto.add_argument("url")
    p_goto.add_argument("--profile", default="default")

    p_snap = sub.add_parser("snapshot", help="Extract interactive element refs (@e1, @e2...).")
    p_snap.add_argument("--profile", default="default")

    p_click = sub.add_parser("click", help="Click an element by ref (high-risk triggers OOB dialog).")
    p_click.add_argument("ref")
    p_click.add_argument("--profile", default="default")

    p_fill = sub.add_parser("fill", help="Fill a non-password input by ref.")
    p_fill.add_argument("ref")
    p_fill.add_argument("value")
    p_fill.add_argument("--profile", default="default")

    p_text = sub.add_parser("text", help="Extract visible, redacted, injection-checked page text.")
    p_text.add_argument("--profile", default="default")
    p_text.add_argument("--max-chars", type=int, default=12000)

    p_save = sub.add_parser("save-recipe", help="Save recorded steps as a deterministic replay recipe.")
    p_save.add_argument("path")
    p_save.add_argument("--profile", default="default")

    p_replay = sub.add_parser("replay", help="Replay a saved recipe without LLM round-trips.")
    p_replay.add_argument("path")
    p_replay.add_argument("--profile", default="default")

    p_verify = sub.add_parser("verify-log", help="Verify tamper-evident SHA-256 audit log chain.")
    p_verify.add_argument("--profile", default="default")

    p_stop = sub.add_parser("stop", help="Close browser session (and wipe profile if --ephemeral).")
    p_stop.add_argument("--profile", default="default")

    args = parser.parse_args()

    if args.command == "_serve":
        return run_daemon(args)
    if args.command == "start":
        return cmd_start(args)
    if args.command == "verify-log":
        ok, count, msg = verify_audit_log(audit_log_for(args.profile))
        print(msg)
        return 0 if ok else 1

    try:
        if args.command == "goto":
            res = rpc_call(args.profile, "/goto", {"url": args.url})
        elif args.command == "snapshot":
            res = rpc_call(args.profile, "/snapshot")
        elif args.command == "click":
            res = rpc_call(args.profile, "/click", {"ref": args.ref})
        elif args.command == "fill":
            res = rpc_call(args.profile, "/fill", {"ref": args.ref, "value": args.value})
        elif args.command == "text":
            res = rpc_call(args.profile, "/text", {"max_chars": args.max_chars})
        elif args.command == "save-recipe":
            res = rpc_call(args.profile, "/save-recipe", {"path": args.path})
        elif args.command == "replay":
            res = rpc_call(args.profile, "/replay", {"path": args.path})
        elif args.command == "stop":
            rpc_call(args.profile, "/stop")
            sess_path = session_file_for(args.profile)
            if sess_path.exists():
                sess_path.unlink(missing_ok=True)
            print(f"Stopped session '{args.profile}'.")
            return 0
        else:
            return 1
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not res.get("ok"):
        msg = res.get("error") or res.get("message") or "Unknown error"
        print(msg, file=sys.stderr)
        return int(res.get("code", 1))

    if args.command == "snapshot":
        print(f"URL: {res['url']}")
        print(f"TITLE: {res['title']}")
        print(res.get("framed_snapshot", ""))
    elif args.command == "text":
        print(f"URL: {res['url']}")
        print(f"TITLE: {res['title']}")
        print(res.get("text", ""))
    else:
        print(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
