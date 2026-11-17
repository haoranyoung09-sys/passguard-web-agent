"""PassGuard Web Agent CLI — Fast, isolated, credential-safe browser driver.

Architecture:
- Single dedicated Playwright actor thread (avoids greenlet cross-thread errors).
- `ThreadingHTTPServer` dispatches RPC requests into the actor's task queue.
- All security guardrails run inside the daemon with zero CLI bypass flags:
  * Service workers blocked (`service_workers="block"`)
  * Domain allowlist enforced across ALL resource types (incl. images, scripts, ping, WS)
  * Effect-based write & sendBeacon/WebSocket gate with human-readable payload summary
  * Out-of-band native OS dialog (`tkinter`) for high-risk clicks, writes & taint egress
  * Live-DOM TOCTOU re-check immediately before clicking
  * Multi-frame (`page.frames`) + open Shadow DOM + ancestor background color filtering
  * Cross-domain taint tracking on `fill`, URL query strings, and request bodies
  * HMAC-SHA256 / SHA-256 hash-chained audit logging (`verify-log`)
  * Verified `--ephemeral` profile wipe and origin-checked recipe replay
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_RULES_PATH = REPO_ROOT / "rules.yaml"
STATE_HOME = Path.home() / ".passguard-web-agent"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit import AuditLogger, resolve_hmac_key, verify_audit_log  # noqa: E402
from oob_confirm import ConfirmCallback, native_oob_confirm  # noqa: E402
from security import (  # noqa: E402
    SecurityPolicy,
    TaintTracker,
    TaskContract,
    detect_prompt_injection,
    is_benign_write_url,
    is_domain_allowed,
    is_login_text,
    is_login_url,
    match_high_risk_keyword,
    redact_text,
    sanitize_profile_name,
    summarize_write_payload,
    wrap_untrusted_content,
)

SNAPSHOT_JS = r"""
() => {
  const effectiveBg = (el) => {
    let cur = el;
    while (cur && cur.nodeType === 1) {
      const bg = window.getComputedStyle(cur).backgroundColor;
      if (bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') {
        return bg;
      }
      cur = cur.parentElement;
    }
    return 'rgb(255, 255, 255)';
  };

  const isHumanVisible = (el) => {
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    if (rect.right <= 0 || rect.bottom <= 0) return false;
    const style = window.getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (parseFloat(style.opacity || '1') <= 0.05) return false;
    if (parseFloat(style.fontSize || '12') < 2) return false;
    if (style.color && style.color === effectiveBg(el)) return false;
    return true;
  };

  const selectorFor = (el) => {
    const testId = el.getAttribute('data-testid');
    if (testId) return `[data-testid="${CSS.escape(testId)}"]`;
    if (el.id) return '#' + CSS.escape(el.id);
    const name = el.getAttribute('name');
    if (name && document.querySelectorAll(`[name="${CSS.escape(name)}"]`).length === 1) {
      return `${el.tagName.toLowerCase()}[name="${CSS.escape(name)}"]`;
    }
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

  const INTERACTIVE = 'a[href], button, input, select, textarea, [role="button"], [role="link"], [role="textbox"]';
  const collected = [];
  const collectFromRoot = (root, inShadow) => {
    for (const el of root.querySelectorAll(INTERACTIVE)) {
      collected.push({ el, inShadow });
    }
    for (const node of root.querySelectorAll('*')) {
      if (node.shadowRoot) {
        collectFromRoot(node.shadowRoot, true);
      }
    }
  };
  collectFromRoot(document, false);

  const elements = [];
  let passwordCount = 0;
  let hiddenSkipped = 0;
  let truncated = 0;
  const MAX_ELEMENTS = 300;

  for (const { el, inShadow } of collected) {
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

    if (elements.length >= MAX_ELEMENTS) {
      truncated++;
      continue;
    }

    const text = (el.innerText || el.value || el.getAttribute('placeholder') || '')
      .trim().replace(/\s+/g, ' ').slice(0, 120);
    const aria = (el.getAttribute('aria-label') || '').trim().slice(0, 120);
    const title = (el.getAttribute('title') || '').trim().slice(0, 120);
    const role = el.getAttribute('role') || tag;

    elements.push({
      tag,
      type,
      role,
      text,
      aria_label: aria,
      title,
      in_shadow: inShadow,
      selector: inShadow ? '' : selectorFor(el),
    });
  }

  return {
    url: window.location.href,
    title: document.title || '',
    password_fields: passwordCount,
    hidden_skipped: hiddenSkipped,
    truncated,
    elements,
  };
}
"""

VISIBLE_TEXT_JS = r"""
() => {
  if (!document.body) return '';
  const effectiveBg = (el) => {
    let cur = el;
    while (cur && cur.nodeType === 1) {
      const bg = window.getComputedStyle(cur).backgroundColor;
      if (bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') return bg;
      cur = cur.parentElement;
    }
    return 'rgb(255, 255, 255)';
  };

  const chunks = [];
  const walkRoot = (root) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
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
      if (style.color && style.color === effectiveBg(parent)) continue;
      const val = (node.nodeValue || '').trim();
      if (val) chunks.push(val);
    }
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) walkRoot(el.shadowRoot);
    }
  };
  walkRoot(document.body);
  return chunks.join(' ').replace(/\s+/g, ' ').trim();
}
"""

LIVE_ELEMENT_META_JS = r"""
el => ({
  text: (el.innerText || el.value || el.getAttribute('placeholder') || '').trim().slice(0, 200),
  aria_label: (el.getAttribute('aria-label') || '').trim().slice(0, 200),
  title: (el.getAttribute('title') || '').trim().slice(0, 200),
  type: (el.getAttribute('type') || '').toLowerCase()
})
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


@dataclass
class _ActorTask:
    method: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    done: threading.Event
    result: dict[str, Any] | None = None
    error: BaseException | None = None


class BrowserController:
    """Single-threaded Playwright actor enforcing all PassGuard security guardrails."""

    def __init__(
        self,
        profile: str,
        contract: TaskContract,
        headless: bool,
        policy: SecurityPolicy,
        confirm_fn: ConfirmCallback = native_oob_confirm,
        hmac_key: bytes | None = None,
    ) -> None:
        self.profile = sanitize_profile_name(profile)
        self.contract = contract
        self.headless = headless
        self.policy = policy
        self.confirm_fn = confirm_fn
        self.taint = TaintTracker()
        self.audit = AuditLogger(audit_log_for(self.profile), policy, hmac_key=hmac_key)
        self.refs: dict[str, dict[str, Any]] = {}
        self.recorded_steps: list[dict[str, Any]] = []
        self.user_data_dir = profile_dir_for(self.profile)
        self.shutdown_event = threading.Event()

        self._queue: queue.Queue[_ActorTask | None] = queue.Queue()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._pw: Any = None
        self.context: Any = None
        self.page: Any = None

        self._actor_thread = threading.Thread(target=self._actor_loop, daemon=True)
        self._actor_thread.start()
        self._ready.wait()
        if self._startup_error is not None:
            raise self._startup_error

    def _actor_loop(self) -> None:
        try:
            from playwright.sync_api import sync_playwright

            self.user_data_dir.mkdir(parents=True, exist_ok=True)
            self._pw = sync_playwright().start()
            self.context = self._pw.chromium.launch_persistent_context(
                user_data_dir=str(self.user_data_dir),
                headless=self.headless,
                service_workers="block",
            )
            self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
            self.context.route("**/*", self._route_guard)

            self.audit.record(
                "session_start",
                "ok",
                {
                    "profile": self.profile,
                    "task": self.contract.task,
                    "domains": self.contract.domains,
                    "asset_domains": self.contract.asset_domains,
                    "allow": sorted(self.contract.allow),
                    "max_write_requests": self.contract.max_write_requests,
                    "confirm_writes_mode": self.contract.confirm_writes_mode,
                    "ephemeral": self.contract.ephemeral,
                },
            )
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            return

        self._ready.set()

        while True:
            task = self._queue.get()
            if task is None:
                break
            try:
                fn = getattr(self, f"_op_{task.method}")
                task.result = fn(*task.args, **task.kwargs)
            except BaseException as exc:
                task.error = exc
            finally:
                task.done.set()

        self._cleanup_browser()

    def invoke(self, method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Dispatch an operation onto the dedicated Playwright actor thread."""
        task = _ActorTask(method=method, args=args, kwargs=kwargs, done=threading.Event())
        self._queue.put(task)
        task.done.wait()
        if task.error is not None:
            raise task.error
        return task.result or {"ok": False, "code": 1, "error": "Empty actor response"}

    def request_shutdown(self) -> None:
        """Signal the actor thread to cleanly shut down Playwright and exit."""
        self._queue.put(None)
        self._actor_thread.join(timeout=10)

    def _cleanup_browser(self) -> None:
        try:
            if self.context is not None:
                self.context.close()
        finally:
            if self._pw is not None:
                self._pw.stop()
            if self.contract.ephemeral and self.user_data_dir.exists():
                wiped = False
                last_err = ""
                for _ in range(5):
                    try:
                        shutil.rmtree(self.user_data_dir)
                        if not self.user_data_dir.exists():
                            wiped = True
                            break
                    except OSError as exc:
                        last_err = str(exc)
                        time.sleep(0.2)
                if wiped:
                    self.audit.record("session_stop", "ephemeral_wiped", {"profile": self.profile})
                else:
                    self.audit.record(
                        "session_stop",
                        "ephemeral_wipe_failed",
                        {"profile": self.profile, "error": last_err},
                    )
            else:
                self.audit.record("session_stop", "ok", {"profile": self.profile})
            self.shutdown_event.set()

    def _route_guard(self, route: Any) -> None:
        request = route.request
        url = request.url
        resource_type = request.resource_type
        method = request.method.upper()

        # 1. Domain allowlist across ALL resource types (blocks <img src="evil.com/?d=...">, WS, ping)
        if self.contract.domains:
            allowed_pool = list(self.contract.domains)
            if resource_type in {"image", "stylesheet", "font", "media", "script"}:
                allowed_pool.extend(self.contract.asset_domains)
            if not is_domain_allowed(url, allowed_pool):
                self.audit.record(
                    "route_domain_block",
                    "blocked",
                    {"method": method, "resource_type": resource_type, "url": url},
                )
                route.abort("blockedbyclient")
                return

        # 2. Taint egress inspection across URL query strings and request bodies
        post_data = request.post_data or ""
        taint_url = self.taint.check_egress(url, url)
        taint_body = self.taint.check_egress(post_data, url)
        taint_hit = taint_url or taint_body
        if taint_hit:
            source_host, kind = taint_hit
            approved = self.confirm_fn(
                "Cross-Domain Network Exfiltration",
                f"Allow sending {kind} read from '{source_host}' to '{redact_text(url, self.policy)}'?",
            )
            if not approved:
                self.audit.record(
                    "route_taint_block",
                    "blocked",
                    {"source_host": source_host, "kind": kind, "url": url},
                )
                route.abort("blockedbyclient")
                return

        # 3. Effect-based write / beacon / WebSocket gate
        is_write_action = (
            method in self.policy.read_only_blocked_methods
            or resource_type in {"ping", "websocket"}
        )
        if is_write_action:
            violation = self.contract.check_action("write")
            if violation:
                self.audit.record(
                    "route_write_block",
                    "blocked",
                    {"method": method, "resource_type": resource_type, "url": url, "reason": violation},
                )
                route.abort("blockedbyclient")
                return

            mode = self.contract.confirm_writes_mode
            should_prompt = mode == "strict" or (
                mode == "smart" and not is_benign_write_url(url, self.policy)
            )
            if should_prompt:
                summary = summarize_write_payload(post_data, self.policy)
                detail = (
                    f"Allow network {resource_type}/{method} request?\n\n"
                    f"URL: {redact_text(url, self.policy)}\n"
                    f"{summary}"
                )
                approved = self.confirm_fn("Network Write Request", detail)
                if not approved:
                    self.audit.record(
                        "route_write_oob",
                        "denied",
                        {"method": method, "resource_type": resource_type, "url": url},
                    )
                    route.abort("blockedbyclient")
                    return

            self.contract.record_write()
            self.audit.record(
                "route_write_oob",
                "approved",
                {
                    "method": method,
                    "resource_type": resource_type,
                    "url": url,
                    "write_count": self.contract.write_count,
                },
            )

        route.continue_()

    def _check_contract(self, action: str) -> dict[str, Any] | None:
        violation = self.contract.check_action(action)
        if violation:
            self.audit.record(action, "contract_denied", {"reason": violation})
            return {"ok": False, "code": 4, "error": violation}
        return None

    def _op_goto(self, url: str) -> dict[str, Any]:
        err = self._check_contract("navigate")
        if err:
            return err
        if self.contract.domains and not is_domain_allowed(url, self.contract.domains):
            msg = f"BLOCKED_DOMAIN: '{url}' is outside allowed domains ({', '.join(self.contract.domains)})."
            self.audit.record("goto", "blocked_domain", {"url": url})
            return {"ok": False, "code": 2, "error": msg}

        self.refs.clear()
        self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
        self.page.wait_for_timeout(450)
        self.recorded_steps.append(
            {
                "action": "goto",
                "url": url,
                "expected_host": (urlparse(self.page.url).hostname or "").lower(),
            }
        )
        self.audit.record("goto", "ok", {"url": self.page.url})
        return {
            "ok": True,
            "url": self.page.url,
            "title": redact_text(self.page.title(), self.policy),
        }

    def _op_snapshot(self) -> dict[str, Any]:
        err = self._check_contract("read")
        if err:
            return err

        self.refs.clear()
        url = self.page.url
        total_pw = 0
        total_hidden = 0
        total_truncated = 0
        lines: list[str] = []
        ref_counter = 1

        for frame_idx, frame in enumerate(self.page.frames):
            try:
                raw = frame.evaluate(SNAPSHOT_JS)
            except Exception:
                continue
            total_pw += int(raw.get("password_fields", 0))
            total_hidden += int(raw.get("hidden_skipped", 0))
            total_truncated += int(raw.get("truncated", 0))
            frame_url = raw.get("url", url)

            for el in raw.get("elements", []):
                ref = f"@e{ref_counter}"
                ref_counter += 1
                el_entry = {**el, "ref": ref, "frame_idx": frame_idx, "frame_url": frame_url}
                self.refs[ref] = el_entry
                label = el["text"] or el["aria_label"] or el["title"] or "(unlabeled)"
                self.taint.observe(label, frame_url, self.policy)
                label = redact_text(label, self.policy)
                kind = f"{el['tag']}[{el['type']}]" if el["type"] else el["role"]
                prefix = f"[frame#{frame_idx}] " if frame_idx > 0 else ""
                lines.append(f"[{ref}] {prefix}{kind}: {label}")

        page_text = ""
        try:
            page_text = self.page.evaluate(VISIBLE_TEXT_JS)[:4000]
        except Exception:
            pass

        is_auth_page = is_login_url(url, self.policy) or (
            total_pw > 0 and (len(lines) <= 12 or is_login_text(page_text, self.policy))
        )
        if is_auth_page:
            self.refs.clear()
            self.audit.record(
                "snapshot", "login_required", {"url": url, "password_fields": total_pw}
            )
            return {
                "ok": False,
                "code": 3,
                "login_required": True,
                "url": url,
                "password_fields": total_pw,
                "message": (
                    f"LOGIN_REQUIRED: Detected authentication flow or {total_pw} password field(s) at {url}. "
                    "Pause and ask the user to log in manually in the visible browser window, then re-run 'snapshot'."
                ),
            }

        notes: list[str] = []
        if total_pw > 0:
            notes.append(f"[SECURITY_NOTE: {total_pw} password input(s) stripped from interactive refs]")
        if total_truncated > 0:
            notes.append(f"[NOTE: {total_truncated} extra element(s) omitted beyond cap]")

        joined = "\n".join(notes + lines)
        warnings = detect_prompt_injection(joined, self.policy)
        framed = wrap_untrusted_content(joined, url, warnings=warnings)
        self.audit.record(
            "snapshot",
            "ok",
            {
                "url": url,
                "element_count": len(lines),
                "hidden_skipped": total_hidden,
                "password_stripped": total_pw,
                "injection_warnings": len(warnings),
            },
        )
        return {
            "ok": True,
            "url": url,
            "title": redact_text(self.page.title(), self.policy),
            "framed_snapshot": framed,
            "injection_warnings": warnings,
        }

    def _locate_ref(self, el: dict[str, Any]) -> Any:
        frame_idx = int(el.get("frame_idx", 0))
        frames = self.page.frames
        target_frame = frames[frame_idx] if frame_idx < len(frames) else self.page.main_frame
        selector = el.get("selector", "")
        if not selector:
            raise RuntimeError(
                f"Element {el.get('ref')} is inside a closed/unaddressed Shadow DOM and cannot be clicked safely."
            )
        return target_frame.locator(selector).first

    def _op_click(self, ref: str) -> dict[str, Any]:
        err = self._check_contract("click")
        if err:
            return err
        el = self.refs.get(ref)
        if not el:
            return {"ok": False, "code": 1, "error": f"Unknown or stale ref '{ref}'. Run 'snapshot' first."}

        locator = self._locate_ref(el)
        return self._click_locator(
            locator=locator,
            selector=el.get("selector", ""),
            snap_text=el.get("text", ""),
            snap_aria=el.get("aria_label", ""),
            snap_title=el.get("title", ""),
            ref_label=ref,
        )

    def _click_locator(
        self,
        locator: Any,
        selector: str,
        snap_text: str,
        snap_aria: str,
        snap_title: str,
        ref_label: str,
    ) -> dict[str, Any]:
        # TOCTOU defense: re-read live attributes right before clicking
        live_meta = locator.evaluate(LIVE_ELEMENT_META_JS, timeout=5000)
        if live_meta.get("type") == "password":
            return {"ok": False, "code": 3, "error": "BLOCKED_PASSWORD_FIELD: Cannot click password input."}

        kw_snap = match_high_risk_keyword(snap_text, snap_aria, snap_title, self.policy)
        kw_live = match_high_risk_keyword(
            live_meta.get("text", ""),
            live_meta.get("aria_label", ""),
            live_meta.get("title", ""),
            self.policy,
        )
        matched_kw = kw_live or kw_snap

        if matched_kw:
            label = redact_text(
                live_meta.get("text")
                or live_meta.get("aria_label")
                or snap_text
                or snap_aria
                or ref_label,
                self.policy,
            )
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

        pre_url = self.page.url
        locator.click(timeout=10000)
        self.page.wait_for_timeout(400)
        if self.page.url != pre_url:
            self.refs.clear()

        self.recorded_steps.append(
            {
                "action": "click",
                "selector": selector,
                "label": live_meta.get("text") or snap_text or snap_aria,
                "expected_host": (urlparse(pre_url).hostname or "").lower(),
            }
        )
        self.audit.record("click", "ok", {"ref": ref_label, "url": self.page.url})
        return {
            "ok": True,
            "url": self.page.url,
            "title": redact_text(self.page.title(), self.policy),
        }

    def _op_fill(self, ref: str, value: str) -> dict[str, Any]:
        err = self._check_contract("fill")
        if err:
            return err
        el = self.refs.get(ref)
        if not el:
            return {"ok": False, "code": 1, "error": f"Unknown or stale ref '{ref}'. Run 'snapshot' first."}
        locator = self._locate_ref(el)
        return self._fill_locator(locator, el.get("selector", ""), el.get("tag", ""), el.get("type", ""), value, ref)

    def _fill_locator(
        self,
        locator: Any,
        selector: str,
        tag: str,
        el_type: str,
        value: str,
        ref_label: str,
    ) -> dict[str, Any]:
        if tag == "input" and el_type == "password":
            self.audit.record("fill", "blocked_password", {"ref": ref_label, "url": self.page.url})
            return {"ok": False, "code": 3, "error": "BLOCKED_PASSWORD_FIELD: Cannot fill password inputs."}

        input_type = locator.evaluate("node => (node.type || '').toLowerCase()", timeout=5000)
        if input_type == "password":
            self.audit.record("fill", "blocked_password_dom", {"ref": ref_label, "url": self.page.url})
            return {"ok": False, "code": 3, "error": "BLOCKED_PASSWORD_FIELD: Live DOM check detected password input."}

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
        self.recorded_steps.append(
            {
                "action": "fill",
                "selector": selector,
                "value": value,
                "expected_host": (urlparse(self.page.url).hostname or "").lower(),
            }
        )
        self.audit.record("fill", "ok", {"ref": ref_label, "url": self.page.url})
        return {"ok": True, "ref": ref_label}

    def _op_text(self, max_chars: int = 12000) -> dict[str, Any]:
        err = self._check_contract("read")
        if err:
            return err

        chunks: list[str] = []
        for frame in self.page.frames:
            try:
                part = frame.evaluate(VISIBLE_TEXT_JS)
                if part:
                    chunks.append(part)
            except Exception:
                continue

        raw_text = "\n".join(chunks)[:max_chars]
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

    def _op_save_recipe(self, path: str, redact_inputs: bool = True) -> dict[str, Any]:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        sanitized_steps: list[dict[str, Any]] = []
        param_idx = 1
        for step in self.recorded_steps:
            item = dict(step)
            if item.get("action") == "fill":
                val = str(item.get("value", ""))
                is_sensitive = redact_inputs or bool(
                    self.taint.check_egress(val, "https://other-origin.invalid")
                )
                if is_sensitive:
                    item["value"] = f"{{{{PARAM_{param_idx}}}}}"
                    param_idx += 1
            sanitized_steps.append(item)

        payload = {"task": self.contract.task, "steps": sanitized_steps}
        out.write_text(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), encoding="utf-8")
        self.audit.record("save_recipe", "ok", {"path": str(out), "steps": len(sanitized_steps)})
        return {"ok": True, "path": str(out), "steps": len(sanitized_steps)}

    def _op_replay(self, path: str, variables: dict[str, str] | None = None) -> dict[str, Any]:
        recipe_path = Path(path)
        if not recipe_path.exists():
            return {"ok": False, "code": 1, "error": f"Recipe not found: {path}"}
        data = yaml.safe_load(recipe_path.read_text(encoding="utf-8")) or {}
        steps = data.get("steps", [])
        vars_map = variables or {}
        executed = 0

        for idx, step in enumerate(steps, start=1):
            action = step.get("action")
            expected_host = (step.get("expected_host") or "").lower()
            if action in {"fill", "click"} and expected_host:
                current_host = (urlparse(self.page.url).hostname or "").lower()
                if current_host != expected_host:
                    return {
                        "ok": False,
                        "code": 2,
                        "error": f"REPLAY_HOST_MISMATCH at step #{idx}: expected '{expected_host}', got '{current_host}'.",
                    }

            if action == "goto":
                res = self._op_goto(step["url"])
            elif action == "fill":
                err = self._check_contract("fill")
                if err:
                    return err
                val = str(step.get("value", ""))
                if val.startswith("{{") and val.endswith("}}"):
                    key = val[2:-2].strip()
                    if key not in vars_map:
                        return {"ok": False, "code": 1, "error": f"Missing replay variable '{key}'."}
                    val = vars_map[key]
                locator = self.page.locator(step["selector"]).first
                res = self._fill_locator(locator, step["selector"], "", "", val, f"recipe#{idx}")
            elif action == "click":
                err = self._check_contract("click")
                if err:
                    return err
                locator = self.page.locator(step["selector"]).first
                res = self._click_locator(
                    locator, step["selector"], step.get("label", ""), "", "", f"recipe#{idx}"
                )
            else:
                return {"ok": False, "code": 1, "error": f"Unknown recipe action '{action}'."}

            if not res.get("ok"):
                return res
            executed += 1

        self.audit.record("replay", "ok", {"path": path, "executed": executed})
        return {"ok": True, "executed": executed, "url": self.page.url}


def _build_contract_from_args(args: argparse.Namespace) -> TaskContract:
    contract = TaskContract.from_yaml(Path(args.contract)) if args.contract else TaskContract()

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
        contract.confirm_writes_mode = "none"
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

            if self.path == "/goto":
                res = controller.invoke("goto", payload["url"])
            elif self.path == "/snapshot":
                res = controller.invoke("snapshot")
            elif self.path == "/click":
                res = controller.invoke("click", payload["ref"])
            elif self.path == "/fill":
                res = controller.invoke("fill", payload["ref"], payload["value"])
            elif self.path == "/text":
                res = controller.invoke("text", int(payload.get("max_chars", 12000)))
            elif self.path == "/save-recipe":
                res = controller.invoke(
                    "save_recipe", payload["path"], bool(payload.get("redact_inputs", True))
                )
            elif self.path == "/replay":
                res = controller.invoke("replay", payload["path"], payload.get("variables", {}))
            elif self.path == "/stop":
                self._send(200, {"ok": True})
                threading.Thread(target=controller.request_shutdown, daemon=True).start()
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
    parser.add_argument("--read-only", action="store_true", help="Block POST/PUT/PATCH/DELETE/ping/WS.")
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

    p_save = sub.add_parser("save-recipe", help="Save recorded steps as a parameterized replay recipe.")
    p_save.add_argument("path")
    p_save.add_argument("--profile", default="default")
    p_save.add_argument("--keep-values", action="store_true", help="Keep non-tainted fill values verbatim.")

    p_replay = sub.add_parser("replay", help="Replay a saved recipe without LLM round-trips.")
    p_replay.add_argument("path")
    p_replay.add_argument("--profile", default="default")
    p_replay.add_argument("--var", action="append", default=[], help="Variable substitution KEY=VALUE.")

    p_verify = sub.add_parser("verify-log", help="Verify hash-chain or HMAC-SHA256 audit log.")
    p_verify.add_argument("--profile", default="default")
    p_verify.add_argument("--key-file", default="", help="Path to HMAC key file.")
    p_verify.add_argument("--require-hmac", action="store_true", help="Fail if log is unkeyed.")

    p_stop = sub.add_parser("stop", help="Close browser session (and wipe profile if --ephemeral).")
    p_stop.add_argument("--profile", default="default")

    args = parser.parse_args()

    if args.command == "_serve":
        return run_daemon(args)
    if args.command == "start":
        return cmd_start(args)
    if args.command == "verify-log":
        key = resolve_hmac_key(Path(args.key_file) if args.key_file else None)
        ok, _, msg = verify_audit_log(
            audit_log_for(args.profile), hmac_key=key, require_hmac=args.require_hmac
        )
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
            res = rpc_call(
                args.profile,
                "/save-recipe",
                {"path": args.path, "redact_inputs": not args.keep_values},
            )
        elif args.command == "replay":
            vars_dict = {}
            for kv in args.var:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    vars_dict[k] = v
            res = rpc_call(args.profile, "/replay", {"path": args.path, "variables": vars_dict})
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
