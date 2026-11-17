"""Lightweight stdio MCP (Model Context Protocol) server for PassGuard Web Agent.

Exposes PassGuard's isolated browser operations over JSON-RPC 2.0 (stdin/stdout)
so MCP clients (Claude Desktop, Cursor, Antigravity) can invoke PassGuard without
shell access—enabling true privilege separation when deployed under a dedicated
service user or sandbox.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import safe_browser  # noqa: E402

TOOLS: list[dict[str, Any]] = [
    {
        "name": "passguard_start",
        "description": "Start an isolated, contract-scoped PassGuard browser session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "default": "default"},
                "allow_domains": {"type": "string", "default": ""},
                "read_only": {"type": "boolean", "default": False},
                "ephemeral": {"type": "boolean", "default": False},
                "ttl": {"type": "integer"},
                "contract": {"type": "string", "default": ""},
            },
        },
    },
    {
        "name": "passguard_goto",
        "description": "Navigate to an allowlisted URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "default": "default"},
                "url": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "passguard_snapshot",
        "description": "Extract visible interactive DOM refs (@e1, @e2...) wrapped as untrusted content.",
        "inputSchema": {
            "type": "object",
            "properties": {"profile": {"type": "string", "default": "default"}},
        },
    },
    {
        "name": "passguard_click",
        "description": "Click an interactive ref; high-risk actions trigger an OOB native dialog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "default": "default"},
                "ref": {"type": "string"},
            },
            "required": ["ref"],
        },
    },
    {
        "name": "passguard_fill",
        "description": "Fill a non-password input by ref (blocked for passwords & cross-site taint).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "default": "default"},
                "ref": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["ref", "value"],
        },
    },
    {
        "name": "passguard_text",
        "description": "Extract redacted, injection-checked visible page text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "default": "default"},
                "max_chars": {"type": "integer", "default": 12000},
            },
        },
    },
    {
        "name": "passguard_stop",
        "description": "Close the browser session (and wipe profile if ephemeral).",
        "inputSchema": {
            "type": "object",
            "properties": {"profile": {"type": "string", "default": "default"}},
        },
    },
]


def _call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    profile = str(args.get("profile", "default"))
    if name == "passguard_start":
        import argparse

        ns = argparse.Namespace(
            profile=profile,
            contract=args.get("contract", ""),
            allow_domains=args.get("allow_domains", ""),
            read_only=bool(args.get("read_only", False)),
            ephemeral=bool(args.get("ephemeral", False)),
            ttl=args.get("ttl"),
            no_confirm_writes=False,
            headless=False,
            rules=str(safe_browser.DEFAULT_RULES_PATH),
        )
        rc = safe_browser.cmd_start(ns)
        return {"ok": rc == 0, "profile": profile}
    if name == "passguard_goto":
        return safe_browser.rpc_call(profile, "/goto", {"url": args["url"]})
    if name == "passguard_snapshot":
        return safe_browser.rpc_call(profile, "/snapshot")
    if name == "passguard_click":
        return safe_browser.rpc_call(profile, "/click", {"ref": args["ref"]})
    if name == "passguard_fill":
        return safe_browser.rpc_call(profile, "/fill", {"ref": args["ref"], "value": args["value"]})
    if name == "passguard_text":
        return safe_browser.rpc_call(
            profile, "/text", {"max_chars": int(args.get("max_chars", 12000))}
        )
    if name == "passguard_stop":
        return safe_browser.rpc_call(profile, "/stop")
    raise ValueError(f"Unknown tool: {name}")


def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "passguard-web-agent", "version": "0.2.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}
        try:
            res = _call_tool(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}],
                    "isError": not bool(res.get("ok", True)),
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"ERROR: {exc}"}],
                    "isError": True,
                },
            }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
