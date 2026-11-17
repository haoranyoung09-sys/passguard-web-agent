"""Out-of-band (OOB) native human confirmation prompt.

Runs outside the browser DOM and outside the LLM CLI channel so neither
malicious website JavaScript nor the AI agent can forge or bypass approval.
Fails closed (returns False) if no interactive GUI display is available.
"""

from __future__ import annotations

import threading
from typing import Callable

ConfirmCallback = Callable[[str, str], bool]


def native_oob_confirm(title: str, detail: str) -> bool:
    """Show a native always-on-top OS confirmation dialog via tkinter.

    Returns True only if a human explicitly clicks Approve/Yes.
    Fails closed (False) on headless systems or errors.
    """
    result = {"approved": False}
    done = threading.Event()

    def _run_dialog() -> None:
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            root.lift()
            root.focus_force()
            result["approved"] = bool(
                messagebox.askyesno(
                    title=f"PassGuard Security Gate — {title}",
                    message=detail,
                    default=messagebox.NO,
                    parent=root,
                )
            )
            root.destroy()
        except Exception:
            result["approved"] = False
        finally:
            done.set()

    # tkinter must run its own loop cleanly; running in a dedicated thread with
    # a single Tk instance avoids interfering with Playwright's thread.
    thread = threading.Thread(target=_run_dialog, daemon=True)
    thread.start()
    done.wait(timeout=120)
    return result["approved"]
