"""Tkinter GUI editor for the ``nm-secrets`` Key Vault secret.

Workflow:
  * On launch: az-CLI auth -> fetch ``ansible-vault-passwd`` and ``nm-secrets``
    from the SONiC Key Vault, decrypt in-memory, pretty-print as JSON.
  * Edit in a single window (text widget).
  * On Save: validate JSON, show diff, confirm, re-encrypt, upload as a new
    Key Vault version.  Old versions are retained automatically by KV.
  * On Quit: confirm if unsaved.
  * Idle for ``IDLE_TIMEOUT_SECS`` -> auto-quit and zero out buffers.

Plaintext secrets never touch disk.
"""

from __future__ import annotations

import difflib
import json
import os
import subprocess
import sys
import threading
import tkinter as tk
import traceback
from tkinter import messagebox, ttk

# AzureCliCredential shells out to ``az`` (a .cmd batch file). When this
# process is launched as pythonw.exe (no console), each spawned cmd.exe
# allocates a fresh console window -> visible flash. Force every
# subprocess we spawn to use CREATE_NO_WINDOW so nothing flashes.
if hasattr(subprocess, "CREATE_NO_WINDOW"):
    _CNW = subprocess.CREATE_NO_WINDOW

    class _NoWindowPopen(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CNW
            super().__init__(*args, **kwargs)

    subprocess.Popen = _NoWindowPopen  # type: ignore[misc, assignment]

try:
    from azure.core.exceptions import HttpResponseError
    from azure.identity import AzureCliCredential
    from azure.keyvault.secrets import SecretClient
    import vault as _vault
except ImportError as _imp_err:
    _root = tk.Tk()
    _root.withdraw()
    messagebox.showerror(
        "Missing dependencies",
        "Required Python packages are not available.\n\n"
        f"Import error:\n  {_imp_err}\n\n"  # noqa: E231
        "Run launch.cmd from this folder to bootstrap the virtualenv.")
    sys.exit(1)

VAULT_URL = "https://sonic.vault.azure.net/"
SECRET_NAME = "nm-secrets"
PASSWORD_NAME = "ansible-vault-passwd"
IDLE_TIMEOUT_SECS = 10 * 60
HEARTBEAT_MS = 1000


def _zero(s):
    """Best-effort wipe of a Python str/bytes (CPython only)."""
    try:
        if isinstance(s, (bytes, bytearray)):
            for i in range(len(s)):
                s[i] = 0  # type: ignore[index]
    except Exception:
        pass


class EditorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SONiC - secrets.json editor")
        self.root.geometry("1100x700")

        self._client: SecretClient | None = None
        self._password: str | None = None
        self._loaded_version: str | None = None
        self._loaded_text: str = ""
        self._idle_deadline: float = 0.0
        self._editable: bool = False

        self._build_ui()
        self._reset_idle()
        self.root.after(HEARTBEAT_MS, self._tick)
        self.root.protocol("WM_DELETE_WINDOW", self._on_quit)

        # Defer initial load so the window paints first.
        self.root.after(100, self._load)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root, padding=(6, 4))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self.reload_btn = ttk.Button(toolbar, text="Reload", command=self._load)
        self.reload_btn.pack(side=tk.LEFT)

        self.edit_btn = ttk.Button(toolbar, text="Edit",
                                   command=self._toggle_editable)
        self.edit_btn.pack(side=tk.LEFT, padx=(6, 0))

        self.save_btn = ttk.Button(toolbar, text="Save \u2192 Key Vault",
                                   command=self._save, state="disabled")
        self.save_btn.pack(side=tk.LEFT, padx=(6, 0))

        ttk.Button(toolbar, text="Quit",
                   command=self._on_quit).pack(side=tk.LEFT, padx=(6, 0))

        self.version_var = tk.StringVar(value="version: \u2014")
        ttk.Label(toolbar, textvariable=self.version_var,
                  anchor="e").pack(side=tk.RIGHT, padx=(12, 4))

        body = ttk.Frame(self.root)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.text = tk.Text(body, wrap="none", undo=True,
                            font=("Cascadia Mono", 10), tabs=("2c",),
                            background="#f3f3f3")
        ysb = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        xsb = ttk.Scrollbar(body, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.text.bind("<<Modified>>", self._on_text_modified)

        self.status_var = tk.StringVar(value="ready")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w",
                  padding=(6, 2), relief="sunken").pack(side=tk.BOTTOM, fill=tk.X)

        self.root.bind_all("<Control-s>", self._on_ctrl_s)
        self.root.bind_all("<Control-e>", lambda _e: self._toggle_editable())
        for evt in ("<Key>", "<Button-1>", "<MouseWheel>"):
            self.root.bind_all(evt, lambda _e: self._reset_idle(), add="+")

    # ------------------------------------------------------------ helpers
    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)
        self.root.update_idletasks()

    def _reset_idle(self) -> None:
        import time
        self._idle_deadline = time.monotonic() + IDLE_TIMEOUT_SECS

    def _tick(self) -> None:
        import time
        remain = int(self._idle_deadline - time.monotonic())
        if remain <= 0:
            self._set_status("idle timeout reached, quitting")
            self.root.after(500, self._force_quit)
            return
        self.root.after(HEARTBEAT_MS, self._tick)

    def _client_or_init(self) -> SecretClient:
        if self._client is None:
            self._client = SecretClient(VAULT_URL, AzureCliCredential())
        return self._client

    def _current_text(self) -> str:
        return self.text.get("1.0", "end-1c")

    def _is_dirty(self) -> bool:
        return self._current_text() != self._loaded_text

    def _on_text_modified(self, _e=None) -> None:
        # Tk only fires <<Modified>> once until the flag is reset.
        self.text.edit_modified(False)
        self._refresh_title()

    def _refresh_title(self) -> None:
        if self._loaded_version is None:
            self.root.title("SONiC - secrets.json editor")
            return
        mode = "editing" if self._editable else "read-only"
        dirty = "*" if self._is_dirty() else ""
        self.root.title(
            f"SONiC - secrets.json editor  [{mode}]{dirty}")  # noqa: E231

    # ---------------------------------------------------- editable mode
    def _set_editable(self, editable: bool) -> None:
        self._editable = editable
        if editable:
            self.text.config(state="normal", background="#ffffff")
            self.edit_btn.config(text="Lock")
            self.save_btn.config(state="normal")
            self._set_status("editing \u2014 click Lock to return to read-only")
        else:
            self.text.config(state="disabled", background="#f3f3f3")
            self.edit_btn.config(text="Edit")
            self.save_btn.config(state="disabled")
            # status updated by callers when relevant
        self._refresh_title()

    def _toggle_editable(self) -> None:
        if self._loaded_version is None:
            messagebox.showwarning("Not loaded", "Nothing loaded yet.")
            return
        if not self._editable:
            if not messagebox.askyesno(
                    "Enable editing?",
                    "Enable editing? Your changes are kept locally until you "
                    "click Save \u2192 Key Vault."):
                return
            self._set_editable(True)
            return
        # Already editing -> attempt to lock.
        if self._is_dirty():
            choice = messagebox.askyesnocancel(
                "Discard unsaved edits?",
                "There are unsaved edits.\n\n"
                "Yes = discard them and return to read-only.\n"
                "No  = keep editing.\n"
                "Cancel = same as No.")
            if not choice:
                return
            # Discard: revert to the loaded text.
            self.text.config(state="normal")
            self.text.delete("1.0", "end")
            self.text.insert("1.0", self._loaded_text)
            self.text.edit_reset()
        self._set_editable(False)
        self._set_status("read-only")

    def _on_ctrl_s(self, _event=None):
        if not self._editable:
            self._set_status("read-only \u2014 click Edit to modify")
            return "break"
        self._save()
        return "break"

    # -------------------------------------------------------------- load
    def _load(self) -> None:
        if self._is_dirty() and not messagebox.askyesno(
                "Discard changes?",
                "There are unsaved changes. Reload and discard them?"):
            return
        self._set_status("fetching from Key Vault...")
        self.root.config(cursor="watch")
        threading.Thread(target=self._load_worker, daemon=True).start()

    def _load_worker(self) -> None:
        try:
            client = self._client_or_init()
            pw = client.get_secret(PASSWORD_NAME).value
            sec = client.get_secret(SECRET_NAME)
            ciphertext = sec.value
            version = sec.properties.version
            plaintext_bytes = _vault.decrypt(ciphertext, pw)
            obj = json.loads(plaintext_bytes.decode("utf-8"))
            pretty = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
            self.root.after(0, self._load_done, pw, version, pretty, len(ciphertext))
        except Exception:
            err = traceback.format_exc()
            self.root.after(0, self._load_failed, err)

    def _load_done(self, pw: str, version: str, pretty: str, n_cipher: int) -> None:
        self._password = pw
        self._loaded_version = version
        self._loaded_text = pretty
        # Insert needs the widget enabled; lock right after.
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", pretty)
        self.text.edit_reset()
        self.version_var.set(f"version: {version}")
        self._set_editable(False)
        self._set_status(
            f"loaded {len(pretty)} bytes plaintext "
            f"({n_cipher} bytes ciphertext) \u2014 read-only")
        self.root.config(cursor="")
        self._reset_idle()

    def _load_failed(self, err: str) -> None:
        self.root.config(cursor="")
        self._set_status("load failed")
        messagebox.showerror("Load failed", err)

    # -------------------------------------------------------------- save
    def _save(self) -> None:
        if self._password is None or self._loaded_version is None:
            messagebox.showwarning("Not loaded", "Nothing loaded yet.")
            return
        if not self._editable:
            self._set_status("read-only \u2014 click Edit to modify")
            return
        new_text = self._current_text()
        try:
            obj = json.loads(new_text)
        except json.JSONDecodeError as e:
            self._set_status(f"invalid JSON: line {e.lineno}, col {e.colno}")
            messagebox.showerror(
                "Invalid JSON \u2014 not saved",
                f"The document is not valid JSON, so nothing was uploaded.\n\n"
                f"{e.msg} (line {e.lineno}, column {e.colno})")
            try:
                self.text.mark_set("insert", f"{e.lineno}.{max(e.colno - 1, 0)}")
                self.text.see("insert")
                self.text.focus_set()
            except Exception:
                pass
            return
        # Re-canonicalise so trivial whitespace tweaks don't push a new version.
        canonical = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
        if canonical == self._loaded_text:
            messagebox.showinfo("No changes",
                                "Document is identical to the loaded version.")
            return
        if not self._confirm_diff(self._loaded_text, canonical):
            return
        self._set_status("uploading new version...")
        self.root.config(cursor="watch")
        threading.Thread(
            target=self._save_worker, args=(canonical,), daemon=True).start()

    def _confirm_diff(self, old: str, new: str) -> bool:
        diff = "".join(difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile=f"loaded (version {self._loaded_version})",
            tofile="to upload", n=3))
        if not diff:
            return False
        win = tk.Toplevel(self.root)
        win.title("Confirm save")
        win.geometry("800x500")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Review changes before uploading to Key Vault:",
                  padding=(8, 6)).pack(side=tk.TOP, fill=tk.X)
        body = ttk.Frame(win)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        txt = tk.Text(body, wrap="none", font=("Cascadia Mono", 10))
        ysb = ttk.Scrollbar(body, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=ysb.set)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.insert("1.0", diff)
        txt.tag_configure("add", foreground="#0a0")
        txt.tag_configure("del", foreground="#a00")
        for i, line in enumerate(diff.splitlines(), start=1):
            tag = "add" if line.startswith("+") and not line.startswith("+++") \
                else "del" if line.startswith("-") and not line.startswith("---") \
                else None
            if tag:
                txt.tag_add(tag, f"{i}.0", f"{i}.end")
        txt.configure(state="disabled")
        result = {"ok": False}
        btns = ttk.Frame(win, padding=(8, 6))
        btns.pack(side=tk.BOTTOM, fill=tk.X)

        def _ok() -> None:
            result["ok"] = True
            win.destroy()

        ttk.Button(btns, text="Cancel",
                   command=win.destroy).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Upload to Key Vault",
                   command=_ok).pack(side=tk.RIGHT, padx=(0, 6))
        self.root.wait_window(win)
        return result["ok"]

    def _save_worker(self, canonical: str) -> None:
        try:
            client = self._client_or_init()
            # Optimistic concurrency: refuse if KV head moved.
            head = client.get_secret(SECRET_NAME).properties.version
            if head != self._loaded_version:
                raise RuntimeError(
                    f"Key Vault version moved from {self._loaded_version} "
                    f"to {head}. Reload before saving.")
            ciphertext = _vault.encrypt(canonical.encode("utf-8"), self._password)
            new = client.set_secret(SECRET_NAME, ciphertext)
            self.root.after(0, self._save_done, canonical, new.properties.version)
        except Exception:
            err = traceback.format_exc()
            self.root.after(0, self._save_failed, err)

    def _save_done(self, canonical: str, version: str) -> None:
        self._loaded_text = canonical
        self._loaded_version = version
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", canonical)
        self.text.edit_reset()
        self.version_var.set(f"version: {version}")
        self._set_editable(False)
        self._set_status(f"saved new version {version} \u2014 read-only")
        self.root.config(cursor="")
        messagebox.showinfo(
            "Saved",
            f"Uploaded new version {version}.\n"
            "Previous versions remain in Key Vault history.")

    def _save_failed(self, err: str) -> None:
        self.root.config(cursor="")
        self._set_status("save failed")
        messagebox.showerror("Save failed", err)

    # -------------------------------------------------------------- quit
    def _on_quit(self) -> None:
        if self._is_dirty() and not messagebox.askyesno(
                "Quit?", "There are unsaved changes. Quit anyway?"):
            return
        self._force_quit()

    def _force_quit(self) -> None:
        self._password = None
        self._loaded_text = ""
        try:
            self.text.delete("1.0", "end")
        except Exception:
            pass
        self.root.destroy()


def _ensure_az_login() -> None:
    """Verify ``az`` is logged in; otherwise show a helpful error and exit."""
    try:
        SecretClient(VAULT_URL, AzureCliCredential()).get_secret(PASSWORD_NAME)
    except HttpResponseError as e:
        messagebox.showerror(
            "Key Vault access failed",
            f"{e.message}\n\nRun `az login` with a Microsoft corp account "  # noqa: E231
            "that has access to the SONiC Key Vault.")
        sys.exit(1)
    except Exception as e:
        messagebox.showerror(
            "Azure CLI not ready",
            f"{e}\n\nRun `az login` with a Microsoft corp account "  # noqa: E231
            "that has access to the SONiC Key Vault.")
        sys.exit(1)


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    root = tk.Tk()
    # Lazy auth check: probe before showing the editor so errors are obvious.
    root.withdraw()
    _ensure_az_login()
    root.deiconify()
    EditorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
