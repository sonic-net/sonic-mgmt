#!/usr/bin/env python3
"""Entrypoint for conditional-mark issue close guard workflow script."""

from skip_issue_expiry_impl.issue_close_guard_cli import run


if __name__ == "__main__":
    raise SystemExit(run())
