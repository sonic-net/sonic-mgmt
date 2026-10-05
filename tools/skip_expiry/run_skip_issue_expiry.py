#!/usr/bin/env python3
"""Entrypoint for the skip-expiry workflow script."""

from skip_issue_expiry_impl.cli import run


if __name__ == "__main__":
    raise SystemExit(run())
