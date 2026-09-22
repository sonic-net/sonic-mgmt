"""Unit tests for the GRUB console helper."""

from importlib import util
from pathlib import Path
import re

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "helpers"
    / "grub_console.py"
)
SPEC = util.spec_from_file_location("unit_target_grub_console", MODULE_PATH)
grub_console = util.module_from_spec(SPEC)
SPEC.loader.exec_module(grub_console)


class FakeConsole:
    """Record console reads and writes."""

    def __init__(self):
        self.reads = []
        self.writes = []

    def read_until_pattern(self, pattern, read_timeout):
        self.reads.append((pattern, read_timeout))

    def write_channel(self, data):
        self.writes.append(data)


@pytest.fixture(autouse=True)
def skip_delays(monkeypatch):
    """Avoid real delays in isolated helper tests."""
    monkeypatch.setattr(grub_console.time, "sleep", lambda unused: None)


def test_select_grub_entry_uses_console_connection():
    console = FakeConsole()

    grub_console.select_grub_entry(
        console,
        current_index=1,
        target_index=3,
        menu_occurrence=2,
        timeout=45,
    )

    assert console.reads == [
        (re.escape(grub_console.GRUB_MENU_READY), 45),
        (re.escape(grub_console.GRUB_MENU_READY), 45),
    ]
    assert console.writes == [
        grub_console.KEY_DOWN,
        grub_console.KEY_DOWN,
        grub_console.ENTER,
    ]


def test_select_grub_entry_waits_and_acknowledges_prerequisite():
    console = FakeConsole()

    grub_console.select_grub_entry(
        console,
        current_index=2,
        target_index=1,
        wait_pattern="Press Enter",
        wait_pattern_occurrence=2,
        acknowledge_wait_pattern=True,
    )

    assert console.reads[:2] == [
        ("Press Enter", 180),
        ("Press Enter", 180),
    ]
    assert console.writes == [
        grub_console.ENTER,
        grub_console.KEY_UP,
        grub_console.ENTER,
    ]


def test_start_grub_entry_selection_reports_worker_errors():
    console = FakeConsole()

    future = grub_console.start_grub_entry_selection(
        console,
        current_index=0,
        target_index=0,
        menu_occurrence=0,
    )

    with pytest.raises(ValueError, match="at least 1"):
        future.result(timeout=1)
