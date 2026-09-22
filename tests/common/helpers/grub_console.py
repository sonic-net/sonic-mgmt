import re
import threading
import time
from concurrent.futures import Future


GRUB_MENU_READY = "The highlighted entry will be executed"
KEY_UP = "\x1b[A"
KEY_DOWN = "\x1b[B"
ENTER = "\n"


def _wait_for_occurrence(console, pattern, occurrence, timeout):
    if occurrence < 1:
        raise ValueError("Pattern occurrence must be at least 1")

    for unused in range(occurrence):
        console.read_until_pattern(pattern=pattern, read_timeout=timeout)


def select_grub_entry(
    console,
    current_index,
    target_index,
    menu_pattern=GRUB_MENU_READY,
    menu_occurrence=1,
    wait_pattern=None,
    wait_pattern_occurrence=1,
    acknowledge_wait_pattern=False,
    timeout=180,
):
    """Select a zero-based GRUB entry through an existing console."""
    if wait_pattern:
        _wait_for_occurrence(
            console,
            wait_pattern,
            wait_pattern_occurrence,
            timeout,
        )
        if acknowledge_wait_pattern:
            time.sleep(1)
            console.write_channel(ENTER)

    _wait_for_occurrence(
        console,
        re.escape(menu_pattern),
        menu_occurrence,
        timeout,
    )
    time.sleep(0.5)

    offset = target_index - current_index
    key = KEY_DOWN if offset > 0 else KEY_UP
    for unused in range(abs(offset)):
        console.write_channel(key)
    console.write_channel(ENTER)
    time.sleep(1)


def start_grub_entry_selection(console, *args, **kwargs):
    """Select a GRUB entry asynchronously and return its Future."""
    future = Future()

    def run():
        try:
            select_grub_entry(console, *args, **kwargs)
            future.set_result(None)
        except Exception as error:
            future.set_exception(error)

    threading.Thread(target=run, daemon=True).start()
    return future
