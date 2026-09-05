#!/usr/bin/env python3

import argparse
import os
import shlex
import sys
import time

import pexpect


GRUB_MENU_READY = "The highlighted entry will be executed"
KEY_UP = "\x1b[A"
KEY_DOWN = "\x1b[B"
GRUB_CONSOLE_SCRIPT_PATH = "/tmp/sonic_grub_console.py"


def start_grub_entry_selection(
    vmhost,
    serial_port,
    current_index,
    target_index,
    menu_pattern=GRUB_MENU_READY,
    menu_occurrence=1,
    wait_pattern=None,
    wait_pattern_occurrence=1,
    acknowledge_wait_pattern=False,
    timeout=180,
    log_path="/tmp/sonic_grub_console.log",
):
    """Start a VM-host process that selects a GRUB entry through serial."""
    vmhost.copy(src=os.path.abspath(__file__), dest=GRUB_CONSOLE_SCRIPT_PATH)
    wait_option = (
        ""
        if wait_pattern is None
        else "--wait-pattern {} --wait-pattern-occurrence {} ".format(
            shlex.quote(wait_pattern),
            int(wait_pattern_occurrence),
        )
    )
    acknowledge_option = (
        "--acknowledge-wait-pattern " if acknowledge_wait_pattern else ""
    )
    command = (
        "rm -f {log}; "
        "nohup timeout {process_timeout} python3 {script} "
        "--port {port} --current-index {current_index} "
        "--target-index {target_index} "
        "--menu-pattern {menu_pattern} --menu-occurrence {menu_occurrence} "
        "{wait_option}{acknowledge_option}"
        "--timeout {timeout} "
        "> {log} 2>&1 < /dev/null & echo $!"
    ).format(
        log=shlex.quote(log_path),
        process_timeout=int(timeout) + 10,
        script=shlex.quote(GRUB_CONSOLE_SCRIPT_PATH),
        port=int(serial_port),
        current_index=int(current_index),
        target_index=int(target_index),
        menu_pattern=shlex.quote(menu_pattern),
        menu_occurrence=int(menu_occurrence),
        wait_option=wait_option,
        acknowledge_option=acknowledge_option,
        timeout=int(timeout),
    )
    result = vmhost.shell(command)
    process_id = result["stdout"].strip()
    if not process_id.isdigit():
        raise RuntimeError(
            "Failed to start GRUB console selection: {}".format(result)
        )
    return process_id, log_path


def _connect(port, timeout):
    last_error = None
    for attempt in range(10):
        try:
            return pexpect.spawn(
                "telnet",
                ["127.0.0.1", str(port)],
                timeout=timeout,
                logfile=sys.stdout,
                encoding="utf-8",
                codec_errors="replace",
            )
        except OSError as error:
            last_error = error
            if attempt == 9:
                break
            time.sleep(1)
    raise RuntimeError(
        "Failed to connect to the serial console: {}".format(last_error)
    )


def select_grub_entry(
    port,
    current_index,
    target_index,
    menu_pattern=GRUB_MENU_READY,
    menu_occurrence=1,
    wait_pattern=None,
    wait_pattern_occurrence=1,
    acknowledge_wait_pattern=False,
    timeout=180,
):
    """Select a zero-based entry when the requested GRUB menu appears."""
    console = _connect(port, timeout)
    try:
        if wait_pattern:
            for unused in range(wait_pattern_occurrence):
                console.expect(wait_pattern)
            if acknowledge_wait_pattern:
                time.sleep(1)
                console.sendline()
        for unused in range(menu_occurrence):
            console.expect_exact(menu_pattern)
        time.sleep(0.5)

        offset = target_index - current_index
        key = KEY_DOWN if offset > 0 else KEY_UP
        for unused in range(abs(offset)):
            console.send(key)
        console.sendline()
        time.sleep(1)
    finally:
        console.close()


def main():
    parser = argparse.ArgumentParser(
        description="Select a GRUB entry through a Telnet serial console"
    )
    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="Local Telnet serial-console port",
    )
    parser.add_argument(
        "--current-index",
        type=int,
        required=True,
        help="Initially highlighted entry index",
    )
    parser.add_argument(
        "--target-index",
        type=int,
        required=True,
        help="Entry index to select",
    )
    parser.add_argument(
        "--menu-pattern",
        default=GRUB_MENU_READY,
        help="Exact output that indicates the GRUB menu is ready",
    )
    parser.add_argument(
        "--menu-occurrence",
        type=int,
        default=1,
        help="Select the entry when this occurrence of the GRUB menu appears",
    )
    parser.add_argument(
        "--wait-pattern",
        help=(
            "Wait for this regular expression before looking for the GRUB "
            "menu"
        ),
    )
    parser.add_argument(
        "--wait-pattern-occurrence",
        type=int,
        default=1,
        help="Wait for this occurrence of the prerequisite pattern",
    )
    parser.add_argument(
        "--acknowledge-wait-pattern",
        action="store_true",
        help="Press Enter after matching the prerequisite pattern",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Console interaction timeout",
    )
    args = parser.parse_args()

    select_grub_entry(
        port=args.port,
        current_index=args.current_index,
        target_index=args.target_index,
        menu_pattern=args.menu_pattern,
        menu_occurrence=args.menu_occurrence,
        wait_pattern=args.wait_pattern,
        wait_pattern_occurrence=args.wait_pattern_occurrence,
        acknowledge_wait_pattern=args.acknowledge_wait_pattern,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
