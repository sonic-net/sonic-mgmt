"""Stress / loaded-bandwidth tests for the SONiC console subsystem.

The test in this module pushes a large amount of data through a console
loopback path and verifies the bytes returned match what was sent. The
payload is the ASCII character ``'U'`` (``0x55`` / ``0b01010101``); the
alternating bit pattern produces the maximum number of edges per unit
time on the wire and makes single-bit errors trivial to detect by XOR.
"""

import hashlib
import logging
import os
import threading
import time
import uuid

import pexpect
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import (
    check_target_line_status,
    create_ssh_client,
    ensure_console_session_up,
    get_dut_console_lines,
    get_host_ip_and_creds,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('c0-lo')
]

# How much data to push through the line per parametrize combo. The payload
# is sized per baud rate so the test stays roughly in the same order of
# magnitude of wall-clock time (~15 min on the wire per parameter combo):
#   - 9600 baud   ->  1 MiB   (~16 min on the wire)
#   - 115200 baud -> 10 MiB   (~15 min on the wire)
TOTAL_BYTES_BY_BAUD = {
    "9600": 1 * 1024 * 1024,
    "115200": 10 * 1024 * 1024,
}

FILL_CHAR = 'U'

# Per-byte framing on the wire (8N1) used by the console line.
_BITS_PER_BYTE = 10

# Stop the test if no new bytes arrive on the receive side for this many
# seconds (independent of the projected wire time).
_NO_PROGRESS_TIMEOUT = 60.0

# Emit a "still receiving" log line at this interval while waiting for the
# end sentinel to arrive on the receive side.
_RECV_PROGRESS_LOG_INTERVAL = 30.0


def _bit_error_summary(expected, actual, max_report=10):
    """Build a human-readable description of how ``actual`` differs from
    ``expected`` (length, md5, total bit-error count, first few diffs).
    """
    lines = []
    lines.append("expected length = {} bytes, actual length = {} bytes".format(
        len(expected), len(actual)))
    lines.append("expected md5 = {}".format(hashlib.md5(expected).hexdigest()))
    lines.append("actual   md5 = {}".format(hashlib.md5(actual).hexdigest()))

    n = min(len(expected), len(actual))
    bit_errors = 0
    diff_offsets = []
    for i in range(n):
        if expected[i] != actual[i]:
            xor = expected[i] ^ actual[i]
            be = bin(xor).count("1")
            bit_errors += be
            if len(diff_offsets) < max_report:
                diff_offsets.append((i, expected[i], actual[i], be))

    lines.append("differing bytes over the first {} bytes = {}".format(n, len(diff_offsets)))
    lines.append("total bit errors over the first {} bytes = {}".format(n, bit_errors))
    if diff_offsets:
        lines.append("first {} differing bytes:".format(len(diff_offsets)))
        for offset, exp_b, got_b, be in diff_offsets:
            lines.append("  offset {:>10d}: sent 0x{:02x} got 0x{:02x} ({} bit-flip(s))".format(
                offset, exp_b, got_b, be))
    if len(expected) != len(actual):
        lines.append("note: length differs; bit-error count above is over the overlapping prefix only")
    return "\n".join(lines)


def _save_artifact(name, blob):
    """Persist ``blob`` to ``tests/logs/console/<name>`` so a CI run captures
    it as part of the standard log artifacts. Returns the absolute path.
    """
    log_dir = os.path.join("logs", "console")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception as e:
        # CWD may not be writable (e.g. running outside the tests/ dir);
        # fall back to /tmp so the forensic capture is still preserved.
        logger.warning("Cannot create %s (%s); falling back to /tmp", log_dir, e)
        log_dir = "/tmp"
    path = os.path.abspath(os.path.join(log_dir, name))
    with open(path, "wb") as f:
        f.write(blob)
    return path


@pytest.mark.parametrize("chunk_size", [128, 1024])
@pytest.mark.parametrize("baud_rate", ["9600", "115200"])
@pytest.mark.parametrize("flow_control", ["enable", "disable"])
def test_console_load(setup_c0, creds, conn_graph_facts, baud_rate, flow_control,  # noqa: F811
                      chunk_size, cleanup_modules):
    """
    Push a baud-rate-dependent amount of ``'U'`` (``0x55``) bytes through the
    lowest-numbered console line of the DUT in chunks of ``chunk_size`` bytes
    and verify the bytes returned by the loopback match what was sent. On
    mismatch the test reports length, md5, and per-bit error count plus the
    first few differing offsets, and persists the captured payload under
    ``tests/logs/console/``.
    """
    # On the c0-lo topology the DUT and the console fanout are the same host
    # (the loopback is wired on the device itself), so there is no separate
    # console_fanout to configure.
    duthost, _ = setup_c0

    lines = get_dut_console_lines(conn_graph_facts, duthost)
    pytest_assert(
        len(lines) >= 1,
        "Stress test requires at least 1 console line; got none in *_serial_links.csv")
    target_line = lines[0]
    total_bytes = TOTAL_BYTES_BY_BAUD[baud_rate]

    projected_seconds = total_bytes * _BITS_PER_BYTE / float(baud_rate)
    logger.info("[console_load] line=%s baud=%s flow_control=%s chunk_size=%s; "
                "total_bytes=%d bytes; projected one-way wire time ~%.1fs (%.2fh)",
                target_line, baud_rate, flow_control, chunk_size,
                total_bytes, projected_seconds, projected_seconds / 3600.0)

    # Capture the line's CONFIG_DB state BEFORE we mutate it so teardown can
    # restore it. core_dump_and_config_check fails the test if we leave the
    # CONSOLE_PORT|<line> entry dirty (especially flow_control drift).
    def _read_field(field, default):
        try:
            res = duthost.command(
                "sonic-db-cli CONFIG_DB hget 'CONSOLE_PORT|{}' {}".format(target_line, field),
                module_ignore_errors=True)
            val = (res.get('stdout') or '').strip()
            return val if val else default
        except Exception as e:
            logger.debug("Failed to read original %s for line %s: %s", field, target_line, e)
            return default

    orig_baud = _read_field("baud_rate", "9600")
    orig_flow_control_int = _read_field("flow_control", "0")
    orig_flow_control = "enable" if orig_flow_control_int == "1" else "disable"

    duthost.command("config console baud {} {}".format(target_line, baud_rate))
    duthost.command("config console flow_control {} {}".format(flow_control, target_line))

    pytest_assert(
        check_target_line_status(duthost, target_line, "IDLE"),
        "Target line {} is busy before stress test starts".format(target_line))

    dutip, dutuser, dutpass = get_host_ip_and_creds(duthost, creds)
    ressh_user = "{}:{}".format(dutuser, target_line)

    # Unique per-run sentinels so that ambient console output (banners, prompts,
    # picocom status lines) cannot collide with our framing markers.
    run_token = uuid.uuid4().hex
    start_marker = "\nSTART_{}\n".format(run_token).encode('latin-1')
    end_marker = "\nEND_{}\n".format(run_token).encode('latin-1')

    client = None
    stop_reader = threading.Event()
    reader_thread = None
    try:
        client = create_ssh_client(dutip, ressh_user, dutpass)
        # pexpect.spawn defaults: delaybeforesend=0.05, delayafterread=0.0001.
        # Per-call delays dominate at small chunk_size: e.g. 50ms * (10 MiB / 128 B)
        # ~= 4096s of pure idling, throttling effective throughput to ~22% of
        # line rate at 115200/128. Disable both to let the wire be the only cap.
        client.delaybeforesend = None
        client.delayafterread = None
        ensure_console_session_up(client, target_line)

        recv_buf = bytearray()
        recv_lock = threading.Lock()
        reader_exc = []
        last_progress_ts = [time.time()]

        def _reader():
            try:
                while not stop_reader.is_set():
                    try:
                        data = client.read_nonblocking(size=8192, timeout=0.2)
                    except pexpect.TIMEOUT:
                        continue
                    except pexpect.EOF:
                        return
                    if not data:
                        continue
                    if isinstance(data, str):
                        data = data.encode('latin-1')
                    with recv_lock:
                        recv_buf.extend(data)
                        last_progress_ts[0] = time.time()
            except Exception as e:
                reader_exc.append(e)

        reader_thread = threading.Thread(target=_reader, name="console-load-reader", daemon=True)
        reader_thread.start()

        def _send_all(payload_bytes):
            """Loop until the entire payload has been written to the spawn,
            handling partial ``send()`` returns and surfacing reader errors.
            """
            view = memoryview(payload_bytes)
            while view:
                if reader_exc:
                    raise reader_exc[0]
                try:
                    written = client.send(view.tobytes())
                except (pexpect.TIMEOUT, pexpect.EOF, OSError) as e:
                    pytest.fail("Failed to write to console session: {}".format(e))
                if not written:
                    time.sleep(0.05)
                    continue
                view = view[written:]

        send_start = time.time()
        _send_all(start_marker)

        chunk_payload = (FILL_CHAR * chunk_size).encode('latin-1')
        total_sent = 0
        next_progress_log = max(total_bytes // 10, 1)
        while total_sent < total_bytes:
            remaining = total_bytes - total_sent
            payload = chunk_payload if remaining >= chunk_size else (FILL_CHAR * remaining).encode('latin-1')
            _send_all(payload)
            total_sent += len(payload)
            if total_sent >= next_progress_log:
                elapsed = time.time() - send_start
                rate = total_sent / max(elapsed, 0.001)
                logger.info("[console_load] sent %d/%d bytes (%.0f B/s, %.0fs elapsed)",
                            total_sent, total_bytes, rate, elapsed)
                next_progress_log += max(total_bytes // 10, 1)

        _send_all(end_marker)

        # Wait for END to arrive on the receive side, with both a wire-time
        # budget and a forward-progress watchdog. Anchor the deadline to the
        # moment send completed (not send_start) so the receive phase gets its
        # full budget regardless of any send-side overhead.
        send_done = time.time()
        wire_budget = (total_bytes + len(start_marker) + len(end_marker)) * _BITS_PER_BYTE / float(baud_rate)
        absolute_deadline = send_done + wire_budget * 2.0 + 60.0
        recv_wait_start = send_done
        next_recv_log = recv_wait_start + _RECV_PROGRESS_LOG_INTERVAL
        while True:
            if reader_exc:
                raise reader_exc[0]
            with recv_lock:
                seen_end = end_marker in recv_buf
                recv_len = len(recv_buf)
            if seen_end:
                break
            now = time.time()
            if now >= next_recv_log:
                elapsed = now - recv_wait_start
                rate = recv_len / max(elapsed, 0.001)
                logger.info("[console_load] receiving: captured %d bytes (~%.0f B/s, %.0fs since send done)",
                            recv_len, rate, elapsed)
                next_recv_log = now + _RECV_PROGRESS_LOG_INTERVAL
            if now > absolute_deadline:
                pytest.fail(
                    "Did not see end sentinel within {:.0f}s after send completed "
                    "(total_bytes={}, baud={}, captured={} bytes)".format(
                        absolute_deadline - recv_wait_start, total_bytes, baud_rate, recv_len))
            if now - last_progress_ts[0] > _NO_PROGRESS_TIMEOUT:
                pytest.fail(
                    "No new bytes received for {:.0f}s; line appears stalled "
                    "(sent {} of {} bytes, captured {} bytes)".format(
                        now - last_progress_ts[0], total_sent, total_bytes, recv_len))
            time.sleep(0.5)

        # Small post-END drain so any trailing bytes land in the buffer.
        time.sleep(1.0)
        if reader_exc:
            raise reader_exc[0]

        captured = bytes(recv_buf)
        start_idx = captured.find(start_marker)
        end_idx = captured.find(end_marker, start_idx + len(start_marker) if start_idx >= 0 else 0)

        artifact_name = "console_load_line{}_{}_{}_{}_{}.bin".format(
            target_line, baud_rate, flow_control, chunk_size, run_token[:8])

        if start_idx < 0 or end_idx < 0:
            artifact_path = _save_artifact(artifact_name, captured)
            pytest.fail(
                "Did not find start/end sentinels in captured stream for line {} "
                "(start={}, end={}, captured={} bytes); raw capture saved to {}".format(
                    target_line, start_idx, end_idx, len(captured), artifact_path))

        recv_payload = captured[start_idx + len(start_marker):end_idx]
        expected_payload = (FILL_CHAR * total_bytes).encode('latin-1')

        if recv_payload == expected_payload:
            return

        artifact_path = _save_artifact(artifact_name, recv_payload)
        pytest.fail(
            "Console loopback content mismatch on line {} (artifact saved to {}).\n{}".format(
                target_line, artifact_path,
                _bit_error_summary(expected_payload, recv_payload)))

    finally:
        # Stop the reader thread BEFORE closing the SSH client so the thread
        # exits via its stop_reader check rather than via a read_nonblocking
        # exception when the client is torn down. Also covers the case where
        # the test fails inside the try block via pytest.fail() and never
        # reached the explicit stop_reader.set() in the happy path.
        stop_reader.set()
        if reader_thread is not None:
            reader_thread.join(timeout=10)
        if client is not None:
            try:
                # Best-effort picocom escape (Ctrl-A Ctrl-X) to release the
                # console line; ignore failures during teardown.
                client.sendcontrol('a')
                client.sendcontrol('x')
            except Exception as e:
                logger.debug("Failed to send picocom escape during cleanup: %s", e)
            try:
                client.close(force=True)
            except Exception as e:
                logger.debug("Failed to close pexpect spawn during cleanup: %s", e)
        try:
            # Best-effort: wait for the line to return to IDLE so the next
            # parametrize combo starts from a clean state.
            wait_until(10, 1, 0, check_target_line_status, duthost, target_line, "IDLE")
        except Exception as e:
            logger.debug("Line %s did not return to IDLE during cleanup: %s", target_line, e)
        # Restore the original CONFIG_DB state for this line so that
        # core_dump_and_config_check does not flag baud_rate / flow_control
        # drift as a teardown failure.
        try:
            duthost.command(
                "config console baud {} {}".format(target_line, orig_baud),
                module_ignore_errors=True)
        except Exception as e:
            logger.debug("Failed to restore baud_rate for line %s: %s", target_line, e)
        try:
            duthost.command(
                "config console flow_control {} {}".format(orig_flow_control, target_line),
                module_ignore_errors=True)
        except Exception as e:
            logger.debug("Failed to restore flow_control for line %s: %s", target_line, e)
