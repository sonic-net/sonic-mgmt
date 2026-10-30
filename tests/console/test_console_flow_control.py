import logging
import re
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import create_ssh_client, ensure_console_session_up
from tests.console.conftest import get_driver_stats, build_chunked_text_data

pytestmark = [
    pytest.mark.topology('c0')
]


console_lines = list(map(str, range(1, 49)))
baud_rates = ["9600", "115200"]


def _stty_apply_and_verify(host, dev, baud_rate, stty_flags):
    host.shell("stty -F {} {} {}".format(dev, baud_rate, " ".join(stty_flags)))
    out = host.shell("stty -a -F {}".format(dev))["stdout"]
    for flag in stty_flags:
        pytest_assert(flag in out, "Expected '{}' in stty output on {} for {} (got: {})"
                      .format(flag, host.hostname, dev, out))


def _configure_flow_control_via_sonic_and_stty(host, target_line, flow_type, baud_rate):
    """
    Set console baud and flow-control mode via SONiC CLI, then apply matching termios on the device with stty
    (RTS/CTS vs IXON/IXOFF) so the link matches what the test asserts.
    Returns (dev, cleanup_fn). Call cleanup_fn in finally to restore original baud and disable flow control.
    """
    dev = "{}{}".format(host.get_serial_device_prefix(), target_line)
    out = host.shell("stty -a -F {}".format(dev), module_ignore_errors=False)["stdout"] or ""
    orig_match = re.search(r'speed (\d+)', out)
    original_baud = orig_match.group(1) if orig_match else "9600"

    def cleanup():
        host.command("config console baud {} {}".format(target_line, original_baud), module_ignore_errors=True)
        host.command("config console flow_control disable {}".format(target_line), module_ignore_errors=True)
        host.shell("stty -F {} {} -crtscts ixon -ixoff"
                   .format(dev, original_baud), module_ignore_errors=True)

    try:
        host.command("config console baud {} {}".format(target_line, baud_rate))

        if flow_type == "hardware":
            # CLI records hardware flow control; stty applies crtscts on the TTY.
            host.command("config console flow_control enable {}".format(target_line))
            stty_flags = ["crtscts", "-ixon", "-ixoff"]
        else:
            host.command("config console flow_control disable {}".format(target_line))
            stty_flags = ["-crtscts", "ixon", "ixoff"]

        _stty_apply_and_verify(host, dev, baud_rate, stty_flags)
        return dev, cleanup
    except Exception:
        cleanup()
        raise


# Pattern for simple ASCII flood payload
_FLOOD_PATTERN = "ABC"
_FLOOD_CHUNK_SIZE = 1024
_FLOOD_TOTAL_MB = 64
_FLOOD_DURATION_SEC = 120
_FLOOD_MAX_BYTES_SEC = 8192


def _create_flood_data(host):
    """
    Create deterministic chunked payload file via conftest helper.
    Returns (data_txt_path, expected_pattern).
    """
    data_path = build_chunked_text_data(
        host,
        total_mb=_FLOOD_TOTAL_MB,
        chunk_size=_FLOOD_CHUNK_SIZE,
        seed=_FLOOD_PATTERN
    )
    return data_path, _FLOOD_PATTERN


def _start_fanout_sender(
        console_fanout, dev, data_txt_path,
        chunk_size=_FLOOD_CHUNK_SIZE, total_mb=_FLOOD_TOTAL_MB,
        duration_sec=_FLOOD_DURATION_SEC, max_bytes_sec=_FLOOD_MAX_BYTES_SEC):
    """
    Start bounded flood in background using generated payload file.
    Sender loops `dd` with chunk_size blocks until duration_sec elapses.
    """
    chunk_size = max(1, int(chunk_size))
    duration_sec = max(1, int(duration_sec))
    data_path = data_txt_path or ""
    pytest_assert(data_path, "Flood payload path is empty")

    # Keep command construction simple: generated paths are fixed /tmp and /dev locations.
    cmd = (
        "timeout {duration}s bash -lc "
        "'while true; do dd if={data} of={dev} bs={chunk} iflag=fullblock status=none; done' "
        ">/tmp/sonic-mgmt-flood.err 2>&1 & echo $!"
    ).format(duration=duration_sec, data=data_path, dev=dev, chunk=chunk_size)

    res = console_fanout.shell(cmd)
    pid_s = (res["stdout"] or "").strip().splitlines()[-1]
    pytest_assert(pid_s.isdigit(), "Failed to start sender on fanout, stdout: {}".format(res["stdout"]))
    return int(pid_s)


def _stop_fanout_sender(console_fanout, pid):
    console_fanout.shell("kill -TERM {} >/dev/null 2>&1 || true".format(pid), module_ignore_errors=True)
    console_fanout.shell("kill -KILL {} >/dev/null 2>&1 || true".format(pid), module_ignore_errors=True)


def _connect_line_via_ressh(duthost, creds, target_line):
    dutip = duthost.host.options["inventory_manager"].get_host(duthost.hostname).vars["ansible_host"]
    dutuser = creds["sonicadmin_user"]
    dutpass = creds["sonicadmin_password"]
    client = create_ssh_client(dutip, "{}:{}".format(dutuser, target_line), dutpass)
    ensure_console_session_up(client, target_line)
    return client


def _expect_data_flood(client, pattern, min_hits=3, timeout_per_hit=2.0):
    hits = 0
    while hits < min_hits:
        client.expect(pattern, timeout=timeout_per_hit)
        hits += 1
        logging.info("Expected flood hits increased to {}".format(hits))


def _assert_counter_progress(label, before, after, min_delta=1):
    pytest_assert(after - before >= min_delta,
                  "{} did not increase as expected (before={}, after={})".format(label, before, after))


def _assert_counter_stable(label, before, after, max_delta=256):
    pytest_assert(after - before <= max_delta,
                  "{} increased unexpectedly during 'paused' window (before={}, after={}, delta={})"
                  .format(label, before, after, after - before))


@pytest.mark.parametrize("target_line", console_lines)
@pytest.mark.parametrize("baud_rate", baud_rates)
@pytest.mark.parametrize("flow_type", ["hardware", "software"])
def test_console_switch_flow_control_pause_resume(setup_c0, creds, target_line, baud_rate, flow_type, cleanup_modules):
    """
    Scenario covered (end-to-end):
    - Configure flow control on DUT and fanout using BOTH:
      - SONiC CLI (`config console ...`)
      - Linux stty (`stty -F ...`)
      and verify the assignment is effective for the line.
    - Start heavy traffic on fanout: ASCII ABC flood looped to the platform console device
      (get_serial_device_prefix() + line index).
    - Connect to DUT line and verify data flood + driver counters increase.
    - Pause and resume:
      - software: send XOFF (Ctrl-S) and XON (Ctrl-Q) from DUT session and verify TX/RX counters stop/resume.
      - hardware: exit the line client (Ctrl-A then Ctrl-X, picocom-style) to stop reading, then reconnect and
        verify DUT RX counters stabilize while disconnected and progress again after reconnect.
    - Terminate the fanout sender.
    """
    duthost, console_fanout = setup_c0

    dut_dev, dut_cleanup = _configure_flow_control_via_sonic_and_stty(duthost, target_line, flow_type, baud_rate)
    fanout_dev, fanout_cleanup = _configure_flow_control_via_sonic_and_stty(console_fanout, target_line, flow_type,
                                                                            baud_rate)

    data_txt_path, flood_pattern = _create_flood_data(console_fanout)
    start_fanout = get_driver_stats(console_fanout, target_line)
    start_dut = get_driver_stats(duthost, target_line)

    sender_pid = None
    client = None
    try:
        # Connect before starting sender so DUT buffer is empty when flood begins.
        # Avoids stale/corrupted data in buffer when flow control engages.
        client = _connect_line_via_ressh(duthost, creds, target_line)
        logging.info("DUT reverse ssh connection successful")
        sender_pid = _start_fanout_sender(console_fanout, fanout_dev, data_txt_path)
        logging.info("Starting sending traffic from fanout continuously through pid: {}".format(sender_pid))
        time.sleep(0.5)

        _expect_data_flood(client, flood_pattern, min_hits=3, timeout_per_hit=5.0)
        logging.info("Verifying traffic from fanout and DUT RX via driver statistics")
        mid_fanout = get_driver_stats(console_fanout, target_line)
        mid_dut = get_driver_stats(duthost, target_line)
        logging.info("mid_fanout: {}, mid_dut: {}".format(mid_fanout, mid_dut))
        _assert_counter_progress("fanout tx", start_fanout["tx"], mid_fanout["tx"], min_delta=64)
        _assert_counter_progress("dut rx", start_dut["rx"], mid_dut["rx"], min_delta=64)

        if flow_type == "software":
            # Send XOFF from DUT and verify traffic stops.
            logging.info("Software flow control...")
            logging.info("Stopping using direct XOFF injection to DUT serial device %s", dut_dev)
            duthost.shell("printf '\x13' > {}".format(dut_dev))  # XOFF (0x13)
            time.sleep(10.0)
            paused_fanout_before = get_driver_stats(console_fanout, target_line)
            paused_dut_before = get_driver_stats(duthost, target_line)
            logging.info("paused_fanout_before: {}, paused_dut_before:{}".format(paused_fanout_before, paused_dut_before))
            time.sleep(10)

            paused_fanout_after = get_driver_stats(console_fanout, target_line)
            paused_dut_after = get_driver_stats(duthost, target_line)
            logging.info(
                "paused_fanout_after: {}, paused_dut_after:{}".format(paused_fanout_after, paused_dut_after))
            _assert_counter_stable("fanout tx", paused_fanout_before["tx"], paused_fanout_after["tx"], max_delta=512)
            _assert_counter_stable("dut rx", paused_dut_before["rx"], paused_dut_after["rx"], max_delta=512)

            # Send XON and verify traffic resumes from the stopped counters.
            resume_fanout_before = get_driver_stats(console_fanout, target_line)
            resume_dut_before = get_driver_stats(duthost, target_line)
            logging.info("Starting using direct XON injection to DUT serial device %s", dut_dev)
            duthost.shell("printf '\x11' > {}".format(dut_dev))  # XON (0x11)
            _expect_data_flood(client, flood_pattern, min_hits=2, timeout_per_hit=5.0)
            time.sleep(1.0)

            resume_fanout_after = get_driver_stats(console_fanout, target_line)
            resume_dut_after = get_driver_stats(duthost, target_line)
            logging.info("resume_fanout_after:{}, resume_dut_after:{}".format(resume_fanout_after, resume_dut_after))
            _assert_counter_progress("fanout tx after XON", resume_fanout_before["tx"], resume_fanout_after["tx"],
                                     min_delta=64)
            _assert_counter_progress("dut rx after XON", resume_dut_before["rx"], resume_dut_after["rx"], min_delta=64)

        else:
            # Hardware (RTS/CTS): exit line client so DUT stops reading; assert DUT RX counters stay flat while
            # disconnected (fanout TX may still move due to driver buffering; this path keys on DUT RX).

            logging.info("Sending CTRL+A+X to stop line connection")
            client.sendcontrol("a")
            client.sendcontrol("x")

            client = None
            time.sleep(10)

            logging.info("Statistics before Terminating connection")
            paused_dut_before = get_driver_stats(duthost, target_line)
            logging.info("paused_dut_before:{}".format(paused_dut_before))

            time.sleep(20)

            paused_dut_after = get_driver_stats(duthost, target_line)
            logging.info("paused_dut_after: {}".format(paused_dut_after))
            _assert_counter_stable("dut rx", paused_dut_before["rx"], paused_dut_after["rx"], max_delta=512)

            # Reconnect and verify traffic resumes.
            logging.info("Reconnecting ...")
            client = _connect_line_via_ressh(duthost, creds, target_line)
            _expect_data_flood(client, flood_pattern, min_hits=2, timeout_per_hit=5.0)

            resume_fanout_before = get_driver_stats(console_fanout, target_line)
            resume_dut_before = get_driver_stats(duthost, target_line)
            logging.info("resume_fanout_before:{}, resume_dut_before:{}".format(resume_fanout_before, resume_dut_before))
            time.sleep(1.0)
            resume_fanout_after = get_driver_stats(console_fanout, target_line)
            resume_dut_after = get_driver_stats(duthost, target_line)
            logging.info(
                "resume_fanout_after:{}, resume_dut_after:{}".format(resume_fanout_after, resume_dut_after))
            _assert_counter_progress("fanout tx after resume", resume_fanout_before["tx"], resume_fanout_after["tx"],
                                     min_delta=64)
            _assert_counter_progress("dut rx after resume", resume_dut_before["rx"], resume_dut_after["rx"],
                                     min_delta=64)

    finally:
        if client is not None:
            client.sendcontrol("a")
            client.sendcontrol("x")
        if sender_pid is not None:
            _stop_fanout_sender(console_fanout, sender_pid)
        dut_cleanup()
        fanout_cleanup()
