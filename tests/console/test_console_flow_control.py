import re
import time
from tests.common import config_reload
import pexpect
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import create_ssh_client, ensure_console_session_up
from tests.console.conftest import _console_dev, get_driver_stats


pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


console_lines = list(map(str, range(0, 48)))
baud_rates = ["9600", "115200"]


def _stty_apply_and_verify(host, dev, baud_rate, stty_flags):
    host.shell("stty -F {} {} {}".format(dev, baud_rate, " ".join(stty_flags)))
    out = host.shell("stty -a -F {}".format(dev))["stdout"]
    for flag in stty_flags:
        pytest_assert(flag in out, "Expected '{}' in stty output on {} for {} (got: {})"
                      .format(flag, host.hostname, dev, out))


def _configure_flow_control_via_sonic_and_stty(host, target_line, flow_type, baud_rate):
    """
    SONiC CLI `config console flow_control ...` toggles the configured RTS/CTS flag only.
    Software flow control (XON/XOFF) is configured via stty (ixon/ixoff).
    Returns (dev, cleanup_fn). Call cleanup_fn in finally to restore original baud and disable flow control.
    """
    dev = _console_dev(host, target_line)
    out = host.shell("stty -F {} -a 2>/dev/null".format(dev))["stdout"] or ""
    orig_match = re.search(r'speed (\d+)', out)
    original_baud = orig_match.group(1) if orig_match else "9600"

    def cleanup():
        host.command("config console baud {} {}".format(target_line, original_baud), module_ignore_errors=True)
        host.command("config console flow_control disable {}".format(target_line), module_ignore_errors=True)
        host.shell("stty -F {} {} -crtscts -ixon -ixoff 2>/dev/null || true"
                   .format(dev, original_baud), module_ignore_errors=True)

    try:
        host.command("config console baud {} {}".format(target_line, baud_rate))

        if flow_type == "hardware":
            #sonic command to set flow_control enable/disable doesnt affect the stty_flags
            #So, manually setting stty_flags, until hw and sw flow_control are implemented in sonic-utilities
            host.command("config console flow_control enable {}".format(target_line))
            stty_flags = ["crtscts", "-ixon", "-ixoff"]
        elif flow_type == "software":
            host.command("config console flow_control disable {}".format(target_line))
            stty_flags = ["-crtscts", "ixon", "ixoff"]
        else:
            pytest.fail("Unsupported flow_type {}".format(flow_type))

        _stty_apply_and_verify(host, dev, baud_rate, stty_flags)
        return dev, cleanup
    except Exception:
        cleanup()
        raise


# Pattern for simple ASCII flood (yes ABC)
_FLOOD_PATTERN = "ABC"

# dd/xxd-generated flood (for use later):
# _FLOOD_DATA_BIN = "/tmp/sonic_mgmt_flow_control_data.bin"
# _FLOOD_DATA_TXT = "/tmp/sonic_mgmt_flow_control_data.txt"
# def _create_flood_data(host):
#     host.shell("dd if=/dev/urandom bs=512 count=3 of={} 2>/dev/null".format(_FLOOD_DATA_BIN))
#     host.shell("xxd {} > {}".format(_FLOOD_DATA_BIN, _FLOOD_DATA_TXT))
#     res = host.shell("head -1 {} | awk '{{print $2$3}}'".format(_FLOOD_DATA_TXT))
#     pattern = (res["stdout"] or "").strip()
#     pytest_assert(len(pattern) >= 8, "Failed to extract pattern from xxd output: {}".format(res["stdout"]))
#     return _FLOOD_DATA_TXT, pattern[:8]


def _create_flood_data(host):
    """
    Use yes ABC for uninterrupted ASCII flood. No file needed.
    Returns (data_txt_path, expected_pattern); data_txt_path is None for yes-based flood.
    """
    return None, _FLOOD_PATTERN


def _start_fanout_sender(console_fanout, dev, data_txt_path):
    """
    Start flood in background. Uses `yes ABC` if data_txt_path is None, else `cat` loop.
    """
    if data_txt_path is None:
        cmd = "yes ABC > {} 2>/tmp/sonic-mgmt-flood.err & echo $!".format(dev)
    else:
        cmd = "while true; do cat {}; done > {} 2>/tmp/sonic-mgmt-flood.err & echo $!".format(data_txt_path, dev)
    res = console_fanout.shell(
        "bash -lc '{}'".format(cmd)
    )
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


def _disconnect_line_session(client):
    # connect line prints: "Press ^A ^X to disconnect"
    client.sendcontrol("a")
    client.sendcontrol("x")
    client.close(force=True)


def _expect_data_flood(client, pattern, min_hits=3, timeout_per_hit=2.0):
    hits = 0
    while hits < min_hits:
        client.expect(pattern, timeout=timeout_per_hit)
        hits += 1


def _assert_counter_progress(label, before, after, min_delta=1):
    pytest_assert(after - before >= min_delta,
                  "{} did not increase as expected (before={}, after={})".format(label, before, after))


def _assert_counter_stable(label, before, after, max_delta=256):
    pytest_assert(after - before <= max_delta,
                  "{} increased unexpectedly during 'paused' window (before={}, after={}, delta={})"
                  .format(label, before, after, after - before))

@pytest.mark.skip(reason="Test still in development")
@pytest.mark.parametrize("target_line", console_lines)
@pytest.mark.parametrize("baud_rate", baud_rates)
@pytest.mark.parametrize("flow_type", ["hardware", "software"])
def test_console_switch_flow_control_pause_resume(setup_c0, creds, target_line, baud_rate, flow_type):
    """
    Scenario covered (end-to-end):
    - Configure flow control on DUT and fanout using BOTH:
      - SONiC CLI (`config console ...`)
      - Linux stty (`stty -F ...`)
      and verify the assignment is effective for the line.
    - Start heavy traffic on fanout: ASCII ABC flood looped to /dev/ttyCOx.
    - Connect to DUT line and verify data flood + driver counters increase.
    - Pause and resume:
      - software: send XOFF (Ctrl-S) and XON (Ctrl-Q) from DUT session and verify TX/RX counters stop/resume.
      - hardware: simulate backpressure by disconnecting (stop reading) then reconnecting and verify TX/RX stop/resume.
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
        sender_pid = _start_fanout_sender(console_fanout, fanout_dev, data_txt_path)
        time.sleep(0.5)

        _expect_data_flood(client, flood_pattern, min_hits=3, timeout_per_hit=5.0)

        mid_fanout = get_driver_stats(console_fanout, target_line)
        mid_dut = get_driver_stats(duthost, target_line)
        _assert_counter_progress("fanout tx", start_fanout["tx"], mid_fanout["tx"], min_delta=64)
        _assert_counter_progress("dut rx", start_dut["rx"], mid_dut["rx"], min_delta=64)

        if flow_type == "software":
            # Send XOFF from DUT and verify traffic stops.
            paused_fanout_before = get_driver_stats(console_fanout, target_line)
            paused_dut_before = get_driver_stats(duthost, target_line)

            client.sendcontrol("s")  # XOFF (0x13)
            time.sleep(2.0)

            paused_fanout_after = get_driver_stats(console_fanout, target_line)
            paused_dut_after = get_driver_stats(duthost, target_line)
            _assert_counter_stable("fanout tx", paused_fanout_before["tx"], paused_fanout_after["tx"], max_delta=512)
            _assert_counter_stable("dut rx", paused_dut_before["rx"], paused_dut_after["rx"], max_delta=512)

            # Also verify console output is not continuing to stream.
            try:
                client.expect(flood_pattern, timeout=1.0)
                pytest.fail("Still receiving flood data on DUT after XOFF (software flow control)")
            except pexpect.TIMEOUT:
                pass

            # Send XON and verify traffic resumes from the stopped counters.
            resume_fanout_before = get_driver_stats(console_fanout, target_line)
            resume_dut_before = get_driver_stats(duthost, target_line)

            client.sendcontrol("q")  # XON (0x11)
            _expect_data_flood(client, flood_pattern, min_hits=2, timeout_per_hit=5.0)
            time.sleep(1.0)

            resume_fanout_after = get_driver_stats(console_fanout, target_line)
            resume_dut_after = get_driver_stats(duthost, target_line)
            _assert_counter_progress("fanout tx after XON", resume_fanout_before["tx"], resume_fanout_after["tx"],
                                     min_delta=64)
            _assert_counter_progress("dut rx after XON", resume_dut_before["rx"], resume_dut_after["rx"], min_delta=64)

        else:
            # Hardware flow control (RTS/CTS) has no XOFF/XON semantics.
            # We validate pause/resume by stopping reads (disconnect) to let receiver backpressure stop transmitter.
            paused_fanout_before = get_driver_stats(console_fanout, target_line)
            paused_dut_before = get_driver_stats(duthost, target_line)

            _disconnect_line_session(client)
            client = None
            time.sleep(10)

            paused_fanout_after = get_driver_stats(console_fanout, target_line)
            paused_dut_after = get_driver_stats(duthost, target_line)
            _assert_counter_stable("fanout tx", paused_fanout_before["tx"], paused_fanout_after["tx"], max_delta=4096)

            # Reconnect and verify traffic resumes.
            client = _connect_line_via_ressh(duthost, creds, target_line)
            _expect_data_flood(client, flood_pattern, min_hits=2, timeout_per_hit=5.0)

            resume_fanout_before = get_driver_stats(console_fanout, target_line)
            resume_dut_before = get_driver_stats(duthost, target_line)
            time.sleep(1.0)
            resume_fanout_after = get_driver_stats(console_fanout, target_line)
            resume_dut_after = get_driver_stats(duthost, target_line)
            _assert_counter_progress("fanout tx after resume", resume_fanout_before["tx"], resume_fanout_after["tx"],
                                     min_delta=64)
            _assert_counter_progress("dut rx after resume", resume_dut_before["rx"], resume_dut_after["rx"],
                                     min_delta=64)

    finally:
        if client is not None:
            try:
                _disconnect_line_session(client)
            except Exception:
                pass
        if sender_pid is not None:
            _stop_fanout_sender(console_fanout, sender_pid)
        dut_cleanup()
        fanout_cleanup()
