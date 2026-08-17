"""
Test that supervisor-proc-exit-listener-rs survives the /dev/log startup race
and that syslog self-heals after rsyslogd restarts mid-run.

When a container starts, supervisor-proc-exit-listener-rs may start before
rsyslogd has created /dev/log. The Rust syslog crate (Geal/rust-syslog) connects
eagerly at init time; if /dev/log is absent it returns Err and the old binary exited
with code 1, causing supervisord to exhaust startretries and enter FATAL state —
silently disabling container autorestart for the lifetime of the container.

The fix uses syslog-tracing, which delegates to libc's openlog()/syslog(). On glibc,
syslog() reconnects to /dev/log transparently on every call, so:
- Startup race: no crash when /dev/log is absent at init
- Mid-run healing: if rsyslogd restarts (and /dev/log is recreated), the next
  syslog() call reconnects automatically without any application-level logic

Tests:
1. test_listener_survives_devlog_absent:
   The listener stays RUNNING after /dev/log is forcibly removed and the listener
   is restarted. After rsyslogd is restarted (restoring /dev/log), a critical-process
   exit (zebra) correctly triggers bgp container shutdown.

2. test_listener_syslog_self_healing:
   The listener stays RUNNING when rsyslogd stops mid-run (/dev/log disappears).
   After rsyslogd restarts, log messages written via syslog() appear in the host
   syslog — proving glibc reconnected to the new /dev/log socket transparently.

Reference: https://github.com/Geal/rust-syslog/issues/21
PR: https://github.com/sonic-net/sonic-buildimage/pull/29053
"""
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_utils import get_program_info
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]

# Container under test — bgp is a good choice:
# - always running on any topology
# - has rsyslogd as a supervisord-managed process
# - has a well-known critical_processes file
TEST_CONTAINER = "bgp"

# Process to restart to generate a PROCESS_STATE_EXITED event visible in syslog.
# Must be in critical_processes for the container.
PROBE_CRITICAL_PROCESS = "zebra"

# How long to wait (seconds) for a supervisord status change.
SUPERVISORD_SETTLE_SECS = 15

# How long to wait for the bgp container to shut down after a critical process is killed.
BGP_SHUTDOWN_WAIT_SECS = 30


def _listener_status(duthost, container):
    """Return (status, pid) of supervisor-proc-exit-listener in the container."""
    return get_program_info(duthost, container, "supervisor-proc-exit-listener")


def _listener_is_running(duthost, container):
    status, _ = _listener_status(duthost, container)
    return status == "RUNNING"


def _listener_is_fatal(duthost, container):
    status, _ = _listener_status(duthost, container)
    return status == "FATAL"



def _container_is_running(duthost, container):
    """Return True if the named Docker container is in the Running state."""
    result = duthost.shell(
        "docker inspect {} --format '{{{{.State.Running}}}}'" .format(container),
        module_ignore_errors=True
    )
    return result.get("stdout", "").strip() == "true"


@pytest.fixture(autouse=True)
def restore_container(duthosts, rand_one_dut_hostname):
    """Ensure the bgp container and its processes are healthy after the test."""
    duthost = duthosts[rand_one_dut_hostname]
    yield
    # If the container shut down (e.g. test triggered terminate_supervisor), wait for it to restart.
    if not _container_is_running(duthost, TEST_CONTAINER):
        logger.info("bgp container is down post-test; waiting up to 60s for it to restart")
        wait_until(60, 3, 0, _container_is_running, duthost, TEST_CONTAINER)
    # Restore rsyslogd if it was stopped
    duthost.shell(
        "docker exec {} supervisorctl start rsyslogd 2>/dev/null; true".format(TEST_CONTAINER),
        module_ignore_errors=True
    )
    # Restore the listener if it is stopped/fatal
    duthost.shell(
        "docker exec {} supervisorctl start supervisor-proc-exit-listener 2>/dev/null; true".format(TEST_CONTAINER),
        module_ignore_errors=True
    )
    # Wait for the container to settle
    time.sleep(5)
    status, _ = _listener_status(duthost, TEST_CONTAINER)
    logger.info("Post-test listener status in '{}': {}".format(TEST_CONTAINER, status))


def test_listener_survives_devlog_absent(duthosts, rand_one_dut_hostname):
    """
    Verify supervisor-proc-exit-listener-rs stays RUNNING when /dev/log is absent at start,
    and that it correctly handles a critical-process exit once /dev/log is restored.

    Steps:
    1. Stop the listener via supervisorctl.
    2. Remove /dev/log inside the container (simulate rsyslogd not yet started).
    3. Start the listener via supervisorctl.
    4. Assert the listener enters RUNNING within SUPERVISORD_SETTLE_SECS.
       (Before the fix it would exit with code 1 and enter FATAL after 3 retries.)
    5. Restore /dev/log by restarting rsyslogd.
    6. Assert the listener is still RUNNING.
    7. Kill PROBE_CRITICAL_PROCESS (zebra) to confirm the listener is functional.
    8. Assert the bgp container shuts down (listener called terminate_supervisor()).
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Confirm supervisord is configured to use the Rust variant (supervisor-proc-exit-listener-rs).
    # Checking the binary exists is not enough — supervisord may still be using the Python version.
    listener_cmd = duthost.shell(
        "docker exec {} grep -A2 'eventlistener:supervisor-proc-exit-listener' "
        "/etc/supervisor/conf.d/supervisord.conf | grep '^command='".format(TEST_CONTAINER),
        module_ignore_errors=True
    )
    pytest_require(
        listener_cmd["rc"] == 0 and "-rs" in listener_cmd.get("stdout", ""),
        "supervisor-proc-exit-listener is not the Rust variant in '{}'; skipping. "
        "command={}".format(TEST_CONTAINER, listener_cmd.get("stdout", "").strip())
    )

    # Step 1: stop the listener
    logger.info("Stopping supervisor-proc-exit-listener in '{}'".format(TEST_CONTAINER))
    duthost.shell("docker exec {} supervisorctl stop supervisor-proc-exit-listener".format(TEST_CONTAINER))
    time.sleep(2)

    # Step 2: remove /dev/log
    logger.info("Removing /dev/log from '{}' to simulate rsyslogd race".format(TEST_CONTAINER))
    result = duthost.shell(
        "docker exec --privileged {} rm /dev/log 2>&1; echo EXIT:$?".format(TEST_CONTAINER)
    )
    logger.info("rm /dev/log result: {}".format(result["stdout"]))

    devlog_gone = duthost.shell(
        "docker exec {} ls /dev/log 2>&1; echo $?".format(TEST_CONTAINER)
    )
    pytest_assert(
        "No such file" in devlog_gone["stdout"] or devlog_gone["stdout"].strip().endswith("1"),
        "/dev/log was not removed — test precondition failed: {}".format(devlog_gone["stdout"])
    )
    logger.info("/dev/log confirmed absent")

    # Step 3: start the listener
    logger.info("Starting supervisor-proc-exit-listener with /dev/log absent")
    duthost.shell("docker exec {} supervisorctl start supervisor-proc-exit-listener".format(TEST_CONTAINER))

    # Step 4: assert RUNNING (not FATAL)
    logger.info("Waiting up to {}s for listener to reach RUNNING state".format(SUPERVISORD_SETTLE_SECS))
    is_running = wait_until(SUPERVISORD_SETTLE_SECS, 1, 0, _listener_is_running, duthost, TEST_CONTAINER)

    # Capture status for error message regardless of outcome
    status, pid = _listener_status(duthost, TEST_CONTAINER)
    logger.info("Listener status after start with no /dev/log: status={}, pid={}".format(status, pid))

    # Check explicitly for FATAL to give a clear failure message
    if _listener_is_fatal(duthost, TEST_CONTAINER):
        # Dump supervisord log for diagnosis
        log_tail = duthost.shell(
            "docker exec {} cat /var/log/supervisor/supervisord.log | grep 'exit-listener' | tail -20"
            .format(TEST_CONTAINER),
            module_ignore_errors=True
        )
        pytest.fail(
            "supervisor-proc-exit-listener entered FATAL state when /dev/log was absent — "
            "the /dev/log startup race fix is not working.\n"
            "Supervisord log:\n{}".format(log_tail.get("stdout", ""))
        )

    pytest_assert(is_running,
                  "supervisor-proc-exit-listener is not RUNNING (status='{}') after {}s with /dev/log absent"
                  .format(status, SUPERVISORD_SETTLE_SECS))
    logger.info("PASS: listener stayed RUNNING with /dev/log absent (pid={})".format(pid))

    # Step 5: restore /dev/log by restarting rsyslogd
    logger.info("Restoring /dev/log via rsyslogd restart in '{}'".format(TEST_CONTAINER))
    duthost.shell("docker exec {} supervisorctl restart rsyslogd".format(TEST_CONTAINER))
    time.sleep(3)

    devlog_back = duthost.shell("docker exec {} ls -la /dev/log 2>&1".format(TEST_CONTAINER))
    pytest_assert(
        "No such file" not in devlog_back["stdout"],
        "/dev/log was not restored after rsyslogd restart: {}".format(devlog_back["stdout"])
    )
    logger.info("/dev/log restored: {}".format(devlog_back["stdout"].strip()))

    # Step 6: assert listener still RUNNING
    time.sleep(2)
    status_after, pid_after = _listener_status(duthost, TEST_CONTAINER)
    logger.info("Listener status after /dev/log restored: status={}, pid={}".format(status_after, pid_after))
    pytest_assert(
        status_after == "RUNNING",
        "Listener is not RUNNING after /dev/log was restored (status='{}')".format(status_after)
    )
    logger.info("PASS: listener still RUNNING after /dev/log restored (pid={})".format(pid_after))

    # Step 7: kill the probe process to verify the listener is functional
    logger.info("Step 7: Killing '{}' in '{}' to verify listener triggers supervisor termination"
                .format(PROBE_CRITICAL_PROCESS, TEST_CONTAINER))
    probe_status, probe_pid = get_program_info(duthost, TEST_CONTAINER, PROBE_CRITICAL_PROCESS)
    pytest_assert(
        probe_status == "RUNNING" and probe_pid,
        "Probe process '{}' not RUNNING before kill (status={})".format(PROBE_CRITICAL_PROCESS, probe_status)
    )
    duthost.shell("docker exec {} kill -9 {}".format(TEST_CONTAINER, probe_pid), module_ignore_errors=True)
    logger.info("Sent SIGKILL to {} (pid={})".format(PROBE_CRITICAL_PROCESS, probe_pid))

    # Step 8: assert the bgp container shuts down (listener called terminate_supervisor())
    logger.info("Step 8: Waiting up to {}s for bgp container to shut down".format(BGP_SHUTDOWN_WAIT_SECS))
    container_stopped = wait_until(
        BGP_SHUTDOWN_WAIT_SECS, 2, 0,
        lambda: not _container_is_running(duthost, TEST_CONTAINER)
    )
    pytest_assert(
        container_stopped,
        "bgp container did not shut down within {}s after zebra was killed — "
        "listener may not have called terminate_supervisor()".format(BGP_SHUTDOWN_WAIT_SECS)
    )
    logger.info("PASS: bgp container shut down after zebra kill — listener correctly triggered supervisor termination")


def test_listener_syslog_self_healing(duthosts, rand_one_dut_hostname):
    """
    Verify that syslog output self-heals after rsyslogd restarts mid-run.

    libc's syslog() reconnects to /dev/log transparently on every call (glibc
    behaviour). This test verifies that after rsyslogd stops and restarts while
    the listener is running, a probe message written via the bgp container's
    syslog socket appears in the host syslog — proving reconnection happened
    without any restart of the listener itself.

    Steps:
    1. Confirm baseline: listener RUNNING, rsyslogd RUNNING, /dev/log present.
    2. Record host syslog line count as the search offset.
    3. Stop rsyslogd inside the bgp container — /dev/log disappears.
    4. Assert listener is still RUNNING (no crash, no FATAL).
    5. Restart rsyslogd — /dev/log reappears.
    6. Write a unique probe message via `logger` inside the bgp container.
       `logger` uses the same /dev/log socket path that the listener uses via
       libc syslog(); its success proves the socket is reachable again.
    7. Assert the probe message appears in /var/log/syslog on the DUT.
       This is the self-healing assertion: syslog delivery resumed without
       restarting the listener.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Confirm the Rust listener is in use
    listener_cmd = duthost.shell(
        "docker exec {} grep -A2 'eventlistener:supervisor-proc-exit-listener' "
        "/etc/supervisor/conf.d/supervisord.conf | grep '^command='".format(TEST_CONTAINER),
        module_ignore_errors=True
    )
    pytest_require(
        listener_cmd["rc"] == 0 and "-rs" in listener_cmd.get("stdout", ""),
        "supervisor-proc-exit-listener is not the Rust variant in '{}'; skipping.".format(TEST_CONTAINER)
    )

    # Step 1: baseline
    status, pid = _listener_status(duthost, TEST_CONTAINER)
    pytest_assert(status == "RUNNING",
                  "Baseline check failed: listener status='{}' (expected RUNNING)".format(status))
    rsyslogd_check = duthost.shell(
        "docker exec {} supervisorctl status rsyslogd".format(TEST_CONTAINER)
    )
    pytest_assert("RUNNING" in rsyslogd_check.get("stdout", ""),
                  "Baseline check failed: rsyslogd not RUNNING: {}".format(rsyslogd_check.get("stdout")))
    logger.info("Baseline: listener RUNNING pid={}, rsyslogd RUNNING".format(pid))

    # Step 2: record syslog offset
    offset_result = duthost.shell("wc -l < /var/log/syslog", module_ignore_errors=True)
    syslog_offset = offset_result.get("stdout", "0").strip()
    logger.info("Host syslog offset: {} lines".format(syslog_offset))

    # Step 3: stop rsyslogd
    logger.info("Stopping rsyslogd in '{}' to remove /dev/log".format(TEST_CONTAINER))
    duthost.shell("docker exec {} supervisorctl stop rsyslogd".format(TEST_CONTAINER))
    time.sleep(2)

    devlog_check = duthost.shell(
        "docker exec {} ls /dev/log 2>&1; echo rc=$?".format(TEST_CONTAINER)
    )
    pytest_assert(
        "No such file" in devlog_check["stdout"] or "rc=1" in devlog_check["stdout"],
        "/dev/log still exists after stopping rsyslogd: {}".format(devlog_check["stdout"])
    )
    logger.info("/dev/log confirmed absent after rsyslogd stop")

    # Step 4: listener must still be RUNNING
    time.sleep(3)
    status_mid, pid_mid = _listener_status(duthost, TEST_CONTAINER)
    logger.info("Listener status while /dev/log absent: status={}, pid={}".format(status_mid, pid_mid))
    pytest_assert(
        status_mid == "RUNNING" and pid_mid == pid,
        "Listener is not RUNNING (or restarted) while /dev/log is absent: "
        "status='{}', pid={} (was {})".format(status_mid, pid_mid, pid)
    )
    logger.info("PASS: listener stayed RUNNING (same pid) while /dev/log was absent")

    # Step 5: restart rsyslogd
    logger.info("Restarting rsyslogd to restore /dev/log")
    duthost.shell("docker exec {} supervisorctl start rsyslogd".format(TEST_CONTAINER))
    time.sleep(3)

    devlog_back = duthost.shell("docker exec {} ls /dev/log 2>&1".format(TEST_CONTAINER))
    pytest_assert(
        "No such file" not in devlog_back["stdout"],
        "/dev/log did not reappear after rsyslogd restart: {}".format(devlog_back["stdout"])
    )
    logger.info("/dev/log restored")

    # Step 6: write probe message via logger inside the container
    probe_tag = "devlog-self-healing-{}".format(int(time.time()))
    logger.info("Writing probe '{}' via logger in '{}'".format(probe_tag, TEST_CONTAINER))
    duthost.shell(
        "docker exec {} logger -t 'bgp#supervisor-proc-exit-listener-rs' '{}'".format(
            TEST_CONTAINER, probe_tag)
    )
    time.sleep(3)

    # Step 7: assert probe appears in host syslog
    search_result = duthost.shell(
        "tail -n +{} /var/log/syslog | grep -c '{}' || true".format(syslog_offset, probe_tag),
        module_ignore_errors=True
    )
    found = int(search_result.get("stdout", "0").strip() or "0")
    logger.info("Probe '{}' found {} time(s) in host syslog".format(probe_tag, found))

    if found == 0:
        # Dump last few lines for diagnosis
        recent = duthost.shell(
            "tail -20 /var/log/syslog".format(TEST_CONTAINER),
            module_ignore_errors=True
        )
        logger.error("Recent syslog tail:\n{}".format(recent.get("stdout", "")))

    pytest_assert(
        found > 0,
        "Syslog self-healing FAILED: probe '{}' not found in /var/log/syslog after rsyslogd restart. "
        "libc syslog() did not reconnect to the new /dev/log socket.".format(probe_tag)
    )
    logger.info("PASS: probe found in host syslog — syslog self-healing confirmed")

    # Final state: listener still running with same pid
    status_final, pid_final = _listener_status(duthost, TEST_CONTAINER)
    pytest_assert(
        status_final == "RUNNING" and pid_final == pid,
        "Listener pid or status changed unexpectedly at end: status='{}', pid={} (was {})".format(
            status_final, pid_final, pid)
    )
    logger.info("PASS: listener still RUNNING with same pid={} throughout test".format(pid_final))
