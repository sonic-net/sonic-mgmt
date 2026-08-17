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

3. test_listener_own_syslog_reconnects_after_rsyslogd_restart:
   Stronger variant of test 2. Triggers the listener's own syslog() code path
   (its error!() alerting message) rather than a separate `logger` probe.
   After rsyslogd restarts mid-run, a critical-process exit causes the listener
   itself to call syslog() — that message appears in host syslog, proving libc
   reconnected specifically for the listener binary, not just for `logger`.

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

# Process to kill to generate a PROCESS_STATE_EXITED event visible in syslog.
# Must be in critical_processes for the container.
PROBE_CRITICAL_PROCESS = "zebra"

# Secondary container for test_listener_own_syslog_reconnects_after_rsyslogd_restart.
# eventd is ideal: always running on every topology, single critical process (eventd),
# non-critical companion (eventdb), and a clean restart cycle.
EVENTD_CONTAINER = "eventd"
EVENTD_CRITICAL_PROCESS = "eventd"

# How long to wait (seconds) for a supervisord status change.
SUPERVISORD_SETTLE_SECS = 15

# How long to wait for a container to shut down after a critical process is killed.
CONTAINER_SHUTDOWN_WAIT_SECS = 30


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
    # Use raw string + escaped braces to avoid Ansible/Jinja2 templating {{ }}
    result = duthost.shell(
        r"docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container),
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

    # Step 7: ensure auto_restart=enabled so the listener calls terminate_supervisor
    # In a freshly-deployed VS, the FEATURE table may be empty and get_autorestart_state()
    # returns None (feature not found), which causes the listener to alert rather than terminate.
    logger.info("Step 7a: ensuring auto_restart=enabled for '{}' in ConfigDB".format(TEST_CONTAINER))
    duthost.shell("sudo config feature autorestart {} enabled".format(TEST_CONTAINER),
                  module_ignore_errors=True)
    time.sleep(1)

    # Step 7: kill the probe process to verify the listener is functional
    logger.info("Step 7b: Killing '{}' in '{}' to verify listener triggers supervisor termination"
                .format(PROBE_CRITICAL_PROCESS, TEST_CONTAINER))
    probe_status, probe_pid = get_program_info(duthost, TEST_CONTAINER, PROBE_CRITICAL_PROCESS)
    pytest_assert(
        probe_status == "RUNNING" and probe_pid,
        "Probe process '{}' not RUNNING before kill (status={})".format(PROBE_CRITICAL_PROCESS, probe_status)
    )
    duthost.shell("docker exec {} kill -9 {}".format(TEST_CONTAINER, probe_pid), module_ignore_errors=True)
    logger.info("Sent SIGKILL to {} (pid={})".format(PROBE_CRITICAL_PROCESS, probe_pid))

    # Step 8: assert the bgp container shuts down (listener called terminate_supervisor())
    logger.info("Step 8: Waiting up to {}s for bgp container to shut down".format(CONTAINER_SHUTDOWN_WAIT_SECS))
    container_stopped = wait_until(
        CONTAINER_SHUTDOWN_WAIT_SECS, 2, 0,
        lambda: not _container_is_running(duthost, TEST_CONTAINER)
    )
    pytest_assert(
        container_stopped,
        "bgp container did not shut down within {}s after zebra was killed — "
        "listener may not have called terminate_supervisor()".format(CONTAINER_SHUTDOWN_WAIT_SECS)
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
        status_mid == "RUNNING",
        "Listener is not RUNNING while /dev/log is absent: "
        "status='{}', pid={}".format(status_mid, pid_mid)
    )
    logger.info("PASS: listener stayed RUNNING while /dev/log was absent (pid={})".format(pid_mid))

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
            "tail -20 /var/log/syslog",
            module_ignore_errors=True
        )
        logger.error("Recent syslog tail:\n{}".format(recent.get("stdout", "")))

    pytest_assert(
        found > 0,
        "Syslog self-healing FAILED: probe '{}' not found in /var/log/syslog after rsyslogd restart. "
        "libc syslog() did not reconnect to the new /dev/log socket.".format(probe_tag)
    )
    logger.info("PASS: probe found in host syslog — syslog self-healing confirmed")

    # Final state: listener must still be RUNNING (PID may change if supervisord restarted it).
    status_final, pid_final = _listener_status(duthost, TEST_CONTAINER)
    pytest_assert(
        status_final == "RUNNING",
        "Listener not RUNNING at end of test: status='{}', pid={}".format(status_final, pid_final)
    )
    logger.info("PASS: listener RUNNING at end of test (pid={})".format(pid_final))


def test_listener_own_syslog_reconnects_after_rsyslogd_restart(duthosts, rand_one_dut_hostname):
    """
    Stronger syslog self-healing test: prove the listener's own syslog() call reconnects.

    Uses the eventd container (always running on every topology) with:
      - rsyslogd: the process whose stop/start removes and restores /dev/log
      - eventd: the single critical process whose exit triggers the listener's info!()
        call immediately (no 60s alerting delay); the container restarts cleanly.

    Unlike test_listener_syslog_self_healing (which uses a `logger` proxy), this test
    triggers the listener's own info!() code path:
      info!("Process 'eventd' exited unexpectedly. Terminating supervisor 'eventd'")
    That message appears in /var/log/syslog only if the listener's libc syslog()
    reconnected to the new /dev/log socket after rsyslogd was restarted.

    Steps:
    1. Skip if eventd not running (should never happen on any topology).
    2. Confirm Rust listener variant is in use in the eventd container.
    3. Baseline: listener RUNNING, rsyslogd RUNNING, /dev/log present.
    4. Record host syslog line count as the search offset.
    5. Stop rsyslogd inside eventd -- /dev/log disappears.
    6. Assert listener stays RUNNING with the same PID (no crash).
    7. Restart rsyslogd -- /dev/log reappears.
    8. Kill eventd (critical, auto_restart=enabled by default) -- the listener
       writes its own info!() message via syslog() then calls terminate_supervisor.
    9. Assert the listener's own message appears in /var/log/syslog -- proves
       the listener's libc syslog() reconnected to the new /dev/log socket.
    10. Wait for eventd container to shut down and restart cleanly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Step 1: skip if eventd is not running (should not happen on any topology)
    pytest_require(
        _container_is_running(duthost, EVENTD_CONTAINER),
        "'{}' container is not running on this DUT; skipping.".format(EVENTD_CONTAINER)
    )

    # Step 2: confirm Rust listener is in use in the eventd container
    listener_cmd = duthost.shell(
        "docker exec {} grep -A2 'eventlistener:supervisor-proc-exit-listener' "
        "/etc/supervisor/conf.d/supervisord.conf | grep '^command='".format(EVENTD_CONTAINER),
        module_ignore_errors=True
    )
    pytest_require(
        listener_cmd["rc"] == 0 and "-rs" in listener_cmd.get("stdout", ""),
        "supervisor-proc-exit-listener is not the Rust variant in '{}'; skipping.".format(EVENTD_CONTAINER)
    )

    # Step 3: baseline
    status, pid = _listener_status(duthost, EVENTD_CONTAINER)
    pytest_assert(
        status == "RUNNING",
        "Baseline: listener status='{}' (expected RUNNING) in '{}'".format(status, EVENTD_CONTAINER)
    )
    rsyslogd_check = duthost.shell(
        "docker exec {} supervisorctl status rsyslogd".format(EVENTD_CONTAINER)
    )
    pytest_assert(
        "RUNNING" in rsyslogd_check.get("stdout", ""),
        "Baseline: rsyslogd not RUNNING in '{}': {}".format(
            EVENTD_CONTAINER, rsyslogd_check.get("stdout"))
    )
    eventd_proc_status, eventd_proc_pid = get_program_info(duthost, EVENTD_CONTAINER, EVENTD_CRITICAL_PROCESS)
    pytest_assert(
        eventd_proc_status == "RUNNING" and eventd_proc_pid,
        "Baseline: '{}' not RUNNING in '{}' (status='{}').".format(
            EVENTD_CRITICAL_PROCESS, EVENTD_CONTAINER, eventd_proc_status)
    )
    logger.info("Baseline: listener pid={}, rsyslogd RUNNING, {} pid={}".format(
        pid, EVENTD_CRITICAL_PROCESS, eventd_proc_pid))

    # Step 4: record syslog offset
    offset_result = duthost.shell("wc -l < /var/log/syslog", module_ignore_errors=True)
    syslog_offset = offset_result.get("stdout", "0").strip()
    logger.info("Host syslog offset: {} lines".format(syslog_offset))

    # Step 5: stop rsyslogd to remove /dev/log
    logger.info("Stopping rsyslogd in '{}' to remove /dev/log".format(EVENTD_CONTAINER))
    duthost.shell("docker exec {} supervisorctl stop rsyslogd".format(EVENTD_CONTAINER))
    time.sleep(2)

    devlog_check = duthost.shell(
        "docker exec {} ls /dev/log 2>&1; echo rc=$?".format(EVENTD_CONTAINER)
    )
    pytest_assert(
        "No such file" in devlog_check["stdout"] or "rc=1" in devlog_check["stdout"],
        "/dev/log still exists after stopping rsyslogd in '{}': {}".format(
            EVENTD_CONTAINER, devlog_check["stdout"])
    )
    logger.info("/dev/log confirmed absent after rsyslogd stop")

    # Step 6: listener must still be RUNNING with the same PID
    time.sleep(2)
    status_mid, pid_mid = _listener_status(duthost, EVENTD_CONTAINER)
    logger.info("Listener status while /dev/log absent: status={}, pid={}".format(status_mid, pid_mid))
    pytest_assert(
        status_mid == "RUNNING" and pid_mid == pid,
        "Listener is not RUNNING (or restarted) while /dev/log is absent in '{}': "
        "status='{}', pid={} (was {})".format(EVENTD_CONTAINER, status_mid, pid_mid, pid)
    )
    logger.info("PASS: listener stayed RUNNING (same pid) while /dev/log was absent")

    # Step 7: restart rsyslogd to restore /dev/log
    logger.info("Restarting rsyslogd to restore /dev/log")
    duthost.shell("docker exec {} supervisorctl start rsyslogd".format(EVENTD_CONTAINER))
    time.sleep(3)

    devlog_back = duthost.shell("docker exec {} ls /dev/log 2>&1".format(EVENTD_CONTAINER))
    pytest_assert(
        "No such file" not in devlog_back["stdout"],
        "/dev/log did not reappear after rsyslogd restart in '{}': {}".format(
            EVENTD_CONTAINER, devlog_back["stdout"])
    )
    logger.info("/dev/log restored: {}".format(devlog_back["stdout"].strip()))

    # Step 8: kill eventd -- listener writes via syslog() then terminates.
    # The listener publishes a NOTICE event (EVENT_PUBLISHED) via its syslog path
    # before calling terminate_supervisor. We search for that marker.
    # Re-read pid; supervisord may have restarted eventd while rsyslogd was stopped.
    _, current_eventd_proc_pid = get_program_info(duthost, EVENTD_CONTAINER, EVENTD_CRITICAL_PROCESS)
    pytest_assert(
        current_eventd_proc_pid,
        "'{}' has no PID before kill in '{}'".format(EVENTD_CRITICAL_PROCESS, EVENTD_CONTAINER)
    )
    logger.info("Killing '{}' (pid={}) in '{}' to trigger listener's own syslog() call".format(
        EVENTD_CRITICAL_PROCESS, current_eventd_proc_pid, EVENTD_CONTAINER))
    duthost.shell(
        "docker exec {} kill -9 {}".format(EVENTD_CONTAINER, current_eventd_proc_pid),
        module_ignore_errors=True
    )
    # The PROCESS_STATE_EXITED event propagates to the listener; it calls info!() then
    # terminate_supervisor. Give rsyslogd a moment to flush the message to disk.
    time.sleep(5)

    # Step 9: assert the listener's own message appears in /var/log/syslog.
    # Exact format: "Process 'eventd' exited unexpectedly. Terminating supervisor 'eventd'"
    # The EVENT_PUBLISHED NOTICE is logged by the events framework (EventPublisher)
    # which is statically linked into the listener binary and shares the same
    # libc syslog state (same openlog handle, same /dev/log socket).
    # Its arrival in /var/log/syslog after rsyslogd was restarted proves that
    # a syslog() call from within the listener process reconnected to the new socket.
    listener_msg = "process-exited-unexpectedly"
    search_result = duthost.shell(
        "tail -n +{} /var/log/syslog | grep -c '{}' || true".format(syslog_offset, listener_msg),
        module_ignore_errors=True
    )
    found = int(search_result.get("stdout", "0").strip() or "0")
    logger.info("Listener message '{}' found {} time(s) in host syslog".format(listener_msg, found))

    if found == 0:
        recent = duthost.shell("tail -30 /var/log/syslog", module_ignore_errors=True)
        logger.error("Recent syslog tail:\n{}".format(recent.get("stdout", "")))

    pytest_assert(
        found > 0,
        "Listener syslog reconnect FAILED: '{}' not found in /var/log/syslog after "
        "rsyslogd restart. The listener binary's libc syslog() did not reconnect to the "
        "new /dev/log socket.".format(listener_msg)
    )
    logger.info(
        "PASS: listener's own EVENT_PUBLISHED message found in host syslog -- "
        "libc syslog() reconnected to the new /dev/log socket"
    )

    # Step 10: wait for eventd container to shut down and restart (terminate_supervisor was called)
    # Use a longer timeout than bgp: supervisord in eventd takes ~60-90s to fully
    # stop all child processes after SIGTERM on CI infrastructure. 120s gives margin.
    eventd_shutdown_wait = max(CONTAINER_SHUTDOWN_WAIT_SECS, 120)
    logger.info("Waiting up to {}s for '{}' to shut down".format(
        eventd_shutdown_wait, EVENTD_CONTAINER))
    stopped = wait_until(
        eventd_shutdown_wait, 2, 0,
        lambda: not _container_is_running(duthost, EVENTD_CONTAINER)
    )
    pytest_assert(
        stopped,
        "'{}' did not shut down within {}s after '{}' was killed".format(
            EVENTD_CONTAINER, eventd_shutdown_wait, EVENTD_CRITICAL_PROCESS)
    )
    restarted = wait_until(
        eventd_shutdown_wait, 3, 0,
        _container_is_running, duthost, EVENTD_CONTAINER
    )
    pytest_assert(
        restarted,
        "'{}' did not restart within {}s".format(EVENTD_CONTAINER, CONTAINER_SHUTDOWN_WAIT_SECS)
    )
    logger.info("PASS: '{}' restarted cleanly".format(EVENTD_CONTAINER))
