import pytest
import re
import time
from spytest import st, SpyTestDict

data = SpyTestDict()

MONITRC = "/etc/monit/monitrc"
MONIT_CONF = "/etc/monit/conf.d/sonic-host"
STRESS_SCRIPT = "/home/admin/cpu_stress_test.sh"

MONITRC_BAK = "/tmp/monitrc.bak.cpuTest"
MONIT_CONF_BAK = "/tmp/sonic-host.bak.cpuTest"

DAEMON_INTERVAL = 15
START_DELAY = 10
TRIGGER_COUNT = 2
WITHIN_CYCLES = 3
REPEAT_CYCLES = 2

MAX_WAIT_INITIAL = DAEMON_INTERVAL * (WITHIN_CYCLES + 7)
MAX_WAIT_REPEAT = DAEMON_INTERVAL * (REPEAT_CYCLES + 5)


def parse_first_int(output, default=0):
    """Extract the first integer from st.config output, ignoring prompts."""
    match = re.search(r'\b(\d+)\b', output)
    if match:
        return int(match.group(1))
    return default


@pytest.fixture(scope="module", autouse=True)
def cpu_threshold_module_hooks():
    global vars
    vars = st.ensure_min_topology("D1")
    cpu_threshold_pre_config()
    yield
    cpu_threshold_post_config()


def cpu_threshold_pre_config():
    """Backup original monit configs, create stress script, apply faster cycle parameters"""
    dut = vars.D1

    st.log("Backing up original monit configuration files")
    st.config(dut, "cp {} {}".format(MONITRC, MONITRC_BAK))
    st.config(dut, "cp {} {}".format(MONIT_CONF, MONIT_CONF_BAK))

    st.log("Creating CPU stress script at {}".format(STRESS_SCRIPT))
    st.config(dut, "printf '#!/bin/bash\\nwhile true; do : ; done\\n' > {}".format(STRESS_SCRIPT))
    st.config(dut, "chmod +x {}".format(STRESS_SCRIPT))

    st.log("Reducing monit daemon interval to {}s and start delay to {}s".format(
        DAEMON_INTERVAL, START_DELAY))
    st.config(dut, "sed -i 's/set daemon 60/set daemon {}/' {}".format(
        DAEMON_INTERVAL, MONITRC))
    st.config(dut, "sed -i 's/with start delay 300/with start delay {}/' {}".format(
        START_DELAY, MONITRC))

    st.log("Adjusting CPU threshold to {} times within {} cycles, repeat every {}".format(
        TRIGGER_COUNT, WITHIN_CYCLES, REPEAT_CYCLES))
    st.config(dut, "sed -i 's/for 10 times within 20 cycles/for {} times within {} cycles/g' {}".format(
        TRIGGER_COUNT, WITHIN_CYCLES, MONIT_CONF))
    st.config(dut, "sed -i 's/repeat every 10 cycles/repeat every {} cycles/g' {}".format(
        REPEAT_CYCLES, MONIT_CONF))

    st.log("Restarting monit with updated configuration")
    st.config(dut, "systemctl restart monit")
    time.sleep(5)

    restart_check = st.config(dut, "systemctl is-active monit")
    st.log("Monit status after restart: {}".format(restart_check.strip()))


def cpu_threshold_post_config():
    """Kill stress processes, remove stress script, restore original monit configuration"""
    dut = vars.D1

    st.log("Killing any remaining CPU stress processes")
    st.config(dut, "pkill -f cpu_stress_test || true")

    st.log("Removing CPU stress script")
    st.config(dut, "rm -f {}".format(STRESS_SCRIPT))

    st.log("Restoring original monit configuration files")
    st.config(dut, "cp {} {}".format(MONITRC_BAK, MONITRC))
    st.config(dut, "cp {} {}".format(MONIT_CONF_BAK, MONIT_CONF))
    st.config(dut, "rm -f {} {}".format(MONITRC_BAK, MONIT_CONF_BAK))

    st.log("Restarting monit with original configuration")
    st.config(dut, "systemctl restart monit")


def start_cpu_stress(dut):
    """Start CPU stress on all cores, verify processes are running, return syslog baseline."""
    syslog_lines_out = st.config(dut, "wc -l /var/log/syslog")
    syslog_start = parse_first_int(syslog_lines_out, default=0)
    st.log("Syslog line count at stress start: {}".format(syslog_start))

    cpu_count_out = st.config(dut, "nproc")
    cpu_count = parse_first_int(cpu_count_out, default=4)
    st.log("Detected {} CPU cores, launching stress script on each".format(cpu_count))

    for i in range(cpu_count):
        st.config(dut, "nohup {} > /dev/null 2>&1 &".format(STRESS_SCRIPT))

    time.sleep(3)
    verify_out = st.config(dut, "pgrep -cf cpu_stress_test || echo 0")
    running_count = parse_first_int(verify_out, default=0)
    st.log("Verified {} cpu_stress_test processes running".format(running_count))

    return syslog_start, running_count


def count_handler_triggers(dut, syslog_start):
    """Count how many times the handler has been triggered since syslog_start."""
    count_out = st.config(
        dut,
        "tail -n +{} /var/log/syslog "
        "| grep cpu_threshold_check_handler "
        "| grep -c 'CPU usage threshold handler triggered'".format(syslog_start + 1)
    )
    return parse_first_int(count_out, default=0)


def test_monit_service_running():
    """Verify monit service is active after configuration changes"""
    dut = vars.D1
    output = st.config(dut, "systemctl is-active monit && echo MONIT_OK || echo MONIT_DOWN")
    if "MONIT_DOWN" in output:
        st.error("Monit service is not running after config modification and restart")
        st.report_fail("operation_failed")
    st.report_pass("test_case_passed")


def test_cpu_threshold_handler_triggered_by_monit():
    """
    Generate sustained high CPU load and verify monit triggers
    cpu_threshold_check_handler.py. Stress is kept running for the
    repeat test that follows.
    """
    dut = vars.D1

    syslog_start, running_count = start_cpu_stress(dut)
    data.syslog_start = syslog_start
    data.stress_running = True

    if running_count < 1:
        data.stress_running = False
        st.error("CPU stress processes failed to start, cannot proceed with test")
        st.report_fail("operation_failed")

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    triggered = False

    st.log("Polling syslog for initial handler trigger (max wait: {}s)".format(MAX_WAIT_INITIAL))
    while elapsed < MAX_WAIT_INITIAL:
        time.sleep(poll_interval)
        elapsed += poll_interval
        trigger_count = count_handler_triggers(dut, syslog_start)
        if trigger_count >= 1:
            triggered = True
            st.log("Handler triggered after ~{}s (trigger count: {})".format(elapsed, trigger_count))
            break
        st.log("Handler not yet triggered after {}s, continuing to poll...".format(elapsed))

    if not triggered:
        st.config(dut, "pkill -f cpu_stress_test || true")
        data.stress_running = False
        monit_out = st.config(dut, "monit status 2>&1 | head -30")
        st.log("Monit status at failure:\n{}".format(monit_out))
        st.error("CPU threshold handler was not triggered by monit within {}s "
                 "of sustained high CPU".format(MAX_WAIT_INITIAL))
        st.report_fail("operation_failed")

    process_log = st.config(
        dut,
        "tail -n +{} /var/log/syslog "
        "| grep cpu_threshold_check_handler "
        "| grep 'Top 5 CPU-consuming' "
        "| head -2".format(syslog_start + 1)
    )
    if "Top 5 CPU-consuming" not in process_log:
        st.config(dut, "pkill -f cpu_stress_test || true")
        data.stress_running = False
        st.error("Handler triggered but did not log top CPU consumer details")
        st.report_fail("operation_failed")

    st.log("Initial trigger syslog output:\n{}".format(process_log))
    st.report_pass("test_case_passed")


def test_cpu_threshold_handler_repeat():
    """
    With CPU stress still running from the previous test, verify that monit
    triggers the handler again after the configured repeat interval
    (repeat every 2 cycles = ~30s with daemon=15s).
    """
    dut = vars.D1

    if not data.get("stress_running", False):
        st.error("CPU stress is not running from previous test, cannot verify repeat")
        st.report_fail("operation_failed")

    syslog_start = data.syslog_start
    initial_count = count_handler_triggers(dut, syslog_start)
    st.log("Handler trigger count before repeat wait: {}".format(initial_count))

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    repeated = False

    st.log("Polling syslog for repeat trigger (need count > {}, max wait: {}s)".format(
        initial_count, MAX_WAIT_REPEAT))
    while elapsed < MAX_WAIT_REPEAT:
        time.sleep(poll_interval)
        elapsed += poll_interval
        current_count = count_handler_triggers(dut, syslog_start)
        st.log("Trigger count after {}s: {} (need > {})".format(
            elapsed, current_count, initial_count))
        if current_count > initial_count:
            repeated = True
            st.log("Repeat trigger detected after ~{}s (count went from {} to {})".format(
                elapsed, initial_count, current_count))
            break

    st.log("Stopping CPU stress processes")
    st.config(dut, "pkill -f cpu_stress_test || true")
    data.stress_running = False
    time.sleep(2)

    if not repeated:
        monit_out = st.config(dut, "monit status 2>&1 | head -30")
        st.log("Monit status at failure:\n{}".format(monit_out))
        st.error("CPU threshold handler was not re-triggered by monit within {}s "
                 "(repeat every {} cycles)".format(MAX_WAIT_REPEAT, REPEAT_CYCLES))
        st.report_fail("operation_failed")

    all_triggers = st.config(
        dut,
        "tail -n +{} /var/log/syslog "
        "| grep cpu_threshold_check_handler "
        "| grep 'CPU usage threshold handler triggered'".format(syslog_start + 1)
    )
    st.log("All handler triggers:\n{}".format(all_triggers))
    st.report_pass("test_case_passed")

