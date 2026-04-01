import pytest
import re
import time
import base64
from spytest import st, SpyTestDict

data = SpyTestDict()

MONITRC = "/etc/monit/monitrc"
MONIT_CONF = "/etc/monit/conf.d/sonic-host"
CHECK_SCRIPT = "/usr/local/bin/memory_threshold_check.py"
HANDLER_SCRIPT = "/usr/local/bin/memory_threshold_check_handler.py"
STRESS_SCRIPT = "/home/admin/mem_stress.py"

MONITRC_BAK = "/tmp/monitrc.bak.memTest"
MONIT_CONF_BAK = "/tmp/sonic-host.bak.memTest"

DAEMON_INTERVAL = 15
START_DELAY = 10
TRIGGER_COUNT = 2
WITHIN_CYCLES = 3
REPEAT_CYCLES = 2

MAX_WAIT_INITIAL = DAEMON_INTERVAL * (WITHIN_CYCLES + 7)
MAX_WAIT_REPEAT = DAEMON_INTERVAL * (REPEAT_CYCLES + 5)

AUTO_TECHSUPPORT_KEY = "AUTO_TECHSUPPORT|GLOBAL"
THRESHOLD_FIELD = "available_mem_threshold"

STRESS_SCRIPT_CONTENT = """\
#!/usr/bin/env python3
import sys, time
target = int(sys.argv[1])
f = open("/proc/meminfo")
lines = f.readlines()
f.close()
total_kb = int(lines[0].split()[1])
avail_kb = int(lines[2].split()[1])
need_kb = max(int(total_kb * target / 100) - (total_kb - avail_kb), 0)
if need_kb > 0:
    data = bytearray(need_kb * 1024)
    for i in range(0, len(data), 4096):
        data[i] = 1
time.sleep(600)
"""


def parse_first_int(output, default=0):
    """Extract the first integer from st.config output, ignoring prompts."""
    match = re.search(r'\b(\d+)\b', output)
    return int(match.group(1)) if match else default


def get_memory_usage_percent(dut):
    """Return current system memory usage as an integer percentage."""
    out = st.config(
        dut,
        'python3 -c "import psutil; print(int(psutil.virtual_memory().percent))"'
    )
    pct = parse_first_int(out, default=0)
    st.log("get_memory_usage_percent raw output: '{}' -> {}%".format(
        out.strip() if out else "", pct))
    return pct


def get_syslog_line_count(dut):
    """Return current syslog line count for use as a search baseline."""
    out = st.config(dut, "wc -l /var/log/syslog")
    return parse_first_int(out, default=0)


def count_handler_triggers(dut, syslog_start):
    """Count 'Memory threshold crossed' messages in syslog since baseline."""
    out = st.config(
        dut,
        "tail -n +{} /var/log/syslog "
        "| grep -c 'Memory threshold crossed' || echo 0".format(syslog_start + 1)
    )
    return parse_first_int(out, default=0)


def count_specific_threshold_triggers(dut, syslog_start, threshold_pct):
    """Count handler triggers for a specific threshold (e.g. '60%') since baseline."""
    out = st.config(
        dut,
        "tail -n +{} /var/log/syslog "
        "| grep -c 'Memory threshold crossed: {}' || echo 0".format(
            syslog_start + 1, threshold_pct)
    )
    return parse_first_int(out, default=0)


def dump_handler_syslog(dut, syslog_start):
    """Fetch and log all memory handler syslog entries since baseline."""
    out = st.config(
        dut,
        "tail -n +{} /var/log/syslog "
        "| grep -E 'memory_threshold_check_handler|Memory threshold crossed"
        "|memory-consuming|Current memory'".format(syslog_start + 1)
    )
    st.log("=== memory_threshold_check_handler syslog entries ===\n{}".format(out))
    return out


def set_memory_threshold(dut, value):
    """Set available_mem_threshold in CONFIG_DB."""
    st.log("Setting {} to {} in CONFIG_DB".format(THRESHOLD_FIELD, value))
    st.config(
        dut,
        'sonic-db-cli CONFIG_DB HSET "{}" "{}" "{}"'.format(
            AUTO_TECHSUPPORT_KEY, THRESHOLD_FIELD, value)
    )


def start_memory_stress(dut, target_pct):
    """Start background process to consume memory up to target_pct usage."""
    st.log("Starting memory stress targeting {}% usage".format(target_pct))
    st.config(dut, "nohup python3 {} {} > /dev/null 2>&1 &".format(
        STRESS_SCRIPT, target_pct))
    time.sleep(5)
    actual = get_memory_usage_percent(dut)
    st.log("Memory usage after stress start: {}%".format(actual))
    return actual


def stop_memory_stress(dut):
    """Kill memory stress processes."""
    st.log("Stopping memory stress processes")
    st.config(dut, "pkill -f mem_stress || true")
    time.sleep(2)


@pytest.fixture(scope="module", autouse=True)
def memory_threshold_module_hooks():
    global vars
    vars = st.ensure_min_topology("D1")
    memory_threshold_pre_config()
    yield
    memory_threshold_post_config()


def memory_threshold_pre_config():
    """Backup monit configs, create stress script, apply faster cycle parameters."""
    dut = vars.D1

    st.log("Saving original {} from CONFIG_DB".format(THRESHOLD_FIELD))
    out = st.config(
        dut,
        'sonic-db-cli CONFIG_DB HGET "{}" "{}"'.format(
            AUTO_TECHSUPPORT_KEY, THRESHOLD_FIELD)
    )
    stripped = out.strip() if out else ""
    data.original_threshold = stripped if re.match(r'^[\d.]+$', stripped) else ""
    st.log("Original threshold value: '{}'".format(data.original_threshold))

    st.log("Backing up monit configuration files")
    st.config(dut, "cp {} {}".format(MONITRC, MONITRC_BAK))
    st.config(dut, "cp {} {}".format(MONIT_CONF, MONIT_CONF_BAK))

    st.log("Creating memory stress script at {}".format(STRESS_SCRIPT))
    encoded = base64.b64encode(STRESS_SCRIPT_CONTENT.encode()).decode()
    st.config(dut, "echo '{}' | base64 -d > {}".format(encoded, STRESS_SCRIPT))
    st.config(dut, "chmod +x {}".format(STRESS_SCRIPT))

    st.log("Reducing monit daemon interval to {}s and start delay to {}s".format(
        DAEMON_INTERVAL, START_DELAY))
    st.config(dut, "sed -i 's/set daemon 60/set daemon {}/' {}".format(
        DAEMON_INTERVAL, MONITRC))
    st.config(dut, "sed -i 's/with start delay 300/with start delay {}/' {}".format(
        START_DELAY, MONITRC))

    st.log("Adjusting memory_check to {} times within {} cycles, "
           "repeat every {} cycles".format(TRIGGER_COUNT, WITHIN_CYCLES, REPEAT_CYCLES))
    st.config(dut, (
        r"sed -i '/memory_threshold_check_handler/s/"
        r"for [0-9]\+ times within [0-9]\+ cycles/"
        "for {} times within {} cycles/g' {}".format(
            TRIGGER_COUNT, WITHIN_CYCLES, MONIT_CONF)
    ))
    st.config(dut, (
        r"sed -i '/memory_threshold_check_handler/s/"
        r"repeat every [0-9]\+ cycles/"
        "repeat every {} cycles/g' {}".format(REPEAT_CYCLES, MONIT_CONF)
    ))

    st.log("Restarting monit with updated configuration")
    st.config(dut, "systemctl restart monit")
    time.sleep(5)

    status = st.config(dut, "systemctl is-active monit")
    st.log("Monit status after restart: {}".format(status.strip()))


def memory_threshold_post_config():
    """Kill stress, remove script, restore monit configs and CONFIG_DB threshold."""
    dut = vars.D1

    st.log("Cleaning up memory stress processes")
    stop_memory_stress(dut)
    st.config(dut, "rm -f {}".format(STRESS_SCRIPT))

    st.log("Restoring original {} in CONFIG_DB".format(THRESHOLD_FIELD))
    if data.original_threshold:
        st.config(
            dut,
            'sonic-db-cli CONFIG_DB HSET "{}" "{}" "{}"'.format(
                AUTO_TECHSUPPORT_KEY, THRESHOLD_FIELD, data.original_threshold)
        )
    else:
        st.config(
            dut,
            'sonic-db-cli CONFIG_DB HDEL "{}" "{}"'.format(
                AUTO_TECHSUPPORT_KEY, THRESHOLD_FIELD)
        )

    st.log("Restoring original monit configuration files")
    st.config(dut, "cp {} {}".format(MONITRC_BAK, MONITRC))
    st.config(dut, "cp {} {}".format(MONIT_CONF_BAK, MONIT_CONF))
    st.config(dut, "rm -f {} {}".format(MONITRC_BAK, MONIT_CONF_BAK))

    st.log("Restarting monit with original configuration")
    st.config(dut, "systemctl restart monit")


def test_monit_service_running():
    """Verify monit service is active after configuration changes."""
    dut = vars.D1
    output = st.config(dut, "systemctl is-active monit && echo MONIT_OK || echo MONIT_DOWN")
    if "MONIT_DOWN" in output:
        st.error("Monit service is not running after config modification and restart")
        st.report_fail("operation_failed")
    st.report_pass("test_case_passed")


def test_monit_memory_check_configured():
    """Verify memory_check scripts exist and monit config has speed-up parameters."""
    dut = vars.D1

    output = st.config(dut, "ls {} {} 2>&1".format(CHECK_SCRIPT, HANDLER_SCRIPT))
    if "No such file" in output:
        st.error("Memory threshold scripts not found on DUT: {}".format(output.strip()))
        st.report_fail("operation_failed")

    output = st.config(dut, "grep -A5 'check program memory_check' {}".format(MONIT_CONF))
    st.log("memory_check monit config:\n{}".format(output))

    expected_trigger = "for {} times within {} cycles".format(TRIGGER_COUNT, WITHIN_CYCLES)
    expected_repeat = "repeat every {} cycles".format(REPEAT_CYCLES)

    if expected_trigger not in output:
        st.error("memory_check trigger parameters not correctly set: "
                 "expected '{}'".format(expected_trigger))
        st.report_fail("operation_failed")
    if expected_repeat not in output:
        st.error("memory_check repeat parameter not correctly set: "
                 "expected '{}'".format(expected_repeat))
        st.report_fail("operation_failed")

    st.report_pass("test_case_passed")


def test_memory_configurable_threshold_triggered():
    """
    Set available_mem_threshold to 99% so the check script returns exit code 2
    on every cycle (no system has 99% free memory). Verify monit triggers the
    handler and the handler logs top memory consumer details.
    """
    dut = vars.D1

    set_memory_threshold(dut, 99)
    time.sleep(2)

    syslog_start = get_syslog_line_count(dut)
    data.syslog_start_configurable = syslog_start
    st.log("Syslog baseline at line: {}".format(syslog_start))

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    triggered = False

    st.log("Polling for configurable threshold handler trigger "
           "(max wait: {}s)".format(MAX_WAIT_INITIAL))
    while elapsed < MAX_WAIT_INITIAL:
        time.sleep(poll_interval)
        elapsed += poll_interval
        count = count_handler_triggers(dut, syslog_start)
        if count >= 1:
            triggered = True
            st.log("Handler triggered after ~{}s (count: {})".format(elapsed, count))
            break
        st.log("Not yet triggered after {}s, polling...".format(elapsed))

    if not triggered:
        monit_out = st.config(dut, "monit status 2>&1 | head -40")
        st.log("Monit status at failure:\n{}".format(monit_out))
        st.error("Memory configurable threshold handler was not triggered by monit "
                 "within {}s".format(MAX_WAIT_INITIAL))
        st.report_fail("operation_failed")

    handler_log = dump_handler_syslog(dut, syslog_start)

    if "Top 5 memory-consuming" not in handler_log:
        st.error("Handler triggered but did not log top memory consumer details")
        st.report_fail("operation_failed")

    st.report_pass("test_case_passed")


def test_memory_configurable_threshold_repeat():
    """
    With available_mem_threshold still at 99%, verify monit re-triggers the
    handler after the configured repeat interval (repeat every 2 cycles).
    """
    dut = vars.D1

    syslog_start = data.get("syslog_start_configurable", 0)
    if not syslog_start:
        st.error("No syslog baseline from configurable threshold test")
        st.report_fail("operation_failed")

    initial_count = count_handler_triggers(dut, syslog_start)
    st.log("Handler trigger count before repeat wait: {}".format(initial_count))

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    repeated = False

    st.log("Polling for repeat trigger (need count > {}, max wait: {}s)".format(
        initial_count, MAX_WAIT_REPEAT))
    while elapsed < MAX_WAIT_REPEAT:
        time.sleep(poll_interval)
        elapsed += poll_interval
        current_count = count_handler_triggers(dut, syslog_start)
        st.log("Trigger count after {}s: {} (need > {})".format(
            elapsed, current_count, initial_count))
        if current_count > initial_count:
            repeated = True
            st.log("Repeat trigger detected after ~{}s (count: {} -> {})".format(
                elapsed, initial_count, current_count))
            break

    if not repeated:
        monit_out = st.config(dut, "monit status 2>&1 | head -40")
        st.log("Monit status at failure:\n{}".format(monit_out))
        st.error("Memory threshold handler was not re-triggered within {}s "
                 "(repeat every {} cycles)".format(MAX_WAIT_REPEAT, REPEAT_CYCLES))
        st.report_fail("operation_failed")

    dump_handler_syslog(dut, syslog_start)
    st.report_pass("test_case_passed")


def test_memory_fixed_60_threshold_triggered():
    """
    Set available_mem_threshold to 1% (disables configurable trigger) and
    verify the 60% fixed threshold (exit code 3) fires. Stresses memory
    to ~65% if the system is not already above 60%.
    """
    dut = vars.D1

    stop_memory_stress(dut)
    set_memory_threshold(dut, 1)
    st.log("Waiting for monit to transition from configurable threshold")
    time.sleep(DAEMON_INTERVAL + 5)

    current_usage = get_memory_usage_percent(dut)
    st.log("Baseline memory usage: {}%".format(current_usage))

    if current_usage < 60:
        st.log("Memory below 60%, stressing to 65%")
        current_usage = start_memory_stress(dut, 65)
        data.stress_running = True
        if current_usage < 60:
            stop_memory_stress(dut)
            data.stress_running = False
            st.error("Could not push memory above 60% (at {}%)".format(current_usage))
            st.report_fail("operation_failed")
    else:
        data.stress_running = False

    if current_usage >= 80:
        st.log("Baseline usage is {}% (above 80%), check will return exit 4/5 "
               "instead of 3 -- stressing to exactly 65%".format(current_usage))
        stop_memory_stress(dut)
        current_usage = start_memory_stress(dut, 65)
        data.stress_running = True

    syslog_start = get_syslog_line_count(dut)
    st.log("Syslog baseline at line: {}".format(syslog_start))

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    triggered = False

    st.log("Polling for 60% threshold handler (max wait: {}s)".format(MAX_WAIT_INITIAL))
    while elapsed < MAX_WAIT_INITIAL:
        time.sleep(poll_interval)
        elapsed += poll_interval
        count = count_specific_threshold_triggers(dut, syslog_start, "60%")
        if count >= 1:
            triggered = True
            st.log("60% handler triggered after ~{}s".format(elapsed))
            break
        st.log("Not yet triggered after {}s, polling...".format(elapsed))

    if not triggered:
        handler_log = dump_handler_syslog(dut, syslog_start)
        monit_out = st.config(dut, "monit status 2>&1 | head -40")
        st.log("Monit status:\n{}".format(monit_out))
        st.error("60% memory threshold handler not triggered within {}s".format(
            MAX_WAIT_INITIAL))
        st.report_fail("operation_failed")

    handler_log = dump_handler_syslog(dut, syslog_start)
    if "Memory threshold crossed: 60%" not in handler_log:
        st.error("Handler log missing 'Memory threshold crossed: 60%'")
        st.report_fail("operation_failed")

    st.report_pass("test_case_passed")


def test_memory_60_to_80_threshold_transition():
    """
    With monit already triggering the 60% handler from the previous test,
    push memory to ~82% and verify monit detects the transition: exit code
    changes from 3 (60%) to 4 (80%), and the 80% handler fires.
    """
    dut = vars.D1

    set_memory_threshold(dut, 1)
    stop_memory_stress(dut)
    time.sleep(3)

    st.log("Stressing memory to 82% to cross the 80% threshold")
    current_usage = start_memory_stress(dut, 82)
    data.stress_running = True

    if current_usage < 80:
        stop_memory_stress(dut)
        data.stress_running = False
        st.error("Could not push memory above 80% (at {}%)".format(current_usage))
        st.report_fail("operation_failed")

    st.log("Memory at {}%, expecting monit to transition to 80% handler".format(
        current_usage))

    syslog_start = get_syslog_line_count(dut)
    st.log("Syslog baseline at line: {}".format(syslog_start))

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    triggered = False

    st.log("Polling for 80% threshold handler (max wait: {}s)".format(MAX_WAIT_INITIAL))
    while elapsed < MAX_WAIT_INITIAL:
        time.sleep(poll_interval)
        elapsed += poll_interval
        count = count_specific_threshold_triggers(dut, syslog_start, "80%")
        if count >= 1:
            triggered = True
            st.log("80% handler triggered after ~{}s".format(elapsed))
            break
        st.log("Not yet triggered after {}s, polling...".format(elapsed))

    if not triggered:
        handler_log = dump_handler_syslog(dut, syslog_start)
        monit_out = st.config(dut, "monit status 2>&1 | head -40")
        st.log("Monit status:\n{}".format(monit_out))
        st.error("80% memory threshold handler not triggered within {}s "
                 "(transition from 60% to 80%)".format(MAX_WAIT_INITIAL))
        st.report_fail("operation_failed")

    handler_log = dump_handler_syslog(dut, syslog_start)
    if "Memory threshold crossed: 80%" not in handler_log:
        st.error("Handler log missing 'Memory threshold crossed: 80%'")
        st.report_fail("operation_failed")

    if "Top 5 memory-consuming" not in handler_log:
        st.error("80% handler did not log top memory consumer details")
        st.report_fail("operation_failed")

    st.report_pass("test_case_passed")


def test_memory_fixed_90_threshold_triggered():
    """
    Push memory to ~92% and verify the 90% fixed threshold (exit code 5)
    fires. This also tests the transition from the 80% band to the 90% band.
    """
    dut = vars.D1

    set_memory_threshold(dut, 1)
    stop_memory_stress(dut)
    time.sleep(3)

    st.log("Stressing memory to 92% to cross the 90% threshold")
    current_usage = start_memory_stress(dut, 92)
    data.stress_running = True

    if current_usage < 90:
        stop_memory_stress(dut)
        data.stress_running = False
        st.error("Could not push memory above 90% (at {}%). "
                 "System may not have enough total memory for safe 90% stress".format(
                     current_usage))
        st.report_fail("operation_failed")

    st.log("Memory at {}%, expecting 90% handler".format(current_usage))

    syslog_start = get_syslog_line_count(dut)
    st.log("Syslog baseline at line: {}".format(syslog_start))

    poll_interval = DAEMON_INTERVAL
    elapsed = 0
    triggered = False

    st.log("Polling for 90% threshold handler (max wait: {}s)".format(MAX_WAIT_INITIAL))
    while elapsed < MAX_WAIT_INITIAL:
        time.sleep(poll_interval)
        elapsed += poll_interval
        count = count_specific_threshold_triggers(dut, syslog_start, "90%")
        if count >= 1:
            triggered = True
            st.log("90% handler triggered after ~{}s".format(elapsed))
            break
        st.log("Not yet triggered after {}s, polling...".format(elapsed))

    stop_memory_stress(dut)
    data.stress_running = False

    if not triggered:
        handler_log = dump_handler_syslog(dut, syslog_start)
        monit_out = st.config(dut, "monit status 2>&1 | head -40")
        st.log("Monit status:\n{}".format(monit_out))
        st.error("90% memory threshold handler not triggered within {}s".format(
            MAX_WAIT_INITIAL))
        st.report_fail("operation_failed")

    handler_log = dump_handler_syslog(dut, syslog_start)
    if "Memory threshold crossed: 90%" not in handler_log:
        st.error("Handler log missing 'Memory threshold crossed: 90%'")
        st.report_fail("operation_failed")

    if "Top 5 memory-consuming" not in handler_log:
        st.error("90% handler did not log top memory consumer details")
        st.report_fail("operation_failed")

    st.report_pass("test_case_passed")


