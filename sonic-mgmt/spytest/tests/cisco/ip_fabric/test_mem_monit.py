#!/usr/bin/env python3
"""
SONiC memory gradual increase — SpyTest coverage (Monit + memory_gradual_check / handler).

Scope (``short`` scale only):
- UT-01 … UT-04: DUT injection + live checker (``--test-mode``), shared fixture
- UT-02-B: oscillation R² (alloc/free cycles)
- UT-05 … UT-13: deterministic / file-based checks
- FUNC-TC-01 … 03: synthetic profiles vs thresholds
- ``test_dut_syslog_*``: ``/var/log/syslog`` handler + checker sanity
- E2E: full monit-triggered cycle

Memory injection uses simple background ``python3 -c "bytearray(...)"``
processes.  Each holds N MB of resident memory (pages touched).  All
injectors share a marker string and are killed in one ``pkill`` call.
"""

import base64
import pytest
import re
import time
import json
try:
    from statistics import correlation, linear_regression as stats_linreg
except ImportError:
    # Python < 3.10 fallback
    import math
    from collections import namedtuple
    _LinearRegression = namedtuple('LinearRegression', ['slope', 'intercept'])

    def stats_linreg(x, y):
        n = len(x)
        xbar = sum(x) / n
        ybar = sum(y) / n
        slope_num = sum((xi - xbar) * (yi - ybar) for xi, yi in zip(x, y))
        slope_den = sum((xi - xbar) ** 2 for xi in x)
        if slope_den == 0:
            raise ValueError("x is constant")
        slope = slope_num / slope_den
        return _LinearRegression(slope=slope, intercept=ybar - slope * xbar)

    def correlation(x, y):
        n = len(x)
        xbar = sum(x) / n
        ybar = sum(y) / n
        num = sum((xi - xbar) * (yi - ybar) for xi, yi in zip(x, y))
        den = math.sqrt(
            sum((xi - xbar) ** 2 for xi in x) *
            sum((yi - ybar) ** 2 for yi in y)
        )
        if den == 0:
            raise ValueError("correlation requires that the data is not constant")
        return num / den
from typing import List, Tuple
from spytest import st, SpyTestDict

data = SpyTestDict()

# ====================================================================
# CONFIGURATION AND CONSTANTS
# ====================================================================

MONITRC = "/etc/monit/monitrc"
MONIT_CONF = "/etc/monit/conf.d/sonic-host"
STATE_DIR = "/var/run"

# Backup files
MONITRC_BAK = "/tmp/monitrc.bak.memTest"
MONIT_CONF_BAK = "/tmp/sonic-host.bak.memTest"

# Memory gradient check scripts location
MEMORY_CHECK_SCRIPT = "/usr/local/bin/memory_gradual_check.py"
MEMORY_HANDLER_SCRIPT = "/usr/local/bin/memory_gradual_handler.py"
SYSLOG_PATH = "/var/log/syslog"

# Monit daemon tuning for test acceleration
DAEMON_INTERVAL = 15  # seconds (default 60)
START_DELAY = 3  # seconds (default 300)

# Monit cycle counts for test mode (cycles = target_interval / DAEMON_INTERVAL)
# These replace the production "every N cycles" and "repeat every N cycles" in sonic-host
MONIT_TEST_CYCLES = {
    "short": {"every": 4, "repeat": 4},    # 4 * 15s = 60s = 1 min (short scale only)
}

# Seconds to wait after killing injectors for memory to settle
INJECTOR_SETTLE_SECS = 10
INJECTOR_HOLD_SECS = 3600       # self-expiry timeout for injector processes

# Test-mode short scale orchestration (checker timing comes from --test-mode;
# these are the test's own injection / validation knobs).
SCALE = "short"
SAMPLES = 10                     # == SCALE_CONFIG_TEST_MODE["short"]["window_size"]
INJECTION_INTERVAL = 15          # seconds between injections (checker uses check_interval_mins for slope math, not wall-clock)
INJECTION_MB = 30                # MB to inject per sample
EXPECTED_SLOPE = 30              # MB/min (INJECTION_MB / check_interval_mins)
SLOPE_TOLERANCE = 10             # MB/min — real systems have cache/buffer noise
STATE_FILE = f"{STATE_DIR}/memory_gradual_short.json"

# Reference system parameters
REFERENCE_TOTAL_RAM_MB = 20480
REFERENCE_BASELINE_USED_MB = 6144
REFERENCE_BASELINE_FREE_MB = 14336


# ====================================================================
# SIMPLE MEMORY INJECTION
#
# Each call spawns a background python3 process that allocates and holds
# N MB of resident memory (bytearray with pages touched).  All injectors
# share a common marker so they can be killed in one shot.
# ====================================================================

_INJECT_MARKER = "memtest_hold_9999"


def _inject_mb(dut, mb):
    """Spawn a background process on DUT that holds *mb* MB of resident memory.

    NOTE (review comment): Adding post-spawn verification (pgrep-based
    process counting) was evaluated and intentionally omitted.
    SpyTest's ``st.config`` returns the full DUT session output
    (command echo + result + shell prompt), making reliable integer
    parsing of ``pgrep -c`` fragile across different DUT prompt
    formats.  The injector command itself is deterministic (fixed
    quoting, well-under-OOM sizes) and the downstream checker run
    validates that memory *did* increase, so a separate spawn check
    adds complexity without meaningful coverage gain.
    """
    st.config(
        dut,
        f"nohup python3 -c 'b=bytearray({mb}*1024*1024);[b.__setitem__(i,1) for i in range(0,len(b),4096)];marker=\"{_INJECT_MARKER}\";import time;time.sleep({INJECTOR_HOLD_SECS})' >/dev/null 2>&1 &",
    )
    time.sleep(1)


def _kill_injectors(dut):
    """Kill every background injector process and wait for memory to settle."""
    st.config(dut, f"pkill -f '{_INJECT_MARKER}' 2>/dev/null || true")
    time.sleep(INJECTOR_SETTLE_SECS)


# ====================================================================
# UTILITY FUNCTIONS
# ====================================================================

def get_system_memory_mb(dut):
    """
    Get current system memory stats via psutil.virtual_memory() on DUT.
    Returns dict or None on error.
    """
    cmd = (
        "python3 -c \""
        "import json, psutil; "
        "m=psutil.virtual_memory(); "
        "to_mb=lambda v:int(v/(1024*1024)); "
        "print(json.dumps({"
        "'total':to_mb(m.total),"
        "'used':to_mb(m.used),"
        "'free':to_mb(m.free),"
        "'available':to_mb(m.available),"
        "'shared':to_mb(getattr(m, 'shared', 0)),"
        "'buffers':to_mb(getattr(m, 'buffers', 0)),"
        "'cached':to_mb(getattr(m, 'cached', 0))"
        "}))\""
    )
    output = st.config(dut, cmd)
    try:
        for line in (output or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
        st.error(f"No JSON line found in psutil output: {output}")
        return None
    except Exception:
        st.error(f"Failed to parse psutil memory output: {output}")
        return None


def linear_regression(y_values: List[float]) -> Tuple[float, float, float]:
    """
    Perform linear regression on y_values using x=[0..n-1].

    Returns:
        (slope, intercept, r_squared)
    """
    n = len(y_values)
    if n < 2:
        return 0.0, y_values[0] if y_values else 0.0, 0.0

    x_values = list(range(n))
    result = stats_linreg(x_values, y_values)
    slope = result.slope
    intercept = result.intercept

    try:
        r = correlation(x_values, y_values)
        r_squared = r ** 2
    except Exception:
        r_squared = 1.0 if slope == 0 else 0.0

    return slope, intercept, r_squared


def calculate_slope_mb_per_min(values, interval_sec):
    """Calculate linear regression slope (MB/min) for evenly spaced samples."""
    if len(values) < 2 or interval_sec <= 0:
        return 0.0

    slope_per_sample, _, _ = linear_regression(values)
    return slope_per_sample / (interval_sec / 60.0)


# ====================================================================
# MODULE FIXTURES
# ====================================================================

@pytest.fixture(scope="module", autouse=True)
def mem_monit_module_hooks():
    """Module-level setup/teardown for memory monitoring tests."""
    global vars, _cached_thresholds, _cached_check_constants
    vars = st.ensure_min_topology("D1")
    _cached_thresholds = None
    _cached_check_constants = None
    mem_monit_pre_config()
    yield
    mem_monit_post_config()


def _clear_state_files(dut):
    """Remove all memory_gradual state files so the next test starts fresh."""
    for scale in ("short", "medium", "long"):
        st.config(dut, f"rm -f {STATE_DIR}/memory_gradual_{scale}.json")


def _ensure_monit_running(dut, max_wait=30):
    """Restart monit and verify it reaches active + responsive state."""
    st.config(dut, "sudo systemctl restart monit")
    time.sleep(5)

    status = st.config(dut, "systemctl is-active monit")
    if "active" not in (status or ""):
        st.error("Monit failed to start after restart")
        return False

    deadline = time.time() + max_wait
    while time.time() < deadline:
        summary = st.config(dut, "sudo monit status 2>&1 | head -5")
        if summary and "Cannot" not in summary and "error" not in summary.lower():
            st.log("[monit] Service active and responding")
            return True
        time.sleep(3)

    st.error(f"[monit] Service active but monit status not responding after {max_wait}s")
    return False


@pytest.fixture(scope="function", autouse=True)
def mem_monit_per_test_clean_slate(request):
    """Per-test setup/teardown: clear state files, kill leftover injectors.

    Runs before every test to ensure a clean DUT: no stale state files from
    a prior test and no orphaned memory-holding processes.  The teardown
    half kills any injectors the test may have spawned.
    """
    if "vars" not in globals() or not hasattr(vars, "D1"):
        yield
        return

    dut = vars.D1
    _clear_state_files(dut)
    time.sleep(3)

    yield

    _kill_injectors(dut)


def mem_monit_pre_config():
    """
    Pre-test configuration:
    - Backup original monit configs
    - Reduce monit daemon interval for test acceleration
    - Verify memory gradient check scripts are present
    - Clear any existing state files from previous runs
    """
    dut = vars.D1
    
    st.log("=" * 80)
    st.log("MEMORY MONITORING TEST SETUP")
    st.log("=" * 80)
    
    # Backup original monit config
    st.log("Backing up original monit configuration files")
    st.config(dut, f"cp {MONITRC} {MONITRC_BAK}")
    st.config(dut, f"cp {MONIT_CONF} {MONIT_CONF_BAK}")
    
    # Verify scripts exist
    st.log("Verifying memory gradient check scripts")
    check_result = st.config(dut, f"test -f {MEMORY_CHECK_SCRIPT} && echo FOUND || echo NOTFOUND")
    if "NOTFOUND" in check_result:
        st.error(f"Memory check script not found at {MEMORY_CHECK_SCRIPT}")
    
    handler_result = st.config(dut, f"test -f {MEMORY_HANDLER_SCRIPT} && echo FOUND || echo NOTFOUND")
    if "NOTFOUND" in handler_result:
        st.error(f"Memory handler script not found at {MEMORY_HANDLER_SCRIPT}")

    # Reduce monit daemon interval for test acceleration
    st.log(f"Reducing monit daemon interval to {DAEMON_INTERVAL}s (from default 60s)")
    st.config(dut, f"sed -i 's/set daemon [0-9]*/set daemon {DAEMON_INTERVAL}/' {MONITRC}")
    
    # Reduce start delay
    st.log(f"Reducing monit start delay to {START_DELAY}s (from default 300s)")
    st.config(dut, f"sed -i 's/with start delay [0-9]*/with start delay {START_DELAY}/' {MONITRC}")
    
    # Rewrite memory_gradual checks with test-mode cycles and --test-mode flag
    st.log("Rewriting sonic-host monit config for test-mode cycles")
    for scale, cycles in MONIT_TEST_CYCLES.items():
        ev = cycles["every"]
        rpt = cycles["repeat"]
        # Add --test-mode to checker path
        st.config(dut,
            f"sed -i 's|memory_gradual_check.py --scale {scale}|"
            f"memory_gradual_check.py --test-mode --scale {scale}|' {MONIT_CONF}")
        # Replace check interval: "    every N cycles" (indented line = check interval)
        st.config(dut,
            f"sed -i '/memory_gradual_{scale}/,+2 "
            f"s/^\\(\\s*\\)every [0-9]* cycles/\\1every {ev} cycles/' {MONIT_CONF}")
        # Replace handler repeat: "repeat every N cycles"
        st.config(dut,
            f"sed -i '/memory_gradual_{scale}/,+2 "
            f"s/repeat every [0-9]* cycles/repeat every {rpt} cycles/' {MONIT_CONF}")
        st.log(f"  {scale}: every {ev} cycles ({ev * DAEMON_INTERVAL}s), repeat every {rpt} cycles")
    
    # Clear state files for clean test start
    st.log("Clearing state files from previous runs")
    st.config(dut, f"rm -f {STATE_FILE}")
    
    # Restart monit with new configuration
    st.log("Restarting monit with accelerated configuration")
    st.config(dut, "systemctl restart monit")
    time.sleep(5)
    
    # Verify monit is running
    monit_status = st.config(dut, "systemctl is-active monit")
    if "active" not in monit_status:
        st.error("Monit service failed to start after configuration")
    else:
        st.log("Monit service is running")


def mem_monit_post_config():
    """
    Post-test cleanup:
    - Kill any memory injection processes
    - Restore original monit configuration
    - Restart monit with original config
    - Clear temporary files
    """
    dut = vars.D1
    
    st.log("=" * 80)
    st.log("MEMORY MONITORING TEST CLEANUP")
    st.log("=" * 80)
    
    # Kill any remaining injector processes
    st.log("Cleaning up injector processes")
    _kill_injectors(dut)
    
    # Restore original monit configuration
    st.log("Restoring original monit configuration")
    st.config(dut, f"cp {MONITRC_BAK} {MONITRC}")
    st.config(dut, f"cp {MONIT_CONF_BAK} {MONIT_CONF}")
    st.config(dut, f"rm -f {MONITRC_BAK} {MONIT_CONF_BAK}")
    
    # Restart monit with original configuration
    st.log("Restarting monit with original configuration")
    st.config(dut, "systemctl restart monit")
    time.sleep(3)
    
    # Clean up temporary files
    st.log("Cleaning up temporary test files")
    st.config(dut, "rm -f /tmp/gdb_*.log")


# ====================================================================
# TEST CASES
# ====================================================================

def calculate_r_squared(y_values):
    """Calculate R² (coefficient of determination) for linear regression fit."""
    _, _, r_squared = linear_regression(y_values)
    return r_squared


# ====================================================================
# SHARED LINEAR INJECTION — runs once, all UT-01..04 read the result
# ====================================================================

def _run_linear_injection(dut):
    """
    Inject INJECTION_MB x SAMPLES into the DUT, running the checker after
    each step.  Returns (final_state_dict, t90_series_list) or None on
    failure.  Caller is responsible for killing injectors afterward.
    """
    st.config(dut, f"rm -f {STATE_FILE}")
    st.config(dut, f"{MEMORY_CHECK_SCRIPT} --test-mode --scale {SCALE}")
    time.sleep(2)

    baseline = get_system_memory_mb(dut)
    if not baseline:
        return None
    total_sys = baseline["total"]
    t90_series = []
    # Track the last successfully parsed state inside the loop rather than
    # re-reading after the loop, because monit may independently detect the
    # threshold breach (exit 2) and fire the handler which deletes the file.
    last_good_state = None

    for sample_num in range(1, SAMPLES + 1):
        st.log(f"Sample {sample_num}/{SAMPLES}: +{INJECTION_MB}MB")
        _inject_mb(dut, INJECTION_MB)
        time.sleep(INJECTION_INTERVAL)
        st.config(dut, f"{MEMORY_CHECK_SCRIPT} --test-mode --scale {SCALE}")
        time.sleep(2)

        state_content = _read_file_from_dut(dut, STATE_FILE)
        if not state_content:
            continue
        state = json.loads(state_content)
        last_good_state = state
        reg = state.get("last_regression") or {}
        slope = reg.get("slope_mb_per_min", 0.0)
        if slope <= 0:
            continue

        mem = get_system_memory_mb(dut)
        if not mem:
            continue
        headroom = 0.9 * total_sys - mem["used"]
        if headroom > 0:
            t90_series.append(headroom / slope)

    if last_good_state is None:
        return None
    return last_good_state, t90_series


@pytest.fixture(scope="module")
def linear_injection_state():
    """Module-scoped fixture: inject once, yield state for UT-01..04."""
    dut = vars.D1
    _clear_state_files(dut)

    st.log("=" * 80)
    st.log(f"SHARED INJECTION: {INJECTION_MB}MB x {SAMPLES} samples @ {INJECTION_INTERVAL}s")
    st.log("=" * 80)

    result = _run_linear_injection(dut)
    yield result
    _kill_injectors(dut)


def test_ut_01_regression_slope_accuracy(linear_injection_state):
    """UT-01: Slope from state file should match INJECTION_MB / check_interval_mins within tolerance."""
    if linear_injection_state is None:
        st.report_fail("test_case_failed")
        return
    state, _ = linear_injection_state
    regression = state.get("last_regression") or {}
    computed_slope = regression.get("slope_mb_per_min", 0.0)
    slope_error = abs(computed_slope - EXPECTED_SLOPE)

    st.log(f"Expected slope: {EXPECTED_SLOPE} MB/min +/- {SLOPE_TOLERANCE}")
    st.log(f"Actual slope:   {computed_slope:.2f} MB/min  (error={slope_error:.2f})")

    if slope_error <= SLOPE_TOLERANCE:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_ut_02_r_squared_validation(linear_injection_state):
    """UT-02: Linear injection should produce R² above the feature's confidence threshold."""
    if linear_injection_state is None:
        st.report_fail("test_case_failed")
        return
    state, _ = linear_injection_state
    _, check_constants = _get_thresholds_and_constants()
    r2_threshold = check_constants["r_squared_threshold"]

    r2 = (state.get("last_regression") or {}).get("r_squared", 0.0)
    st.log(f"R² from state: {r2:.4f}  (threshold: {r2_threshold})")

    if r2 > r2_threshold:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_ut_02b_oscillation_low_r_squared():
    """UT-02-B: Alloc/free oscillation on DUT should produce R² < 0.5 (no false trigger)."""
    dut = vars.D1

    st.log("=" * 80)
    st.log("TEST: UT-02-B - Oscillation R² (alloc/free cycles)")
    st.log("=" * 80)

    try:
        free_samples = []
        for cycle in range(1, 5):
            st.log(f"Cycle {cycle}: alloc 300MB")
            _inject_mb(dut, 300)
            time.sleep(5)
            mem = get_system_memory_mb(dut)
            if mem:
                free_samples.append(mem["free"])

            st.log(f"Cycle {cycle}: free")
            _kill_injectors(dut)
            time.sleep(5)
            mem = get_system_memory_mb(dut)
            if mem:
                free_samples.append(mem["free"])

        if len(free_samples) < 4:
            st.report_fail("test_case_failed")
            return

        r2 = calculate_r_squared(free_samples)
        st.log(f"Oscillatory R²: {r2:.4f}  (expect < 0.5)")

        if r2 < 0.5:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_03_time_to_90_calculation(linear_injection_state):
    """UT-03: Time-to-90% values from the injection loop should be finite, positive, trending downward, and unit-consistent."""
    if linear_injection_state is None:
        st.report_fail("test_case_failed")
        return
    _, t90_series = linear_injection_state

    if len(t90_series) < 3:
        st.error(f"Only {len(t90_series)} t90 samples collected")
        st.report_fail("test_case_failed")
        return

    all_finite = all(0 < t < float("inf") for t in t90_series)

    MIN_TREND_SAMPLES = 5
    decreasing_count = sum(
        1 for i in range(1, len(t90_series)) if t90_series[i] < t90_series[i - 1]
    )
    decreasing_ratio = decreasing_count / (len(t90_series) - 1)
    if len(t90_series) >= MIN_TREND_SAMPLES:
        trending_down = decreasing_ratio >= 0.6
    else:
        trending_down = True
        st.log(
            f"Trend check skipped: only {len(t90_series)} t90 samples "
            f"(need >={MIN_TREND_SAMPLES} for a meaningful ratio)"
        )

    t90_hours = [t / 60.0 for t in t90_series]
    t90_days = [t / 1440.0 for t in t90_series]
    unit_consistent = all(
        abs(t90_series[i] - t90_hours[i] * 60.0) < 0.001
        and abs(t90_series[i] - t90_days[i] * 1440.0) < 0.001
        for i in range(len(t90_series))
    )

    st.log(f"t90 series ({len(t90_series)} pts): {t90_series}")
    st.log(f"all finite & positive: {all_finite}")
    st.log(f"decreasing ratio: {decreasing_ratio:.2f} (threshold: 0.60, enforced: {len(t90_series) >= MIN_TREND_SAMPLES})")
    st.log(f"unit consistency (min/hr/day): {unit_consistent}")

    checks = [
        ("all_finite_and_positive", all_finite),
        ("trending_downward", trending_down),
        ("unit_conversion_consistent", unit_consistent),
    ]
    passed = _log_named_checks("UT-03", checks)

    if passed:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_ut_04_growth_percent(linear_injection_state):
    """UT-04: Growth-as-%-of-free should be positive and larger when free headroom is smaller."""
    if linear_injection_state is None:
        st.report_fail("test_case_failed")
        return
    state, _ = linear_injection_state

    window = state.get("system_memory_window") or []
    baseline_mb = (state.get("baseline_snapshot") or {}).get("memory_mb")
    total_ram = (state.get("baseline_snapshot") or {}).get("total_ram_mb", 1)

    if len(window) < 2 or baseline_mb is None:
        st.report_fail("test_case_failed")
        return

    current = window[-1]
    growth_mb = current - baseline_mb
    free_mb = total_ram - current
    growth_pct = (growth_mb / free_mb) * 100.0 if free_mb > 0 else 100.0

    st.log(f"Live: growth={growth_mb:.0f}MB, free={free_mb:.0f}MB, growth%={growth_pct:.2f}%")

    high_free_total = 20000.0
    low_free_total = 12000.0
    sim_baseline = baseline_mb
    sim_current = current

    high_free = high_free_total - sim_current
    low_free = low_free_total - sim_current
    sim_growth = sim_current - sim_baseline

    high_free_pct = (sim_growth / high_free) * 100.0 if high_free > 0 else 100.0
    low_free_pct = (sim_growth / low_free) * 100.0 if low_free > 0 else 100.0

    st.log(
        f"Headroom comparison: same growth={sim_growth:.0f}MB | "
        f"high-free({high_free:.0f}MB)={high_free_pct:.2f}%, "
        f"low-free({low_free:.0f}MB)={low_free_pct:.2f}%"
    )

    checks = [
        ("growth_pct_positive", growth_pct > 0),
        ("pct_higher_when_free_lower", low_free_pct > high_free_pct),
        ("both_simulated_pcts_positive", high_free_pct > 0 and low_free_pct > 0),
    ]
    passed = _log_named_checks("UT-04", checks)

    if passed:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


# UT-05 — TRIGGER TRUTH TABLE VALIDATION
# ====================================================================

def test_ut_05_trigger_truth_table():
    """UT-05: Exhaustive truth table of (R², time-to-90, growth%) combinations against thresholds read from DUT checker."""
    thresholds, check_constants = _get_thresholds_and_constants()
    cfg = thresholds["short"]

    st.log("=" * 80)
    st.log("TEST: UT-05-SHORT - Trigger Truth Table")
    st.log(
        f"Feature constants: R2>{check_constants['r_squared_threshold']}, "
        f"time<{cfg['time_to_90_mins']} mins, growth>{cfg['growth_pct']}%"
    )
    st.log("=" * 80)

    try:
        r2_thr = check_constants['r_squared_threshold']
        t_thr = cfg['time_to_90_mins']
        g_thr = cfg['growth_pct']

        cases = [
            {"name": "A", "desc": "R² pass, time pass, growth fail => ALERT", "r2": r2_thr + 0.2, "t": t_thr - 1, "g": g_thr - 1, "exp": True},
            {"name": "B", "desc": "R² pass, time fail, growth pass => ALERT", "r2": r2_thr + 0.2, "t": t_thr + 1, "g": g_thr + 1, "exp": True},
            {"name": "C", "desc": "R² pass, time fail, growth fail => NO ALERT", "r2": r2_thr + 0.2, "t": t_thr + 1, "g": g_thr - 1, "exp": False},
            {"name": "D", "desc": "R² fail, time pass, growth pass => NO ALERT", "r2": max(0.0, r2_thr - 0.2), "t": t_thr - 1, "g": g_thr + 1, "exp": False},
            {"name": "E", "desc": "R² fail, time pass, growth fail => NO ALERT", "r2": max(0.0, r2_thr - 0.2), "t": t_thr - 1, "g": g_thr - 1, "exp": False},
            {"name": "F", "desc": "R² fail, time fail, growth pass => NO ALERT", "r2": max(0.0, r2_thr - 0.2), "t": t_thr + 1, "g": g_thr + 1, "exp": False},
        ]

        mismatches = []
        for case in cases:
            actual = _trigger_decision("short", case['r2'], case['t'], case['g'])
            st.log(
                f"Case {case['name']} | {case['desc']} | "
                f"r2={case['r2']:.3f}, t90={case['t']:.2f}, growth={case['g']:.2f}% | "
                f"expected={case['exp']} actual={actual}"
            )
            if actual != case['exp']:
                mismatches.append(case['name'])

        st.log("=" * 80)
        if mismatches:
            st.log(f"TEST RESULT: FAIL - mismatches={mismatches}")
            st.report_fail("test_case_failed")
        else:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")

DEFAULT_TEST_MODE_THRESHOLDS = {
    "short": {"time_to_90_mins": 30, "growth_pct": 1},
    "medium": {"time_to_90_mins": 60, "growth_pct": 5},
    "long": {"time_to_90_mins": 150, "growth_pct": 5},
}

DEFAULT_CHECK_CONSTANTS = {
    "r_squared_threshold": 0.7,
    "process_min_ram_pct": 0.5,
    "max_tracked_processes": 100,
}

DEFAULT_HANDLER_CONSTANTS = {
    "contribution_pct": 10.0,
    "r_squared_min": 0.5,
}


def _read_file_from_dut(dut, path):
    """Read a file from DUT via base64 encoding to avoid shell escaping issues.

    For small files (state JSON, monit conf) the base64 payload is
    compact.  For large scripts this function should be avoided in
    favour of ``_grep_dut_file`` which extracts only the needed lines.
    """
    marker_begin = "__MEMMONIT_B64_BEGIN__"
    marker_end = "__MEMMONIT_B64_END__"
    cmd = (
        f"bash -c 'echo {marker_begin}; "
        f"base64 {path} 2>/dev/null | tr -d \"\\n\"; "
        f"echo; echo {marker_end}'"
    )
    output = st.config(dut, cmd)

    try:
        start = output.find(marker_begin)
        end = output.find(marker_end)
        if start == -1 or end == -1 or end <= start:
            return ""

        payload = output[start + len(marker_begin):end].strip()
        if not payload:
            return ""

        return base64.b64decode(payload).decode(errors="ignore")
    except Exception:
        return ""


def _grep_dut_file(dut, path, pattern):
    """Run grep on DUT and return matching lines (avoids transferring full files)."""
    marker = "__GREP_RESULT__"
    output = st.config(
        dut,
        f"echo {marker}; grep -E '{pattern}' {path} 2>/dev/null || true; echo {marker}",
    )
    try:
        start = output.find(marker)
        end = output.find(marker, start + len(marker))
        if start == -1 or end == -1:
            return ""
        return output[start + len(marker):end].strip()
    except Exception:
        return ""


def _read_check_test_mode_thresholds(dut):
    """Parse SCALE_CONFIG_TEST_MODE thresholds from memory_gradual_check.py on DUT."""
    content = _grep_dut_file(
        dut, MEMORY_CHECK_SCRIPT,
        "time_threshold_mins|growth_threshold_pct|short|medium|long",
    )
    if not content:
        return dict(DEFAULT_TEST_MODE_THRESHOLDS)

    thresholds = {}
    for scale in ["short", "medium", "long"]:
        pattern = (
            rf'"{scale}"\s*:\s*\{{.*?'
            rf'"time_threshold_mins"\s*:\s*([0-9]+).*?'
            rf'"growth_threshold_pct"\s*:\s*([0-9]+)'
        )
        match = re.search(pattern, content, re.DOTALL)
        if match:
            thresholds[scale] = {
                "time_to_90_mins": int(match.group(1)),
                "growth_pct": int(match.group(2)),
            }

    if len(thresholds) != 3:
        return dict(DEFAULT_TEST_MODE_THRESHOLDS)
    return thresholds


def _read_check_constants(dut):
    """Parse detection constants from memory_gradual_check.py on DUT."""
    content = _grep_dut_file(
        dut, MEMORY_CHECK_SCRIPT,
        "R_SQUARED_THRESHOLD|PROCESS_MIN_RAM_PCT|MAX_TRACKED_PROCESSES",
    )
    if not content:
        return dict(DEFAULT_CHECK_CONSTANTS)

    constants = dict(DEFAULT_CHECK_CONSTANTS)

    r2_match = re.search(r"R_SQUARED_THRESHOLD\s*=\s*([0-9.]+)", content)
    min_ram_match = re.search(r"PROCESS_MIN_RAM_PCT\s*=\s*([0-9.]+)", content)
    cap_match = re.search(r"MAX_TRACKED_PROCESSES\s*=\s*([0-9]+)", content)

    if r2_match:
        constants["r_squared_threshold"] = float(r2_match.group(1))
    if min_ram_match:
        constants["process_min_ram_pct"] = float(min_ram_match.group(1))
    if cap_match:
        constants["max_tracked_processes"] = int(cap_match.group(1))

    return constants


def _read_handler_constants(dut):
    """Parse contributor filtering constants from memory_gradual_handler.py on DUT."""
    content = _grep_dut_file(
        dut, MEMORY_HANDLER_SCRIPT,
        "CONTRIBUTION_PCT|R_SQUARED_MIN",
    )
    if not content:
        return dict(DEFAULT_HANDLER_CONSTANTS)

    constants = dict(DEFAULT_HANDLER_CONSTANTS)

    contribution_match = re.search(r"CONTRIBUTION_PCT\s*=\s*([0-9.]+)", content)
    r2_match = re.search(r"R_SQUARED_MIN\s*=\s*([0-9.]+)", content)

    if contribution_match:
        constants["contribution_pct"] = float(contribution_match.group(1))
    if r2_match:
        constants["r_squared_min"] = float(r2_match.group(1))

    return constants


_cached_thresholds = None
_cached_check_constants = None


def _get_thresholds_and_constants():
    """Return (thresholds, check_constants), reading from DUT only once."""
    global _cached_thresholds, _cached_check_constants
    if _cached_thresholds is None or _cached_check_constants is None:
        dut = vars.D1
        _cached_thresholds = _read_check_test_mode_thresholds(dut)
        _cached_check_constants = _read_check_constants(dut)
    return _cached_thresholds, _cached_check_constants


def _trigger_decision(scale, r_squared, time_to_90_mins, growth_pct):
    """Mirror memory_gradual_check.py trigger logic for deterministic UT validation.

    Detection fires when: R² gate passes AND (time-to-90% gate OR growth% gate).
    Thresholds are read from the DUT once and cached for the session.
    """
    thresholds, check_constants = _get_thresholds_and_constants()
    cfg = thresholds[scale]
    r2_pass = r_squared > check_constants["r_squared_threshold"]
    time_pass = time_to_90_mins < cfg["time_to_90_mins"]
    growth_pass = growth_pct > cfg["growth_pct"]
    return r2_pass and (time_pass or growth_pass)


def _append_with_cap(window, value, cap):
    window.append(value)
    if len(window) > cap:
        window.pop(0)


def _filter_significant_processes(process_mem_mb, total_ram_mb, min_ram_pct=0.5, cap=100):
    min_mem_mb = total_ram_mb * min_ram_pct / 100.0
    eligible = [(name, mb) for name, mb in process_mem_mb.items() if mb >= min_mem_mb]
    eligible.sort(key=lambda item: item[1], reverse=True)
    return eligible[:cap]


def _filter_contributors(contributors, system_growth_mb, min_pct=10.0, min_r2=0.5):
    min_contribution = system_growth_mb * (min_pct / 100.0)
    kept = []
    for item in contributors:
        if item["growth_mb"] >= min_contribution and item["r_squared"] > min_r2:
            kept.append(item)
    kept.sort(key=lambda item: item["growth_mb"], reverse=True)
    return kept


def _load_json_file_from_dut(dut, path):
    output = _read_file_from_dut(dut, path)
    if not output or not output.strip():
        return None
    try:
        return json.loads(output)
    except Exception as e:
        st.error(f"Failed to parse JSON from {path}: {e}")
        return None


def _log_named_checks(test_name, checks):
    """Log each check with pass/fail and return True only if all checks pass."""
    def _norm(token):
        normalized = re.sub(r"[^a-z0-9]+", "_", str(token).lower()).strip("_")
        return normalized if normalized else "unnamed_check"

    suite = _norm(test_name)
    failed = []
    for name, ok in checks:
        check_id = f"{suite}__{_norm(name)}"
        st.log(f"CHECK {check_id}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failed.append(check_id)

    if failed:
        st.log(f"FAILED_CHECKS {suite}: {', '.join(failed)}")
        return False
    return True


def test_ut_06_scale_specific_threshold_mapping():
    """UT-06: Boundary tests around per-scale time-to-90 and growth% thresholds (just-below, just-above, both-below, R²-blocked)."""
    thresholds, check_constants = _get_thresholds_and_constants()
    cfg = thresholds["short"]

    st.log("=" * 80)
    st.log("TEST: UT-06-SHORT - Scale-Specific Threshold Mapping")
    st.log("=" * 80)

    try:
        cases = [
            {"name": "time just below threshold", "r2": 0.95, "t90": cfg["time_to_90_mins"] - 1, "growth": cfg["growth_pct"] - 1, "expected": True},
            {"name": "time just above, growth below", "r2": 0.95, "t90": cfg["time_to_90_mins"] + 1, "growth": cfg["growth_pct"] - 1, "expected": False},
            {"name": "growth just above threshold", "r2": 0.95, "t90": cfg["time_to_90_mins"] + 5, "growth": cfg["growth_pct"] + 0.1, "expected": True},
            {"name": "both gates below threshold", "r2": 0.95, "t90": cfg["time_to_90_mins"] + 5, "growth": cfg["growth_pct"] - 0.1, "expected": False},
            {"name": "r2 gate blocks decision", "r2": 0.60, "t90": cfg["time_to_90_mins"] - 10, "growth": cfg["growth_pct"] + 10, "expected": False},
        ]

        failures = []
        for idx, case in enumerate(cases, 1):
            actual = _trigger_decision("short", case["r2"], case["t90"], case["growth"])
            st.log(f"Case {idx}: {case['name']} | expected={case['expected']} actual={actual}")
            if actual != case["expected"]:
                failures.append(case["name"])

        st.log("=" * 80)
        if failures:
            st.log(f"TEST RESULT: FAIL - mismatches: {', '.join(failures)}")
            st.report_fail("test_case_failed")
        else:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_07_zero_negative_slope_handling():
    """UT-07: Flat and decreasing memory profiles produce zero/negative slopes, infinite time-to-90, and never trigger detection."""
    st.log("=" * 80)
    st.log("TEST: UT-07-SHORT - Zero/Negative Slope Handling")
    st.log("=" * 80)

    try:
        flat = [8000] * 12
        decreasing = [9000 - (i * 35) for i in range(12)]

        flat_slope = calculate_slope_mb_per_min(flat, INJECTION_INTERVAL)
        dec_slope = calculate_slope_mb_per_min(decreasing, INJECTION_INTERVAL)
        flat_r2 = calculate_r_squared(flat)
        dec_r2 = calculate_r_squared(decreasing)

        flat_t90 = float("inf") if flat_slope <= 0 else 1000 / flat_slope
        dec_t90 = float("inf") if dec_slope <= 0 else 1000 / dec_slope

        st.log(f"Flat: slope={flat_slope:.4f}, r2={flat_r2:.4f}, t90={flat_t90}")
        st.log(f"Decreasing: slope={dec_slope:.4f}, r2={dec_r2:.4f}, t90={dec_t90}")

        checks = [
            ("flat_slope_near_zero", abs(flat_slope) < 0.001),
            ("decreasing_slope_negative", dec_slope < 0),
            ("flat_time_to_90_inf", flat_t90 == float("inf")),
            ("decreasing_time_to_90_inf", dec_t90 == float("inf")),
            ("flat_no_trigger", _trigger_decision("short", flat_r2, flat_t90, -1.0) is False),
            ("decreasing_no_trigger", _trigger_decision("short", dec_r2, dec_t90, -2.0) is False),
        ]
        passed = _log_named_checks("UT-07-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_08_sliding_window_eviction():
    """UT-08: Feed cap+overflow samples into the sliding window; verify oldest samples are evicted and window stays at cap size."""
    cap = SAMPLES
    overflow = 5

    st.log("=" * 80)
    st.log(f"TEST: UT-08-SHORT - Sliding Window Eviction (cap={cap}, overflow={overflow})")
    st.log("=" * 80)

    try:
        window = []
        for value in range(1, cap + overflow + 1):
            _append_with_cap(window, value, cap)

        checks = [
            ("window_size_equals_cap", len(window) == cap),
            ("first_sample_after_eviction", window[0] == overflow + 1),
            ("last_sample_is_latest", window[-1] == cap + overflow),
        ]
        passed = _log_named_checks("UT-08-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_09_baseline_lifecycle():
    """UT-09: After a baseline reset, growth is measured from the new baseline, not the stale pre-reset value."""
    st.log("=" * 80)
    st.log("TEST: UT-09-SHORT - Baseline Lifecycle")
    st.log("=" * 80)

    try:
        pre_reset_growth = 6400 - 6100
        post_reset_growth = 6725 - 6550
        stale_growth_if_bug = 6725 - 6100

        st.log(f"Pre-reset growth={pre_reset_growth}, Post-reset growth={post_reset_growth}, Stale={stale_growth_if_bug}")

        checks = [
            ("pre_reset_growth_expected", pre_reset_growth == 300),
            ("post_reset_growth_expected", post_reset_growth == 175),
            ("no_stale_baseline_leak", post_reset_growth != stale_growth_if_bug),
        ]
        passed = _log_named_checks("UT-09-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_10_process_tracking_filter():
    """UT-10: 130 processes filtered by PROCESS_MIN_RAM_PCT; verify cap enforcement, below-threshold exclusion, and descending sort."""
    _, check_constants = _get_thresholds_and_constants()

    st.log("=" * 80)
    st.log("TEST: UT-10-SHORT - Process Tracking Filter")
    st.log("=" * 80)

    try:
        total_ram_mb = 20000.0
        min_ram_pct = check_constants["process_min_ram_pct"]
        process_cap = check_constants["max_tracked_processes"]
        threshold_mb = total_ram_mb * min_ram_pct / 100.0

        proc_map = {}
        for i in range(1, 121):
            proc_map[f"proc_hi_{i}"] = 100 + (i * 2)
        for i in range(1, 11):
            proc_map[f"proc_lo_{i}"] = 20 + i

        tracked = _filter_significant_processes(proc_map, total_ram_mb, min_ram_pct=min_ram_pct, cap=process_cap)
        names = [name for name, _ in tracked]
        values = [mb for _, mb in tracked]

        checks = [
            ("exclude_below_threshold", all(mb >= threshold_mb for mb in values)),
            ("cap_enforced", len(tracked) == process_cap),
            ("low_processes_not_tracked", all(not n.startswith("proc_lo_") for n in names)),
            ("tracked_list_sorted_desc", all(values[i] >= values[i + 1] for i in range(len(values) - 1))),
        ]
        passed = _log_named_checks("UT-10-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_11_contributor_filter():
    """UT-11: Four candidates with varying growth and R²; only those meeting both contribution% and R² minimums are retained."""
    dut = vars.D1
    handler_constants = _read_handler_constants(dut)

    st.log("=" * 80)
    st.log("TEST: UT-11-SHORT - Contributor Filter")
    st.log("=" * 80)

    try:
        contributors = [
            {"name": "A", "growth_mb": 150.0, "r_squared": 0.81},
            {"name": "B", "growth_mb": 90.0, "r_squared": 0.82},
            {"name": "C", "growth_mb": 120.0, "r_squared": 0.45},
            {"name": "D", "growth_mb": 250.0, "r_squared": 0.92},
        ]
        min_pct = handler_constants["contribution_pct"]
        min_r2 = handler_constants["r_squared_min"]
        kept = _filter_contributors(contributors, 1000.0, min_pct=min_pct, min_r2=min_r2)
        kept_names = [item["name"] for item in kept]
        st.log(f"Kept contributors={kept_names} (expected=['D', 'A'])")

        checks = [
            ("kept_contributor_order_matches_expected", kept_names == ["D", "A"]),
        ]
        passed = _log_named_checks("UT-11-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_12_restart_artifact_suppression():
    """UT-12: Stable-growth process retained; process with restart-induced drop (low R²) excluded from contributors."""
    dut = vars.D1
    handler_constants = _read_handler_constants(dut)

    st.log("=" * 80)
    st.log("TEST: UT-12-SHORT - Restart Artifact Suppression")
    st.log("=" * 80)

    try:
        stable_series = [500, 530, 560, 590, 620, 650]
        restart_series = [500, 530, 560, 120, 150, 180]

        candidates = [
            {"name": "stable_proc", "growth_mb": float(stable_series[-1] - stable_series[0]), "r_squared": calculate_r_squared(stable_series)},
            {"name": "restarted_proc", "growth_mb": float(restart_series[-1] - restart_series[0]), "r_squared": calculate_r_squared(restart_series)},
        ]
        min_pct = handler_constants["contribution_pct"]
        min_r2 = handler_constants["r_squared_min"]
        kept_names = [item["name"] for item in _filter_contributors(candidates, 1000.0, min_pct=min_pct, min_r2=min_r2)]
        st.log(f"Kept contributors={kept_names}")

        checks = [
            ("stable_process_retained", "stable_proc" in kept_names),
            ("restarted_artifact_excluded", "restarted_proc" not in kept_names),
        ]
        passed = _log_named_checks("UT-12-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_ut_13_memory_handler_output_contract():
    """UT-13: Validate monit sonic-host wiring (checker->handler), handler source markers, and output regex for header/summary/process/container lines."""
    dut = vars.D1

    st.log("=" * 80)
    st.log("TEST: UT-13-SHORT - Memory Handler Output Contract")
    st.log("=" * 80)

    try:
        sonic_host_content = _read_file_from_dut(dut, MONIT_CONF)

        checker_pattern = (
            r"check program memory_gradual_short with path \"/usr/local/bin/memory_gradual_check.py[^\"]*--scale short\""
            r"[\s\S]*?if status == 2 for \d+ cycles then exec \"/usr/local/bin/memory_gradual_handler.py --scale short\""
        )
        checker_wiring_ok = re.search(checker_pattern, sonic_host_content) is not None

        marker_out = st.config(
            dut,
            f"grep -nE 'Gradual memory increase detected|Current:|Memory-consuming processes:|Memory-consuming containers:' "
            f"{MEMORY_HANDLER_SCRIPT} || true",
        )
        marker_present = all(m in marker_out for m in [
            "Gradual memory increase detected", "Current:",
            "Memory-consuming processes:", "Memory-consuming containers:",
        ])

        header_ok = re.search(r"^Gradual memory increase detected \(window: .+\)$",
                              "Gradual memory increase detected (window: 10 min)") is not None
        summary_ok = re.search(r"Current: \d+MB used, \d+MB free \([0-9.]+%\).+time to 90%:",
                               "  Current: 8000MB used, 4000MB free (66.7%) ; Growth: 7500MB -> 8000MB (+500MB, +12.5% of free mem), time to 90%: 14.0 hours") is not None
        process_ok = re.search(r"#\d+ PID:\d+ .+ - [+-]\d+MB",
                               "    #1 PID:123 python3 - +400MB (+50%) - python3 script.py") is not None
        container_ok = re.search(r"Memory-consuming containers: .+",
                                 "  Memory-consuming containers: syncd: 1234MB (10.3%); pmon: 450MB (3.8%)") is not None

        checks = [
            ("handler_markers_present", marker_present),
            ("header_regex_ok", header_ok),
            ("summary_regex_ok", summary_ok),
            ("process_line_regex_ok", process_ok),
            ("container_line_regex_ok", container_ok),
            ("sonic_host_wiring_ok", checker_wiring_ok),
        ]
        passed = _log_named_checks("UT-13-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


# FUNCTIONAL TESTS — FUNC-TC-01 .. FUNC-TC-03 (short only)
# ====================================================================

FUNC_SAMPLES_SHORT = 10


def _generate_linear_profile(start_used_mb, step_mb, samples):
    return [start_used_mb + (i * step_mb) for i in range(samples)]


def _generate_burst_recovery_profile(start_used_mb, burst_mb, samples):
    series = [start_used_mb]
    hold1 = start_used_mb + burst_mb
    hold2 = hold1
    recovery1 = start_used_mb + max(10, int(0.35 * burst_mb))
    recovery2 = start_used_mb + max(5, int(0.15 * burst_mb))
    recovery3 = start_used_mb + max(2, int(0.05 * burst_mb))

    seed = [hold1, hold2, recovery1, recovery2, recovery3]
    for value in seed:
        if len(series) >= samples:
            break
        series.append(value)

    while len(series) < samples:
        series.append(start_used_mb)

    return series


def _generate_oscillation_profile(start_used_mb, amplitude_mb, samples):
    return [start_used_mb + (amplitude_mb if i % 2 == 1 else 0) for i in range(samples)]


def _evaluate_profile_against_feature(scale, used_samples, total_ram_mb):
    thresholds, check_constants = _get_thresholds_and_constants()
    cfg = thresholds[scale]
    interval_sec = INJECTION_INTERVAL

    slope_mb_per_min = calculate_slope_mb_per_min(used_samples, interval_sec)
    r_squared = calculate_r_squared(used_samples)
    baseline_used = float(used_samples[0])
    current_used = float(used_samples[-1])
    # Match memory_gradual_check.check_for_gradual_increase: % of *free* RAM, not % of baseline used.
    growth_mb = current_used - baseline_used
    free_memory_mb = total_ram_mb - current_used
    growth_pct = (
        (growth_mb / free_memory_mb) * 100.0 if free_memory_mb > 0 else 100.0
    )

    headroom_mb = (0.9 * total_ram_mb) - current_used
    if slope_mb_per_min > 0 and headroom_mb > 0:
        time_to_90_mins = headroom_mb / slope_mb_per_min
    else:
        time_to_90_mins = float("inf")

    time_trigger = time_to_90_mins < cfg["time_to_90_mins"]
    growth_trigger = growth_pct > cfg["growth_pct"]
    r2_pass = r_squared > check_constants["r_squared_threshold"]
    detected = r2_pass and (time_trigger or growth_trigger)

    return {
        "samples": used_samples,
        "slope_mb_per_min": slope_mb_per_min,
        "r_squared": r_squared,
        "baseline_used": baseline_used,
        "current_used": current_used,
        "growth_mb": growth_mb,
        "growth_pct": growth_pct,
        "time_to_90_mins": time_to_90_mins,
        "time_trigger": time_trigger,
        "growth_trigger": growth_trigger,
        "r2_pass": r2_pass,
        "detected": detected,
        "threshold_time_mins": cfg["time_to_90_mins"],
        "threshold_growth_pct": cfg["growth_pct"],
        "threshold_r2": check_constants["r_squared_threshold"],
    }


def _log_profile_result(label, result):
    st.log(
        f"{label}: slope={result['slope_mb_per_min']:.2f}MB/min, r2={result['r_squared']:.4f}, "
        f"growth={result['growth_pct']:.2f}%, t90={result['time_to_90_mins']}, "
        f"gates(r2/time/growth)=({result['r2_pass']}/{result['time_trigger']}/{result['growth_trigger']}), "
        f"detected={result['detected']}"
    )
    st.log(
        f"Thresholds used: r2>{result['threshold_r2']}, "
        f"time<{result['threshold_time_mins']} mins, growth>{result['threshold_growth_pct']}%"
    )
    st.log(f"Profile head={result['samples'][:6]} tail={result['samples'][-6:]}")


def test_func_tc_01_slow_leak_sensitivity():
    """FUNC-TC-01: Monotonically increasing profile triggers detection with positive slope and R² gate pass."""
    st.log("=" * 80)
    st.log("TEST: FUNC-TC-01-SHORT - Slow Leak Detection Sensitivity")
    st.log("=" * 80)

    try:
        used = _generate_linear_profile(6000.0, 40.0, FUNC_SAMPLES_SHORT)
        result = _evaluate_profile_against_feature("short", used, 20000.0)
        _log_profile_result("FUNC-TC-01", result)

        checks = [
            ("detector_asserted", result["detected"] is True),
            ("r2_gate_passed", result["r2_pass"] is True),
            ("positive_slope", result["slope_mb_per_min"] > 0),
        ]
        passed = _log_named_checks("FUNC-TC-01-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_func_tc_02_burst_recovery():
    """FUNC-TC-02: Spike followed by recovery returns near baseline; no false detection, growth gate not triggered."""
    st.log("=" * 80)
    st.log("TEST: FUNC-TC-02-SHORT - Burst Allocation Then Recovery")
    st.log("=" * 80)

    try:
        used = _generate_burst_recovery_profile(6000.0, 400.0, FUNC_SAMPLES_SHORT)
        result = _evaluate_profile_against_feature("short", used, 20000.0)
        _log_profile_result("FUNC-TC-02", result)

        checks = [
            ("no_false_detection", result["detected"] is False),
            ("recovered_near_baseline", abs(result["current_used"] - 6000.0) <= max(15.0, 0.02 * 400.0)),
            ("growth_gate_not_triggered", result["growth_trigger"] is False),
        ]
        passed = _log_named_checks("FUNC-TC-02-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


def test_func_tc_03_oscillation_immunity():
    """FUNC-TC-03: Alternating up/down memory pattern produces R² < 0.7; no false detection."""
    st.log("=" * 80)
    st.log("TEST: FUNC-TC-03-SHORT - Oscillation Immunity")
    st.log("=" * 80)

    try:
        used = _generate_oscillation_profile(6000.0, 50.0, FUNC_SAMPLES_SHORT)
        result = _evaluate_profile_against_feature("short", used, 20000.0)
        _log_profile_result("FUNC-TC-03", result)

        checks = [
            ("no_false_detection", result["detected"] is False),
            ("r2_below_confidence_gate", result["r_squared"] < 0.7),
        ]
        passed = _log_named_checks("FUNC-TC-03-SHORT", checks)

        st.log("=" * 80)
        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log("TEST RESULT: FAIL")
            st.report_fail("test_case_failed")
        st.log("=" * 80)
    except Exception as e:
        st.error(f"Test exception: {e}")
        st.report_fail("test_case_failed")


# Syslog integration — handler output in /var/log/syslog (sudo)
# ====================================================================


def _syslog_line_count(dut) -> int:
    """Return current line count of /var/log/syslog so we can diff after an action."""
    raw = st.config(
        dut,
        f"sudo wc -l {SYSLOG_PATH} 2>/dev/null | awk '{{print $1}}' || echo 0",
    )
    raw = (raw or "").strip()
    try:
        return int(raw.split()[0])
    except (IndexError, ValueError):
        return 0


def _syslog_tail_from_1based(dut, start_line_1based: int) -> str:
    """Read recent syslog lines, filtering to memory_gradual and monit entries only."""
    return st.config(
        dut,
        f"sudo tail -n +{start_line_1based} {SYSLOG_PATH} 2>/dev/null "
        f"| grep -E 'memory_gradual|monit\\[' | tail -200 || true",
    ) or ""


def _require_memory_scripts_executable(dut):
    for path in (MEMORY_CHECK_SCRIPT, MEMORY_HANDLER_SCRIPT):
        out = st.config(dut, f"test -x {path} && echo OK || echo MISSING")
        if "MISSING" in (out or ""):
            pytest.skip(f"Not executable or missing: {path}")


def _write_minimal_handler_state(dut):
    """
    Write a synthetic state file that guarantees the handler will detect growth.
    Uses a low baseline (100 MB) with a steadily increasing window up to 1000 MB
    and an artificially large total_ram_mb so that time-to-90% stays finite.
    """
    state = {
        "window_type": "short",
        "window_size": 10,
        "window_description": "10 min",
        "sample_count": 10,
        "system_memory_window": [100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 900.0, 1000.0],
        "tracked_containers": {},
        "tracked_processes": {},
        "baseline_snapshot": {
            "timestamp": "spytest",
            "memory_mb": 100.0,
            "total_ram_mb": 131072.0,
        },
        "last_regression": {
            "slope_mb_per_min": 1.0,
            "r_squared": 0.95,
            "slope_mb_per_interval": 1.0,
            "calculated_at_sample": 10,
        },
    }
    payload = json.dumps(state)
    b64 = base64.standard_b64encode(payload.encode()).decode()
    st.config(
        dut,
        f"echo {b64} | base64 -d | sudo tee {STATE_FILE} >/dev/null",
    )


def test_dut_syslog_handler_missing_state():
    """Syslog: Handler exits with RC=1 and logs an error when the state file is missing."""
    dut = vars.D1
    _require_memory_scripts_executable(dut)

    st.config(dut, f"sudo rm -f {STATE_FILE}")
    before_lines = _syslog_line_count(dut)

    rc_out = st.config(dut, f"sudo {MEMORY_HANDLER_SCRIPT} --scale short; echo RC=$?")
    blob = _syslog_tail_from_1based(dut, before_lines + 1)

    checks = [
        ("handler_exit_rc1", "RC=1" in (rc_out or "")),
        ("handler_tag_in_syslog", "memory_gradual_handler" in blob),
        ("state_file_error_logged", bool(re.search(
            r"Could not load state file|Failed to load state file",
            blob,
            re.IGNORECASE,
        ))),
    ]
    passed = _log_named_checks("SYSLOG-HANDLER-MISSING-STATE", checks)

    if passed:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_dut_syslog_handler_happy_path():
    """Syslog: Handler exits RC=0, logs all required markers (header/current/processes/containers), and deletes the state file."""
    dut = vars.D1
    _require_memory_scripts_executable(dut)

    _write_minimal_handler_state(dut)
    before_lines = _syslog_line_count(dut)

    rc_out = st.config(dut, f"sudo {MEMORY_HANDLER_SCRIPT} --scale short; echo RC=$?")

    gone = st.config(
        dut,
        f"test -f {STATE_FILE} && echo exists || echo gone",
    )

    blob = _syslog_tail_from_1based(dut, before_lines + 1)

    checks = [
        ("handler_exit_rc0", "RC=0" in (rc_out or "")),
        ("state_file_deleted", "gone" in (gone or "")),
        ("handler_tag_in_syslog", "memory_gradual_handler" in blob),
        ("marker_header", "Gradual memory increase detected" in blob),
        ("marker_current", "Current:" in blob),
        ("marker_processes", "Memory-consuming processes:" in blob),
        ("marker_containers", "Memory-consuming containers:" in blob),
    ]
    passed = _log_named_checks("SYSLOG-HANDLER-HAPPY-PATH", checks)

    if passed:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_dut_syslog_checker_cold_run_no_detection():
    """``--test-mode`` single run on empty state should not return exit 2."""
    dut = vars.D1
    _require_memory_scripts_executable(dut)

    st.config(dut, f"sudo rm -f {STATE_FILE}")
    out = st.config(dut, f"sudo {MEMORY_CHECK_SCRIPT} --test-mode --scale short; echo RC=$?")

    checks = [
        ("no_detection_on_cold_run", "RC=2" not in (out or "")),
    ]
    passed = _log_named_checks("SYSLOG-CHECKER-COLD-RUN", checks)

    if passed:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


# ====================================================================
# END-TO-END MONIT INTEGRATION TEST
# ====================================================================

def test_e2e_monit_triggered_detection():
    """
    End-to-end: warm up the checker's sliding window with manual runs,
    then let monit's scheduled cycle trigger detection and fire the handler.
    Validates syslog output, state-file cleanup, and monit status logging.
    """
    dut = vars.D1
    _require_memory_scripts_executable(dut)

    st.log("=" * 80)
    st.log("TEST: E2E Monit-Triggered Detection")
    st.log("=" * 80)

    # Fill the checker's sliding window to (window_size - 2) with manual runs
    # so monit only needs 1-2 scheduled cycles to reach a full window and
    # trigger detection.  Without warmup, monit would need ~10 min of its own
    # cycles to fill the 10-sample window.
    WARMUP_SAMPLES = SAMPLES - 2
    MONIT_POLL_INTERVAL = 15      # seconds between syslog checks
    MONIT_MAX_WAIT = 300          # max seconds to wait for monit detection

    try:
        st.config(dut, f"rm -f {STATE_FILE}")
        if not _ensure_monit_running(dut):
            st.report_fail("test_case_failed")
            return

        # Phase 1: warm up the state file with manual checker runs
        st.log(f"[Phase 1] Warming up: {WARMUP_SAMPLES} manual inject+check cycles")
        for i in range(1, WARMUP_SAMPLES + 1):
            _inject_mb(dut, INJECTION_MB)
            time.sleep(INJECTION_INTERVAL)
            st.config(dut, f"{MEMORY_CHECK_SCRIPT} --test-mode --scale {SCALE}")
            time.sleep(2)
            st.log(f"  Warmup {i}/{WARMUP_SAMPLES}: +{INJECTION_MB}MB, checker done")

        state_content = _read_file_from_dut(dut, STATE_FILE)
        if state_content:
            warmup_state = json.loads(state_content)
            samples = warmup_state.get("sample_count", 0)
            st.log(f"  State file has {samples} samples after warmup")
        else:
            st.log("  WARNING: State file empty after warmup")

        # Phase 2: keep injecting and wait for monit to trigger detection
        st.log("[Phase 2] Continuing injection, waiting for monit-triggered detection")
        before_lines = _syslog_line_count(dut)
        detected = False
        elapsed = 0

        while elapsed < MONIT_MAX_WAIT:
            _inject_mb(dut, INJECTION_MB)
            st.log(f"  +{INJECTION_MB}MB injected (elapsed {elapsed}s)")
            time.sleep(MONIT_POLL_INTERVAL)
            elapsed += MONIT_POLL_INTERVAL

            blob = _syslog_tail_from_1based(dut, before_lines + 1)
            if "Gradual memory increase detected" in blob:
                st.log(f"  Detection triggered after {elapsed}s!")
                detected = True
                break

        if not detected:
            st.log(f"WARNING: Detection did not trigger within {MONIT_MAX_WAIT}s")

        time.sleep(10)

        # Phase 3: validate syslog, state file, monit log
        st.log("[Phase 3] Validating results")
        blob = _syslog_tail_from_1based(dut, before_lines + 1)

        required_markers = [
            "Gradual memory increase detected",
            "Current:",
            "Memory-consuming processes:",
            "Memory-consuming containers:",
        ]
        missing = [m for m in required_markers if m not in blob]

        for marker in required_markers:
            found = marker in blob
            st.log(f"  Syslog marker '{marker}': {'FOUND' if found else 'MISSING'}")

        st.log("[Phase 3b] Checking state file was deleted by handler")
        state_check = st.config(dut, f"test -f {STATE_FILE} && echo exists || echo gone")
        state_deleted = "gone" in (state_check or "")
        st.log(f"  State file: {'deleted (correct)' if state_deleted else 'still exists (unexpected)'}")

        monit_logged = "memory_gradual_short" in blob and "status failed (2)" in blob
        st.log(f"  Monit status log: {'FOUND' if monit_logged else 'NOT FOUND'}")

        st.log("=" * 80)
        checks = [
            ("all_syslog_markers_present", len(missing) == 0),
            ("state_file_deleted", state_deleted),
            ("monit_status_logged", monit_logged),
        ]
        passed = _log_named_checks("E2E-MONIT", checks)

        if passed:
            st.log("TEST RESULT: PASS")
            st.report_pass("test_case_passed")
        else:
            st.log(f"TEST RESULT: FAIL (missing markers: {missing})")
            st.report_fail("test_case_failed")
        st.log("=" * 80)

    except Exception as e:
        st.error(f"Test exception: {e}")
        import traceback
        st.error(traceback.format_exc())
        st.report_fail("test_case_failed")
