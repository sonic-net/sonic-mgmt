import pytest
import logging

from tests.common.fixtures.duthost_utils import stop_route_checker_on_duthost
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.common.plugins.loganalyzer.loganalyzer import DisableLogrotateAndWaitSyslogContext, LogAnalyzer

pytestmark = [
    pytest.mark.disable_route_check,
    pytest.mark.topology('any'),
]

# Small topologies: require SIGTERM log for every LAG (feasible, no syslog flood).
LAG_LOG_STRICT_PER_PC_MAX = 64

# Large topologies: per-LAG patterns for 'all' LAGs fail when rsyslog drops lines; use one
# broad pattern plus certain samples of LAG names that must each match. A single
# broken LAG may still slip if it is not in the sample and its line is dropped — syslog
# cannot prove completeness for hundreds of LAGs;
LOG_EXPECT_PO_CLEANUP_RE = r".*teammgrd: :- cleanTeamProcesses: Sent SIGTERM to port channel.*{}.*"
LOG_EXPECT_PO_CLEANUP_SIGTERM_ANY = (
    r".*teammgrd: :- cleanTeamProcesses: Sent SIGTERM to port channel PortChannel[0-9]+.*"
)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        LAG tests are triggering following syncd complaints but the don't cause
        harm to DUT.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    # when loganalyzer is disabled, the object could be None
    if loganalyzer:
        ignoreRegex = [
            ".*",
        ]
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)
        expectRegex = [
            ".*teammgrd: :- cleanTeamProcesses.*",
            ".*teamsyncd: :- cleanTeamSync.*"
        ]
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].expect_regex.extend(expectRegex)


@pytest.fixture(autouse=True)
def disable_route_check_for_duthost(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    allowed_topologies = {"t2", "ut2", "lt2"}
    topo_name = tbinfo['topo']['name']
    if topo_name in allowed_topologies:
        logging.info("Stopping route check monitor before test case")
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in duthosts.frontend_nodes:
                executor.submit(stop_route_checker_on_duthost, duthost, wait_for_status=True)
    else:
        logging.info("Topology {} is not allowed for disable_route_check_for_duthost fixture".format(topo_name))

    yield


def lag_numeric_key(name):
    return int(str(name).replace("PortChannel", ""), 10)


def bgp_wait_seconds_after_config_reload(sonic_host, requested_wait):
    """
    Seconds for wait_until(check_bgp_session_state_all_asics) after config_reload, matching
    tests.common.config_reload: modular_chassis.Additionally, for H6 platform wait bump then +120.
    """
    wait = requested_wait
    if sonic_host.get_facts().get("modular_chassis"):
        wait = max(wait, 600)
    platform = sonic_host.facts['platform']
    if platform in ['x86_64-nokia_ixr7220_h6_128-r0']:
        wait = max(wait, 600)
    return wait + 120


def stratified_lag_samples_for_syslog(sorted_pcs, max_samples=14):
    """Spread indices over sorted_pcs so one mandatory SIGTERM line per sampled LAG."""
    n = len(sorted_pcs)
    if n <= max_samples:
        return list(sorted_pcs)
    idxs = {
        0, 1, 2, max(0, n // 8 - 1), n // 4, n // 2 - 1, n // 2, n // 2 + 1,
        (3 * n) // 4, n - 4, n - 3, n - 2, n - 1,
    }
    out = []
    for i in sorted(x for x in idxs if 0 <= x < n):
        pc = sorted_pcs[i]
        if not out or out[-1] != pc:
            out.append(pc)
    return out[:max_samples]


def check_kernel_po_interface_cleaned(duthost, asic_index):
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    res = duthost.shell(duthost.get_linux_ip_cmd_for_namespace("ip link show | grep -c PortChannel", namespace),
                        module_ignore_errors=True)["stdout_lines"][0]
    return res == '0'


def test_po_cleanup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index, tbinfo):
    """
    test port channel are cleaned up correctly and teammgrd and teamsyncd process
    handle  SIGTERM gracefully
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logging.info("Disable swss/teamd Feature in all asics")
    # Following will call "sudo systemctl stop swss@0", same for swss@1 ..
    duthost.stop_service("swss")
    # Check if Linux Kernel Portchannel Interface teamdev are clean up
    for asic_id in duthost.get_asic_ids():
        if not wait_until(10, 1, 0, check_kernel_po_interface_cleaned, duthost, asic_id):
            fail_msg = "PortChannel interface still exists in kernel"
            pytest.fail(fail_msg)
    # Restore config services
    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


def test_po_cleanup_after_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    test port channel are cleaned up correctly after config reload, with system under stress.

    For large LAG counts we require a stratified subset of LAGs to
    each log SIGTERM plus a broad pattern for any LAG; for small counts we still require
    every LAG.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    host_facts = duthost.setup()['ansible_facts']

    # Get the cpu information.
    if "ansible_processor_vcpus" in host_facts:
        host_vcpus = int(host_facts['ansible_processor_vcpus'])
    else:
        res = duthost.shell("nproc")
        host_vcpus = int(res['stdout'])

    logging.info("found {} cpu on the dut".format(host_vcpus))

    # Get portchannel facts and interfaces.
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    port_channel_intfs = list(lag_facts['names'].keys())
    n_pc = len(port_channel_intfs)
    pcs_sorted = sorted(port_channel_intfs, key=lag_numeric_key)

    # Add start marker to the DUT syslog
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='port_channel_cleanup')
    if n_pc <= LAG_LOG_STRICT_PER_PC_MAX:
        loganalyzer.expect_regex = [LOG_EXPECT_PO_CLEANUP_RE.format(pc) for pc in port_channel_intfs]
        logging.info(
            "test_po_cleanup_after_reload: {} port channels; loganalyzer requires SIGTERM "
            "line per LAG (strict)".format(n_pc))
    else:
        sample = stratified_lag_samples_for_syslog(pcs_sorted)
        loganalyzer.expect_regex = [LOG_EXPECT_PO_CLEANUP_SIGTERM_ANY] + [
            LOG_EXPECT_PO_CLEANUP_RE.format(pc) for pc in sample]
        logging.info(
            "test_po_cleanup_after_reload: {} port channels; loganalyzer uses broad SIGTERM "
            "pattern plus {} stratified mandatory LAGs".format(n_pc, len(sample)))

    watchdog_pid = None
    try:
        # Start a watchdog that guarantees cleanup even if the test times out or aborts.
        # Without this, 'yes' processes can leak on weak-per-core platforms (e.g. armhf)
        # where the test may be killed before reaching the finally block.
        # See: https://github.com/sonic-net/sonic-mgmt/issues/21517
        watchdog_timeout = 600  # 10 minutes — well beyond config_reload's 240s wait
        watchdog_cmd = "nohup sh -c 'sleep {}; pkill -x -9 yes' >/dev/null 2>&1 & echo $!".format(
            watchdog_timeout)
        watchdog_pid = duthost.shell(watchdog_cmd)['stdout'].strip()

        # Make CPU high
        for i in range(host_vcpus):
            duthost.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        # Stop rsyslogd in the swss container for this test case. This is because in the
        # shutdown path, there will be a flood of syslogs from orchagent with messages
        # like "removeLag: Failed to remove ref count 3 LAG PortChannel101". On scale
        # setups, this can potentially cause some syslogs from other containers to get
        # missed (because rsyslog is all using UDP, so if the RX buffer on the host's
        # rsyslogd gets full, messages will get dropped. This test case is looking for
        # specific logs from the teamd container, and if those logs happen to get dropped,
        # this test case will incorrectly fail.
        #
        # Since we don't care about logs from swss for this test case, stop rsyslogd in
        # the swss container completely.
        for asic_id in duthost.get_asic_ids():
            if asic_id is None:
                asic_id = ""
            duthost.command("docker exec swss{} supervisorctl stop rsyslogd".format(asic_id))

        with loganalyzer:
            with DisableLogrotateAndWaitSyslogContext(
                duthost,
                cleanup=lambda: duthost.shell("killall yes", module_ignore_errors=True),
            ):
                logging.info("Reloading config..")
                if n_pc > LAG_LOG_STRICT_PER_PC_MAX:
                    # Scale LAG + per-vCPU `yes` keeps CPUs busy during reload; `config_reload`'s
                    # BGP wait would then time out. Keep stress for reload/teammgrd path, then drop
                    # load and wait for BGP here (same timeout math as config_reload).
                    config_reload(duthost, wait=240, safe_reload=True, wait_for_bgp=False)
                    duthost.shell("killall yes", module_ignore_errors=True)
                    bgp_neighbors = duthost.get_bgp_neighbors_per_asic(state="all")
                    bgp_timeout = bgp_wait_seconds_after_config_reload(duthost, 240)
                    pytest_assert(
                        wait_until(bgp_timeout, 10, 0, duthost.check_bgp_session_state_all_asics, bgp_neighbors),
                        "Not all bgp sessions are established after config reload",
                    )
                else:
                    config_reload(duthost, wait=240, safe_reload=True, wait_for_bgp=True)
        # Cancel the watchdog so it doesn't fire during later tests
        if watchdog_pid:
            duthost.shell("kill {} 2>/dev/null || true".format(watchdog_pid), module_ignore_errors=True)
    except Exception:
        duthost.shell("killall yes", module_ignore_errors=True)
        if watchdog_pid:
            duthost.shell("kill {} 2>/dev/null || true".format(watchdog_pid), module_ignore_errors=True)
        raise
