import pytest
import logging
import re

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


TEAM_PID_RE = re.compile(r"(\d+)\s+.*\bteamd\b.*-t\s+(PortChannel\d+)\b")


def teamd_container_name(asic_id):
    if asic_id is None:
        return "teamd"
    return "teamd{}".format(asic_id)


def collect_teamd_lag_pids(duthost):
    """
    Host PIDs of per-LAG teamd processes, keyed by PortChannel name.
    """
    pids = {}
    for asic_id in duthost.get_asic_ids():
        container = teamd_container_name(asic_id)
        res = duthost.shell("docker top {} -eo pid,args".format(container), module_ignore_errors=True)
        if res['rc'] != 0:
            logging.info("docker top %s failed: %s", container, res.get('stderr'))
            continue
        for line in res['stdout'].splitlines():
            match = TEAM_PID_RE.search(line)
            if match:
                pids[match.group(2)] = int(match.group(1))
    return pids


def pre_reload_teamd_pids_gone(duthost, old_pids):
    """
    True when none of the pre-reload per-LAG teamd host PIDs are still alive.
    """
    if not old_pids:
        return False
    pid_list = ",".join(str(pid) for pid in old_pids.values())
    res = duthost.shell("ps -o pid= -p {} 2>/dev/null || true".format(pid_list), module_ignore_errors=True)
    alive = [line.strip() for line in res['stdout'].splitlines() if line.strip()]
    if alive:
        logging.info("pre-reload teamd PIDs still alive: %s", alive)
        return False
    return True


def all_lags_recovered(duthost, expected_names, old_pids):
    """
    Every configured LAG has a new teamd process and a kernel interface.
    A reused pre-reload PID means that LAG's teamd was not replaced.
    """
    current = collect_teamd_lag_pids(duthost)
    missing_teamd = [pc for pc in expected_names if pc not in current]
    reused = [pc for pc, pid in old_pids.items() if current.get(pc) == pid]
    if missing_teamd or reused:
        logging.info("LAG teamd not replaced, missing=%s reused=%s", missing_teamd, reused)
        return False

    by_ns = {}
    for pc, ns in expected_names.items():
        by_ns.setdefault(ns or "", []).append(pc)
    for ns, pcs in by_ns.items():
        cmd = duthost.get_linux_ip_cmd_for_namespace("ip link show", ns)
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res['rc'] != 0:
            logging.info("ip link show failed in namespace '%s'", ns)
            return False
        present = set(re.findall(r"PortChannel\d+", res['stdout']))
        absent = [pc for pc in pcs if pc not in present]
        if absent:
            logging.info("kernel PortChannel missing in namespace '%s': %s", ns, absent)
            return False
    return True


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

    Syslog-based checks cannot distinguish a dropped line from a missing SIGTERM for one LAG
    among hundreds. For large LAG counts the log check is a broad SIGTERM pattern plus a
    stratified sample. Every LAG is covered separately: the pre-reload teamd process must be
    gone, and each PortChannel must have a new teamd process and a kernel interface.
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

    # Independent of the syslog sample: one teamd PID per configured LAG.
    teamd_pids_before = collect_teamd_lag_pids(duthost)
    missing_teamd = sorted(set(port_channel_intfs) - set(teamd_pids_before))
    pytest_assert(
        not missing_teamd,
        "teamd process missing before reload for {}".format(missing_teamd))
    logging.info("Snapshotted teamd PIDs for %s LAGs before reload", len(teamd_pids_before))

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

        # Always stop CPU stress after reload (covers small-LAG else branch; large-LAG also
        # kills yes before BGP, then this is a no-op if already gone).
        duthost.shell("killall yes", module_ignore_errors=True)

        # All-LAG cleanup and recovery. Config reload also stops the teamd container, so a
        # dead pre-reload PID alone does not prove cleanTeamProcesses sent SIGTERM. Requiring
        # a new teamd process and a kernel interface for every LAG still fails a cleanup that
        # leaves a LAG unrestored, including LAGs omitted from the syslog sample.
        pytest_assert(
            wait_until(180, 10, 0, pre_reload_teamd_pids_gone, duthost, teamd_pids_before),
            "pre-reload teamd processes still running after config reload")
        pytest_assert(
            wait_until(300, 10, 0, all_lags_recovered, duthost, lag_facts['names'], teamd_pids_before),
            "not all LAG teamd processes and kernel interfaces recovered after config reload")
    except Exception:
        duthost.shell("killall yes", module_ignore_errors=True)
        if watchdog_pid:
            duthost.shell("kill {} 2>/dev/null || true".format(watchdog_pid), module_ignore_errors=True)
        raise
