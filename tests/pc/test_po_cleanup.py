import pytest
import logging

from tests.common.fixtures.duthost_utils import stop_route_checker_on_duthost
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.utilities import wait_until
from tests.common import config_reload

pytestmark = [
    pytest.mark.disable_route_check,
    pytest.mark.topology('any'),
]


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


def _get_teamd_pids_by_portchannel(duthost):
    """
    Return a dict mapping portchannel name to its teamd host-level PID.

    teamd processes run inside the 'teamd' container but are visible in the host
    process table.  We parse 'pgrep -a teamd' output and extract the portchannel
    name from the '-t <name>' argument that teamd is invoked with.
    """
    result = duthost.shell("pgrep -a teamd || true", module_ignore_errors=True)
    pids = {}
    for line in result.get('stdout_lines', []):
        # typical line: "12345 /usr/bin/teamd -t PortChannel0001 -f /tmp/..."
        parts = line.split()
        if len(parts) < 2:
            continue
        pid = parts[0]
        for i, part in enumerate(parts):
            if part == '-t' and i + 1 < len(parts):
                pids[parts[i + 1]] = pid
                break
    return pids


def _get_stale_teamd_portchannels(duthost, old_pids):
    """
    Return portchannel names whose old teamd PID is still alive on the DUT.

    A process entry in /proc/<pid>/ persists only while the process is running.
    If the old teamd was properly sent SIGTERM and exited, its /proc entry is gone.
    """
    stale = []
    for pc, pid in old_pids.items():
        result = duthost.shell(
            "test -e /proc/{}/status && echo running || echo gone".format(pid),
            module_ignore_errors=True,
        )
        if 'running' in result.get('stdout', ''):
            stale.append(pc)
    return stale


def _get_portchannels_missing_from_kernel(duthost, port_channel_intfs, lag_facts):
    """
    Return portchannel names that are absent from the kernel after reload.

    A portchannel missing from the kernel means the new teamd process failed to
    (re-)create it, which indicates the old teamd was not properly cleaned up and
    its kernel team device was left in a broken state.
    """
    missing = []
    for pc in port_channel_intfs:
        namespace_id = lag_facts['lags'][pc].get('po_namespace_id', '')
        asic_index = int(namespace_id) if namespace_id else None
        namespace = duthost.get_namespace_from_asic_id(asic_index)
        result = duthost.shell(
            duthost.get_linux_ip_cmd_for_namespace("ip link show {}".format(pc), namespace),
            module_ignore_errors=True,
        )
        if result['rc'] != 0:
            missing.append(pc)
    return missing


def test_po_cleanup_after_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Test that portchannels are cleaned up correctly after config reload under CPU stress.

    Instead of relying on syslog (UDP-based, lossy under stress) to verify that
    SIGTERM was sent to each portchannel's teamd process, this test directly verifies:

    1. Before reload: record the host-level PID of every teamd process.
    2. Trigger config reload under CPU stress.
    3. After reload:
       a. None of the old teamd PIDs are still alive  → cleanup happened correctly.
       b. All portchannel kernel interfaces are present → new teamd started successfully.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    host_facts = duthost.setup()['ansible_facts']

    # Get the CPU count.
    if "ansible_processor_vcpus" in host_facts:
        host_vcpus = int(host_facts['ansible_processor_vcpus'])
    else:
        res = duthost.shell("nproc")
        host_vcpus = int(res['stdout'])

    logging.info("found {} cpu on the dut".format(host_vcpus))

    # Get portchannel facts and interfaces.
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    port_channel_intfs = list(lag_facts['names'].keys())

    if not port_channel_intfs:
        pytest.skip("No portchannel interfaces found on DUT")

    # Record teamd PIDs before reload so we can verify they are gone afterwards.
    old_pids = _get_teamd_pids_by_portchannel(duthost)
    logging.info("Teamd PIDs before reload: %s", old_pids)

    watchdog_pid = None
    try:
        # Start a watchdog that guarantees 'yes' process cleanup even if the test
        # times out or aborts on weak-per-core platforms (e.g. armhf).
        # See: https://github.com/sonic-net/sonic-mgmt/issues/21517
        watchdog_timeout = 600  # 10 minutes — well beyond config_reload's 240s wait
        watchdog_cmd = "nohup sh -c 'sleep {}; pkill -x -9 yes' >/dev/null 2>&1 & echo $!".format(
            watchdog_timeout)
        watchdog_pid = duthost.shell(watchdog_cmd)['stdout'].strip()

        # Saturate all CPUs to stress-test the cleanup path.
        for i in range(host_vcpus):
            duthost.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        logging.info("Reloading config under CPU stress...")
        config_reload(duthost, wait=240, safe_reload=True, wait_for_bgp=True)

        duthost.shell("killall yes", module_ignore_errors=True)

        # Cancel the watchdog now that cleanup has been done.
        if watchdog_pid:
            duthost.shell("kill {} 2>/dev/null || true".format(watchdog_pid), module_ignore_errors=True)
    except Exception:
        duthost.shell("killall yes", module_ignore_errors=True)
        if watchdog_pid:
            duthost.shell("kill {} 2>/dev/null || true".format(watchdog_pid), module_ignore_errors=True)
        raise

    # --- Verification ---
    # 1. Verify old teamd processes are gone (cleanup/SIGTERM worked).
    stale = _get_stale_teamd_portchannels(duthost, old_pids)
    if stale:
        pytest.fail(
            "Old teamd processes are still running after config reload for portchannel(s): {}. "
            "This means cleanTeamProcesses did not send SIGTERM correctly.".format(stale)
        )

    # Warn if we could not obtain pre-reload PIDs for some portchannels — the
    # process may have already exited by the time we sampled, which is harmless.
    no_pid_recorded = [pc for pc in port_channel_intfs if pc not in old_pids]
    if no_pid_recorded:
        logging.warning(
            "Could not record pre-reload teamd PIDs for %d portchannel(s): %s. "
            "They may have already been cycling when sampled.",
            len(no_pid_recorded), no_pid_recorded,
        )

    # 2. Verify all portchannel kernel interfaces came back up.
    #    If a portchannel is missing, it means the new teamd failed to (re-)create its
    #    kernel team device — a sign that the old process left stale kernel state.
    missing = _get_portchannels_missing_from_kernel(duthost, port_channel_intfs, lag_facts)
    if missing:
        pytest.fail(
            "Portchannel kernel interface(s) missing after config reload: {}. "
            "This indicates teamd failed to restart cleanly, likely due to stale "
            "kernel state from an incompletely cleaned-up prior instance.".format(missing)
        )

    logging.info("All %d portchannel(s) verified: old teamd PIDs gone and kernel "
                 "interfaces present after reload.", len(port_channel_intfs))
