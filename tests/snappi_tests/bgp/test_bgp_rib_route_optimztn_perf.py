# Added for multi-asic support: this module was reworked (ported from data3
# test_bgp_rib_route_optimztn_perf_v1.py) so the test runs on single-asic, multi-asic and multi-DUT /
# line-card testbeds. The previous single-asic version is kept as bkup.test_bgp_rib_route_optimztn_perf.py.
from tests.common.snappi_tests.snappi_fixtures import (                     # noqa: F401
    snappi_api, snappi_api_serv_ip, snappi_api_serv_port, tgen_ports,
    get_snappi_ports, get_snappi_ports_single_dut, get_snappi_ports_multi_dut)
from tests.snappi_tests.bgp.files.bgp_convergence_helper import run_rib_in_convergence_test, \
    find_blocked_ports                                                      # Added for multi-asic support
# Added for multi-asic support: per-ASIC / per-DUT setup helpers
from tests.snappi_tests.bgp.files.rib_combo_dut_setup import (
    affected_setup_targets,
    apply_bk_to_targets,
    apply_profile_to_targets,
    asic_indices_for_duthost,
    backup_config_dbs,
    revert_bk_on_targets,
    revert_config_db,
    swss_docker_cmd,
    unique_duthosts_from_targets,
)
from tests.common.fixtures.conn_graph_facts import (                        # noqa: F401
    conn_graph_facts, fanout_graph_facts, fanout_graph_facts_multidut)
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
import json
import logging
import os
import pytest
import yaml

logger = logging.getLogger(__name__)

# Added for multi-asic support: 'multidut-tgen' topology (line-card / multi-DUT testbeds) in addition to
# 'tgen'; memory_utilization stays disabled and loganalyzer is disabled because the DUTs are cold rebooted.
pytestmark = [
    pytest.mark.topology('multidut-tgen', 'tgen'),
    pytest.mark.disable_memory_utilization,
    pytest.mark.disable_loganalyzer,
    pytest.mark.enable_proc_mem_cpu_monitor,
]

# Added for multi-asic support: opt-in for the multi-asic / multidut port discovery done by the ``tgen_ports``
# fixture: with --bgp_pc_config it reads the preconfigured port-channels of every ASIC
# (see snappi_fixtures._tgen_ports_from_portchannel_all_asics); without the flag, multi-ASIC DUTs and ports spread
# over several DUTs / line cards are planned per ASIC (snappi_fixtures._tgen_ports_non_pc_all_asics) and the DUT is
# configured by the convergence helper after the config_db backup. Single-asic single-DUT setups are unchanged.
TGEN_PORTS_MULTI_ASIC_SUPPORT = True

# Test parameters (not from files)
CONVERGENCE_TEST_ITERATIONS = 1
RIB_TIMEOUT = 120

_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


def _load_fine_tunings():
    yml_path = os.path.join(_FILES_DIR, 'fine-tunings.yml')
    with open(yml_path, 'r') as f:
        return yaml.safe_load(f)


def _load_bk_pairs():
    """Load (bulk, batch) pairs from bk_values.json.
    Each pair is [bulk_value, batch_value] for orchagent -b and -k.
    Supports legacy: single list -> same value for both; or bulk_values+batch_values -> zip.
    """
    json_path = os.path.join(_FILES_DIR, 'bk_values.json')
    with open(json_path, 'r') as f:
        data = json.load(f)
    if isinstance(data, list):
        return [[v, v] for v in data]
    if 'pairs' in data:
        return data['pairs']
    return list(zip(data['bulk_values'], data['batch_values']))


# To load fine-tuning parameters from files/fine-tunings.yml file.
try:
    _FINE_TUNINGS = _load_fine_tunings() or {}
except Exception:
    _FINE_TUNINGS = {}

# To load bk-values from files/bk_values.json file if present,else load following defaults.
try:
    _BK_PAIRS = _load_bk_pairs()
except Exception:
    _BK_PAIRS = [['default', 'default']]

PROFILE_NAMES = [
    name for name, cfg in _FINE_TUNINGS.items()
    if isinstance(cfg, dict) and (
        cfg.get('config_db_wo_tuning')
        or 'DEVICE_METADATA' in cfg
        or 'SYSTEM_DEFAULTS' in cfg
    )
]

if not PROFILE_NAMES:
    PROFILE_NAMES = ['_no_profile_']


# Added for multi-asic support: one monitored host per distinct DUT / line card used by the test ports.
def _hosts_for_mem_monitor(duthost, ports, port_count):
    seen = set()
    hosts = []
    for port in ports[:port_count]:
        dh = port.get('duthost') or duthost
        if dh.hostname not in seen:
            seen.add(dh.hostname)
            hosts.append(dh)
    return hosts or [duthost]


# Added for multi-asic support: single-DUT tgen_ports entries carry no 'duthost'; default it.
def _ensure_port_duthost(ports, port_count, default_duthost):
    for port in ports[:port_count]:
        if port.get('duthost') is None:
            port['duthost'] = default_duthost


# Added for multi-asic support: setup/teardown is done per (duthost, asic) target (config_dbN.json,
# swss<N> docker on multi-asic) and the cold reboot is done on every distinct DUT / line card.
@pytest.fixture
def dut_ready_for_rib_combo(
        duthost, localhost, profile_name, bulk_value, batch_value, tgen_ports, MULTIPATH,  # noqa: F811
        request, route_type):
    """
    Setup: save config_db backup on every targeted DUT/ASIC, apply profile, apply bulk/batch (-b/-k),
    reboot every targeted DUT, wait.
    Teardown: revert orchagent and config_db from backup.
    """
    if profile_name == '_no_profile_':
        pytest.skip("No valid profiles in fine-tunings.yml")

    # Added for multi-asic support: moved here from the test body so that the skip happens before the DUT is
    # backed up, tuned and rebooted (a skip after the reboot triggers an immediate config reload on teardown).
    if route_type == 'IPv4v6':
        pytest.skip("Skipping test for route_type IPv4v6 due to outstanding keysight issue")

    port_count = MULTIPATH + 1
    profile_config = _FINE_TUNINGS[profile_name]
    _ensure_port_duthost(tgen_ports, port_count, duthost)

    # Added for multi-asic support: without --bgp_pc_config and when the DUT is configured per ASIC (multi-asic DUT
    # or ports planned per ASIC), the helper later removes the ports from their PortChannel and builds new ones, which
    # fails for ports bound to an ACL table or in a VLAN. Check the SAVED config_db (what the cold reboot below will
    # load) before anything is changed, so that the skip is clean: no backup, no reboot, nothing to revert.
    use_bgp_pc_config = request.config.getoption("--bgp_pc_config", default=False)
    if not use_bgp_pc_config and (duthost.is_multi_asic or any(p.get('multi_asic_flow') for p in tgen_ports)):
        blocked_ports = find_blocked_ports(duthost, tgen_ports, port_count, use_saved_config=True)
        if blocked_ports:
            pytest.skip(
                "Test ports cannot be used while bound to an ACL table or a VLAN in the saved config_db. Unbind / "
                "remove them on the DUT, run 'config save' and re-run. Nothing was changed on the DUT. "
                "Affected ports:\n  {}".format("\n  ".join(blocked_ports)))

    targets = affected_setup_targets(tgen_ports, port_count, default_duthost=duthost)

    logger.info(
        'Fixture: profile=%s bulk=%s batch=%s port_count=%s targets=%s',
        profile_name, bulk_value, batch_value, port_count,
        [(t[0].hostname, t[1].asic_index) for t in targets],
    )

    for dh in unique_duthosts_from_targets(targets):
        indices = asic_indices_for_duthost(dh, targets)
        backup_config_dbs(dh, indices)

    # if the config_db_wo_tuning is present, then no changes in config_db (handled in apply_profile_to_targets).
    apply_profile_to_targets(profile_config, targets)
    apply_bk_to_targets(targets, bulk_value, batch_value)

    for dh in unique_duthosts_from_targets(targets):
        logger.info('Fixture: cold reboot %s', dh.hostname)
        reboot(dh, localhost, reboot_type='cold', return_after_reconnect=True)
        pytest_assert(
            wait_until(900, 30, 1, dh.critical_services_fully_started),
            "Not all critical services are fully started on {}".format(dh.hostname),
        )
        logger.info('Applying TSB config on %s to ensure BGP readiness', dh.hostname)
        dh.shell("sudo TSB", module_ignore_errors=True)
        dh.shell("sudo config save -y", module_ignore_errors=True)

    for dh, asic in targets:
        rawout = dh.shell(swss_docker_cmd(dh, asic, 'pgrep -af orchagent'))
        logger.info(
            'orchagent on %s asic%s: %s',
            dh.hostname, asic.asic_index, rawout.get('stdout', ''),
        )

    yield

    logger.info('Fixture teardown: reverting config_db and orchagent')
    revert_bk_on_targets(targets)
    for dh in unique_duthosts_from_targets(targets):
        indices = asic_indices_for_duthost(dh, targets)
        revert_config_db(dh, indices)


@pytest.mark.parametrize('profile_name', PROFILE_NAMES)
@pytest.mark.parametrize('bulk_value,batch_value', _BK_PAIRS)
@pytest.mark.parametrize('route_type', ['IPv4', 'IPv6'])
@pytest.mark.parametrize('MULTIPATH', [1])
@pytest.mark.parametrize('NUMBER_OF_ROUTES', [300000])
def test_rib_route_opt_perf(snappi_api,                    # noqa: F811
                            duthost,
                            tgen_ports,                 # noqa: F811
                            conn_graph_facts,           # noqa: F811
                            fanout_graph_facts,         # noqa: F811
                            dut_ready_for_rib_combo,    # fixture: apply profile + bulk/batch + reboot
                            request,
                            profile_name,
                            bulk_value,
                            MULTIPATH,
                            NUMBER_OF_ROUTES,
                            batch_value,
                            mem_cpu_monitor,
                            tmp_path,
                            route_type,):
    """
    Run RIB-IN convergence test for one (profile, bulk_value, batch_value, route_type).
    DUT is already prepared by dut_ready_for_rib_combo (same boot);

    Profiles and (bulk, batch) pairs are parameterized from files/fine-tunings.yml and
    files/bk_values.json (pairs; same as test_bgp_rib_in_combo).

    supports --bgp_pc_config:
    when --bgp_pc_config is passed, tgen_ports uses port-channel info from config_db
    (every ASIC namespace and every DUT / line card used by the test ports)
    and run_rib_in_convergence_test skips duthost_bgp_config (port-channels preconfigured).

    without --bgp_pc_config (multi-asic / multi-DUT):
    duthost_bgp_config reads each port's ASIC config, frees the ports (IPs, PortChannel / VLAN membership),
    builds the PortChannels and BGP with the DUT / peer ASNs found on the DUT (else DUT_AS_NUM / TGEN_AS_NUM).

    Same flow as test_rib_route_opt_perf with ``mem_cpu_monitor``:
    ``start()`` before convergence, ``get_rib_in_convergence`` snapshots before/after
    RIB-IN metrics and ``stop()`` in ``finally``; optional ``plot()`` to tmp_path.

    """
    if profile_name == '_no_profile_':
        pytest.skip("No valid profiles in fine-tunings.yml")

    # Added for multi-asic support: the IPv4v6 skip now lives in dut_ready_for_rib_combo (before the DUT is touched)

    use_bgp_pc_config = request.config.getoption("--bgp_pc_config", default=False)

    # Added for multi-asic support: monitor every DUT / line card used by the test ports
    port_count = MULTIPATH + 1
    monitor_hosts = _hosts_for_mem_monitor(duthost, tgen_ports, port_count)

    logger.info('Profile=%s, bulk_value=%s, batch_value=%s, route_type=%s, bgp_pc_config=%s multi_asic=%s',
                profile_name, bulk_value, batch_value, route_type, use_bgp_pc_config, duthost.is_multi_asic)

    logger.info('Running RIB-IN convergence test')

    mem_cpu_monitor.start(
        monitor_hosts,
        ["bgpd", "zebra"],
        interval=2.0,
        include_host_free=True,
        host_top_all_procs=True,
        capture_raw_stdout=True,
        include_tcmalloc_stats=True,
        output_basename_style="short_node",
    )

    try:
        run_rib_in_convergence_test(snappi_api,
                                    duthost,
                                    tgen_ports,
                                    CONVERGENCE_TEST_ITERATIONS,
                                    MULTIPATH,
                                    NUMBER_OF_ROUTES,
                                    route_type,
                                    timeout=RIB_TIMEOUT,
                                    skip_duthost_bgp_config=use_bgp_pc_config,
                                    mem_cpu_monitor=mem_cpu_monitor,
                                    tag_tier2_leak_communities=True,    # Added for multi-asic support
                                    skip_cleanup=True)                  # Added for multi-asic support
    finally:
        mem_cpu_monitor.stop()
        plot_path = mem_cpu_monitor.plot(out_dir=str(tmp_path))
        if plot_path:
            logger.info('mem_cpu_monitor plot written to %s', plot_path)
        exported = mem_cpu_monitor.export_samples(out_dir=str(tmp_path))
        for fmt, p in exported.items():
            logger.info('mem_cpu_monitor export_samples (%s) wrote %s', fmt, p)
