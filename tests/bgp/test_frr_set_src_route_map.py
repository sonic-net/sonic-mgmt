"""Ensure mgmtd FRR replays preserve default-route set-src even with large configs."""

import ipaddress
import logging
import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.gcu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0', 't1', 't2')
]


BLOAT_PREFIX_LIST_COUNT = 512
BLOAT_FRR_CONFIG_FILE = "/tmp/frr_set_src_bloat.conf"
ITERATION_LEVEL_MAP = {
    'debug': 1,
    'basic': 1,
    'confident': 2,
    'thorough': 3
}
logger = logging.getLogger(__name__)


def _get_frontend_bgp_docker_names(duthost):
    """Return bgp container names for frontend ASICs only."""
    if not duthost.is_multi_asic:
        return ["bgp"]
    return ["bgp{}".format(asic_id) for asic_id in duthost.get_frontend_asic_ids()]


def _mgmtd_running(duthost):
    """Return True if mgmtd is running inside all frontend bgp containers."""
    for bgp_name in _get_frontend_bgp_docker_names(duthost):
        if duthost.shell(
            "docker exec {} pgrep -x mgmtd".format(bgp_name), module_ignore_errors=True
        )['rc'] != 0:
            return False
    return True


def _get_asic_hosts(duthost):
    """
    Provide a normalized list of ASIC hosts to iterate over.
    """
    if duthost.is_multi_asic:
        return [duthost.asic_instance(asic_index) for asic_index in duthost.get_frontend_asic_ids()]
    return [duthost.asic_instance()]


def _extract_loopback_ips(asichost, duthost):
    """
    Return the IPv4/IPv6 addresses configured on Loopback0 for the supplied ASIC.
    """
    config_facts = asichost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    loopbacks = config_facts.get("LOOPBACK_INTERFACE", {})
    pytest_assert("Loopback0" in loopbacks, "Loopback0 missing from config facts")

    lo_ipv4 = None
    lo_ipv6 = None

    for ip_str in loopbacks["Loopback0"]:
        loop_ip = ipaddress.ip_interface(ip_str)
        if loop_ip.version == 4:
            lo_ipv4 = loop_ip
        elif loop_ip.version == 6:
            lo_ipv6 = loop_ip

    pytest_assert(lo_ipv4, "Failed to locate IPv4 Loopback0 address")
    pytest_assert(lo_ipv6, "Failed to locate IPv6 Loopback0 address")

    return lo_ipv4, lo_ipv6


def _verify_default_route_set_src(asichost, lo_ipv4, lo_ipv6):
    """
    Ensure both IPv4 and IPv6 default routes carry the expected source address.
    """
    ipv4_default = asichost.get_ip_route_info(ipaddress.ip_network("0.0.0.0/0"))
    pytest_assert(ipv4_default.get("set_src"), "IPv4 default route missing set_src attribute")
    pytest_assert(
        ipv4_default["set_src"] == lo_ipv4.ip,
        "IPv4 default route set_src {} does not match Loopback0 {}".format(ipv4_default['set_src'], lo_ipv4.ip)
    )

    ipv6_default = asichost.get_ip_route_info(ipaddress.ip_network("::/0"))
    pytest_assert(ipv6_default.get("set_src"), "IPv6 default route missing set_src attribute")
    pytest_assert(
        ipv6_default["set_src"] == lo_ipv6.ip,
        "IPv6 default route set_src {} does not match Loopback0 {}".format(ipv6_default['set_src'], lo_ipv6.ip)
    )


def _verify_route_maps_in_running_config(asichost, lo_ipv4, lo_ipv6):
    """
    Confirm FRR running-config retains the route-maps that install the Loopback source-ip.
    """
    running_cfg = asichost.run_vtysh("-c 'show running-config'")["stdout"]
    pytest_assert("route-map RM_SET_SRC permit 10" in running_cfg, "RM_SET_SRC missing from running-config")
    pytest_assert(
        "set src {}".format(lo_ipv4.ip) in running_cfg,
        "RM_SET_SRC missing the Loopback0 IPv4 address {}".format(lo_ipv4.ip)
    )
    pytest_assert(
        "ip protocol bgp route-map RM_SET_SRC" in running_cfg,
        "RM_SET_SRC not bound to 'ip protocol bgp'"
    )
    pytest_assert("route-map RM_SET_SRC6 permit 10" in running_cfg, "RM_SET_SRC6 missing from running-config")
    pytest_assert(
        "set src {}".format(lo_ipv6.ip) in running_cfg,
        "RM_SET_SRC6 missing the Loopback0 IPv6 address {}".format(lo_ipv6.ip)
    )
    pytest_assert(
        "ipv6 protocol bgp route-map RM_SET_SRC6" in running_cfg,
        "RM_SET_SRC6 not bound to 'ipv6 protocol bgp'"
    )


def _verify_set_src_all_asics(duthost):
    """Run the default-route checks on every frontend ASIC."""
    for asichost in _get_asic_hosts(duthost):
        lo_ipv4, lo_ipv6 = _extract_loopback_ips(asichost, duthost)
        _verify_default_route_set_src(asichost, lo_ipv4, lo_ipv6)
        _verify_route_maps_in_running_config(asichost, lo_ipv4, lo_ipv6)


def _check_set_src_all_asics(duthost):
    """Non-asserting wrapper for use with wait_until."""
    try:
        _verify_set_src_all_asics(duthost)
        return True
    except Exception as e:
        logger.debug("_check_set_src_all_asics not yet passing: %s", e)
        return False


def _generate_bloat_frr_config(count=BLOAT_PREFIX_LIST_COUNT):
    """Generate FRR prefix-list + route-map lines to add extra config load."""
    assert count <= 65536, "count exceeds 65536; 198.18.x.y address space exhausted"
    lines = []
    for i in range(count):
        lines.append("ip prefix-list BLOAT_PL seq {} permit 198.18.{}.{}/32".format(
            (i + 1) * 5, i // 256, i % 256
        ))
    lines.append("route-map BLOAT_RM permit 10")
    lines.append(" match ip address prefix-list BLOAT_PL")
    return "\n".join(lines) + "\n"


def _inject_bloat_frr_config(duthost, count=BLOAT_PREFIX_LIST_COUNT):
    """Inject bloat prefix-lists into FRR running config via vtysh -f.

    The config file is placed under /etc/frr/ inside the container rather than
    /tmp/ because FRR 10.x daemons may run with PrivateTmp or separate mount
    namespaces, making /tmp invisible to child processes spawned by vtysh -f.
    /etc/frr/ is always shared across all FRR daemon processes.
    """
    config_text = _generate_bloat_frr_config(count)
    duthost.copy(content=config_text, dest=BLOAT_FRR_CONFIG_FILE)
    for bgp_name in _get_frontend_bgp_docker_names(duthost):
        duthost.shell("docker cp {} {}:/etc/frr/bloat.conf".format(BLOAT_FRR_CONFIG_FILE, bgp_name))
        duthost.shell("docker exec {} vtysh -f /etc/frr/bloat.conf".format(bgp_name))
        duthost.shell("docker exec {} rm -f /etc/frr/bloat.conf".format(bgp_name))
        duthost.shell("docker exec {} vtysh -c 'write memory'".format(bgp_name))
    logger.info("Injected %d bloat prefix-list entries into FRR config", count)


def _remove_bloat_frr_config(duthost):
    """Remove injected bloat from FRR running-config and persist the clean state."""
    for bgp_name in _get_frontend_bgp_docker_names(duthost):
        duthost.shell(
            "docker exec {} vtysh -c 'configure terminal' "
            "-c 'no route-map BLOAT_RM' "
            "-c 'no ip prefix-list BLOAT_PL'".format(bgp_name),
            module_ignore_errors=True
        )
        duthost.shell(
            "docker exec {} vtysh -c 'write memory'".format(bgp_name),
            module_ignore_errors=True
        )


def _start_vtysh_race_loop(duthost):
    """
    Start a background process on the DUT that continuously spawns competing
    vtysh sessions.  Returns (pid, pgid) so the caller can kill the process
    group reliably even if the PID has exited by cleanup time.

    The loop must keep running across the config_reload so it catches the
    window when the bgp container comes back and mgmtd starts replaying.
    """
    bgp_names = _get_frontend_bgp_docker_names(duthost)
    probe_cmds = "; ".join(
        'docker exec {c} vtysh -c "show version" &>/dev/null &'.format(c=c)
        for c in bgp_names
    )
    result = duthost.shell(
        "nohup setsid bash -c 'while true; do for i in $(seq 1 5); do "
        "{probes} done; wait; sleep 1; done' >/dev/null 2>&1 & "
        "PID=$!; echo $PID $(ps -o pgid= -p $PID | tr -d ' ')".format(probes=probe_cmds),
        module_ignore_errors=True
    )
    parts = result["stdout"].strip().split()
    pytest_assert(
        len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit(),
        "Failed to start vtysh race loop, got: '{}'".format(result["stdout"].strip())
    )
    pid, pgid = parts
    logger.info("Started vtysh race loop (PID %s, PGID %s) targeting containers: %s", pid, pgid, bgp_names)
    return pid, pgid


def _stop_vtysh_race_loop(duthost, pid, pgid):
    """Kill the background vtysh race loop and its full process tree."""
    # Kill the entire process group (captured at start time for reliability),
    # then the PID itself as a fallback, then mop up any orphaned docker exec
    # vtysh processes.
    duthost.shell(
        "kill -- -{pgid} 2>/dev/null; kill {pid} 2>/dev/null".format(pid=pid, pgid=pgid),
        module_ignore_errors=True
    )
    # Belt and suspenders: kill any remaining docker exec vtysh processes
    duthost.shell(
        "pkill -f 'docker exec.*vtysh.*show version' 2>/dev/null",
        module_ignore_errors=True
    )


def _race_loop_alive(duthost, pid):
    """Return True if the race loop process is still running."""
    return duthost.shell(
        "kill -0 {} 2>/dev/null".format(pid), module_ignore_errors=True
    )['rc'] == 0


def test_mgmtd_preserves_default_route_set_src(
        dut_with_default_route,
        get_function_completeness_level):
    """
    Regress the mgmtd replay bug by forcing a config reload and ensuring FRR keeps the set src route-maps.
    """
    duthost = dut_with_default_route

    pytest_require(_mgmtd_running(duthost), "Test requires mgmtd (FRR 10.x+)")

    normalized_level = get_function_completeness_level if get_function_completeness_level else 'debug'
    iterations = ITERATION_LEVEL_MAP.get(normalized_level, ITERATION_LEVEL_MAP['debug'])

    logger.info("Running mgmtd set-src regression for %s iteration(s)", iterations)

    # Baseline: verify route-maps exist before reload
    pytest_assert(
        wait_until(60, 10, 0, _check_set_src_all_asics, duthost),
        "Baseline check failed: RM_SET_SRC route-maps not present before reload"
    )

    for iteration in range(1, iterations + 1):
        logger.info("Iteration %s/%s: issuing config reload with race amplification", iteration, iterations)
        pid, pgid = _start_vtysh_race_loop(duthost)
        try:
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
            if not _race_loop_alive(duthost, pid):
                logger.warning(
                    "vtysh race loop (PID %s) died during config_reload — "
                    "this iteration did NOT exercise the mgmtd race condition",
                    pid
                )
        finally:
            _stop_vtysh_race_loop(duthost, pid, pgid)

        pytest_assert(
            wait_until(120, 10, 0, _check_set_src_all_asics, duthost),
            "RM_SET_SRC route-maps not restored within 120s after config reload"
        )


def test_mgmtd_preserves_default_route_set_src_with_large_config(
        dut_with_default_route):
    """
    Inject extra FRR config (prefix-lists) before reload to validate that
    route-maps remain correct under additional FRR state.  The bloat is
    FRR-only and does not survive config_reload (container restart
    regenerates frr.conf from CONFIG_DB).
    """
    duthost = dut_with_default_route

    pytest_require(_mgmtd_running(duthost), "Test requires mgmtd (FRR 10.x+)")

    checkpoint_name = "set_src_bloat_cp"

    # Baseline: verify route-maps exist before reload
    pytest_assert(
        wait_until(60, 10, 0, _check_set_src_all_asics, duthost),
        "Baseline check failed: RM_SET_SRC route-maps not present before reload"
    )

    create_checkpoint(duthost, checkpoint_name)

    try:
        _inject_bloat_frr_config(duthost)

        # config save omitted — FRR-only state doesn't persist across reload
        pid, pgid = _start_vtysh_race_loop(duthost)
        try:
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
            if not _race_loop_alive(duthost, pid):
                logger.warning(
                    "vtysh race loop (PID %s) died during config_reload — "
                    "this iteration did NOT exercise the mgmtd race condition",
                    pid
                )
        finally:
            _stop_vtysh_race_loop(duthost, pid, pgid)

        pytest_assert(
            wait_until(120, 10, 0, _check_set_src_all_asics, duthost),
            "RM_SET_SRC route-maps not restored within 120s after config reload"
        )
    finally:
        _remove_bloat_frr_config(duthost)
        rollback_or_reload(duthost, checkpoint_name)
        delete_checkpoint(duthost, checkpoint_name)
        duthost.shell("rm -f {}".format(BLOAT_FRR_CONFIG_FILE), module_ignore_errors=True)
