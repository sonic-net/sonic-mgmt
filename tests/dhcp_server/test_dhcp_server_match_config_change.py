"""MATCH mode runtime configuration and recovery tests (C01-C12 of the IPv4 match condition test plan)."""
import logging
import time

import pytest
import ptf.packet as scapy

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401
from dhcp_server_match_common import match_env, match_config_snapshot, match_test_isolation, \
    ignore_expected_errors  # noqa: F401
from dhcp_server_match_common import VENDOR_A, VENDOR_B, KEA_GENERATION_ERROR, DHCP_SERVER_CONTAINER, \
    MatchConfig, DhcpClient, baseline_config, binding_command, run_cli, hset_config_db, del_config_db, \
    add_syslog_marker, wait_for_syslog, wait_for_kea_pools, get_kea_pools, get_kea_config_hash, \
    get_kea_match_state, get_kea_lease, kea_lease_active, remaining_lease_seconds, get_state_db_lease, \
    get_dhcp_server_pids, verify_client_lease, expect_nak, expect_ack, cleanup_test_leases, dhcp_option
from dhcp_server_test_common import DHCP_MESSAGE_TYPE_NAK_NUM

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('mx'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"]),
]

PERSISTENCE_LEASE_TIME = 3600
LEASE_MARGIN = 120
# Recovery plus verification budget for each persistence action, in seconds.
PERSISTENCE_BUDGET = {"config_reload": 600, "service_restart": 300, "cold_reboot": 1200}
SECOND_PREFIX_INTERFACE = "10.231.0.1/24"
SECOND_PREFIX_IP = "10.231.0.10"
MOVED_PREFIX_INTERFACE = "10.232.0.1/24"


@pytest.fixture(scope="module", autouse=True)
def match_module_setup(match_config_snapshot):  # noqa: F811
    yield


@pytest.fixture(autouse=True)
def match_test_setup(match_test_isolation, enable_sonic_dhcpv4_relay_agent):  # noqa: F811
    yield


def _general(env):
    return env.ip_range(100, 104)


def _assert_baseline_served(env, ptfadapter, skip_p1=False):
    """Probe the baseline assignment table with DISCOVERs (no leases are created)."""
    if not skip_p1:
        DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))
        DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_offer(env.ip(22))
        DhcpClient(env, ptfadapter, env.p1).expect_offer(_general(env))
    DhcpClient(env, ptfadapter, env.p2).expect_offer(env.ip(30))


def _binding_cmd(env, verb, name, matches=None, ips=None, ranges=None):
    cmd = "config dhcp_server ipv4 binding {} {} {}".format(verb, env.vlan, name)
    if matches:
        cmd += " --match {}".format(",".join(matches))
    if ranges:
        cmd += " --range {}".format(",".join(ranges))
    if ips:
        cmd += " {}".format(",".join(ips))
    return cmd


def _offered_ip(env, ptfadapter, port, opt60=None):
    reply = DhcpClient(env, ptfadapter, port, opt60).discover()
    return reply[scapy.BOOTP].yiaddr if reply is not None else None


def _wait_offer(env, ptfadapter, port, opt60, expected, what):
    """Wait for a runtime change that does not alter the pool set to take effect."""
    pytest_assert(wait_until(30, 2, 0, lambda: _offered_ip(env, ptfadapter, port, opt60) == expected),
                  "{}: client on {} with Option 60 {!r} is not offered {}".format(what, port.name, opt60, expected))


def _wait_container_restarted(duthost, started_at, timeout=180):
    def _restarted():
        state = duthost.shell("docker inspect -f '{{{{.State.StartedAt}}}} {{{{.State.Running}}}}' {}".format(
            DHCP_SERVER_CONTAINER), module_ignore_errors=True)["stdout"].split()
        return len(state) == 2 and state[0] != started_at and state[1] == "true"
    pytest_assert(wait_until(timeout, 3, 0, _restarted), "dhcp_server container did not restart")


def _container_started_at(duthost):
    return duthost.shell("docker inspect -f '{{{{.State.StartedAt}}}}' {}".format(DHCP_SERVER_CONTAINER))["stdout"]


def _wait_kea_running(duthost, timeout=180):
    pytest_assert(wait_until(timeout, 3, 0, lambda: "RUNNING" in duthost.shell(
        "docker exec {} supervisorctl status dhcp-server-ipv4:kea-dhcp4".format(DHCP_SERVER_CONTAINER),
        module_ignore_errors=True)["stdout"]), "kea-dhcp4 is not running")


def test_match_binding_add_update_del(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C01: binding add, update (IP, matches, ranges) and delete apply at runtime without restart."""
    env = match_env
    r1 = env.ip_range(100, 104)
    cfg = MatchConfig(env)
    cfg.add_range("r1", r1[0], r1[-1])
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_match("vendor_b", "option60", VENDOR_B)
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)

    run_cli(duthost, _binding_cmd(env, "add", "a_on_p1", ["port_p1", "vendor_a"], ips=[env.ip(21)]))
    wait_for_kea_pools(duthost, env, {(env.ip(21), env.ip(21))})
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))

    run_cli(duthost, _binding_cmd(env, "update", "a_on_p1", ips=[env.ip(25)]))
    wait_for_kea_pools(duthost, env, {(env.ip(25), env.ip(25))})
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(25))

    run_cli(duthost, _binding_cmd(env, "update", "a_on_p1", ["port_p1", "vendor_b"]))
    _wait_offer(env, ptfadapter, env.p1, VENDOR_B, env.ip(25), "Binding match update")
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_no_offer()

    run_cli(duthost, _binding_cmd(env, "update", "a_on_p1", ranges=["r1"]))
    wait_for_kea_pools(duthost, env, {(r1[0], r1[-1])})
    DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_offer(r1)

    run_cli(duthost, "config dhcp_server ipv4 binding del {} a_on_p1".format(env.vlan))
    wait_for_kea_pools(duthost, env, set())
    DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_no_offer()
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def test_match_add_more_specific_binding(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C02: adding a more-specific binding keeps the general lease but NAKs its renewal."""
    env = match_env
    cfg = baseline_config(env)
    del cfg.bindings["a_on_p1"]
    cfg.apply(duthost)

    client = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    general_ip = client.dora(_general(env))
    verify_client_lease(duthost, env, client, general_ip)

    run_cli(duthost, _binding_cmd(env, "add", "a_on_p1", ["port_p1", "vendor_a"], ips=[env.ip(21)]))
    wait_for_kea_pools(duthost, env, baseline_config(env).expected_pools())
    pytest_assert(kea_lease_active(duthost, general_ip, client.mac), "Kea deleted the general lease")
    pytest_assert(get_state_db_lease(duthost, env.vlan, client.mac).get("ip") == general_ip,
                  "State DB lost the general lease")

    expect_nak(client.renew(general_ip), "RENEW of the general address after adding a more-specific binding")
    client.dora(env.ip(21))


def test_match_condition_update(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C03: updating a vendor value or a port alias reclassifies all dependent bindings."""
    env = match_env
    baseline_config(env).apply(duthost)
    pids = get_dhcp_server_pids(duthost)

    run_cli(duthost, "config dhcp_server ipv4 match update vendor_a --value VendorA2")
    _wait_offer(env, ptfadapter, env.p1, "VendorA2", env.ip(21), "Vendor value update")
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(_general(env))

    run_cli(duthost, "config dhcp_server ipv4 binding del {} any_on_p2".format(env.vlan))
    run_cli(duthost, "config dhcp_server ipv4 match update port_p1 --value {}".format(env.p2.alias))
    expected = baseline_config(env).expected_pools() - {(env.ip(30), env.ip(30))}
    wait_for_kea_pools(duthost, env, expected)
    _wait_offer(env, ptfadapter, env.p2, VENDOR_B, env.ip(22), "Port alias update")
    DhcpClient(env, ptfadapter, env.p2, "VendorA2").expect_offer(env.ip(21))
    DhcpClient(env, ptfadapter, env.p2).expect_offer(_general(env))
    for opt60 in ("VendorA2", VENDOR_B, None):
        DhcpClient(env, ptfadapter, env.p1, opt60).expect_no_offer()
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def test_match_range_update(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C04: updating a referenced range moves the pool for new clients."""
    env = match_env
    old_range = env.ip_range(100, 104)
    new_range = env.ip_range(110, 114)
    cfg = MatchConfig(env)
    cfg.add_range("r1", old_range[0], old_range[-1])
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_binding("any_on_p1", ["port_p1"], ranges=["r1"])
    cfg.apply(duthost)
    DhcpClient(env, ptfadapter, env.p1).expect_offer(old_range)

    run_cli(duthost, "config dhcp_server ipv4 range update r1 {} {}".format(new_range[0], new_range[-1]))
    wait_for_kea_pools(duthost, env, {(new_range[0], new_range[-1])})
    client = DhcpClient(env, ptfadapter, env.p1)
    client.dora(new_range)


def test_match_mode_switch(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C05: switching PORT/MATCH serves only the active mode and does not delete leases."""
    env = match_env
    cfg = baseline_config(env, mode="PORT")
    cfg.add_range("port_range", env.ip(60))
    cfg.add_port_binding(env.p1.name, ["port_range"])
    cfg.apply(duthost)
    port_state = get_kea_match_state(duthost)

    port_client = DhcpClient(env, ptfadapter, env.p1)
    port_ip = port_client.dora(env.ip(60))
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_no_offer()

    run_cli(duthost, "config dhcp_server ipv4 update {} --mode MATCH".format(env.vlan))
    cfg.mode = "MATCH"
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))
    pytest_assert(kea_lease_active(duthost, port_ip, port_client.mac), "Mode switch deleted the PORT lease")
    # .60 is in no MATCH pool, so Kea treats it as an unknown address and drops the NAK
    # (DHCP4_UNKNOWN_ADDRESS_REQUESTED); it NAKs only addresses in a pool the class may not use.
    reply = port_client.renew(port_ip)
    pytest_assert(reply is None or dhcp_option(reply, "message-type") == DHCP_MESSAGE_TYPE_NAK_NUM,
                  "RENEW of the PORT address in MATCH mode was not refused: {}".format(
                      reply.summary() if reply else None))

    run_cli(duthost, "config dhcp_server ipv4 update {} --mode PORT".format(env.vlan))
    cfg.mode = "PORT"
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    pytest_assert(get_kea_match_state(duthost) == port_state, "Kea configuration differs after switching back")
    expect_ack(env, port_client.renew(port_ip), port_ip, "RENEW after switching back to PORT")


def test_match_interface_enable_disable(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C06: disabled or binding-less MATCH interfaces send no offer and Kea keeps running."""
    env = match_env
    cfg = baseline_config(env)
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)

    run_cli(duthost, "config dhcp_server ipv4 disable {}".format(env.vlan))
    wait_for_kea_pools(duthost, env, set())
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_no_offer()
    DhcpClient(env, ptfadapter, env.p2).expect_no_offer()
    run_cli(duthost, "config dhcp_server ipv4 enable {}".format(env.vlan))
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    _assert_baseline_served(env, ptfadapter)

    for name in cfg.bindings:
        run_cli(duthost, "config dhcp_server ipv4 binding del {} {}".format(env.vlan, name))
    wait_for_kea_pools(duthost, env, set())
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_no_offer()

    run_cli(duthost, "config dhcp_server ipv4 disable {}".format(env.vlan))
    run_cli(duthost, "config dhcp_server ipv4 enable {}".format(env.vlan))
    wait_for_kea_pools(duthost, env, set())
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_no_offer()
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")

    run_cli(duthost, binding_command(env.vlan, "a_on_p1", cfg.bindings["a_on_p1"]))
    wait_for_kea_pools(duthost, env, {(env.ip(21), env.ip(21))})
    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))


def test_match_vlan_member_change(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C07: bindings of a port that leaves the VLAN are skipped; others keep serving."""
    env = match_env
    cfg = baseline_config(env)
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)
    marker = add_syslog_marker(duthost)
    try:
        run_cli(duthost, "config vlan member del {} {}".format(env.vlan_id, env.p1.name))
        wait_for_syslog(duthost, marker, "circuit ID value {} is not a member of {}".format(env.p1.alias, env.vlan))
        wait_for_kea_pools(duthost, env, {(env.ip(30), env.ip(30))})
        DhcpClient(env, ptfadapter, env.p2).expect_offer(env.ip(30))
    finally:
        duthost.shell("config vlan member add -u {} {}".format(env.vlan_id, env.p1.name), module_ignore_errors=True)
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    _assert_baseline_served(env, ptfadapter)
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def test_match_vlan_prefix_change(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C08: pools outside a changed VLAN prefix are skipped; restoring the prefix restores service."""
    env = match_env
    cfg = baseline_config(env)
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)
    try:
        run_cli(duthost, "config interface ip remove {} {}".format(env.vlan, env.vlan_interface))
        run_cli(duthost, "config interface ip add {} {}".format(env.vlan, MOVED_PREFIX_INTERFACE))
        wait_for_kea_pools(duthost, env, set())
        DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_no_offer()
        DhcpClient(env, ptfadapter, env.p2).expect_no_offer()
        pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")
    finally:
        duthost.shell("config interface ip remove {} {}".format(env.vlan, MOVED_PREFIX_INTERFACE),
                      module_ignore_errors=True)
        duthost.shell("config interface ip add {} {}".format(env.vlan, env.vlan_interface), module_ignore_errors=True)
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    _wait_offer(env, ptfadapter, env.p2, None, env.ip(30), "VLAN prefix restore")
    _assert_baseline_served(env, ptfadapter)


@pytest.mark.parametrize("invalid_case", ["equal_specificity", "partial_overlap", "multi_prefix"])
def test_match_invalid_config_keeps_last_known_good(duthost, ptfadapter, match_env, invalid_case,  # noqa: F811
                                                    ignore_expected_errors, relay_agent):  # noqa: F811
    """C09: configuration that cannot be compiled is logged and the last-known-good Kea config keeps serving."""
    env = match_env
    cfg = baseline_config(env)
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)
    kea_hash = get_kea_config_hash(duthost)
    binding_key = "DHCP_SERVER_IPV4_BINDING|{}|invalid_binding".format(env.vlan)
    range_key = "DHCP_SERVER_IPV4_RANGE|invalid_range"
    if invalid_case == "equal_specificity":
        error = "overlap with equal specificity"
        fields = {"matches@": "vendor_a", "ips@": env.ip(70)}
    elif invalid_case == "partial_overlap":
        error = "have partially overlapping pools"
        fields = {"matches@": "port_p2,vendor_a", "ranges@": "invalid_range"}
    else:
        error = "cannot span multiple IPv4 prefixes"
        fields = {"matches@": "port_p2,vendor_a", "ips@": SECOND_PREFIX_IP}
    ignore_expected_errors(KEA_GENERATION_ERROR, ".*{}.*".format(error))

    second_prefix_added = False
    try:
        if invalid_case == "partial_overlap":
            hset_config_db(duthost, range_key, {"range@": "{},{}".format(env.ip(103), env.ip(106))})
        if invalid_case == "multi_prefix":
            run_cli(duthost, "config interface ip add {} {}".format(env.vlan, SECOND_PREFIX_INTERFACE))
            second_prefix_added = True
        marker = add_syslog_marker(duthost)
        hset_config_db(duthost, binding_key, fields)
        wait_for_syslog(duthost, marker, error)
        pytest_assert(get_kea_config_hash(duthost) == kea_hash, "Running Kea configuration changed")
        _assert_baseline_served(env, ptfadapter)
    finally:
        del_config_db(duthost, binding_key)
        del_config_db(duthost, range_key)
        if second_prefix_added:
            duthost.shell("config interface ip remove {} {}".format(env.vlan, SECOND_PREFIX_INTERFACE),
                          module_ignore_errors=True)

    # Recovery: a valid change after removing the invalid entry is applied without restart.
    run_cli(duthost, "config dhcp_server ipv4 binding update {} any_on_p2 {}".format(env.vlan, env.ip(31)))
    expected = cfg.expected_pools() - {(env.ip(30), env.ip(30))} | {(env.ip(31), env.ip(31))}
    wait_for_kea_pools(duthost, env, expected)
    DhcpClient(env, ptfadapter, env.p2).expect_offer(env.ip(31))
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def test_match_missing_match_reference(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C10a: a missing match skips its dependent binding; restoring it re-enables the binding."""
    env = match_env
    cfg = baseline_config(env)
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)
    match_key = "DHCP_SERVER_IPV4_MATCH|vendor_a"
    marker = add_syslog_marker(duthost)
    del_config_db(duthost, match_key)
    try:
        wait_for_syslog(duthost, marker, "match vendor_a does not exist, skip")
        wait_for_kea_pools(duthost, env, cfg.expected_pools() - {(env.ip(21), env.ip(21))})
        DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(_general(env))
        DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_offer(env.ip(22))
        DhcpClient(env, ptfadapter, env.p2).expect_offer(env.ip(30))
    finally:
        hset_config_db(duthost, match_key, cfg.matches["vendor_a"])
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    _assert_baseline_served(env, ptfadapter)
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def test_match_missing_range_reference(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """C10b: a missing range drops only its pool; a binding without usable pools is skipped."""
    env = match_env
    cfg = MatchConfig(env)
    cfg.add_range("r1", env.ip(100), env.ip(101))
    cfg.add_range("r2", env.ip(110))
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_binding("any_on_p1", ["port_p1"], ranges=["r1", "r2"])
    cfg.apply(duthost)
    pids = get_dhcp_server_pids(duthost)
    all_addresses = [env.ip(100), env.ip(101), env.ip(110)]
    try:
        marker = add_syslog_marker(duthost)
        del_config_db(duthost, "DHCP_SERVER_IPV4_RANGE|r1")
        wait_for_syslog(duthost, marker, "Range r1 referenced by")
        wait_for_kea_pools(duthost, env, {(env.ip(110), env.ip(110))})
        DhcpClient(env, ptfadapter, env.p1).expect_offer(env.ip(110))

        marker = add_syslog_marker(duthost)
        del_config_db(duthost, "DHCP_SERVER_IPV4_RANGE|r2")
        wait_for_syslog(duthost, marker, "has no usable pool, skip")
        wait_for_kea_pools(duthost, env, set())
        DhcpClient(env, ptfadapter, env.p1).expect_no_offer()
        pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")
    finally:
        for name, (start, end) in cfg.ranges.items():
            hset_config_db(duthost, "DHCP_SERVER_IPV4_RANGE|{}".format(name), {"range@": "{},{}".format(start, end)})
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    client = DhcpClient(env, ptfadapter, env.p1)
    client.dora(all_addresses)
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def _show(duthost, what):
    return duthost.shell("show dhcp_server ipv4 {}".format(what))["stdout"]


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("action", ["config_reload", "service_restart", "cold_reboot"])
def test_match_persistence(duthost, localhost, ptfadapter, match_env, action, relay_agent):  # noqa: F811
    """C11: MATCH configuration and unexpired leases persist across reload, restart and reboot."""
    env = match_env
    budget = PERSISTENCE_BUDGET[action] + LEASE_MARGIN
    pytest_assert(PERSISTENCE_LEASE_TIME > budget, "Lease time does not cover the {} budget".format(action))
    cfg = baseline_config(env, lease_time=PERSISTENCE_LEASE_TIME)
    cfg.apply(duthost)
    clients = [DhcpClient(env, ptfadapter, env.p1, VENDOR_A), DhcpClient(env, ptfadapter, env.p2)]
    for client, expected in zip(clients, (env.ip(21), env.ip(30))):
        client.dora(expected, lease_time=PERSISTENCE_LEASE_TIME)
        verify_client_lease(duthost, env, client, client.ip, PERSISTENCE_LEASE_TIME)
    run_cli(duthost, "config save -y")
    before = {"match": _show(duthost, "match"), "binding": _show(duthost, "binding"),
              "kea": get_kea_match_state(duthost)}
    for client in clients:
        remaining = remaining_lease_seconds(duthost, client.ip)
        pytest_assert(remaining > budget, "Precondition: lease {} has {}s left, budget is {}s".format(
            client.ip, remaining, budget))
    expiry = {client.ip: get_kea_lease(duthost, client.ip)["cltt"] + PERSISTENCE_LEASE_TIME for client in clients}

    started = time.time()
    if action == "config_reload":
        config_reload(duthost, config_source="config_db", safe_reload=True)
    elif action == "service_restart":
        duthost.shell("sudo systemctl restart dhcp_server")
    else:
        reboot(duthost, localhost, reboot_type="cold", safe_reboot=True)
    _wait_kea_running(duthost)
    wait_for_kea_pools(duthost, env, cfg.expected_pools(), timeout=180)
    elapsed = time.time() - started
    logger.info("%s recovery took %.0f seconds", action, elapsed)

    pytest_assert(_show(duthost, "match") == before["match"], "show match changed after {}".format(action))
    pytest_assert(_show(duthost, "binding") == before["binding"], "show binding changed after {}".format(action))
    pytest_assert(get_kea_match_state(duthost) == before["kea"], "Kea configuration changed after {}".format(action))
    for client in clients:
        if time.time() >= expiry[client.ip]:
            pytest.fail("Timing precondition failure: {} recovery took {:.0f}s and lease {} expired; this is a "
                        "budget overrun, not a persistence failure".format(action, elapsed, client.ip))
        pytest_assert(kea_lease_active(duthost, client.ip, client.mac),
                      "Lease {} for {} did not persist in Kea after {}".format(client.ip, client.mac, action))
        # A cold reboot empties State DB, and dhcpservd only re-syncs leases from the Kea lease file on
        # the next lease event (SIGUSR1 from Kea's run_script hook), so State DB is checked after RENEW.
        if action != "cold_reboot":
            pytest_assert(_state_db_has_lease(duthost, env, client),
                          "Lease {} did not persist in State DB after {}".format(client.ip, action))
    for client in clients:
        old_cltt = get_kea_lease(duthost, client.ip)["cltt"]
        expect_ack(env, client.renew(client.ip), client.ip, "RENEW after {}".format(action),
                   lease_time=PERSISTENCE_LEASE_TIME)
        pytest_assert(wait_until(10, 1, 0, lambda: get_kea_lease(duthost, client.ip)["cltt"] > old_cltt),
                      "Lease expiry for {} did not advance".format(client.ip))
    for client in clients:
        pytest_assert(_state_db_has_lease(duthost, env, client),
                      "Lease {} is not in State DB after RENEW following {}".format(client.ip, action))
    cleanup_test_leases(duthost)


def _state_db_has_lease(duthost, env, client):
    return wait_until(30, 2, 0, lambda: get_state_db_lease(duthost, env.vlan, client.mac).get("ip") == client.ip)


@pytest.mark.parametrize("program", ["dhcpservd", "kea-dhcp4"])
def test_match_critical_process(duthost, ptfadapter, match_env, program, ignore_expected_errors,  # noqa: F811
                                relay_agent):
    """C12: killing a critical process restarts the container and restores MATCH service."""
    env = match_env
    critical = duthost.shell("docker exec {} cat /etc/supervisor/critical_processes".format(
        DHCP_SERVER_CONTAINER))["stdout"]
    pytest_assert("dhcp-server-ipv4" in critical, "Unexpected critical process list: {}".format(critical))
    ignore_expected_errors(r".*Process '{}' is not running.*".format(program),
                           r".*{}.*exited unexpectedly.*".format(program),
                           r".*dhcp_server.*(exited|terminated|Stopped|failed).*",
                           r".*Failed to (get|connect|send).*kea.*")
    cfg = baseline_config(env)
    cfg.apply(duthost)
    kea_state = get_kea_match_state(duthost)
    started_at = _container_started_at(duthost)
    pid = duthost.shell("docker exec {} supervisorctl pid dhcp-server-ipv4:{}".format(
        DHCP_SERVER_CONTAINER, program))["stdout"].strip()
    pytest_assert(pid.isdigit() and int(pid) > 0, "Cannot find the PID of {}: {}".format(program, pid))
    try:
        duthost.shell("docker exec {} kill -9 {}".format(DHCP_SERVER_CONTAINER, pid))
        _wait_container_restarted(duthost, started_at)
        _wait_kea_running(duthost)
        wait_for_kea_pools(duthost, env, cfg.expected_pools(), timeout=120)
        pytest_assert(get_kea_match_state(duthost) == kea_state, "Kea configuration changed after recovery")
        _assert_baseline_served(env, ptfadapter)
    finally:
        duthost.shell("sudo systemctl reset-failed dhcp_server", module_ignore_errors=True)
    pytest_assert(get_kea_pools(duthost, env) is not None, "Kea is not reachable after recovery")
