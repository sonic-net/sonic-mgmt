"""MATCH mode with several DHCP interfaces (M01-M02 of the IPv4 match condition test plan).

A second VLAN with its own prefix is created by moving PTF-connected members out of the first VLAN,
so the first VLAN keeps its addresses and relay settings.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401
from dhcp_server_match_common import match_env, match_config_snapshot, match_test_isolation, \
    ignore_expected_errors  # noqa: F401
from dhcp_server_match_common import VENDOR_A, VENDOR_B, KEA_GENERATION_ERROR, MatchConfig, DhcpClient, \
    baseline_config, apply_match_configs, second_vlan, clean_match_server_config, run_cli, hset_config_db, \
    del_config_db, add_syslog_marker, wait_for_syslog, wait_for_kea_pools, get_kea_pools, get_kea_config_hash, \
    get_kea_subnet_leases, verify_client_lease, expect_ack, get_dhcp_server_pids

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('mx'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"]),
]


@pytest.fixture(scope="module")
def two_vlans(match_config_snapshot, duthost, tbinfo, match_env):  # noqa: F811
    """Yield (env of the original VLAN, env of the new VLAN)."""
    clean_match_server_config(duthost)
    with second_vlan(duthost, tbinfo, match_env) as envs:
        yield envs


@pytest.fixture(autouse=True)
def multi_vlan_test_setup(match_test_isolation, enable_sonic_dhcpv4_relay_agent):  # noqa: F811
    yield


def _port_config(env):
    cfg = MatchConfig(env, mode="PORT")
    cfg.add_range("mv_b_r1", env.ip(100), env.ip(104))
    cfg.add_range("mv_b_r2", env.ip(110), env.ip(114))
    cfg.add_port_binding(env.p1.name, ["mv_b_r1"])
    cfg.add_port_binding(env.p2.name, ["mv_b_r2"])
    return cfg


def _assert_port_vlan_served(env, ptfadapter):
    DhcpClient(env, ptfadapter, env.p1).expect_offer(env.ip_range(100, 104))
    DhcpClient(env, ptfadapter, env.p2).expect_offer(env.ip_range(110, 114))


def _assert_port_vlan_unaffected(duthost, env, ptfadapter, pools, clients, what):
    pytest_assert(get_kea_pools(duthost, env) == pools, "{}: pools of {} changed to {}".format(
        what, env.vlan, get_kea_pools(duthost, env)))
    leases = {mac: ip for mac, ip in get_kea_subnet_leases(duthost, env.vlan_id).items()
              if mac in {client.mac for client in clients}}
    pytest_assert(leases == {client.mac: client.ip for client in clients},
                  "{}: leases of {} changed to {}".format(what, env.vlan, leases))
    for client in clients:
        expect_ack(env, client.renew(client.ip), client.ip, "{}: RENEW on {}".format(what, env.vlan))
    _assert_port_vlan_served(env, ptfadapter)


def test_dhcp_server_match_and_port_mode_coexist(duthost, ptfadapter, two_vlans, ignore_expected_errors,  # noqa: F811
                                                 relay_agent):
    """M01: a MATCH VLAN and a PORT VLAN are served together, and MATCH changes do not affect the PORT VLAN."""
    env_a, env_b = two_vlans
    cfg_a, cfg_b = baseline_config(env_a), _port_config(env_b)
    apply_match_configs(duthost, [cfg_a, cfg_b])

    clients_a = [DhcpClient(env_a, ptfadapter, env_a.p1, VENDOR_A), DhcpClient(env_a, ptfadapter, env_a.p1, VENDOR_B),
                 DhcpClient(env_a, ptfadapter, env_a.p1), DhcpClient(env_a, ptfadapter, env_a.p2)]
    for client, expected in zip(clients_a, [env_a.ip(21), env_a.ip(22), env_a.ip_range(100, 104), env_a.ip(30)]):
        client.dora(expected)
        verify_client_lease(duthost, env_a, client, client.ip)
    clients_b = [DhcpClient(env_b, ptfadapter, env_b.p1, VENDOR_A), DhcpClient(env_b, ptfadapter, env_b.p2)]
    for client, expected in zip(clients_b, [env_b.ip_range(100, 104), env_b.ip_range(110, 114)]):
        client.dora(expected)
        verify_client_lease(duthost, env_b, client, client.ip)
    pools_b = get_kea_pools(duthost, env_b)
    pytest_assert(set(pools_b) == cfg_b.expected_pools(), "Pools of {} are {}".format(env_b.vlan, pools_b))
    pids = get_dhcp_server_pids(duthost)

    # A runtime binding change on the MATCH VLAN.
    run_cli(duthost, "config dhcp_server ipv4 binding update {} any_on_p2 {}".format(env_a.vlan, env_a.ip(31)))
    wait_for_kea_pools(duthost, env_a, cfg_a.expected_pools() - {(env_a.ip(30), env_a.ip(30))} |
                       {(env_a.ip(31), env_a.ip(31))})
    DhcpClient(env_a, ptfadapter, env_a.p2).expect_offer(env_a.ip(31))
    _assert_port_vlan_unaffected(duthost, env_b, ptfadapter, pools_b, clients_b, "After MATCH binding update")

    # Invalid MATCH configuration written directly to Config DB keeps the last-known-good Kea config.
    error = "overlap with equal specificity"
    ignore_expected_errors(KEA_GENERATION_ERROR, ".*{}.*".format(error))
    binding_key = "DHCP_SERVER_IPV4_BINDING|{}|invalid_binding".format(env_a.vlan)
    kea_hash = get_kea_config_hash(duthost)
    marker = add_syslog_marker(duthost)
    hset_config_db(duthost, binding_key, {"matches@": "vendor_a", "ips@": env_a.ip(70)})
    try:
        wait_for_syslog(duthost, marker, error)
        pytest_assert(get_kea_config_hash(duthost) == kea_hash, "Running Kea configuration changed")
        _assert_port_vlan_unaffected(duthost, env_b, ptfadapter, pools_b, clients_b, "With invalid MATCH config")
        expect_ack(env_a, clients_a[0].renew(clients_a[0].ip), env_a.ip(21), "RENEW on {}".format(env_a.vlan))
    finally:
        del_config_db(duthost, binding_key)
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")


def test_dhcp_server_match_shared_conditions(duthost, ptfadapter, two_vlans, relay_agent):
    """M02: one option60 match condition is used by bindings on two MATCH VLANs."""
    cfgs = []
    for env in two_vlans:
        cfg = MatchConfig(env)
        cfg.add_match("vendor_a", "option60", VENDOR_A)
        cfg.add_binding("vendor_a_only", ["vendor_a"], ips=[env.ip(40)])
        cfgs.append(cfg)
    apply_match_configs(duthost, cfgs)
    for env in two_vlans:
        for port in (env.p1, env.p2):
            DhcpClient(env, ptfadapter, port).expect_no_offer()
        client = DhcpClient(env, ptfadapter, env.p2, VENDOR_A)
        client.dora(env.ip(40))
        verify_client_lease(duthost, env, client, client.ip)
