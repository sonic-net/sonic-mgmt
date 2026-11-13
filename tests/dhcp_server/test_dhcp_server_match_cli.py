"""MATCH mode CLI and GCU tests (V01-V06 of the IPv4 match condition test plan).

Detailed argument validation is covered by the CLI unit tests; these tests verify the
most important behaviour on a DUT: show output, rejection without partial writes,
GCU YANG rejection and configuration order independence.
"""
import json
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401
from dhcp_server_match_common import match_env, match_config_snapshot, match_test_isolation, \
    ignore_expected_errors  # noqa: F401
from dhcp_server_match_common import VENDOR_A, VENDOR_B, MatchConfig, DhcpClient, baseline_config, \
    run_cli, run_cli_expect_failure, show_table, get_dhcp_server_config_db, get_kea_config_hash, \
    get_kea_match_state, wait_for_kea_pools,     wait_for_state_db_lease, hset_config_db
from dhcp_server_test_common import DHCP_SERVER_CONFIG_TOOL_CLI, DHCP_SERVER_CONFIG_TOOL_GCU

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('mx'),
]

RELAY_AGENTS = pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
NUMERIC_MATCH_VALUE = "0123"
OFF_SUBNET_IP = "10.240.0.10"
SECOND_PREFIX_INTERFACE = "10.231.0.1/24"
SECOND_PREFIX_IP = "10.231.0.10"
# GCU validates the target configuration with sonic_yang, which logs the rejection as an error.
GCU_YANG_ERROR = r".*ERR sonic_yang: Data Loading Failed.*"


@pytest.fixture(scope="module", autouse=True)
def match_module_setup(match_config_snapshot):  # noqa: F811
    yield


@pytest.fixture(autouse=True)
def match_test_setup(match_test_isolation):  # noqa: F811
    yield


def _cells(value):
    return value.split("\n") if value else []


def _snapshot(duthost):
    return get_dhcp_server_config_db(duthost), get_kea_config_hash(duthost)


def _assert_unchanged(duthost, before, what):
    config, kea_hash = _snapshot(duthost)
    pytest_assert(config == before[0], "{}: Config DB changed:\nbefore {}\nafter {}".format(what, before[0], config))
    pytest_assert(kea_hash == before[1], "{}: Kea running configuration changed".format(what))


def _apply_patch(duthost, patch):
    """Apply a GCU patch and return the command result without asserting success."""
    tmpfile = duthost.shell("mktemp")["stdout"]
    try:
        duthost.copy(content=json.dumps(patch, indent=4), dest=tmpfile)
        return duthost.shell("config apply-patch {}".format(tmpfile), module_ignore_errors=True)
    finally:
        duthost.file(path=tmpfile, state="absent")


@RELAY_AGENTS
def test_dhcp_server_match_show(duthost, ptfadapter, match_env, enable_sonic_dhcpv4_relay_agent,  # noqa: F811
                                relay_agent):
    """V01: show match, binding, info and lease reflect the configuration and learned ports."""
    env = match_env
    cfg = baseline_config(env)
    cfg.add_match("numeric", "option60", NUMERIC_MATCH_VALUE)
    cfg.apply(duthost)

    rows = show_table(duthost, "show dhcp_server ipv4 match")
    pytest_assert(rows and set(rows[0]) == {"Match", "Type", "Value"}, "Unexpected match columns: {}".format(rows))
    got = {row["Match"]: (row["Type"], row["Value"]) for row in rows}
    expected = {name: (match["type"], repr(match["value"])) for name, match in cfg.matches.items()}
    pytest_assert(got == expected, "show match: expected {}, got {}".format(expected, got))
    rows = show_table(duthost, "show dhcp_server ipv4 match numeric")
    pytest_assert([(r["Match"], r["Value"]) for r in rows] == [("numeric", repr(NUMERIC_MATCH_VALUE))],
                  "show match numeric: {}".format(rows))
    pytest_assert(show_table(duthost, "show dhcp_server ipv4 match nonexistent") == [],
                  "show match of an unknown name is not empty")

    for cmd in ("show dhcp_server ipv4 binding", "show dhcp_server ipv4 binding {}".format(env.vlan)):
        rows = show_table(duthost, cmd)
        pytest_assert(rows and list(rows[0]) == ["Interface", "Binding", "Matches", "IPs", "Ranges"],
                      "{}: unexpected columns {}".format(cmd, rows))
        got = {row["Binding"]: (row["Interface"], _cells(row["Matches"]), _cells(row["IPs"]), _cells(row["Ranges"]))
               for row in rows}
        expected = {name: (env.vlan, sorted(binding["matches"]), binding.get("ips", []), binding.get("ranges", []))
                    for name, binding in cfg.bindings.items()}
        pytest_assert(got == expected, "{}: expected {}, got {}".format(cmd, expected, got))
    pytest_assert(show_table(duthost, "show dhcp_server ipv4 binding Vlan4093") == [],
                  "show binding of another VLAN is not empty")

    rows = show_table(duthost, "show dhcp_server ipv4 info {}".format(env.vlan))
    pytest_assert(len(rows) == 1 and rows[0]["Mode"] == "MATCH", "show info: {}".format(rows))

    clients = [(DhcpClient(env, ptfadapter, env.p1, VENDOR_A), env.ip(21)),
               (DhcpClient(env, ptfadapter, env.p2), env.ip(30))]
    for client, ip in clients:
        client.dora(ip)
        wait_for_state_db_lease(duthost, env.vlan, client.mac)
    rows = {row["MAC Address"]: row for row in show_table(duthost, "show dhcp_server ipv4 lease {}".format(env.vlan))}
    for client, ip in clients:
        row = rows.get(client.mac)
        pytest_assert(row is not None, "show lease has no row for {}: {}".format(client.mac, rows))
        pytest_assert(row["Interface"] == "{}|{}".format(env.vlan, client.port.name) and row["IP"] == ip,
                      "show lease row for {} is {}, expected {}|{} and {}".format(
                          client.mac, row, env.vlan, client.port.name, ip))


def test_dhcp_server_match_cli_rejection(duthost, match_env):  # noqa: F811
    """V02-V04: invalid commands fail with an actionable error and change neither Config DB nor Kea."""
    env = match_env
    cfg = baseline_config(env)
    px = env.px or env.non_member
    cfg.add_match("port_px", "circuit_id", px.alias)
    cfg.add_range("partial_range", env.ip(102), env.ip(106))
    cfg.apply(duthost)
    vlan = env.vlan
    base = "config dhcp_server ipv4 binding add {} x".format(vlan)
    cases = [
        ("config dhcp_server ipv4 match add m1 --type circuit_id --value NoSuchAlias99",
         "Circuit ID alias NoSuchAlias99 does not exist"),
        ("config dhcp_server ipv4 match add m1 --type mac --value x",
         "Only match types circuit_id, option60 are supported"),
        ("{} --match port_px {}".format(base, env.ip(70)),
         "Circuit ID alias {} is not a member of vlan {}".format(px.alias, vlan)),
        ("{} --match port_p1,port_p2 {}".format(base, env.ip(70)),
         "Binding x cannot reference multiple matches of type circuit_id"),
        ("{} --match vendor_a,vendor_b {}".format(base, env.ip(70)),
         "Binding x cannot reference multiple matches of type option60"),
        ("{} --match vendor_a {}".format(base, env.ip(70)),
         "Bindings any_on_p1 and x overlap with equal specificity on {}".format(vlan)),
        ("{} --match port_p2,vendor_a --range partial_range".format(base),
         "Bindings any_on_p1 and x have partially overlapping pools on {}".format(vlan)),
        ("{} --match port_p2,vendor_a {}".format(base, OFF_SUBNET_IP),
         "IP {} is not in any subnet of vlan {}".format(OFF_SUBNET_IP, vlan)),
        ("{} --match port_p2,vendor_a 300.1.1.1".format(base), "Illegal IP address 300.1.1.1"),
        ("{} --match port_p2,vendor_a --range any_p1_range {}".format(base, env.ip(70)),
         "Exactly one of IP list or range list must be provided"),
        ("config dhcp_server ipv4 binding add {} a_on_p1 --match port_p1,vendor_a {}".format(vlan, env.ip(21)),
         "Binding a_on_p1 already exists on {}".format(vlan)),
        ("config dhcp_server ipv4 match del vendor_a", "Match vendor_a is referenced in"),
        ("config dhcp_server ipv4 match update vendor_b --type circuit_id --value {}".format(env.p2.alias),
         "Binding b_on_p1 cannot reference multiple matches of type circuit_id"),
        ("config dhcp_server ipv4 match update port_p1 --value {}".format(px.alias),
         "Circuit ID alias {} is not a member of vlan {}".format(px.alias, vlan)),
        ("config dhcp_server ipv4 range update any_p1_range 10.240.0.1 10.240.0.5",
         "Range any_p1_range is not in any subnet of vlan {}".format(vlan)),
        ("config dhcp_server ipv4 range del any_p1_range", "Range any_p1_range is referenced in"),
        ("config dhcp_server ipv4 del {}".format(vlan),
         "Dhcp interface {} has match bindings and cannot be deleted".format(vlan)),
    ]
    before = _snapshot(duthost)
    errors = []
    for cmd, expected_error in cases:
        try:
            run_cli_expect_failure(duthost, cmd, expected_error)
        except AssertionError as error:
            errors.append(str(error))
    _assert_unchanged(duthost, before, "CLI rejections")
    pytest_assert(not errors, "Rejection checks failed:\n" + "\n".join(errors))

    # Guarded deletion is bypassed only with --force; the binding then loses its pool.
    run_cli(duthost, "config dhcp_server ipv4 range del any_p1_range --force")
    del cfg.ranges["any_p1_range"]
    del cfg.bindings["any_on_p1"]
    wait_for_kea_pools(duthost, env, cfg.expected_pools())


def test_dhcp_server_match_multi_prefix_rejection(duthost, match_env):  # noqa: F811
    """V03: a binding pool in a second prefix of a MATCH VLAN is rejected; PORT mode is not."""
    env = match_env
    cfg = baseline_config(env)
    cfg.apply(duthost)
    run_cli(duthost, "config interface ip add {} {}".format(env.vlan, SECOND_PREFIX_INTERFACE))
    try:
        before = _snapshot(duthost)
        run_cli_expect_failure(
            duthost, "config dhcp_server ipv4 binding add {} x --match port_p2,vendor_a {}".format(
                env.vlan, SECOND_PREFIX_IP),
            "DHCP pools on {} cannot span multiple IPv4 prefixes".format(env.vlan))
        _assert_unchanged(duthost, before, "Multi-prefix binding")
    finally:
        duthost.shell("config interface ip remove {} {}".format(env.vlan, SECOND_PREFIX_INTERFACE),
                      module_ignore_errors=True)


def test_dhcp_server_match_rules_not_applied_to_port_mode(duthost, match_env):  # noqa: F811
    """V03: MATCH pool overlap rules do not reject PORT mode bindings."""
    env = match_env
    cfg = MatchConfig(env, mode="PORT", state="disabled")
    cfg.add_range("r_a", env.ip(100), env.ip(104))
    cfg.add_range("r_b", env.ip(102), env.ip(106))
    cfg.add_port_binding(env.p1.name, ["r_a"])
    cfg.add_port_binding(env.p2.name, ["r_b"])
    cfg.apply(duthost, wait=False)
    ports = get_dhcp_server_config_db(duthost).get("DHCP_SERVER_IPV4_PORT", {})
    for port, ranges in cfg.port_bindings.items():
        key = "{}|{}".format(env.vlan, port)
        pytest_assert(ports.get(key, {}).get("ranges") == ranges,
                      "PORT binding {} was not written: {}".format(key, ports))


def test_dhcp_server_match_mode_switch_rejection(duthost, match_env):  # noqa: F811
    """V04: switching an enabled PORT interface to MATCH is rejected while its bindings are invalid."""
    env = match_env
    cfg = MatchConfig(env, mode="PORT")
    cfg.add_range("r_port", env.ip(60))
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_match("vendor_b", "option60", VENDOR_B)
    cfg.add_port_binding(env.p1.name, ["r_port"])
    cfg.apply(duthost)
    # PORT mode ignores bindings, so write two equal-specificity bindings directly.
    hset_config_db(duthost, "DHCP_SERVER_IPV4_BINDING|{}|first".format(env.vlan),
                   {"matches@": "vendor_a", "ips@": env.ip(70)})
    hset_config_db(duthost, "DHCP_SERVER_IPV4_BINDING|{}|second".format(env.vlan),
                   {"matches@": "vendor_a", "ips@": env.ip(71)})
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    before = _snapshot(duthost)
    run_cli_expect_failure(duthost, "config dhcp_server ipv4 update {} --mode MATCH".format(env.vlan),
                           "Bindings first and second overlap with equal specificity on {}".format(env.vlan))
    _assert_unchanged(duthost, before, "Mode switch to MATCH")


@pytest.mark.parametrize("invalid_patch", ["both_pool_forms", "missing_match", "nonexistent_port"])
def test_dhcp_server_match_gcu_rejection(duthost, match_env, invalid_patch, ignore_expected_errors):  # noqa: F811
    """V05: GCU rejects YANG-invalid MATCH configuration and leaves the configuration unchanged."""
    env = match_env
    ignore_expected_errors(GCU_YANG_ERROR)
    cfg = baseline_config(env)
    cfg.apply(duthost)
    if invalid_patch == "both_pool_forms":
        path = "/DHCP_SERVER_IPV4_BINDING/{}|x".format(env.vlan)
        value = {"matches": ["port_p2", "vendor_a"], "ips": [env.ip(70)], "ranges": ["any_p1_range"]}
    elif invalid_patch == "missing_match":
        path = "/DHCP_SERVER_IPV4_BINDING/{}|x".format(env.vlan)
        value = {"matches": ["port_p2", "no_such_match"], "ips": [env.ip(70)]}
    else:
        path = "/DHCP_SERVER_IPV4_MATCH/port_bad"
        value = {"type": "circuit_id", "value": "NoSuchAlias99"}
    before = _snapshot(duthost)
    result = _apply_patch(duthost, [{"op": "add", "path": path, "value": value}])
    pytest_assert(result["rc"] != 0 and "Patch applied successfully" not in result["stdout"],
                  "GCU accepted invalid patch {}: {}".format(invalid_patch, result["stdout"]))
    _assert_unchanged(duthost, before, "GCU {}".format(invalid_patch))


@RELAY_AGENTS
def test_dhcp_server_match_cli_order_independence(duthost, ptfadapter, match_env,  # noqa: F811
                                                  enable_sonic_dhcpv4_relay_agent, relay_agent):  # noqa: F811
    """V06: CLI in forward order and GCU in reverse order produce the same Kea configuration and behaviour."""
    env = match_env
    cfg = baseline_config(env)
    states = []
    for config_tool, reverse in ((DHCP_SERVER_CONFIG_TOOL_CLI, False), (DHCP_SERVER_CONFIG_TOOL_GCU, True)):
        cfg.apply(duthost, config_tool=config_tool, reverse=reverse)
        states.append(get_kea_match_state(duthost))
        DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))
        DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_offer(env.ip(22))
        DhcpClient(env, ptfadapter, env.p1).expect_offer(env.ip_range(100, 104))
        DhcpClient(env, ptfadapter, env.p2, VENDOR_A).expect_offer(env.ip(30))
    pytest_assert(states[0] == states[1], "Kea configuration differs between CLI and GCU:\n{}\n{}".format(*states))
