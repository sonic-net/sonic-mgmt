"""MATCH mode address assignment tests (F01-F14 of the IPv4 match condition test plan)."""
import binascii
import logging

import pytest
import ptf.packet as scapy

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import capture_and_check_packet_on_dut, wait_until
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401
from dhcp_server_test_common import DHCP_SERVER_CONFIG_TOOL_CLI, DHCP_SERVER_CONFIG_TOOL_GCU
from dhcp_server_match_common import match_env, match_config_snapshot, match_test_isolation  # noqa: F401
from dhcp_server_match_common import VENDOR_A, VENDOR_B, MatchConfig, DhcpClient, baseline_config, \
    add_syslog_marker, wait_for_syslog, get_kea_dhcp4_config, get_kea_lease, get_state_db_lease, \
    get_dhcp_server_pids, wait_for_state_db_lease, verify_client_lease, \
    learn_mac_on_port, run_cli, expect_nak, expect_ack, dhcp_option, parse_relay_agent_info, \
    clean_match_server_config

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('mx'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"]),
]

TEST_PORTCHANNEL = "PortChannel0999"


@pytest.fixture(scope="module", autouse=True)
def match_module_setup(match_config_snapshot):  # noqa: F811
    yield


@pytest.fixture(autouse=True)
def match_test_setup(match_test_isolation, enable_sonic_dhcpv4_relay_agent):  # noqa: F811
    yield


def _circuit_id(env, port):
    return "{}:{}".format(env.hostname, port.alias)


def _kea_class_tests(duthost):
    return [client_class.get("test", "") for client_class in get_kea_dhcp4_config(duthost).get("client-classes", [])]


def _validate_relayed_circuit_ids(pkts, expected):
    """Every client in ``expected`` ({mac: circuit_id}) must be relayed with that Circuit ID."""
    seen = {}
    for pkt in pkts:
        if scapy.BOOTP not in pkt or scapy.DHCP not in pkt or pkt[scapy.BOOTP].op != 1:
            continue
        mac = binascii.hexlify(bytes(pkt[scapy.BOOTP].chaddr)[:6]).decode()
        relay_info = dhcp_option(pkt, "relay_agent_information")
        if mac in expected and relay_info is not None:
            seen.setdefault(mac, set()).add(parse_relay_agent_info(relay_info).get(1, b"").decode("utf-8", "replace"))
    for mac, circuit_id in expected.items():
        pytest_assert(seen.get(mac) == {circuit_id}, "Relayed Circuit IDs for {} are {}, expected {}".format(
            mac, seen.get(mac), circuit_id))


def test_match_circuit_id_on_wire(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F01: the relayed Circuit ID is <hostname>:<alias> and is the value tested by the Kea class."""
    env = match_env
    baseline_config(env).apply(duthost)
    clients = [DhcpClient(env, ptfadapter, port) for port in (env.p1, env.p2)]
    expected = {client.mac.replace(":", ""): _circuit_id(env, client.port) for client in clients}
    # The relay forwards to the server container over docker0; the client broadcast is excluded.
    with capture_and_check_packet_on_dut(duthost=duthost, interface="docker0",
                                         pkts_filter="udp dst port 67 and not dst host 255.255.255.255",
                                         pkts_validator=_validate_relayed_circuit_ids,
                                         pkts_validator_args=[expected], wait_time=2):
        for client in clients:
            client.discover()

    class_tests = " ".join(_kea_class_tests(duthost)).lower()
    for client in clients:
        circuit_hex = binascii.hexlify(_circuit_id(env, client.port).encode("utf-8")).decode()
        pytest_assert("relay4[1].hex == 0x{}".format(circuit_hex) in class_tests,
                      "No Kea class tests Circuit ID {} (0x{})".format(_circuit_id(env, client.port), circuit_hex))


def test_match_circuit_id_only_binding(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F02: a port-only binding ignores Option 60 and the client's FDB location."""
    env = match_env
    pool = env.ip_range(40, 44)
    cfg = MatchConfig(env)
    cfg.add_range("p1_range", pool[0], pool[-1])
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_binding("any_on_p1", ["port_p1"], ranges=["p1_range"])
    cfg.apply(duthost)

    for opt60 in (None, VENDOR_A, VENDOR_B, "Unrelated"):
        DhcpClient(env, ptfadapter, env.p1, opt60).expect_offer(pool)
        DhcpClient(env, ptfadapter, env.p2, opt60).expect_no_offer()

    # A MAC learned behind P2 is still classified by its actual ingress port, and vice versa.
    stale_on_p2 = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    learn_mac_on_port(ptfadapter, env.p2, stale_on_p2.mac)
    stale_on_p2.dora(pool)
    verify_client_lease(duthost, env, stale_on_p2, stale_on_p2.ip)
    stale_on_p1 = DhcpClient(env, ptfadapter, env.p2)
    learn_mac_on_port(ptfadapter, env.p1, stale_on_p1.mac)
    stale_on_p1.expect_no_offer()


def test_match_option60_only_binding(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F03: an Option 60 binding serves matching clients on any member and nobody else."""
    env = match_env
    pool = env.ip_range(50, 54)
    cfg = MatchConfig(env)
    cfg.add_range("vendor_range", pool[0], pool[-1])
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_binding("vendor_a_any", ["vendor_a"], ranges=["vendor_range"])
    cfg.apply(duthost)

    on_p1 = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    on_p2 = DhcpClient(env, ptfadapter, env.p2, VENDOR_A)
    on_p1.dora(pool)
    on_p2.dora(pool)
    pytest_assert(on_p1.ip != on_p2.ip, "Both clients were assigned {}".format(on_p1.ip))
    for client in (on_p1, on_p2):
        verify_client_lease(duthost, env, client, client.ip)

    for opt60 in (VENDOR_B, None):
        DhcpClient(env, ptfadapter, env.p1, opt60).expect_no_offer()
    if env.px is not None:
        DhcpClient(env, ptfadapter, env.px, VENDOR_A).expect_no_offer()


def test_match_combined_binding(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F04: a port plus vendor binding requires both conditions."""
    env = match_env
    cfg = MatchConfig(env)
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_binding("a_on_p1", ["port_p1", "vendor_a"], ips=[env.ip(21)])
    cfg.apply(duthost)

    DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))
    DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_no_offer()
    DhcpClient(env, ptfadapter, env.p1).expect_no_offer()
    DhcpClient(env, ptfadapter, env.p2, VENDOR_A).expect_no_offer()


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_CLI, DHCP_SERVER_CONFIG_TOOL_GCU])
@pytest.mark.parametrize("binding_order", ["forward", "reverse"])
def test_match_baseline_specificity(duthost, ptfadapter, match_env, config_tool, binding_order,  # noqa: F811
                                    relay_agent):
    """F05: more-specific bindings win, independent of configuration order and tool."""
    env = match_env
    general = env.ip_range(100, 104)
    baseline_config(env).apply(duthost, config_tool, reverse=(binding_order == "reverse"))

    a_client = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    a_client.dora(env.ip(21))
    verify_client_lease(duthost, env, a_client, a_client.ip)
    DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_offer(env.ip(22))
    DhcpClient(env, ptfadapter, env.p1).expect_offer(general)
    DhcpClient(env, ptfadapter, env.p1, "Unrelated").expect_offer(general)
    for opt60 in (None, VENDOR_A):
        DhcpClient(env, ptfadapter, env.p2, opt60).expect_offer(env.ip(30))
    if len(env.members) >= 3:
        DhcpClient(env, ptfadapter, env.p3, VENDOR_A).expect_no_offer()


def test_match_specific_pool_exhaustion(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F06: an exhausted specific pool does not fall back to the general pool."""
    env = match_env
    baseline_config(env).apply(duthost)

    holder = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    holder.dora(env.ip(21))
    waiting = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    waiting.expect_no_offer()
    holder.release(duthost)
    waiting.dora(env.ip(21))


def test_match_shared_pool_between_vendors(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F07: two vendor bindings with an identical pool share it without duplicate allocation."""
    env = match_env
    pool = env.ip_range(70, 71)
    cfg = MatchConfig(env)
    cfg.add_range("shared_range", pool[0], pool[-1])
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_match("vendor_b", "option60", VENDOR_B)
    cfg.add_binding("vendor_a_shared", ["vendor_a"], ranges=["shared_range"])
    cfg.add_binding("vendor_b_shared", ["vendor_b"], ranges=["shared_range"])
    marker = add_syslog_marker(duthost)
    cfg.apply(duthost)

    lines = wait_for_syslog(duthost, marker, "DHCP MATCH class")
    pytest_assert(any("{}|vendor_a_shared".format(env.vlan) in line and "{}|vendor_b_shared".format(env.vlan) in line
                      for line in lines), "No class maps to both shared bindings: {}".format(lines))

    DhcpClient(env, ptfadapter, env.p1, "Unrelated").expect_no_offer()
    a_client = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    b_client = DhcpClient(env, ptfadapter, env.p2, VENDOR_B)
    a_client.dora(pool)
    b_client.dora(pool)
    pytest_assert(a_client.ip != b_client.ip, "Shared pool allocated {} twice".format(a_client.ip))
    DhcpClient(env, ptfadapter, env.p1, VENDOR_B).expect_no_offer()


def test_match_multiple_ranges(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F08: a binding with several ranges (one single-address) allocates only those addresses."""
    env = match_env
    pool = [env.ip(60), env.ip(61), env.ip(65)]
    cfg = MatchConfig(env)
    cfg.add_range("r1", env.ip(60), env.ip(61))
    cfg.add_range("r2", env.ip(65))
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_binding("multi_range", ["port_p1"], ranges=["r1", "r2"])
    cfg.apply(duthost)

    clients = [DhcpClient(env, ptfadapter, env.p1) for _ in pool]
    for client in clients:
        client.dora(pool)
    pytest_assert(sorted(client.ip for client in clients) == sorted(pool),
                  "Allocated {}, expected {}".format([client.ip for client in clients], pool))
    late = DhcpClient(env, ptfadapter, env.p1)
    late.expect_no_offer()
    single = next(client for client in clients if client.ip == env.ip(65))
    single.release(duthost)
    late.dora(env.ip(65))


def test_match_option60_byte_matching(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F09: Option 60 matching is byte-exact apart from trailing NUL padding."""
    env = match_env
    utf8_vendor = u"Vend\u00f6r-\u03b1"
    cfg = MatchConfig(env)
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_match("vendor_utf8", "option60", utf8_vendor)
    cfg.add_binding("vendor_a_any", ["vendor_a"], ips=[env.ip(21)])
    cfg.add_binding("vendor_utf8_any", ["vendor_utf8"], ips=[env.ip(23)])
    cfg.apply(duthost)

    vendor = VENDOR_A.encode()
    matching = {
        "exact": (vendor, env.ip(21)),
        "trailing NUL": (vendor + b"\x00", env.ip(21)),
        "UTF-8": (utf8_vendor.encode("utf-8"), env.ip(23)),
    }
    not_matching = {
        "lower case": vendor.lower(),
        "upper case": vendor.upper(),
        "prefix": vendor[:-1],
        "longer value": vendor + b"B",
        "leading byte": b"x" + vendor,
        "leading space": b" " + vendor,
        "trailing space": vendor + b" ",
        "leading NUL": b"\x00" + vendor,
        "Latin-1 encoding": utf8_vendor.encode("latin-1", "replace"),
    }
    for label, (value, expected) in matching.items():
        logger.info("Option 60 variant '%s' must match", label)
        DhcpClient(env, ptfadapter, env.p1, value).expect_offer(expected)
    for label, value in not_matching.items():
        logger.info("Option 60 variant '%s' must not match", label)
        DhcpClient(env, ptfadapter, env.p1, value).expect_no_offer()


def test_match_option60_change_between_messages(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F10: every packet is classified independently, including REQUEST, RENEW and INIT-REBOOT."""
    env = match_env
    baseline_config(env).apply(duthost)
    client = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    ip = client.dora(env.ip(21))

    expect_nak(client.request(ip, opt60=VENDOR_B), "SELECTING REQUEST with VendorB")
    expect_nak(client.request(ip, opt60=None), "SELECTING REQUEST without Option 60")
    expect_nak(client.renew(ip, opt60=VENDOR_B), "RENEW with VendorB")
    expect_nak(client.renew(ip, opt60=None), "RENEW without Option 60")
    expect_nak(client.init_reboot(ip, opt60=VENDOR_B), "INIT-REBOOT with VendorB")
    expect_nak(client.init_reboot(ip, opt60=None), "INIT-REBOOT without Option 60")
    expect_ack(env, client.renew(ip), ip, "RENEW with VendorA")
    expect_ack(env, client.init_reboot(ip), ip, "INIT-REBOOT with VendorA")

    # When the specific and general bindings share one pool the address stays reachable without Option 60.
    pool = env.ip_range(21, 22)
    shared = MatchConfig(env)
    shared.add_range("shared_range", pool[0], pool[-1])
    shared.add_match("port_p1", "circuit_id", env.p1.alias)
    shared.add_match("vendor_a", "option60", VENDOR_A)
    shared.add_binding("a_on_p1", ["port_p1", "vendor_a"], ranges=["shared_range"])
    shared.add_binding("any_on_p1", ["port_p1"], ranges=["shared_range"])
    shared.apply(duthost)
    client = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    ip = client.dora(pool)
    expect_ack(env, client.request(ip, opt60=None), ip, "SELECTING REQUEST without Option 60 on shared pool")
    expect_ack(env, client.renew(ip, opt60=None), ip, "RENEW without Option 60 on shared pool")


def test_match_renew_and_release(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F11: RENEW extends the lease of the same address and RELEASE removes it."""
    env = match_env
    baseline_config(env).apply(duthost)
    client = DhcpClient(env, ptfadapter, env.p1, VENDOR_B)
    ip = client.dora(env.ip(22))
    first_state = verify_client_lease(duthost, env, client, ip)
    first_cltt = get_kea_lease(duthost, ip)["cltt"]

    def _renewed():
        expect_ack(env, client.renew(ip), ip, "RENEW")
        return get_kea_lease(duthost, ip)["cltt"] > first_cltt

    pytest_assert(wait_until(20, 2, 1, _renewed), "Kea lease expiry did not advance after RENEW")
    pytest_assert(wait_until(20, 1, 0, lambda: int(get_state_db_lease(duthost, env.vlan, client.mac).get(
        "lease_end", 0)) > int(first_state["lease_end"])), "State DB lease_end did not advance after RENEW")
    pytest_assert(get_state_db_lease(duthost, env.vlan, client.mac)["ip"] == ip, "Renewal changed the address")

    client.release(duthost)
    wait_for_state_db_lease(duthost, env.vlan, client.mac, present=False)


def test_match_client_mac_move(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F12: allocation follows the current ingress port after MACs move or swap."""
    env = match_env
    p1_pool = env.ip_range(100, 104)
    p2_pool = env.ip_range(30, 34)
    cfg = MatchConfig(env)
    cfg.add_range("p1_range", p1_pool[0], p1_pool[-1])
    cfg.add_range("p2_range", p2_pool[0], p2_pool[-1])
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_match("port_p2", "circuit_id", env.p2.alias)
    cfg.add_binding("any_on_p1", ["port_p1"], ranges=["p1_range"])
    cfg.add_binding("any_on_p2", ["port_p2"], ranges=["p2_range"])
    cfg.apply(duthost)

    first = DhcpClient(env, ptfadapter, env.p1)
    second = DhcpClient(env, ptfadapter, env.p2)
    first.dora(p1_pool)
    second.dora(p2_pool)

    first.port, second.port = env.p2, env.p1
    first.dora(p2_pool)
    second.dora(p1_pool)
    for client in (first, second):
        verify_client_lease(duthost, env, client, client.ip)


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_CLI, DHCP_SERVER_CONFIG_TOOL_GCU])
def test_match_customized_options(duthost, ptfadapter, match_env, config_tool, relay_agent):  # noqa: F811
    """F13: customized options bound to a MATCH interface are sent in OFFER and ACK."""
    env = match_env
    option_value = "match_mode_option"
    cfg = baseline_config(env)
    cfg.add_option("match_option", 147, "string", option_value)
    cfg.apply(duthost, config_tool)

    client = DhcpClient(env, ptfadapter, env.p1, VENDOR_A)
    client.dora(env.ip(21), options={"147": option_value.encode()})


def _wait_portchannel_up(duthost, name):
    def _up():
        output = duthost.shell("show interfaces portchannel", module_ignore_errors=True)["stdout"]
        return any(name in line and "(Up)" in line and "(S)" in line for line in output.splitlines())
    pytest_assert(wait_until(90, 3, 0, _up), "{} did not come up".format(name))


def test_match_portchannel_circuit_id(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """F14: a PortChannel created after daemon start is matched by its name without restarting dhcpservd."""
    # dhcp4relay maps the ingress physical port to a VLAN through VLAN_MEMBER only and never reads
    # PORTCHANNEL_MEMBER, so it drops untagged DHCP from LAG members ("Invalid input interface").
    if relay_agent == "sonic-relay-agent":
        pytest.skip("sonic-relay-agent does not relay DHCP received on PortChannel members")
    env = match_env
    member = env.p3
    vlan_member_key = "VLAN_MEMBER|{}|{}".format(env.vlan, member.name)
    tagging = duthost.shell("sonic-db-cli CONFIG_DB HGET '{}' tagging_mode".format(vlan_member_key))["stdout"]
    pytest_require(tagging == "untagged", "{} is not an untagged member of {}".format(member.name, env.vlan))
    acl_ports = {}
    for key in duthost.shell("sonic-db-cli CONFIG_DB KEYS 'ACL_TABLE|*'")["stdout_lines"]:
        ports = duthost.shell("sonic-db-cli CONFIG_DB HGET '{}' 'ports@'".format(key))["stdout"]
        if member.name in ports.split(","):
            acl_ports[key] = ports

    baseline_config(env).apply(duthost)
    pids = get_dhcp_server_pids(duthost)
    try:
        for key, ports in acl_ports.items():
            remaining = ",".join(port for port in ports.split(",") if port != member.name)
            duthost.shell("sonic-db-cli CONFIG_DB HSET '{}' 'ports@' '{}'".format(key, remaining))
        run_cli(duthost, "config vlan member del {} {}".format(env.vlan_id, member.name))
        run_cli(duthost, "config portchannel add {} --fallback true".format(TEST_PORTCHANNEL))
        run_cli(duthost, "config portchannel member add {} {}".format(TEST_PORTCHANNEL, member.name))
        run_cli(duthost, "config vlan member add -u {} {}".format(env.vlan_id, TEST_PORTCHANNEL))
        _wait_portchannel_up(duthost, TEST_PORTCHANNEL)

        cfg = baseline_config(env)
        cfg.add_match("port_lag", "circuit_id", TEST_PORTCHANNEL)
        cfg.add_binding("any_on_lag", ["port_lag"], ips=[env.ip(40)])
        cfg.apply(duthost)
        client = DhcpClient(env, ptfadapter, member._replace(alias=TEST_PORTCHANNEL))
        client.dora(env.ip(40))
        verify_client_lease(duthost, env, client, client.ip)
        DhcpClient(env, ptfadapter, env.p1, VENDOR_A).expect_offer(env.ip(21))
        pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")
    finally:
        clean_match_server_config(duthost)
        duthost.shell("config vlan member del {} {}".format(env.vlan_id, TEST_PORTCHANNEL), module_ignore_errors=True)
        duthost.shell("config portchannel member del {} {}".format(TEST_PORTCHANNEL, member.name),
                      module_ignore_errors=True)
        duthost.shell("config portchannel del {}".format(TEST_PORTCHANNEL), module_ignore_errors=True)
        duthost.shell("config vlan member add -u {} {}".format(env.vlan_id, member.name), module_ignore_errors=True)
        for key, ports in acl_ports.items():
            duthost.shell("sonic-db-cli CONFIG_DB HSET '{}' 'ports@' '{}'".format(key, ports))
    pytest_assert(duthost.shell("sonic-db-cli CONFIG_DB EXISTS '{}'".format(vlan_member_key))["stdout"] == "1",
                  "{} was not restored to {}".format(member.name, env.vlan))
