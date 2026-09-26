"""
Test routed-port to VLAN/SVI transition and MAC learning behavior for ARP, IP2ME, and NDP traffic.
"""
import ipaddress
import logging
from types import SimpleNamespace

import pytest

import ptf.testutils as testutils
from scapy.all import (
    Ether,
    IPv6,
    ICMPv6ND_NS,
    ICMPv6NDOptSrcLLAddr,
    in6_getnsma,
    in6_getnsmac,
    inet_pton,
    inet_ntop,
    socket,
)

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.vlan_hardening import ignore_expected_loganalyzer_exceptions  # noqa: F401
from tests.common.helpers.vlan_hardening import (
    get_bridge_port_admin_state,
    get_config_facts,
    get_portchannel_for_port,
    get_routed_ip_prefixes,
    mac_learned_on_port,
    pick_free_vlan_id,
    port_sort_key,
    ptf_indices_for_ports,
    wait_for_ports_up,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Candidate VLAN ID range; each ID is verified unused before use.
TEST_VLAN_ID_RANGE = range(951, 999)

SVI_IPV4 = "192.168.201.1"
SVI_IPV4_PREFIXLEN = 24
PEER_IPV4 = "192.168.201.50"

SVI_IPV6 = "2001:db8:201::1"
SVI_IPV6_PREFIXLEN = 64
PEER_IPV6 = "2001:db8:201::50"

FDB_WAIT_TIMEOUT = 15
FDB_WAIT_INTERVAL = 2


def _get_mac_str(ptfadapter, ptf_idx):
    # Return the PTF port MAC as a normalized colon-separated string.
    mac = ptfadapter.dataplane.get_mac(0, ptf_idx)
    if isinstance(mac, bytes):
        mac = mac.decode()
    return mac


def _generate_link_local_addr(mac):
    # Derive an IPv6 link-local address from a MAC using modified EUI-64.
    parts = mac.split(":")
    pytest_assert(len(parts) == 6, "Unexpected MAC format (expected 6 colon-separated octets): {}".format(mac))
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6_parts = []
    for i in range(0, len(parts), 2):
        ipv6_parts.append("".join(parts[i:i + 2]))
    return "fe80::{}".format(":".join(ipv6_parts))


def _confirm_mac_never_learned(duthost, asic, port, mac, vlan_id, timeout, interval):
    # Return True only if `mac` never becomes learned on `port`/`vlan_id` within timeout seconds.
    # wait_until returns True as soon as the predicate (mac_learned_on_port) is satisfied, so
    # inverting it gives "never learned" -- consistent with every other wait in this file instead
    # of a bespoke sleep loop.
    return not wait_until(timeout, interval, 0, mac_learned_on_port, duthost, asic, port, mac, vlan_id)


def _ndp_entry_exists(duthost, ip_addr, mac):
    # Return whether `show ndp` maps `ip_addr` to `mac`, normalizing IPv6 text form.
    mac_upper = mac.upper()
    target_addr = ipaddress.IPv6Address(ip_addr)
    res = duthost.command('show ndp')
    for line in res['stdout_lines']:
        items = line.split()
        if len(items) != 5 or ':' not in items[0]:
            continue
        addr, neighbor_mac = items[0], items[1]
        try:
            parsed_addr = ipaddress.IPv6Address(addr)
        except ValueError:
            continue
        if parsed_addr == target_addr and neighbor_mac.upper() == mac_upper:
            return True
    return False


def _pick_test_ports(topo_type, config_facts, mg_facts, asic, duthost, tbinfo, enum_frontend_asic_index, ptfhost):
    # Pick a transitioning test port and peer port, restricted to PTF-wired candidates.
    if topo_type == 't0':
        vlan_members = config_facts.get('VLAN_MEMBER', {})
        candidate_ports = [
            port
            for members in vlan_members.values()
            for port, member_info in members.items()
            if member_info.get('tagging_mode') == 'untagged'
        ]
    else:
        external_ports = [p for p in mg_facts['minigraph_ports'].keys() if 'BP' not in p]
        ports = sorted(external_ports, key=port_sort_key)
        intf_status = asic.show_interface(command='status')['ansible_facts']['int_status']
        interface_table = config_facts.get('INTERFACE', {})
        admin_up_ports = [p for p in ports if intf_status.get(p, {}).get('admin_state') == 'up']

        def _is_free(port):
            is_routed = any('/' in key for key in interface_table.get(port, {}))
            return not is_routed and get_portchannel_for_port(mg_facts, port) is None

        free_ports = [p for p in admin_up_ports if _is_free(p)]
        disruptive_ports = [p for p in admin_up_ports if p not in free_ports]
        # Prefer ports that are neither routed nor a PortChannel member, so this test doesn't
        # unnecessarily bounce a live BGP/PortChannel port when an unused link is available.
        candidate_ports = free_ports + disruptive_ports

    ptf_indices = ptf_indices_for_ports(duthost, ptfhost, tbinfo, enum_frontend_asic_index, candidate_ports)
    wired_candidates = [p for p in candidate_ports if p in ptf_indices]
    pytest_require(
        len(wired_candidates) >= 2,
        "Need at least 2 PTF-wired {} ports on the DUT for this test, found {} candidate(s), "
        "{} with PTF wiring".format(
            "untagged VLAN member" if topo_type == 't0' else "admin-up external",
            len(candidate_ports), len(wired_candidates)))
    return wired_candidates[0], wired_candidates[1]


def _transition_port_to_l2(duthost, asic, config_facts, port, removed):
    # Remove routed, VLAN, or PortChannel config from `port`, recording each change in `removed` as it happens.
    interface_table = config_facts.get('INTERFACE', {})
    ip_prefixes = get_routed_ip_prefixes(interface_table, port)
    if ip_prefixes:
        for prefix in ip_prefixes:
            logger.info("%s has a routed IP %s; removing it before the L2 transition", port, prefix)
            duthost.shell("config interface ip remove {} {}".format(port, prefix))
            removed['ip_addrs'].append(prefix)
    else:
        logger.info(
            "%s has no routed IP configured in CONFIG_DB INTERFACE (likely already a VLAN member "
            "or a PortChannel member, handled below) -- no routed-config removal needed", port)

    vlan_members = config_facts.get('VLAN_MEMBER', {})
    for vlan_name, members in vlan_members.items():
        if port in members:
            vlan_id = vlan_name.replace('Vlan', '')
            logger.info(
                "%s is currently an untagged member of %s; removing that membership so it can "
                "join the new test VLAN", port, vlan_name)
            duthost.shell("config vlan member del {} {}".format(vlan_id, port))
            removed['vlan_membership'] = vlan_id
            break

    # Live CONFIG_DB, not mg_facts: mg_facts is a static minigraph snapshot, so if borrow_port
    # already pulled this port out of a PortChannel (Tier 2/3 in _borrow_port_generic) before this
    # runs, mg_facts would still show it as a member -- triggering a redundant
    # config_portchannel_member del that fails silently but adds confusing orchagent noise.
    live_pc_members = config_facts.get('PORTCHANNEL_MEMBER', {})
    po_name = next((pc for pc, members in live_pc_members.items() if port in members), None)
    if po_name is not None:
        logger.info(
            "%s is currently a member of PortChannel %s; removing it from the PortChannel and "
            "bringing it up standalone so it can join the new test VLAN", port, po_name)
        asic.config_portchannel_member(po_name, port, "del")
        asic.startup_interface(port)
        removed['portchannel'] = po_name

    return removed


def _restore_port_from_l2(duthost, asic, port, removed):
    if removed['vlan_membership'] is not None:
        duthost.shell("config vlan member add {} {} --untagged".format(removed['vlan_membership'], port),
                      module_ignore_errors=True)
    for prefix in removed['ip_addrs']:
        duthost.shell("config interface ip add {} {}".format(port, prefix), module_ignore_errors=True)
    if removed.get('portchannel') is not None:
        try:
            asic.config_portchannel_member(removed['portchannel'], port, "add")
        except Exception as exc:
            logger.warning(
                "Failed to re-add %s to PortChannel %s during teardown: %s", port, removed['portchannel'], exc)


@pytest.fixture
def configure_test_vlan(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index, ptfhost, ptfadapter):
    # Create a test VLAN with two untagged ports and a dual-stack SVI, restoring state afterward.
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = get_config_facts(duthost)
    asic = duthost.asic_instance(enum_frontend_asic_index)

    topo_type = tbinfo['topo']['type']
    # Only used on non-T0 topologies, which lack default VLAN_MEMBER port candidates.
    mg_facts = asic.get_extended_minigraph_facts(tbinfo) if topo_type != 't0' else None

    vlan_id = pick_free_vlan_id(config_facts, TEST_VLAN_ID_RANGE)
    tgen1_port, peer_port = _pick_test_ports(
        topo_type, config_facts, mg_facts, asic, duthost, tbinfo, enum_frontend_asic_index, ptfhost)

    # Cover both transitions in one try/finally so any partial setup is still restored.
    removed_tgen1 = {'ip_addrs': [], 'vlan_membership': None, 'portchannel': None}
    removed_peer = {'ip_addrs': [], 'vlan_membership': None, 'portchannel': None}
    svi_created = False
    try:
        _transition_port_to_l2(duthost, asic, config_facts, tgen1_port, removed_tgen1)
        _transition_port_to_l2(duthost, asic, config_facts, peer_port, removed_peer)

        if removed_tgen1.get('portchannel') or removed_peer.get('portchannel'):
            # Let a port removed from a PortChannel settle before using it for VLAN traffic.
            wait_for_ports_up(duthost, [tgen1_port, peer_port])

        duthost.shell("config vlan add {}".format(vlan_id))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, tgen1_port))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, peer_port))

        # Wait for ASIC_DB BRIDGE_PORT objects before traffic; STATE_DB tagging_mode alone is
        # insufficient for FDB learning.
        pytest_assert(
            wait_until(30, 2, 0, lambda: (
                get_bridge_port_admin_state(duthost, asic, tgen1_port) is True and
                get_bridge_port_admin_state(duthost, asic, peer_port) is True)),
            "ASIC_DB BRIDGE_PORT admin_state for {} and {} did not both become True within 30s "
            "after 'config vlan member add' -- orchagent never finished creating the ASIC-side "
            "bridge port".format(tgen1_port, peer_port))

        duthost.shell("config interface ip add Vlan{} {}/{}".format(vlan_id, SVI_IPV4, SVI_IPV4_PREFIXLEN))
        duthost.shell("config interface ip add Vlan{} {}/{}".format(vlan_id, SVI_IPV6, SVI_IPV6_PREFIXLEN))
        svi_created = True

        def _svi_exists():
            res = duthost.shell(
                "test -e /sys/class/net/Vlan{}/address".format(vlan_id), module_ignore_errors=True)
            return res['rc'] == 0

        pytest_assert(
            wait_until(15, 1, 0, _svi_exists),
            "SVI Vlan{} netdev never appeared after config commands".format(vlan_id))
        router_mac = duthost.shell("cat /sys/class/net/Vlan{}/address".format(vlan_id))['stdout'].strip()

        ptf_indices = ptf_indices_for_ports(
            duthost, ptfhost, tbinfo, enum_frontend_asic_index, [tgen1_port, peer_port])

        ctx = SimpleNamespace(
            duthost=duthost,
            asic=asic,
            vlan_id=vlan_id,
            tgen1_port=tgen1_port,
            peer_port=peer_port,
            tgen1_ptf_index=ptf_indices[tgen1_port],
            peer_ptf_index=ptf_indices[peer_port],
            svi_ipv4=SVI_IPV4,
            svi_ipv6=SVI_IPV6,
            router_mac=router_mac,
        )
        yield ctx
    finally:
        if svi_created:
            duthost.shell("config interface ip remove Vlan{} {}/{}".format(vlan_id, SVI_IPV4, SVI_IPV4_PREFIXLEN),
                          module_ignore_errors=True)
            duthost.shell("config interface ip remove Vlan{} {}/{}".format(vlan_id, SVI_IPV6, SVI_IPV6_PREFIXLEN),
                          module_ignore_errors=True)
        duthost.shell("config vlan member del {} {}".format(vlan_id, tgen1_port), module_ignore_errors=True)
        duthost.shell("config vlan member del {} {}".format(vlan_id, peer_port), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        _restore_port_from_l2(duthost, asic, tgen1_port, removed_tgen1)
        _restore_port_from_l2(duthost, asic, peer_port, removed_peer)


def test_transition_removes_routed_config(configure_test_vlan):
    # Verify the transitioned port is an untagged test VLAN member with no remaining routed IP config.
    ctx = configure_test_vlan
    config_facts = get_config_facts(ctx.duthost)

    vlan_name = "Vlan{}".format(ctx.vlan_id)
    vlan_members = config_facts.get('VLAN_MEMBER', {}).get(vlan_name, {})
    pytest_assert(ctx.tgen1_port in vlan_members,
                  "{} is not a member of {} after the transition".format(ctx.tgen1_port, vlan_name))
    pytest_assert(vlan_members[ctx.tgen1_port].get('tagging_mode') == 'untagged',
                  "{} is a member of {} but not untagged".format(ctx.tgen1_port, vlan_name))

    interface_table = config_facts.get('INTERFACE', {})
    port_ip_entries = interface_table.get(ctx.tgen1_port, {})
    leftover_ips = [key for key in port_ip_entries if '/' in key]
    pytest_assert(not leftover_ips,
                  "{} still has routed IP(s) {} in CONFIG_DB INTERFACE table after transitioning "
                  "to an L2 VLAN member".format(ctx.tgen1_port, leftover_ips))


def test_transition_forwards_and_learns_mac(ptfadapter, configure_test_vlan):
    # Verify L2 broadcast forwarding from the transitioned port and FDB learning of its source MAC.
    ctx = configure_test_vlan
    src_mac = _get_mac_str(ptfadapter, ctx.tgen1_ptf_index)
    pkt = testutils.simple_eth_packet(eth_dst="ff:ff:ff:ff:ff:ff", eth_src=src_mac, eth_type=0x1234)

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ctx.tgen1_ptf_index, pkt)
    testutils.verify_packets_any(ptfadapter, pkt, ports=[ctx.peer_ptf_index])

    pytest_assert(
        wait_until(FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL, 0, mac_learned_on_port,
                   ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id),
        "source MAC {} of {} was not learned in the FDB for Vlan{} after a plain L2 broadcast frame".format(
            src_mac, ctx.tgen1_port, ctx.vlan_id))


def test_mac_learning_ipv4_arp_broadcast(ptfadapter, configure_test_vlan):
    # Verify broadcast ARP to the SVI learns the sender MAC in the FDB.
    ctx = configure_test_vlan
    src_mac = _get_mac_str(ptfadapter, ctx.tgen1_ptf_index)
    pkt = testutils.simple_arp_packet(
        eth_dst="ff:ff:ff:ff:ff:ff",
        eth_src=src_mac,
        arp_op=1,
        ip_snd=PEER_IPV4,
        ip_tgt=ctx.svi_ipv4,
        hw_snd=src_mac,
        hw_tgt="ff:ff:ff:ff:ff:ff",
    )
    testutils.send(ptfadapter, ctx.tgen1_ptf_index, pkt)

    pytest_assert(
        wait_until(FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL, 0, mac_learned_on_port,
                   ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id),
        "source MAC {} of {} was not learned in the FDB for Vlan{} after a broadcast ARP request "
        "for the SVI's own IPv4 address".format(src_mac, ctx.tgen1_port, ctx.vlan_id))


def _is_dnx_platform(duthost):
    # IP2ME MAC learning is platform-dependent: VOQ/DNX does not learn it, while XGS does.
    return duthost.facts.get('switch_type') == 'voq'


def test_mac_learning_ipv4_ip2me(ptfadapter, configure_test_vlan):
    # Verify IPv4 IP2ME MAC learning matches the platform's DNX or XGS behavior.
    ctx = configure_test_vlan
    src_mac = _get_mac_str(ptfadapter, ctx.tgen1_ptf_index)
    pkt = testutils.simple_icmp_packet(
        eth_dst=ctx.router_mac,
        eth_src=src_mac,
        ip_src=PEER_IPV4,
        ip_dst=ctx.svi_ipv4,
        ip_ttl=64,
    )
    testutils.send(ptfadapter, ctx.tgen1_ptf_index, pkt)

    if _is_dnx_platform(ctx.duthost):
        pytest_assert(
            _confirm_mac_never_learned(
                ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id, FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL),
            "Source MAC {} on {} was learned in Vlan{} after IPv4 IP2ME traffic on a DNX platform, "
            "but IP2ME must not trigger MAC learning there.".format(src_mac, ctx.tgen1_port, ctx.vlan_id)
        )
    else:
        pytest_assert(
            wait_until(FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL, 0, mac_learned_on_port,
                       ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id),
            "source MAC {} of {} was not learned in the FDB for Vlan{} after IPv4 IP2ME traffic on a "
            "non-DNX (XGS) platform, where IP2ME traffic is expected to be learned like any other "
            "ingress frame".format(src_mac, ctx.tgen1_port, ctx.vlan_id))


def test_mac_learning_ipv6_ndp(ptfadapter, configure_test_vlan):
    # Verify NDP populates `show ndp` but FDB learning occurs only after a normal dataplane frame.
    ctx = configure_test_vlan
    src_mac = _get_mac_str(ptfadapter, ctx.tgen1_ptf_index)

    tgt_addr = ctx.svi_ipv6
    ll_src_addr = _generate_link_local_addr(src_mac)
    multicast_tgt_addr = in6_getnsma(inet_pton(socket.AF_INET6, tgt_addr))
    multicast_tgt_mac = in6_getnsmac(multicast_tgt_addr)

    ns_pkt = Ether(src=src_mac, dst=multicast_tgt_mac)
    ns_pkt /= IPv6(dst=inet_ntop(socket.AF_INET6, multicast_tgt_addr), src=ll_src_addr)
    ns_pkt /= ICMPv6ND_NS(tgt=tgt_addr)
    ns_pkt /= ICMPv6NDOptSrcLLAddr(lladdr=src_mac)

    testutils.send(ptfadapter, ctx.tgen1_ptf_index, ns_pkt)

    pytest_assert(
        wait_until(FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL, 0, _ndp_entry_exists,
                   ctx.duthost, ll_src_addr, src_mac),
        "IPv6 neighbor {} (MAC {}) was not reflected in 'show ndp' after an IPv6 NDP NS "
        "targeting the SVI's own address".format(ll_src_addr, src_mac))

    ns_only_learned = mac_learned_on_port(ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id)
    logger.info(
        "After IPv6 NDP NS only: source MAC %s learned in FDB = %s (expected False or "
        "True-by-coincidence-from-other-traffic; not asserted)", src_mac, ns_only_learned)

    frame_pkt = testutils.simple_eth_packet(eth_dst="ff:ff:ff:ff:ff:ff", eth_src=src_mac, eth_type=0x1234)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ctx.tgen1_ptf_index, frame_pkt)
    testutils.verify_packets_any(ptfadapter, frame_pkt, ports=[ctx.peer_ptf_index])

    pytest_assert(
        wait_until(FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL, 0, mac_learned_on_port,
                   ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id),
        "source MAC {} of {} was not learned in the FDB for Vlan{} after a normal L2 broadcast "
        "frame (sent following an IPv6 NDP NS, which is not expected to learn by itself)".format(
            src_mac, ctx.tgen1_port, ctx.vlan_id))


def test_mac_learning_ipv6_ip2me(ptfadapter, configure_test_vlan):
    # Verify IPv6 IP2ME MAC learning matches the platform's DNX or XGS behavior.
    ctx = configure_test_vlan
    src_mac = _get_mac_str(ptfadapter, ctx.tgen1_ptf_index)
    pkt = testutils.simple_icmpv6_packet(
        eth_dst=ctx.router_mac,
        eth_src=src_mac,
        ipv6_src=PEER_IPV6,
        ipv6_dst=ctx.svi_ipv6,
        ipv6_hlim=64,
    )
    testutils.send(ptfadapter, ctx.tgen1_ptf_index, pkt)

    if _is_dnx_platform(ctx.duthost):
        pytest_assert(
            _confirm_mac_never_learned(
                ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id, FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL),
            "Source MAC {} on {} was learned in Vlan{} after IPv6 IP2ME traffic on a DNX platform, "
            "but IP2ME must not trigger MAC learning there.".format(src_mac, ctx.tgen1_port, ctx.vlan_id)
        )
    else:
        pytest_assert(
            wait_until(FDB_WAIT_TIMEOUT, FDB_WAIT_INTERVAL, 0, mac_learned_on_port,
                       ctx.duthost, ctx.asic, ctx.tgen1_port, src_mac, ctx.vlan_id),
            "source MAC {} of {} was not learned in the FDB for Vlan{} after IPv6 IP2ME traffic on a "
            "non-DNX (XGS) platform, where IP2ME traffic is expected to be learned like any other "
            "ingress frame".format(src_mac, ctx.tgen1_port, ctx.vlan_id))
