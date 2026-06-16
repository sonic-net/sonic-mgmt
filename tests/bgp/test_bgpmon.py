import pytest
import logging
import ipaddress
from netaddr import IPNetwork
import ptf.testutils as testutils
from jinja2 import Template
import ptf.packet as scapy
from ptf.mask import Mask
import json
from tests.common.helpers.generators import generate_ip_through_default_route, generate_ip_through_default_v6_route
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import wait_tcp_connection
from tests.common.utilities import is_ipv6_only_topology
from tests.common.utilities import get_image_type
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME, BGP_MONITOR_PORT

pytestmark = [
    pytest.mark.topology('any'),
]

BGP_PORT = 179
BGP_CONNECT_TIMEOUT = 121
MAX_TIME_FOR_BGPMON = 180
ZERO_ADDR = r'0.0.0.0/0'
ZERO_ADDR_V6 = r'::/0'
logger = logging.getLogger(__name__)


def get_default_route_ports(host, tbinfo, default_addr=ZERO_ADDR, is_ipv6=False):
    """
    Returns (ptf_port_indices, dut_ports) for ports reachable via the default route.
    ptf_port_indices[i] is the PTF index of the port; dut_ports[i] is the DUT interface
    name (physical member port) that maps to it — used to look up the per-ASIC router MAC
    on multi-ASIC devices.
    """
    mg_facts = host.get_extended_minigraph_facts(tbinfo)
    ip_cmd = "ipv6" if is_ipv6 else "ip"
    route_info = json.loads(host.shell("show {} route {} json".format(ip_cmd, default_addr))['stdout'])
    ports = []
    for route in route_info.get(default_addr, []):
        if route['protocol'] != 'bgp':
            continue
        for itfs in route.get('nexthops', []):
            if 'interfaceName' in itfs and '-IB' not in itfs['interfaceName']:
                ports.append(itfs['interfaceName'])
    port_indices = []
    dut_ports = []
    for port in ports:
        if 'PortChannel' in port:
            for member in mg_facts['minigraph_portchannels'][port]['members']:
                port_indices.append(mg_facts['minigraph_ptf_indices'][member])
                dut_ports.append(member)
        else:
            port_indices.append(mg_facts['minigraph_ptf_indices'][port])
            dut_ports.append(port)

    return port_indices, dut_ports


def build_syn_pkt(local_addr, peer_addr, is_ipv6=False):
    if is_ipv6:
        pkt = testutils.simple_tcpv6_packet(
            pktlen=74,
            ipv6_src=local_addr,
            ipv6_dst=peer_addr,
            tcp_dport=BGP_PORT,
            tcp_flags="S"
        )
        exp_packet = Mask(pkt)
        exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_packet.set_do_not_care_scapy(scapy.Ether, "src")
        exp_packet.set_do_not_care_scapy(scapy.IPv6, "version")
        exp_packet.set_do_not_care_scapy(scapy.IPv6, "tc")
        exp_packet.set_do_not_care_scapy(scapy.IPv6, "fl")
        exp_packet.set_do_not_care_scapy(scapy.IPv6, "plen")
        exp_packet.set_do_not_care_scapy(scapy.IPv6, "nh")
        exp_packet.set_do_not_care_scapy(scapy.IPv6, "hlim")
    else:
        pkt = testutils.simple_tcp_packet(
            pktlen=54,
            ip_src=local_addr,
            ip_dst=peer_addr,
            tcp_dport=BGP_PORT,
            tcp_flags="S"
        )
        exp_packet = Mask(pkt)
        exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_packet.set_do_not_care_scapy(scapy.Ether, "src")
        exp_packet.set_do_not_care_scapy(scapy.IP, "version")
        exp_packet.set_do_not_care_scapy(scapy.IP, "ihl")
        exp_packet.set_do_not_care_scapy(scapy.IP, "tos")
        exp_packet.set_do_not_care_scapy(scapy.IP, "len")
        exp_packet.set_do_not_care_scapy(scapy.IP, "id")
        exp_packet.set_do_not_care_scapy(scapy.IP, "flags")
        exp_packet.set_do_not_care_scapy(scapy.IP, "frag")
        exp_packet.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
        exp_packet.set_do_not_care_scapy(scapy.IP, "options")

    # TCP fields (common for both IPv4 and IPv6)
    exp_packet.set_do_not_care_scapy(scapy.TCP, "sport")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "seq")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "ack")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "reserved")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "dataofs")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "window")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "urgptr")

    exp_packet.set_ignore_extra_bytes()
    return exp_packet


def get_router_mac_for_port(duthost, dut_port):
    """
    Return the router MAC for the DUT interface.
    On multi-ASIC devices each ASIC has its own MAC; get it from the ASIC that owns dut_port.
    On single-ASIC devices return the global router MAC.
    """
    if duthost.is_multi_asic:
        return duthost.get_port_asic_instance(dut_port).get_router_mac()
    return duthost.facts["router_mac"]


def bgpmon_peer_connected(asichost, bgpmon_peer, is_ipv6=False):
    try:
        bgp_summary = json.loads(asichost.run_vtysh("-c 'show bgp summary json'")['stdout'])
        af_key = 'ipv6Unicast' if is_ipv6 else 'ipv4Unicast'
        return bgp_summary[af_key]['peers'][bgpmon_peer]["state"] == "Established"
    except Exception:
        logger.info('Unable to get bgp status')
        return False


@pytest.fixture
def common_setup_teardown(dut_with_default_route, tbinfo, enum_rand_one_frontend_asic_index):
    """
    Provides v4 and v6 peer/local addresses and peer-ports for bgpmon tests.
    Yields a dict with keys 'v4', 'v6', 'asn', 'router_id'.
    - 'v4'/'v6' each contain {'local_addr', 'peer_addr', 'peer_ports'}.
    - local_addr is taken from Loopback4096 (multi-ASIC) or Loopback0 (single-ASIC).
    - Cleanup removes BGP_MONITORS entries for both address families.
    """
    duthost = dut_with_default_route

    # router_id is always an IPv4 address (used as BGP identifier)
    router_id = generate_ip_through_default_route(duthost)
    pytest_assert(router_id, "Failed to generate router id")
    router_id = str(IPNetwork(router_id).ip)

    # peer addresses
    peer_addr_v4 = router_id
    peer_addr_v6_raw = generate_ip_through_default_v6_route(duthost)
    peer_addr_v6 = str(IPNetwork(peer_addr_v6_raw).ip) if peer_addr_v6_raw else None

    # peer port indices + corresponding DUT interface names via default route for each AF
    peer_ports_v4, peer_dut_ports_v4 = get_default_route_ports(duthost, tbinfo, ZERO_ADDR, is_ipv6=False)
    peer_ports_v6, peer_dut_ports_v6 = get_default_route_ports(duthost, tbinfo, ZERO_ADDR_V6, is_ipv6=True)

    # local_addr: Loopback4096 (multi-ASIC) or Loopback0 (single-ASIC) for each AF
    local_addr_v4 = None
    local_addr_v6 = None
    if duthost.is_multi_asic:
        asic_idx = enum_rand_one_frontend_asic_index if enum_rand_one_frontend_asic_index else 0
        cfg_facts = duthost.config_facts(
            source='persistent', asic_index='all'
        )[asic_idx]['ansible_facts']
        lb4096_intfs = cfg_facts.get('LOOPBACK_INTERFACE', {}).get('Loopback4096', {})
        for lb_key in lb4096_intfs:
            intf = ipaddress.ip_interface(lb_key)
            if intf.ip.version == 4 and local_addr_v4 is None:
                local_addr_v4 = str(intf.ip)
            elif intf.ip.version == 6 and local_addr_v6 is None:
                local_addr_v6 = str(intf.ip)
        pytest_assert(local_addr_v4 is not None,
                      "Multi-ASIC device must have an IPv4 address on Loopback4096 (asic {})".format(asic_idx))
        pytest_assert(local_addr_v6 is not None,
                      "Multi-ASIC device must have an IPv6 address on Loopback4096 (asic {})".format(asic_idx))
    else:
        # Single-ASIC: use Loopback0 from minigraph
        mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        for lo_intf in mg_facts['minigraph_lo_interfaces']:
            if local_addr_v4 is None and ':' not in lo_intf['addr']:
                local_addr_v4 = lo_intf['addr']
            elif local_addr_v6 is None and ':' in lo_intf['addr']:
                local_addr_v6 = lo_intf['addr']

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']

    logger.info("local_addr v4={} v6={}, peer_addr v4={} v6={}".format(
        local_addr_v4, local_addr_v6, peer_addr_v4, peer_addr_v6))

    yield {
        'v4': {'local_addr': local_addr_v4, 'peer_addr': peer_addr_v4,
               'peer_ports': peer_ports_v4, 'peer_dut_ports': peer_dut_ports_v4},
        'v6': {'local_addr': local_addr_v6, 'peer_addr': peer_addr_v6,
               'peer_ports': peer_ports_v6, 'peer_dut_ports': peer_dut_ports_v6},
        'asn': asn,
        'router_id': router_id,
    }

    # Remove the bgpmon config file from DUT as a safety net.
    # CONFIG_DB cleanup is the responsibility of each test (in its finally block),
    # since only the test knows which peer_addr it actually configured.
    duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


def test_bgpmon_v4(dut_with_default_route, localhost, tbinfo, enum_rand_one_frontend_asic_index,
                   common_setup_teardown, set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add a bgp monitor on ptf and verify that DUT is attempting to establish connection to it.
    IPv6-only topologies are skipped — v6 bgpmon is covered by test_bgpmon_v6.
    For Public cloudtype devices (where 'ip nht resolve-via-default' is absent from the
    template), temporarily enable ip nht resolve-via-default so the DUT can resolve and actively
    connect to the BGP monitor peer via the default route.
    """
    if is_ipv6_only_topology(tbinfo):
        pytest.skip("v6 topo will always have v6 bgpmon so skipping this")

    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    local_addr = common_setup_teardown['v4']['local_addr']
    peer_addr = common_setup_teardown['v4']['peer_addr']
    peer_ports = common_setup_teardown['v4']['peer_ports']
    peer_dut_ports = common_setup_teardown['v4']['peer_dut_ports']
    asn = common_setup_teardown['asn']
    router_id = common_setup_teardown['router_id']

    pytest_assert(local_addr, "No v4 local_addr available")
    pytest_assert(peer_addr, "No v4 peer_addr available")

    # Render and load bgpmon config for the v4 peer
    bgpmon_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': peer_addr,
        'asn': asn,
        'local_addr': local_addr,
        'peer_name': BGP_MONITOR_NAME
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args), dest=BGPMON_CONFIG_FILE)

    # For Public cloudtype, nht resolve-via-default is not configured in the template.
    # Temporarily enable it so the DUT can resolve the BGP monitor peer and send a SYN.
    cloudtype = duthost.shell(
        "sonic-cfggen -d -v \"DEVICE_METADATA['localhost'].get('cloudtype', '')\"",
        module_ignore_errors=True
    )['stdout'].strip().lower()
    nht_configured_for_test = cloudtype == 'public'
    if nht_configured_for_test:
        logger.info("Public cloudtype: temporarily enabling ip nht resolve-via-default for test")
        duthost.run_vtysh(
            "-c 'configure terminal' -c 'ip nht resolve-via-default'",
            asic_index='all'
        )

    exp_packet = build_syn_pkt(local_addr, peer_addr)
    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying packet on {}".format(peer_ports))
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)
    # Verify syn packet on ptf — confirms DUT is actively initiating the connection
    (rcvd_port_index, rcvd_pkt) = testutils.verify_packet_any_port(
        test=ptfadapter, pkt=exp_packet, ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT
    )
    # Use the port/MAC from the SYN to set up ExaBGP on the correct interface
    ptf_interface = "eth" + str(peer_ports[rcvd_port_index])
    router_mac = get_router_mac_for_port(duthost, peer_dut_ports[rcvd_port_index])
    res = ptfhost.shell('cat /sys/class/net/{}/address'.format(ptf_interface))
    original_mac = res['stdout']
    ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, scapy.Ether(rcvd_pkt).dst))

    ptfhost.shell("ip addr add %s dev %s" % (peer_addr + "/24", ptf_interface))
    ptfhost.exabgp(
        name=BGP_MONITOR_NAME,
        state="started",
        local_ip=peer_addr,
        router_id=router_id,
        peer_ip=local_addr,
        local_asn=asn,
        peer_asn=asn,
        port=BGP_MONITOR_PORT,
        passive=True
    )
    ptfhost.shell(
        "ip neigh add %s lladdr %s dev %s"
        % (local_addr, router_mac, ptf_interface)
    )
    ptfhost.shell(
        "ip route replace %s dev %s"
        % (local_addr + "/32", ptf_interface)
    )
    try:
        pytest_assert(
            wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
            "Failed to start bgp monitor session on PTF"
        )
        pytest_assert(
            wait_until(MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, asichost, peer_addr),
            "BGPMon Peer connection not established"
        )
    finally:
        if nht_configured_for_test:
            logger.info("Public cloudtype: removing temporary ip nht resolve-via-default")
            duthost.run_vtysh(
                "-c 'configure terminal' -c 'no ip nht resolve-via-default'",
                asic_index='all'
            )
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        ptfhost.shell("ip route del %s dev %s" % (local_addr + "/32", ptf_interface))
        ptfhost.shell("ip neigh del %s lladdr %s dev %s"
                      % (local_addr, router_mac, ptf_interface))
        ptfhost.shell("ip addr del %s dev %s" % (peer_addr + "/24", ptf_interface))
        ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, original_mac))
        duthost.run_sonic_db_cli_cmd(
            "CONFIG_DB del 'BGP_MONITORS|{}'".format(peer_addr), asic_index='all')


def test_bgpmon_v6(dut_with_default_route, localhost, enum_rand_one_frontend_asic_index,
                   common_setup_teardown, set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add an IPv6 bgp monitor and verify ExaBGP can actively establish a session.
    Uses 'v6' data from common_setup_teardown (Loopback4096 on multi-ASIC, Loopback0 on single-ASIC).
    For non-internal images explicitly configures 'neighbor <peer> passive' on the DUT so ExaBGP
    can initiate the connection; internal images already have passive configured via the image build.
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    local_addr = common_setup_teardown['v6']['local_addr']
    peer_addr = common_setup_teardown['v6']['peer_addr']
    peer_ports = common_setup_teardown['v6']['peer_ports']
    peer_dut_ports = common_setup_teardown['v6']['peer_dut_ports']
    asn = common_setup_teardown['asn']
    router_id = common_setup_teardown['router_id']

    pytest_assert(local_addr, "No v6 local_addr available")
    pytest_assert(peer_addr, "No v6 peer_addr available")
    pytest_assert(peer_ports, "No v6 peer_ports available")

    # Render and load bgpmon config for the v6 peer
    bgpmon_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': peer_addr,
        'asn': asn,
        'local_addr': local_addr,
        'peer_name': BGP_MONITOR_NAME
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args), dest=BGPMON_CONFIG_FILE)

    # For non-internal images, configure DUT neighbor as passive so ExaBGP can actively connect.
    configure_passive = get_image_type(duthost) != "internal"

    # Flush dataplane
    ptfadapter.dataplane.flush()
    logger.info("Configured bgpmon v6 and verifying active ExaBGP peering")
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)
    if configure_passive:
        duthost.run_vtysh(
            "-c 'configure terminal' -c 'router bgp {}' -c 'neighbor {} passive'".format(asn, peer_addr),
            asic_index='all'
        )

    selected_ptf_interface = None
    selected_router_mac = None
    bgpmon_established = False

    try:
        for port_index, dut_port in zip(peer_ports, peer_dut_ports):
            logger.info("Trying BGPMon v6 active peering on PTF port %s (DUT %s)", port_index, dut_port)
            router_mac = get_router_mac_for_port(duthost, dut_port)
            ptf_interface = "eth" + str(port_index)
            ptfhost.shell("ip -6 addr add {} dev {}".format(peer_addr + "/128", ptf_interface))
            ptfhost.shell("ip neigh add %s lladdr %s dev %s"
                          % (local_addr, router_mac, ptf_interface))
            ptfhost.shell("ip -6 route replace %s dev %s" % (local_addr + "/128", ptf_interface))

            ptfhost.exabgp(name=BGP_MONITOR_NAME,
                           state="started",
                           local_ip=peer_addr,
                           router_id=router_id,
                           peer_ip=local_addr,
                           local_asn=asn,
                           peer_asn=asn,
                           port=BGP_MONITOR_PORT,
                           passive=False)
            pytest_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
                          "Failed to start bgp monitor session on PTF")
            if wait_until(MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, asichost, peer_addr, True):
                selected_ptf_interface = ptf_interface
                selected_router_mac = router_mac
                bgpmon_established = True
                break

            ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
            ptfhost.shell("ip -6 route del %s dev %s" % (local_addr + "/128", ptf_interface))
            ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s"
                          % (local_addr, router_mac, ptf_interface))
            ptfhost.shell("ip -6 addr del %s dev %s" % (peer_addr + "/128", ptf_interface))

        pytest_assert(bgpmon_established, "BGPMon v6 Peer connection not established")
    finally:
        if configure_passive:
            duthost.run_vtysh(
                "-c 'configure terminal' -c 'router bgp {}' -c 'no neighbor {} passive'".format(asn, peer_addr),
                asic_index='all'
            )
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        if selected_ptf_interface:
            ptfhost.shell("ip -6 route del %s dev %s" % (local_addr + "/128", selected_ptf_interface))
            ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s"
                          % (local_addr, selected_router_mac, selected_ptf_interface))
            ptfhost.shell("ip -6 addr del %s dev %s" % (peer_addr + "/128", selected_ptf_interface))
        duthost.run_sonic_db_cli_cmd(
            "CONFIG_DB del 'BGP_MONITORS|{}'".format(peer_addr), asic_index='all')
