import pytest
import logging
from netaddr import IPNetwork
import ptf.testutils as testutils
from jinja2 import Template
import ptf.packet as scapy
from ptf.mask import Mask
import json
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # noqa F401
from tests.common.helpers.generators import generate_ip_through_default_route, generate_ip_through_default_v6_route
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import wait_tcp_connection
from tests.common.utilities import is_ipv6_only_topology
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
    mg_facts = host.get_extended_minigraph_facts(tbinfo)
    ip_cmd = "ipv6" if is_ipv6 else "ip"
    route_info = json.loads(host.shell("show {} route {} json".format(ip_cmd, default_addr))['stdout'])
    ports = []
    for route in route_info[default_addr]:
        if route['protocol'] != 'bgp':
            continue
        for itfs in route['nexthops']:
            if 'interfaceName' in itfs and '-IB' not in itfs['interfaceName']:
                ports.append(itfs['interfaceName'])
    port_indices = []
    for port in ports:
        if 'PortChannel' in port:
            for member in mg_facts['minigraph_portchannels'][port]['members']:
                port_indices.append(mg_facts['minigraph_ptf_indices'][member])
        else:
            port_indices.append(mg_facts['minigraph_ptf_indices'][port])

    return port_indices


@pytest.fixture
def common_setup_teardown(dut_with_default_route, tbinfo):
    duthost = dut_with_default_route
    is_ipv6_only = is_ipv6_only_topology(tbinfo)

    # Generate a unique IPV4 address to be used as the BGP router identifier for the monitor connection
    router_id = generate_ip_through_default_route(duthost)
    pytest_assert(router_id, "Failed to generate router id")
    router_id = str(IPNetwork(router_id).ip)

    if is_ipv6_only:
        peer_addr = generate_ip_through_default_v6_route(duthost)
        pytest_assert(peer_addr, "Failed to generate ipv6 address for test")
        peer_addr = str(IPNetwork(peer_addr).ip)
    else:
        peer_addr = router_id

    peer_ports = get_default_route_ports(
        duthost,
        tbinfo,
        default_addr=ZERO_ADDR_V6 if is_ipv6_only else ZERO_ADDR,
        is_ipv6=is_ipv6_only
    )
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    local_addr = None
    for lo_intf in mg_facts['minigraph_lo_interfaces']:
        if is_ipv6_only and ':' in lo_intf['addr']:
            local_addr = lo_intf['addr']
            break
        elif not is_ipv6_only and ':' not in lo_intf['addr']:
            local_addr = lo_intf['addr']
            break

    pytest_assert(local_addr, "Failed to get appropriate loopback address")

    # Assign peer addr to an interface on ptf
    logger.info("Generated peer address {}".format(peer_addr))
    bgpmon_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': peer_addr,
        'asn': mg_facts['minigraph_bgp_asn'],
        'local_addr': local_addr,
        'peer_name': BGP_MONITOR_NAME
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args),
                 dest=BGPMON_CONFIG_FILE)
    yield local_addr, peer_addr, peer_ports, mg_facts['minigraph_bgp_asn'], is_ipv6_only, router_id
    # Cleanup bgp monitor
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(peer_addr), asic_index='all')
    duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


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


def test_resolve_via_default_exist(duthost):
    """
    Test to verify if 'ip nht resolve-via-default' and 'ipv6 nht resolve-via-default' are present in global FRR config.
    """
    frr_global_config = duthost.shell("vtysh -c 'show running-config'")['stdout']
    pytest_assert("ip nht resolve-via-default" in frr_global_config,
                  "ip nht resolve-via-default not present in global FRR config")
    pytest_assert("ipv6 nht resolve-via-default" in frr_global_config,
                  "ipv6 nht resolve-via-default not present in global FRR config")


def configure_ipv6_bgpmon_update_source(duthost, asn, local_addr):
    duthost.run_vtysh(
        "-c 'configure terminal' -c 'router bgp {}' -c 'neighbor BGPMON update-source {}'".format(asn, local_addr),
        asic_index='all'
    )


def test_bgpmon(dut_with_default_route, localhost, enum_rand_one_frontend_asic_index,
                common_setup_teardown, set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add a bgp monitor on ptf and verify that DUT is attempting to establish connection to it
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    def bgpmon_peer_connected(duthost, bgpmon_peer, is_ipv6):
        try:
            bgp_summary = json.loads(asichost.run_vtysh("-c 'show bgp summary json'")['stdout'])
            af_key = 'ipv6Unicast' if is_ipv6 else 'ipv4Unicast'
            return bgp_summary[af_key]['peers'][bgpmon_peer]["state"] == "Established"
        except Exception:
            logger.info('Unable to get bgp status')
            return False

    local_addr, peer_addr, peer_ports, asn, is_ipv6_only, router_id = common_setup_teardown
    exp_packet = build_syn_pkt(local_addr, peer_addr, is_ipv6=is_ipv6_only)
    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying packet on {}".format(peer_ports))
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)
    if is_ipv6_only:
        configure_ipv6_bgpmon_update_source(duthost, asn, local_addr)
    # Verify syn packet on ptf
    (rcvd_port_index, rcvd_pkt) = testutils.verify_packet_any_port(
        test=ptfadapter, pkt=exp_packet, ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT
    )
    # ip as BGMPMON IP , mac as the neighbor mac(mac for default nexthop that was used for sending syn packet) ,
    # add the neighbor entry and the default route for dut loopback
    ptf_interface = "eth" + str(peer_ports[rcvd_port_index])
    res = ptfhost.shell('cat /sys/class/net/{}/address'.format(ptf_interface))
    original_mac = res['stdout']
    ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, scapy.Ether(rcvd_pkt).dst))

    ip_cmd = "-6" if is_ipv6_only else ""
    prefix_len = "/64" if is_ipv6_only else "/24"
    route_prefix_len = "/128" if is_ipv6_only else "/32"

    ptfhost.shell("ip %s addr add %s dev %s" % (ip_cmd, peer_addr + prefix_len, ptf_interface))
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
        "ip %s neigh add %s lladdr %s dev %s"
        % (ip_cmd, local_addr, duthost.facts["router_mac"], ptf_interface)
    )
    ptfhost.shell(
        "ip %s route replace %s dev %s"
        % (ip_cmd, local_addr + route_prefix_len, ptf_interface)
    )
    try:
        pytest_assert(
            wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
            "Failed to start bgp monitor session on PTF"
        )
        pytest_assert(
            wait_until(
                MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, duthost, peer_addr, is_ipv6_only
            ),
            "BGPMon Peer connection not established"
        )
    finally:
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        ptfhost.shell(
            "ip %s route del %s dev %s"
            % (ip_cmd, local_addr + route_prefix_len, ptf_interface)
        )
        ptfhost.shell(
            "ip %s neigh del %s lladdr %s dev %s"
            % (ip_cmd, local_addr, duthost.facts["router_mac"], ptf_interface)
        )
        ptfhost.shell(
            "ip %s addr del %s dev %s"
            % (ip_cmd, peer_addr + prefix_len, ptf_interface)
        )
        ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, original_mac))


def test_bgpmon_no_resolve_via_default(dut_with_default_route, enum_rand_one_frontend_asic_index,
                                       common_setup_teardown, ptfadapter):
    """
    Verify no syn for BGP is sent when 'ip nht resolve-via-default' or 'ipv6 nht resolve-via-default' is disabled.
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    local_addr, peer_addr, peer_ports, asn, is_ipv6_only, router_id = common_setup_teardown
    exp_packet = build_syn_pkt(local_addr, peer_addr, is_ipv6=is_ipv6_only)

    ip_cmd = "ipv6" if is_ipv6_only else "ip"

    # Load bgp monitor config
    logger.info(
        "Configured bgpmon and verifying no packet on {} when resolve-via-default is disabled".format(peer_ports)
    )
    try:
        # Disable resolve-via-default
        duthost.run_vtysh(
            " -c \"configure terminal\" -c \"no {} nht resolve-via-default\"".format(ip_cmd),
            asic_index='all'
        )
        # Flush dataplane
        ptfadapter.dataplane.flush()
        asichost.write_to_config_db(BGPMON_CONFIG_FILE)

        # Verify no syn packet is received
        pytest_assert(
            0 == testutils.count_matched_packets_all_ports(
                test=ptfadapter, exp_packet=exp_packet, ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT
            ),
            "Syn packets is captured when resolve-via-default is disabled"
        )
    finally:
        # Re-enable resolve-via-default
        duthost.run_vtysh(
            "-c \"configure terminal\" -c \"{} nht resolve-via-default\"".format(ip_cmd),
            asic_index='all'
        )
