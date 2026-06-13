import pytest
import logging
from netaddr import IPNetwork
from jinja2 import Template
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


def configure_ipv6_bgpmon_update_source(duthost, asn, local_addr):
    duthost.run_vtysh(
        "-c 'configure terminal' -c 'router bgp {}' -c 'neighbor BGPMON update-source {}'".format(asn, local_addr),
        asic_index='all'
    )


def test_bgpmon(dut_with_default_route, localhost, enum_rand_one_frontend_asic_index,
                common_setup_teardown, set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add a bgp monitor and verify ExaBGP can actively establish a session
    with DUT configured as passive peer.
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    def bgpmon_peer_connected(bgpmon_peer, is_ipv6):
        try:
            bgp_summary = json.loads(asichost.run_vtysh("-c 'show bgp summary json'")['stdout'])
            af_key = 'ipv6Unicast' if is_ipv6 else 'ipv4Unicast'
            return bgp_summary[af_key]['peers'][bgpmon_peer]["state"] == "Established"
        except Exception:
            logger.info('Unable to get bgp status')
            return False

    local_addr, peer_addr, peer_ports, asn, is_ipv6_only, router_id = common_setup_teardown
    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying active ExaBGP peering")
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)
    if is_ipv6_only:
        configure_ipv6_bgpmon_update_source(duthost, asn, local_addr)
    duthost.run_vtysh(
        "-c 'configure terminal' -c 'router bgp {}' -c 'neighbor {} passive'".format(asn, peer_addr),
        asic_index='all'
    )

    ip_cmd = "-6" if is_ipv6_only else ""
    prefix_len = "/64" if is_ipv6_only else "/24"
    route_prefix_len = "/128" if is_ipv6_only else "/32"

    selected_ptf_interface = None
    bgpmon_established = False
    try:
        for port_index in peer_ports:
            ptf_interface = "eth" + str(port_index)
            logger.info("Trying BGPMon active peering on %s", ptf_interface)
            ptfhost.shell("ip %s addr add %s dev %s" % (ip_cmd, peer_addr + prefix_len, ptf_interface))
            ptfhost.shell(
                "ip %s neigh add %s lladdr %s dev %s"
                % (ip_cmd, local_addr, duthost.facts["router_mac"], ptf_interface)
            )
            ptfhost.shell(
                "ip %s route replace %s dev %s"
                % (ip_cmd, local_addr + route_prefix_len, ptf_interface)
            )
            ptfhost.exabgp(
                name=BGP_MONITOR_NAME,
                state="started",
                local_ip=peer_addr,
                router_id=router_id,
                peer_ip=local_addr,
                local_asn=asn,
                peer_asn=asn,
                port=BGP_MONITOR_PORT,
                passive=False
            )
            pytest_assert(
                wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
                "Failed to start bgp monitor session on PTF"
            )
            if wait_until(
                MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, peer_addr, is_ipv6_only
            ):
                selected_ptf_interface = ptf_interface
                bgpmon_established = True
                break
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
        pytest_assert(bgpmon_established, "BGPMon Peer connection not established")
    finally:
        duthost.run_vtysh(
            "-c 'configure terminal' -c 'router bgp {}' -c 'no neighbor {} passive'".format(asn, peer_addr),
            asic_index='all'
        )
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        if selected_ptf_interface:
            ptfhost.shell(
                "ip %s route del %s dev %s"
                % (ip_cmd, local_addr + route_prefix_len, selected_ptf_interface)
            )
            ptfhost.shell(
                "ip %s neigh del %s lladdr %s dev %s"
                % (ip_cmd, local_addr, duthost.facts["router_mac"], selected_ptf_interface)
            )
            ptfhost.shell(
                "ip %s addr del %s dev %s"
                % (ip_cmd, peer_addr + prefix_len, selected_ptf_interface)
            )
