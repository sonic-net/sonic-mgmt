import pytest
import logging
import json
import random
import time

from tests.common.dualtor.dual_tor_utils import get_crm_nexthop_counter
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.helpers import bgp
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.assertions import pytest_require as py_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_garp_service, \
                                                copy_arp_responder_py   # noqa: F401
from tests.common.dualtor.dual_tor_mock import *                        # noqa: F401, F403
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import is_ipv4_address


CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300
EXABGP_PORT_UPPER_TOR = 11000
EXABGP_PORT_LOWER_TOR = 11001


@pytest.fixture
def set_crm_polling_interval(rand_selected_dut):
    """
    A function level fixture to set crm polling interval to 1 second
    """
    wait_time = 2
    logging.info("Setting crm polling interval to {} seconds".format(CRM_POLL_INTERVAL))
    rand_selected_dut.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logging.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    logging.info("Setting crm polling interval to {} seconds".format(CRM_DEFAULT_POLL_INTERVAL))
    rand_selected_dut.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))


@pytest.fixture
def verify_crm_nexthop_counter_not_increased(rand_selected_dut, set_crm_polling_interval):
    """
    A function level fixture to verify crm nexthop counter not increased
    """
    original_counter = get_crm_nexthop_counter(rand_selected_dut)
    logging.info("Before test: crm nexthop counter = {}".format(original_counter))
    yield
    time.sleep(CRM_POLL_INTERVAL)
    diff = get_crm_nexthop_counter(rand_selected_dut) - original_counter
    logging.info("Before test: crm nexthop counter = {}".format(original_counter + diff))
    py_assert(diff <= 0, "crm nexthop counter is increased by {}.".format(diff))


def pytest_addoption(parser):
    """
    Adds pytest options that are used by dual ToR tests
    """

    dual_tor_group = parser.getgroup("Dual ToR test suite options")

    dual_tor_group.addoption(
        "--mux-stress-count",
        action="store",
        default=2,
        type=int,
        help="The number of iterations for mux stress test"
    )


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(rand_selected_dut, request, tbinfo, vmhost):
    # Skip dualtor test cases on unsupported platform
    if rand_selected_dut.facts['asic_type'] != 'vs':
        supported_platforms = ['broadcom_td3_hwskus', 'broadcom_th2_hwskus', 'cisco_hwskus', 'mellanox_dualtor_hwskus']
        hostvars = get_host_visible_vars(rand_selected_dut.host.options['inventory'], rand_selected_dut.hostname)
        hwsku = rand_selected_dut.facts['hwsku']
        skip = True
        for platform in supported_platforms:
            supported_skus = hostvars.get(platform, [])
            if hwsku in supported_skus:
                skip = False
                break
        py_require(not skip, "Skip on unsupported platform")

    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('run_garp_service')


def _setup_arp_responder(rand_selected_dut, ptfhost, tbinfo, ip_type):
    logging.info('Setup ARP responder in the PTF container  {}'.format(ptfhost.hostname))
    duthost = rand_selected_dut
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    minigraph_ptf_indices = mg_facts['minigraph_ptf_indices']
    mux_config = mux_cable_server_ip(duthost)
    if ip_type == 'ipv4':
        arp_responder_conf = {"eth%s" % minigraph_ptf_indices[port]: [config["server_ipv4"].split("/")[0]]
                              for port, config in list(mux_config.items())}
    else:
        arp_responder_conf = {"eth%s" % minigraph_ptf_indices[port]: [config["server_ipv6"].split("/")[0]]
                              for port, config in list(mux_config.items())}
    ptfhost.copy(content=json.dumps(arp_responder_conf, indent=4), dest="/tmp/from_t1.json")

    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": ""})
    ptfhost.template(src="templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
    ptfhost.shell('supervisorctl reread && supervisorctl update')
    ptfhost.shell('supervisorctl restart arp_responder')


@pytest.fixture(scope="module")
def run_arp_responder_ipv6(rand_selected_dut, ptfhost, tbinfo, apply_mock_dual_tor_tables):
    """Run arp_responder to enable ptf to respond neighbor solicitation messages"""
    _setup_arp_responder(rand_selected_dut, ptfhost, tbinfo, 'ipv6')
    yield

    ptfhost.shell('supervisorctl stop arp_responder', module_ignore_errors=True)


@pytest.fixture(scope="module")
def run_arp_responder(rand_selected_dut, ptfhost, tbinfo):
    _setup_arp_responder(rand_selected_dut, ptfhost, tbinfo, 'ipv4')
    yield

    ptfhost.shell('supervisorctl stop arp_responder', module_ignore_errors=True)


@pytest.fixture(scope="module")
def config_facts(rand_selected_dut):
    return rand_selected_dut.config_facts(host=rand_selected_dut.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module")
def test_device_interface(request):
    return request.param


@pytest.fixture(scope="module")
def setup_interfaces(ptfhost, upper_tor_host, lower_tor_host, tbinfo, test_device_interface):
    """Setup the interfaces used by the new BGP sessions on PTF."""

    if "dualtor" not in tbinfo['topo']['name']:
        pytest.skip("This is only applicable for dualtor topology")

    def _find_test_lo_interface(mg_facts):
        for loopback in mg_facts["minigraph_lo_interfaces"]:
            if loopback["name"] == test_device_interface:
                return loopback

    def _find_ipv4_vlan(mg_facts):
        for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
            if is_ipv4_address(vlan_intf["addr"]):
                return vlan_intf

    def _find_ipv6_vlan(mg_facts):
        for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
            if not is_ipv4_address(vlan_intf["addr"]):
                return vlan_intf

    # find the DUT interface ip used in the bgp session
    upper_tor_mg_facts = upper_tor_host.get_extended_minigraph_facts(tbinfo)
    lower_tor_mg_facts = lower_tor_host.get_extended_minigraph_facts(tbinfo)
    upper_tor_intf = _find_test_lo_interface(upper_tor_mg_facts)
    lower_tor_intf = _find_test_lo_interface(lower_tor_mg_facts)
    assert upper_tor_intf, ("upper_tor_intf is not True or it's None")
    assert lower_tor_intf, ("lower_tor_intf is not True or it's None")

    upper_tor_intf_addr = "%s/%s" % (upper_tor_intf["addr"], upper_tor_intf["prefixlen"])
    lower_tor_intf_addr = "%s/%s" % (lower_tor_intf["addr"], lower_tor_intf["prefixlen"])

    # find the server ip used in the bgp session
    mux_configs = mux_cable_server_ip(upper_tor_host)
    test_iface = random.choice(list(mux_configs.keys()))
    test_server = mux_configs[test_iface]
    test_server_ip = test_server["server_ipv4"]
    test_server_ipv6 = test_server["server_ipv6"]
    upper_tor_server_ptf_intf_idx = upper_tor_mg_facts["minigraph_port_indices"][test_iface]
    lower_tor_server_ptf_intf_idx = lower_tor_mg_facts["minigraph_port_indices"][test_iface]
    upper_tor_server_ptf_intf = "eth%s" % upper_tor_server_ptf_intf_idx
    lower_tor_server_ptf_intf = "eth%s" % lower_tor_server_ptf_intf_idx
    assert upper_tor_server_ptf_intf == lower_tor_server_ptf_intf, (
        "Mismatch in PTF interface mapping for the test server between upper and lower ToR.\n"
        "- Upper ToR PTF interface: {}\n"
        "- Lower ToR PTF interface: {}"
    ).format(upper_tor_server_ptf_intf, lower_tor_server_ptf_intf)

    # find the vlan interface ip, used as next-hop for routes added on ptf
    upper_tor_vlan = _find_ipv4_vlan(upper_tor_mg_facts)
    lower_tor_vlan = _find_ipv4_vlan(lower_tor_mg_facts)
    assert upper_tor_vlan, ("upper_tor_vlan is not True or it's None or empty")

    assert lower_tor_vlan, ("lower_tor_vlan is not True or it's None or empty")

    assert upper_tor_vlan["addr"] == lower_tor_vlan["addr"], (
        "Mismatch in IPv4 VLAN interface addresses between upper and lower ToR.\n"
        "- Upper ToR VLAN address: {}\n"
        "- Lower ToR VLAN address: {}"
    ).format(upper_tor_vlan["addr"], lower_tor_vlan["addr"])

    vlan_intf_addr = upper_tor_vlan["addr"]
    vlan_intf_prefixlen = upper_tor_vlan["prefixlen"]

    upper_tor_vlan_ipv6 = _find_ipv6_vlan(upper_tor_mg_facts)
    lower_tor_vlan_ipv6 = _find_ipv6_vlan(lower_tor_mg_facts)
    assert upper_tor_vlan_ipv6, ("upper_tor_vlan_ipv6 is not True or it's None or empty")

    assert lower_tor_vlan_ipv6, ("lower_tor_vlan_ipv6 is not True or it's None or empty")

    assert upper_tor_vlan_ipv6["addr"] == lower_tor_vlan_ipv6["addr"], (
        "Mismatch in IPv6 VLAN interface addresses between upper and lower ToR.\n"
        "- Upper ToR VLAN IPv6 address: {}\n"
        "- Lower ToR VLAN IPv6 address: {}"
    ).format(upper_tor_vlan_ipv6["addr"], lower_tor_vlan_ipv6["addr"])

    vlan_intf_prefixlen_ipv6 = upper_tor_vlan_ipv6["prefixlen"]

    # construct the server ip with the vlan prefix length
    upper_tor_server_ip = "%s/%s" % (test_server_ip.split("/")[0], vlan_intf_prefixlen)
    lower_tor_server_ip = "%s/%s" % (test_server_ip.split("/")[0], vlan_intf_prefixlen)

    upper_tor_server_ipv6 = "%s/%s" % (test_server_ipv6.split("/")[0], vlan_intf_prefixlen_ipv6)
    lower_tor_server_ipv6 = "%s/%s" % (test_server_ipv6.split("/")[0], vlan_intf_prefixlen_ipv6)

    # find ToRs' ASNs
    upper_tor_asn = upper_tor_mg_facts["minigraph_bgp_asn"]
    lower_tor_asn = lower_tor_mg_facts["minigraph_bgp_asn"]
    assert upper_tor_asn == lower_tor_asn, (
        "Mismatch in BGP ASN between upper and lower ToR.\n"
        "- Upper ToR ASN: {}\n"
        "- Lower ToR ASN: {}"
    ).format(upper_tor_asn, lower_tor_asn)

    upper_tor_slb_asn = upper_tor_host.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \
                                             \"constants.deployment_id_asn_map[DEVICE_METADATA[\
                                             'localhost']['deployment_id']]\"")["stdout"]
    lower_tor_slb_asn = lower_tor_host.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \
                                             \"constants.deployment_id_asn_map[DEVICE_METADATA[\
                                             'localhost']['deployment_id']]\"")["stdout"]

    connections = {
        "upper_tor": {
            "localhost": upper_tor_host,
            "local_intf": test_device_interface,
            "local_addr": upper_tor_intf_addr,
            "local_asn": upper_tor_asn,
            "test_intf": test_iface,
            "neighbor_intf": upper_tor_server_ptf_intf,
            "neighbor_addr": upper_tor_server_ip,
            "neighbor_addr_ipv6": upper_tor_server_ipv6,
            "neighbor_asn": upper_tor_slb_asn,
            "exabgp_port": EXABGP_PORT_UPPER_TOR,
        },
        "lower_tor": {
            "localhost": lower_tor_host,
            "local_intf": test_device_interface,
            "local_addr": lower_tor_intf_addr,
            "local_asn": lower_tor_asn,
            "test_intf": test_iface,
            "neighbor_intf": lower_tor_server_ptf_intf,
            "neighbor_addr": lower_tor_server_ip,
            "neighbor_addr_ipv6": lower_tor_server_ipv6,
            "neighbor_asn": lower_tor_slb_asn,
            "exabgp_port": EXABGP_PORT_LOWER_TOR,
        }
    }

    try:
        ptfhost.shell("ifconfig %s %s" % (upper_tor_server_ptf_intf, upper_tor_server_ip))
        for conn in list(connections.values()):
            ptfhost.shell(
                "ip route show %s | grep -q '%s' || ip route add %s via %s" %
                (conn["local_addr"], vlan_intf_addr, conn["local_addr"], vlan_intf_addr)
            )
        yield connections
    finally:
        upper_tor_host.shell("show arp")
        lower_tor_host.shell("show arp")
        ptfhost.shell("ip route show")
        for conn in list(connections.values()):
            ptfhost.shell("ifconfig %s 0.0.0.0" % conn["neighbor_intf"], module_ignore_errors=True)
            ptfhost.shell("ip route del %s" % conn["local_addr"], module_ignore_errors=True)


@pytest.fixture(scope="module")
def bgp_neighbors(ptfhost, setup_interfaces):
    """Build the bgp neighbor objects used to start new bgp sessions."""
    # allow ebgp neighbors that are multiple hops away
    connections = setup_interfaces
    neighbors = {}
    for dut, conn in list(connections.items()):
        neighbors[dut] = bgp.BGPNeighbor(
            conn["localhost"],
            ptfhost,
            "slb_%s" % dut,
            conn["neighbor_addr"].split("/")[0],
            conn["neighbor_asn"],
            conn["local_addr"].split("/")[0],
            conn["local_asn"],
            conn["exabgp_port"],
            is_passive=True,
            debug=True
        )
    return neighbors


def pytest_configure(config):

    config.addinivalue_line(
        "markers", "enable_active_active: mark test to run with 'active_active' ports"
    )

    config.addinivalue_line(
        "markers", "skip_active_standby: mark test to skip running with 'active_standby' ports"
    )
