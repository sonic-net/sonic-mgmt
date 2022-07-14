"""
Tests the functionality of the configurable drop counter feature in SONiC.

Todo:
    - Add test cases for ACL_ANY and UNRESOLVED_NEXT_HOP
    - Add test cases for dynamic add/remove of drop reasons
    - Add test cases with multiple drop counters
    - Verify standard drop counters as well as configurable drop counters
"""

import logging
import random
import time
import json
import tempfile
import re
from collections import defaultdict

import pytest
import ptf.testutils as testutils
from netaddr import IPNetwork, EUI

import configurable_drop_counters as cdc
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # lgtm[py/unused-import]
from tests.common.utilities import is_ipv4_address
from tests.common import constants
from tests.common import config_reload


pytestmark = [
    pytest.mark.topology('any')
]

PACKET_COUNT = 1000

VLAN_INDEX = 0
VLAN_HOSTS = 100
VLAN_BASE_MAC_PATTERN = "72060001{:04}"

MOCK_DEST_IP = "2.2.2.2"
LINK_LOCAL_IP = "169.254.0.1"

# For dualtor
@pytest.fixture(scope='module')
def vlan_mac(duthost):
    config_facts = duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']
    dut_vlan_mac = None
    for vlan in config_facts.get('VLAN', {}).values():
        if 'mac' in vlan:
            logging.debug('Found VLAN mac')
            dut_vlan_mac = vlan['mac']
            break
    if not dut_vlan_mac:
        logging.debug('No VLAN mac, use default router_mac')
        dut_vlan_mac = duthost.facts['router_mac']
    return dut_vlan_mac


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(duthosts, rand_one_dut_hostname, loganalyzer):
    if loganalyzer:
        ignore_regex_list = [
            ".*ERR swss[0-9]*#orchagent.*meta_sai_validate_fdb_entry.*object key SAI_OBJECT_TYPE_FDB_ENTRY.*doesn't exist.*",
            ".*ERR swss[0-9]*#orchagent.*removeFdbEntry: FdbOrch RemoveFDBEntry: Failed to remove FDB entry. mac=.*, bv_id=.*",
            ".*ERR swss[0-9]*#orchagent.*handleSaiRemoveStatus: Encountered failure in remove operation, exiting orchagent, SAI API: SAI_API_FDB, status: SAI_STATUS_INVALID_PARAMETER.*",
            ".*ERR syncd[0-9]*#syncd.*SAI_API_DEBUG_COUNTER:_brcm_sai_debug_counter_value_get.*No debug_counter at index.*found.*",
            ".*ERR syncd[0-9]*#syncd.*collectPortDebugCounters: Failed to get stats of port.*"
        ]
        duthost = duthosts[rand_one_dut_hostname]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_list)


def apply_fdb_config(duthost, vlan_id, iface, mac_address, op, type):
    """ Generate FDB config file to apply it using 'swssconfig' tool.
    Generated config file template:
    [
        {
            "FDB_TABLE:[vlan_id]:XX-XX-XX-XX-XX-XX": {
                "port": "Ethernet0",
                "type": "static"
            },
            "OP": "SET"
        }
    ]
    """
    dut_fdb_config = "/tmp/fdb.json"
    fdb_config_json = []
    entry_key_template = "FDB_TABLE:{vid}:{mac}"

    fdb_entry_json = {entry_key_template.format(vid=vlan_id, mac=mac_address):
        {"port": iface, "type": type},
        "OP": op
    }
    fdb_config_json.append(fdb_entry_json)

    with tempfile.NamedTemporaryFile(suffix=".json", prefix="fdb_config") as fp:
        logging.info("Generating FDB config: {}".format(fdb_config_json))
        json.dump(fdb_config_json, fp)
        fp.flush()

        # Copy FDB JSON config to switch
        duthost.template(src=fp.name, dest=dut_fdb_config, force=True)

    # Copy FDB JSON config to SWSS container
    cmd = "docker cp {} swss:/".format(dut_fdb_config)
    duthost.command(cmd)

    # Set FDB entry
    cmd = "docker exec -i swss swssconfig /fdb.json"
    duthost.command(cmd)
    time.sleep(3)

    cmd = "docker exec -i swss rm -f /fdb.json"
    duthost.command(cmd)
    time.sleep(5)

def verifyFdbArp(duthost, dst_ip, dst_mac, dst_intf):
    """
    Check if the ARP and FDB entry is present
    """
    logging.info("Verify if the ARP and FDB entry is present for {}".format(dst_ip))
    result = duthost.command("show arp {}".format(dst_ip))
    pytest_assert("Total number of entries 1" in result['stdout'],
                  "ARP entry for {} missing in ASIC".format(dst_ip))
    result = duthost.shell("ip neigh show {}".format(dst_ip))
    pytest_assert(result['stdout_lines'], "{} not in arp table".format(dst_ip))
    match = re.match("{}.*lladdr\s+(.*)\s+[A-Z]+".format(dst_ip),
                     result['stdout_lines'][0])
    pytest_assert(match,
                  "Regex failed while retrieving arp entry for {}".format(dst_ip))
    pytest_assert(match.group(1).replace(":", "-") == dst_mac,
                  "ARP entry's lladdr is changed from {} to {}".format(dst_mac, match.group(1).replace(":", "-")))

    fdb_count = int(duthost.shell("show mac | grep {} | grep {} | wc -l".format(match.group(1), dst_intf))["stdout"])
    pytest_assert(fdb_count == 1, "FDB entry doesn't exist for {}, fdb_count is {}".format(dst_mac, fdb_count))

@pytest.mark.parametrize("drop_reason", ["L3_EGRESS_LINK_DOWN"])
def test_neighbor_link_down(testbed_params, setup_counters, duthosts, rand_one_dut_hostname, toggle_all_simulator_ports_to_rand_selected_tor_m, mock_server,
                            send_dropped_traffic, drop_reason, generate_dropped_packet, tbinfo):
    """
    Verifies counters that check for a neighbor link being down.

    Note:
        This test works by mocking a server within a VLAN, thus the T0
        topology is required.

    Args:
        drop_reason (str): The drop reason being tested.
    """
    duthost = duthosts[rand_one_dut_hostname]
    counter_type = setup_counters([drop_reason])

    rx_port = random.choice([port
                             for port in testbed_params["physical_port_map"].keys()
                             if port != mock_server["server_dst_port"]])
    logging.info("Selected port %s to send traffic", rx_port)

    src_ip = MOCK_DEST_IP
    pkt = generate_dropped_packet(rx_port, src_ip, mock_server["server_dst_addr"])

    try:
        # Add a static fdb entry
        apply_fdb_config(duthost, testbed_params['vlan_interface']['attachto'],
                            mock_server['server_dst_intf'], mock_server['server_dst_mac'],
                            "SET", "static")
        mock_server["fanout_neighbor"].shutdown(mock_server["fanout_intf"])
        time.sleep(3)
        verifyFdbArp(duthost, mock_server['server_dst_addr'], mock_server['server_dst_mac'], mock_server['server_dst_intf'])
        send_dropped_traffic(counter_type, pkt, rx_port)
    finally:
        mock_server["fanout_neighbor"].no_shutdown(mock_server["fanout_intf"])
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")
        # Delete the static fdb entry
        apply_fdb_config(duthost, testbed_params['vlan_interface']['attachto'],
                            mock_server['server_dst_intf'], mock_server['server_dst_mac'],
                            "DEL", "static")
        # FIXME: Add config reload on t0-backend as a workaround to keep DUT healthy because the following
        # drop packet testcases will suffer from the brcm_sai_get_port_stats errors flooded in syslog
        if "backend" in tbinfo["topo"]["name"]:
            config_reload(duthost, safe_reload=True)


@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_dip_link_local(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,
                        send_dropped_traffic, drop_reason, add_default_route_to_dut, generate_dropped_packet):
    """
    Verifies counters that check for link local dst IP.

    Args:
        drop_reason (str): The drop reason being tested.
    """
    duthost = duthosts[rand_one_dut_hostname]
    counter_type = setup_counters([drop_reason])

    rx_port = random.choice(testbed_params["physical_port_map"].keys())
    logging.info("Selected port %s to send traffic", rx_port)

    src_ip = "10.10.10.10"
    pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

    try:
        send_dropped_traffic(counter_type, pkt, rx_port)
    finally:
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.parametrize("drop_reason", ["SIP_LINK_LOCAL"])
def test_sip_link_local(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,
                        send_dropped_traffic, drop_reason, add_default_route_to_dut, generate_dropped_packet):
    """
    Verifies counters that check for link local src IP.

    Args:
        drop_reason (str): The drop reason being tested.
    """
    duthost = duthosts[rand_one_dut_hostname]
    counter_type = setup_counters([drop_reason])

    rx_port = random.choice(testbed_params["physical_port_map"].keys())
    logging.info("Selected port %s to send traffic", rx_port)

    dst_ip = "10.10.10.10"
    pkt = generate_dropped_packet(rx_port, LINK_LOCAL_IP, dst_ip)

    try:
        send_dropped_traffic(counter_type, pkt, rx_port)
    finally:
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.fixture
def add_default_route_to_dut(duts_running_config_facts, duthosts, tbinfo):
    """
    Add a default route to the device for storage backend testbed.
    This is to ensure the packet sent in test_sip_link_local and test_dip_link_local
    are routable on the device.
    """
    if "backend" in tbinfo["topo"]["name"]:
        logging.info("Add default route on the DUT.")
        try:
            for duthost in duthosts:
                cfg_facts = duts_running_config_facts[duthost.hostname]
                for asic_index, asic_cfg_facts in enumerate(cfg_facts):
                    asic = duthost.asic_instance(asic_index)
                    bgp_neighbors = asic_cfg_facts["BGP_NEIGHBOR"]
                    ipv4_cmd_parts = ["ip route add default"]
                    for neighbor in bgp_neighbors.keys():
                        if is_ipv4_address(neighbor):
                            ipv4_cmd_parts.append("nexthop via %s" % neighbor)
                    ipv4_cmd_parts.sort()
                    ipv4_cmd = " ".join(ipv4_cmd_parts)
                    asic.shell(ipv4_cmd)
            yield
        finally:
            logging.info("Remove default route on the DUT.")
            for duthost in duthosts:
                for asic in duthost.asics:
                    if asic.is_it_backend():
                        continue
                    asic.shell("ip route del default", module_ignore_errors=True)
    else:
        yield


@pytest.fixture(scope="module")
def testbed_params(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Gathers parameters about the testbed for the test cases to use.

    Returns: A Dictionary with the following information:
    """
    duthost = duthosts[rand_one_dut_hostname]
    if tbinfo["topo"]["type"] != "t0":
        pytest.skip("Unsupported topology {}".format(tbinfo["topo"]["name"]))

    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)

    physical_port_map = {v: k
                         for k, v
                         in mgFacts["minigraph_ptf_indices"].items()
                         if k in mgFacts["minigraph_ports"].keys()}  # Trim inactive ports

    vlan_ports = [mgFacts["minigraph_ptf_indices"][ifname]
                  for ifname
                  in mgFacts["minigraph_vlans"].values()[VLAN_INDEX]["members"]]

    vlan_interface = mgFacts["minigraph_vlan_interfaces"][VLAN_INDEX].copy()
    vlan_interface["type"] = mgFacts["minigraph_vlans"].values()[VLAN_INDEX].get("type", "untagged").lower()

    return {"physical_port_map": physical_port_map,
            "vlan_ports": vlan_ports,
            "vlan_interface": vlan_interface}


@pytest.fixture(scope="module")
def device_capabilities(duthosts, rand_one_dut_hostname):
    """
    Gather information about the DUT's drop counter capabilities.

    Returns:
        A Dictionary of device capabilities (see `get_device_capabilities` under the
        `configurable_drop_counters` package).

    """
    duthost = duthosts[rand_one_dut_hostname]
    capabilities = cdc.get_device_capabilities(duthost)

    pytest_assert(capabilities, "Error fetching device capabilities")

    logging.info("Retrieved drop counter capabilities: %s", capabilities)
    return capabilities


@pytest.fixture(params=cdc.SUPPORTED_COUNTER_TYPES)
def setup_counters(request, device_capabilities, duthosts, rand_one_dut_hostname):
    """
    Return a method to setup drop counters.

    Notes:
        This fixture will automatically clean-up created drop counters.

    Returns:
        A method which, when called, will create a drop counter with the specified drop reasons.

    """
    duthost = duthosts[rand_one_dut_hostname]
    if request.param not in device_capabilities["counters"]:
        pytest.skip("Counter type not supported on target DUT")

    counter_type = request.param
    supported_reasons = device_capabilities["reasons"][counter_type]

    def _setup_counters(drop_reasons):
        if any(reason not in supported_reasons for reason in drop_reasons):
            pytest.skip("Drop reasons not supported on target DUT")

        cdc.create_drop_counter(duthost, "TEST", counter_type, drop_reasons)
        time.sleep(1)

        logging.info("Created counter TEST: type = %s, drop reasons = %s",
                     counter_type, drop_reasons)
        return counter_type

    yield _setup_counters

    try:
        cdc.delete_drop_counter(duthost, "TEST")
        time.sleep(1)
        logging.info("Deleted counter TEST")
    except Exception:
        logging.info("Drop counter does not exist, skipping delete step...")


@pytest.fixture
def send_dropped_traffic(duthosts, rand_one_dut_hostname, ptfadapter, testbed_params):
    """
    Return a method to send traffic to the DUT to be dropped.

    Returns:
        A method which, when called, will send traffic to the DUT and check if the proper
        drop counter has been incremented.

    """
    duthost = duthosts[rand_one_dut_hostname]
    def _runner(counter_type, pkt, rx_port):
        duthost.command("sonic-clear dropcounters")

        logging.info("Sending traffic from ptf on port %s", rx_port)
        _send_packets(duthost, ptfadapter, pkt, rx_port)

        def _check_drops():
            dst_port = testbed_params["physical_port_map"][rx_port]
            recv_count = cdc.get_drop_counts(duthost,
                                             counter_type,
                                             "TEST",
                                             dst_port)
            logging.info("Received %s drops on port %s, expected %s",
                         recv_count, dst_port, PACKET_COUNT)
            return recv_count == PACKET_COUNT

        pytest_assert(wait_until(10, 2, 0, _check_drops), "Expected {} drops".format(PACKET_COUNT))

    return _runner


@pytest.fixture
def arp_responder(ptfhost, testbed_params, tbinfo):
    """Set up the ARP responder utility in the PTF container."""
    vlan_network = testbed_params["vlan_interface"]["subnet"]
    is_storage_backend = "backend" in tbinfo["topo"]["name"]

    logging.info("Generating simulated servers under VLAN network %s", vlan_network)
    vlan_host_map = _generate_vlan_servers(vlan_network, testbed_params["vlan_ports"])

    logging.info("Generating ARP responder topology")
    if is_storage_backend:
        vlan_id = testbed_params["vlan_interface"]["attachto"].lstrip("Vlan")
        arp_responder_conf = {"eth%s%s%s" % (k, constants.VLAN_SUB_INTERFACE_SEPARATOR, vlan_id): v for k, v in vlan_host_map.items()}
    else:
        arp_responder_conf = {"eth%s" % k: v for k, v in vlan_host_map.items()}

    logging.info("Copying ARP responder topology to PTF")
    with open("/tmp/from_t1.json", "w") as ar_config:
        json.dump(arp_responder_conf, ar_config)
    ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")

    logging.info("Copying ARP responder to PTF container")

    logging.info("Copying ARP responder config file")
    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": "-e"})
    ptfhost.template(src="templates/arp_responder.conf.j2",
                     dest="/etc/supervisor/conf.d/arp_responder.conf")

    logging.info("Refreshing supervisor and starting ARP responder")
    ptfhost.shell("supervisorctl reread && supervisorctl update")
    ptfhost.shell("supervisorctl restart arp_responder")

    yield vlan_host_map

    logging.info("Stopping ARP responder")
    ptfhost.shell("supervisorctl stop arp_responder")


@pytest.fixture
def mock_server(fanouthosts, testbed_params, arp_responder, ptfadapter, duthosts, rand_one_dut_hostname):
    """
    Mock the presence of a server beneath a T0.

    Returns:
        A MockServer which will allow the caller to mock the behavior of
        a server within a VLAN under a T0.

    """
    duthost = duthosts[rand_one_dut_hostname]
    server_dst_port = random.choice(arp_responder.keys())
    server_dst_addr = random.choice(arp_responder[server_dst_port].keys())
    server_dst_mac = str(EUI(arp_responder[server_dst_port].get(server_dst_addr)))
    server_dst_intf = testbed_params["physical_port_map"][server_dst_port]
    logging.info("Creating mock server with IP %s; dut port = %s, dut intf = %s",
                 server_dst_addr, server_dst_port, server_dst_intf)

    logging.info("Clearing ARP and FDB tables for test setup")
    duthost.command("sonic-clear fdb all")
    duthost.command("sonic-clear arp")

    # Populate FDB
    logging.info("Populating FDB and ARP entry for mock server under VLAN")
    # Issue a ping to populate ARP table on DUT
    duthost.command('ping %s -c 3' % server_dst_addr, module_ignore_errors=True)

    time.sleep(5)
    fanout_neighbor, fanout_intf = fanout_switch_port_lookup(fanouthosts, duthost.hostname, server_dst_intf)

    return {"server_dst_port": server_dst_port,
            "server_dst_addr": server_dst_addr,
            "server_dst_mac": server_dst_mac,
            "server_dst_intf": server_dst_intf,
            "fanout_neighbor": fanout_neighbor,
            "fanout_intf": fanout_intf}


@pytest.fixture
def generate_dropped_packet(duthosts, rand_one_dut_hostname, testbed_params, vlan_mac):

    def _get_simple_ip_packet(rx_port, src_ip, dst_ip):
        dst_mac = vlan_mac if rx_port in testbed_params["vlan_ports"] \
            else duthost.get_dut_iface_mac(testbed_params["physical_port_map"][rx_port])
        src_mac = "DE:AD:BE:EF:12:34"
        # send tagged packet for t0-backend whose vlan mode is tagged
        enable_vlan = rx_port in testbed_params["vlan_ports"] and testbed_params["vlan_interface"]["type"] == "tagged"
        packet_params = dict(
            eth_src=src_mac,
            eth_dst=dst_mac,
            ip_src=src_ip,
            ip_dst=dst_ip
        )
        if enable_vlan:
            packet_params["dl_vlan_enable"] = enable_vlan
            packet_params["vlan_vid"] = int(testbed_params["vlan_interface"]["attachto"].lstrip("Vlan"))
        pkt = testutils.simple_ip_packet(**packet_params)

        logging.info("Generated simple IP packet (SMAC=%s, DMAC=%s, SIP=%s, DIP=%s)",
                    src_mac, dst_mac, src_ip, dst_ip)

        return pkt

    duthost = duthosts[rand_one_dut_hostname]

    return _get_simple_ip_packet


def _generate_vlan_servers(vlan_network, vlan_ports):
    vlan_host_map = defaultdict(dict)

    # Each physical port maps to a set of IP address and their associated MAC addresses
    # - MACs are generated sequentially as offsets from VLAN_BASE_MAC_PATTERN
    # - IP addresses are randomly selected from the given VLAN network
    # - "Hosts" (IP/MAC pairs) are distributed evenly amongst the ports in the VLAN
    addr_list = list(IPNetwork(vlan_network))
    for counter, i in enumerate(xrange(2, VLAN_HOSTS + 2)):
        mac = VLAN_BASE_MAC_PATTERN.format(counter)
        port = vlan_ports[i % len(vlan_ports)]
        addr = random.choice(addr_list)
        # Ensure that we won't get a duplicate ip address
        addr_list.remove(addr)

        vlan_host_map[port][str(addr)] = mac

    return vlan_host_map


def _send_packets(duthost, ptfadapter, pkt, ptf_tx_port_id,
                  count=PACKET_COUNT):
    duthost.command("sonic-clear dropcounters")

    ptfadapter.dataplane.flush()
    time.sleep(1)

    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=count)
    time.sleep(1)
