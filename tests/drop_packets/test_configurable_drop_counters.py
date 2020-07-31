"""
Tests the functionality of the configurable drop counter feature in SONiC.

Todo:
    - Add test cases for ACL_ANY, SIP/DIP_LINK_LOCAL, and UNRESOLVED_NEXT_HOP
    - Add test cases for dynamic add/remove of drop reasons
    - Add test cases with multiple drop counters
    - Verify standard drop counters as well as configurable drop counters
"""

import logging
import random
import time
import json
from collections import defaultdict

import pytest
import ptf.testutils as testutils
from netaddr import IPNetwork

import configurable_drop_counters as cdc
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('any')
]

PACKET_COUNT = 1000

VLAN_INDEX = 0
VLAN_HOSTS = 100
VLAN_BASE_MAC_PATTERN = "72060001{:04}"

MOCK_DEST_IP = "2.2.2.2"

@pytest.mark.parametrize("drop_reason", ["L3_EGRESS_LINK_DOWN"])
def test_neighbor_link_down(testbed_params, setup_counters, duthost, mock_server,
                            send_dropped_traffic, drop_reason):
    """
    Verifies counters that check for a neighbor link being down.

    Note:
        This test works by mocking a server within a VLAN, thus the T0
        topology is required.

    Args:
        drop_reason (str): The drop reason being tested.
    """
    counter_type = setup_counters([drop_reason])

    rx_port = random.choice([port
                             for port in testbed_params["physical_port_map"].keys()
                             if port != mock_server["server_dst_port"]])
    rx_mac = duthost.get_dut_iface_mac(testbed_params["physical_port_map"][rx_port])
    logging.info("Selected port %s, mac = %s to send traffic", rx_port, rx_mac)

    src_mac = "DE:AD:BE:EF:12:34"
    src_ip = MOCK_DEST_IP
    pkt = _get_simple_ip_packet(src_mac, rx_mac, src_ip, mock_server["server_dst_addr"])

    try:
        mock_server["fanout_neighbor"].shutdown(mock_server["fanout_intf"])
        send_dropped_traffic(counter_type, pkt, rx_port)
    finally:
        mock_server["fanout_neighbor"].no_shutdown(mock_server["fanout_intf"])
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.fixture(scope="module")
def testbed_params(duthost, testbed):
    """
    Gathers parameters about the testbed for the test cases to use.

    Returns: A Dictionary with the following information:
    """
    if testbed["topo"]["type"] != "t0":
        pytest.skip("Unsupported topology {}".format(testbed["topo"]["name"]))

    minigraph_facts = \
        duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]

    physical_port_map = {v: k
                         for k, v
                         in minigraph_facts["minigraph_port_indices"].items()
                         if k in minigraph_facts["minigraph_ports"].keys()}  # Trim inactive ports

    vlan_ports = [minigraph_facts["minigraph_port_indices"][ifname]
                  for ifname
                  in minigraph_facts["minigraph_vlans"].values()[VLAN_INDEX]["members"]]

    return {"physical_port_map": physical_port_map,
            "vlan_ports": vlan_ports,
            "vlan_interface": minigraph_facts["minigraph_vlan_interfaces"][VLAN_INDEX]}


@pytest.fixture(scope="module")
def device_capabilities(duthost):
    """
    Gather information about the DUT's drop counter capabilities.

    Returns:
        A Dictionary of device capabilities (see `get_device_capabilities` under the
        `configurable_drop_counters` package).

    """
    capabilities = cdc.get_device_capabilities(duthost)

    pytest_assert(capabilities, "Error fetching device capabilities")

    logging.info("Retrieved drop counter capabilities: %s", capabilities)
    return capabilities


@pytest.fixture(params=cdc.SUPPORTED_COUNTER_TYPES)
def setup_counters(request, device_capabilities, duthost):
    """
    Return a method to setup drop counters.

    Notes:
        This fixture will automatically clean-up created drop counters.

    Returns:
        A method which, when called, will create a drop counter with the specified drop reasons.

    """
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
def send_dropped_traffic(duthost, ptfadapter, testbed_params):
    """
    Return a method to send traffic to the DUT to be dropped.

    Returns:
        A method which, when called, will send traffic to the DUT and check if the proper
        drop counter has been incremented.

    """
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

        pytest_assert(wait_until(5, 1, _check_drops), "Expected {} drops".format(PACKET_COUNT))

    return _runner


@pytest.fixture
def arp_responder(ptfhost, testbed_params):
    """Set up the ARP responder utility in the PTF container."""
    vlan_network = testbed_params["vlan_interface"]["subnet"]

    logging.info("Generating simulated servers under VLAN network %s", vlan_network)
    arp_responder_conf = {}
    vlan_host_map = _generate_vlan_servers(vlan_network, testbed_params["vlan_ports"])

    logging.info("Generating ARP responder topology")
    for port in vlan_host_map:
        arp_responder_conf['eth{}'.format(port)] = vlan_host_map[port]

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
def mock_server(fanouthosts, testbed_params, arp_responder, ptfadapter, duthost):
    """
    Mock the presence of a server beneath a T0.

    Returns:
        A MockServer which will allow the caller to mock the behavior of
        a server within a VLAN under a T0.

    """
    server_dst_port = random.choice(testbed_params["vlan_ports"])
    server_dst_addr = random.choice(arp_responder[server_dst_port].keys())
    server_dst_intf = testbed_params["physical_port_map"][server_dst_port]
    logging.info("Creating mock server with IP %s; dut port = %s, dut intf = %s",
                 server_dst_addr, server_dst_port, server_dst_intf)

    logging.info("Clearing ARP and FDB tables for test setup")
    duthost.command("sonic-clear fdb all")
    duthost.command("sonic-clear arp")

    # Populate FDB
    logging.info("Populating FDB entry for mock server under VLAN")
    src_mac = _hex_to_mac(arp_responder[server_dst_port][server_dst_addr])
    pkt = _get_simple_ip_packet(src_mac,
                                duthost.get_dut_iface_mac(server_dst_intf),
                                server_dst_addr,
                                MOCK_DEST_IP)
    _send_packets(duthost, ptfadapter, pkt, server_dst_port, count=100)

    fanout_neighbor, fanout_intf = fanout_switch_port_lookup(fanouthosts, server_dst_intf)

    return {"server_dst_port": server_dst_port,
            "server_dst_addr": server_dst_addr,
            "server_dst_intf": server_dst_intf,
            "fanout_neighbor": fanout_neighbor,
            "fanout_intf": fanout_intf}


def _generate_vlan_servers(vlan_network, vlan_ports):
    vlan_host_map = defaultdict(dict)

    # Each physical port maps to a set of IP address and their associated MAC addresses
    # - MACs are generated sequentially as offsets from VLAN_BASE_MAC_PATTERN
    # - IP addresses are randomly selected from the given VLAN network
    # - "Hosts" (IP/MAC pairs) are distributed evenly amongst the ports in the VLAN
    for counter, i in enumerate(xrange(2, VLAN_HOSTS + 2)):
        mac = VLAN_BASE_MAC_PATTERN.format(counter)
        port = vlan_ports[i % len(vlan_ports)]
        addr = str(random.choice(list(IPNetwork(vlan_network))))

        vlan_host_map[port][addr] = mac

    return vlan_host_map


def _get_simple_ip_packet(src_mac, dst_mac, src_ip, dst_ip):
    pkt = testutils.simple_ip_packet(
        eth_src=src_mac,
        eth_dst=dst_mac,
        ip_src=src_ip,
        ip_dst=dst_ip
    )

    logging.info("Generated simple IP packet (SMAC=%s, DMAC=%s, SIP=%s, DIP=%s)",
                 src_mac, dst_mac, src_ip, dst_ip)

    return pkt


def _send_packets(duthost, ptfadapter, pkt, ptf_tx_port_id,
                  count=PACKET_COUNT):
    duthost.command("sonic-clear dropcounters")

    ptfadapter.dataplane.flush()
    time.sleep(1)

    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=count)
    time.sleep(1)


def _hex_to_mac(hex_mac):
    return ':'.join(hex_mac[i:i+2] for i in range(0, len(hex_mac), 2))
