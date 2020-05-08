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
import pytest
from natsort import natsorted

import ptf.testutils as testutils
from netaddr import IPNetwork

import configurable_drop_counters as cdc
from mock_server import MockServer
from common.helpers.assertions import pytest_assert

PACKET_COUNT = 1000

@pytest.mark.parametrize("drop_reason", ["L3_EGRESS_LINK_DOWN"])
def test_neighbor_link_down(testbed_params, setup_counters, duthost, mock_server, test_runner,
                            drop_reason):
    """
    Verifies that counters that check for a neighbor link being down work properly.

    Note:
        This test works by mocking a server within a VLAN, thus the T0 topology is required.

    Args:
        drop_reason (str): The drop reason being tested.
    """
    counter_type = setup_counters([drop_reason])

    rx_port = random.choice([intf
                             for intf in testbed_params["ports"]
                             if intf != mock_server.get_neighbor_iface()])
    pkt = _get_simple_ip_packet(duthost, rx_port, "2.2.2.2", mock_server.get_addr())

    try:
        mock_server.start()
        mock_server.shutdown_link()
        test_runner(counter_type, pkt, rx_port)
    finally:
        mock_server.startup_link()
        mock_server.shutdown()
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")

@pytest.fixture(scope="module")
def testbed_params(duthost, testbed):
    """
    Gathers parameters about the testbed for the test cases to use.

    Returns: A Dictionary with the following information:
        "ports": A List of the active ports in the system
        "phy_intfs": A List of ALL physical interfaces in the system
        "vlan_intfs": A Dictionary containing all the VLAN interfaces in the system, including
            their address, subnet, prefix length, and VLAN members.
    """

    if testbed["topo"]["name"] != "t0":
        pytest.skip("Unsupported topology {}".format(testbed["topo"]["name"]))

    minigraph_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]

    active_ports = natsorted(minigraph_facts["minigraph_ports"].keys())

    physical_interfaces = natsorted(minigraph_facts["minigraph_port_name_to_alias_map"].keys())

    vlan_interfaces = {}
    for vlan_intf in minigraph_facts["minigraph_vlan_interfaces"]:
        intf_name = vlan_intf["attachto"]
        vlan_interfaces[intf_name] = {
            "addr": vlan_intf["addr"],
            "subnet": vlan_intf["subnet"],
            "prefix_len": vlan_intf["prefixlen"],
            "members": minigraph_facts["minigraph_vlans"][intf_name]["members"]
        }

    return {
        "ports": active_ports,
        "phy_intfs": physical_interfaces,
        "vlan_intfs": vlan_interfaces
    }

@pytest.fixture(scope="module")
def device_capabilities(duthost):
    """
    Gathers information about the DUT's drop counter capabilities.

    Returns:
        A Dictionary of device capabilities (see `get_device_capabilities` under the
        `configurable_drop_counters` package).
    """

    capabilities = cdc.get_device_capabilities(duthost)

    if not capabilities:
        pytest.fail("Error fetching device capabilities")

    return capabilities

@pytest.fixture(params=cdc.SUPPORTED_COUNTER_TYPES)
def setup_counters(request, device_capabilities, duthost):
    """
    Returns a method to setup drop counters.

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

        return counter_type

    yield _setup_counters

    try:
        cdc.delete_drop_counter(duthost, "TEST")
        time.sleep(1)
    except Exception:
        logging.info("Drop counter does not exist, skipping delete step...")

@pytest.fixture
def test_runner(duthost, ptfadapter, testbed_params):
    """
    Returns a method to run the drop counter tests.

    Returns:
        A method which, when called, will send traffic to the DUT and check if the proper
        drop counter has been incremented.
    """

    def _runner(counter_type, pkt, rx_port):
        duthost.command("sonic-clear dropcounters")

        ptf_tx_port_id = testbed_params["phy_intfs"].index(rx_port)
        _send_packets(duthost, ptfadapter, pkt, ptf_tx_port_id)
        time.sleep(3)

        recv_count = cdc.get_drop_counts(duthost, counter_type, "TEST", rx_port)

        pytest_assert(recv_count == PACKET_COUNT,
                      "Expected {} drops, received {}".format(PACKET_COUNT, recv_count))

    return _runner

@pytest.fixture
def mock_server(ptfhost, fanouthosts, testbed_params):
    """
    Mocks the presence of a server beneath a T0.

    Returns:
        A MockServer which will allow the caller to mock the behavior of a server within
        a VLAN under a T0.
    """

    if not testbed_params["vlan_intfs"]:
        pytest.skip("No VLANs available to mock a server under T0")

    # Randomly pick one of the VLANs beneath the T0.
    vlan = testbed_params["vlan_intfs"][random.choice(list(testbed_params["vlan_intfs"]))]

    # Generate a dummy IP that falls under the VLAN subnet. Make sure it isn't
    # the same as the VLAN interface IP!
    server_ip = vlan["addr"]
    while server_ip == vlan["addr"]:
        server_ip = random.choice(list(IPNetwork(vlan["subnet"])))

    # Randomly pick one of the interfaces in the VLAN to be connected to the server.
    outbound_dut_intf = random.choice(vlan["members"])
    outbound_port = testbed_params["phy_intfs"].index(outbound_dut_intf)

    return MockServer(server_ip, vlan["prefix_len"], vlan["addr"], outbound_dut_intf,
                      outbound_port, ptfhost, fanouthosts)

def _get_simple_ip_packet(duthost, dst_port, src_ip, dst_ip):
    pkt = testutils.simple_ip_packet(
        eth_dst=duthost.get_dut_iface_mac(dst_port),
        eth_src="00:de:ad:be:ef:00",
        ip_src=src_ip,
        ip_dst=dst_ip
    )

    return pkt

def _send_packets(duthost, ptfadapter, pkt, ptf_tx_port_id):
    duthost.command("sonic-clear dropcounters")

    ptfadapter.dataplane.flush()
    time.sleep(1)

    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=PACKET_COUNT)
    time.sleep(1)
