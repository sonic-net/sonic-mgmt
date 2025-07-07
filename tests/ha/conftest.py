import pytest
from common.ha.smartswitch_ha_helper import PtfTcpTestAdapter
from common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest
from common.ha.smartswitch_ha_helper import (
    add_port_to_namespace,
    remove_namespace,
    add_static_route_to_ptf,
    add_static_route_to_dut
)


@pytest.fixture(scope="module")
def copy_files(ptfhost):
    ptfhost.copy(src="/data/tests/ha/tcp_server.py", dest='/root')
    ptfhost.copy(src="/data/tests/ha/tcp_client.py", dest='/root')


@pytest.fixture(scope='module')
def tcp_adapter(ptfadapter):
    return PtfTcpTestAdapter(ptfadapter)


@pytest.fixture(scope="module")
def setup_SmartSwitchHaTrafficTest(duthost, ptfhost, ptfadapter, vmhost, tbinfo):
    activehost = duthost
    standbyhost = duthost
    io_ready = None

    ha_io = SmartSwitchHaTrafficTest(activehost, standbyhost, ptfhost,
                                     ptfadapter, vmhost, tbinfo, io_ready, namespace="ns1")
    return ha_io


@pytest.fixture(scope="module")
def setup_namespaces_with_routes(ptfhost, duthosts):
    """
    Set up 4 PTF namespaces (ns1, ns2, ns3, ns4), assign interfaces from both DUTs,
    configure IPs, static routes on PTF & DUTs, and clean up after the module.

    Each DUT port goes into a unique namespace for full isolation.
    """

    # Namespace and interface mapping
    ns_ifaces = [
        {"namespace": "ns1", "iface": "eth3", "ip": "172.16.1.1/24", "dut": duthosts[0], "next_hop": "172.16.1.254"},
        {"namespace": "ns2", "iface": "eth4", "ip": "172.16.2.1/24", "dut": duthosts[0], "next_hop": "172.16.2.254"},
        {"namespace": "ns3", "iface": "eth22", "ip": "172.16.3.1/24", "dut": duthosts[1], "next_hop": "172.16.3.254"},
        {"namespace": "ns4", "iface": "eth23", "ip": "172.16.4.1/24", "dut": duthosts[1], "next_hop": "172.16.4.254"},
    ]

    # Step 1: Setup namespaces and assign PTF interfaces
    for ns in ns_ifaces:
        add_port_to_namespace(ptfhost, ns["namespace"], ns["iface"], ns["ip"])

    # Step 2: Add static routes in each namespace to reach DUT-side networks
    for ns in ns_ifaces:
        # Example route: 192.168.X.0/24 → DUT next hop
        add_static_route_to_ptf(
            ptfhost,
            "192.168.{}.0/24".format(ns["namespace"][-1]),
            ns["next_hop"],
            name_of_namespace=ns["namespace"]
        )

    # Step 3: Add static routes on DUTs to reach all 192.168.0.0/16 networks via PTF interfaces
    for ns in ns_ifaces:
        add_static_route_to_dut(ns["dut"], "192.168.0.0/16", ns["ip"].split('/')[0])  # Use IP w/o mask

    yield

    # Cleanup
    for ns in ns_ifaces:
        remove_namespace(ptfhost, ns["namespace"], ns["iface"], ns["ip"])
