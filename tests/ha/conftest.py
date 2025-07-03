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
def setup_namespaces_with_routes(ptfhost, duthost):
    """
    Set up PTF namespaces (ns1, ns2), assign interfaces (eth0, eth2), IPs,
    add static routes on both PTF and DUT, and clean up after module.
    """
    ns1 = "ns1"
    ns2 = "ns2"
    eth0 = "eth0"
    eth2 = "eth2"

    ip_eth0 = "172.16.1.1/24"
    ip_eth2 = "172.16.2.1/24"

    route_on_ptf_ns1 = {
        "network": "192.168.2.0/24",
        "next_hop": "172.16.1.254"
    }

    route_on_ptf_ns2 = {
        "network": "192.168.1.0/24",
        "next_hop": "172.16.2.254"
    }

    route_on_dut = {
        "network": "192.168.0.0/16",
        "next_hop": "172.16.1.1"
    }

    # Step 1–2: Setup namespaces and assign ports
    add_port_to_namespace(ptfhost, ns1, eth0, ip_eth0)
    add_port_to_namespace(ptfhost, ns2, eth2, ip_eth2)

    # Step 3: Add static routes on PTF (in namespaces)
    add_static_route_to_ptf(ptfhost, route_on_ptf_ns1["network"], route_on_ptf_ns1["next_hop"], name_of_namespace=ns1)
    add_static_route_to_ptf(ptfhost, route_on_ptf_ns2["network"], route_on_ptf_ns2["next_hop"], name_of_namespace=ns2)

    # Step 4: Add route to DUT
    add_static_route_to_dut(duthost, route_on_dut["network"], route_on_dut["next_hop"])

    yield

    # Cleanup
    remove_namespace(ptfhost, ns1, eth0, ip_eth0)
    remove_namespace(ptfhost, ns2, eth2, ip_eth2)
