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


def get_all_ptf_port_indices_from_mg_facts(mg_asic_facts):
    """
    Retrieve all PTF port indices from minigraph ASIC facts.

    Args:
        mg_asic_facts (list): List of (asic_index, asic_facts_dict) tuples.

    Returns:
        dict: {ptf_port_index: port_name}
    """
    all_port_indices = {}

    for asic_index, asic_facts in mg_asic_facts:
        ptf_indices = asic_facts.get('minigraph_ptf_indices', {})
        for port_name, port_index in ptf_indices.items():
            all_port_indices[port_index] = port_name

    return all_port_indices


def get_all_ptf_ports_from_all_duts(duts_minigraph_facts):
    combined_ports = {}
    for dut_hostname, mg_asic_facts_list in duts_minigraph_facts.items():
        dut_ports = get_all_ptf_port_indices_from_mg_facts(mg_asic_facts_list)
        for ptf_idx, port_name in dut_ports.items():
            combined_ports[ptf_idx] = (dut_hostname, port_name)  # Include DUT
    return combined_ports


@pytest.fixture(scope="module")
def setup_namespaces_with_routes(ptfhost, duthosts, duts_minigraph_facts):
    ns_ifaces = []

    # Get all PTF ports from all DUTs combined
    all_ports = get_all_ptf_ports_from_all_duts(duts_minigraph_facts)
    sorted_port_indices = sorted(all_ports.keys())

    # Example split ports arbitrarily for namespace assignment
    ns1_ports = sorted_port_indices[:2]
    ns2_ports = sorted_port_indices[-2:]

    for idx, port_idx in enumerate(ns1_ports, start=1):
        iface_name = f"eth{port_idx}"
        dut_name, _ = all_ports[port_idx]  # Unpack DUT name from all_ports
        ns_ifaces.append({
            "namespace": "ns1",
            "iface": iface_name,
            "ip": f"172.16.1.{idx}/24",
            "next_hop": "172.16.1.254",
            "dut": dut_name  # Add DUT for static route
        })

    for idx, port_idx in enumerate(ns2_ports, start=1):
        iface_name = f"eth{port_idx}"
        dut_name, _ = all_ports[port_idx]
        ns_ifaces.append({
            "namespace": "ns2",
            "iface": iface_name,
            "ip": f"172.16.2.{idx}/24",
            "next_hop": "172.16.2.254",
            "dut": dut_name  # Add DUT
        })

    # Setup namespaces and static routes
    for ns in ns_ifaces:
        add_port_to_namespace(ptfhost, ns["namespace"], ns["iface"], ns["ip"])
        add_static_route_to_ptf(
            ptfhost,
            f"192.168.{ns['namespace'][-1]}.0/24",
            ns["next_hop"],
            name_of_namespace=ns["namespace"]
        )
        # Add static route on DUT
        add_static_route_to_dut(
            duthosts[ns["dut"]], "192.168.0.0/16", ns["ip"].split('/')[0]
        )

    yield

    # Cleanup
    for ns in ns_ifaces:
        remove_namespace(ptfhost, ns["namespace"], ns["iface"], ns["ip"])
