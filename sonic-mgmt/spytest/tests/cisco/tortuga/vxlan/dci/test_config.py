import pytest
from spytest import st
from dci.const import DCI_CLIS, DCI_VLAN_VNI_MAPPING_DEL
from dci.config import configure_devices, configure_bgp, configure_sonic, run_clis_on_duts
from dci.send_and_verify_traffic import send_ping_and_verify_traffic
from dci.sonic_verifiers import verify_dci_remotevtep, verify_dci_remotemac
from dci.frr_verifiers import (
    verify_type_5_routes_are_not_reoriginated,
    verify_type_4_routes_are_not_reoriginated,
    verify_type_1_routes_are_not_reoriginated,
)
from dci.expected_results_frr import no_reorigination_routes
import apis.system.interface as intf_api


def test_deconfigure_reconfigure_devices(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_devices(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_devices deconfigure")
    if not configure_devices(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_devices reconfigure")
    st.wait(60)
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        verify_type_5_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_4_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_1_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_devices")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_devices")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_devices")


def test_deconfigure_reconfigure_dc1gw2(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    dci_node = {"dc1gw2": nodes["dc1gw2"]}
    if not configure_devices(config_file, dci_node, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dc1gw2 deconfigure")
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    if not configure_devices(config_file, dci_node, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dc1gw2 reconfigure")
    st.wait(60)
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        verify_type_5_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_4_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_1_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_dc1gw2")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_dc1gw2")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_dc1gw2")


def test_deconfigure_reconfigure_sonic(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_sonic(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_sonic deconfigure")
    if not configure_sonic(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_sonic reconfigure")
    # this is needed for MIGSOFTWAR-30415
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        st.vtysh_show(nodes[node_name], "clear bgp *", skip_error_check=True, skip_tmpl=True)
    st.wait(120)
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        verify_type_5_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_4_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_1_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_sonic")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_sonic")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_sonic")


def test_deconfigure_reconfigure_bgp(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_bgp(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_bgp deconfigure")
    if not configure_bgp(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_bgp reconfigure")
    st.wait(180)
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        verify_type_5_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_4_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_1_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_bgp")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_bgp")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_bgp")


def test_deconfigure_reconfigure_dci_config(setup):
    nodes = setup["nodes"]

    config = DCI_CLIS.copy()
    # BGP ASN mapping for each DCI gateway node
    bgp_asn_mapping = {"dc1gw1": "65001", "dc1gw2": "65002", "dc2gw1": "65003", "dc3gw1": "65004"}

    # Deconfigure DCI configuration on all gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        duts_config.append((nodes[node_name], [f"router bgp {bgp_asn_mapping[node_name]}"] + config["del"]))

    if not run_clis_on_duts(duts_config, is_bgp=True):
        st.report_fail(
            "test_case_failed",
            f"test_deconfigure_reconfigure_dci_config deconfigure on {[config[0] for config in duts_config]}",
        )
    st.wait(10)

    # Reconfigure DCI configuration on all gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        duts_config.append((nodes[node_name], [f"router bgp {bgp_asn_mapping[node_name]}"] + config["add"]))

    if not run_clis_on_duts(duts_config, is_bgp=True):
        st.report_fail(
            "test_case_failed",
            f"test_deconfigure_reconfigure_dci_config reconfigure on {[config[0] for config in duts_config]}",
        )
    st.wait(180)
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        verify_type_5_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_4_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_1_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
    # Verify VXLAN remote VTEP and MAC configurations after reconfiguration
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_dci_config")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_dci_config")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_dci_config")


def test_deconfigure_reconfigure_dci_nodes(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    dci_nodes = {
        "dc1gw1": nodes["dc1gw1"],
        "dc1gw2": nodes["dc1gw2"],
        "dc2gw1": nodes["dc2gw1"],
        "dc3gw1": nodes["dc3gw1"],
    }
    if not configure_devices(config_file, dci_nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dci_nodes deconfigure")
    if not configure_devices(config_file, dci_nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dci_nodes reconfigure")
    st.wait(180)
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        verify_type_5_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_4_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
        verify_type_1_routes_are_not_reoriginated(nodes[node_name], no_reorigination_routes[node_name])
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_dci_nodes")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_dci_nodes")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_dci_nodes")


def test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes(setup):
    nodes = setup["nodes"]

    # Deconfigure VLAN-VNI mappings on all DCI gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if node_name in DCI_VLAN_VNI_MAPPING_DEL:
            duts_config.append((nodes[node_name], DCI_VLAN_VNI_MAPPING_DEL[node_name]["del"]))

    if not run_clis_on_duts(duts_config):
        st.report_fail(
            "test_case_failed",
            f"test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes deconfigure on {[config[0] for config in duts_config]}",
        )
    st.wait(60)

    # Reconfigure VLAN-VNI mappings on all DCI gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if node_name in DCI_VLAN_VNI_MAPPING_DEL:
            duts_config.append((nodes[node_name], DCI_VLAN_VNI_MAPPING_DEL[node_name]["add"]))

    if not run_clis_on_duts(duts_config):
        st.report_fail(
            "test_case_failed",
            f"test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes reconfigure on {[config[0] for config in duts_config]}",
        )
    st.wait(60)

    # Verify VXLAN remote VTEP and MAC configurations after reconfiguration
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes")
    if setup["use_ubuntu_hosts"]:
        # Initiate mac learning by sending traffic from hosts to their respective leafs
        send_ping_and_verify_traffic(
            st.getwa(),
            setup["ping_anycast"],
            use_ubuntu_hosts=True,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    if not send_ping_and_verify_traffic(
        st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
    ):
        st.report_fail("test_case_failed", "Ping test failed after VLAN-VNI mapping reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes")


"""
Currently we only test link failures within DCI only.
WAN side link failures are not supported and behavior is unknown
"""


def test_single_link_failures(setup):
    """
    Test single link failures between DC1 gateways (dc1gw1, dc1gw2) and leaf nodes (leaf1, leaf2).
    Verifies traffic continues to work from DC2/DC3 hosts to DC1 hosts during link failures.

    Single link failure scenarios using DxDyPz notation:
    - D1D5P1: dc1gw1 (D1) to leaf1 (D5) link 1
    - D1D6P1: dc1gw1 (D1) to leaf2 (D6) link 1
    - D2D5P1: dc1gw2 (D2) to leaf1 (D5) link 1
    - D2D6P1: dc1gw2 (D2) to leaf2 (D6) link 1
    """

    nodes = setup["nodes"]
    ports = setup["ports"]

    # Define traffic pairs from DC2/DC3 hosts to DC1 hosts
    # These specific pairs should continue working even with single link failures
    traffic_pairs = [
        ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host1"], "ip": "10.212.10.1"}),
        ({"name": nodes["host3"], "ip": "10.212.20.3"}, {"name": nodes["host1"], "ip": "10.212.20.1"}),
        ({"name": nodes["host4"], "ip": "10.212.10.4"}, {"name": nodes["host1"], "ip": "10.212.10.1"}),
        ({"name": nodes["host4"], "ip": "10.212.20.4"}, {"name": nodes["host1"], "ip": "10.212.20.1"}),
        ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host2"], "ip": "10.212.10.2"}),
        ({"name": nodes["host4"], "ip": "10.212.10.4"}, {"name": nodes["host2"], "ip": "10.212.10.2"}),
    ]

    # Define link failure test cases using DxDyPz notation from conftest
    # Format: (gateway_node, gateway_name, leaf_name, port_name, interface)
    link_failure_tests = [
        (nodes["dc1gw1"], "dc1gw1", "leaf1", "D1D5P1", ports["D1D5P1"]),  # DC1GW1 -> Leaf1
        (nodes["dc1gw1"], "dc1gw1", "leaf2", "D1D6P1", ports["D1D6P1"]),  # DC1GW1 -> Leaf2
        (nodes["dc1gw2"], "dc1gw2", "leaf1", "D2D5P1", ports["D2D5P1"]),  # DC1GW2 -> Leaf1
        (nodes["dc1gw2"], "dc1gw2", "leaf2", "D2D6P1", ports["D2D6P1"]),  # DC1GW2 -> Leaf2
    ]

    # Single link failure tests
    for gateway_node, gateway_name, leaf_name, port_name, interface in link_failure_tests:
        st.log(f"Testing link failure between {gateway_name} and {leaf_name} on interface {interface} ({port_name})")

        # Shutdown the interface on the gateway node
        st.log(f"Shutting down interface {interface} ({port_name}) on {gateway_name}")
        intf_api.interface_shutdown(gateway_node, interface)

        # Wait for convergence
        st.wait(30)

        # Verify traffic still works (multi-homing should provide redundancy)
        st.log(f"Verifying traffic with {gateway_name}-{leaf_name} link down ({port_name})")
        if not send_ping_and_verify_traffic(
            st.getwa(), traffic_pairs, use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
        ):
            st.report_fail(
                "test_case_failed", f"Ping test failed with {gateway_name}-{leaf_name} link down ({port_name})"
            )

        # Bring the interface back up
        st.log(f"Bringing up interface {interface} ({port_name}) on {gateway_name}")
        intf_api.interface_noshutdown(gateway_node, interface)

        # Wait for convergence
        st.wait(30)

        # Verify traffic works after link restoration
        st.log(f"Verifying traffic after {gateway_name}-{leaf_name} link restoration ({port_name})")
        if not send_ping_and_verify_traffic(
            st.getwa(), traffic_pairs, use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
        ):
            st.report_fail(
                "test_case_failed", f"Ping test failed after {gateway_name}-{leaf_name} link restoration ({port_name})"
            )

        # Verify DCI remote VTEP and MAC after link restoration
        verify_dci_remotevtep(nodes, f"test_single_link_failures_{gateway_name}_{leaf_name}")
        verify_dci_remotemac(nodes, f"test_single_link_failures_{gateway_name}_{leaf_name}")

        st.log(f"Link failure test passed for {gateway_name}-{leaf_name} ({port_name})")

    st.report_pass("test_case_passed", "test_single_link_failures")


def test_double_link_failures(setup):
    """
    Test double link failures where a gateway is completely disconnected from both leaf nodes.
    Verifies traffic continues to work from DC2/DC3 hosts to DC1 hosts via the redundant gateway.

    Double link failure scenarios (gateway isolation):
    - D1 (dc1gw1) disconnected from both D5 (leaf1) and D6 (leaf2)
    - D2 (dc1gw2) disconnected from both D5 (leaf1) and D6 (leaf2)
    """

    nodes = setup["nodes"]
    ports = setup["ports"]

    # Define traffic pairs from DC2/DC3 hosts to DC1 hosts
    # These specific pairs should continue working with gateway isolation
    traffic_pairs = [
        ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host1"], "ip": "10.212.10.1"}),
        ({"name": nodes["host3"], "ip": "10.212.20.3"}, {"name": nodes["host1"], "ip": "10.212.20.1"}),
        ({"name": nodes["host4"], "ip": "10.212.10.4"}, {"name": nodes["host1"], "ip": "10.212.10.1"}),
        ({"name": nodes["host4"], "ip": "10.212.20.4"}, {"name": nodes["host1"], "ip": "10.212.20.1"}),
        ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host2"], "ip": "10.212.10.2"}),
        ({"name": nodes["host4"], "ip": "10.212.10.4"}, {"name": nodes["host2"], "ip": "10.212.10.2"}),
    ]

    # Double link failure tests - gateway disconnected from both leaf nodes
    st.log("Starting double link failure tests")

    # Test 1: D1 (dc1gw1) disconnected from both D5 (leaf1) and D6 (leaf2)
    double_link_failure_tests = [
        {
            "gateway_node": nodes["dc1gw1"],
            "gateway_name": "dc1gw1",
            "links": [
                {"leaf_name": "leaf1", "port_name": "D1D5P1", "interface": ports["D1D5P1"]},
                {"leaf_name": "leaf2", "port_name": "D1D6P1", "interface": ports["D1D6P1"]},
            ],
        },
        # Test 2: D2 (dc1gw2) disconnected from both D5 (leaf1) and D6 (leaf2)
        {
            "gateway_node": nodes["dc1gw2"],
            "gateway_name": "dc1gw2",
            "links": [
                {"leaf_name": "leaf1", "port_name": "D2D5P1", "interface": ports["D2D5P1"]},
                {"leaf_name": "leaf2", "port_name": "D2D6P1", "interface": ports["D2D6P1"]},
            ],
        },
    ]

    for test_case in double_link_failure_tests:
        gateway_node = test_case["gateway_node"]
        gateway_name = test_case["gateway_name"]
        links = test_case["links"]

        st.log(f"Testing double link failure: {gateway_name} disconnected from both leaf nodes")

        # Shutdown both interfaces on the gateway node
        for link in links:
            st.log(f"Shutting down interface {link['interface']} ({link['port_name']}) on {gateway_name}")
            intf_api.interface_shutdown(gateway_node, link["interface"])

        # Wait for convergence
        st.wait(30)

        # Verify traffic still works (other gateway should provide redundancy)
        st.log(f"Verifying traffic with {gateway_name} completely isolated from DC1 leaf nodes")
        if not send_ping_and_verify_traffic(
            st.getwa(), traffic_pairs, use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
        ):
            st.report_fail("test_case_failed", f"Ping test failed with {gateway_name} isolated (double link failure)")

        # Bring both interfaces back up
        for link in links:
            st.log(f"Bringing up interface {link['interface']} ({link['port_name']}) on {gateway_name}")
            intf_api.interface_noshutdown(gateway_node, link["interface"])

        # Wait for convergence
        st.wait(30)

        # Verify traffic works after link restoration
        st.log(f"Verifying traffic after {gateway_name} double link restoration")
        if not send_ping_and_verify_traffic(
            st.getwa(), traffic_pairs, use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)
        ):
            st.report_fail("test_case_failed", f"Ping test failed after {gateway_name} double link restoration")

        st.log(f"Double link failure test passed for {gateway_name}")

    # Verify DCI remote VTEP and MAC after all links are restored
    st.log("Verifying DCI remote VTEP and MAC tables after all double link failure tests completed")
    verify_dci_remotevtep(nodes, "test_double_link_failures")
    verify_dci_remotemac(nodes, "test_double_link_failures")

    st.report_pass("test_case_passed", "test_double_link_failures")
