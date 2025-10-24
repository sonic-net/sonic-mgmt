import pytest
from dci.const import DCI_CLIS, DCI_VLAN_VNI_MAPPING_DEL
from dci.config import configure_devices, configure_bgp, configure_sonic, run_clis_on_duts
from dci.send_and_verify_traffic import send_ping_and_verify_traffic
from dci.sonic_verifiers import verify_dci_remotevtep, verify_dci_remotemac
from spytest import st


def test_deconfigure_reconfigure_devices(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_devices(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_devices deconfigure")
    if not configure_devices(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_devices reconfigure")
    st.wait(30)
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_devices")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_devices")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_devices")


def test_deconfigure_reconfigure_dc1gw2(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    dci_node = {
        "dc1gw2": nodes["dc1gw2"]
    }
    if not configure_devices(config_file, dci_node, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dc1gw2 deconfigure")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    if not configure_devices(config_file, dci_node, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dc1gw2 reconfigure")
    st.wait(30)
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_dc1gw2")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
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
    # keepalive timer is 10s, hold timer is 30s, wait for 2x hold timer before configuring the system back
    st.wait(180)
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_sonic")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
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
    st.wait(30)
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_bgp")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_bgp")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_bgp")


def test_deconfigure_reconfigure_dci_config(setup):
    nodes = setup["nodes"]

    config = DCI_CLIS.copy()
    # BGP ASN mapping for each DCI gateway node
    bgp_asn_mapping = {
        "dc1gw1": "65001",
        "dc1gw2": "65002", 
        "dc2gw1": "65003",
        "dc3gw1": "65004"
    }
    
    # Deconfigure DCI configuration on all gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        duts_config.append((
            nodes[node_name],
            [f"router bgp {bgp_asn_mapping[node_name]}"] + config["del"]
        ))
    
    if not run_clis_on_duts(duts_config, is_bgp=True):
        st.report_fail("test_case_failed", f"test_deconfigure_reconfigure_dci_config deconfigure on {[config[0] for config in duts_config]}")
    st.wait(10)
    
    # Reconfigure DCI configuration on all gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        duts_config.append((
            nodes[node_name],
            [f"router bgp {bgp_asn_mapping[node_name]}"] + config["add"]
        ))
    
    if not run_clis_on_duts(duts_config, is_bgp=True):
        st.report_fail("test_case_failed", f"test_deconfigure_reconfigure_dci_config reconfigure on {[config[0] for config in duts_config]}")
    st.wait(30)
    
    # Verify VXLAN remote VTEP and MAC configurations after reconfiguration
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_dci_config")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
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
        "dc3gw1": nodes["dc3gw1"]
    }
    if not configure_devices(config_file, dci_nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dci_nodes deconfigure")
    if not configure_devices(config_file, dci_nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_dci_nodes reconfigure")
    st.wait(30)
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_dci_nodes")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_dci_nodes")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_dci_nodes")


def test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes(setup):
    nodes = setup["nodes"]

    # Deconfigure VLAN-VNI mappings on all DCI gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if node_name in DCI_VLAN_VNI_MAPPING_DEL:
            duts_config.append((
                nodes[node_name],
                DCI_VLAN_VNI_MAPPING_DEL[node_name]["del"]
            ))
    
    if not run_clis_on_duts(duts_config):
        st.report_fail("test_case_failed", f"test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes deconfigure on {[config[0] for config in duts_config]}")
    st.wait(30)
    
    # Reconfigure VLAN-VNI mappings on all DCI gateway nodes
    duts_config = []
    for node_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if node_name in DCI_VLAN_VNI_MAPPING_DEL:
            duts_config.append((
                nodes[node_name],
                DCI_VLAN_VNI_MAPPING_DEL[node_name]["add"]
            ))
    
    if not run_clis_on_duts(duts_config):
        st.report_fail("test_case_failed", f"test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes reconfigure on {[config[0] for config in duts_config]}")
    st.wait(30)
    
    # Verify VXLAN remote VTEP and MAC configurations after reconfiguration
    verify_dci_remotevtep(nodes, "test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes")
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"], use_ubuntu_hosts=setup.get("use_ubuntu_hosts", False)):
        st.report_fail("test_case_failed", "Ping test failed after VLAN-VNI mapping reconfiguration")
    verify_dci_remotemac(nodes, "test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_vlan_vni_mapping_at_dci_nodes")
