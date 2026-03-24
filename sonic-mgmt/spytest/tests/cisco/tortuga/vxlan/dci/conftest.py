import pytest
import os
from typing import Optional
from ixnetwork_restpy import SessionAssistant

from dci.const import CONFIG_FILE_PATH_DEFAULT, get_traffic_pairs, get_ping_anycast
from dci.config import configure_devices
from dci.send_and_verify_traffic import send_ping_and_verify_traffic
from dci.ixia.configure import configure_ixia_session
from dci.ixia.start_stop import start_all_protocols, cleanup_ixia_session
import evpn_mh_utils as mh_utils
from spytest import st
import vxlan_utils as vxlan_utils


def get_command_line_args():
    """
    Get test configuration from environment variables.
    """
    return {
        "topology": os.getenv("DCI_TOPOLOGY", "8d_3dc"),
        "deploy_leaf_on_ixia": os.getenv("DCI_DEPLOY_LEAF_ON_IXIA", "false").lower() == "true",
        "use_ixia_for_hosts": os.getenv("DCI_USE_IXIA_FOR_HOSTS", "false").lower() == "true",
        "no_config": os.getenv("DCI_NO_CONFIG", "false").lower() == "true",
        "config_file": os.getenv("DCI_CONFIG_FILE", CONFIG_FILE_PATH_DEFAULT),
        "cleanup": os.getenv("DCI_CLEANUP", "false").lower() == "true",
        "ixia_config_file": os.getenv("DCI_IXIA_CONFIG_FILE", "ixia_dci_hosts.ixncfg"),
        "ixia_api_key": os.getenv("DCI_IXIA_API_KEY", ""),
        "ixia_force_new_session": os.getenv("DCI_IXIA_FORCE_NEW_SESSION", "true").lower() == "true",
        "auto_start_protocols": os.getenv("DCI_AUTO_START_PROTOCOLS", "true").lower() == "true",
    }


def testbed_vars(deploy_leaf_on_ixia=False, use_ixia_for_hosts=False):
    """
    Test to get the testbed variables
    """
    tb_vars = st.get_testbed_vars()
    assert tb_vars is not None, "Testbed variables are not available"

    # {device_type: WorkArea}
    nodes = {}
    nodes["dc1gw1"] = tb_vars.D1
    nodes["dc1gw2"] = tb_vars.D2
    nodes["dc2gw1"] = tb_vars.D3
    nodes["dc3gw1"] = tb_vars.D4
    nodes["leaf1"] = tb_vars.D5
    nodes["leaf2"] = tb_vars.D6
    if not deploy_leaf_on_ixia and not use_ixia_for_hosts:
        nodes["host1"] = tb_vars.D9
        nodes["host2"] = tb_vars.D10
        nodes["host3"] = tb_vars.D11
        nodes["host4"] = tb_vars.D12
        nodes["host5"] = tb_vars.D13

    # Add TGEN port variables for IXIA configurations
    if use_ixia_for_hosts:
        nodes["leaf3"] = tb_vars.D7
        nodes["leaf4"] = tb_vars.D8
        nodes["D5T1P1"] = tb_vars.D5T1P1
        nodes["D5T1P2"] = tb_vars.D5T1P2
        nodes["D6T1P3"] = tb_vars.D6T1P1
        nodes["D7T1P4"] = tb_vars.D7T1P1
        nodes["D8T1P5"] = tb_vars.D8T1P1
        nodes["D1T1P6"] = tb_vars.D1T1P1

    return tb_vars, nodes


def auto_start_protocols_and_verify(data):
    """
    Automatically start protocols and verify initial traffic.
    
    This function is called by default for test_config.py.
    For test_mobility.py, set DCI_AUTO_START_PROTOCOLS=false to skip this
    and use fine-grained control via start_device_group/start_protocol_stack APIs.
    
    Args:
        data (dict): Test data dictionary containing session_assistant, traffic_pairs, etc.
    """
    # Initiate mac learning by sending traffic from hosts to their respective leafs
    if not data.get("use_ixia_for_hosts"):
        send_ping_and_verify_traffic(
            st.getwa(),
            data.get("ping_anycast", []),
            use_ixia_for_hosts=False,
            single_direction=True,
            ignore_validation=True,
            packet_count=2,
        )
    else:
        # Start all IXIA protocols
        session_assistant = data["session_assistant"]
        assert isinstance(session_assistant, SessionAssistant)
        start_all_protocols(session_assistant)
        st.wait(20, "waiting for IXIA protocols to stabilize and perform ARP resolution")

    # Test regular traffic pairs (bidirectional)
    if not send_ping_and_verify_traffic(
        st.getwa(),
        data.get("traffic_pairs", []),
        use_ixia_for_hosts=data.get("use_ixia_for_hosts"),
        session_assistant=data.get("session_assistant", None),
        packet_count=5,
        max_percent_loss=10.0,
    ):
        session_assistant = data["session_assistant"]
        assert isinstance(session_assistant, SessionAssistant)
        cleanup_ixia_session(session_assistant)
        st.report_fail("test_case_failed", "Initial ping test failed after configuration")


@pytest.fixture(scope="module", autouse=True)
def setup():
    """
    fixture to setup testbed for the test run.
    """
    command_line_args = get_command_line_args()
    data, tb_vars, nodes = {}, {}, {}
    tb_vars, nodes = testbed_vars(command_line_args["deploy_leaf_on_ixia"], command_line_args["use_ixia_for_hosts"])
    if command_line_args["deploy_leaf_on_ixia"]:
        st.log("deploying leaf3/host3 and leaf4/host4 on ixia")
        data["skip_config_leafs"] = ["leaf3", "leaf4"]
    # Always set tb_vars and nodes in data dictionary
    data["tb_vars"] = tb_vars
    data["nodes"] = nodes

    # Store port connections for link failure tests
    # Based on tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml topology
    data["ports"] = {
        "D1D5P1": tb_vars.D1D5P1,  # DC1GW1:Ethernet1_1 -> Leaf1:Ethernet1_1
        "D1D5P2": tb_vars.D1D5P2,  # DC1GW1:Ethernet1_2 -> Leaf1:Ethernet1_2
        "D1D6P1": tb_vars.D1D6P1,  # DC1GW1:Ethernet1_5 -> Leaf2:Ethernet1_1
        "D1D6P2": tb_vars.D1D6P2,  # DC1GW1:Ethernet1_6 -> Leaf2:Ethernet1_2
        "D2D5P1": tb_vars.D2D5P1,  # DC1GW2:Ethernet1_1 -> Leaf1:Ethernet1_5
        "D2D5P2": tb_vars.D2D5P2,  # DC1GW2:Ethernet1_2 -> Leaf1:Ethernet1_6
        "D2D6P1": tb_vars.D2D6P1,  # DC1GW2:Ethernet1_5 -> Leaf2:Ethernet1_5
        "D2D6P2": tb_vars.D2D6P2,  # DC1GW2:Ethernet1_6 -> Leaf2:Ethernet1_6
    }

    config_file = command_line_args["config_file"]

    updated_config_file = vxlan_utils.modify_config_file(config_file, tb_vars)
    data["config_file"] = updated_config_file
    dut_names = st.get_dut_names()
    dut_type = vxlan_utils.check_hw_or_sim(dut_names[0])
    if dut_type != "sim":
        pytest.skip("Test is currently supported only on VXR platform")
    mh_utils.change_fdb_ageout("60000", skip_duts_with="HOST")
    if not command_line_args["deploy_leaf_on_ixia"] and not command_line_args["use_ixia_for_hosts"]:
        data["traffic_pairs"] = get_traffic_pairs(nodes)
        data["ping_anycast"] = get_ping_anycast(nodes)
    else:
        data["use_ixia_for_hosts"] = True
        data["deploy_leaf_on_ixia"] = command_line_args["deploy_leaf_on_ixia"]

    if data["use_ixia_for_hosts"]:
        if not command_line_args["ixia_config_file"] or not command_line_args["ixia_api_key"]:
            st.abort_run(-1, "ixia_config_file and ixia_api_key are required for deploying leafs on ixia", False)
        wa = st.getwa()
        config_file = command_line_args["ixia_config_file"]
        api_key = command_line_args["ixia_api_key"]
        force_new_session = command_line_args["ixia_force_new_session"]
        ixia_vm_ip = wa.net.tb.devices["T1"]["properties"]["ix_server"]
        sess_assistant: Optional[SessionAssistant] = configure_ixia_session(
            config_file, ixia_vm_ip, api_key, force_new_session
        )
        if not sess_assistant:
            st.abort_module("module_config_failed", "failed to configure IXIA session")
        data["session_assistant"] = sess_assistant

    if not command_line_args["cleanup"] and not command_line_args["no_config"]:
        configure_devices(updated_config_file, nodes, add=True)
        st.wait(60, "waiting on device to reach stable state post configuration")
        
        # Auto-start protocols and verify traffic (for test_config.py)
        # For test_mobility.py, set DCI_AUTO_START_PROTOCOLS=false for fine-grained control
        if command_line_args["auto_start_protocols"]:
            auto_start_protocols_and_verify(data)
        else:
            st.log("Skipping auto-start protocols and traffic verification (DCI_AUTO_START_PROTOCOLS=false)")
            st.log("Test will manually control protocol start/stop for fine-grained control")

    # Always yield data regardless of conditions
    if not command_line_args["cleanup"]:
        yield data

    # Cleanup code runs after tests complete
    mh_utils.change_fdb_ageout()
    configure_devices(updated_config_file, nodes, add=False)
    if data.get("use_ixia_for_hosts") and data.get("session_assistant"):
        session_assistant = data["session_assistant"]
        assert isinstance(session_assistant, SessionAssistant)
        cleanup_ixia_session(session_assistant)
    if command_line_args["cleanup"]:
        st.abort_run(0, "Cleanup done, exiting", False)
