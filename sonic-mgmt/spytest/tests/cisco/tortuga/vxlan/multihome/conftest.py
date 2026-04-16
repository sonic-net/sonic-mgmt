import pytest
import re

import evpn_mh_utils as mh_utils
import vxlan_utils
from multihome.const import (
    lag_name,
    lag_ports,
    phy_int_map,
    interface_map,
    spytest_data,
)
from spytest import st
import apis.switching.portchannel as portchannel_obj
from multihome import dut
from multihome.const import spytest_data
from multihome.traffic_generator import PORTCHANNEL_NAME, LAG_POLL_INTERVAL, LAG_POLL_TIMEOUT


def testbed_vars():
    """
    Test to get the testbed variables
    """
    vars = st.get_testbed_vars()
    assert vars is not None, "Testbed variables are not available"

    # {device_type: WorkArea}
    nodes = {}
    nodes["spine0"] = vars.D1
    nodes["leaf0"] = vars.D2
    nodes["leaf1"] = vars.D3
    nodes["leaf2"] = vars.D4
    return vars, nodes


@pytest.fixture(scope="module", autouse=True)
def configure():
    """
    fixture to modify the config file and configure the switch nodes
    :param config_file: config file to be modified
    :return: modified config file
    """
    vars, nodes = testbed_vars()

    config_file = "multihome/config.yaml"
    updated_config_file = vxlan_utils.modify_config_file(config_file, vars)
    mh_utils.change_fdb_ageout("6000")
    dut.configure(updated_config_file, nodes)

    lag_handle = vxlan_utils.config_lag_interface(
        lag_name,
        lag_ports,
        spytest_data.lag_ip,
        spytest_data.lag_gateway_ip,
        spytest_data.lag_mac,
    )

    lag_handle.update(vxlan_utils.config_tgen_interface(phy_int_map))

    dut_names = st.get_dut_names()
    dut_type = vxlan_utils.check_hw_or_sim(dut_names[0])
    # yield to test_data
    test_data = {
        "duts": nodes,
        "dut_names": dut_names,
        "dut_type": dut_type,
        "lag_handle": lag_handle,
        "config_file": updated_config_file,
        "interface_map": interface_map,
        "D2T1P1": vars.D2T1P1,
        "D2T1P2": vars.D2T1P2,
        "D3T1P1": vars.D3T1P1,
        "D3T1P2": vars.D3T1P2,
        "D4T1P1": vars.D4T1P1,
        "D4T1P2": vars.D4T1P2,
        "D2D1P1": vars.D2D1P1,
    }
    dut.wait(15)
    yield test_data

    # Destroy LAG interface
    tg = lag_handle[lag_name]["tg_handle"]
    topology_handle = re.search(
        "/topology:\d+", lag_handle[lag_name]["int_handle"]
    ).group()
    tg.tg_test_control(action="stop_protocol", handle=topology_handle)
    if not st.poll_wait2(LAG_POLL_INTERVAL, LAG_POLL_TIMEOUT,
                         portchannel_obj.verify_portchannel_state,
                         vars.D2, PORTCHANNEL_NAME, state="down"):
        st.log("PortChannel did not go down during teardown")
    tg.tg_topology_config(topology_handle=topology_handle, mode="destroy")
    dut.wait(5)
    tg.tg_emulation_lag_config(
        mode="delete", lag_handle=lag_handle[lag_name]["lag_handle"], lag_name=lag_name
    )
    dut.wait(5)

    dut.configure(updated_config_file, nodes, add=False)
    mh_utils.change_fdb_ageout("600")

    vxlan_utils.remove_temp_config(updated_config_file)


@pytest.fixture(scope="module", autouse=True)
def traffic_setup(configure):
    """
    Fixture to set up the traffic configuration.
    """
    ### update SIM and HW specifc info ###

    if configure["dut_type"] == "sim":
        spytest_data.transmit_mode = "single_burst"
        spytest_data.pkts_per_burst = "1000"
        ### Using lower line rate for SIM tgen ###
        spytest_data.rate_percent = "0.01"
        spytest_data.circuit_endpoint_type = "ipv4"
        spytest_data.frame_size = "100"
    else:
        spytest_data.mode = "create"
        spytest_data.transmit_mode = "single_burst"
        spytest_data.pkts_per_burst = "2000"
        spytest_data.rate_percent = "10"
        spytest_data.circuit_endpoint_type = "ipv4"
        spytest_data.frame_size = "1000"
    yield configure
