import pytest

from dci.const import CONFIG_FILE_PATH_DEFAULT
from dci.config import configure_devices
from dci.send_and_verify_traffic import send_ping_and_verify_traffic
import evpn_mh_utils as mh_utils
from spytest import st
import vxlan_utils as vxlan_utils


def pytest_addoption(parser):
    parser.addoption(
        "--topology",
        action="store",
        default="8d_3dc",
        help="Path to the topology file.",
    )
    parser.addoption(
        "--deploy-leaf-on-ixia",
        action="store_true",
        default=False,
        help="Deploy leaf devices on Ixia, look for supported options",
    )
    parser.addoption(
        "--no-config",
        action="store_true",
        default=False,
        help="Skip configuration of devices",
    )
    parser.addoption(
        "--cleanup",
        action="store_true",
        default=False,
        help="Cleanup the enviroment before running tests",
    )


@pytest.fixture(scope="session")
def command_line_args(request):
    """
    Fixture to capture command line arguments passed to pytest.
    """
    return {
        "topology": request.config.getoption("--topology"),
        "deploy_leaf_on_ixia": request.config.getoption("--deploy-leaf-on-ixia"),
        "no_config": request.config.getoption("--no-config"),
        "cleanup": request.config.getoption("--cleanup"),
    }


def testbed_vars_8d(deploy_leaf_on_ixia=False):
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
    if not deploy_leaf_on_ixia:
        nodes["leaf3"] = tb_vars.D7
        nodes["leaf4"] = tb_vars.D8
    nodes["host1"] = tb_vars.D9
    nodes["host2"] = tb_vars.D10
    nodes["host3"] = tb_vars.D11
    nodes["host4"] = tb_vars.D12
    return tb_vars, nodes


@pytest.fixture(scope="module", autouse=True)
def setup(command_line_args):
    """
    fixture to setup testbed for the test run.
    """
    data, tb_vars, nodes = {}, {}, {}
    if command_line_args["topology"] == "8d_3dc":
        tb_vars, nodes = testbed_vars_8d(command_line_args["deploy_leaf_on_ixia"] == True)
        if command_line_args["deploy_leaf_on_ixia"]:
            st.log("deploying leaf3/host3 and leaf4/host4 on ixia")
            data["skip_config_leafs"] = ["leaf3", "leaf4"]
        # Always set tb_vars and nodes in data dictionary
        data["tb_vars"] = tb_vars
        data["nodes"] = nodes

    config_file = CONFIG_FILE_PATH_DEFAULT
    if command_line_args["topology"] == "8d_3dc":
        config_file = CONFIG_FILE_PATH_DEFAULT
    else:
        st.report_fail("Unsupported topology option")

    updated_config_file = vxlan_utils.modify_config_file(config_file, tb_vars)
    data["config_file"] = updated_config_file
    dut_names = st.get_dut_names()
    dut_type = vxlan_utils.check_hw_or_sim(dut_names[0])
    if dut_type != "sim":
        pytest.skip("Test is currently supported only on VXR platform")

    data["traffic_pairs"] = [
            ({"name": nodes["host1"], "ip": "10.212.10.1"}, {"name": nodes["host3"], "ip": "10.212.10.3"}),
            ({"name": nodes["host2"], "ip": "10.212.10.2"}, {"name": nodes["host3"], "ip": "10.212.10.3"}),
            ({"name": nodes["host1"], "ip": "10.212.10.1"}, {"name": nodes["host4"], "ip": "10.212.10.4"}),
            ({"name": nodes["host2"], "ip": "10.212.10.2"}, {"name": nodes["host4"], "ip": "10.212.10.4"}),
            ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host1"], "ip": "10.212.10.1"}),
            ({"name": nodes["host4"], "ip": "10.212.10.4"}, {"name": nodes["host1"], "ip": "10.212.10.1"}),
            ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host2"], "ip": "10.212.10.2"}),
            ({"name": nodes["host4"], "ip": "10.212.10.4"}, {"name": nodes["host2"], "ip": "10.212.10.2"}),
            ({"name": nodes["host3"], "ip": "10.212.10.3"}, {"name": nodes["host4"], "ip": "10.212.10.4"}),
        ]
    if not command_line_args["cleanup"] and not command_line_args["no_config"]:
        configure_devices(updated_config_file, nodes, add=True)
        if not send_ping_and_verify_traffic(st.getwa(), data["traffic_pairs"]):
            st.report_fail("test_case_failed", "Initial ping test failed after configuration")
        yield data


    mh_utils.change_fdb_ageout("6000")
    configure_devices(updated_config_file, nodes, add=False)
    if command_line_args["cleanup"]:
        pytest.skip("Cleanup done, skipping tests")
