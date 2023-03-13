import pytest
import json
import os

from tests.common import config_reload
from mx_utils import remove_all_vlans

FILE_DIR = "mx/config"
CONFIG_FILE = "dhcp_server_vlan_conf.json"
IGNORE_REG_LIST = [
    ".*Failed to get port by bridge port.*",
    ".*that doesn't map to a port index.*",
    ".*Calculated address.*",
    ".*removeVlan: Failed to remove ref count.*"
]


@pytest.fixture(scope="function")
def function_fixture_remove_all_vlans(duthost):
    """
    Remove all vlans in DUT before every test case
    """
    remove_all_vlans(duthost)

    yield


@pytest.fixture(scope="module")
def module_fixture_remove_all_vlans(duthost):
    """
    Remove all vlans in DUT before every module
    """
    remove_all_vlans(duthost)

    yield


@pytest.fixture(scope="function", autouse=True)
def log_analyzer_setup(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(IGNORE_REG_LIST)
    yield


@pytest.fixture(scope="module")
def mx_common_setup_teardown(duthost, tbinfo):
    # Get vlan configs
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    vlan_configs = json.load(open(os.path.join(FILE_DIR, CONFIG_FILE), "r"))

    dut_port_index = cfg_facts["port_index_map"]
    dut_index_port = dict(zip(dut_port_index.values(), dut_port_index.keys()))

    duts_map = tbinfo["duts_map"]
    dut_indx = duts_map[duthost.hostname]
    ptf_port_index = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_index_port = dict(zip(ptf_port_index.values(), ptf_port_index.keys()))

    yield dut_index_port, ptf_index_port, vlan_configs

    config_reload(duthost, config_source="minigraph")
