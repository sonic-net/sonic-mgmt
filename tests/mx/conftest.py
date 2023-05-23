import pytest
import json
import os

from tests.common import config_reload
from mx_utils import create_vlan, get_vlan_config, remove_all_vlans

FILE_DIR = "mx/config"
MX_VLAN_CONFIG_FILE = "mx_vlan_conf.json"
IGNORE_REG_LIST = [
    ".*Failed to get port by bridge port.*",
    ".*that doesn't map to a port index.*",
    ".*Calculated address.*",
    ".*removeVlan: Failed to remove ref count.*"
]


@pytest.fixture(scope="function")
def setup_vlan(duthost, mx_common_setup_teardown, vlan_number):
    remove_all_vlans(duthost)
    dut_index_port, ptf_index_port, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, vlan_number)
    intf_count = create_vlan(duthost, vlan_config, dut_index_port)
    # Save config_db of mx vlan, to make it to take affect after reboot.
    duthost.shell("config save -y")
    yield intf_count, vlan_config, ptf_index_port


@pytest.fixture(scope="function", autouse=True)
def log_analyzer_setup(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(IGNORE_REG_LIST)
    yield


@pytest.fixture(scope="module")
def mx_common_setup_teardown(duthost, tbinfo):
    # Get vlan configs
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    vlan_configs = json.load(open(os.path.join(FILE_DIR, MX_VLAN_CONFIG_FILE), "r"))

    dut_port_index = cfg_facts["port_index_map"]
    dut_index_port = dict(zip(dut_port_index.values(), dut_port_index.keys()))  # port_index -> dut_port_name {0: "Ethernet0", 1: "Ethernet1"}

    duts_map = tbinfo["duts_map"]
    dut_indx = duts_map[duthost.hostname]
    ptf_port_index = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_index_port = dict(zip(ptf_port_index.values(), ptf_port_index.keys()))  # port_index -> ptf_port_name {0: "0", 1: "1"}

    yield dut_index_port, ptf_index_port, vlan_configs

    config_reload(duthost, config_source="minigraph")


@pytest.fixture(scope="module")
def port_alias_to_name(duthost):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    return mg_facts['minigraph_port_alias_to_name_map']


@pytest.fixture(scope="module")
def port_alias_to_ptf_index(port_alias_to_name, mx_common_setup_teardown):
    ptf_idx_to_port_name, _, _ = mx_common_setup_teardown
    port_name_to_ptf_idx = {value: key for key, value in ptf_idx_to_port_name.items()}
    return {alias: port_name_to_ptf_idx[name] for alias, name in port_alias_to_name.items()}
