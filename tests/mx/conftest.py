import pytest
import json
import os

from tests.common import config_reload

FILE_DIR = "mx/config"
CONFIG_FILE = "dhcp_server_vlan_conf.json"
IGNORE_REG_LIST = [
    ".*Failed to get port by bridge port.*",
    ".*that doesn't map to a port index.*",
    ".*Calculated address.*",
    ".*removeVlan: Failed to remove ref count.*"
]


@pytest.fixture(scope="function", autouse=True)
def remove_all_vlans(duthost):
    """
    Remove all vlans in DUT before every test case
    """
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    if "VLAN_INTERFACE" in cfg_facts:
        vlan_intfs = cfg_facts["VLAN_INTERFACE"]
        for intf, prefixs in vlan_intfs.items():
            for prefix in prefixs.keys():
                duthost.remove_ip_from_port(intf, prefix)

    if "VLAN_MEMBER" in cfg_facts:
        vlan_members = cfg_facts["VLAN_MEMBER"]
        for vlan_name, members in vlan_members.items():
            vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
            for member in members.keys():
                duthost.del_member_from_vlan(vlan_id, member)

            duthost.remove_vlan(vlan_id)

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

    config_reload(duthost)
