import pytest

import time
import logging
import json

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]

PTF_LAG_NAME = "bond1"
DUT_LAG_NAME = "PortChannel1"
ATTR_PORT_NOT_BEHIND_LAG = "port_not_behind_lag"
ATTR_PORT_BEHIND_LAG = "port_behind_lag"
TEST_DIR = "/tmp/acstests/"
HWSKU_INTF_NUMBERS_DICT = {
    "Mellanox-SN2700": 16,
    "ACS-MSN4600C": 16,
    "Mellanox-SN2700": 16,
    "Mellanox-SN3800-D112C8": 16,
    "Force10-S6000": 16
}

def add_member_to_vlan(duthost, vlan_id, member_name, params):
    """
    Add vlan member

    Args:
        duthost: DUT host object
        vlan_id: id of vlan
        member_name: interface added to vlan
        params: additional params in command line
    """
    duthost.shell("config vlan member add {} {} {}".format(params, vlan_id, member_name))

def remove_member_from_vlan(duthost, vlan_id, member_name):
    """
    Remove vlan member

    Args:
        duthost: DUT host object
        vlan_id: id of vlan
        member_name: interface removed from vlan
    """
    duthost.shell("config vlan member del {} {}".format(vlan_id, member_name))

def restart_ptf_nn_agent(ptfhost):
    """
    Restart ptf_nn_agent

    Args:
        ptfhost: PTF host object
    """
    ptfhost.shell("supervisorctl restart ptf_nn_agent")

def remove_ip_from_port(duthost, port, ip=None):
    """
    Remove ip addresses from port

    Args:
        duthost: DUT host object
        port: port name
        ip: IP address
    """
    ip_addresses = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"].get("INTERFACE", {}).get(port, {})
    if ip_addresses:
        for ip in ip_addresses:
            duthost.shell("config interface ip remove {} {}".format(port, ip))
    elif ip:
        duthost.shell("config interface ip remove {} {}".format(port, ip))

def dut_teardown(duthost, dut_lag_map):
    """
    Restore dut configuration

    Args:
        duthost: DUT host object
        dut_lag_map: imformation about lag in dut
    """
    try:
        for dut_lag_member in dut_lag_map[DUT_LAG_NAME]:
            duthost.shell("config portchannel member del {} {}".format(DUT_LAG_NAME, dut_lag_member))
        add_member_to_vlan(duthost, 1000, dut_lag_member, "-u")

        remove_member_from_vlan(duthost, dut_lag_map["vlan"]["id"], DUT_LAG_NAME)
        duthost.shell("config portchannel del {}".format(DUT_LAG_NAME))
        remove_member_from_vlan(duthost, dut_lag_map["vlan"]["id"], dut_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["port_name"])
        remove_ip_from_port(duthost, "Vlan{}".format(dut_lag_map["vlan"]["id"]), dut_lag_map["vlan"]["ip"])
        add_member_to_vlan(duthost, 1000, dut_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["port_name"], "-u")
        duthost.shell("config vlan del {}".format(dut_lag_map["vlan"]["id"]))
    finally:
        config_reload(duthost)

def ptf_teardown(ptfhost, ptf_lag_map):
    """
    Restore ptf configuration

    Args:
        ptfhost: PTF host object
        ptf_lag_map: imformation about lag in ptf
    """
    ptfhost.shell("ip link set {} nomaster".format(PTF_LAG_NAME))

    for ptf_lag_member in ptf_lag_map[PTF_LAG_NAME]["port_list"]:
        ptfhost.shell("ip link set {} nomaster".format(ptf_lag_member))
        ptfhost.shell("ip link set {} up".format(ptf_lag_member))
        
    ptfhost.shell("ip link del {}".format(PTF_LAG_NAME))
    ptfhost.shell("ip addr del {} dev {}".format(ptf_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["ip"], ptf_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["port_name"]))
    restart_ptf_nn_agent(ptfhost)

def setup_dut_lag(duthost, dut_ports, vlan):
    """
    Setup dut lag

    Args:
        duthost: DUT host object
        dut_ports: ports need to configure
        vlan: information about vlan configuration

    Returns:
        information about dut lag
    """
    duthost.shell("config acl remove table EVERFLOW")
    duthost.shell("config acl remove table EVERFLOWV6")
    duthost.shell("config portchannel add {}".format(DUT_LAG_NAME))

    lag_port_list = []
    port_list_idx = 0
    port_list = list(dut_ports[ATTR_PORT_BEHIND_LAG].values())
    for _ in range(1, 10000):
        port_name = port_list[port_list_idx]
        remove_ip_from_port(duthost, port_name)
        remove_member_from_vlan(duthost, "1000", port_name)
        duthost.shell("config portchannel member add {} {}".format(DUT_LAG_NAME, port_name))
        lag_port_list.append(port_name)
        port_list_idx += 1

        if len(lag_port_list) == len(dut_ports[ATTR_PORT_BEHIND_LAG]):
            break

    duthost.shell("config vlan add {}".format(vlan["id"]))
    duthost.shell("config interface ip add Vlan{} {}".format(vlan["id"], vlan["ip"]))
    add_member_to_vlan(duthost, vlan["id"], DUT_LAG_NAME, "-u")
    remove_member_from_vlan(duthost, 1000, dut_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_name"])
    remove_ip_from_port(duthost, dut_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_name"])
    add_member_to_vlan(duthost, vlan["id"], dut_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_name"], "-u")

    lag_port_map = {}
    lag_port_map[DUT_LAG_NAME] = lag_port_list
    lag_port_map[ATTR_PORT_NOT_BEHIND_LAG] = dut_ports[ATTR_PORT_NOT_BEHIND_LAG]
    lag_port_map["vlan"] = vlan
    return lag_port_map

def setup_ptf_lag(ptfhost, ptf_ports, vlan):
    """
    Setup ptf lag

    Args:
        ptfhost: PTF host object
        ptf_ports: ports need to configure
        vlan: information about vlan configuration

    Returns:
        information about ptf lag
    """
    ip_prefix = ".".join(vlan["ip"].split("/")[0].split(".")[0:3])
    mask_len = vlan["ip"].split("/")[1]
    lag_ip = "{}.2/{}".format(ip_prefix, mask_len)
    port_not_behind_lag_ip = "{}.3/{}".format(ip_prefix, mask_len)

    ptfhost.shell("ip link add {} type bond".format(PTF_LAG_NAME))
    ptfhost.shell("ip link set {} type bond miimon 100 mode 802.3ad".format(PTF_LAG_NAME))
    ptfhost.shell("ip address add {} dev {}".format(lag_ip, PTF_LAG_NAME))
    
    port_list = []
    for _, port_name in ptf_ports[ATTR_PORT_BEHIND_LAG].items():
        ptfhost.shell("ip link set {} down".format(port_name))
        ptfhost.shell("ip link set {} master {}".format(port_name, PTF_LAG_NAME))
        port_list.append(port_name)

    lag_port_map = {}
    lag_port_map[PTF_LAG_NAME] = {
        "port_list": port_list,
        "ip": lag_ip
    }
    lag_port_map[ATTR_PORT_NOT_BEHIND_LAG] = ptf_ports[ATTR_PORT_NOT_BEHIND_LAG]
    lag_port_map[ATTR_PORT_NOT_BEHIND_LAG]["ip"] = port_not_behind_lag_ip
    
    ptfhost.shell("ip link set dev {} up".format(PTF_LAG_NAME))
    ptfhost.shell("ifconfig {} mtu 9100 up".format(PTF_LAG_NAME))
    ptfhost.shell("ip addr add {} dev {}".format(port_not_behind_lag_ip, ptf_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_name"]))
    restart_ptf_nn_agent(ptfhost)
    time.sleep(10)

    return lag_port_map

def setup_dut_ptf(ptfhost, duthost, tbinfo):
    """
    Setup dut and ptf

    Args:
        ptfhost: PTF host object
        duthost: DUT host object
        tbinfo: fixture provides information about testbed
    
    Returns:
        information about lag of ptf and dut
    """
    cfg_facts = duthost.config_facts(host = duthost.hostname, source="running")["ansible_facts"]
    portchannel_members = []
    for member in cfg_facts.get("PORTCHANNEL_MEMBER", {}).values():
        portchannel_members += member.keys()
    
    config_vlan_members = cfg_facts["port_index_map"]
    port_status = cfg_facts["PORT"]
    duts_map = tbinfo["duts_map"]
    dut_indx = duts_map[duthost.hostname]

    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {}
    for key in host_interfaces:
        ptf_ports_available_in_topo[host_interfaces[key]] = "eth{}".format(key)    


    dut_hwsku = duthost.facts["hwsku"]
    number_of_lag_member = HWSKU_INTF_NUMBERS_DICT.get(dut_hwsku, 8)
    dut_ports = {
        ATTR_PORT_BEHIND_LAG: {},
        ATTR_PORT_NOT_BEHIND_LAG: {}
    }
    sub_interface_ports = set([_.split(".")[0] for _ in cfg_facts.get("VLAN_SUB_INTERFACE", {}).keys()])
    for port, port_id in config_vlan_members.items():
        if ((port not in portchannel_members) and
            (not port in sub_interface_ports) and
            (port_status[port].get("admin_status", "down") == "up")):
            if len(dut_ports[ATTR_PORT_BEHIND_LAG]) == number_of_lag_member:
                dut_ports[ATTR_PORT_NOT_BEHIND_LAG] = {
                    "port_id": port_id,
                    "port_name": port
                }
                break
            dut_ports[ATTR_PORT_BEHIND_LAG][port_id] = port

    pytest_require(len(dut_ports[ATTR_PORT_BEHIND_LAG]) == number_of_lag_member and len(dut_ports[ATTR_PORT_NOT_BEHIND_LAG]), "No port for testing")

    ptf_ports = {
        ATTR_PORT_BEHIND_LAG: {},
        ATTR_PORT_NOT_BEHIND_LAG: {}
    }

    for port_id in ptf_ports_available_in_topo:
        if port_id in dut_ports[ATTR_PORT_BEHIND_LAG]:
            ptf_ports[ATTR_PORT_BEHIND_LAG][port_id] = ptf_ports_available_in_topo[port_id]
        elif port_id == dut_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_id"]:
            ptf_ports[ATTR_PORT_NOT_BEHIND_LAG] = {
                "port_id": port_id,
                "port_name": ptf_ports_available_in_topo[port_id]
            }

    vlan = {
        "id": 109,
        "ip": "192.168.9.1/24"
    }
    dut_lag_map = setup_dut_lag(duthost, dut_ports, vlan)
    ptf_lag_map = setup_ptf_lag(ptfhost, ptf_ports, vlan)
    return dut_lag_map, ptf_lag_map

@pytest.fixture(scope="module")
def common_setup_teardown(ptfhost):
    logger.info("########### Setup for lag testing ###########")

    ptfhost.shell("mkdir -p {}".format(TEST_DIR))
    # Copy PTF test into PTF-docker for test LACP DU
    test_files = ["lag_test.py", "acs_base_test.py", "router_utils.py"]
    for test_file in test_files:
        src = "../ansible/roles/test/files/acstests/%s" % test_file
        dst = TEST_DIR + test_file
        ptfhost.copy(src=src, dest=dst)

    yield ptfhost

    ptfhost.file(path=TEST_DIR, state="absent")

@pytest.fixture(scope="module")
def ptf_dut_setup_and_teardown(duthost, ptfhost, tbinfo):
    """
    Setup and teardown of ptf and dut

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
        tbinfo: fixture provides information about testbed
    """
    dut_lag_map, ptf_lag_map = setup_dut_ptf(ptfhost, duthost, tbinfo)

    yield dut_lag_map, ptf_lag_map

    dut_teardown(duthost, dut_lag_map)
    ptf_teardown(ptfhost, ptf_lag_map)

def get_port_channel_status(duthost, port_channel):
    """
    Get status of port channel by port channel name

    Args:
        duthost: DUT host object
        port_channel: port channel name

    Returns:
        status of port channel
    """
    commond_output = duthost.shell("docker exec -i teamd teamdctl {} state dump".format(port_channel))
    pytest_assert(commond_output["rc"] == 0, "Get status of {}".format(port_channel))
    json_info = json.loads(commond_output["stdout"])
    return json_info

def test_lag_member_status(duthost, ptf_dut_setup_and_teardown):
    """
    Test ports' status of 16 members in a lag
    """
    port_channel_status = get_port_channel_status(duthost, DUT_LAG_NAME)
    dut_hwsku = duthost.facts["hwsku"]
    number_of_lag_member = HWSKU_INTF_NUMBERS_DICT.get(dut_hwsku, 8)
    pytest_assert(number_of_lag_member == len(port_channel_status["ports"]), "Number of lag member error")
    for _, status in port_channel_status["ports"].items():
        pytest_assert(status["runner"]["aggregator"]["selected"], "Status of lag member error")

def run_lag_member_traffic_test(duthost, dut_vlan, ptf_lag_map, ptfhost):
    """
    Run lag member traffic test

    Args:
        duthost: DUT host object
        dut_vlan: vlan information in dut
        ptf_lag_map: information about lag in ptf
        ptfhost: PTF host object
    """
    params = {
        "dut_mac": duthost.facts["router_mac"],
        "dut_vlan": dut_vlan,
        "ptf_lag": ptf_lag_map[PTF_LAG_NAME],
        ATTR_PORT_NOT_BEHIND_LAG: ptf_lag_map[ATTR_PORT_NOT_BEHIND_LAG]
    }
    ptf_runner(ptfhost, TEST_DIR, "lag_test.LagMemberTrafficTest", "/root/ptftests", params=params)

def test_lag_member_traffic(common_setup_teardown, duthost, ptf_dut_setup_and_teardown):
    """
    Test traffic about 16 ports in a lag
    """
    ptfhost = common_setup_teardown
    dut_lag_map, ptf_lag_map = ptf_dut_setup_and_teardown
    run_lag_member_traffic_test(duthost, dut_lag_map["vlan"], ptf_lag_map, ptfhost)
