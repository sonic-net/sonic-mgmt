import pytest

import time
import logging
import json
import ipaddress
import sys

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]

# TODO: Remove this once we no longer support Python 2
if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode

PTF_LAG_NAME = "bond1"
DUT_LAG_NAME = "PortChannel1"
# Definition of behind or not behind:
# Port behind lag means ports that in a lag, port not behind lag means ports that not in a lag. In this test case, for example, create lag
# between DUT and PTF. Lag on DUT contains Ethernet4, Ethernet8. Lag on PTF contains eth1, eth2. Then Ethernet4, Ethernet8, eth1, eth2 are
# called "port_behind_lag". For testing the connectivity of lag, select a port on the DUT that is not in the lag such as Ethernet12, and
# select the port connected to Ethernet12 on PTF such as eth3. Then Ethernet12 and eth3 are called "port_not_behind_lag".
ATTR_PORT_BEHIND_LAG = "port_behind_lag"
ATTR_PORT_NOT_BEHIND_LAG = "port_not_behind_lag"
TEST_DIR = "/tmp/acstests/"
HWSKU_INTF_NUMBERS_DICT = {
    "Mellanox-SN2700": 16,
    "ACS-MSN4600C": 16,
    "Mellanox-SN2700": 16,
    "Mellanox-SN3800-D112C8": 16,
    "Force10-S6000": 16
}
# To save time when debugging: if True, wouldn't run config_reload() in dut_teardown() and wouldn't recover acl table
IS_DEBUG = False
DEAFULT_NUMBER_OF_MEMBER_IN_LAG = 8

def transfer_vlan_member(duthost, src_vlan_id, dst_vlan_id, member_name):
    """
    Transfer vlan member from src to dst

    Args:
        duthost: DUT host object
        src_vlan_id: src vlan id
        dst_vlan_id: dst vlan id
        member_name: name of member to be transfered
    """
    duthost.del_member_from_vlan(src_vlan_id, member_name)
    duthost.add_member_to_vlan(dst_vlan_id, member_name, False)

def fast_dut_restore(duthost, dut_lag_map, src_vlan_id):
    """
    Restore DUT configuration by reverse operation of adding lag
    This function wouldn't recover acl table deleted in previous step!!!

    Args:
        duthost: DUT host object
        dut_lag_map: imformation about lag in dut
        src_vlan_id: src vlan id
    """
    # Del port channel member
    for dut_lag_member in dut_lag_map[DUT_LAG_NAME]:
        duthost.shell("config portchannel member del {} {}".format(DUT_LAG_NAME, dut_lag_member))
        duthost.add_member_to_vlan(src_vlan_id, dut_lag_member, False)

    duthost.del_member_from_vlan(dut_lag_map["vlan"]["id"], DUT_LAG_NAME)
    duthost.shell("config portchannel del {}".format(DUT_LAG_NAME))
    transfer_vlan_member(duthost, dut_lag_map["vlan"]["id"], src_vlan_id, dut_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["port_name"])
    duthost.remove_ip_from_port("Vlan{}".format(dut_lag_map["vlan"]["id"]), dut_lag_map["vlan"]["ip"])
    duthost.shell("config vlan del {}".format(dut_lag_map["vlan"]["id"]))

def dut_teardown(duthost, dut_lag_map, src_vlan_id):
    """
    Restore dut configuration

    Args:
        duthost: DUT host object
        dut_lag_map: imformation about lag in dut
        src_vlan_id: id of vlan members is used for testing
    """
    if IS_DEBUG:
        # To save time, try a fast restore first, wouldn't restore the acl table
        try:
            fast_dut_restore(duthost, dut_lag_map, src_vlan_id)
        except:
            config_reload(duthost)
    else:
        config_reload(duthost)

def ptf_teardown(ptfhost, ptf_lag_map):
    """
    Restore ptf configuration

    Args:
        ptfhost: PTF host object
        ptf_lag_map: imformation about lag in ptf
    """
    ptfhost.set_dev_no_master(PTF_LAG_NAME)

    for ptf_lag_member in ptf_lag_map[PTF_LAG_NAME]["port_list"]:
        ptfhost.set_dev_no_master(ptf_lag_member)
        ptfhost.set_dev_up_or_down(ptf_lag_member, True)

    ptfhost.shell("ip link del {}".format(PTF_LAG_NAME))
    ptfhost.shell("ip addr del {} dev {}".format(ptf_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["ip"], ptf_lag_map[ATTR_PORT_NOT_BEHIND_LAG]["port_name"]))
    ptfhost.ptf_nn_agent()

def setup_dut_lag(duthost, dut_ports, vlan, src_vlan_id):
    """
    Setup dut lag

    Args:
        duthost: DUT host object
        dut_ports: ports need to configure
        vlan: information about vlan configuration
        src_vlan_id: ip of vlan whose member is used for testing

    Returns:
        information about dut lag
    """
    # Port in acl table can't be added to port channel, and acl table can only be updated by json file
    duthost.remove_acl_table("EVERFLOW")
    duthost.remove_acl_table("EVERFLOWV6")
    # Create port channel
    duthost.shell("config portchannel add {}".format(DUT_LAG_NAME))

    lag_port_list = []
    port_list_idx = 0
    port_list = list(dut_ports[ATTR_PORT_BEHIND_LAG].values())
    # Add ports to port channel
    for port_list_idx in range(0, len(dut_ports[ATTR_PORT_BEHIND_LAG])):
        port_name = port_list[port_list_idx]
        duthost.del_member_from_vlan(src_vlan_id, port_name)
        duthost.shell("config portchannel member add {} {}".format(DUT_LAG_NAME, port_name))
        lag_port_list.append(port_name)
        port_list_idx += 1

    duthost.shell("config vlan add {}".format(vlan["id"]))
    duthost.shell("config interface ip add Vlan{} {}".format(vlan["id"], vlan["ip"]))
    duthost.add_member_to_vlan(vlan["id"], DUT_LAG_NAME, False)
    transfer_vlan_member(duthost, src_vlan_id, vlan["id"], dut_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_name"])

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
    ip_splits = vlan["ip"].split("/")
    vlan_ip = ipaddress.ip_address(UNICODE_TYPE(ip_splits[0]))
    lag_ip = "{}/{}".format(vlan_ip + 1, ip_splits[1])
    port_not_behind_lag_ip = "{}/{}".format(vlan_ip + 2, ip_splits[1])
    # Add lag
    ptfhost.create_lag(PTF_LAG_NAME, lag_ip, "802.3ad")

    port_list = []
    # Add member to lag
    for _, port_name in ptf_ports[ATTR_PORT_BEHIND_LAG].items():
        ptfhost.add_intf_to_lag(PTF_LAG_NAME, port_name)
        port_list.append(port_name)

    lag_port_map = {}
    lag_port_map[PTF_LAG_NAME] = {
        "port_list": port_list,
        "ip": lag_ip
    }
    lag_port_map[ATTR_PORT_NOT_BEHIND_LAG] = ptf_ports[ATTR_PORT_NOT_BEHIND_LAG]
    lag_port_map[ATTR_PORT_NOT_BEHIND_LAG]["ip"] = port_not_behind_lag_ip

    ptfhost.startup_lag(PTF_LAG_NAME)
    ptfhost.add_ip_to_dev(ptf_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_name"], port_not_behind_lag_ip)
    ptfhost.ptf_nn_agent()
    # Wait for lag sync
    time.sleep(10)

    return lag_port_map

def setup_dut_ptf(ptfhost, duthost, tbinfo):
    """
    Setup dut and ptf based on ports available in dut vlan

    Args:
        ptfhost: PTF host object
        duthost: DUT host object
        tbinfo: fixture provides information about testbed

    Returns:
        information about lag of ptf and dut
    """
    # Get number of members in a lag
    dut_hwsku = duthost.facts["hwsku"]
    number_of_lag_member = HWSKU_INTF_NUMBERS_DICT.get(dut_hwsku, DEAFULT_NUMBER_OF_MEMBER_IN_LAG)

    # Get id of vlan that concludes enough up ports as src_vlan_id, port in this vlan is used for testing
    cfg_facts = duthost.config_facts(host = duthost.hostname, source="running")["ansible_facts"]
    port_status = cfg_facts["PORT"]
    src_vlan_id = -1
    pytest_require(cfg_facts.has_key("VLAN_MEMBER"), "Can't get vlan member")
    for vlan_name, members in cfg_facts["VLAN_MEMBER"].items():
        # Number of members in vlan is insufficient
        if len(members) < number_of_lag_member + 1:
            continue

        # Get count of available port in vlan
        count = 0
        for vlan_member in members:
            if port_status[vlan_member].get("admin_status", "down") != "up":
                continue

            count += 1
            if count == number_of_lag_member + 1:
                src_vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
                break

        if src_vlan_id != -1:
            break

    pytest_require(src_vlan_id != -1, "Can't get usable vlan concluding enough member")

    dut_ports = {
        ATTR_PORT_BEHIND_LAG: {},
        ATTR_PORT_NOT_BEHIND_LAG: {}
    }
    src_vlan_members = cfg_facts["VLAN_MEMBER"]["Vlan{}".format(src_vlan_id)]
    # Get the port correspondence between DUT and PTF
    port_index_map = cfg_facts["port_index_map"]
    # Get dut_ports (behind / not behind lag) used for creating dut lag by src_vlan_members and port_index_map
    for port_name, _ in src_vlan_members.items():
        port_id = port_index_map[port_name]
        if len(dut_ports[ATTR_PORT_BEHIND_LAG]) == number_of_lag_member:
            dut_ports[ATTR_PORT_NOT_BEHIND_LAG] = {
                    "port_id": port_id,
                    "port_name": port_name
                }
            break

        dut_ports[ATTR_PORT_BEHIND_LAG][port_id] = port_name

    ptf_ports = {
        ATTR_PORT_BEHIND_LAG: {},
        ATTR_PORT_NOT_BEHIND_LAG: {}
    }
    duts_map = tbinfo["duts_map"]
    dut_indx = duts_map[duthost.hostname]
    # Get available port in PTF
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {}
    for key in host_interfaces:
        ptf_ports_available_in_topo[host_interfaces[key]] = "eth{}".format(key)

    # Get ptf_ports (behind / not behind lag) used for creating ptf lag by ptf_ports_available_in_topo and dut_ports
    for port_id in ptf_ports_available_in_topo:
        if port_id in dut_ports[ATTR_PORT_BEHIND_LAG]:
            ptf_ports[ATTR_PORT_BEHIND_LAG][port_id] = ptf_ports_available_in_topo[port_id]
        elif port_id == dut_ports[ATTR_PORT_NOT_BEHIND_LAG]["port_id"]:
            ptf_ports[ATTR_PORT_NOT_BEHIND_LAG] = {
                "port_id": port_id,
                "port_name": ptf_ports_available_in_topo[port_id]
            }

    pytest_require(len(ptf_ports[ATTR_PORT_BEHIND_LAG]) == len(dut_ports[ATTR_PORT_BEHIND_LAG]) and ptf_ports[ATTR_PORT_NOT_BEHIND_LAG].has_key("port_id"),
                            "Can't get enough ports in ptf")

    vlan = {
        "id": 109,
        "ip": "192.168.9.1/24"
    }
    dut_lag_map = setup_dut_lag(duthost, dut_ports, vlan, src_vlan_id)
    ptf_lag_map = setup_ptf_lag(ptfhost, ptf_ports, vlan)
    return dut_lag_map, ptf_lag_map, src_vlan_id

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
    dut_lag_map, ptf_lag_map, src_vlan_id = setup_dut_ptf(ptfhost, duthost, tbinfo)

    yield dut_lag_map, ptf_lag_map

    dut_teardown(duthost, dut_lag_map, src_vlan_id)
    ptf_teardown(ptfhost, ptf_lag_map)

def test_lag_member_status(duthost, ptf_dut_setup_and_teardown):
    """
    Test ports' status of members in a lag

    Test steps:
        1.) Setup DUT and PTF
        2.) Get status of port channel new added and verify number of member and members' status is correct
    """
    port_channel_status = duthost.get_port_channel_status(DUT_LAG_NAME)
    dut_hwsku = duthost.facts["hwsku"]
    number_of_lag_member = HWSKU_INTF_NUMBERS_DICT.get(dut_hwsku, DEAFULT_NUMBER_OF_MEMBER_IN_LAG)
    pytest_assert(port_channel_status.has_key("ports") and number_of_lag_member == len(port_channel_status["ports"]), "get port status error")
    for _, status in port_channel_status["ports"].items():
        pytest_assert(status["runner"]["selected"], "status of lag member error")

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
    Test traffic about ports in a lag

    Test steps:
        1.) Setup DUT and PTF
        2.) Send ICMP request packet from port behind lag in PTF to port behind lag in DUT, and then verify receive ICMP reply packet in PTF lag
        3.) Send ICMP request packet from port behind lag in PTF to port not behind lag in PTF, and then verify receive the packet in port not behind lag
        4.) Send ICMP request packet from port not behind lag in PTF to port behind lag in PTF, and then verify recieve the packet in port behind lag
    """
    ptfhost = common_setup_teardown
    dut_lag_map, ptf_lag_map = ptf_dut_setup_and_teardown
    run_lag_member_traffic_test(duthost, dut_lag_map["vlan"], ptf_lag_map, ptfhost)
