import pytest
import ptf.testutils as testutils
import collections
import ipaddress
import time
import sys
from netaddr import valid_ipv4

from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses    # noqa F401
from tests.common.fixtures.duthost_utils import ports_list   # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig          # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_add
from tests.common.helpers.backend_acl import apply_acl_rules, bind_acl_table
from tests.generic_config_updater.gu_utils import create_checkpoint, rollback


# TODO: Remove this once we no longer support Python 2
if sys.version_info.major >= 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode      # noqa F821

SETUP_ENV_CP = "test_setup_checkpoint"
PTF_LAG_NAME = "bond1"
DUT_LAG_NAME = "PortChannel1"
ATTR_PORT_BEHIND_LAG = "port_behind_lag"
ATTR_PORT_TEST = "port_for_test"
ATTR_PORT_NO_TEST = "port_not_for_test"


def build_icmp_packet(vlan_id, src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                      src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):

    pkt = testutils.simple_icmp_packet(pktlen=100 if vlan_id == 0 else 104,
                                       eth_dst=dst_mac,
                                       eth_src=src_mac,
                                       dl_vlan_enable=False if vlan_id == 0 else True,
                                       vlan_vid=vlan_id,
                                       vlan_pcp=0,
                                       ip_src=src_ip,
                                       ip_dst=dst_ip,
                                       ip_ttl=ttl)
    return pkt


def populate_fdb(ptfadapter, vlan_ports_list, vlan_intfs_dict):
    # send icmp packet from each tagged and untagged port in each test vlan to populate fdb
    for vlan in vlan_intfs_dict:
        for vlan_port in vlan_ports_list:
            if vlan in vlan_port['permit_vlanid']:
                # vlan_id: 0 - untagged, vlan = tagged
                vlan_id = 0 if vlan == vlan_port['pvid'] else vlan
                port_id = vlan_port['port_index'][0]
                src_mac = ptfadapter.dataplane.get_mac(0, port_id)
                pkt = build_icmp_packet(vlan_id=vlan_id, src_mac=src_mac)
                testutils.send(ptfadapter, port_id, pkt)


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
    ptfhost.ptf_nn_agent()


def setup_dut_lag(duthost, dut_ports, vlan, src_vlan_id):
    """
    Setup dut lag

    Args:
        duthost: DUT host object
        dut_ports: ports need to configure
        vlan: information about vlan configuration
        src_vlan_id: original vlan id

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
    port_list = list(dut_ports[ATTR_PORT_NO_TEST].values())
    # Remove ports from vlan
    for port_list_idx in range(0, len(dut_ports[ATTR_PORT_NO_TEST])):
        port_name = port_list[port_list_idx]
        duthost.del_member_from_vlan(src_vlan_id, port_name)

    duthost.shell("config vlan add {}".format(vlan["id"]))
    duthost.shell("config interface ip add Vlan{} {}".format(vlan["id"], vlan["ip"]))
    duthost.add_member_to_vlan(vlan["id"], DUT_LAG_NAME, True)
    duthost.add_member_to_vlan(src_vlan_id, DUT_LAG_NAME, True)

    lag_port_map = {}
    lag_port_map[DUT_LAG_NAME] = lag_port_list
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
    # Add lag
    ptfhost.create_lag(PTF_LAG_NAME, lag_ip, "802.3ad")

    port_list = []
    # Add member to lag
    for _, port_name in list(ptf_ports[ATTR_PORT_BEHIND_LAG].items()):
        ptfhost.add_intf_to_lag(PTF_LAG_NAME, port_name)
        port_list.append(port_name)

    lag_port_map = {}
    lag_port_map[PTF_LAG_NAME] = {
        "port_list": port_list,
    }

    ptfhost.startup_lag(PTF_LAG_NAME)
    ptfhost.ptf_nn_agent()
    # Wait for lag sync
    time.sleep(10)

    return lag_port_map


def setup_dut_ptf(ptfhost, duthost, tbinfo, vlan_intfs_dict):
    """
    Setup dut and ptf based on ports available in dut vlan

    Args:
        ptfhost: PTF host object
        duthost: DUT host object
        tbinfo: fixture provides information about testbed

    Returns:
        information about lag of ptf and dut
    """
    number_of_lag_member = 2
    number_of_test_ports = 4

    # Get id of vlan that concludes enough up ports as src_vlan_id, port in this vlan is used for testing
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    src_vlan_id = get_vlan_id(cfg_facts, number_of_lag_member)
    pytest_require(src_vlan_id != -1, "Can't get usable vlan concluding enough member")

    dut_ports = {
        ATTR_PORT_BEHIND_LAG: {},
        ATTR_PORT_TEST: {},
        ATTR_PORT_NO_TEST: {},
    }
    src_vlan_members = cfg_facts["VLAN_MEMBER"]["Vlan{}".format(src_vlan_id)]
    # Get the port correspondence between DUT and PTF
    port_index_map = cfg_facts["port_index_map"]
    # Get dut_ports (behind / not behind lag) used for creating dut lag by src_vlan_members and port_index_map
    for port_name, _ in list(src_vlan_members.items()):
        port_id = port_index_map[port_name]
        if len(dut_ports[ATTR_PORT_BEHIND_LAG]) < number_of_lag_member:
            dut_ports[ATTR_PORT_BEHIND_LAG][port_id] = port_name
        elif len(dut_ports[ATTR_PORT_TEST]) < number_of_test_ports:
            dut_ports[ATTR_PORT_TEST][port_id] = port_name
        else:
            dut_ports[ATTR_PORT_NO_TEST][port_id] = port_name

    ptf_ports = {
        ATTR_PORT_BEHIND_LAG: {},
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

    pytest_require(len(ptf_ports[ATTR_PORT_BEHIND_LAG]) == len(dut_ports[ATTR_PORT_BEHIND_LAG]),
                   "Can't get enough ports in ptf")

    vlan = {}
    for k, v in vlan_intfs_dict.items():
        if v['orig'] is False:
            vlan['id'] = k
            vlan['ip'] = v['ip']
            break
    dut_lag_map = setup_dut_lag(duthost, dut_ports, vlan, src_vlan_id)
    ptf_lag_map = setup_ptf_lag(ptfhost, ptf_ports, vlan)
    return dut_lag_map, ptf_lag_map, src_vlan_id


def get_vlan_id(cfg_facts, number_of_lag_member):
    """
    Determine if Vlan have enough port members needed

    Args:
        cfg_facts: DUT config facts
        number_of_lag_member: number of lag members needed for test
    """
    port_status = cfg_facts["PORT"]
    src_vlan_id = -1
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
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
    return src_vlan_id


def running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list): # noqa F811
    """
    Read running config facts and get vlan ports list

    Args:
        duthosts: DUT host object
        rand_one_dut_hostname: random one dut hostname
        rand_selected_dut: random selected dut
        tbinfo: fixture provides information about testbed
        ports_list: list of ports
    """
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports_list = []
    config_ports = {k: v for k, v in list(cfg_facts['PORT'].items()) if v.get('admin_status', 'down') == 'up'}
    config_portchannels = cfg_facts.get('PORTCHANNEL_MEMBER', {})
    config_port_indices = {k: v for k, v in list(mg_facts['minigraph_ptf_indices'].items()) if k in config_ports}
    config_ports_vlan = collections.defaultdict(list)
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    # key is dev name, value is list for configured VLAN member.
    for k, v in list(cfg_facts['VLAN'].items()):
        vlanid = v['vlanid']
        for addr in cfg_facts['VLAN_INTERFACE']['Vlan'+vlanid]:
            # address could be IPV6 and IPV4, only need IPV4 here
            if addr and valid_ipv4(addr.split('/')[0]):
                ip = addr
                break
        else:
            continue
        if k not in vlan_members:
            continue
        for port in vlan_members[k]:
            if 'tagging_mode' not in vlan_members[k][port]:
                continue
            mode = vlan_members[k][port]['tagging_mode']
            config_ports_vlan[port].append({'vlanid': int(vlanid), 'ip': ip, 'tagging_mode': mode})

    if config_portchannels:
        for po in config_portchannels:
            vlan_port = {
                'dev': po,
                'port_index': [config_port_indices[member] for member in list(config_portchannels[po].keys())],
                'permit_vlanid': []
            }
            if po in config_ports_vlan:
                vlan_port['pvid'] = 0
                for vlan in config_ports_vlan[po]:
                    if 'vlanid' not in vlan or 'ip' not in vlan or 'tagging_mode' not in vlan:
                        continue
                    if vlan['tagging_mode'] == 'untagged':
                        vlan_port['pvid'] = vlan['vlanid']
                    vlan_port['permit_vlanid'].append(vlan['vlanid'])
            if 'pvid' in vlan_port:
                vlan_ports_list.append(vlan_port)

    for i, port in enumerate(ports_list):
        vlan_port = {
            'dev': port,
            'port_index': [config_port_indices[port]],
            'permit_vlanid': []
        }
        if port in config_ports_vlan:
            vlan_port['pvid'] = 0
            for vlan in config_ports_vlan[port]:
                if 'vlanid' not in vlan or 'ip' not in vlan or 'tagging_mode' not in vlan:
                    continue
                if vlan['tagging_mode'] == 'untagged':
                    vlan_port['pvid'] = vlan['vlanid']
                vlan_port['permit_vlanid'].append(vlan['vlanid'])
        if 'pvid' in vlan_port:
            vlan_ports_list.append(vlan_port)

    return vlan_ports_list


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module")
def vlan_intfs_dict(tbinfo, utils_vlan_intfs_dict_orig):        # noqa F811
    vlan_intfs_dict = utils_vlan_intfs_dict_orig
    # For t0 topo, will add VLAN for test.
    # Need to make sure vlan id is unique, and avoid vlan ip network overlapping.
    # For example, ip prefix is 192.168.0.1/21 for VLAN 1000,
    # Below ip prefix overlaps with 192.168.0.1/21, and need to skip:
    # 192.168.0.1/24, 192.168.1.1/24, 192.168.2.1/24, 192.168.3.1/24,
    # 192.168.4.1/24, 192.168.5.1/24, 192.168.6.1/24, 192.168.7.1/24
    vlan_intfs_dict = utils_vlan_intfs_dict_add(vlan_intfs_dict, 1)
    return vlan_intfs_dict


@pytest.fixture(scope="module")
def acl_rule_cleanup(duthost, tbinfo):
    """Cleanup all the existing DATAACL rules"""
    # remove all rules under the ACL_RULE table
    if "t0-backend" in tbinfo["topo"]["name"]:
        duthost.shell('acl-loader delete')

    yield


@pytest.fixture(scope="module")
def setup_acl_table(duthost, tbinfo, acl_rule_cleanup):
    """ Remove the DATAACL table prior to the test and recreate it at the end"""
    if "t0-backend" in tbinfo["topo"]["name"]:
        duthost.command('config acl remove table DATAACL')

    yield

    if "t0-backend" in tbinfo["topo"]["name"]:
        duthost.command('config acl remove table DATAACL')
        # rebind with new set of ports
        bind_acl_table(duthost, tbinfo)


@pytest.fixture(scope="module", autouse=True)
def setup_po2vlan(duthosts, ptfhost, rand_one_dut_hostname, rand_selected_dut, ptfadapter,
               ports_list, tbinfo, vlan_intfs_dict, setup_acl_table):  # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        create_checkpoint(duthost, SETUP_ENV_CP)
        dut_lag_map, ptf_lag_map, src_vlan_id = setup_dut_ptf(ptfhost, duthost, tbinfo, vlan_intfs_dict)

        vp_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
        populate_fdb(ptfadapter, vp_list, vlan_intfs_dict)
        bind_acl_table(duthost, tbinfo)
        apply_acl_rules(duthost, tbinfo)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        rollback(duthost, SETUP_ENV_CP)
        ptf_teardown(ptfhost, ptf_lag_map)
