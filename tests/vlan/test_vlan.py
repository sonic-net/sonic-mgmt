import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

import collections
import ipaddress
import logging
import time
import sys
from netaddr import valid_ipv4

from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses    # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.fixtures.duthost_utils import ports_list   # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig          # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_add
from tests.common.helpers.backend_acl import apply_acl_rules, bind_acl_table
from tests.generic_config_updater.gu_utils import create_checkpoint, rollback

SETUP_ENV_CP = "test_setup_checkpoint"


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

# TODO: Remove this once we no longer support Python 2
if sys.version_info.major >= 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode      # noqa F821

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"

PTF_LAG_NAME = "bond1"
DUT_LAG_NAME = "PortChannel1"
ATTR_PORT_BEHIND_LAG = "port_behind_lag"
ATTR_PORT_TEST = "port_for_test"
ATTR_PORT_NO_TEST = "port_not_for_test"


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


def work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list): # noqa F811
    """
    Read running config facts and get vlan ports list

    Args:
        duthosts: DUT host object
        rand_one_dut_hostname: random one dut hostname
        rand_selected_dut: random selected dut
        tbinfo: fixture provides information about testbed
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
def setup_vlan(duthosts, ptfhost, rand_one_dut_hostname, rand_selected_dut, ptfadapter,
               ports_list, tbinfo, vlan_intfs_dict, cfg_facts, setup_acl_table):  # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        create_checkpoint(duthost, SETUP_ENV_CP)
        dut_lag_map, ptf_lag_map, src_vlan_id = setup_dut_ptf(ptfhost, duthost, tbinfo, vlan_intfs_dict)

        vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
        populate_fdb(ptfadapter, vlan_ports_list, vlan_intfs_dict)
        bind_acl_table(duthost, tbinfo)
        apply_acl_rules(duthost, tbinfo)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        rollback(duthost, SETUP_ENV_CP)
        ptf_teardown(ptfhost, ptf_lag_map)


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


def build_qinq_packet(outer_vlan_id, vlan_id,
                      src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                      src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):
    pkt = testutils.simple_qinq_tcp_packet(eth_dst=dst_mac,
                                           eth_src=src_mac,
                                           dl_vlan_outer=outer_vlan_id,
                                           vlan_vid=vlan_id,
                                           ip_src=src_ip,
                                           ip_dst=dst_ip,
                                           ip_ttl=ttl)
    return pkt


def verify_packets_with_portchannel(test, pkt, ports=[], portchannel_ports=[], device_number=0, timeout=5):
    for port in ports:
        result = testutils.dp_poll(test, device_number=device_number, port_number=port,
                                   timeout=timeout, exp_pkt=pkt)
        if isinstance(result, test.dataplane.PollFailure):
            test.fail("Expected packet was not received on device %d, port %r.\n%s"
                      % (device_number, port, result.format()))

    for port_group in portchannel_ports:
        for port in port_group:
            result = testutils.dp_poll(test, device_number=device_number, port_number=port,
                                       timeout=timeout, exp_pkt=pkt)
            if isinstance(result, test.dataplane.PollSuccess):
                break
        else:
            test.fail("Expected packet was not received on device %d, ports %s.\n"
                      % (device_number, str(port_group)))


def verify_icmp_packets(ptfadapter, send_pkt, vlan_ports_list, vlan_port, vlan_id):
    untagged_pkt = build_icmp_packet(0)
    tagged_pkt = build_icmp_packet(vlan_id)
    untagged_dst_ports = []
    tagged_dst_ports = []
    untagged_dst_pc_ports = []
    tagged_dst_pc_ports = []
    # vlan priority attached to packets is determined by the port, so we ignore it here
    masked_tagged_pkt = Mask(tagged_pkt)
    masked_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

    logger.info("Verify untagged packets from ports " +
                str(vlan_port["port_index"][0]))
    for port in vlan_ports_list:
        if vlan_port["port_index"] == port["port_index"]:
            # Skip src port
            continue
        if port["pvid"] == vlan_id:
            if len(port["port_index"]) > 1:
                untagged_dst_pc_ports.append(port["port_index"])
            else:
                untagged_dst_ports += port["port_index"]
        elif vlan_id in list(map(int, port["permit_vlanid"])):
            if len(port["port_index"]) > 1:
                tagged_dst_pc_ports.append(port["port_index"])
            else:
                tagged_dst_ports += port["port_index"]

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, vlan_port["port_index"][0], send_pkt)
    verify_packets_with_portchannel(test=ptfadapter,
                                    pkt=untagged_pkt,
                                    ports=untagged_dst_ports,
                                    portchannel_ports=untagged_dst_pc_ports)
    verify_packets_with_portchannel(test=ptfadapter,
                                    pkt=masked_tagged_pkt,
                                    ports=tagged_dst_ports,
                                    portchannel_ports=tagged_dst_pc_ports)


def verify_unicast_packets(ptfadapter, send_pkt, exp_pkt, src_port, dst_ports):
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, send_pkt)
    try:
        testutils.verify_packets_any(ptfadapter, exp_pkt, ports=dst_ports)
    except AssertionError as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet was not received")
        raise


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


@pytest.mark.bsl
@pytest.mark.exo
def test_vlan_tc1_send_untagged(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo,
                                ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    """
    Test case #1
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #1 starting ...")

    untagged_pkt = build_icmp_packet(0)
    # Need a tagged packet for set_do_not_care_scapy
    tagged_pkt = build_icmp_packet(4095)
    exp_pkt = Mask(tagged_pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for vlan_port in vlan_ports_list:
        logger.info("Send untagged packet from {} ...".format(
            vlan_port["port_index"][0]))
        logger.info(untagged_pkt.sprintf(
            "%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        if vlan_port['pvid'] != 0:
            verify_icmp_packets(
                ptfadapter, untagged_pkt, vlan_ports_list, vlan_port, vlan_port["pvid"])
        else:
            dst_ports = []
            for port in vlan_ports_list:
                dst_ports += port["port_index"] if port != vlan_port else []
            testutils.send(ptfadapter, vlan_port["port_index"][0], untagged_pkt)
            logger.info("Check on " + str(dst_ports) + "...")
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ports)


@pytest.mark.bsl
@pytest.mark.exo
def test_vlan_tc2_send_tagged(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo,
                              ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):   # noqa F811
    """
    Test case #2
    Send tagged packets from each port.
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #2 starting ...")

    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for vlan_port in vlan_ports_list:
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            pkt = build_icmp_packet(permit_vlanid)
            logger.info("Send tagged({}) packet from {} ...".format(
                permit_vlanid, vlan_port["port_index"][0]))
            logger.info(pkt.sprintf(
                "%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))

            verify_icmp_packets(
                ptfadapter, pkt, vlan_ports_list, vlan_port, permit_vlanid)


@pytest.mark.bsl
@pytest.mark.exo
def test_vlan_tc3_send_invalid_vid(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo,
                                   ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):  # noqa F811
    """
    Test case #3
    Send packets with invalid VLAN ID
    Verify no port can receive these packets
    """

    logger.info("Test case #3 starting ...")

    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    invalid_tagged_pkt = build_icmp_packet(4095)
    masked_invalid_tagged_pkt = Mask(invalid_tagged_pkt)
    masked_invalid_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
    for vlan_port in vlan_ports_list:
        dst_ports = []
        src_port = vlan_port["port_index"][0]
        for port in vlan_ports_list:
            dst_ports += port["port_index"] if port != vlan_port else []
        logger.info("Send invalid tagged packet " +
                    " from " + str(src_port) + "...")
        logger.info(invalid_tagged_pkt.sprintf(
            "%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        testutils.send(ptfadapter, src_port, invalid_tagged_pkt)
        logger.info("Check on " + str(dst_ports) + "...")
        testutils.verify_no_packet_any(
            ptfadapter, masked_invalid_tagged_pkt, dst_ports)


@pytest.mark.bsl
@pytest.mark.exo
def test_vlan_tc4_tagged_unicast(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                 tbinfo, vlan_intfs_dict,
                                 ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):    # noqa F811
    """
    Test case #4
    Send packets w/ src and dst specified over tagged ports in vlan
    Verify that bidirectional communication between two tagged ports work
    """
    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for tagged_test_vlan in vlan_intfs_dict:
        ports_for_test = []

        for vlan_port in vlan_ports_list:
            if vlan_port['pvid'] != tagged_test_vlan and tagged_test_vlan in vlan_port['permit_vlanid']:
                ports_for_test.append(vlan_port['port_index'])
        if len(ports_for_test) < 2:
            continue

        # take two tagged ports for test
        src_port = ports_for_test[0]
        dst_port = ports_for_test[-1]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_tagged_pkt = build_icmp_packet(
            vlan_id=tagged_test_vlan, src_mac=src_mac, dst_mac=dst_mac)
        return_transmit_tagged_pkt = build_icmp_packet(
            vlan_id=tagged_test_vlan, src_mac=dst_mac, dst_mac=src_mac)

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(
            tagged_test_vlan, src_port, dst_port))

        verify_unicast_packets(
            ptfadapter, transmit_tagged_pkt, transmit_tagged_pkt, src_port[0], dst_port)

        logger.info("One Way Tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(
            tagged_test_vlan, src_port, dst_port))

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(
            tagged_test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_tagged_pkt,
                               return_transmit_tagged_pkt, dst_port[0], src_port)

        logger.info("Two Way Tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(
            tagged_test_vlan, dst_port[0], src_port))


@pytest.mark.bsl
@pytest.mark.exo
def test_vlan_tc5_untagged_unicast(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                   tbinfo, vlan_intfs_dict,
                                   ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):  # noqa F811
    """
    Test case #5
    Send packets w/ src and dst specified over untagged ports in vlan
    Verify that bidirectional communication between two untagged ports work
    """
    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for untagged_test_vlan in vlan_intfs_dict:

        ports_for_test = []

        for vlan_port in vlan_ports_list:
            if vlan_port['pvid'] == untagged_test_vlan:
                ports_for_test.append(vlan_port['port_index'])
        if len(ports_for_test) < 2:
            continue

        # take two untagged ports for test
        src_port = ports_for_test[0]
        dst_port = ports_for_test[-1]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_untagged_pkt = build_icmp_packet(
            vlan_id=0, src_mac=src_mac, dst_mac=dst_mac)
        return_transmit_untagged_pkt = build_icmp_packet(
            vlan_id=0, src_mac=dst_mac, dst_mac=src_mac)

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(
            untagged_test_vlan, src_port, dst_port))

        verify_unicast_packets(
            ptfadapter, transmit_untagged_pkt, transmit_untagged_pkt, src_port[0], dst_port)

        logger.info("One Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(
            untagged_test_vlan, src_port, dst_port))

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(
            untagged_test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_untagged_pkt,
                               return_transmit_untagged_pkt, dst_port[0], src_port)

        logger.info("Two Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(
            untagged_test_vlan, dst_port, src_port))


@pytest.mark.bsl
@pytest.mark.exo
def test_vlan_tc6_tagged_untagged_unicast(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                          tbinfo, vlan_intfs_dict,
                                          ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):   # noqa F811
    """
    Test case #6
    Send packets w/ src and dst specified over tagged port and untagged port in vlan
    Verify that bidirectional communication between tagged port and untagged port work
    """
    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for test_vlan in vlan_intfs_dict:
        untagged_ports_for_test = []
        tagged_ports_for_test = []

        for vlan_port in vlan_ports_list:
            if test_vlan not in vlan_port['permit_vlanid']:
                continue
            if vlan_port['pvid'] == test_vlan:
                untagged_ports_for_test.append(vlan_port['port_index'])
            else:
                tagged_ports_for_test.append(vlan_port['port_index'])
        if not untagged_ports_for_test:
            continue
        if not tagged_ports_for_test:
            continue

        # take two ports for test
        src_port = untagged_ports_for_test[0]
        dst_port = tagged_ports_for_test[0]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_untagged_pkt = build_icmp_packet(
            vlan_id=0, src_mac=src_mac, dst_mac=dst_mac)
        exp_tagged_pkt = build_icmp_packet(
            vlan_id=test_vlan, src_mac=src_mac, dst_mac=dst_mac)
        exp_tagged_pkt = Mask(exp_tagged_pkt)
        exp_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

        return_transmit_tagged_pkt = build_icmp_packet(
            vlan_id=test_vlan, src_mac=dst_mac, dst_mac=src_mac)
        exp_untagged_pkt = build_icmp_packet(
            vlan_id=0, src_mac=dst_mac, dst_mac=src_mac)

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(
            test_vlan, src_port, dst_port))

        verify_unicast_packets(
            ptfadapter, transmit_untagged_pkt, exp_tagged_pkt, src_port[0], dst_port)

        logger.info("One Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(
            test_vlan, src_port, dst_port))

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(
            test_vlan, dst_port, src_port))

        verify_unicast_packets(
            ptfadapter, return_transmit_tagged_pkt, exp_untagged_pkt, dst_port[0], src_port)

        logger.info("Two Way tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(
            test_vlan, dst_port, src_port))


@pytest.mark.exo
def test_vlan_tc7_tagged_qinq_switch_on_outer_tag(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                                  tbinfo, vlan_intfs_dict, duthost,
                                                  ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):   # noqa F811
    """
    Test case #7
    Send qinq packets w/ src and dst specified over tagged ports in vlan
    Verify that the qinq packet is switched based on outer vlan tag + src/dst mac
    """
    vlan_ports_list = work_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for tagged_test_vlan in vlan_intfs_dict:
        ports_for_test = []
        for vlan_port in vlan_ports_list:
            if vlan_port['pvid'] != tagged_test_vlan and tagged_test_vlan in vlan_port['permit_vlanid']:
                ports_for_test.append(vlan_port['port_index'])
        if len(ports_for_test) < 2:
            continue

        # take two tagged ports for test
        src_port = ports_for_test[0]
        dst_port = ports_for_test[-1]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_qinq_pkt = build_qinq_packet(
            outer_vlan_id=tagged_test_vlan, vlan_id=250, src_mac=src_mac, dst_mac=dst_mac)
        logger.info("QinQ({}) packet to be sent from port {} to port {}".format(
            tagged_test_vlan, src_port, dst_port))

        verify_unicast_packets(ptfadapter, transmit_qinq_pkt,
                               transmit_qinq_pkt, src_port[0], dst_port)

        logger.info("QinQ packet switching worked successfully...")
