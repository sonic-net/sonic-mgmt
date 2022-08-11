import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

import itertools
import logging
import pprint
import time

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # lgtm[py/unused-import]
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from tests.common.fixtures.duthost_utils import ports_list, utils_vlan_ports_list
from tests.common.fixtures.duthost_utils import utils_create_test_vlans
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_add

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"

# Only test the first 2 portchannels
PORTCHANNELS_TEST_NUM = 2


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

@pytest.fixture(scope="module")
def vlan_intfs_dict(tbinfo, utils_vlan_intfs_dict_orig):
    vlan_intfs_dict = utils_vlan_intfs_dict_orig
    # For t0 topo, will add 2 VLANs for test.
    # Need to make sure vlan id is unique, and avoid vlan ip network overlapping.
    # For example, ip prefix is 192.168.0.1/21 for VLAN 1000,
    # Below ip prefix overlaps with 192.168.0.1/21, and need to skip:
    # 192.168.0.1/24, 192.168.1.1/24, 192.168.2.1/24, 192.168.3.1/24,
    # 192.168.4.1/24, 192.168.5.1/24, 192.168.6.1/24, 192.168.7.1/24
    if tbinfo['topo']['name'] != 't0-56-po2vlan':
        vlan_intfs_dict = utils_vlan_intfs_dict_add(vlan_intfs_dict, 2)
    return vlan_intfs_dict


@pytest.fixture(scope="module")
def work_vlan_ports_list(rand_selected_dut, tbinfo, cfg_facts, ports_list, utils_vlan_ports_list, vlan_intfs_dict, pc_num=PORTCHANNELS_TEST_NUM):
    if tbinfo['topo']['name'] == 't0-56-po2vlan':
        return utils_vlan_ports_list

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    work_vlan_ports_list = []
    config_ports = {k: v for k,v in cfg_facts['PORT'].items() if v.get('admin_status', 'down') == 'up'}
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_indices = {k: v for k, v in mg_facts['minigraph_ptf_indices'].items() if k in config_ports}

    # For t0 topo, will add port to new VLAN, use 'orig' field to identify new VLAN.
    vlan_id_list = [k for k, v in vlan_intfs_dict.items() if v['orig'] == False]
    pvid_cycle = itertools.cycle(vlan_id_list)
    # when running on t0 we can use the portchannel members
    if config_portchannels:
        portchannel_cnt = 0
        for po in config_portchannels:
            vlan_port = {
                'dev' : po,
                'port_index' : [config_port_indices[member] for member in config_portchannels[po]['members']],
                'permit_vlanid' : []
            }
            # Add 2 portchannels for test
            if portchannel_cnt < pc_num:
                portchannel_cnt += 1
                vlan_port['pvid'] = pvid_cycle.next()
                vlan_port['permit_vlanid'] = vlan_id_list[:]
            if 'pvid' in vlan_port:
                work_vlan_ports_list.append(vlan_port)
        assert portchannel_cnt == pc_num, 'Need 2 portchannels for test'

    for i, port in enumerate(ports_list):
        vlan_port = {
            'dev' : port,
            'port_index' : [config_port_indices[port]],
            'permit_vlanid' : []
        }
        # Add 4 ports for test
        if i < 4:
            vlan_port['pvid'] = pvid_cycle.next()
            vlan_port['permit_vlanid'] = vlan_id_list[:]
        if 'pvid' in vlan_port:
            work_vlan_ports_list.append(vlan_port)

    return work_vlan_ports_list


def shutdown_portchannels(duthost, portchannel_interfaces, pc_num=PORTCHANNELS_TEST_NUM):
    cmds = []
    cnt = 0
    logger.info("Shutdown lags, flush IP addresses")
    for portchannel, ips in portchannel_interfaces.items():
        cmds.append('config interface shutdown {}'.format(portchannel))
        for ip in ips:
            cmds.append('config interface ip remove {} {}'.format(portchannel, ip))
        cnt += 1
        if cnt >= pc_num:
            break

    duthost.shell_cmds(cmds=cmds)


def check_portchannels_down(duthost, portchannel_interfaces, pc_num=PORTCHANNELS_TEST_NUM):
    '''
    After shutdown portchannels, check redis to make sure router interface is removed.
    '''
    cnt = 0
    oid_list = []
    # Get oid list for first 2 portchannels
    for portchannel in portchannel_interfaces:
        res = duthost.shell("sonic-db-cli COUNTERS_DB hget COUNTERS_LAG_NAME_MAP {}".format(portchannel))
        oid_list.append(res['stdout'])
        cnt += 1
        if cnt >= pc_num:
            break
    res = duthost.shell("sonic-db-cli ASIC_DB keys *ROUTER_INTERFACE*")
    for line in res['stdout_lines']:
        get_res = duthost.shell("sonic-db-cli ASIC_DB hget {} SAI_ROUTER_INTERFACE_ATTR_PORT_ID".format(line))
        if 'oid' not in get_res['stdout']:
            continue
        if get_res['stdout'] in oid_list:
            return False
    return True


def create_test_vlans(duthost, cfg_facts, work_vlan_ports_list, vlan_intfs_dict):
    utils_create_test_vlans(duthost, cfg_facts, work_vlan_ports_list, vlan_intfs_dict, delete_untagged_vlan=True)

def startup_portchannels(duthost, portchannel_interfaces, pc_num=PORTCHANNELS_TEST_NUM):
    cmds = []
    cnt = 0
    logger.info("Bringup lags")
    for portchannel in portchannel_interfaces:
        cmds.append('config interface startup {}'.format(portchannel))
        cnt += 1
        if cnt >= pc_num:
            break

    duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module", autouse=True)
def setup_vlan(duthosts, rand_one_dut_hostname, ptfadapter, tbinfo, work_vlan_ports_list, vlan_intfs_dict, cfg_facts):
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        if tbinfo['topo']['name'] != 't0-56-po2vlan':
            portchannel_interfaces = cfg_facts.get('PORTCHANNEL_INTERFACE', {})

            shutdown_portchannels(duthost, portchannel_interfaces)

            # Must wait for orchagent to remove related router interface
            start_time = time.time()
            assert wait_until(120, 2, 0, check_portchannels_down, duthost, portchannel_interfaces), "Shutdown portchannels failed"
            end_time = time.time()
            logger.info('Take {} seconds to shutdown portchannels'.format(end_time-start_time))

            create_test_vlans(duthost, cfg_facts, work_vlan_ports_list, vlan_intfs_dict)

            startup_portchannels(duthost, portchannel_interfaces)

            res = duthost.command('show int portchannel')
            logger.info('"show int portchannel" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))

            populate_fdb(ptfadapter, work_vlan_ports_list, vlan_intfs_dict)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        tearDown(duthost, tbinfo)


def tearDown(duthost, tbinfo):

    logger.info("VLAN test ending ...")

    if tbinfo['topo']['name'] != 't0-56-po2vlan':
        config_reload(duthost)


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


def verify_icmp_packets(ptfadapter, send_pkt, work_vlan_ports_list, vlan_port, vlan_id):
    untagged_pkt = build_icmp_packet(0)
    tagged_pkt = build_icmp_packet(vlan_id)
    untagged_dst_ports = []
    tagged_dst_ports = []
    untagged_dst_pc_ports = []
    tagged_dst_pc_ports = []
    # vlan priority attached to packets is determined by the port, so we ignore it here
    masked_tagged_pkt = Mask(tagged_pkt)
    masked_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

    logger.info("Verify untagged packets from ports " + str(vlan_port["port_index"][0]))
    for port in work_vlan_ports_list:
        if vlan_port["port_index"] == port["port_index"]:
            # Skip src port
            continue
        if port["pvid"] == vlan_id:
            if len(port["port_index"]) > 1:
                untagged_dst_pc_ports.append(port["port_index"])
            else:
                untagged_dst_ports += port["port_index"]
        elif vlan_id in map(int, port["permit_vlanid"]):
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


def populate_fdb(ptfadapter, work_vlan_ports_list, vlan_intfs_dict):
    # send icmp packet from each tagged and untagged port in each test vlan to populate fdb
    for vlan in vlan_intfs_dict:
        for vlan_port in work_vlan_ports_list:
            if vlan in vlan_port['permit_vlanid']:
                vlan_id = 0 if vlan == vlan_port['pvid'] else vlan  # vlan_id: 0 - untagged, vlan = tagged
                port_id = vlan_port['port_index'][0]
                src_mac = ptfadapter.dataplane.get_mac(0, port_id)
                pkt = build_icmp_packet(vlan_id=vlan_id, src_mac=src_mac)
                testutils.send(ptfadapter, port_id, pkt)


@pytest.mark.bsl
def test_vlan_tc1_send_untagged(ptfadapter, work_vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #1
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #1 starting ...")

    for vlan_port in work_vlan_ports_list:
        pkt = build_icmp_packet(0)
        logger.info("Send untagged packet from {} ...".format(vlan_port["port_index"][0]))
        logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        if vlan_port['pvid'] != 0:
            verify_icmp_packets(ptfadapter, pkt, work_vlan_ports_list, vlan_port, vlan_port["pvid"])
        else:
            exp_pkt = Mask(pkt)
            exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
            dst_ports = []
            for port in work_vlan_ports_list:
                dst_ports += port["port_index"] if port != vlan_port else []
            testutils.send(ptfadapter, vlan_port["port_index"][0], pkt)
            logger.info("Check on " + str(dst_ports) + "...")
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ports)


@pytest.mark.bsl
def test_vlan_tc2_send_tagged(ptfadapter, work_vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #2
    Send tagged packets from each port.
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #2 starting ...")

    for vlan_port in work_vlan_ports_list:
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            pkt = build_icmp_packet(permit_vlanid)
            logger.info("Send tagged({}) packet from {} ...".format(permit_vlanid, vlan_port["port_index"][0]))
            logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))

            verify_icmp_packets(ptfadapter, pkt, work_vlan_ports_list, vlan_port, permit_vlanid)


@pytest.mark.bsl
def test_vlan_tc3_send_invalid_vid(ptfadapter, work_vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #3
    Send packets with invalid VLAN ID
    Verify no port can receive these packets
    """

    logger.info("Test case #3 starting ...")

    invalid_tagged_pkt = build_icmp_packet(4095)
    masked_invalid_tagged_pkt = Mask(invalid_tagged_pkt)
    masked_invalid_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
    for vlan_port in work_vlan_ports_list:
        dst_ports = []
        src_port = vlan_port["port_index"][0]
        for port in work_vlan_ports_list:
            dst_ports += port["port_index"] if port != vlan_port else []
        logger.info("Send invalid tagged packet " + " from " + str(src_port) + "...")
        logger.info(invalid_tagged_pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        testutils.send(ptfadapter, src_port, invalid_tagged_pkt)
        logger.info("Check on " + str(dst_ports) + "...")
        testutils.verify_no_packet_any(ptfadapter, masked_invalid_tagged_pkt, dst_ports)


@pytest.mark.bsl
def test_vlan_tc4_tagged_unicast(ptfadapter, work_vlan_ports_list, vlan_intfs_dict, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #4
    Send packets w/ src and dst specified over tagged ports in vlan
    Verify that bidirectional communication between two tagged ports work
    """
    for tagged_test_vlan in vlan_intfs_dict:
        ports_for_test = []

        for vlan_port in work_vlan_ports_list:
            if vlan_port['pvid'] != tagged_test_vlan and tagged_test_vlan in vlan_port['permit_vlanid']:
                ports_for_test.append(vlan_port['port_index'])
        if len(ports_for_test) < 2:
            continue

        #take two tagged ports for test
        src_port = ports_for_test[0]
        dst_port = ports_for_test[-1]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_tagged_pkt = build_icmp_packet(vlan_id=tagged_test_vlan, src_mac=src_mac, dst_mac=dst_mac)
        return_transmit_tagged_pkt = build_icmp_packet(vlan_id=tagged_test_vlan, src_mac=dst_mac, dst_mac=src_mac)

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(tagged_test_vlan, src_port, dst_port))

        verify_unicast_packets(ptfadapter, transmit_tagged_pkt, transmit_tagged_pkt, src_port[0], dst_port)

        logger.info("One Way Tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(tagged_test_vlan, src_port, dst_port))

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(tagged_test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_tagged_pkt, return_transmit_tagged_pkt, dst_port[0], src_port)

        logger.info("Two Way Tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(tagged_test_vlan, dst_port[0], src_port))


@pytest.mark.bsl
def test_vlan_tc5_untagged_unicast(ptfadapter, work_vlan_ports_list, vlan_intfs_dict, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #5
    Send packets w/ src and dst specified over untagged ports in vlan
    Verify that bidirectional communication between two untagged ports work
    """
    for untagged_test_vlan in vlan_intfs_dict:

        ports_for_test = []

        for vlan_port in work_vlan_ports_list:
            if vlan_port['pvid'] == untagged_test_vlan:
                ports_for_test.append(vlan_port['port_index'])
        if len(ports_for_test) < 2:
            continue

        #take two untagged ports for test
        src_port = ports_for_test[0]
        dst_port = ports_for_test[-1]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_untagged_pkt = build_icmp_packet(vlan_id=0, src_mac=src_mac, dst_mac=dst_mac)
        return_transmit_untagged_pkt = build_icmp_packet(vlan_id=0, src_mac=dst_mac, dst_mac=src_mac)

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(untagged_test_vlan, src_port, dst_port))

        verify_unicast_packets(ptfadapter, transmit_untagged_pkt, transmit_untagged_pkt, src_port[0], dst_port)

        logger.info("One Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(untagged_test_vlan, src_port, dst_port))

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(untagged_test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_untagged_pkt, return_transmit_untagged_pkt, dst_port[0], src_port)

        logger.info("Two Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(untagged_test_vlan, dst_port, src_port))


@pytest.mark.bsl
def test_vlan_tc6_tagged_untagged_unicast(ptfadapter, work_vlan_ports_list, vlan_intfs_dict, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #6
    Send packets w/ src and dst specified over tagged port and untagged port in vlan
    Verify that bidirectional communication between tagged port and untagged port work
    """
    for test_vlan in vlan_intfs_dict:
        untagged_ports_for_test = []
        tagged_ports_for_test = []

        for vlan_port in work_vlan_ports_list:
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

        #take two ports for test
        src_port = untagged_ports_for_test[0]
        dst_port = tagged_ports_for_test[0]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_untagged_pkt = build_icmp_packet(vlan_id=0, src_mac=src_mac, dst_mac=dst_mac)
        exp_tagged_pkt = build_icmp_packet(vlan_id=test_vlan, src_mac=src_mac, dst_mac=dst_mac)
        exp_tagged_pkt = Mask(exp_tagged_pkt)
        exp_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

        return_transmit_tagged_pkt = build_icmp_packet(vlan_id=test_vlan, src_mac=dst_mac, dst_mac=src_mac)
        exp_untagged_pkt = build_icmp_packet(vlan_id=0, src_mac=dst_mac, dst_mac=src_mac)

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(test_vlan, src_port, dst_port))

        verify_unicast_packets(ptfadapter, transmit_untagged_pkt, exp_tagged_pkt, src_port[0], dst_port)

        logger.info("One Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(test_vlan, src_port, dst_port))

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_tagged_pkt, exp_untagged_pkt, dst_port[0], src_port)

        logger.info("Two Way tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(test_vlan, dst_port, src_port))


def test_vlan_tc7_tagged_qinq_switch_on_outer_tag(ptfadapter, work_vlan_ports_list, vlan_intfs_dict, duthost, toggle_all_simulator_ports_to_rand_selected_tor_m):
    """
    Test case #7
    Send qinq packets w/ src and dst specified over tagged ports in vlan
    Verify that the qinq packet is switched based on outer vlan tag + src/dst mac
    """

    for tagged_test_vlan in vlan_intfs_dict:
        ports_for_test = []
        for vlan_port in work_vlan_ports_list:
            if vlan_port['pvid'] != tagged_test_vlan and tagged_test_vlan in vlan_port['permit_vlanid']:
                ports_for_test.append(vlan_port['port_index'])
        if len(ports_for_test) < 2:
            continue

        #take two tagged ports for test
        src_port = ports_for_test[0]
        dst_port = ports_for_test[-1]

        src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

        transmit_qinq_pkt = build_qinq_packet(outer_vlan_id=tagged_test_vlan, vlan_id=250, src_mac=src_mac, dst_mac=dst_mac)
        logger.info ("QinQ({}) packet to be sent from port {} to port {}".format(tagged_test_vlan, src_port, dst_port))

        verify_unicast_packets(ptfadapter, transmit_qinq_pkt, transmit_qinq_pkt, src_port[0], dst_port)

        logger.info ("QinQ packet switching worked successfully...")
