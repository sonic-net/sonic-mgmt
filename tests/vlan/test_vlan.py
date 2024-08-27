import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

import logging

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig          # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_add           # noqa F401
from tests.common.fixtures.duthost_utils import ports_list            # noqa F401
from tests.common.helpers.portchannel_to_vlan import setup_acl_table  # noqa F401
from tests.common.helpers.portchannel_to_vlan import acl_rule_cleanup # noqa F401
from tests.common.helpers.portchannel_to_vlan import vlan_intfs_dict  # noqa F401
from tests.common.helpers.portchannel_to_vlan import setup_po2vlan    # noqa F401
from tests.common.helpers.portchannel_to_vlan import running_vlan_ports_list
from tests.common.helpers.portchannel_to_vlan import has_portchannels

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    """
       Ignore expected errors in logs during test execution

       Args:
           loganalyzer: Loganalyzer utility fixture
           duthost: DUT host object
    """
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        loganalyzer_ignore_regex = [
            ".*ERR swss#orchagent: :- update: Failed to get port by bridge port ID.*",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(loganalyzer_ignore_regex)

    yield


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
    for src_port in vlan_port["port_index"]:
        testutils.send(ptfadapter, src_port, send_pkt)
    logger.info("Verify untagged packets from ports " + str(vlan_port["port_index"][0]))
    verify_packets_with_portchannel(test=ptfadapter,
                                    pkt=untagged_pkt,
                                    ports=untagged_dst_ports,
                                    portchannel_ports=untagged_dst_pc_ports)
    logger.info("Verify tagged packets from ports " + str(vlan_port["port_index"][0]))
    verify_packets_with_portchannel(test=ptfadapter,
                                    pkt=masked_tagged_pkt,
                                    ports=tagged_dst_ports,
                                    portchannel_ports=tagged_dst_pc_ports)


def verify_unicast_packets(ptfadapter, send_pkt, exp_pkt, src_ports, dst_ports, timeout=None):
    ptfadapter.dataplane.flush()
    for src_port in src_ports:
        testutils.send(ptfadapter, src_port, send_pkt)
    try:
        testutils.verify_packets_any(ptfadapter, exp_pkt, ports=dst_ports, timeout=timeout)
    except AssertionError as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet was not received")
        raise


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_vlan_tc1_send_untagged(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo,
                                ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    """
    Test case #1
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #1 starting ...")
    if "dualtor" in tbinfo["topo"]["name"]:
        pytest.skip("Dual TOR device does not support broadcast packet")

    # Skip the test if no portchannel interfaces are detected
    # e.g., when sending packets to an egress port with PVID 0 on a portchannel interface
    # the absence of portchannel interfaces means the expected destination doesn't exist
    if not has_portchannels(duthosts, rand_one_dut_hostname):
        pytest.skip("Test skipped: No portchannels detected when sending untagged packets")

    untagged_pkt = build_icmp_packet(0)
    # Need a tagged packet for set_do_not_care_scapy
    tagged_pkt = build_icmp_packet(4095)
    exp_pkt = Mask(tagged_pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for vlan_port in vlan_ports_list:
        logger.info("Send untagged packet from the port {} ...".format(
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
            for src_port in vlan_port["port_index"]:
                testutils.send(ptfadapter, src_port, untagged_pkt)
            logger.info("Check on " + str(dst_ports) + "...")
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ports)


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_vlan_tc2_send_tagged(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo,
                              ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):   # noqa F811
    """
    Test case #2
    Send tagged packets from each port.
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #2 starting ...")
    if "dualtor" in tbinfo["topo"]["name"]:
        pytest.skip("Dual TOR device does not support broadcast packet")

    # Skip the test if no portchannel interfaces are detected
    # e.g., when sending packets to an egress port with PVID 0 on a portchannel interface
    # the absence of portchannel interfaces means the expected destination doesn't exist
    if not has_portchannels(duthosts, rand_one_dut_hostname):
        pytest.skip("Test skipped: No portchannels detected when sending tagged packets")

    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for vlan_port in vlan_ports_list:
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            pkt = build_icmp_packet(permit_vlanid)
            logger.info("Send tagged({}) packet from the port {} ...".format(
                permit_vlanid, vlan_port["port_index"][0]))
            logger.info(pkt.sprintf(
                "%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))

            verify_icmp_packets(
                ptfadapter, pkt, vlan_ports_list, vlan_port, permit_vlanid)


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_vlan_tc3_send_invalid_vid(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo,
                                   ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m):  # noqa F811
    """
    Test case #3
    Send packets with invalid VLAN ID
    Verify no port can receive these packets
    """

    logger.info("Test case #3 starting ...")
    if "dualtor" in tbinfo["topo"]["name"]:
        pytest.skip("Dual TOR device does not support broadcast packet")

    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    invalid_tagged_pkt = build_icmp_packet(4095)
    masked_invalid_tagged_pkt = Mask(invalid_tagged_pkt)
    masked_invalid_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
    for vlan_port in vlan_ports_list:
        dst_ports = []
        for port in vlan_ports_list:
            dst_ports += port["port_index"] if port != vlan_port else []
        src_ports = vlan_port["port_index"]
        logger.info("Send invalid tagged packet " +
                    " from " + str(src_ports) + "...")
        logger.info(invalid_tagged_pkt.sprintf(
            "%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        for src_port in src_ports:
            testutils.send(ptfadapter, src_port, invalid_tagged_pkt)
        logger.info("Check on " + str(dst_ports) + "...")
        testutils.verify_no_packet_any(
            ptfadapter, masked_invalid_tagged_pkt, dst_ports)


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_vlan_tc4_tagged_unicast(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                 tbinfo, vlan_intfs_dict, ports_list,                   # noqa F811
                                 toggle_all_simulator_ports_to_rand_selected_tor_m):    # noqa F811
    """
    Test case #4
    Send packets w/ src and dst specified over tagged ports in vlan
    Verify that bidirectional communication between two tagged ports work
    """
    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
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
            ptfadapter, transmit_tagged_pkt, transmit_tagged_pkt, src_port,
            dst_port, timeout=5)

        logger.info("One Way Tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(
            tagged_test_vlan, src_port, dst_port))

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(
            tagged_test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_tagged_pkt,
                               return_transmit_tagged_pkt, dst_port, src_port, timeout=5)

        logger.info("Two Way Tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(
            tagged_test_vlan, dst_port[0], src_port))


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_vlan_tc5_untagged_unicast(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                   tbinfo, vlan_intfs_dict, ports_list,                 # noqa F811
                                   toggle_all_simulator_ports_to_rand_selected_tor_m):  # noqa F811
    """
    Test case #5
    Send packets w/ src and dst specified over untagged ports in vlan
    Verify that bidirectional communication between two untagged ports work
    """
    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
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
            ptfadapter, transmit_untagged_pkt, transmit_untagged_pkt, src_port,
            dst_port, timeout=5)

        logger.info("One Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(
            untagged_test_vlan, src_port, dst_port))

        logger.info("Untagged({}) packet to be sent from port {} to port {}".format(
            untagged_test_vlan, dst_port, src_port))

        verify_unicast_packets(ptfadapter, return_transmit_untagged_pkt,
                               return_transmit_untagged_pkt, dst_port, src_port, timeout=5)

        logger.info("Two Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(
            untagged_test_vlan, dst_port, src_port))


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_vlan_tc6_tagged_untagged_unicast(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                          tbinfo, vlan_intfs_dict, ports_list,                  # noqa F811
                                          toggle_all_simulator_ports_to_rand_selected_tor_m):   # noqa F811
    """
    Test case #6
    Send packets w/ src and dst specified over tagged port and untagged port in vlan
    Verify that bidirectional communication between tagged port and untagged port work
    """
    # Skip the test if no portchannel interfaces are detected
    # e.g., when sending packets to an egress port with PVID 0 on a portchannel interface
    # the absence of portchannel interfaces means the expected destination doesn't exist
    if not has_portchannels(duthosts, rand_one_dut_hostname):
        pytest.skip("Test skipped: No portchannels detected when sending untagged packets")

    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
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
            ptfadapter, transmit_untagged_pkt, exp_tagged_pkt, src_port, dst_port)

        logger.info("One Way Untagged Packet Transmission Works")
        logger.info("Untagged({}) packet successfully sent from port {} to port {}".format(
            test_vlan, src_port, dst_port))

        logger.info("Tagged({}) packet to be sent from port {} to port {}".format(
            test_vlan, dst_port, src_port))

        verify_unicast_packets(
            ptfadapter, return_transmit_tagged_pkt, exp_untagged_pkt, dst_port, src_port)

        logger.info("Two Way tagged Packet Transmission Works")
        logger.info("Tagged({}) packet successfully sent from port {} to port {}".format(
            test_vlan, dst_port, src_port))


@pytest.mark.po2vlan
def test_vlan_tc7_tagged_qinq_switch_on_outer_tag(ptfadapter, duthosts, rand_one_dut_hostname, rand_selected_dut,
                                                  tbinfo, vlan_intfs_dict, duthost, ports_list,         # noqa F811
                                                  toggle_all_simulator_ports_to_rand_selected_tor_m):   # noqa F811
    """
    Test case #7
    Send qinq packets w/ src and dst specified over tagged ports in vlan
    Verify that the qinq packet is switched based on outer vlan tag + src/dst mac
    """
    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
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
                               transmit_qinq_pkt, src_port, dst_port)

        logger.info("QinQ packet switching worked successfully...")
