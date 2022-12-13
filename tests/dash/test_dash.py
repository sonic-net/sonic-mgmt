import logging
import pytest

import ptf.packet as scapy
from ptf.mask import Mask
import ptf.testutils as testutils

from constants import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

@pytest.fixture(scope="module")
def dash_configure(duthosts, enum_frontend_dut_hostname, skip_config):
    """
    Prepares DUT hosts for testing

    Args:
        duthost: DUT host object
    """
    if skip_config:
        logger.info("Skipping DASH configuration")
        return

    duthost = duthosts[enum_frontend_dut_hostname]
    dut_facts = duthost.facts
    # copy_dut_config_files(duthost)
    # apply_dut_config_files(duthost)
    # yield
    # Remove when inbound/outbound routing deletes are supported
    # remove_dut_config_files(duthost)


class DashTest:
    def __init__(self):
        self.ptf_ports = []


    def runTestInboundPaValidate(self, ptfadapter):
        inner_packet = testutils.simple_udp_packet(
                                    eth_src="F9:22:83:99:22:A2",
                                    eth_dst="F4:93:9F:EF:C4:7E",
                                    ip_src="20.2.2.2",
                                    ip_dst="11.1.1.1",
                                    ip_ttl=64,
                                    ip_ihl=5,
                                    with_udp_chksum=False,
                                    udp_payload=None)

        vxlan_packet = testutils.simple_vxlan_packet(
                                    eth_src="4E:E0:F6:98:88:DD",
                                    eth_dst="08:C0:EB:20:38:14",
                                    ip_dst="10.1.0.32",
                                    ip_src="10.0.2.2",
                                    with_udp_chksum=False,
                                    vxlan_vni=2000,
                                    ip_ttl=64,
                                    ip_id=0,
                                    udp_sport=5000,
                                    vxlan_reserved1=0,
                                    vxlan_reserved2=0,
                                    ip_flags=0x2,
                                    inner_frame=inner_packet)

        expected_packet = testutils.simple_vxlan_packet(
                                    eth_src="08:C0:EB:20:38:EC",
                                    eth_dst="CE:5C:FD:76:41:D6",
                                    ip_dst="10.0.1.2",
                                    ip_src="10.1.0.32",
                                    ip_ttl=0,
                                    ip_id=0,
                                    vxlan_vni=4321,
                                    vxlan_reserved1=0,
                                    vxlan_reserved2=0,
                                    ip_flags=0x0,
                                    inner_frame=inner_packet)

        logger.info("Sending VxLAN encapped packet")
        testutils.send(ptfadapter, 1, vxlan_packet, 1)
        logger.info("expected_packet")
        logger.info(testutils.inspect_packet(expected_packet))
        masked_exp_packet = Mask(expected_packet)
        masked_exp_packet.set_do_not_care_scapy(scapy.Ether, "len")
        masked_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_packet.set_do_not_care_scapy(scapy.IP, "options")
        masked_exp_packet.set_do_not_care_scapy(scapy.IP, "len")
        masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
        masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")
        masked_exp_packet.set_do_not_care_scapy(scapy.VXLAN, "flags")
        masked_exp_packet.set_ignore_extra_bytes()
        testutils.verify_packet(ptfadapter, masked_exp_packet, 0)


    def runTestOutboundVnet(self, ptfadapter, outbound_vnet_packets):
        inner_packet = testutils.simple_udp_packet(
                                    eth_src="F4:93:9F:EF:C4:7E",
                                    eth_dst="F9:22:83:99:22:A2",
                                    ip_dst="20.2.2.2",
                                    ip_src="11.1.1.1",
                                    ip_ttl=64,
                                    ip_ihl=5,
                                    ip_id=1,
                                    with_udp_chksum=False,
                                    udp_payload=None)

        vxlan_packet = testutils.simple_vxlan_packet(
                                    eth_src="ce:5c:fd:76:41:d6",
                                    eth_dst="08:c0:eb:20:38:ec",
                                    ip_dst="10.1.0.32",
                                    ip_src="10.0.1.2",
                                    with_udp_chksum=False,
                                    vxlan_vni=4321,
                                    ip_ttl=64,
                                    ip_id=0,
                                    udp_sport=5000,
                                    vxlan_reserved1=0,
                                    vxlan_reserved2=0,
                                    ip_flags=0x2,
                                    inner_frame=inner_packet)

        expected_packet = testutils.simple_vxlan_packet(
                                    eth_src="08:c0:eb:20:38:ec",
                                    eth_dst="4e:e0:f6:98:88:dd",
                                    ip_dst="10.0.2.2",
                                    ip_src="10.1.0.32",
                                    vxlan_vni=2000,
                                    ip_ttl=0,
                                    ip_id=0,
                                    vxlan_reserved1=0,
                                    vxlan_reserved2=0,
                                    ip_flags=0x0,
                                    inner_frame=inner_packet)

        logger.info("Sending VxLAN encapped packet")
        import pdb; pdb.set_trace()
        testutils.send(ptfadapter, 0, vxlan_packet, 1)
        masked_exp_packet = Mask(expected_packet)
        masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
        masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")
        # masked_exp_packet.set_ignore_extra_bytes()
        testutils.verify_packet(ptfadapter, masked_exp_packet, 1)

# @pytest.fixture
# def inbound_vnet_packets(dash_config_info):

@pytest.fixture
def outbound_vnet_packets(dash_config_info):
    inner_packet = testutils.simple_udp_packet(
        eth_src=dash_config_info[LOCAL_ENI_MAC],
        eth_dst=dash_config_info[REMOTE_ENI_MAC],
        ip_dst=dash_config_info[REMOTE_CA_IP],
        ip_src=dash_config_info[LOCAL_CA_IP],
        ip_ttl=64,
        ip_ihl=5,
        ip_id=1,
        with_udp_chksum=False,
        udp_payload=None
    )

    vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[LOCAL_PTF_MAC],
        eth_dst=dash_config_info[DUT_MAC],
        ip_dst=dash_config_info[LOOPBACK_IP],
        ip_src=dash_config_info[LOCAL_PA_IP],
        with_udp_chksum=False,
        vxlan_vni=dash_config_info[VM_VNI],
        ip_ttl=64,
        ip_id=0,
        udp_sport=5000,
        vxlan_reserved1=0,
        vxlan_reserved2=0,
        ip_flags=0x2,
        inner_frame=inner_packet
    )

    expected_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[DUT_MAC],
        eth_dst=dash_config_info[REMOTE_PTF_MAC],
        ip_dst=dash_config_info[REMOTE_PA_IP],
        ip_src=dash_config_info[LOOPBACK_IP],
        vxlan_vni=dash_config_info[VNET2_VNI],
        ip_ttl=0,
        ip_id=0,
        vxlan_reserved1=0,
        vxlan_reserved2=0,
        ip_flags=0x0,
        inner_frame=inner_packet
    )
    masked_exp_packet = Mask(expected_packet)
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")
    return inner_packet, vxlan_packet, masked_exp_packet

def test_outbound_vnet(ptfadapter, apply_vnet_configs, outbound_vnet_packets, dash_config_info):
    _, vxlan_packet, expected_packet = outbound_vnet_packets
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[REMOTE_PTF_INTF])
    

def test_dash(apply_vnet_configs, outbound_vnet_packets, dash_config_info, duthosts, ptfadapter, enum_frontend_dut_hostname, config_only):
    """
    Test case for DASH

    Args:
        duthosts: DUT host object
        dash_configure: Pytest fixture that sets up DUT hosts
    """
    logger.info("Starting DASH test")

    if config_only:
        logger.info("Skipping DASH traffic tests")
        return

    dTest = DashTest()
    dTest.runTestInboundPaValidate(ptfadapter)
