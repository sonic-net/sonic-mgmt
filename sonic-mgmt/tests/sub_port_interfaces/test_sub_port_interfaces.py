"""
Tests sub-port interfaces in SONiC.
"""

import pytest

from sub_ports_helpers import generate_and_verify_traffic

pytestmark = [
    pytest.mark.topology('t0')
]

class TestSubPorts(object):
    """
    TestSubPorts class for testing sub-port interfaces
    """

    def test_packet_routed_with_valid_vlan(self, duthost, ptfadapter, apply_config_on_the_dut, apply_config_on_the_ptf):
        """
        Validates that packet routed if sub-ports have valid VLAN ID.

        Test steps:
            1.) Setup configuration of sub-ports on the DUT.
            2.) Setup configuration of sub-ports on the PTF.
            3.) Create ICMP packet.
            4.) Send ICMP request packet from PTF to DUT.
            5.) Verify that DUT sends ICMP reply packet to PTF.
            6.) Clear configuration of sub-ports on the DUT.
            7.) Clear configuration of sub-ports on the DUT.

        Pass Criteria: PTF gets ICMP reply packet from DUT.
        """
        sub_ports = apply_config_on_the_dut['sub_ports']

        for sub_port, value in sub_ports.items():
            generate_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        src_port=value['neighbor_port'],
                                        ip_src=value['neighbor_ip'],
                                        dst_port=sub_port,
                                        ip_dst=value['ip'],
                                        pkt_action='fwd')

    def test_packet_routed_with_invalid_vlan(self, duthost, ptfadapter, apply_config_on_the_dut, apply_config_on_the_ptf):
        """
        Validates that packet aren't routed if sub-ports have invalid VLAN ID.

        Test steps:
            1.) Setup correct configuration of sub-ports on the DUT.
            2.) Setup different VLAN IDs on directly connected interfaces of sub-ports on the PTF.
            3.) Create ICMP packet.
            4.) Send ICMP request packet from PTF to DUT.
            5.) Verify that DUT doesn't sends ICMP reply packet to PTF.
            6.) Clear configuration of sub-ports on the DUT.
            7.) Clear configuration of sub-ports on the DUT.

        Pass Criteria: PTF doesn't get ICMP reply packet from DUT.
        """
        sub_ports = apply_config_on_the_dut['sub_ports']

        for sub_port, value in sub_ports.items():
            generate_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        src_port=value['neighbor_port'],
                                        ip_src=value['neighbor_ip'],
                                        dst_port=sub_port,
                                        ip_dst=value['ip'],
                                        pkt_action='drop')
