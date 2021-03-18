"""
Tests sub-port interfaces in SONiC.
"""

import random
import pytest

from tests.common.helpers.assertions import pytest_assert
from sub_ports_helpers import generate_and_verify_traffic
from sub_ports_helpers import get_port_mtu
from sub_ports_helpers import shutdown_port
from sub_ports_helpers import startup_port
from sub_ports_helpers import setup_vlan
from sub_ports_helpers import remove_vlan
from sub_ports_helpers import check_sub_port

pytestmark = [
    pytest.mark.topology('t0', 't1')
]

class TestSubPorts(object):
    """
    TestSubPorts class for testing sub-port interfaces
    """

    def test_packet_routed_with_valid_vlan(self, duthost, ptfhost, ptfadapter, apply_config_on_the_dut, apply_config_on_the_ptf):
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
            5.) Verify that DUT doesn't send ICMP reply packet to PTF.
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


    def test_admin_status_down_disables_forwarding(self, duthost, ptfadapter, apply_config_on_the_dut, apply_config_on_the_ptf):
        """
        Validates that admin status DOWN disables packet forwarding.

        Test steps:
            1.) Setup configuration of sub-ports on the DUT.
            2.) Setup configuration of sub-ports on the PTF.
            3.) Shutdown sub-ports on the DUT
            4.) Create ICMP packet.
            5.) Send ICMP request packet from PTF to DUT.
            6.) Verify that DUT doesn't send ICMP reply packet to PTF.
            7.) Create ICMP packet.
            8.) Send ICMP request packet from PTF to another sub-port of DUT.
            9.) Verify that DUT sends ICMP reply packet to PTF.
            10.) Startup sub-port on the DUT
            11.) Create ICMP packet.
            12.) Send ICMP request packet from PTF to DUT.
            13.) Verify that DUT sends ICMP reply packet to PTF.
            14.) Clear configuration of sub-ports on the DUT.
            15.) Clear configuration of sub-ports on the PTF.

        Pass Criteria: PTF doesn't get ICMP reply packet from disabled sub-ports of DUT.
        """
        sub_ports = apply_config_on_the_dut['sub_ports']

        for sub_port, value in sub_ports.items():
            shutdown_port(duthost, sub_port)
            generate_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        src_port=value['neighbor_port'],
                                        ip_src=value['neighbor_ip'],
                                        dst_port=sub_port,
                                        ip_dst=value['ip'],
                                        pkt_action='drop')

            for next_sub_port, next_value in sub_ports.items():
                if next_sub_port != sub_port:
                    generate_and_verify_traffic(duthost=duthost,
                                                ptfadapter=ptfadapter,
                                                src_port=next_value['neighbor_port'],
                                                ip_src=next_value['neighbor_ip'],
                                                dst_port=next_sub_port,
                                                ip_dst=next_value['ip'],
                                                pkt_action='fwd')

            startup_port(duthost, sub_port)
            generate_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        src_port=value['neighbor_port'],
                                        ip_src=value['neighbor_ip'],
                                        dst_port=sub_port,
                                        ip_dst=value['ip'],
                                        pkt_action='fwd')


    def test_max_numbers_of_sub_ports(self, duthost, ptfadapter, apply_config_on_the_dut, apply_config_on_the_ptf):
        """
        Validates that 256 sub-ports can be created per port or LAG

        Test steps:
            1.) Setup configuration of 256 sub-ports on the DUT.
            2.) Setup configuration of 256 sub-ports on the PTF.
            3.) Create ICMP packet.
            4.) Send ICMP request packet from PTF to DUT.
            5.) Verify that DUT sends ICMP reply packet to PTF.
            6.) Clear configuration of sub-ports on the DUT.
            7.) Clear configuration of sub-ports on the PTF.

        Pass Criteria: PTF gets ICMP reply packet from DUT.

        Note:
            The running of the test case takes about 80 minutes.
        """
        sub_ports_new = dict()
        sub_ports = apply_config_on_the_dut['sub_ports']
        sub_ports_new[sub_ports.keys()[0]] = sub_ports[sub_ports.keys()[0]]
        sub_ports_new[sub_ports.keys()[-1]] = sub_ports[sub_ports.keys()[-1]]

        rand_sub_ports = sub_ports.keys()[random.randint(1, len(sub_ports)-1)]
        sub_ports_new[rand_sub_ports] = sub_ports[rand_sub_ports]

        for sub_port, value in sub_ports_new.items():
            generate_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        src_port=value['neighbor_port'],
                                        ip_src=value['neighbor_ip'],
                                        dst_port=sub_port,
                                        ip_dst=value['ip'],
                                        pkt_action='fwd')


    def test_mtu_inherited_from_parent_port(self, duthost, apply_config_on_the_dut, apply_config_on_the_ptf):
        """
        Validates that MTU settings of sub-ports inherited from parent port

        Test steps:
            1.) Setup correct configuration of sub-ports on the DUT.
            3.) Get MTU value of sub-port
            4.) Get MTU value of parent port
            6.) Clear configuration of sub-ports on the DUT.

        Pass Criteria: MTU settings of sub-ports inherited from parent port.
        """
        sub_ports = apply_config_on_the_dut['sub_ports']

        for sub_port in sub_ports.keys():
            sub_port_mtu = int(get_port_mtu(duthost, sub_port))
            # Get name of parent port from name of sub-port
            port = sub_port.split('.')[0]
            port_mtu = int(get_port_mtu(duthost, port))

            pytest_assert(sub_port_mtu == port_mtu, "MTU of {} doesn't inherit MTU of {}".format(sub_port, port))


    def test_vlan_config_impact(self, duthost, ptfadapter, apply_config_on_the_dut, apply_config_on_the_ptf):
        """
        Validates that removal of VLAN doesn't impact sub-port RIF with same VLAN ID.

        Test steps:
            1.) Setup correct configuration of sub-ports on the DUT.
            3.) Create a VLAN RIF with the same VLAN ID of sub-port.
            4.) Added PortChannel interface to VLAN members.
            5.) Delete a VLAN RIF.
            6.) Make sure sub-port is available in redis-db.
            7.) Verify that DUT sends ICMP reply packet to PTF.
            8.) Clear configuration of sub-ports on the DUT.
            9.) Clear configuration of sub-ports on the PTF.

        Pass Criteria:
            1.) Sub-port is available in redis-db.
            2.) PTF gets ICMP reply packet from DUT.
        """
        sub_ports = apply_config_on_the_dut['sub_ports']

        for sub_port, value in sub_ports.items():
            # Get VLAN ID from name of sub-port
            vlan_vid = int(sub_port.split('.')[1])
            # Create a VLAN RIF
            setup_vlan(duthost, vlan_vid)
            # Delete a VLAN RIF
            remove_vlan(duthost, vlan_vid)

            pytest_assert(check_sub_port(duthost, sub_port), "Sub-port {} was deleted".format(sub_port))

            generate_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        src_port=value['neighbor_port'],
                                        ip_src=value['neighbor_ip'],
                                        dst_port=sub_port,
                                        ip_dst=value['ip'],
                                        pkt_action='fwd')
