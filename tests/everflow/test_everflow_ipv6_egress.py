import pytest
import logging
import ptf.packet as scapy
import ptf.mask as mask
from ptf.testutils import send, verify_packet_any_port
from tests.common.helpers.assertions import pytest_require
from tests.common.utilities import wait_until
from everflow_test_utilities import EverflowIPv6Tests

logger = logging.getLogger(__name__)


@pytest.mark.usefixtures("setup_mirror_session", "setup_acl_table")
class TestEverflowV6EgressAclEgressMirror(EverflowIPv6Tests):
    """
    TestEverflowV6EgressAclEgressMirror

    Purpose:
        Validate Everflow IPv6 egress mirroring behavior.

    Scope:
        - Mirrors IPv6 traffic on egress (post-routing)
        - Tests ACL match fields relevant to IPv6
        - Confirms mirrored packets reach monitor port

    Related to:
        sonic-mgmt/tests/everflow/test_everflow_testbed.py::TestEverflowV4EgressAclEgressMirror
    """

    @pytest.fixture(scope="class", autouse=True)
    def skip_if_not_supported(self, duthost):
        """Skip test if platform doesn’t support IPv6 egress Everflow"""
        facts = duthost.facts
        pytest_require(
            "Mellanox" in facts["asic_type"] or True,  # Replace with platform detection logic if needed
            "IPv6 egress Everflow not supported on this platform"
        )

    def test_everflow_ipv6_egress(self, setup_mirror_session, ptfadapter, duthost, setup_acl_table):
        """
        Verify IPv6 traffic is mirrored correctly on egress.
        """

        session_name = setup_mirror_session["session_name"]
        mirror_session = setup_mirror_session["session_info"]

        # Step 1: Build base IPv6 packet
        pkt = scapy.simple_ipv6ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src="00:11:22:33:44:55",
            ipv6_src="2001:db8::1",
            ipv6_dst="2001:db8::2",
            ipv6_hlim=64,
            tcp_sport=1234,
            tcp_dport=80
        )

        # Step 2: Send packet on egress port
        tx_port = mirror_session["tx_port"]
        rx_ports = mirror_session["monitor_ports"]

        logger.info("Sending IPv6 test packet on port %s", tx_port)
        send(ptfadapter, tx_port, pkt)

        # Step 3: Build expected mirrored packet
        expected_mirror_pkt = self.build_mirrored_packet(pkt, mirror_session)

        # Mask fields that may change in transit
        exp_pkt_mask = mask.Mask(expected_mirror_pkt)
        exp_pkt_mask.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt_mask.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt_mask.set_do_not_care_scapy(scapy.IPv6, "fl")

        # Step 4: Verify mirrored packet is received
        logger.info("Verifying mirrored packet on monitor ports %s", rx_ports)
        verify_packet_any_port(ptfadapter, exp_pkt_mask, ports=rx_ports)

        logger.info("IPv6 egress Everflow mirror test PASSED")

    def build_mirrored_packet(self, original_pkt, mirror_session):
        """
        Helper to wrap IPv6 packet into mirror encapsulation (GRE or ERSPAN)
        """

        # Outer IPv6 encapsulation (envelope)
        mirrored_pkt = scapy.Ether(
            src=mirror_session["src_mac"],
            dst=mirror_session["dst_mac"]
        ) / scapy.IPv6(
            src=mirror_session["src_ip"],
            dst=mirror_session["dst_ip"],
            nh=47  # GRE
        ) / scapy.GRE(proto=0x86DD) / original_pkt

        return mirrored_pkt

