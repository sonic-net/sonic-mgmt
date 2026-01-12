import logging
import pytest
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

from tests.common.helpers.upgrade_helpers import install_sonic  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.reboot import reboot
from tests.common.helpers.upgrade_helpers import check_sonic_version
from tests.common.mellanox_data import is_mellanox_device
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.srv6_helper import dump_packet_detail, is_bgp_route_synced

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox"),
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

ECN_MODE_CHANGE_VERSION = "202511"
MASTER_BRANCH = "master"
RELEASE_CMD = "sonic-cfggen -y /etc/sonic/sonic_version.yml -v release"


@pytest.fixture(scope="module", autouse=True)
def skip_non_mellanox(rand_selected_dut):
    """
    The test only runs on Mellanox devices and platforms with 'mlnx' in the platform name
    """
    if not is_mellanox_device(rand_selected_dut):
        pytest.skip("This test only runs on Mellanox devices")
    if 'mlnx' not in rand_selected_dut.facts['platform']:
        pytest.skip("This test only runs on Mellanox platforms, for the platform name with 'nvidia', \
                    the default ECN mode is 'copy_from_outer'")


@pytest.fixture(scope="module", autouse=True)
def skip_unsupported_image(rand_selected_dut):
    """
    The test would skip master image due to its ecn mode is not stable and no need to test
    """
    if rand_selected_dut.sonichost.sonic_release == MASTER_BRANCH:
        pytest.skip("Skip test because the ecn_mode at master branch is not stable and no need to test")


@pytest.fixture(scope="module", autouse=True)
def restore_image(localhost, rand_selected_dut, request, tbinfo):
    restore_to_image = request.config.getoption('restore_to_image')

    yield

    if restore_to_image:
        logger.info(f"Preparing to cleanup and restore to {restore_to_image}")
        install_sonic(rand_selected_dut, restore_to_image, tbinfo)
        reboot(rand_selected_dut, localhost, safe_reboot=True)


class TestECNMode:

    PTF_QLEN = 100000
    PTF_TIMEOUT = 30
    ECN_MODE_COPY_FROM_OUTER = 'copy_from_outer'
    ECN_MODE_STANDARD = 'standard'
    PKT_NUM = 10

    @pytest.fixture(autouse=True)
    def init_param(self, prepare_param):
        self.params = prepare_param

    def create_ipip_packet(self, outer_src_mac, outer_dst_mac,
                           outer_src_ip, outer_dst_ip, outer_ecn, inner_ecn, exp_ecn,
                           inner_src_ip, inner_dst_ip):
        """
        A general way to create IP in IP packet with different IP versions

        Args:
            outer_src_mac: outer source MAC address
            outer_dst_mac: outer destination MAC address
            outer_src_ip: outer source IP address
            outer_dst_ip: outer destination IP address
            outer_ecn: outer IP ecn mode value
            inner_ecn: inner IP ecn mode value
            exp_ecn: expected decapsulated IP ecn mode value
            inner_src_ip: inner source IP address
            inner_dst_ip: inner destination IP address

        Returns:
            tuple: (outer_pkt, exp_pkt)
        """
        inner_pkt = testutils.simple_tcp_packet(
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_ecn=inner_ecn,
        )

        outer_pkt = testutils.simple_ipv4ip_packet(
            eth_src=outer_src_mac,
            eth_dst=outer_dst_mac,
            ip_src=outer_src_ip,
            ip_dst=outer_dst_ip,
            ip_ecn=outer_ecn,
            inner_frame=inner_pkt[scapy.IP]
        )

        exp_pkt = testutils.simple_tcp_packet(
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_ecn=exp_ecn,
        )

        exp_pkt = Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(scapy.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(scapy.IP, 'id')
        exp_pkt.set_do_not_care_scapy(scapy.IP, 'ttl')
        exp_pkt.set_do_not_care_scapy(scapy.IP, 'chksum')

        return outer_pkt, exp_pkt

    def send_verify_ipinip_packet(
            self,
            ptfadapter,
            pkt,
            exp_pkt,
            ptf_src_port_id,
            ptf_dst_port_ids,
            packet_num=PKT_NUM):
        """
        Send and verify IP in IP packets

        Args:
            ptfadapter: PTF adapter object
            pkt: Packet to send
            exp_pkt: Expected packet
            ptf_src_port_id (int): Source PTF port ID
            ptf_dst_port_ids (list): List of destination PTF port IDs
            packet_num (int): Number of packets to send (default: PKT_NUM)
        """
        ptfadapter.dataplane.flush()
        ptfadapter.dataplane.set_qlen(self.PTF_QLEN)
        logger.info(f'Send IPinIP packet(s) from PTF port {ptf_src_port_id} to upstream')
        testutils.send(ptfadapter, ptf_src_port_id, pkt, count=packet_num)
        logger.info('IPinIP packet format:\n ---------------------------')
        logger.info(f'{dump_packet_detail(pkt)}\n---------------------------')
        logger.info('Expect decapsulated IPinIP packet format:\n ---------------------------')
        logger.info(f'{dump_packet_detail(exp_pkt.exp_pkt)}\n---------------------------')

        try:
            port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_pkt, timeout=self.PTF_TIMEOUT,
                                                             ports=ptf_dst_port_ids)
            logger.info(f'Received packet(s) on port {ptf_dst_port_ids[port_index]}\n')
        except AssertionError as detail:
            raise detail

    def check_ecn_mode_in_appl_db(self, duthost, exp_ecn_mode):
        tunnel_type = duthost.shell('sonic-db-cli APPL_DB hget "TUNNEL_DECAP_TABLE:IPINIP_TUNNEL" "ecn_mode"')["stdout"]
        if tunnel_type != exp_ecn_mode:
            return False
        return True

    def verify_ecn_mode(self, duthost, ptfadapter, exp_ecn_mode):
        with allure.step("Generate expected ecn_mode value"):
            if exp_ecn_mode == self.ECN_MODE_COPY_FROM_OUTER:
                exp_ecn = self.params['outer_ecn']
            elif exp_ecn_mode == self.ECN_MODE_STANDARD:
                exp_ecn = max(self.params['inner_ecn'], self.params['outer_ecn'])
            else:
                raise ValueError(f"Invalid ECN mode: {exp_ecn_mode}")

        with allure.step(f"Verify IP in IP tunnel ecn mode is {exp_ecn_mode}"):
            pytest_assert(wait_until(60, 5, 0, self.check_ecn_mode_in_appl_db, duthost, exp_ecn_mode),
                          f"IP in IP tunnel ecn mode is not {exp_ecn_mode}")

        with allure.step("Generate IP in IP packet"):
            pkt, exp_pkt = self.create_ipip_packet(outer_src_mac=self.params['outer_src_mac'],
                                                   outer_dst_mac=self.params['outer_dst_mac'],
                                                   outer_src_ip=self.params['outer_src_ip'],
                                                   outer_dst_ip=self.params['outer_dst_ip'],
                                                   outer_ecn=self.params['outer_ecn'],
                                                   inner_ecn=self.params['inner_ecn'],
                                                   exp_ecn=exp_ecn,
                                                   inner_src_ip=self.params['inner_src_ip'],
                                                   inner_dst_ip=self.params['inner_dst_ip'])

        with allure.step("Send and verify IP in IP packet"):
            self.send_verify_ipinip_packet(ptfadapter=ptfadapter,
                                           pkt=pkt,
                                           exp_pkt=exp_pkt,
                                           ptf_src_port_id=self.params['ptf_downlink_port'],
                                           ptf_dst_port_ids=self.params['ptf_uplink_ports'])

    def _check_bgp_route(self, duthost):
        with allure.step('Validate BGP docker UP'):
            pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"),
                          "BGP not started.")

        with allure.step('Validate BGP route sync finished'):
            pytest_assert(wait_until(120, 5, 0, is_bgp_route_synced, duthost), "BGP route is not synced")

    def test_ecn_mode(self, rand_selected_dut, localhost, ptfadapter, tbinfo):  # noqa: F811
        """
        Test ECN mode before and after upgrade

        Args:
            duthost: DUT host object
            localhost: Localhost object
            ptfadapter: PTF adapter object
            tbinfo: Testbed information
        """
        if self.params['from_list']:

            with allure.step(f"Boot into base image {self.params['from_list']}"):
                target_version = install_sonic(rand_selected_dut, self.params['from_list'], tbinfo)
                reboot(rand_selected_dut, localhost, safe_reboot=True)
                check_sonic_version(rand_selected_dut, target_version)

        if self.params['to_list']:

            with allure.step(f"Install target image {self.params['to_list']}"):
                install_sonic(rand_selected_dut, self.params['to_list'], tbinfo)

            with allure.step("Upgrade to target image by warm reboot"):
                reboot(rand_selected_dut, localhost, reboot_type="warm", safe_reboot=True, check_intf_up_ports=True,
                       wait_for_bgp=True, wait_warmboot_finalizer=True)

        with allure.step("Check BGP route"):
            self._check_bgp_route(rand_selected_dut)

        with allure.step("Get the base SONiC branch"):
            current_branch = rand_selected_dut.command(RELEASE_CMD)['stdout_lines'][0].strip()

        if current_branch:
            if current_branch != "none" and current_branch != MASTER_BRANCH:
                with allure.step("Verify ECN mode"):
                    if current_branch < ECN_MODE_CHANGE_VERSION:
                        self.verify_ecn_mode(rand_selected_dut, ptfadapter, self.ECN_MODE_STANDARD)
                    else:
                        self.verify_ecn_mode(rand_selected_dut, ptfadapter, self.ECN_MODE_COPY_FROM_OUTER)
            else:
                pytest.skip("Skip test because the ecn_mode at master branch is not stable and no need to test")
        else:
            raise ValueError(f"Failed to get SONiC branch : {current_branch}")
