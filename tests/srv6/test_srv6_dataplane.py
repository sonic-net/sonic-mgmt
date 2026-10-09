import pytest
import time
import random
import logging

from tests.srv6.srv6_utils import MySIDs, verify_appl_db_sid_entry_exist, SRv6, \
    validate_techsupport_generation, validate_srv6_counters, clear_srv6_counters, \
    get_neighbor_mac, verify_asic_db_sid_entry_exist, ROUTE_BASE, run_srv6_traffic_test, \
    run_srv6_no_sid_blackhole_test
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.mellanox_data import is_mellanox_device
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401
from tests.common.helpers.srv6_helper import create_srv6_packet, send_verify_srv6_packet, \
    validate_srv6_in_appl_db, validate_srv6_in_asic_db, validate_srv6_route, is_bgp_route_synced

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox", "broadcom", "vpp"),
    pytest.mark.topology("t0", "t1")
]


class SRv6Base():

    @pytest.fixture(autouse=True)
    def use_param(self, prepare_param):
        self.params = prepare_param

    def _validate_srv6_function(self, duthost, ptfadapter, dscp_mode, weak_server):
        srv6_pkt_list = []
        logger.info('Clear the SRv6 counters')
        clear_srv6_counters(duthost)

        logger.info('Validate SRv6 table in APPL DB')
        pytest_assert(wait_until(60, 5, 0, validate_srv6_in_appl_db, duthost, MySIDs.MY_SID_LIST),
                      "SRv6 table in APPL DB is not as expected")

        logger.info('Validate SRv6 table in ASIC DB')
        pytest_assert(wait_until(60, 5, 0, validate_srv6_in_asic_db, duthost, MySIDs.MY_SID_LIST),
                      "SRv6 table in ASIC DB is not as expected")

        logger.info('Validate SRv6 route in ASIC DB')
        pytest_assert(wait_until(120, 5, 0, validate_srv6_route, duthost, ROUTE_BASE),
                      "SRv6 route in ASIC DB is not as expected")

        delay_interval = 0
        if weak_server:
            delay_interval = 0.4
            self.params['packet_num'] = 10
        ptf_src_mac = ptfadapter.dataplane.get_mac(0, self.params['ptf_downlink_port']).decode('utf-8')
        for srv6_packet in self.params['srv6_packets']:
            if duthost.facts["asic_type"] == "broadcom" and \
               (srv6_packet['srh_seg_left'] or srv6_packet['srh_seg_list']):
                logger.info("Skip the test for Broadcom ASIC with SRH")
                continue

            if duthost.facts["asic_type"] == "vpp" and \
               (srv6_packet['validate_usd_flavor']):
                logger.info("Skip the test for VPP with USD flavor.")
                continue

            logger.info('-------------------------------------------------------------------------')
            if srv6_packet['validate_dip_shift']:
                logger.info('Validate DIP shift')
            if srv6_packet['validate_usd_flavor']:
                logger.info('Validate USD flavor')
            logger.info(f'SRv6 tunnel decapsulation mode: {dscp_mode}')
            logger.info(f'Send {self.params["packet_num"]} SRv6 packets with action: {srv6_packet["action"]}')
            logger.info(f'Pkt Src MAC: {ptf_src_mac}')
            logger.info(f'Pkt Dst MAC: {self.params["router_mac"]}')
            if srv6_packet['action'] == SRv6.uN:
                logger.info(f'Outer Pkt Src IP: {srv6_packet["outer_src_ipv6"]}')
                logger.info(f'Outer Pkt Dst IP: {srv6_packet["dst_ipv6"]}')
                if srv6_packet["exp_dst_ipv6"]:
                    logger.info(f'Expect Outer Pkt Dst IP: {srv6_packet["exp_dst_ipv6"]}')
            if dscp_mode == SRv6.uniform_mode:
                if srv6_packet['outer_dscp']:
                    logger.info(f'Outer DSCP value: {srv6_packet["outer_dscp"]}')
                if srv6_packet['exp_outer_dscp_uniform']:
                    logger.info(f'Expect inner DSCP value: {srv6_packet["exp_outer_dscp_uniform"]}')
            else:
                if srv6_packet['inner_dscp']:
                    logger.info(f'Inner DSCP value: {srv6_packet["inner_dscp"]}')
                if srv6_packet['exp_inner_dscp_pipe']:
                    logger.info(f'Expect inner DSCP value: {srv6_packet["exp_inner_dscp_pipe"]}')
            logger.info(f'SRH Segment List: {srv6_packet["srh_seg_list"]}')
            logger.info(f'SRH Segment Left: {srv6_packet["srh_seg_left"]}')

            logger.info(f'Expect Segment Left: {srv6_packet["exp_srh_seg_left"]}')
            logger.info(f'Expect process result: {srv6_packet["exp_process_result"]}')
            logger.info('-------------------------------------------------------------------------')

            srv6_pkt, exp_pkt = create_srv6_packet(
                outer_src_mac=ptf_src_mac,
                outer_dst_mac=self.params['router_mac'],
                outer_src_pkt_ip=srv6_packet['outer_src_ipv6'],
                outer_dst_pkt_ip=srv6_packet['dst_ipv6'],
                srv6_action=srv6_packet['action'],
                inner_dscp=srv6_packet['inner_dscp'],
                outer_dscp=srv6_packet['outer_dscp'],
                exp_outer_dst_pkt_ip=srv6_packet['exp_dst_ipv6'],
                exp_seg_left=srv6_packet['exp_srh_seg_left'],
                exp_dscp_pipe=srv6_packet['exp_inner_dscp_pipe'],
                exp_dscp_uniform=srv6_packet['exp_outer_dscp_uniform'],
                seg_left=srv6_packet['srh_seg_left'],
                sef_list=srv6_packet['srh_seg_list'],
                inner_pkt_ver=srv6_packet['inner_pkt_ver'],
                dscp_mode=dscp_mode,
                router_mac=self.params['router_mac'],
                inner_src_ip=srv6_packet['inner_src_ip'],
                inner_dst_ip=srv6_packet['inner_dst_ip'],
                inner_src_ipv6=srv6_packet['inner_src_ipv6'],
                inner_dst_ipv6=srv6_packet['inner_dst_ipv6']
            )

            send_verify_srv6_packet(
                ptfadapter=ptfadapter,
                pkt=srv6_pkt,
                exp_pkt=exp_pkt,
                exp_pro=srv6_packet["exp_process_result"],
                ptf_src_port_id=self.params['ptf_downlink_port'],
                ptf_dst_port_ids=self.params['ptf_uplink_ports'],
                packet_num=self.params['packet_num']
            )

            srv6_pkt_list.append(srv6_pkt)
            time.sleep(delay_interval)

        return srv6_pkt_list


class TestSRv6DataPlaneBase(SRv6Base):

    @pytest.mark.enable_monit_refresh
    def test_srv6_full_func(self, config_setup, srv6_crm_total_sids,
                            setup_standby_ports_on_rand_unselected_tor,       # noqa: F811
                            toggle_all_simulator_ports_to_rand_selected_tor,  # noqa: F811
                            ptfadapter, rand_selected_dut, localhost, request, enum_frontend_asic_index, weak_server):

        with allure.step('Validate SRv6 packet process'):
            srv6_pkt_list = self._validate_srv6_function(rand_selected_dut, ptfadapter, config_setup, weak_server)

        with allure.step('Validate SRv6 counters'):
            pytest_assert(wait_until(60, 5, 0, validate_srv6_counters, rand_selected_dut, srv6_pkt_list,
                                     MySIDs.MY_SID_LIST, self.params['packet_num']),
                          "SRv6 counters are not as expected")

        if random.random() < 0.5:

            with allure.step('Execute reboot test'):
                reboot_type = request.config.getoption("--srv6_reboot_type")

                if reboot_type == "random":
                    reboot_type = random.choice(["cold", "reload", "bgp"])

                if reboot_type == "cold":
                    with allure.step('Execute cold reboot'):
                        reboot(rand_selected_dut, localhost, reboot_type=reboot_type, wait_warmboot_finalizer=True,
                               safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)
                elif reboot_type == "reload":
                    with allure.step('Execute config reload'):
                        config_reload(rand_selected_dut, safe_reload=True, check_intf_up_ports=True)
                else:
                    with allure.step('Execute BGP restart'):
                        if rand_selected_dut.is_multi_asic:
                            rand_selected_dut.command(
                                f"systemctl restart bgp@{enum_frontend_asic_index}")
                        else:
                            rand_selected_dut.command("systemctl restart bgp")

                with allure.step('Validate BGP docker UP'):
                    pytest_assert(wait_until(100, 10, 0, rand_selected_dut.is_service_fully_started_per_asic_or_host,
                                             "bgp"),
                                  "BGP not started.")

                with allure.step('Validate BGP route sync'):
                    pytest_assert(wait_until(120, 5, 0, is_bgp_route_synced,
                                             rand_selected_dut), "BGP route is not synced")

                with allure.step('Validate SRv6 packet process'):
                    self._validate_srv6_function(rand_selected_dut, ptfadapter, config_setup, weak_server)

                with allure.step('Validate SRv6 counters'):
                    pytest_assert(wait_until(60, 5, 0, validate_srv6_counters, rand_selected_dut, srv6_pkt_list,
                                             MySIDs.MY_SID_LIST, self.params['packet_num']),
                                  "SRv6 counters are not as expected")

            if is_mellanox_device(rand_selected_dut) and config_setup == SRv6.pipe_mode:
                with allure.step('Validate SAI SDK dump contains SRv6 information'):
                    validate_techsupport_generation(rand_selected_dut, feature_list=['SRv6'])


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_config_reload(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_ports = setup_uN['ptf_src_ports']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)

    # reload the config
    duthost.command("config reload -y -f")
    time.sleep(180)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"
    # Verify that the ASIC DB has the SRv6 SID entries
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB after config reload"

    pytest_assert(wait_until(60, 5, 0, is_bgp_route_synced, duthost), "BGP route is not synced")

    pytest_assert(wait_until(60, 5, 0, get_neighbor_mac, duthost, neighbor_ip),
                  "IP table not updating MAC for neighbour")

    # verify the forwarding works after config reload
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_bgp_restart(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_ports = setup_uN['ptf_src_ports']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)

    # restart BGP service, which will restart the BGP container
    if duthost.is_multi_asic:
        duthost.command("systemctl restart bgp@{}".format(setup_uN['asic_index']))
    else:
        duthost.command("systemctl restart bgp")
    time.sleep(180)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"
    # Verify that the ASIC DB has the SRv6 SID entries
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB after BGP restart"

    pytest_assert(wait_until(60, 5, 0, is_bgp_route_synced, duthost), "BGP route is not synced")
    # verify the forwarding works after BGP restart
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_reboot(setup_uN, ptfadapter, ptfhost, localhost, with_srh, loganalyzer):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_ports = setup_uN['ptf_src_ports']
    neighbor_ip = setup_uN['neighbor_ip']

    # Reloading the configuration will restart eth0 and update the TACACS settings.
    # This change may introduce a delay, potentially causing temporary TACACS reporting errors.
    if loganalyzer and duthost.hostname and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend([r".*tac_connect_single: .*",
                                                           r".*nss_tacplus: .*"])

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)

    # reboot DUT
    reboot(duthost, localhost, wait=300, safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"
    # Verify that the ASIC DB has the SRv6 SID entries
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB after reboot"

    pytest_assert(wait_until(60, 5, 0, is_bgp_route_synced, duthost), "BGP route is not synced")
    # verify the forwarding works after reboot
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_no_sid_blackhole(setup_uN, ptfadapter, ptfhost, with_srh):
    run_srv6_no_sid_blackhole_test(setup_uN, ptfadapter, ptfhost, with_srh)
