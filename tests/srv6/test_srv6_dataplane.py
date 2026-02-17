import pytest
import time
import random
import logging
import string

from scapy.all import Raw
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
from ptf.testutils import simple_ipv6_sr_packet, send_packet, verify_no_packet_any
from ptf.mask import Mask
from tests.srv6.srv6_utils import MySIDs, runSendReceive, verify_appl_db_sid_entry_exist, SRv6, \
    validate_techsupport_generation, validate_srv6_counters, clear_srv6_counters, \
    get_neighbor_mac, verify_asic_db_sid_entry_exist, ROUTE_BASE
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat
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


def get_ptf_src_port_and_dut_port_and_neighbor(dut, tbinfo):
    """Get the PTF port mapping for the duthost or an asic of the duthost"""
    dut_mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    ports_map = dut_mg_facts["minigraph_ptf_indices"]
    if len(ports_map) == 0:
        pytest.skip("No PTF ports found for {}".format(dut))

    lldp_table = dut.command("show lldp table")['stdout'].split("\n")[3:]
    neighbor_table = [line.split() for line in lldp_table]
    for entry in neighbor_table:
        intf = entry[0]
        if intf in ports_map:
            # Check if this interface is part of a portchannel
            ptf_ports = [ports_map[intf]]

            # Check if the interface is a member of any portchannel
            if 'minigraph_portchannels' in dut_mg_facts:
                for pc_name, pc_info in dut_mg_facts['minigraph_portchannels'].items():
                    if intf in pc_info.get('members', []):
                        # Found a portchannel - get PTF ports for all members
                        logger.info("Interface {} is a member of portchannel {}".format(intf, pc_name))
                        ptf_ports = []
                        for member in pc_info['members']:
                            if member in ports_map:
                                ptf_ports.append(ports_map[member])
                                logger.info("Added portchannel member {} with PTF port {}".format(
                                    member, ports_map[member]))
                        break

            return intf, ptf_ports, entry[1]  # local intf, ptf_src_ports (list), neighbor hostname

    pytest.skip("No active LLDP neighbor found for {}".format(dut))


def run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh):
    # Convert single port to list for uniform handling
    if isinstance(ptf_src_ports, int):
        ptf_src_ports_list = [ptf_src_ports]
    else:
        ptf_src_ports_list = ptf_src_ports

    # Use the first port for sending packets
    ptf_src_port = ptf_src_ports_list[0]

    for i in range(0, 10):
        # generate a random payload
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1",
                ipv6_dst="fcbb:bbbb:1:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6() / UDP(dport=4791) / Raw(load=payload)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                           / IPv6(src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1", dst="fcbb:bbbb:1:2::") \
                           / IPv6() / UDP(dport=4791) / Raw(load=payload)

        expected_pkt = injected_pkt.copy()
        expected_pkt['Ether'].dst = get_neighbor_mac(duthost, neighbor_ip)
        expected_pkt['Ether'].src = dut_mac
        expected_pkt['IPv6'].dst = "fcbb:bbbb:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, ptf_src_ports_list, True, ptfadapter)


@pytest.fixture()
def setup_uN(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_port_ids = []
    for interface in list(mg_facts["minigraph_ptf_indices"].keys()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        ptf_port_ids.append(port_id)

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_asic = duthost.asic_instance[asic_index]
        dut_mac = dut_asic.get_router_mac()
        dut_port, ptf_src_ports, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost._get_router_mac()
        dut_port, ptf_src_ports, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(duthost, tbinfo)

    logger.info("Doing test on DUT port {} | PTF ports {}".format(dut_port, ptf_src_ports))

    neighbor_ip = None
    # get neighbor IP
    lines = duthost.command("show ipv6 bgp sum")['stdout'].split("\n")
    for line in lines:
        if neighbor in line:
            neighbor_ip = line.split()[0]
    assert neighbor_ip, "Unable to find neighbor {} IP".format(neighbor)

    # use DUT portchannel if applicable
    pc_info = duthost.command("show int portchannel")['stdout']
    if dut_port in pc_info:
        lines = pc_info.split("\n")
        for line in lines:
            if dut_port in line:
                dut_port = line.split()[1]
                logger.info("Using portchannel interface: {}".format(dut_port))
                break

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    random.seed(time.time())
    # add the static route for IPv6 forwarding towards PTF's uSID and the blackhole route in a random order
    if random.randint(0, 1) == 0:
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                        .format(neighbor_ip, dut_port))
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
    else:
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                        .format(neighbor_ip, dut_port))
    duthost.command("config save -y")
    # Verify that the ASIC DB has the SRv6 SID entries
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB"

    setup_info = {
        "asic_index": asic_index,
        "duthost": duthost,
        "dut_mac": dut_mac,
        "dut_port": dut_port,
        "ptf_src_ports": ptf_src_ports,
        "neighbor_ip": neighbor_ip,
        "cli_options": cli_options,
        "ptf_port_ids": ptf_port_ids
    }

    yield setup_info

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb::/32")
    duthost.command("config save -y")


class SRv6Base():

    @pytest.fixture(autouse=True)
    def use_param(self, prepare_param):
        self.params = prepare_param

    def _validate_srv6_function(self, duthost, ptfadapter, dscp_mode):
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

        return srv6_pkt_list


class TestSRv6DataPlaneBase(SRv6Base):

    def test_srv6_full_func(self, config_setup, srv6_crm_total_sids,
                            setup_standby_ports_on_rand_unselected_tor,       # noqa: F811
                            toggle_all_simulator_ports_to_rand_selected_tor,  # noqa: F811
                            ptfadapter, rand_selected_dut, localhost, request, enum_frontend_asic_index):

        with allure.step('Validate SRv6 packet process'):
            srv6_pkt_list = self._validate_srv6_function(rand_selected_dut, ptfadapter, config_setup)

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
                    self._validate_srv6_function(rand_selected_dut, ptfadapter, config_setup)

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
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    dut_port = setup_uN['dut_port']
    ptf_src_ports = setup_uN['ptf_src_ports']
    neighbor_ip = setup_uN['neighbor_ip']
    ptf_port_ids = setup_uN['ptf_port_ids']

    # Use the first port to send traffic
    first_ptf_port = ptf_src_ports[0] if isinstance(ptf_src_ports, list) else ptf_src_ports

    # Verify that the ASIC DB has the SRv6 SID entries
    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB before blackhole test"

    # get the drop counter before traffic test
    if duthost.facts["asic_type"] == "broadcom":
        portstat = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])
        before_count = int(portstat[dut_port]['rx_drp'])
    elif duthost.facts["asic_type"] == "mellanox":
        before_count = int(duthost.command(f"show interfaces counters rif {dut_port}")['stdout_lines'][6].split()[0])

    # inject a number of packets with random payload
    pkt_count = 100
    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    if with_srh:
        injected_pkt = simple_ipv6_sr_packet(
            eth_dst=dut_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, first_ptf_port).decode(),
            ipv6_src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1",
            ipv6_dst="fcbb:bbbb:3:2::",
            srh_seg_left=1,
            srh_nh=41,
            inner_frame=IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1") / UDP(
                dport=4791) / Raw(load=payload)
        )
    else:
        injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, first_ptf_port).decode()) \
                       / IPv6(src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1", dst="fcbb:bbbb:3:2::") \
                       / IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1") \
                       / UDP(dport=4791) / Raw(load=payload)

    expected_pkt = injected_pkt.copy()
    expected_pkt['IPv6'].dst = "fcbb:bbbb:3:2::"
    expected_pkt['IPv6'].hlim -= 1
    logger.debug("Expected packet: {}".format(expected_pkt.summary()))

    expected_pkt = Mask(expected_pkt)
    expected_pkt.set_do_not_care_packet(Ether, "dst")
    expected_pkt.set_do_not_care_packet(Ether, "src")
    send_packet(ptfadapter, first_ptf_port, injected_pkt, count=pkt_count)
    verify_no_packet_any(ptfadapter, expected_pkt, ptf_port_ids, 0, 1)

    # verify that the RX_DROP counter is incremented
    if duthost.facts["asic_type"] == "broadcom":
        portstat = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])
        after_count = int(portstat[dut_port]['rx_drp'])
        assert after_count >= (before_count + pkt_count), "RX_DRP counter is not incremented as expected"
    elif duthost.facts["asic_type"] == "mellanox":
        after_count = int(duthost.command(f"show interfaces counters rif {dut_port}")['stdout_lines'][6].split()[0])
        assert after_count >= (before_count + pkt_count), "RIF RX_ERR counter is not incremented as expected"
