import pytest
import time
import random
import logging
import string
from scapy.all import Raw
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.testutils import simple_ipv6_sr_packet, send_packet, verify_no_packet_any
from ptf.mask import Mask
from srv6_utils import runSendReceive, verify_appl_db_sid_entry_exist, SRv6, dump_packet_detail, \
    validate_srv6_in_appl_db, validate_techsupport_generation, get_neighbor_mac
from tests.common.reboot import reboot
from tests.common.portstat_utilities import parse_portstat
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.mellanox_data import is_mellanox_device
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox", "broadcom"),
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
            return intf, ports_map[intf], entry[1]  # local intf, ptf_src_port, neighbor hostname

    pytest.skip("No active LLDP neighbor found for {}".format(dut))


def run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh):
    for i in range(0, 10):
        # generate a random payload
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfhost.mgmt_ipv6,
                ipv6_dst="fcbb:bbbb:1:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6() / UDP(dport=4791) / Raw(load=payload)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfhost.mgmt_ipv6, dst="fcbb:bbbb:1:2::") \
                / IPv6() / UDP(dport=4791) / Raw(load=payload)

        expected_pkt = injected_pkt.copy()
        expected_pkt['Ether'].dst = get_neighbor_mac(duthost, neighbor_ip)
        expected_pkt['Ether'].src = dut_mac
        expected_pkt['IPv6'].dst = "fcbb:bbbb:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)


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
        dut_port, ptf_src_port, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost._get_router_mac()
        dut_port, ptf_src_port, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(duthost, tbinfo)

    logger.info("Doing test on DUT port {} | PTF port {}".format(dut_port, ptf_src_port))

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
    time.sleep(5)

    setup_info = {
        "asic_index": asic_index,
        "duthost": duthost,
        "dut_mac": dut_mac,
        "dut_port": dut_port,
        "ptf_src_port": ptf_src_port,
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

    def _create_srv6_packet(self,
                            outer_src_mac,
                            outer_dst_mac,
                            outer_src_pkt_ip,
                            outer_dst_pkt_ip,
                            srv6_action,
                            inner_dscp,
                            outer_dscp,
                            exp_outer_dst_pkt_ip,
                            exp_seg_left,
                            exp_dscp_pipe,
                            exp_dscp_uniform,
                            seg_left,
                            sef_list,
                            inner_pkt_ver,
                            dscp_mode):

        if dscp_mode == SRv6.uniform_mode:
            exp_dscp = exp_dscp_uniform
        else:
            exp_dscp = exp_dscp_pipe

        if inner_pkt_ver == '4':
            inner_pkt = testutils.simple_tcp_packet(eth_src=self.params['router_mac'],
                                                    ip_src=self.params['inner_src_ip'],
                                                    ip_dst=self.params['inner_dst_ip'],
                                                    ip_dscp=inner_dscp if inner_dscp else 0)

            exp_inner_pkt = testutils.simple_tcp_packet(eth_src=self.params['router_mac'],
                                                        ip_src=self.params['inner_src_ip'],
                                                        ip_dst=self.params['inner_dst_ip'],
                                                        ip_dscp=exp_dscp if exp_dscp else 0)
            scapy_ver = scapy.IP
        else:
            inner_pkt = testutils.simple_tcpv6_packet(eth_src=self.params['router_mac'],
                                                      ipv6_src=self.params['inner_src_ipv6'],
                                                      ipv6_dst=self.params['inner_dst_ipv6'],
                                                      ipv6_dscp=inner_dscp if inner_dscp else 0)

            exp_inner_pkt = testutils.simple_tcpv6_packet(eth_src=self.params['router_mac'],
                                                          ipv6_src=self.params['inner_src_ipv6'],
                                                          ipv6_dst=self.params['inner_dst_ipv6'],
                                                          ipv6_dscp=exp_dscp if exp_dscp else 0)
            scapy_ver = scapy.IPv6

        if srv6_action == SRv6.uN:
            if exp_outer_dst_pkt_ip:
                if seg_left or sef_list:
                    logger.info('Create SRv6 packets with SRH')
                    srv6_pkt = testutils.simple_ipv6_sr_packet(
                        eth_dst=outer_dst_mac,
                        eth_src=outer_src_mac,
                        ipv6_src=outer_src_pkt_ip,
                        ipv6_dst=outer_dst_pkt_ip,
                        srh_seg_left=seg_left,
                        srh_seg_list=sef_list,
                        ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                        srh_nh=self.params['srv6_next_header'][scapy_ver],
                        inner_frame=inner_pkt[scapy_ver],
                    )
                    exp_pkt = testutils.simple_ipv6_sr_packet(
                        eth_dst=outer_dst_mac,
                        eth_src=outer_src_mac,
                        ipv6_src=outer_src_pkt_ip,
                        ipv6_dst=exp_outer_dst_pkt_ip,
                        srh_seg_left=exp_seg_left,
                        srh_seg_list=sef_list,
                        ipv6_tc=exp_dscp * 4 if exp_dscp else 0,
                        srh_nh=self.params['srv6_next_header'][scapy_ver],
                        inner_frame=exp_inner_pkt[scapy_ver],
                    )
                else:
                    logger.info('Create SRv6 packet with reduced SRH(no SRH header)')
                    srv6_pkt = testutils.simple_ipv6ip_packet(
                        eth_dst=outer_dst_mac,
                        eth_src=outer_src_mac,
                        ipv6_src=outer_src_pkt_ip,
                        ipv6_dst=outer_dst_pkt_ip,
                        ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                        inner_frame=inner_pkt[scapy_ver],
                    )
                    exp_pkt = testutils.simple_ipv6ip_packet(
                        eth_dst=outer_dst_mac,
                        eth_src=outer_src_mac,
                        ipv6_src=outer_src_pkt_ip,
                        ipv6_dst=exp_outer_dst_pkt_ip,
                        ipv6_tc=exp_dscp * 4 if exp_dscp else 0,
                        inner_frame=exp_inner_pkt[scapy_ver],
                    )

                exp_pkt['IPv6'].hlim -= 1
                exp_pkt = Mask(exp_pkt)

                logger.info('Do not care packet ethernet destination address')
                exp_pkt.set_do_not_care_packet(scapy.Ether, 'dst')
                logger.info('Do not care packet ethernet source address')
                exp_pkt.set_do_not_care_packet(scapy.Ether, 'src')

            else:
                if seg_left or sef_list:
                    logger.info('Create SRv6 packets with SRH for USD flavor validation')
                    srv6_pkt = testutils.simple_ipv6_sr_packet(
                        eth_dst=outer_dst_mac,
                        eth_src=outer_src_mac,
                        ipv6_src=outer_src_pkt_ip,
                        ipv6_dst=outer_dst_pkt_ip,
                        srh_seg_left=seg_left,
                        srh_seg_list=sef_list,
                        ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                        srh_nh=self.params['srv6_next_header'][scapy_ver],
                        inner_frame=inner_pkt[scapy_ver],
                    )
                else:
                    logger.info('Create SRv6 packets without SRH for USD flavor validation')
                    srv6_pkt = testutils.simple_ipv6ip_packet(
                        eth_dst=outer_dst_mac,
                        eth_src=outer_src_mac,
                        ipv6_src=outer_src_pkt_ip,
                        ipv6_dst=outer_dst_pkt_ip,
                        ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                        inner_frame=inner_pkt[scapy_ver],
                    )

                if inner_pkt_ver == '4':
                    exp_inner_pkt['IP'].ttl -= 1
                    exp_pkt = Mask(exp_inner_pkt)
                    logger.info('Do not care packet checksum')
                    exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
                else:
                    exp_inner_pkt['IPv6'].hlim -= 1
                    exp_pkt = Mask(exp_inner_pkt)
                logger.info('Do not care packet ethernet destination address')
                exp_pkt.set_do_not_care_packet(scapy.Ether, 'dst')

        return srv6_pkt, exp_pkt

    def _send_verify_srv6_packet(self,
                                 ptfadapter,
                                 pkt,
                                 exp_pkt,
                                 exp_pro,
                                 ptf_src_port_id,
                                 ptf_dst_port_ids):
        ptfadapter.dataplane.flush()
        logger.info(f'Send SRv6 packet(s) from PTF port {ptf_src_port_id} to upstream')
        testutils.send(ptfadapter, ptf_src_port_id, pkt, count=self.params['packet_num'])
        logger.info('SRv6 packet format:\n ---------------------------')
        logger.info(f'{dump_packet_detail(pkt)}\n---------------------------')
        logger.info('Expect receive SRv6 packet format:\n ---------------------------')
        logger.info(f'{dump_packet_detail(exp_pkt.exp_pkt)}\n---------------------------')

        try:
            if exp_pro == 'forward':
                port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
                logger.info(f'Received packet(s) on port {ptf_dst_port_ids[port_index]}\n')
            elif exp_pro == 'drop':
                testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
                logger.info(f'No packet received on {ptf_dst_port_ids}')
            else:
                logger.error(f'Wrong expected process result: {exp_pro}')

        except AssertionError as detail:
            raise detail

    def _validate_srv6_function(self, duthost, ptfadapter, dscp_mode):
        logger.info('Validate SRv6 table in APPL DB')
        wait_until(60, 5, 0, validate_srv6_in_appl_db, duthost)

        ptf_src_mac = ptfadapter.dataplane.get_mac(0, self.params['ptf_downlink_port']).decode('utf-8')
        for srv6_packet in self.params['srv6_packets']:
            logger.info('-------------------------------------------------------------------------')
            logger.info(f'SRv6 tunnel decapsulation mode: {dscp_mode}')
            logger.info(f'Send {self.params["packet_num"]} SRv6 packets with action: {srv6_packet["action"]}')
            logger.info(f'Pkt Src MAC: {ptf_src_mac}')
            logger.info(f'Pkt Dst MAC: {self.params["router_mac"]}')
            if srv6_packet['action'] == SRv6.uN:
                logger.info(f'Outer Pkt Src IP: {self.params["inner_src_ipv6"]}')
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

            srv6_pkt, exp_pkt = self._create_srv6_packet(outer_src_mac=ptf_src_mac,
                                                         outer_dst_mac=self.params['router_mac'],
                                                         outer_src_pkt_ip=self.params['outer_src_ipv6'],
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
                                                         dscp_mode=dscp_mode)

            self._send_verify_srv6_packet(ptfadapter=ptfadapter,
                                          pkt=srv6_pkt,
                                          exp_pkt=exp_pkt,
                                          exp_pro=srv6_packet["exp_process_result"],
                                          ptf_src_port_id=self.params['ptf_downlink_port'],
                                          ptf_dst_port_ids=self.params['ptf_uplink_ports'])


class TestSRv6Base(SRv6Base):

    def test_srv6_full_func(self, config_setup, default_tunnel_mode,
                            setup_standby_ports_on_rand_unselected_tor,       # noqa: F811
                            toggle_all_simulator_ports_to_rand_selected_tor,  # noqa: F811
                            ptfadapter, rand_selected_dut, localhost):
        with allure.step('Validate SRv6 packet process'):
            self._validate_srv6_function(rand_selected_dut, ptfadapter, config_setup)

        # TODO: WA for issue https://github.com/sonic-net/sonic-buildimage/issues/21867, remove after it is closed
        # if not is_mellanox_device(rand_selected_dut) or default_tunnel_mode == config_setup:
        #     with allure.step('Randomly choose one action from reload/cold reboot and do the action and wait'):
        #         random_reboot(rand_selected_dut, localhost)
        #
        #     with allure.step('Validate SRv6 packet process'):
        #         self._validate_srv6_function(rand_selected_dut, ptfadapter, config_setup)

        if is_mellanox_device(rand_selected_dut) and config_setup == SRv6.pipe_mode:
            with allure.step('Validate SAI SDK dump contains SRv6 information'):
                validate_techsupport_generation(rand_selected_dut, feature_list=['SRv6'])


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_config_reload(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)

    # reload the config
    duthost.command("config reload -y -f")
    time.sleep(180)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"

    # verify the forwarding works after config reload
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_bgp_restart(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)

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

    # verify the forwarding works after BGP restart
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_reboot(setup_uN, ptfadapter, ptfhost, localhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)

    # reboot DUT
    reboot(duthost, localhost, safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"

    # verify the forwarding works after reboot
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_no_sid_blackhole(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    dut_port = setup_uN['dut_port']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']
    ptf_port_ids = setup_uN['ptf_port_ids']

    # get the drop counter before traffic test
    if duthost.facts["asic_type"] == "broadcom":
        before_count = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])[dut_port]['RX_DRP']
    elif duthost.facts["asic_type"] == "mellanox":
        before_count = duthost.command(f"show interfaces counters rif {dut_port}")['stdout_lines'][6].split()[0]

    # inject a number of packets with random payload
    pkt_count = 100
    for i in range(pkt_count):
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfhost.mgmt_ipv6,
                ipv6_dst="fcbb:bbbb:3:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6) / UDP(dport=4791) / Raw(load=payload)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfhost.mgmt_ipv6, dst="fcbb:bbbb:3:2::") \
                / IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6) / UDP(dport=4791) / Raw(load=payload)

        expected_pkt = injected_pkt.copy()
        expected_pkt['IPv6'].dst = "fcbb:bbbb:3:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))

        expected_pkt = Mask(expected_pkt)
        expected_pkt.set_do_not_care_packet(Ether, "dst")
        expected_pkt.set_do_not_care_packet(Ether, "src")
        send_packet(ptfadapter, ptf_src_port, injected_pkt, 1)
        verify_no_packet_any(ptfadapter, expected_pkt, ptf_port_ids, 0, 1)

    # verify that the RX_DROP counter is incremented
    if duthost.facts["asic_type"] == "broadcom":
        after_count = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])[dut_port]['RX_DRP']
        assert after_count >= (before_count + pkt_count), "RX_DRP counter is not incremented as expected"
    elif duthost.facts["asic_type"] == "mellanox":
        after_count = duthost.command(f"show interfaces counters rif {dut_port}")['stdout_lines'][6].split()[0]
        assert after_count >= (before_count + pkt_count), "RIF RX_ERR counter is not incremented as expected"
