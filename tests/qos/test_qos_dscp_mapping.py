"""
Test cases for testing DSCP to Queue mapping for IP-IP packets in SONiC.
"""
import time
import logging
import pytest
import allure
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf import mask
from scapy.all import Ether, IP
from tabulate import tabulate
from tests.common.reboot import reboot

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, select_random_link, \
    get_stream_ptf_ports, get_dut_pair_port_from_ptf_port, apply_dscp_cfg_setup, apply_dscp_cfg_teardown  # noqa F401
from tests.common.utilities import get_ipv4_loopback_ip, get_dscp_to_queue_value, find_egress_queue, \
    get_egress_queue_pkt_count_all_port_prio, wait_until, get_vlan_from_port
from tests.common.helpers.assertions import pytest_assert
from tests.qos.qos_helpers import get_upstream_exabgp_port, announce_route
from tests.common.fixtures.duthost_utils import dut_qos_maps_module  # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1')
]

DEFAULT_MAPPING_TYPE = "AZURE"
DEFAULT_DSCP = 4
DEFAULT_TTL = 64
DEFAULT_ECN = 1
DEFAULT_PKT_COUNT = 500
BASE_EXABGP_PORT = 5000
WITHDRAW = 'withdraw'
ANNOUNCE = 'announce'
DUMMY_OUTER_SRC_IP = '8.8.8.8'
DUMMY_INNER_SRC_IP = '9.9.9.9'
INNER_DST_IP_PREFIX = '10.10.10.'
output_table = []
packet_egressed_success = []


def pytest_generate_tests(metafunc):
    if "dscp_mode" in metafunc.fixturenames:
        metafunc.parametrize("dscp_mode", ["uniform", "pipe"])


@pytest.fixture(scope='module')
def completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope='module')
def route_config(nbrhosts, tbinfo):
    ptf_ip = tbinfo['ptf_ip']
    upstream_exabgp_port_list = get_upstream_exabgp_port(nbrhosts=nbrhosts,
                                                         tbinfo=tbinfo,
                                                         exabgp_base_port=BASE_EXABGP_PORT)
    upstream_vm_num = len(upstream_exabgp_port_list)
    inner_dst_ip_list = [INNER_DST_IP_PREFIX + str(i + 1) for i in range(upstream_vm_num)]

    for i in range(upstream_vm_num):
        logger.info(f"{ANNOUNCE} {inner_dst_ip_list[i] + '/32'} from upstream VMs")
        announce_route(ptfip=ptf_ip,
                       route=inner_dst_ip_list[i] + '/32',
                       port=upstream_exabgp_port_list[i])

    yield inner_dst_ip_list

    for i in range(upstream_vm_num):
        logger.info(f"{WITHDRAW} {inner_dst_ip_list[i] + '/32'} from upstream VMs")
        announce_route(ptfip=ptf_ip,
                       route=inner_dst_ip_list[i] + '/32',
                       port=upstream_exabgp_port_list[i],
                       action=WITHDRAW)


@pytest.fixture(scope='function')
def dscp_config(dscp_mode, duthost, loganalyzer):
    """
    Test setup and teardown

    Args:
        request: pytest request
        duthost (AnsibleHost): The DUT host
    """
    is_global_map_key_exist = duthost.shell('redis-cli -n 4 -c KEYS "PORT_QOS_MAP|global"')["stdout"]
    if is_global_map_key_exist:
        origin_dscp_to_tc_map = duthost.shell('redis-cli -n 4 -c HGET "PORT_QOS_MAP|global" "dscp_to_tc_map"')["stdout"]
        logger.info(f"Original dscp_to_tc_map: {origin_dscp_to_tc_map}")

    logger.info(f"Set dscp_to_tc_map to {DEFAULT_MAPPING_TYPE}")
    duthost.shell(f'redis-cli -n 4 -c HSET "PORT_QOS_MAP|global" "dscp_to_tc_map" "{DEFAULT_MAPPING_TYPE}"')
    apply_dscp_cfg_setup(duthost, dscp_mode, loganalyzer)

    yield

    apply_dscp_cfg_teardown(duthost, loganalyzer)
    logger.info("Recover the original QoS map configuration")
    if is_global_map_key_exist:
        duthost.shell(f'redis-cli -n 4 -c HSET "PORT_QOS_MAP|global" "dscp_to_tc_map" "{origin_dscp_to_tc_map}"')
    else:
        duthost.shell('redis-cli -n 4 -c DEL "PORT_QOS_MAP|global"')


def create_ipip_packet(outer_src_mac,
                       outer_dst_mac,
                       outer_src_pkt_ip,
                       outer_dst_pkt_ip,
                       outer_dscp,
                       inner_src_pkt_ip,
                       inner_dst_pkt_ip,
                       inner_dscp,
                       decap_mode):
    """
    Generate IPV4 IP-IP packets.

    Args:
        outer_src_mac: Outer source MAC address
        outer_dst_mac: Outer destination MAC address
        outer_src_pkt_ip: Outer source IP address
        outer_dst_pkt_ip: Outer destination IP address
        outer_dscp: Outer DSCP value
        inner_src_pkt_ip: Inner source IP address
        inner_dst_pkt_ip: Inner destination IP address
        inner_dscp: Inner DSCP value
        decap_mode: DSCP decap mode

    Returns:
        IP-IP packet, expected packet
    """

    inner_pkt = testutils.simple_tcp_packet(ip_src=inner_src_pkt_ip,
                                            ip_dst=inner_dst_pkt_ip,
                                            ip_dscp=inner_dscp,
                                            ip_ecn=DEFAULT_ECN,
                                            ip_ttl=DEFAULT_TTL)

    inner_pkt.ttl -= 1

    outer_pkt = testutils.simple_ipv4ip_packet(eth_src=outer_src_mac,
                                               eth_dst=outer_dst_mac,
                                               ip_src=outer_src_pkt_ip,
                                               ip_dst=outer_dst_pkt_ip,
                                               ip_dscp=outer_dscp,
                                               ip_ecn=DEFAULT_ECN,
                                               inner_frame=inner_pkt[scapy.IP])

    inner_pkt.ttl += 1

    if decap_mode == "uniform":
        exp_dscp = outer_dscp
    elif decap_mode == "pipe":
        exp_dscp = inner_dscp

    exp_pkt = testutils.simple_tcp_packet(ip_src=inner_src_pkt_ip,
                                          ip_dst=inner_dst_pkt_ip,
                                          ip_dscp=exp_dscp,
                                          ip_ecn=DEFAULT_ECN,
                                          ip_ttl=DEFAULT_TTL)

    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(Ether, 'src')
    exp_pkt.set_do_not_care_scapy(Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(IP, 'id')
    exp_pkt.set_do_not_care_scapy(IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(IP, 'chksum')

    return outer_pkt, exp_pkt


def send_and_verify_traffic(ptfadapter,
                            pkt_list,
                            exp_pkt_list,
                            ptf_src_port_id,
                            ptf_dst_port_ids):
    """
    Send traffic and verify that traffic was received

    Args:
        ptfadapter: PTF adapter
        pkt: Packet that should be sent
        exp_pkt: Expected packet
        ptf_src_port_id: Source port of ptf
        ptf_dst_port_ids: Possible destination ports of ptf
    """
    pkt_egress_index = 0
    ptf_dst_port_list = []
    logger.info("Send packet(s) from port {} from downstream to upstream".format(ptf_src_port_id))

    try:
        for pkt, exp_pkt in zip(pkt_list, exp_pkt_list):
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, ptf_src_port_id, pkt, count=DEFAULT_PKT_COUNT)
            logger.info(f"Send packet: {pkt}, expected packet: {exp_pkt}")
            result = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_port_ids, timeout=5)
            if isinstance(result, bool):
                logger.info("Return a dummy value for VS platform")
                port_index = 0
            else:
                port_index, _ = result
            logger.info("Received packet(s) on port {}".format(ptf_dst_port_ids[port_index]))
            global packet_egressed_success
            packet_egressed_success.append(True)
            ptf_dst_port_list.append(ptf_dst_port_ids[port_index])
            pkt_egress_index += 1
        return ptf_dst_port_list
    except AssertionError as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet(s) was not received on any of the ports -> {}".format(ptf_dst_port_ids))


def find_queue_count_and_value(duthost, queue_val_list, dut_egress_port_list):
    egress_queue_counts_all_queues = get_egress_queue_pkt_count_all_port_prio(duthost)
    global egress_queue_count_list, egress_queue_val_list
    egress_queue_count_list = []
    egress_queue_val_list = []
    for dut_egress_port, queue_val in zip(dut_egress_port_list, queue_val_list):
        egress_queue_count = egress_queue_counts_all_queues[dut_egress_port][queue_val]
        egress_queue_val = find_egress_queue(egress_queue_counts_all_queues[dut_egress_port], DEFAULT_PKT_COUNT)
        egress_queue_count_list.append(egress_queue_count)
        egress_queue_val_list.append(egress_queue_val)

    return egress_queue_count_list, egress_queue_val_list


class TestQoSSaiDSCPQueueMapping_IPIP_Base():
    """
    Test class for DSCP to Queue Mapping for IP-IP packets.
    """
    def _setup_test_params(self,
                           duthost,
                           tbinfo,
                           downstream_links,  # noqa F811
                           upstream_links,  # noqa F811
                           loganalyzer
                           ):
        """
        Set up test parameters for the DSCP to Queue mapping test for IP-IP packets.

        Destination mac returned will prioritize the VLAN mac address and fallback to the router mac
        if no VLAN is found.

        Args:
            duthost (fixture): DUT fixture
            downstream_links (fixture): Dictionary of downstream links info for DUT
            upstream_links (fixture): Dictionary of upstream links info for DUT
        """
        test_params = {}
        downlink = select_random_link(downstream_links)
        uplink_ptf_ports = get_stream_ptf_ports(upstream_links)
        loopback_ip = get_ipv4_loopback_ip(duthost)
        ptf_downlink_port_id = downlink.get("ptf_port_id")

        src_port_name = get_dut_pair_port_from_ptf_port(duthost, tbinfo, ptf_downlink_port_id)
        pytest_assert(src_port_name, "No port on DUT found for ptf downlink port {}".format(ptf_downlink_port_id))
        vlan_name = get_vlan_from_port(duthost, src_port_name)
        logger.debug("Found VLAN {} on port {}".format(vlan_name, src_port_name))
        vlan_mac = None if vlan_name is None else duthost.get_dut_iface_mac(vlan_name)
        if vlan_mac is not None:
            logger.info("Using VLAN mac {} instead of router mac".format(vlan_mac))
            dst_mac = vlan_mac
        else:
            logger.info("VLAN mac not found, falling back to router mac")
            dst_mac = duthost.facts["router_mac"]

        pytest_assert(downlink is not None, "No downlink found")
        pytest_assert(uplink_ptf_ports is not None, "No uplink found")
        pytest_assert(loopback_ip is not None, "No loopback IP found")
        pytest_assert(dst_mac is not None, "No router/vlan MAC found")

        test_params["ptf_downlink_port"] = ptf_downlink_port_id
        test_params["ptf_uplink_ports"] = uplink_ptf_ports
        test_params["outer_src_ip"] = '8.8.8.8'
        test_params["outer_dst_ip"] = loopback_ip
        test_params["dst_mac"] = dst_mac

        return test_params

    def _run_test(self,
                  ptfadapter,
                  duthost,
                  tbinfo,
                  test_params,
                  inner_dst_ip_list,
                  dut_qos_maps_module,  # noqa F811
                  decap_mode):  # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets
            Args:
                ptfadapter (PtfAdapter): PTF adapter
                duthost (AnsibleHost): The DUT host
                tbinfo (fixture): Testbed info
                test_params (dict): Dictionary of test parameters - initialized in _setup_test_params()
                dut_qos_maps_module (Fixture): A module level fixture, return qos maps on DUT host
                decap_mode (str): DSCP mode
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        ptf_port_to_dut_port_map = {}
        if "backend" in tbinfo["topo"]["type"]:
            pytest.skip("Dscp-queue mapping is not supported on {}".format(tbinfo["topo"]["type"]))

        asic_type = duthost.facts['asic_type']
        dst_mac = test_params['dst_mac']
        ptf_src_port_id = test_params['ptf_downlink_port']
        ptf_dst_port_ids = test_params['ptf_uplink_ports']
        outer_dst_pkt_ip = test_params['outer_dst_ip']
        outer_src_pkt_ip = DUMMY_OUTER_SRC_IP
        inner_dst_pkt_ip_list = inner_dst_ip_list
        inner_src_pkt_ip = DUMMY_INNER_SRC_IP
        ptf_src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port_id)
        step = len(inner_dst_ip_list)
        failed_once = False

        def _check_test_port_status(duthost, tbinfo, ptf_port_list):
            dut_test_ports = []
            for ptf_port in ptf_port_list:
                dut_port = get_dut_pair_port_from_ptf_port(duthost, tbinfo, ptf_port)
                dut_test_ports.append(dut_port)
            pytest_assert(wait_until(30, 10, 0, duthost.links_status_up, dut_test_ports), "Test ports are not up")

        def check_tunnel_dscp_mode(duthost, dscp_mode):
            real_dscp_mode = duthost.shell('redis-cli hget "TUNNEL_DECAP_TABLE:IPINIP_TUNNEL" "dscp_mode"')["stdout"]
            pytest_assert(dscp_mode == real_dscp_mode, "Wrong DSCP mode configured")

        def check_ip_route(duthost, step):
            ip_route_list = [INNER_DST_IP_PREFIX + str(i + 1) + '/32' for i in range(step)]
            for i in range(step):
                route = duthost.shell(f"show ip route {ip_route_list[i]}")["stdout"]
                if ip_route_list[i] not in route:
                    return False
            return True

        logger.info("Checking dscp mode")
        check_tunnel_dscp_mode(duthost, decap_mode)
        logger.info("Checking test ports status")
        _check_test_port_status(duthost, tbinfo, ptf_dst_port_ids[:] + [ptf_src_port_id])
        logger.info("Checking ip routes")
        pytest_assert(wait_until(30, 10, 0, check_ip_route, duthost, step), "IP routes are not configured")

        # Log packet information
        logger.info("Outer Pkt Src IP: {}".format(outer_src_pkt_ip))
        logger.info("Outer Pkt Dst IP: {}".format(outer_dst_pkt_ip))
        logger.info("Inner Pkt Src IP: {}".format(inner_src_pkt_ip))
        logger.info("Inner Pkt Dst IP: {}".format(inner_dst_pkt_ip_list))
        logger.info("Pkt Src MAC: {}".format(ptf_src_mac))
        logger.info("Pkt Dst MAC: {}".format(dst_mac))

        pytest_assert(dut_qos_maps_module.get("dscp_to_tc_map") and dut_qos_maps_module.get("tc_to_queue_map"),
                      "No QoS map found on DUT")

        for rotating_dscp in range(0, 64, step):
            pkt_list = []
            exp_pkt_list = []
            logger.info("Clear queue counter, and wait 1 seconds to make sure queue counter cleared")
            duthost.command("sonic-clear queuecounters")
            time.sleep(1)

            outer_dscp = rotating_dscp if decap_mode == "uniform" else DEFAULT_DSCP
            inner_dscp = DEFAULT_DSCP if decap_mode == "uniform" else rotating_dscp
            for i in range(step):
                logger.info(f"{decap_mode} mode: outer_dscp ="
                            f"{outer_dscp + i if decap_mode == 'uniform' else DEFAULT_DSCP}, "
                            f"inner_dscp = {inner_dscp if decap_mode == 'uniform' else inner_dscp + i}")
                pkt, exp_pkt = create_ipip_packet(outer_src_mac=ptf_src_mac,
                                                  outer_dst_mac=dst_mac,
                                                  outer_src_pkt_ip=outer_src_pkt_ip,
                                                  outer_dst_pkt_ip=outer_dst_pkt_ip,
                                                  outer_dscp=outer_dscp + i if decap_mode == "uniform" else
                                                  DEFAULT_DSCP,
                                                  inner_src_pkt_ip=inner_src_pkt_ip,
                                                  inner_dst_pkt_ip=inner_dst_pkt_ip_list[i],
                                                  inner_dscp=inner_dscp if decap_mode == "uniform" else inner_dscp + i,
                                                  decap_mode=decap_mode)
                pkt_list.append(pkt)
                exp_pkt_list.append(exp_pkt)

            queue_val_list = []
            global output_table

            for i in range(step):
                queue_val = get_dscp_to_queue_value(rotating_dscp + i,
                                                    dut_qos_maps_module.get("dscp_to_tc_map").get("AZURE"),
                                                    dut_qos_maps_module.get("tc_to_queue_map").get("AZURE"))
                if queue_val is None:
                    logger.info(f"No queue found for dscp {rotating_dscp} on DUT")
                    output_table.append([rotating_dscp, "No queue found", "N/A", "N/A"])
                    continue

                queue_val_list.append(queue_val)

            try:
                dst_ptf_port_id_list = send_and_verify_traffic(ptfadapter=ptfadapter,
                                                               pkt_list=pkt_list,
                                                               exp_pkt_list=exp_pkt_list,
                                                               ptf_src_port_id=ptf_src_port_id,
                                                               ptf_dst_port_ids=ptf_dst_port_ids)

            except ConnectionError as e:
                # Sending large number of packets can cause socket buffer to be full and leads connection timeout.
                logger.error("{}: Try reducing DEFAULT_PKT_COUNT value".format(str(e)))
                failed_once = True

            if asic_type == 'vs':
                logger.info("Skipping queue verification for VS platform")
                continue
            global packet_egressed_success

            dut_egress_port_list = []
            for i in range(step):
                dst_ptf_port_id = dst_ptf_port_id_list[i]
                if dst_ptf_port_id in ptf_port_to_dut_port_map:
                    dut_egress_port = ptf_port_to_dut_port_map[dst_ptf_port_id]
                else:
                    dut_egress_port = get_dut_pair_port_from_ptf_port(duthost, tbinfo, dst_ptf_port_id)
                    ptf_port_to_dut_port_map[dst_ptf_port_id] = dut_egress_port
                pytest_assert(dut_egress_port, "No egress port on DUT found for ptf port {}".format(dst_ptf_port_id))
                dut_egress_port_list.append(dut_egress_port)

            def validate_all_queue_counter(duthost, queue_val_list, dut_egress_port_list):
                egress_queue_count_list = find_queue_count_and_value(duthost, queue_val_list, dut_egress_port_list)[0]
                for queue_count in egress_queue_count_list:
                    if queue_count < DEFAULT_PKT_COUNT or queue_count % DEFAULT_PKT_COUNT != 0:
                        return False
                return True

            # Wait for the queue counters to be populated.
            wait_until(30, 0.5, 0, validate_all_queue_counter, duthost, queue_val_list, dut_egress_port_list)

            global egress_queue_count_list, egress_queue_val_list

            for i in range(step):
                cur_dscp = rotating_dscp + i
                if packet_egressed_success[i]:
                    if egress_queue_count_list[i] >= DEFAULT_PKT_COUNT:
                        logger.info(f"SUCCESS: Received expected number of packets on queue {queue_val_list[i]}")
                        output_table.append([cur_dscp, queue_val_list[i], egress_queue_count_list[i], "SUCCESS",
                                             queue_val_list[i]])
                    else:
                        if queue_val_list[i] == egress_queue_val_list[i]:
                            # If the queue value is correct, but the packet count is incorrect, then the DUT poll failed
                            logger.info(
                                f"FAILURE: Not all packets received on queue {queue_val_list[i]}. DUT poll failure.")
                            logger.info(f"Received {egress_queue_count_list[i]} packets instead")
                            output_table.append([cur_dscp, queue_val_list[i], egress_queue_count_list[i],
                                                 "FAILURE - INCORRECT PACKET COUNT", egress_queue_val_list[i]])
                        else:
                            if egress_queue_val_list[i] == -1:
                                logger.info("FAILURE: Packets not received on any queue. DUT poll failure.")
                                output_table.append([cur_dscp, queue_val_list[i], egress_queue_count_list[i],
                                                     "FAILURE - DUT POLL FAILURE", egress_queue_val_list[i]])
                            else:
                                logger.info(
                                    f"FAILURE: Received {DEFAULT_PKT_COUNT} packets on queue "
                                    f"{egress_queue_val_list[i]} instead of queue {queue_val_list[i]}.")
                                output_table.append([cur_dscp, queue_val_list[i], egress_queue_count_list[i],
                                                     "FAILURE - INCORRECT QUEUE", egress_queue_val_list[i]])
                        failed_once = True
                else:
                    output_table.append([cur_dscp, queue_val_list[i], 0, "FAILURE - NO PACKETS EGRESSED", "N/A"])
                    failed_once = True

            # Reset packet egress status
            packet_egressed_success = []

        logger.info("DSCP to queue mapping test results:\n{}"
                    .format(tabulate(output_table,
                                     headers=["Inner Packet DSCP Value", "Expected Egress Queue",
                                              "Egress Queue Count", "Result", "Actual Egress Queue"])))
        # Clear the output_table (for next test functions).
        output_table = []

        pytest_assert(not failed_once, "FAIL: Test failed. Please check table for details.")

    def test_dscp_to_queue_mapping(self, ptfadapter, rand_selected_dut, localhost, dscp_config, dscp_mode,
                                   toggle_all_simulator_ports_to_rand_selected_tor, completeness_level,  # noqa F811
                                   setup_standby_ports_on_rand_unselected_tor, route_config,
                                   tbinfo, downstream_links, upstream_links, dut_qos_maps_module, loganalyzer):  # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets in DSCP "uniform" and "pipe" mode
        """
        duthost = rand_selected_dut
        inner_dst_ip_list = route_config

        with allure.step("Prepare test parameter"):
            test_params = self._setup_test_params(duthost, tbinfo, downstream_links, upstream_links, loganalyzer)

        with allure.step("Run test"):
            self._run_test(ptfadapter, duthost, tbinfo, test_params, inner_dst_ip_list, dut_qos_maps_module, dscp_mode)

        if completeness_level != "basic" and \
                not duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch"):
            with allure.step("Do warm-reboot"):
                reboot(duthost, localhost, reboot_type="warm", safe_reboot=True, check_intf_up_ports=True,
                       wait_warmboot_finalizer=True)

            with allure.step("Run test after warm-reboot"):
                self._run_test(ptfadapter, duthost, tbinfo, test_params, inner_dst_ip_list, dut_qos_maps_module,
                               dscp_mode)
