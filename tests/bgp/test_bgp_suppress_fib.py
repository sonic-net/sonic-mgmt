import requests
import json
import logging
import random
import ipaddress
import pytest
import allure
import time

from scapy.all import sniff, IP, IPv6
from scapy.contrib import bgp
import ptf.testutils as testutils
import ptf.packet as scapy
from copy import deepcopy
from retry.api import retry_call
from ptf.mask import Mask
from natsort import natsorted
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.tcpdump_sniff_helper import TcpdumpSniffHelper
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from bgp_helpers import restart_bgp_session, get_eth_port, get_exabgp_port, get_vm_name_list, get_bgp_neighbor_ip, \
    check_route_install_status, validate_route_propagate_status, operate_orchagent, get_t2_ptf_intfs, \
    get_eth_name_from_ptf_port, check_bgp_neighbor, check_fib_route

pytestmark = [
    pytest.mark.topology("t1"),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
WITHDRAW = 'withdraw'
ANNOUNCE = 'announce'
ACTION_STOP = "stop"
ACTION_CONTINUE = "continue"
FORWARD = "FORWARD"
DROP = "DROP"
ACTION_IN = "in"
ACTION_NOT_IN = "not"
QUEUED = "queued"
OFFLOADED = "offloaded"
IP_VER = 4
IPV6_VER = 6
SRC_IP = {
    4: "192.168.0.2",
    6: "fc02:1000::2"
}
USER_DEFINED_VRF = "Vrf1"
DEFAULT = "default"
VRF_TYPES = [DEFAULT, USER_DEFINED_VRF]
BGP_FILTER = 'tcp port 179'
STATIC_ROUTE_PREFIX = "1.1.1.0/24"
BASE_IP_ROUTE = '91.0.1.0/24'
BASE_IPV6_ROUTE = '1000:1001::/64'
BULK_ROUTE_COUNT = 512  # 512 ipv4 route and 512 ipv6 route
FUNCTION = "function"
STRESS = "stress"
TRAFFIC_WAIT_TIME = 0.1
BULK_TRAFFIC_WAIT_TIME = 0.004
BGP_ROUTE_FLAP_TIMES = 5
UPDATE_WITHDRAW_THRESHOLD = 2  # Use the threshold value defined in test_bgp_update_timer.py


@pytest.fixture(scope="module")
def generate_route_and_traffic_data():
    """
    Generate route and traffic data
    """
    ip_routes_ipv4 = generate_routes(BASE_IP_ROUTE)
    ip_routes_ipv6 = generate_routes(BASE_IPV6_ROUTE)

    ipv4_routes_stress_and_perf = generate_routes(BASE_IP_ROUTE, BULK_ROUTE_COUNT)
    ipv6_routes_stress_and_perf = generate_routes(BASE_IPV6_ROUTE, BULK_ROUTE_COUNT)

    route_and_traffic_data = {
        FUNCTION: [
            ip_routes_ipv4,
            ip_routes_ipv6,
            generate_traffic_data(ip_routes_ipv4, FORWARD),
            generate_traffic_data(ip_routes_ipv6, FORWARD),
            generate_traffic_data(ip_routes_ipv4, DROP),
            generate_traffic_data(ip_routes_ipv6, DROP)
        ],
        STRESS: [
            ipv4_routes_stress_and_perf,
            ipv6_routes_stress_and_perf,
            generate_traffic_data(ipv4_routes_stress_and_perf, FORWARD),
            generate_traffic_data(ipv6_routes_stress_and_perf, FORWARD),
            generate_traffic_data(ipv4_routes_stress_and_perf, DROP),
            generate_traffic_data(ipv6_routes_stress_and_perf, DROP)
        ]
    }

    return route_and_traffic_data


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_errors(duthosts, rand_one_dut_hostname, loganalyzer):
    """
       Ignore expected error during TC execution

       Args:
            duthosts: list of DUTs.
            rand_one_dut_hostname: Hostname of a random chosen dut
            loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR swss#supervisor-proc-exit-listener:.*Process \'orchagent\' is stuck in namespace \'host\' "
            "\\(.* minutes\\).*"
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)


@pytest.fixture(scope="function")
def restore_bgp_suppress_fib(duthost):
    """
    Record the configuration before test only restore bgp suppress fib
    if it is not enabled before test
    """
    suppress_fib = True
    rets = duthost.shell('show suppress-fib-pending')
    if rets['rc'] != 0:
        logger.info("Failed to get suppress-fib-pending configuration")
    else:
        logger.info("Get suppress-fib-pending configuration: {}".format(rets['stdout']))
        if rets['stdout'] == 'Enabled':
            suppress_fib = True
        else:
            suppress_fib = False

    """
    Restore bgp suppress fib pending function
    """
    yield
    config_bgp_suppress_fib(duthost, suppress_fib)
    logger.info("Save configuration")
    duthost.shell('sudo config save -y')


@pytest.fixture(scope='module')
def completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="function")
def get_exabgp_ptf_ports(duthost, nbrhosts, tbinfo, completeness_level, request):
    """
    Get ipv4 and ipv6 Exabgp port and ptf receive port
    """
    is_random = True
    if completeness_level == "thorough":
        logger.info("Completeness Level is 'thorough', and script would do full verification over all VMs!")
        is_random = False
    exabgp_port_list, ptf_recv_port_list = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT, is_random)
    exabgp_port_list_v6, ptf_recv_port_list_v6 = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT_V6,
                                                                 is_random)
    return [(exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6)
            for exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 in zip(exabgp_port_list,
                                                                                    ptf_recv_port_list,
                                                                                    exabgp_port_list_v6,
                                                                                    ptf_recv_port_list_v6)]


@pytest.fixture(scope="function")
def prepare_param(duthost, tbinfo, get_exabgp_ptf_ports):
    """
    Prepare parameters
    """
    router_mac = duthost.facts["router_mac"]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_ip = tbinfo['ptf_ip']
    total_port_list = get_exabgp_ptf_ports
    exabgp_port_list, ptf_recv_port_list, exabgp_port_list_v6, ptf_recv_port_list_v6 = zip(*total_port_list)
    recv_port_list = [{4: ptf_recv_port, 6: ptf_recv_port_v6} for ptf_recv_port, ptf_recv_port_v6 in
                      zip(ptf_recv_port_list, ptf_recv_port_list_v6)]
    return router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list


@pytest.fixture(scope="module")
def continuous_boot_times(request, completeness_level):
    continuous_boot_times = request.config.getoption("--continuous_boot_times")
    if completeness_level == 'thorough':
        logger.info(f"Completeness Level is 'thorough', and script would do continuous boot test "
                    f"for {continuous_boot_times} times")
        return continuous_boot_times
    else:
        return 1


@pytest.fixture(scope="function")
def tcpdump_helper(ptfadapter, duthost, ptfhost):
    return TcpdumpSniffHelper(ptfadapter, duthost, ptfhost)


def ip_address_incr(ip_str):
    """
    Increment an IP subnet prefix by 1
    """
    net = ipaddress.ip_network(ip_str, strict=False)
    next_net_addr = net.network_address + net.num_addresses
    return f"{next_net_addr}/{net.prefixlen}"


def generate_routes(start_ip, count=2):
    """
    Generate a number of IP routes
    """
    route_list = [start_ip]
    for _ in range(count - 1):
        start_ip = ip_address_incr(start_ip)
        route_list.append(start_ip)
    return route_list


def get_first_ip(subnet):
    """
    Get the first IP address from the subnet
    """
    network = ipaddress.ip_network(subnet, strict=False)
    all_usable_ips = network.hosts()
    first_ip = next(all_usable_ips)
    return str(first_ip)


def generate_traffic_data(route_list, action):
    """
    Generate traffic data list
    Example:
    Input: route_list=['91.0.1.0/24', '91.0.2.0/24'], action='FORWARD'
    Output: [
                ('91.0.1.1', 'FORWARD'),
                ('91.0.2.1', 'FORWARD')
            ]
    """
    traffic_data_list = []
    for route in route_list:
        ipaddr = get_first_ip(route)
        traffic_data = (ipaddr, action)
        traffic_data_list.append(traffic_data)
    return traffic_data_list


def is_orchagent_stopped(duthost):
    """
    Check if process 'orchagent' is stopped
    """
    out = duthost.shell('cat /proc/$(pidof orchagent)/status | grep State')['stdout']
    logger.info('Orchagent process - {}'.format(out))
    return ACTION_STOP in out


@pytest.fixture(scope="function", autouse=True)
def restore_orchagent(duthost, tbinfo, nbrhosts, get_exabgp_ptf_ports):
    """
    Fixture to restore process 'orchagent' in case of unexpected failures in case
    """
    yield

    if is_orchagent_stopped(duthost):
        logger.info('Orchagent process stopped, will restore it')
        operate_orchagent(duthost, action=ACTION_CONTINUE)


def get_cfg_facts(duthost):
    """
    Get config port indices
    """
    cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])

    port_name_list_sorted = natsorted(cfg_facts['PORT'].keys())
    port_index_map = {}
    for idx, val in enumerate(port_name_list_sorted):
        port_index_map[val] = idx

    cfg_facts['config_port_indices'] = port_index_map

    return cfg_facts


def get_port_connected_with_vm(duthost, nbrhosts, vm_type='T0'):
    """
    Get ports that connects with T0 VM
    """
    port_list = []
    vm_list = [vm_name for vm_name in nbrhosts.keys() if vm_name.endswith(vm_type)]
    for vm in vm_list:
        port = duthost.shell("show ip interface | grep -w {} | awk '{{print $1}}'".format(vm))['stdout']
        port_list.append(port)
    logger.info("Ports connected with {} VMs: {}".format(vm_type, port_list))
    return port_list


def setup_vrf_cfg(duthost, cfg_facts, nbrhosts, tbinfo):
    """
    Config vrf based configuration
    """
    cfg_t1 = deepcopy(cfg_facts)
    cfg_t1.pop('config_port_indices', None)
    port_list = get_port_connected_with_vm(duthost, nbrhosts)
    vm_list = nbrhosts.keys()
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_channel_list = mg_facts['minigraph_portchannels'].keys()
    extra_vars = {'cfg_t1': cfg_t1, 'port_list': port_list, 'vm_list': vm_list, 'pc_list': port_channel_list}

    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src="bgp/vrf_config_db.j2", dest="/tmp/config_db_vrf.json")
    duthost.shell("cp -f /tmp/config_db_vrf.json /etc/sonic/config_db.json")

    config_reload(duthost, safe_reload=True)


def setup_vrf(duthost, nbrhosts, tbinfo):
    """
    Prepare vrf based environment
    """
    logger.info("Back up original config_db.json")
    duthost.shell("mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    cfg_t1 = get_cfg_facts(duthost)
    setup_vrf_cfg(duthost, cfg_t1, nbrhosts, tbinfo)


def install_route_from_exabgp(operation, ptfip, route_list, port):
    """
    Install or withdraw ipv4 or ipv6 route by exabgp
    """
    route_data = []
    url = "http://{}:{}".format(ptfip, port)
    for route in route_list:
        route_data.append(route)
    command = "{} attribute next-hop self nlri {}".format(operation, ' '.join(route_data))
    data = {"command": command}
    logger.info("url: {}".format(url))
    logger.info("command: {}".format(data))
    r = requests.post(url, data=data, timeout=90)
    assert r.status_code == 200


def announce_route(ptfip, route_list, port, action=ANNOUNCE):
    """
    Announce or withdraw ipv4 or ipv6 route
    """
    logger.info("\n========================== announce_route -- {} ==========================".format(action))
    logger.info(" action:{}\n ptfip:{}\n route:{}\n port:{}".format(action, ptfip, route_list, port))
    install_route_from_exabgp(action, ptfip, route_list, port)
    logger.info("\n--------------------------------------------------------------------------------")


def generate_packet(src_ip, dst_ip, dst_mac):
    """
    Build ipv4 and ipv6 packets/expected_packets for testing
    """
    if ipaddress.ip_network(src_ip.encode().decode(), False).version == 4:
        pkt = testutils.simple_ip_packet(eth_dst=dst_mac, ip_src=src_ip, ip_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_packet(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")

    exp_pkt.set_do_not_care_packet(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_packet(scapy.Ether, "src")

    return pkt, exp_pkt


def send_and_verify_packet(ptfadapter, pkt_list, exp_pkt_list, tx_port, rx_ports, exp_action_list, ip_ver_list=None):
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected
    """
    ptfadapter.dataplane.flush()
    for pkt, exp_pkt, exp_action, ip_ver in zip(pkt_list, exp_pkt_list, exp_action_list, ip_ver_list):
        rx_port = rx_ports[ip_ver] if ip_ver else rx_ports
        testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
        if exp_action == FORWARD:
            testutils.verify_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=TRAFFIC_WAIT_TIME)
        else:
            testutils.verify_no_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=TRAFFIC_WAIT_TIME)


def send_and_verify_loopback_packets(ptfadapter, pkt_list, exp_pkt_list, tx_port, rx_ports, exp_action_list):
    """
    Send packet with ptfadapter and verify if packet is forwarded back or dropped as expected
    """
    ptfadapter.dataplane.flush()
    for pkt, exp_pkt, exp_action in zip(pkt_list, exp_pkt_list, exp_action_list):
        testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
        if exp_action == FORWARD:
            testutils.verify_packets_any(ptfadapter, pkt=exp_pkt, ports=rx_ports, timeout=TRAFFIC_WAIT_TIME)
        else:
            testutils.verify_no_packet_any(ptfadapter, pkt=exp_pkt, ports=rx_ports, timeout=TRAFFIC_WAIT_TIME)


def send_and_verify_bulk_traffic(tcpdump_helper, ptfadapter, ip_ver_list, pkt_list, tx_port, rx_ports, exp_action_list):
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected
    """
    tcpdump_helper.in_direct_ifaces = rx_ports if isinstance(rx_ports, list) else rx_ports.values()
    tcpdump_helper.start_sniffer()
    logger.info("Start sending traffic")
    ptfadapter.dataplane.flush()
    for pkt in pkt_list:
        testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
        time.sleep(BULK_TRAFFIC_WAIT_TIME)

    logger.info("Stop sending traffic")
    tcpdump_helper.stop_sniffer()
    cap_pkt_list = tcpdump_helper.sniffer_result()
    check_pkt_forward_state(cap_pkt_list, ip_ver_list, pkt_list, exp_action_list)


def check_pkt_forward_state(captured_packets, ip_ver_list, send_packet_list, expect_action_list):
    """
    Validate if sent packets are captured as expected
    """
    act_forward_count = 0
    exp_forward_count = len([1 for action in expect_action_list if action == FORWARD])
    filter = "src={} dst={}"
    captured_packets_str = str(captured_packets.res)

    for i in range(len(send_packet_list)):
        ver_filter = 'IPv6' if ip_ver_list[i] == 6 else 'IP'
        if filter.format(send_packet_list[i][ver_filter].src,
                         send_packet_list[i][ver_filter].dst) in captured_packets_str and \
                expect_action_list[i] == FORWARD:
            act_forward_count += 1
            logger.debug("Packet is captured:\n{}".format(str(send_packet_list[i].summary)))
        else:
            logger.info("Packet is not captured:\n{}".format(str(send_packet_list[i].summary)))

    assert act_forward_count == exp_forward_count, \
        "Captured forward traffic number: {}, expect forward traffic number: {}".format(act_forward_count,
                                                                                        exp_forward_count)


def update_time_stamp(time_stamp_dict, prefix, timestamp):
    if prefix in time_stamp_dict:
        time_stamp_dict[prefix].append(timestamp)
    else:
        time_stamp_dict[prefix] = [timestamp]


def parse_time_stamp(bgp_packets, ipv4_route_list, ipv6_route_list):
    announce_prefix_time_stamp, withdraw_prefix_time_stamp = {}, {}
    bgp_updates = bgp_packets[bgp.BGPUpdate]
    # get time stamp
    for i in range(len(bgp_updates)):
        if bgp.BGPNLRI_IPv4 in bgp_updates[i]:
            layer_index = 1
            while bgp_updates[i].getlayer(bgp.BGPUpdate, nb=layer_index):
                layer = bgp_updates[i].getlayer(bgp.BGPUpdate, nb=layer_index)
                if layer.nlri:
                    for route in layer.nlri:
                        if route.prefix in ipv4_route_list:
                            update_time_stamp(announce_prefix_time_stamp, route.prefix, bgp_packets[i].time)
                if layer.withdrawn_routes:
                    for route in layer.withdrawn_routes:
                        if route.prefix in ipv4_route_list:
                            update_time_stamp(withdraw_prefix_time_stamp, route.prefix, bgp_packets[i].time)
                layer_index += 1

        if bgp.BGPNLRI_IPv6 in bgp_updates[i]:
            layer_index = 1
            while bgp_updates[i].getlayer(bgp.BGPPAMPReachNLRI, nb=layer_index):
                layer = bgp_updates[i].getlayer(bgp.BGPPAMPReachNLRI, nb=layer_index)
                if layer.nlri:
                    for route in layer.nlri:
                        if route.prefix in ipv6_route_list:
                            update_time_stamp(announce_prefix_time_stamp, route.prefix, bgp_packets[i].time)
                layer_index += 1

            layer_index = 1
            while bgp_updates[i].getlayer(bgp.BGPPAMPUnreachNLRI_IPv6, nb=layer_index):
                layer = bgp_updates[i].getlayer(bgp.BGPPAMPUnreachNLRI_IPv6, nb=layer_index)
                if layer.withdrawn_routes:
                    for route in layer.withdrawn_routes:
                        if route.prefix in ipv6_route_list:
                            update_time_stamp(withdraw_prefix_time_stamp, route.prefix, bgp_packets[i].time)
                layer_index += 1

    return announce_prefix_time_stamp, withdraw_prefix_time_stamp


def compute_middle_average_time(time_stamp_dict):
    time_delta_list = []
    for _, timestamp_list in time_stamp_dict.items():
        time_delta_list.append(abs(timestamp_list[1] - timestamp_list[0]))
    time_delta_list.sort()

    mid_delta_time = time_delta_list[(len(time_delta_list) - 1) // 2]
    ave_delta_time = sum(time_delta_list) / len(time_delta_list)
    return mid_delta_time, ave_delta_time


def validate_route_process_perf(pcap_file, ipv4_route_list, ipv6_route_list):
    route_num = len(ipv4_route_list + ipv6_route_list)
    bgp_packets = sniff(offline=pcap_file,
                        lfilter=lambda p: (IP or IPv6 in p) and bgp.BGPHeader in p and p[bgp.BGPHeader].type == 2)
    announce_prefix_time_stamp, withdraw_prefix_time_stamp = parse_time_stamp(bgp_packets, ipv4_route_list,
                                                                              ipv6_route_list)
    logger.info("Received and send timestamp for announced routes:\n{}".format(announce_prefix_time_stamp))
    logger.info("Received and send timestamp for withdrawn routes:\n{}".format(withdraw_prefix_time_stamp))

    announce_middle_time, announce_average_time = compute_middle_average_time(announce_prefix_time_stamp)
    withdraw_middle_time, withdraw_average_time = compute_middle_average_time(withdraw_prefix_time_stamp)
    # compare with threshold
    logger.info("\n------------------------------------------------------------------------------------")
    logger.info("Middle time usage of announce {} route : {} s".format(route_num, announce_middle_time))
    logger.info("Average time usage of announce {} route : {} s".format(route_num, announce_average_time))
    logger.info("Middle time usage of withdraw {} route : {} s".format(route_num, withdraw_middle_time))
    logger.info("Average time usage of withdraw {} route : {} s".format(route_num, withdraw_average_time))
    logger.info("------------------------------------------------------------------------------------\n")
    assert announce_middle_time < UPDATE_WITHDRAW_THRESHOLD
    assert announce_average_time < UPDATE_WITHDRAW_THRESHOLD
    assert withdraw_middle_time < UPDATE_WITHDRAW_THRESHOLD
    assert withdraw_average_time < UPDATE_WITHDRAW_THRESHOLD


def prepare_traffic(traffic_data, router_mac, ptf_interfaces, recv_port):
    ip_ver_list, pkt_list, exp_pkt_list, exp_res_list = [], [], [], []
    tx_port = random.choice(ptf_interfaces)

    for test_item in traffic_data:
        dst_ip = test_item[0]
        exp_res = test_item[1]
        ip_ver = ipaddress.ip_network(dst_ip.encode().decode(), False).version
        pkt, exp_pkt = generate_packet(SRC_IP[ip_ver], dst_ip, router_mac)
        if ptf_interfaces is recv_port:
            rx_port = ptf_interfaces
        else:
            rx_port = recv_port[ip_ver]
        logger.info("Expected packet:\n dst_mac:{} - src_ip:{} - dst_ip:{} - ptf tx_port:{} - ptf rx_port:{} - "
                    "expected_result = {}".format(router_mac, SRC_IP[ip_ver], dst_ip, tx_port, rx_port, exp_res))

        ip_ver_list.append(ip_ver)
        pkt_list.append(pkt)
        exp_pkt_list.append(exp_pkt)
        exp_res_list.append(exp_res)

    return tx_port, ip_ver_list, pkt_list, exp_pkt_list, exp_res_list


def validate_traffic(ptfadapter, traffic_data_list, router_mac, ptf_interfaces, recv_port, loop_back=False):
    """
    Verify traffic is forwarded/forwarded back/drop as expected
    """
    for traffic_data in traffic_data_list:
        tx_port, ip_ver_list, pkt_list, exp_pkt_list, exp_res_list = prepare_traffic(traffic_data, router_mac,
                                                                                     ptf_interfaces, recv_port)
        if ptf_interfaces is recv_port:
            if loop_back:
                send_and_verify_loopback_packets(ptfadapter, pkt_list, exp_pkt_list, tx_port, ptf_interfaces,
                                                 exp_res_list)
            else:
                send_and_verify_packet(ptfadapter, pkt_list, exp_pkt_list, tx_port, tx_port, exp_res_list)
        else:
            send_and_verify_packet(ptfadapter, pkt_list, exp_pkt_list, tx_port, recv_port, exp_res_list, ip_ver_list)


def validate_bulk_traffic(tcpdump_helper, ptfadapter, traffic_data_list, router_mac, ptf_interfaces, recv_port):
    tx_port, ip_ver_list, pkt_list, exp_pkt_list, exp_res_list = prepare_traffic(traffic_data_list, router_mac,
                                                                                 ptf_interfaces, recv_port)
    send_and_verify_bulk_traffic(tcpdump_helper, ptfadapter, ip_ver_list, pkt_list, tx_port, recv_port, exp_res_list)


def announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6, action=ANNOUNCE):
    """
    Announce or withdraw ipv4 and ipv6 routes by exabgp
    """
    announce_route(ptf_ip, ipv4_route_list, exabgp_port, action)
    announce_route(ptf_ip, ipv6_route_list, exabgp_port_v6, action)


def config_bgp_suppress_fib(duthost, enable=True, validate_result=False):
    """
    Enable or disable bgp suppress-fib-pending function
    """
    if enable:
        logger.info('Enable BGP suppress fib pending function')
        cmd = 'sudo config suppress-fib-pending enabled'
    else:
        logger.info('Disable BGP suppress fib pending function')
        cmd = 'sudo config suppress-fib-pending disabled'
    duthost.shell(cmd)
    if validate_result:
        res = duthost.shell('show suppress-fib-pending')
        assert enable is (res['stdout'] == 'Enabled')


def do_and_wait_reboot(duthost, localhost, reboot_type):
    """
    Do reboot and wait critical services and ports up
    """
    with allure.step("Do {}".format(reboot_type)):
        reboot(duthost, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=None,
               wait_warmboot_finalizer=True)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "All critical services should be fully started!")
        pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")


def param_reboot(request, duthost, localhost):
    """
    Read reboot_type from option bgp_suppress_fib_reboot_type
    If reboot_type is reload, do config reload
    If reboot_type is random, randomly choose one action from reload/cold/warm/fast reboot
    Else do a reboot directly as bgp_suppress_fib_reboot_type assigned
    """
    reboot_type = request.config.getoption("--bgp_suppress_fib_reboot_type")
    reboot_type_list = ["reload", "cold", "warm", "fast"]
    if reboot_type == "random":
        reboot_type = random.choice(reboot_type_list)
        logger.info("Randomly choose {} from reload, cold, warm, fast".format(reboot_type))

    if reboot_type == "reload":
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    else:
        do_and_wait_reboot(duthost, localhost, reboot_type)


def validate_route_states(duthost, ipv4_route_list, ipv6_route_list, vrf=DEFAULT, check_point=QUEUED, action=ACTION_IN):
    """
    Verify ipv4 and ipv6 routes install status
    """
    for route in ipv4_route_list:
        check_route_install_status(duthost, route, vrf, IP_VER, check_point, action)
    for route in ipv6_route_list:
        check_route_install_status(duthost, route, vrf, IPV6_VER, check_point, action)


def validate_fib_route(duthost, ipv4_route_list, ipv6_route_list):
    """
    Verify ipv4 and ipv6 route were installed into fib
    """
    retry_call(check_fib_route, fargs=[duthost, ipv4_route_list], tries=5, delay=2)
    retry_call(check_fib_route, fargs=[duthost, ipv6_route_list, IPV6_VER], tries=5, delay=2)


def validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, vrf=DEFAULT, exist=True):
    """
    Verify ipv4 and ipv6 route propagate status at t2 vm side
    """
    t2_vm_list = get_vm_name_list(tbinfo)
    for t2_vm in t2_vm_list:
        bgp_neighbor_v4, bgp_neighbor_v6 = get_bgp_neighbor_ip(duthost, t2_vm, vrf)
        validate_route_propagate_status(nbrhosts[t2_vm], ipv4_route_list, bgp_neighbor_v4, vrf, exist=exist)
        validate_route_propagate_status(nbrhosts[t2_vm], ipv6_route_list, bgp_neighbor_v6, vrf, ip_ver=IPV6_VER,
                                        exist=exist)


def redistribute_static_route_to_bgp(duthost, redistribute=True):
    """
    Enable or disable redistribute static route to BGP
    """
    vtysh_cmd = "sudo vtysh"
    config_terminal = " -c 'config'"
    enter_bgp_mode = " -c 'router bgp'"
    enter_address_family_ipv4 = " -c 'address-family ipv4'"
    redistribute_static = " -c 'redistribute static'"
    no_redistribute_static = " -c 'no redistribute static'"
    if redistribute:
        duthost.shell(vtysh_cmd + config_terminal + enter_bgp_mode + enter_address_family_ipv4 + redistribute_static)
    else:
        duthost.shell(vtysh_cmd + config_terminal + enter_bgp_mode + enter_address_family_ipv4 + no_redistribute_static)


def remove_static_route_and_redistribute(duthost):
    """
    Remove static route and stop redistribute it to BGP
    """
    out = duthost.shell("show ip route {}".format(STATIC_ROUTE_PREFIX), verbose=False)['stdout']
    if STATIC_ROUTE_PREFIX in out:
        duthost.shell("sudo config route del prefix {}".format(STATIC_ROUTE_PREFIX))
        redistribute_static_route_to_bgp(duthost, redistribute=False)


def bgp_route_flap_with_stress(duthost, tbinfo, nbrhosts, ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list,
                               exabgp_port_v6, vrf=DEFAULT, flap_time=1):
    """
    Do bgp route flap
    """
    for i in range(flap_time):
        with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
            announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

        with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
            validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, vrf=vrf)

        with allure.step("Withdraw BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
            announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                      action=WITHDRAW)

        with allure.step("Validate bgp neighbors are established"):
            check_bgp_neighbor(duthost)


def perf_sniffer_prepare(tcpdump_sniffer, duthost, nbrhosts, mg_facts, recv_port):
    eths_to_t2_vm = get_port_connected_with_vm(duthost, nbrhosts, vm_type='T2')
    eths_to_t0_vm = get_eth_name_from_ptf_port(mg_facts, [port for port in recv_port.values()])
    tcpdump_sniffer.out_direct_ifaces = [random.choice(eths_to_t2_vm)]
    tcpdump_sniffer.in_direct_ifaces = eths_to_t0_vm
    tcpdump_sniffer.tcpdump_filter = BGP_FILTER


@pytest.mark.parametrize("vrf_type", VRF_TYPES)
def test_bgp_route_with_suppress(duthost, tbinfo, nbrhosts, ptfadapter, localhost, restore_bgp_suppress_fib,
                                 prepare_param, vrf_type, continuous_boot_times, generate_route_and_traffic_data,
                                 request):
    try:
        if vrf_type == USER_DEFINED_VRF:
            with allure.step("Configure user defined vrf"):
                setup_vrf(duthost, nbrhosts, tbinfo)

        with allure.step("Prepare needed parameters"):
            router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param

        with allure.step("Get route and traffic data"):
            ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
                traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[FUNCTION]

        with allure.step("Config bgp suppress-fib-pending function"):
            config_bgp_suppress_fib(duthost)

        with allure.step("Save configuration"):
            logger.info("Save configuration")
            duthost.shell('sudo config save -y')

        for continous_boot_index in range(continuous_boot_times):
            if continuous_boot_times > 1:
                logger.info("======== Continuous boot needed - this is the {} time boot test ========".
                            format(continous_boot_index+1))

            with allure.step("Do reload"):
                param_reboot(request, duthost, localhost)

            for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
                try:
                    with allure.step("Suspend orchagent process to simulate a route install delay"):
                        operate_orchagent(duthost)

                    with allure.step(f"Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP - "
                                     f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                        announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

                    with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(QUEUED)):
                        validate_route_states(duthost, ipv4_route_list, ipv6_route_list, vrf_type)

                    with allure.step("Validate BGP ipv4 and ipv6 routes are not announced to T2 VM peer"):
                        validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, vrf_type,
                                                 exist=False)

                    with allure.step("Validate traffic could not be forwarded to T0 VM"):
                        ptf_interfaces = get_t2_ptf_intfs(mg_facts)
                        validate_traffic(ptfadapter, [traffic_data_ipv4_drop, traffic_data_ipv6_drop], router_mac,
                                         ptf_interfaces, recv_port)

                    with allure.step("Restore orchagent process"):
                        operate_orchagent(duthost, action=ACTION_CONTINUE)

                    with allure.step("Validate announced BGP ipv4 and ipv6 routes are not in {} state".format(QUEUED)):
                        validate_route_states(duthost, ipv4_route_list, ipv6_route_list, vrf_type, check_point=QUEUED,
                                              action=ACTION_NOT_IN)

                    with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
                        validate_route_states(duthost, ipv4_route_list, ipv6_route_list, vrf_type,
                                              check_point=OFFLOADED)

                    with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
                        validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, vrf_type)

                    with allure.step("Validate traffic would be forwarded to T0 VM"):
                        validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                                         ptf_interfaces, recv_port)
                finally:
                    with allure.step(f"Withdraw BGP ipv4 and ipv6 routes from T0 VM by ExaBGP - "
                                     f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                        announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                                  action=WITHDRAW)

                    with allure.step("Validate BGP ipv4 and ipv6 routes are withdrawn from T2 VM peer"):
                        validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, vrf_type,
                                                 exist=False)

    finally:
        if vrf_type == USER_DEFINED_VRF:
            with allure.step("Clean user defined vrf"):
                duthost.shell("cp -f /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
                config_reload(duthost, safe_reload=True)


def test_bgp_route_without_suppress(duthost, tbinfo, nbrhosts, ptfadapter, prepare_param, restore_bgp_suppress_fib,
                                    generate_route_and_traffic_data):
    with allure.step("Prepare needed parameters"):
        router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param

    with allure.step("Disable bgp suppress-fib-pending function"):
        config_bgp_suppress_fib(duthost, False)

    with allure.step("Get route and traffic data"):
        ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
            traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[FUNCTION]

    for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
        try:
            with allure.step("Suspend orchagent process to simulate a route install delay"):
                operate_orchagent(duthost)

            with allure.step(f"Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

            with allure.step("Validate announced BGP ipv4 and ipv6 routes are not in {} state".format(QUEUED)):
                validate_route_states(duthost, ipv4_route_list, ipv6_route_list, check_point=QUEUED,
                                      action=ACTION_NOT_IN)

            with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
                validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list)

            with allure.step("Restore orchagent process"):
                operate_orchagent(duthost, action=ACTION_CONTINUE)

            with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
                validate_route_states(duthost, ipv4_route_list, ipv6_route_list, check_point=OFFLOADED)

            with allure.step("Validate traffic would be forwarded to T0 VM"):
                ptf_interfaces = get_t2_ptf_intfs(mg_facts)
                validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                                 ptf_interfaces, recv_port)
        finally:
            with allure.step(f"Withdraw BGP ipv4 and ipv6 routes from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                          action=WITHDRAW)


def test_bgp_route_with_suppress_negative_operation(duthost, tbinfo, nbrhosts, ptfadapter, localhost, prepare_param,
                                                    restore_bgp_suppress_fib, generate_route_and_traffic_data):
    try:
        with allure.step("Prepare needed parameters"):
            router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param

        with allure.step("Get route and traffic data"):
            ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
                traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[FUNCTION]

        with allure.step("Config bgp suppress-fib-pending function"):
            config_bgp_suppress_fib(duthost)

        for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
            try:
                with allure.step("Suspend orchagent process to simulate a route install delay"):
                    operate_orchagent(duthost)

                with allure.step(f"Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP - "
                                 f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                    announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

                with allure.step("Execute bgp sessions restart"):
                    restart_bgp_session(duthost)

                with allure.step("Validate bgp neighbor are established"):
                    check_bgp_neighbor(duthost)

                with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(QUEUED)):
                    validate_route_states(duthost, ipv4_route_list, ipv6_route_list)

                with allure.step("Validate BGP ipv4 and ipv6 routes are not announced to T2 VM peer"):
                    validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, exist=False)

                with allure.step("Config static route and redistribute to BGP"):
                    port = get_eth_port(duthost, tbinfo)
                    logger.info("Config static route - sudo config route add prefix {} nexthop dev {}".
                                format(STATIC_ROUTE_PREFIX, port))
                    duthost.shell("sudo config route add prefix {} nexthop dev {}".format(STATIC_ROUTE_PREFIX, port))
                    redistribute_static_route_to_bgp(duthost)

                with allure.step("Validate redistributed static route is propagate to T2 VM peer"):
                    validate_route_propagate(duthost, nbrhosts, tbinfo, [STATIC_ROUTE_PREFIX], [])

                with allure.step("Validate traffic could not be forwarded to T0 VM"):
                    ptf_interfaces = get_t2_ptf_intfs(mg_facts)
                    validate_traffic(ptfadapter, [traffic_data_ipv4_drop, traffic_data_ipv6_drop], router_mac,
                                     ptf_interfaces, recv_port)

                with allure.step("Restore orchagent process"):
                    operate_orchagent(duthost, action=ACTION_CONTINUE)

                with allure.step("Validate announced BGP ipv4 and ipv6 routes are not in {} state".format(QUEUED)):
                    validate_route_states(duthost, ipv4_route_list, ipv6_route_list, check_point=QUEUED,
                                          action=ACTION_NOT_IN)

                with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
                    validate_route_states(duthost, ipv4_route_list, ipv6_route_list, check_point=OFFLOADED)

                with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
                    validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list)

                with allure.step("Validate traffic would be forwarded to T0 VM"):
                    validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                                     ptf_interfaces, recv_port)
            finally:
                with allure.step(f"Withdraw BGP ipv4 and ipv6 routes from T0 VM by ExaBGP - "
                                 f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                    announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                              action=WITHDRAW)
    finally:
        with allure.step("Delete static route and remove redistribute to BGP"):
            remove_static_route_and_redistribute(duthost)


def test_credit_loop(duthost, tbinfo, nbrhosts, ptfadapter, prepare_param, generate_route_and_traffic_data,
                     restore_bgp_suppress_fib):
    """
    The problem with BGP programming occurs after the T1 switch is rebooted:

    First, the T1 FRR learns a default route from at least 1 T2
    The T0 advertises its prefixes to T1
    FRR advertises the prefixes to T2 without waiting for them to be programmed in the ASIC
    T2 starts forwarding traffic for prefixes not yet programmed, according to T1 routing table,
    T1 sends it back to a default route - same T2
    When the traffic is bounced back on lossless queue, buffers on both sides are overflown, credit loop happens
    """
    with allure.step("Prepare needed parameters"):
        router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param

    with allure.step("Get route and traffic data"):
        ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
            traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[FUNCTION]

    for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
        try:
            with allure.step("Disable bgp suppress-fib-pending function"):
                config_bgp_suppress_fib(duthost, False)

            with allure.step(
                    "Validate traffic is forwarded back to T2 VM and routes in HW table are removed by orchagent"):
                ptf_interfaces = get_t2_ptf_intfs(mg_facts)
                retry_call(validate_traffic,
                           fargs=[ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                                  ptf_interfaces, ptf_interfaces, True], tries=3, delay=2)

            with allure.step("Suspend orchagent process to simulate a route install delay"):
                operate_orchagent(duthost)

            with allure.step(f"Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

            with allure.step("Validate the BGP routes are propagated to T2 VM"):
                validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list)

            with allure.step("Validate traffic is forwarded back to T2 VM"):
                validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                                 ptf_interfaces, ptf_interfaces, loop_back=True)

            with allure.step("Config bgp suppress-fib-pending function"):
                config_bgp_suppress_fib(duthost, validate_result=True)

            with allure.step("Restore orchagent process"):
                assert is_orchagent_stopped(duthost), "orchagent shall in stop state"
                operate_orchagent(duthost, action=ACTION_CONTINUE)

            with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
                validate_route_states(duthost, ipv4_route_list, ipv6_route_list, check_point=OFFLOADED)

            with allure.step("Validate traffic would be forwarded to T0 VM"):
                validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                                 ptf_interfaces, recv_port)
        finally:
            with allure.step(f"Withdraw BGP ipv4 and ipv6 routes from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                          action=WITHDRAW)


def test_suppress_fib_stress(duthost, tbinfo, nbrhosts, ptfadapter, prepare_param, completeness_level,
                             generate_route_and_traffic_data, tcpdump_helper, restore_bgp_suppress_fib):
    with allure.step("Prepare needed parameters"):
        router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param

    with allure.step("Get route and traffic data"):
        ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
            traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[STRESS]

    for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
        try:
            with allure.step("Do BGP route flap"):
                flap_time = 1 if completeness_level == "thorough" else BGP_ROUTE_FLAP_TIMES
                bgp_route_flap_with_stress(duthost, tbinfo, nbrhosts, ptf_ip, ipv4_route_list, exabgp_port,
                                           ipv6_route_list, exabgp_port_v6, flap_time=flap_time)

            with allure.step("Disable bgp suppress-fib-pending function"):
                config_bgp_suppress_fib(duthost, enable=False, validate_result=True)

            with allure.step("Validate traffics are back to T2 VM to make sure routes in HW are removed by orchagent"):
                ptf_interfaces = get_t2_ptf_intfs(mg_facts)
                retry_call(validate_bulk_traffic,
                           fargs=[tcpdump_helper, ptfadapter, traffic_data_ipv4_forward + traffic_data_ipv6_forward,
                                  router_mac, ptf_interfaces, ptf_interfaces], tries=3, delay=2)

            with allure.step("Suspend orchagent process to simulate a route install delay"):
                operate_orchagent(duthost)

            with allure.step(f"Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

            with allure.step("Validate the BGP routes are propagated to T2 VM"):
                validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list)

            with allure.step("Validate traffics are forwarded back to T2 VM"):
                validate_bulk_traffic(tcpdump_helper, ptfadapter,
                                      traffic_data_ipv4_forward + traffic_data_ipv6_forward, router_mac,
                                      ptf_interfaces, ptf_interfaces)

            with allure.step("Config bgp suppress-fib-pending function"):
                config_bgp_suppress_fib(duthost, validate_result=True)

            with allure.step("Restore orchagent process"):
                assert is_orchagent_stopped(duthost), "orchagent shall in stop state"
                operate_orchagent(duthost, action=ACTION_CONTINUE)

            with allure.step("Validate announced BGP ipv4 and ipv6 routes are installed into fib"):
                validate_fib_route(duthost, ipv4_route_list, ipv6_route_list)

            with allure.step("Validate traffic would be forwarded to T0 VM"):
                validate_bulk_traffic(tcpdump_helper, ptfadapter,
                                      traffic_data_ipv4_forward + traffic_data_ipv6_forward, router_mac,
                                      ptf_interfaces, recv_port)
        finally:
            with allure.step(f"Withdraw BGP ipv4 and ipv6 routes from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list,
                                          exabgp_port_v6, action=WITHDRAW)


def test_suppress_fib_performance(tcpdump_helper, duthost, tbinfo, nbrhosts, ptfadapter, prepare_param,
                                  generate_route_and_traffic_data, restore_bgp_suppress_fib):
    with allure.step("Prepare needed parameters"):
        router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param

    with allure.step("Get route and traffic data"):
        ipv4_route_list, ipv6_route_list, _, _, _, _ = generate_route_and_traffic_data[STRESS]

    for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
        try:
            with allure.step("Config bgp suppress-fib-pending function"):
                config_bgp_suppress_fib(duthost)

            with allure.step("Start sniffer"):
                tcpdump_sniffer = tcpdump_helper
                perf_sniffer_prepare(tcpdump_sniffer, duthost, nbrhosts, mg_facts, recv_port)
                tcpdump_sniffer.start_sniffer(host='dut')

            with allure.step(f"Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6)

            with allure.step("Validate the BGP routes are propagated to T2 VM"):
                validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list)

            with allure.step(f"Withdraw BGP ipv4 and ipv6 routes from T0 VM by ExaBGP - "
                             f"v4: {exabgp_port} v6: {exabgp_port_v6}"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                          action=WITHDRAW)
            with allure.step("Validate the BGP routes are withdrawn from T2 VM"):
                validate_route_propagate(duthost, nbrhosts, tbinfo, ipv4_route_list, ipv6_route_list, exist=False)

            with allure.step("Stop sniffer"):
                tcpdump_sniffer.stop_sniffer(host='dut')

            with allure.step("Validate BGP route process performance"):
                validate_route_process_perf(tcpdump_sniffer.pcap_path, ipv4_route_list, ipv6_route_list)
        finally:
            with allure.step("Disable bgp suppress-fib-pending function"):
                config_bgp_suppress_fib(duthost, False, validate_result=True)

            with allure.step("Withdraw BGP ipv4 and ipv6 routes in case of any failure in case"):
                announce_ipv4_ipv6_routes(ptf_ip, ipv4_route_list, exabgp_port, ipv6_route_list, exabgp_port_v6,
                                          action=WITHDRAW)
