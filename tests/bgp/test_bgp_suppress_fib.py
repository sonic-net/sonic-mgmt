import requests
import json
import logging
import random
import ipaddress
import pytest
import allure
import ptf.testutils as testutils
import ptf.packet as scapy
from copy import deepcopy

from ptf.mask import Mask
from natsort import natsorted
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from bgp_helpers import restart_bgp_session, get_eth_port, get_exabgp_port, get_vm_name, get_bgp_neighbor_ip, \
    check_route_install_status, validate_route_propagate_status, operate_orchagent, get_t2_ptf_intfs

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

STATIC_ROUTE_PREFIX = "1.1.1.0/24"
# ipv4 route injection from T0
IP_ROUTE_LIST = [
    '91.0.1.0/24',
    '91.0.2.0/24'
]

# ipv6 route injection from T0
IPV6_ROUTE_LIST = [
    '1000:1001::1/128',
    '1000:1001::2/128'
]

TRAFFIC_DATA_FORWARD = [
    # src_ip, expected_result
    ("91.0.1.1", FORWARD),
    ("91.0.2.1", FORWARD),
    ("1000:1001::1", FORWARD),
    ("1000:1001::2", FORWARD)
]

TRAFFIC_DATA_DROP = [
    # src_ip, expected_result
    ("91.0.1.1", DROP),
    ("91.0.2.1", DROP),
    ("1000:1001::1", DROP),
    ("1000:1001::2", DROP),
]


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
    Restore bgp suppress fib pending function
    """
    yield

    config_bgp_suppress_fib(duthost, False)
    logger.info("Save configuration")
    duthost.shell('sudo config save -y')


@pytest.fixture(scope="module")
def get_exabgp_ptf_ports(duthost, nbrhosts, tbinfo):
    """
    Get ipv4 and ipv6 Exabgp port and ptf receive port
    """
    exabgp_port, ptf_recv_port = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT)
    exabgp_port_v6, ptf_recv_port_v6 = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT_V6)
    return exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6


def is_orchagent_stopped(duthost):
    """
    Check if process 'orchagent' is stopped
    """
    out = duthost.shell('cat /proc/$(pidof orchagent)/status | grep State')['stdout']
    logger.info('Orchagent process - {}'.format(out))
    return ACTION_STOP in out


@pytest.fixture(scope="function", autouse=True)
def withdraw_bgp_routes_and_restore_orchagent(duthost, tbinfo, nbrhosts, get_exabgp_ptf_ports):
    """
    Fixture to withdraw ipv4 and ipv6 routes and restore process 'orchagent' in case of unexpected failures in case
    """
    yield

    ptf_ip = tbinfo['ptf_ip']
    exabgp_port, _, exabgp_port_v6, _ = get_exabgp_ptf_ports
    announce_ipv4_ipv6_routes(ptf_ip, exabgp_port, exabgp_port_v6, action=WITHDRAW)
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


def get_port_connected_with_t0_vm(duthost, nbrhosts):
    """
    Get ports that connects with T0 VM
    """
    port_list = []
    t0_vm_list = [vm_name for vm_name in nbrhosts.keys() if vm_name.endswith('T0')]
    for t0_vm in t0_vm_list:
        port = duthost.shell("show ip interface | grep -w {} | awk '{{print $1}}'".format(t0_vm))['stdout']
        port_list.append(port)
    logger.info("Ports connected with T0 VMs: {}".format(port_list))
    return port_list


def setup_vrf_cfg(duthost, cfg_facts, nbrhosts, tbinfo):
    """
    Config vrf based configuration
    """
    cfg_t1 = deepcopy(cfg_facts)
    cfg_t1.pop('config_port_indices', None)
    port_list = get_port_connected_with_t0_vm(duthost, nbrhosts)
    vm_list = nbrhosts.keys()
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_channel_list = mg_facts['minigraph_portchannels'].keys()
    extra_vars = {'cfg_t1': cfg_t1, 'port_list': port_list, 'vm_list': vm_list, 'pc_list': port_channel_list}

    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src="bgp/vrf_config_db.j2", dest="/tmp/config_db_vrf.json")
    duthost.shell("cp -f /tmp/config_db_vrf.json /etc/sonic/config_db.json")

    config_reload(duthost)


def setup_vrf(duthost, nbrhosts, tbinfo):
    """
    Prepare vrf based environment
    """
    logger.info("Back up original config_db.json")
    duthost.shell("mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    cfg_t1 = get_cfg_facts(duthost)
    setup_vrf_cfg(duthost, cfg_t1, nbrhosts, tbinfo)


def install_route_from_exabgp(operation, ptfip, route, port):
    """
    Install or withdraw ipv4 or ipv6 route by exabgp
    """
    url = "http://{}:{}".format(ptfip, port)
    data = {"command": "{} route {} next-hop self".format(operation, route)}
    logging.info("url: {}".format(url))
    logging.info("data: {}".format(data))
    r = requests.post(url, data=data)
    assert r.status_code == 200


def announce_route(ptfip, route, port, action=ANNOUNCE):
    """
    Announce or withdraw ipv4 or ipv6 route
    """
    logging.info("\n========================== announce_route -- {} ==========================".format(action))
    logging.info(" action:{}\n ptfip:{}\n route:{}\n port:{}".format(action, ptfip, route, port))
    install_route_from_exabgp(action, ptfip, route, port)
    logging.info("\n--------------------------------------------------------------------------------")


def generate_packet(src_ip, dst_ip, dst_mac):
    """
    Build ipv4 and ipv6 packets/expected_packets for testing
    """
    if ipaddress.ip_network(src_ip.encode().decode(), False).version == 4:
        pkt = testutils.simple_ip_packet(eth_dst=dst_mac, ip_src=src_ip, ip_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

    return pkt, exp_pkt


def send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, rx_port, expected_action):
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected
    """
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
    if expected_action == FORWARD:
        testutils.verify_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=5)
    else:
        testutils.verify_no_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=5)


def send_and_verify_loopback_packets(ptfadapter, pkt, exp_pkt, tx_port, rx_ports, expected_action):
    """
    Send packet with ptfadapter and verify if packet is forwarded back or dropped as expected
    """
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
    if expected_action == FORWARD:
        testutils.verify_packets_any(ptfadapter, pkt=exp_pkt, ports=rx_ports)
    else:
        testutils.verify_no_packet_any(ptfadapter, pkt=exp_pkt, ports=rx_ports)


def validate_traffic(ptfadapter, traffic_data, router_mac, ptf_interfaces, recv_port, loop_back=False):
    """
    Verify traffic is forwarded/forwarded back/drop as expected
    """
    for test_item in traffic_data:
        dst_ip = test_item[0]
        expected_result = test_item[1]
        ip_ver = ipaddress.ip_network(dst_ip.encode().decode(), False).version
        logger.info("Testing with dst_ip = {} expected_result = {}"
                    .format(dst_ip, expected_result))
        pkt, exp_pkt = generate_packet(SRC_IP[ip_ver], dst_ip, router_mac)
        tx_port = random.choice(ptf_interfaces)
        if ptf_interfaces is recv_port:
            if loop_back:
                logger.info("Expected packet:\n dst_mac:{} - src_ip:{} - dst_ip:{} - ptf tx_port:{} - ptf rx_port:{}".
                            format(router_mac, SRC_IP[ip_ver], dst_ip, tx_port, ptf_interfaces))
                send_and_verify_loopback_packets(ptfadapter, pkt, exp_pkt, tx_port, ptf_interfaces, expected_result)
            else:
                logger.info("Loopback traffic - expected packet:\n dst_mac:{} - src_ip:{} - dst_ip:{} - ptf tx_port:{}\
                 - ptf rx_port:{}".format(router_mac, SRC_IP[ip_ver], dst_ip, tx_port, tx_port))
                send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, tx_port, expected_result)
        else:
            logger.info("Expected packet:\n dst_mac:{} - src_ip:{} - dst_ip:{} - ptf tx_port:{} - ptf rx_port:{}".
                        format(router_mac, SRC_IP[ip_ver], dst_ip, tx_port, recv_port[ip_ver]))
            send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, recv_port[ip_ver], expected_result)


def announce_ipv4_ipv6_routes(ptf_ip, exabgp_port, exabgp_port_v6, action=ANNOUNCE):
    """
    Announce or withdraw ipv4 and ipv6 routes by exabgp
    """
    for route in IP_ROUTE_LIST:
        announce_route(ptf_ip, route, exabgp_port, action)

    for route in IPV6_ROUTE_LIST:
        announce_route(ptf_ip, route, exabgp_port_v6, action)


def config_bgp_suppress_fib(duthost, enable=True):
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


def validate_route_states(duthost, vrf=DEFAULT, check_point=QUEUED, action=ACTION_IN):
    """
    Verify ipv4 and ipv6 routes install status
    """
    for route in IP_ROUTE_LIST:
        check_route_install_status(duthost, route, vrf, IP_VER, check_point, action)
    for route in IPV6_ROUTE_LIST:
        check_route_install_status(duthost, route, vrf, IPV6_VER, check_point, action)


def validate_route_propagate(duthost, tbinfo, vrf=DEFAULT, exist=True):
    """
    Verify ipv4 and ipv6 route propagate status
    """
    t2_vm = get_vm_name(tbinfo)
    bgp_neighbor_v4, bgp_neighbor_v6 = get_bgp_neighbor_ip(duthost, t2_vm, vrf)
    for route in IP_ROUTE_LIST:
        validate_route_propagate_status(duthost, route, bgp_neighbor_v4, vrf, exist=exist)
    for route in IPV6_ROUTE_LIST:
        validate_route_propagate_status(duthost, route, bgp_neighbor_v6, vrf, ip_ver=IPV6_VER, exist=exist)


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


@pytest.mark.parametrize("vrf_type", VRF_TYPES)
def test_bgp_route_with_suppress(duthost, tbinfo, nbrhosts, ptfadapter, localhost, restore_bgp_suppress_fib,
                                 get_exabgp_ptf_ports, vrf_type, request):
    try:
        if vrf_type == USER_DEFINED_VRF:
            with allure.step("Configure user defined vrf"):
                setup_vrf(duthost, nbrhosts, tbinfo)

        with allure.step("Prepare needed parameters"):
            router_mac = duthost.facts["router_mac"]
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
            ptf_ip = tbinfo['ptf_ip']
            exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 = get_exabgp_ptf_ports
            recv_port = {
                4: ptf_recv_port,
                6: ptf_recv_port_v6
            }

        with allure.step("Config bgp suppress-fib-pending function"):
            config_bgp_suppress_fib(duthost)

        with allure.step("Save configuration"):
            logger.info("Save configuration")
            duthost.shell('sudo config save -y')

        with allure.step("Do reload"):
            param_reboot(request, duthost, localhost)

        with allure.step("Suspend orchagent process to simulate a route install delay"):
            operate_orchagent(duthost)

        with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
            announce_ipv4_ipv6_routes(ptf_ip, exabgp_port, exabgp_port_v6)

        with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(QUEUED)):
            validate_route_states(duthost, vrf_type)

        with allure.step("Validate BGP ipv4 and ipv6 routes are not announced to T2 VM peer"):
            validate_route_propagate(duthost, tbinfo, vrf_type, exist=False)

        with allure.step("Validate traffic could not be forwarded to T0 VM"):
            ptf_interfaces = get_t2_ptf_intfs(mg_facts)
            validate_traffic(ptfadapter, TRAFFIC_DATA_DROP, router_mac, ptf_interfaces, recv_port)

        with allure.step("Restore orchagent process"):
            operate_orchagent(duthost, action=ACTION_CONTINUE)

        with allure.step("Validate announced BGP ipv4 and ipv6 routes are not in {} state".format(QUEUED)):
            validate_route_states(duthost, vrf_type, check_point=QUEUED, action=ACTION_NOT_IN)

        with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
            validate_route_states(duthost, vrf_type, check_point=OFFLOADED)

        with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
            validate_route_propagate(duthost, tbinfo, vrf_type)

        with allure.step("Validate traffic would be forwarded to T0 VM"):
            validate_traffic(ptfadapter, TRAFFIC_DATA_FORWARD, router_mac, ptf_interfaces, recv_port)

    finally:
        if vrf_type == USER_DEFINED_VRF:
            with allure.step("Clean user defined vrf"):
                duthost.shell("cp -f /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
                config_reload(duthost)


def test_bgp_route_without_suppress(duthost, tbinfo, nbrhosts, ptfadapter, get_exabgp_ptf_ports):
    with allure.step("Prepare needed parameters"):
        router_mac = duthost.facts["router_mac"]
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ptf_ip = tbinfo['ptf_ip']
        exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 = get_exabgp_ptf_ports
        recv_port = {
            4: ptf_recv_port,
            6: ptf_recv_port_v6
        }

    with allure.step("Suspend orchagent process to simulate a route install delay"):
        operate_orchagent(duthost)

    with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
        announce_ipv4_ipv6_routes(ptf_ip, exabgp_port, exabgp_port_v6)

    with allure.step("Validate announced BGP ipv4 and ipv6 routes are not in {} state".format(QUEUED)):
        validate_route_states(duthost, check_point=QUEUED, action=ACTION_NOT_IN)

    with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
        validate_route_propagate(duthost, tbinfo)

    with allure.step("Restore orchagent process"):
        operate_orchagent(duthost, action=ACTION_CONTINUE)

    with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
        validate_route_states(duthost, check_point=OFFLOADED)

    with allure.step("Validate traffic would be forwarded to T0 VM"):
        ptf_interfaces = get_t2_ptf_intfs(mg_facts)
        validate_traffic(ptfadapter, TRAFFIC_DATA_FORWARD, router_mac, ptf_interfaces, recv_port)


def test_bgp_route_with_suppress_negative_operation(duthost, tbinfo, nbrhosts, ptfadapter, localhost,
                                                    restore_bgp_suppress_fib, get_exabgp_ptf_ports):
    try:
        with allure.step("Prepare needed parameters"):
            router_mac = duthost.facts["router_mac"]
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
            ptf_ip = tbinfo['ptf_ip']
            exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 = get_exabgp_ptf_ports
            recv_port = {
                4: ptf_recv_port,
                6: ptf_recv_port_v6
            }

        with allure.step("Config bgp suppress-fib-pending function"):
            config_bgp_suppress_fib(duthost)

        with allure.step("Suspend orchagent process to simulate a route install delay"):
            operate_orchagent(duthost)

        with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
            announce_ipv4_ipv6_routes(ptf_ip, exabgp_port, exabgp_port_v6)

        with allure.step("Execute bgp sessions restart"):
            restart_bgp_session(duthost)

        with allure.step("Validate bgp neighbor are established"):
            config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
            bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
            pytest_assert(
                wait_until(300, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
                "graceful restarted bgp sessions {} are not coming back".format(bgp_neighbors)
            )

        with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(QUEUED)):
            validate_route_states(duthost)

        with allure.step("Validate BGP ipv4 and ipv6 routes are not announced to T2 VM peer"):
            validate_route_propagate(duthost, tbinfo, exist=False)

        with allure.step("Config static route and redistribute to BGP"):
            port = get_eth_port(duthost, tbinfo)
            logger.info("Config static route - sudo config route add prefix {} nexthop dev {}".
                        format(STATIC_ROUTE_PREFIX, port))
            duthost.shell("sudo config route add prefix {} nexthop dev {}".format(STATIC_ROUTE_PREFIX, port))
            redistribute_static_route_to_bgp(duthost)

        with allure.step("Validate redistributed static route is propagate to T2 VM peer"):
            t2_vm = get_vm_name(tbinfo)
            bgp_neighbor_v4, _ = get_bgp_neighbor_ip(duthost, t2_vm)
            validate_route_propagate_status(duthost, STATIC_ROUTE_PREFIX, bgp_neighbor_v4)

        with allure.step("Validate traffic could not be forwarded to T0 VM"):
            ptf_interfaces = get_t2_ptf_intfs(mg_facts)
            validate_traffic(ptfadapter, TRAFFIC_DATA_DROP, router_mac, ptf_interfaces, recv_port)

        with allure.step("Restore orchagent process"):
            operate_orchagent(duthost, action=ACTION_CONTINUE)

        with allure.step("Validate announced BGP ipv4 and ipv6 routes are not in {} state".format(QUEUED)):
            validate_route_states(duthost, check_point=QUEUED, action=ACTION_NOT_IN)

        with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
            validate_route_states(duthost, check_point=OFFLOADED)

        with allure.step("Validate BGP ipv4 and ipv6 routes are announced to T2 VM peer"):
            validate_route_propagate(duthost, tbinfo)

        with allure.step("Validate traffic would be forwarded to T0 VM"):
            validate_traffic(ptfadapter, TRAFFIC_DATA_FORWARD, router_mac, ptf_interfaces, recv_port)

    finally:
        with allure.step("Delete static route and remove redistribute to BGP"):
            remove_static_route_and_redistribute(duthost)


def test_credit_loop(duthost, tbinfo, nbrhosts, ptfadapter, get_exabgp_ptf_ports, restore_bgp_suppress_fib):
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
        router_mac = duthost.facts["router_mac"]
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ptf_ip = tbinfo['ptf_ip']
        exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 = get_exabgp_ptf_ports
        recv_port = {
            4: ptf_recv_port,
            6: ptf_recv_port_v6
        }

    with allure.step("Suspend orchagent process to simulate a route install delay"):
        operate_orchagent(duthost)

    with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
        announce_ipv4_ipv6_routes(ptf_ip, exabgp_port, exabgp_port_v6)

    with allure.step("Validate the BGP routes are propagated to T2 VM"):
        validate_route_propagate(duthost, tbinfo)

    with allure.step("Validate traffic is forwarded back to T2 VM"):
        ptf_interfaces = get_t2_ptf_intfs(mg_facts)
        validate_traffic(ptfadapter, TRAFFIC_DATA_FORWARD, router_mac, ptf_interfaces, ptf_interfaces, loop_back=True)

    with allure.step("Config bgp suppress-fib-pending function"):
        config_bgp_suppress_fib(duthost)

    with allure.step("Restore orchagent process"):
        operate_orchagent(duthost, action=ACTION_CONTINUE)

    with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(OFFLOADED)):
        validate_route_states(duthost, check_point=OFFLOADED)

    with allure.step("Validate traffic would be forwarded to T0 VM"):
        ptf_interfaces = get_t2_ptf_intfs(mg_facts)
        validate_traffic(ptfadapter, TRAFFIC_DATA_FORWARD, router_mac, ptf_interfaces, recv_port)
