import logging
import time
import requests
import random
import sys
from io import StringIO
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.dut_utils import get_available_tech_support_files, get_new_techsupport_files_list, \
    extract_techsupport_tarball_file
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


class SRv6():
    uN = 'uN'
    prefix_len = '48'
    pipe_mode = 'pipe'
    uniform_mode = 'uniform'


class SRv6Packets():
    '''
    Define the ipv6 packets used in srv6 test
    Each item was defined with actions and packet type as well as segment left and segment list, destination ip
    '''
    srv6_packets = [
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': None,
            'outer_dscp': None,
            'dst_ipv6': '2001:1000:0100:0200::',
            'exp_dst_ipv6': '2001:1000:0200::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward',
        },
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': None,
            'outer_dscp': None,
            'dst_ipv6': '2001:1001:0200:0300::',
            'exp_dst_ipv6': '2001:1001:0300::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'one_u_sid',
            'srh_seg_left': 1,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': ['2001:2000:0300:0400:0500:0600::'],
            'dst_ipv6': '2001:2000:0300::',
            'exp_dst_ipv6': '2001:2000:0300:0400:0500:0600::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 0,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'one_u_sid',
            'srh_seg_left': 1,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': ['2001:2001:0400:0500:0600::'],
            'dst_ipv6': '2001:2001:0400:0500::',
            'exp_dst_ipv6': '2001:2001:0500::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 1,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'two_u_sid',
            'srh_seg_left': 1,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': [
                '2001:3000:0500:0600::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:3000:0500::',
            'exp_dst_ipv6': '2001:3000:0500:0600::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 0,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'two_u_sid',
            'srh_seg_left': 2,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': [
                '2001:3001:0500::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:3001:0600::',
            'exp_dst_ipv6': '2001:3000:0600:0700:0800:0900:0a00::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 1,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': 20,
            'outer_dscp': 40,
            'dst_ipv6': '2001:4000:0700::',
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'exp_inner_dscp_pipe': 20,
            'exp_outer_dscp_uniform': 40,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'one_u_sid',
            'srh_seg_left': 0,
            'inner_dscp': 32,
            'outer_dscp': 31,
            'srh_seg_list': [
                '2001:3001:0500::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:4001:0800::',
            'exp_inner_dscp_pipe': 32,
            'exp_outer_dscp_uniform': 31,
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'two_u_sid',
            'srh_seg_left': 0,
            'inner_dscp': 2,
            'outer_dscp': 62,
            'srh_seg_list': [
                '2001:3001:0500::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:5000:0900::',
            'exp_inner_dscp_pipe': 2,
            'exp_outer_dscp_uniform': 62,
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': 63,
            'outer_dscp': 1,
            'dst_ipv6': '2001:5001:0a00::',
            'exp_inner_dscp_pipe': 63,
            'exp_outer_dscp_uniform': 1,
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        }
    ]
    srv6_next_header = {
        scapy.IP: 4,
        scapy.IPv6: 41
    }


class MyLocators():
    my_locator_list = [
        ['locator_1', '2001:1000:100::'],
        ['locator_2', '2001:1001:200::'],
        ['locator_3', '2001:2000:300::'],
        ['locator_4', '2001:2001:400::'],
        ['locator_5', '2001:3000:500::'],
        ['locator_6', '2001:3001:600::'],
        ['locator_7', '2001:4000:700::'],
        ['locator_8', '2001:4001:800::'],
        ['locator_9', '2001:5000:900::'],
        ['locator_10', '2001:5001:a00::']
    ]


class MySIDs(MyLocators):
    TUNNEL_MODE = [SRv6.pipe_mode]
    MY_SID_LIST = [
        [MyLocators.my_locator_list[0][0], MyLocators.my_locator_list[0][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[1][0], MyLocators.my_locator_list[1][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[2][0], MyLocators.my_locator_list[2][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[3][0], MyLocators.my_locator_list[3][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[4][0], MyLocators.my_locator_list[4][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[5][0], MyLocators.my_locator_list[5][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[6][0], MyLocators.my_locator_list[6][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[7][0], MyLocators.my_locator_list[7][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[8][0], MyLocators.my_locator_list[8][1], SRv6.uN, 'default'],
        [MyLocators.my_locator_list[9][0], MyLocators.my_locator_list[9][1], SRv6.uN, 'default']
    ]


def create_srv6_locator(duthost,
                        locator_name,
                        prefix,
                        block_len=32,
                        node_len=16,
                        func_len=0,
                        arg_len=0):
    logger.info(f'Configure locator: SRV6_MY_LOCATORS|{locator_name}')
    duthost.shell(
        f'sonic-db-cli CONFIG_DB HSET "SRV6_MY_LOCATORS|{locator_name}" '
        f'"prefix" "{prefix}" '
        f'"block_len" "{block_len}" '
        f'"node_len" "{node_len}" '
        f'"func_len" "{func_len}" '
        f'"arg_len" "{arg_len}"')


def validate_srv6_in_appl_db(duthost,
                             block_len=32,
                             node_len=16,
                             func_len=0,
                             arg_len=0):
    for entry in MySIDs.MY_SID_LIST:
        prefix = entry[1]
        action = entry[2]
        try:
            appl_action = duthost.shell(f'sonic-db-cli APPL_DB HGET "SRV6_MY_SID_TABLE:'
                                        f'{block_len}:{node_len}:{func_len}:{arg_len}:{prefix}" action')["stdout"]
            if action.lower() != appl_action:
                logger.error(f"Real action is {appl_action}, but expected action is {action}")
                return False
        except Exception as err:
            logger.error(f"Failed to check SRV6_MY_SID_TABLE - prefix:{prefix} in Application DB")
            raise err
    return True


def del_srv6_locator(duthost, locator_name):
    logger.info(f'Delete locator: SRV6_MY_LOCATORS|{locator_name}')
    duthost.shell(f'sonic-db-cli CONFIG_DB DEL "SRV6_MY_LOCATORS|{locator_name}"')


def create_srv6_sid(duthost,
                    locator_name,
                    ip_addr,
                    action=SRv6.uN,
                    decap_vrf='default',
                    decap_dscp_mode=SRv6.uniform_mode):
    logger.info(f'Configure sid: SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}')
    duthost.shell(
        f'sonic-db-cli CONFIG_DB HSET "SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}" '
        f'"action" "{action}" '
        f'"decap_vrf" "{decap_vrf}" '
        f'"decap_dscp_mode" "{decap_dscp_mode}"')


def del_srv6_sid(duthost, locator_name, ip_addr):
    logger.info(f'Delete sid: SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}')
    duthost.shell(f'sonic-db-cli CONFIG_DB DEL "SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}"')


def random_reboot(duthost, localhost):
    """
    Randomly choose one action from reload/cold reboot and do the action and wait system recovery
    """
    reboot_type_list = ["reload", "cold"]
    reboot_type = random.choice(reboot_type_list)
    logger.info(f'Randomly choose {reboot_type} from {reboot_type_list}')

    if reboot_type == "reload":
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    else:
        logger.info(f'Do {reboot_type}')
        reboot(duthost, localhost, reboot_type=reboot_type, wait_warmboot_finalizer=True, safe_reboot=True,
               check_intf_up_ports=True, wait_for_bgp=True)


def dump_packet_detail(pkt):
    _stdout, sys.stdout = sys.stdout, StringIO()
    try:
        pkt.show()
        return sys.stdout.getvalue()
    finally:
        sys.stdout = _stdout


def validate_sai_sdk_dump_files(duthost, techsupport_folder, feature_list=[]):
    """
    Validated that expected SAI dump file available inside in techsupport dump file
    """
    logger.info('Validate SAI dump file is included in the tech-support dump')
    saidump_files_inside_techsupport = \
        duthost.shell(f'ls {techsupport_folder}/sai_sdk_dump')['stdout_lines']
    assert saidump_files_inside_techsupport, 'Expected SAI SDK dump file(folder) not available in techsupport dump'
    for feature in feature_list:
        for sai_sdk_dump in saidump_files_inside_techsupport:
            res = duthost.shell(f'zgrep {feature} {techsupport_folder}/sai_sdk_dump/{sai_sdk_dump}',
                                module_ignore_errors=True)['stdout_lines']
            if res and feature in ''.join(res):
                logger.info(f'Feature {feature} parameter exist in {techsupport_folder}/sai_sdk_dump/{sai_sdk_dump}'
                            f'\n{res}')
                break
        else:
            raise Exception(f'Feature "{feature}" parameter does not exist in sai sdk dump files')


def validate_techsupport_generation(duthost, feature_list=[]):
    """
    Validate sai sdk dump file exist
    """
    available_tech_support_files = get_available_tech_support_files(duthost)
    logger.info('Execute show techsupport command')
    duthost.shell('show techsupport')
    new_techsupport_files_list = get_new_techsupport_files_list(duthost, available_tech_support_files)
    tech_support_file_path = new_techsupport_files_list[0]
    logger.info(f'New tech support file: {new_techsupport_files_list}')
    tech_support_name = tech_support_file_path.split('.')[0].lstrip('/var/dump/')

    try:
        logger.info(f'Doing validation for techsupport : {tech_support_name}')
        techsupport_folder_path = extract_techsupport_tarball_file(duthost, tech_support_file_path)
        logger.info('Checking that expected SAI SDK dump file available in techsupport file')
        validate_sai_sdk_dump_files(duthost, techsupport_folder_path, feature_list)
    finally:
        logger.info(f'Delete {tech_support_file_path}')
        duthost.shell(f'sudo rm -rf {tech_support_file_path}')


#
# log directory inside each vsonic. vsonic starts with admin as user.
#
test_log_dir = "/home/admin/testlogs/"


#
# Helper func for print a set of lines
#
def print_lines(outlines):
    for line in outlines:
        logger.debug(line)


#
# Util functions for announce / withdraw routes from ptf docker.
#
def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)


def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)


def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" % (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


#
# Skip some BGP neighbor check
#
def skip_bgp_neighbor_check(neighbor):
    skip_addresses = []
    for addr in skip_addresses:
        if neighbor == addr:
            return True

    return False


#
# Helper func to check if a list of BGP neighbors are up
#
def check_bgp_neighbors_func(nbrhost, neighbors, vrf=""):
    cmd = "vtysh -c 'show bgp summary'"
    if vrf != "":
        cmd = "vtysh -c 'show bgp vrf {} summary'".format(vrf)
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for neighbor in neighbors:
        if skip_bgp_neighbor_check(neighbor):
            logger.debug("Skip {} check".format(neighbor))
            found = found + 1
            continue

        for line in res:
            if neighbor in line:
                arr = line.split()
                pfxrcd = arr[9]
                try:
                    int(pfxrcd)
                    found = found + 1
                    logger.debug("{} ==> BGP neighbor is up and gets pfxrcd {}".format(line, pfxrcd))
                except ValueError:
                    logger.debug("{} ==> BGP neighbor state {}, not up".format(line, pfxrcd))
    return len(neighbors) == found


#
# Checke BGP neighbors
#
def check_bgp_neighbors(nbrhost, neighbors, vrf=""):
    pytest_assert(check_bgp_neighbors_func(nbrhost, neighbors, vrf))


#
# Helper function to count number of Ethernet interfaces
#
def find_node_interfaces(nbrhost):
    cmd = "show version"
    res = nbrhost.command(cmd)["stdout_lines"]
    hwsku = ""
    for line in res:
        if "HwSKU:" in line:
            logger.debug("{}".format(line))
            sarr = line.split()
            hwsku = sarr[1]
            break

    cmd = "show interface status"
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for line in res:
        logger.debug("{}".format(line))
        if "Ethernet" in line:
            found = found + 1

    return found, hwsku


#
# Send receive packets
#
def runSendReceive(pkt, src_port, exp_pkt, dst_ports, pkt_expected, ptfadapter):
    """
    @summary Send packet and verify it is received/not received on the expected ports
    @param pkt: The packet that will be injected into src_port
    @param src_ports: The port into which the pkt will be injected
    @param exp_pkt: The packet that will be received on one of the dst_ports
    @param dst_ports: The ports on which the exp_pkt may be received
    @param pkt_expected: Indicated whether it is expected to receive the exp_pkt on one of the dst_ports
    @param ptfadapter: The ptfadapter fixture
    """
    # Send the packet and poll on destination ports
    testutils.send(ptfadapter, src_port, pkt, 1)
    logger.debug("Sent packet: " + pkt.summary())

    time.sleep(1)
    (index, rcv_pkt) = testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ports)
    received = False
    if rcv_pkt:
        received = True
    pytest_assert(received == pkt_expected)
    logger.debug('index=%s, received=%s' % (str(index), str(received)))
    if received:
        logger.debug("Received packet: " + scapy.Ether(rcv_pkt).summary())
    if pkt_expected:
        logger.debug('Expected packet on dst_ports')
        passed = True if received else False
        logger.debug('Received: ' + str(received))
    else:
        logger.debug('No packet expected on dst_ports')
        passed = False if received else True
        logger.debug('Received: ' + str(received))
    logger.debug('Passed: ' + str(passed))
    return passed


#
# Helper func to check if a list of IPs go via a given set of next hop
#
def check_routes_func(nbrhost, ips, nexthops, vrf="", is_v6=False):
    # Check remote learnt dual homing routes
    vrf_str = ""
    if vrf != "":
        vrf_str = "vrf {}".format(vrf)
    ip_str = "ip"
    if is_v6:
        ip_str = "ipv6"
    for ip in ips:
        cmd = "show {} route {} {} nexthop-group".format(ip_str, vrf_str, ip)
        res = nbrhost.command(cmd)["stdout_lines"]
        print_lines(res)
        found = 0
        for nexthop in nexthops:
            for line in res:
                if nexthop in line:
                    found = found + 1
        if len(nexthops) != found:
            return False
    return True


#
# check if a list of IPs go via a given set of next hop
#
def check_routes(nbrhost, ips, nexthops, vrf="", is_v6=False):
    # Add retry for debugging purpose
    count = 0
    ret = False

    #
    # Sleep 10 sec before retrying
    #
    sleep_duration_for_retry = 10

    # retry 3 times before claiming failure
    while count < 3 and not ret:
        ret = check_routes_func(nbrhost, ips, nexthops, vrf, is_v6)
        if not ret:
            count = count + 1
            # sleep make sure all forwarding structures are settled down.
            time.sleep(sleep_duration_for_retry)
            logger.info("Sleep {} seconds to retry round {}".format(sleep_duration_for_retry, count))

    pytest_assert(ret)


#
# Record fwding chain to a file
#
def recording_fwding_chain(nbrhost, fname, comments):

    filename = "{}{}".format(test_log_dir, fname)

    cmd = "mkdir -p {}".format(test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "sudo touch /etc/sonic/frr/vtysh.conf"
    nbrhost.shell(cmd, module_ignore_errors=True)

    cmd = "date >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "echo ' {}' >> {} ".format(comments, filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show bgp summary' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ip route vrf Vrf1 192.100.1.0 nexthop-group' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ipv6 route fd00:201:201:fff1:11:: nexthop-group' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ipv6 route fd00:202:202:fff2:22:: nexthop-group' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)

    cmd = "echo '' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Debug commands for FRR zebra
#
debug_cmds = [
    'debug zebra events',
    'debug zebra rib',
    'debug zebra rib detailed',
    'debug zebra nht',
    'debug zebra nht detailed',
    'debug zebra dplane',
    'debug zebra nexthop',
    'debug zebra nexthop detail',
    'debug zebra packet',
    'debug zebra packet detail'
]


#
# Turn on/off FRR debug to a file
#
def turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, filename, vm, is_on=True):
    nbrhost = nbrhosts[vm]['host']
    # save frr log to a file
    pfxstr = " "
    if not is_on:
        pfxstr = " no "

    cmd = "vtysh -c 'configure terminal' -c '{} log file {}'".format(pfxstr, filename)
    nbrhost.command(cmd)

    #
    # Change frr debug flags
    #
    for dcmd in debug_cmds:
        cmd = "vtysh -c '" + pfxstr + dcmd + "'"
        nbrhost.command(cmd)

    #
    # Check debug flags
    #
    cmd = "vtysh -c 'show debug'"
    nbrhost.shell(cmd, module_ignore_errors=True)
    #
    # Check log file
    #
    cmd = "vtysh -c 'show run' | grep log"
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Collect file from bgp docker
#
def collect_frr_debugfile(duthosts, rand_one_dut_hostname, nbrhosts, filename, vm):
    nbrhost = nbrhosts[vm]['host']
    cmd = "mkdir -p {}".format(test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "docker cp bgp:{} {}".format(filename, test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Verify that the SID entry is programmed in APPL_DB
#
def verify_appl_db_sid_entry_exist(duthost, sonic_db_cli, key, exist):
    appl_db_my_sids = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]
    return key in appl_db_my_sids if exist else key not in appl_db_my_sids


#
# Get the mac address of a neighbor
#
def get_neighbor_mac(dut, neighbor_ip):
    """Get the MAC address of the neighbor via the ip neighbor table"""
    return dut.command("ip neigh show {}".format(neighbor_ip))['stdout'].split()[4]
