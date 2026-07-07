import logging
import time
import requests
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.helpers.dut_utils import get_available_tech_support_files, get_new_techsupport_files_list, \
    extract_techsupport_tarball_file
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.srv6_helper import SRv6

logger = logging.getLogger(__name__)
LOCATOR_NUM = 128
ROUTE_BASE = '2001'


class MyLocators():
    # Generate 128 locators with incrementing IPv6 addresses
    my_locator_list = [
        [f'locator_{i + 1}', f'{ROUTE_BASE}:1001:{1 + i}::', f'{1 + i}'] for i in range(LOCATOR_NUM)
    ]


class MySIDs(MyLocators):
    TUNNEL_MODE = [SRv6.pipe_mode]
    # Generate 128 SIDs based on the locator list
    MY_SID_LIST = [
        [locator_name, sid, SRv6.uN, 'default']
        for locator_name, sid, _ in MyLocators.my_locator_list
    ]


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
    ptfadapter.dataplane.flush()
    ptfadapter.dataplane.set_qlen(1000000)
    # Send the packet and poll on destination ports
    testutils.send(ptfadapter, src_port, pkt, 1)
    logger.debug("Sent packet: " + pkt.summary())

    time.sleep(1)
    (index, rcv_pkt) = testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ports, timeout=60)
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


def enable_srv6_counterpoll(duthost):
    """
    Enable SRv6 counterpoll on the DUT.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cmd = 'sudo counterpoll srv6 enable'
        duthost.shell(cmd)
        logger.info("Successfully enabled SRv6 counterpoll")
        return True
    except Exception as e:
        raise Exception(f"Failed to enable SRv6 counterpoll: {str(e)}")


def disable_srv6_counterpoll(duthost):
    """
    Disable SRv6 counterpoll on the DUT.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cmd = 'sudo counterpoll srv6 disable'
        duthost.shell(cmd)
        logger.info("Successfully disabled SRv6 counterpoll")
        return True
    except Exception as e:
        raise Exception(f"Failed to disable SRv6 counterpoll: {str(e)}")


def set_srv6_counterpoll_interval(duthost, interval_ms, wait_for_new_interval=True):
    """
    Set the polling interval for SRv6 counterpoll.

    Args:
        duthost (SonicHost): DUT host object
        interval_ms (int): Polling interval in milliseconds
        wait_for_new_interval (bool): Whether to wait for the new interval to take effect

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get current interval
        current_status = duthost.get_counter_poll_status()
        if 'SRV6_STAT' not in current_status:
            logger.error("SRv6 counterpoll is not available")
            return False

        current_interval = current_status['SRV6_STAT']['interval']

        # Set new interval
        cmd = f'sudo counterpoll srv6 interval {interval_ms}'
        duthost.shell(cmd)

        # Wait for the new interval to take effect if requested
        if wait_for_new_interval:
            wait_time = current_interval / 1000 + 1  # Convert to seconds and add 1 second buffer
            logger.info(f"Waiting {wait_time} seconds for new interval to take effect")
            time.sleep(wait_time)

        logger.info(f"Successfully set SRv6 counterpoll interval to {interval_ms} ms")
        return True
    except Exception as e:
        raise Exception(f"Failed to set SRv6 counterpoll interval: {str(e)}")


def get_srv6_counterpoll_status(duthost):
    """
    Get the current status of SRv6 counterpoll.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        dict: Dictionary containing status information or None if failed
    """
    try:
        status = duthost.get_counter_poll_status()
        if 'SRV6_STAT' in status:
            return status['SRV6_STAT']
        return None
    except Exception as e:
        raise Exception(f"Failed to get SRv6 counterpoll status: {str(e)}")


def verify_srv6_counterpoll_status(duthost, expected_status, expected_interval=None):
    """
    Verify the status of SRv6 counterpoll.

    Args:
        duthost (SonicHost): DUT host object
        expected_status (str): Expected status ('enable' or 'disable')
        expected_interval (str): Expected interval in milliseconds
    Returns:
        bool: True if status matches expected, False otherwise
    """
    try:
        status = get_srv6_counterpoll_status(duthost)
        if status is None:
            return False

        actual_status = status['status'].lower()
        expected_status = expected_status.lower()
        actual_interval = status['interval']

        if expected_interval:
            if actual_interval != expected_interval:
                logger.error(f"SRv6 counterpoll interval mismatch. Expected: {expected_interval}, "
                             f"Actual: {actual_interval}")
                return False

        if actual_status == expected_status:
            logger.info(f"SRv6 counterpoll status verified as {expected_status}")
            return True
        else:
            logger.error(f"SRv6 counterpoll status mismatch. Expected: {expected_status}, Actual: {actual_status}")
            return False
    except Exception as e:
        raise Exception(f"Failed to verify SRv6 counterpoll status: {str(e)}")


def validate_srv6_counters(duthost, srv6_pkt_list, mysid_list, pkt_num):
    """
    Validate SRv6 counters based on the list of SRv6 packets.

    Args:
        duthost (SonicHost): DUT host object
        srv6_pkt_list (list): List of SRv6 packets
        mysid_list (list): List of MySID to validate
        pkt_num (int): Number of packets to validate

    Returns:
        bool: True if counters match expected values, False otherwise
    """
    try:
        stats_list = duthost.show_and_parse('show srv6 stats')
        stats_dict = {item['mysid']: item for item in stats_list}

        for srv6_pkt, mysid in zip(srv6_pkt_list, mysid_list):
            # Wireshark and PTF do not include FCS field when calculating frame length, but the switch does,
            # so add 4 bytes when validating SRv6 counters at switch
            single_pkt_len = len(srv6_pkt) + 4
            mysid_with_prefix = mysid[1] + '/' + str(SRv6.prefix_len)

            if mysid_with_prefix not in stats_dict:
                logger.error(f"MySID {mysid_with_prefix} not found in SRv6 statistics")
                return False

            current_stats = stats_dict[mysid_with_prefix]
            current_packets = int(current_stats['packets'])
            current_bytes = int(current_stats['bytes'])

            if current_packets != pkt_num or current_bytes != pkt_num * single_pkt_len:
                logger.error(f"SRv6 statistics mismatch for MySID {mysid_with_prefix}: "
                             f"Expected Packets={pkt_num}, Bytes={pkt_num * single_pkt_len}, "
                             f"Actual Packets={current_packets}, Bytes={current_bytes}")
                return False

            logger.info(f"SRv6 statistics match expected values for MySID {mysid_with_prefix}: "
                        f"Packets={current_packets}, Bytes={current_bytes}")

        return True
    except Exception as e:
        raise Exception(f"Failed to validate SRv6 counters: {str(e)}")


def get_srv6_mysid_entry_usage(duthost):
    """
    Get the usage information of SRv6 MySID Entry resources.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        dict: Dictionary containing usage information with keys:
            - 'used_count': Number of used entries
            - 'available_count': Number of available entries
            - 'total_count': Total number of entries
        Returns None if failed to get the information
    """
    try:
        # Get SRv6 MySID Entry usage information using show_and_parse
        usage_list = duthost.show_and_parse('crm show resources srv6-my-sid-entry')

        # Find the entry for srv6_my_sid_entry
        for entry in usage_list:
            if entry['resource name'] == 'srv6_my_sid_entry':
                used_count = int(entry['used count'])
                available_count = int(entry['available count'])
                total_count = used_count + available_count

                result = {
                    'used_count': used_count,
                    'available_count': available_count,
                    'total_count': total_count
                }

                logger.info(f"SRv6 MySID Entry usage: Used={used_count}, Available={available_count}, "
                            f"Total={total_count}")
                return result

        logger.error("SRv6 MySID Entry resource not found in CRM output")
        return None

    except Exception as e:
        raise Exception(f"Failed to get SRv6 MySID Entry usage: {str(e)}")


def clear_srv6_counters(duthost):
    """
    Clear all SRv6 counters using sonic-clear command.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cmd = 'sudo sonic-clear srv6counters'
        duthost.shell(cmd)
        logger.info("Successfully cleared SRv6 counters")
        return True
    except Exception as e:
        raise Exception(f"Failed to clear SRv6 counters: {str(e)}")


def verify_srv6_crm_status(duthost, expected_used_count, expected_available_count):
    '''
    Verify the CRM status of SRv6 SID.

    Args:
        duthost (SonicHost): DUT host object
        expected_used_count (int): Expected number of used entries
        expected_available_count (int): Expected number of available entries
    '''
    mysid_crm_status = get_srv6_mysid_entry_usage(duthost)
    if not mysid_crm_status:
        logger.info("Failed to get SRv6 MySID Entry usage")
        return False
    if mysid_crm_status['used_count'] != expected_used_count:
        logger.info(f"Expected {expected_used_count} used SRv6 MySID Entries, but got {mysid_crm_status['used_count']}")
        return False
    if mysid_crm_status['available_count'] != expected_available_count:
        logger.info(f"Expected {expected_available_count} available SRv6 MySID Entries, "
                    f"but got {mysid_crm_status['available_count']}")
        return False

    logger.info("SRv6 MySID Entry usage verified successfully")
    return True


#
# Get the mac address of a neighbor
#
def get_neighbor_mac(dut, neighbor_ip):
    """Get the MAC address of the neighbor via the ip neighbor table"""
    return dut.command("ip neigh show {}".format(neighbor_ip))['stdout'].split()[4]


def verify_asic_db_sid_entry_exist(duthost, sonic_db_cli):
    """
    Verify that ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries exist in the ASIC DB.
    Args:
        duthost: The DUT host object
        sonic_db_cli: The sonic-db-cli command with namespace options
    Returns:
        bool: True if entries exist, False otherwise
    """
    asic_db_my_sids = duthost.command(sonic_db_cli +
                                      " ASIC_DB keys *ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY*")["stdout"]
    return len(asic_db_my_sids.strip()) > 0
