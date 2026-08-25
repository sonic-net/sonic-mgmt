import json
import logging
import random
import re
import string
import time
import pytest
import requests
import ptf.packet as scapy
import ptf.testutils as testutils

from ptf.mask import Mask
from ptf.testutils import simple_ipv6_sr_packet, send_packet, verify_no_packet_any
from scapy.all import Raw
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
from tests.common.helpers.dut_utils import get_available_tech_support_files, get_new_techsupport_files_list, \
    extract_techsupport_tarball_file
from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat
from tests.common.utilities import wait_until
from tests.common.helpers.srv6_helper import SRv6

logger = logging.getLogger(__name__)
LOCATOR_NUM = 128
ROUTE_BASE = '2001'

# CRM refreshes its resource counters on this interval, in seconds
CRM_DEFAULT_POLL_INTERVAL = 300
CRM_FAST_POLL_INTERVAL = 10

#
# uN configuration used by the SRv6 data plane and warm reboot tests
#
UN_LOCATOR_NAME = 'loc1'
UN_LOCATOR_PREFIX = 'fcbb:bbbb:1::'
UN_SID_PREFIX = 'fcbb:bbbb:1::/48'
UN_SID_APPL_DB_KEY = 'SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::'
# Destination address of the injected packets, it matches the uN SID above
UN_SID_TRAFFIC_DST = 'fcbb:bbbb:1:2::'
# Destination address of the packets once the uN behavior has been applied
UN_EGRESS_DST = 'fcbb:bbbb:2::'
UN_EGRESS_ROUTE = 'fcbb:bbbb:2::/48'
SRV6_BLACKHOLE_ROUTE = 'fcbb:bbbb::/32'


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
    if duthost.facts["asic_type"] == "vpp":
        return True
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


def get_crm_polling_interval(duthost):
    """
    Return the CRM polling interval, in seconds, configured on the DUT.

    Falls back to the SONiC default when the value cannot be parsed, so that the
    caller always has something to restore.
    """
    output = duthost.command("crm show summary", module_ignore_errors=True)["stdout"]
    match = re.search(r'Polling Interval:\s*(\d+)\s*second', output)
    if match:
        return int(match.group(1))
    logger.warning("Could not parse the CRM polling interval from {!r}, assuming the default {}s"
                   .format(output, CRM_DEFAULT_POLL_INTERVAL))
    return CRM_DEFAULT_POLL_INTERVAL


def set_crm_polling_interval(duthost, interval):
    """Set the CRM polling interval, in seconds, on the DUT."""
    logger.info("Setting the CRM polling interval to {}s".format(interval))
    duthost.command("crm config polling interval {}".format(interval))


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


def _normalize_asic_db_mysid_key(key):
    """
    Build a comparable identity for an ASIC_DB MY_SID entry key.

    The key embeds the entry definition as a json document, e.g.
    ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY:{"switch_id":"oid:0x21...","sid":"fcbb:bbbb:1::",...}
    The SAI object ids are dropped so that the comparison only covers the entry
    itself: both the switch id and the virtual router id are allocated by syncd
    and are legitimately reassigned across a warm reboot, while the SID and its
    locator, function and argument lengths identify the entry.
    """
    _, _, entry = key.partition('SAI_OBJECT_TYPE_MY_SID_ENTRY:')
    if not entry:
        return key
    try:
        decoded = json.loads(entry)
    except ValueError:
        return entry
    if isinstance(decoded, dict):
        decoded.pop('switch_id', None)
        decoded.pop('vr_id', None)
        return json.dumps(decoded, sort_keys=True)
    return entry


def get_asic_db_mysid_entries(duthost, sonic_db_cli="sonic-db-cli"):
    """
    Collect the SRv6 MY_SID entries programmed in the ASIC DB.

    Returns:
        dict: {normalized entry key: {attribute: value}}
    """
    entries = {}
    keys = duthost.command(
        sonic_db_cli + ' ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY*"')["stdout"]
    for key in keys.splitlines():
        key = key.strip()
        if not key:
            continue
        attributes = duthost.command(
            "{} ASIC_DB HGETALL '{}'".format(sonic_db_cli, key), module_ignore_errors=True)["stdout"]
        entries[_normalize_asic_db_mysid_key(key)] = attributes
    return entries


def verify_static_route_installed(duthost, prefix, nexthop=None, ifname=None, blackhole=False,
                                  sonic_db_cli="sonic-db-cli", cli_options=""):
    """
    Verify that a static route is installed all the way down to the ASIC.

    The static routes used for SRv6 forwarding are configured in CONFIG_DB and
    are never redistributed into BGP, so they cannot be verified from a BGP
    neighbor. They are instead checked on the box, stage by stage, so that a
    failure tells which component did not program the route:
    FRR RIB -> kernel -> APPL_DB -> ASIC_DB.

    Args:
        duthost: DUT host object
        prefix: the route prefix, e.g. fcbb:bbbb:2::/48
        nexthop: expected next hop address, checked when given
        ifname: expected egress interface, checked when given
        blackhole: True when the route is expected to be a blackhole route
        sonic_db_cli: sonic-db-cli command, including the namespace options
        cli_options: namespace options for vtysh

    Returns:
        bool: True when the route is installed everywhere it is expected to be
    """
    # 1. FRR RIB
    frr_route = duthost.command(
        'vtysh{} -c "show ipv6 route {} json"'.format(cli_options, prefix),
        module_ignore_errors=True)["stdout"]
    try:
        frr_routes = json.loads(frr_route) if frr_route.strip() else {}
    except ValueError:
        logger.error("Unable to parse the FRR route entry for {}: {}".format(prefix, frr_route))
        return False

    frr_entries = []
    for route_entries in frr_routes.values():
        frr_entries.extend(route_entries)
    static_entries = [entry for entry in frr_entries if entry.get('protocol') == 'static']
    if not static_entries:
        logger.error("Static route {} is missing from the FRR RIB".format(prefix))
        return False
    if not any(entry.get('selected') or entry.get('installed') for entry in static_entries):
        logger.error("Static route {} is in the FRR RIB but is not selected nor installed".format(prefix))
        return False

    # 2. Linux kernel
    kernel_route = duthost.command(
        "ip -6 route show {}".format(prefix), module_ignore_errors=True)["stdout"]
    if prefix.split('/')[0] not in kernel_route:
        logger.error("Static route {} is missing from the kernel routing table".format(prefix))
        return False
    if blackhole and "blackhole" not in kernel_route:
        logger.error("Route {} is not a blackhole route in the kernel: {}".format(prefix, kernel_route))
        return False
    if nexthop and nexthop not in kernel_route:
        logger.error("Static route {} does not use next hop {} in the kernel: {}".format(
            prefix, nexthop, kernel_route))
        return False
    if ifname and ifname not in kernel_route:
        logger.error("Static route {} does not use interface {} in the kernel: {}".format(
            prefix, ifname, kernel_route))
        return False

    # 3. APPL_DB
    appl_db_route = duthost.command(
        "{} APPL_DB HGETALL 'ROUTE_TABLE:{}'".format(sonic_db_cli, prefix),
        module_ignore_errors=True)["stdout"]
    if not appl_db_route.strip():
        logger.error("Static route {} is missing from APPL_DB".format(prefix))
        return False
    if blackhole and "true" not in appl_db_route.lower():
        logger.error("Route {} is not marked as blackhole in APPL_DB: {}".format(prefix, appl_db_route))
        return False
    if nexthop and nexthop not in appl_db_route:
        logger.error("Static route {} does not use next hop {} in APPL_DB: {}".format(
            prefix, nexthop, appl_db_route))
        return False

    # 4. ASIC_DB
    asic_db_route = duthost.command(
        '{} ASIC_DB KEYS "*SAI_OBJECT_TYPE_ROUTE_ENTRY*{}*"'.format(sonic_db_cli, prefix),
        module_ignore_errors=True)["stdout"]
    if not asic_db_route.strip():
        logger.error("Static route {} is missing from ASIC_DB".format(prefix))
        return False

    logger.info("Static route {} is installed in the FRR RIB, the kernel, APPL_DB and ASIC_DB".format(prefix))
    return True


def verify_reboot_cause_warm(duthost):
    """
    Verify that the last reboot was a warm reboot.

    A warm reboot which silently degraded into a cold one would make any hitless
    expectation meaningless, so this is checked explicitly.
    """
    reboot_cause = duthost.command("show reboot-cause")["stdout"]
    logger.info("Reboot cause: {}".format(reboot_cause))
    return "warm-reboot" in reboot_cause


def collect_warmboot_diagnostics(duthost, sonic_db_cli="sonic-db-cli"):
    """Collect the warm restart state, to be called when a warm boot test fails."""
    commands = [
        "show reboot-cause",
        "show warm_restart state",
        "show warm_restart config",
        '{} STATE_DB KEYS "WARM_RESTART_TABLE|*"'.format(sonic_db_cli),
        '{} STATE_DB KEYS "WARM_RESTART_ENABLE_TABLE|*"'.format(sonic_db_cli),
    ]
    for command in commands:
        output = duthost.command(command, module_ignore_errors=True)["stdout"]
        logger.info("=== {} ===\n{}".format(command, output))


def run_srv6_no_sid_blackhole_test(setup_uN, ptfadapter, ptfhost, with_srh):
    """
    Verify that packets sent to a SID which is not programmed are dropped.

    The drop relies on the fcbb:bbbb::/32 blackhole static route, so this also
    covers the persistence of that route across a disruption.
    """
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
