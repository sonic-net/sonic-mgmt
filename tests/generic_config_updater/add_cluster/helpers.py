import json
import logging
import random
import re
import time

import requests
import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import clear_counters, get_queue_count_all_prio
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


# -----------------------------
# Static Route Helper Functions
# -----------------------------

def get_exabgp_port_for_neighbor(tbinfo, neigh_name, exabgp_base_port=5000):
    offset = tbinfo['topo']['properties']['topology']['VMs'][neigh_name]['vm_offset']
    exabgp_port = exabgp_base_port + offset
    return exabgp_port


def change_route(operation, ptfip, route, nexthop, port, aspath):
    url = "http://%s:%d" % (ptfip, port)
    data = {
        "command": "%s route %s next-hop %s as-path [ %s ]" % (operation, route, nexthop, aspath)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


def add_static_route(tbinfo, neigh_ip, exabgp_port, ip, mask='32', aspath=65500, nhipv4='10.10.246.254'):
    common_config = tbinfo['topo']['properties']['configuration_properties'].get('common', {})
    ptf_ip = tbinfo['ptf_ip']
    dst_prefix = ip + '/' + mask
    nexthop = common_config.get('nhipv4', nhipv4)
    logger.info(
        "Announcing route: ptf_ip={} dst_prefix={} nexthop={} exabgp_port={} aspath={} via neighbor {}".format(
            ptf_ip, dst_prefix, nexthop, exabgp_port, aspath, neigh_ip)
        )
    change_route('announce', ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)


def clear_static_route(tbinfo, duthost, ip, nhipv4='10.10.246.254'):
    config_facts_localhost = duthost.config_facts(host=duthost.hostname, source='running',
                                                  verbose=False, namespace=None
                                                  )['ansible_facts']
    num_asic = duthost.facts.get('num_asic')
    for asic_index in range(num_asic):
        output = duthost.shell("sudo ip netns exec asic{} show ip route | grep {}"
                               .format(asic_index, ip))['stdout']
        ip_address = re.search(r'via (\d+\.\d+\.\d+\.\d+)', output)
        if ip_address:
            ip_address = ip_address.group(1)
            # Check if this is a direct BGP neighbor (not a recursive route)
            if ip_address not in config_facts_localhost['BGP_NEIGHBOR']:
                logger.warning(f"Next-hop {ip_address} is not a direct BGP neighbor (may be recursive route). "
                               f"Skipping route withdrawal for {ip}")
                continue
            bgp_neigh_name = config_facts_localhost['BGP_NEIGHBOR'][ip_address]['name']
            exabgp_port = get_exabgp_port_for_neighbor(tbinfo, bgp_neigh_name)
            remove_static_route(tbinfo, ip_address, exabgp_port, ip=ip, nhipv4=nhipv4)
            wait_until(10, 1, 0, verify_routev4_existence, duthost, asic_index, ip, should_exist=False)


def remove_static_route(tbinfo, neigh_ip, exabgp_port, ip, mask='32', aspath=65500, nhipv4='10.10.246.254'):
    common_config = tbinfo['topo']['properties']['configuration_properties'].get('common', {})
    ptf_ip = tbinfo['ptf_ip']
    dst_prefix = ip + '/' + mask
    nexthop = common_config.get('nhipv4', nhipv4)
    logger.info(
        "Withdrawing route: ptf_ip={} dst_prefix={} nexthop={} exabgp_port={} aspath={} via neighbor {}".format(
            ptf_ip, dst_prefix, nexthop, exabgp_port, aspath, neigh_ip
        )
    )
    change_route('withdraw', ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)


def verify_routev4_existence(duthost, asic_id, ip, should_exist=True):
    cur_ipv4_routes = duthost.asic_instance(asic_id).command("ip -4 route")['stdout']
    if ip in cur_ipv4_routes:
        logger.info("{}:Verifying route {} existence || Found=True || Expected={}.".format(duthost, ip, should_exist))
        return True if should_exist else False
    else:
        logger.info("{}:Verifying route {} existence || Found=False || Expected={}.".format(duthost, ip, should_exist))
        return False if should_exist else True


# -----------------------------
# Apply Patch Related Helper Functions
# -----------------------------

def add_content_to_patch_file(json_data, patch_file):
    logger.info("Adding extra content to patch file = {}".format(patch_file))

    try:
        with open(patch_file, "r") as file:
            existing_content = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_content = []

    if isinstance(json_data, str):
        try:
            json_data = json.loads(json_data)
        except json.JSONDecodeError:
            logger.error("Invalid JSON format in json_data")
            raise ValueError("json_data must be a valid JSON list or dictionary")

    if isinstance(existing_content, list) and isinstance(json_data, list):
        existing_content.extend(json_data)
    elif isinstance(existing_content, dict) and isinstance(json_data, dict):
        existing_content.update(json_data)
    else:
        raise ValueError("add_content_to_patch_file: Mismatched types: Cannot merge {} with {}".format(
            type(existing_content).__name__, type(json_data).__name__
        ))

    with open(patch_file, "w") as file:
        json.dump(existing_content, file, indent=4)


def change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               namespace,
                                               status=None,
                                               apply=True,
                                               verify=True,
                                               patch_file=""):
    """
    Applies a patch to change the administrative status (up/down) of interfaces for a specific namespace
    on the DUT host.

    Applies changes at configuration path:
    - /<namespace>/PORT/<port>/admin_status

    This function updates the administrative state (enabled/disabled) of interfaces within the specified namespace
    on the DUT host by applying a patch. It also offers optional verification of the changes.

    Args:
        config_facts (dict): Configuration facts from the DUT host, containing the current state of the configuration.
        duthost (object): DUT host object on which the patch will be applied.
        namespace (str): The namespace whose interfaces should have their administrative state modified.
        status (str, optional): The desired administrative state of the interfaces ('up' or 'down'). If not provided,
                                no state change is applied. Defaults to None.
        verify (bool, optional): If True, verifies the changes after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """

    pytest_assert(status, "Test didn't provided the admin status value to change to.")

    logger.info("{}: Changing admin status for local interfaces to {} for ASIC namespace {}".format(
        duthost.hostname, status, namespace)
        )
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = []

    # find all the interfaces that are active based on configuration
    up_interfaces = []
    for key, _value in config_facts.get("INTERFACE", {}).items():
        if re.compile(r'^Ethernet\d{1,3}$').match(key):
            up_interfaces.append(key)
    for portchannel in config_facts.get("PORTCHANNEL_MEMBER", {}):
        for key, _value in config_facts.get("PORTCHANNEL_MEMBER", {}).get(portchannel, {}).items():
            up_interfaces.append(key)
    logger.info("Up interfaces for this namespace:{}".format(up_interfaces))

    for interface in up_interfaces:
        json_patch.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": status
        })

    if apply:

        tmpfile = generate_tmpfile(duthost)

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                logger.info("{}: Verifying interfaces status is {}.".format(duthost.hostname, status))
                pytest_assert(check_interface_status(duthost, namespace, up_interfaces, exp_status=status),
                              "Interfaces failed to update admin status to {}'".format(status))
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


# -----------------------------
# Helper Functions - Interfaces, Config
# -----------------------------

def check_interface_status(duthost, namespace, interface_list, exp_status='up'):
    """
    Verifies if all interfaces for one namespace are the expected status
    Args:
        duthost: DUT host object under test
        namespace: Namespace to verify
        interface_list: The list of interfaces to verify
        exp_status: Expected status for all the interfaces
    """
    for interface in interface_list:
        cmds = "show interface status {} -n {}".format(interface, namespace)
        output = duthost.shell(cmds)
        pytest_assert(not output['rc'])
        status_data = output["stdout_lines"]
        field_index = status_data[0].split().index("Admin")
        for line in status_data:
            interface_status = line.strip()
            pytest_assert(len(interface_status) > 0, "Failed to read line {}".format(line))
            if interface_status.startswith(interface):
                status = re.split(r" {2,}", interface_status)[field_index]
                if status != exp_status:
                    logger.error("Found interface {} in non-expected state {}. Line output: {}".format(
                        interface, interface_status, line))
                    return False
    return True


def get_cfg_info_from_dut(duthost, path, enum_rand_one_asic_namespace):
    """
    Returns the running configuration for a given configuration path within a namespace.
    """
    dict_info = None
    namespace_prefix = '' if enum_rand_one_asic_namespace is None else '-n ' + enum_rand_one_asic_namespace
    raw_output = duthost.command(
        "sudo sonic-cfggen {} -d --var-json {}".format(
            namespace_prefix, path)
    )["stdout"]
    try:
        dict_info = json.loads(raw_output)
    except json.JSONDecodeError:
        dict_info = None

    if not isinstance(dict_info, dict):
        print("Expected a dictionary, but got:", type(dict_info))
        dict_info = None
    return dict_info


def get_active_interfaces(config_facts, duthost=None):
    """
    Finds all the active interfaces based on running configuration.
    For chassis-packet switches: Skips BP (backplane) interfaces and PortChannels with BP member interfaces.
    For other switches: Returns all active interfaces without BP filtering.

    Args:
        config_facts: Configuration facts dictionary
        duthost: DUT host object (optional, used to check switch_type)
    """
    active_interfaces = []

    # Check if this is a chassis-packet switch
    is_chassis_packet = (duthost and
                         duthost.facts.get('switch_type') == 'chassis-packet')

    # Add interfaces from INTERFACE table, skip BP interfaces only for chassis-packet
    for key, _value in config_facts.get("INTERFACE", {}).items():
        if re.compile(r'^Ethernet\d{1,3}$').match(key):
            # Skip BP interfaces only for chassis-packet switches
            if is_chassis_packet and key.startswith("Ethernet-BP"):
                continue
            active_interfaces.append(key)

    # Identify PortChannels with BP members (internal PortChannels) - only for chassis-packet
    internal_portchannels = set()
    if is_chassis_packet:
        for portchannel, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
            for member_port in members.keys():
                if member_port.startswith("Ethernet-BP"):
                    internal_portchannels.add(portchannel)
                    break

    # Add interfaces from PORTCHANNEL_MEMBER, skip BP interfaces and members of internal PortChannels
    for portchannel in config_facts.get("PORTCHANNEL_MEMBER", {}):
        # Skip internal PortChannels (those with BP members) - only for chassis-packet
        if portchannel in internal_portchannels:
            logger.info(f"Skipping internal PortChannel {portchannel} (has BP members)")
            continue

        for key, _value in config_facts.get("PORTCHANNEL_MEMBER", {}).get(portchannel, {}).items():
            # Skip BP interfaces only for chassis-packet switches
            if is_chassis_packet and key.startswith("Ethernet-BP"):
                continue
            active_interfaces.append(key)

    logger.info("Active interfaces for this namespace: {}".format(active_interfaces))
    if internal_portchannels:
        logger.info("Skipped internal PortChannels (chassis-packet only): {}".format(internal_portchannels))
    return active_interfaces


def select_random_active_interface(duthost, namespace):
    """
    Finds all the active interfaces based on status in duthost and returns a random selected.
    """
    interfaces = duthost.get_interfaces_status(namespace)
    active_interfaces = []
    for interface_name, interface_info in list(interfaces.items()):
        if interface_name.startswith('Ethernet') \
            and interface_info.get('oper') == 'up' \
                and interface_info.get('admin') == 'up':
            active_interfaces.append(interface_name)
    return random.choice(active_interfaces)


# -----------------------------
# ACL Helper Functions and Variables
# -----------------------------

def acl_asic_shell_wrappper(duthost, cmd, asic=''):
    def run_cmd(host, command):
        if isinstance(command, list):
            for cm in command:
                host.shell(cm)
        else:
            host.shell(command)

    if duthost.is_multi_asic:
        asics = [duthost.asics[int(asic.replace("asic", ""))]] if asic else duthost.asics

        for asichost in asics:
            ns_cmd = ["{} {}".format(asichost.ns_arg, cm) for cm in (cmd if isinstance(cmd, list) else [cmd])]
            run_cmd(asichost, ns_cmd)
    else:
        run_cmd(duthost, cmd)


def remove_dataacl_table_single_dut(table_name, duthost):
    lines = duthost.shell(cmd="show acl table {}".format(table_name))['stdout_lines']
    data_acl_existing = False
    for line in lines:
        if table_name in line:
            data_acl_existing = True
            break
    if data_acl_existing:
        # Remove DATAACL
        logger.info("{} Removing ACL table {}".format(duthost.hostname, table_name))
        cmds = [
            "config acl remove table {}".format(table_name),
            "config save -y"
        ]
        acl_asic_shell_wrappper(duthost, cmds)


def get_cacl_tables(duthost, ip_netns_namespace_prefix):
    """Get acl control plane tables
    """
    cmds = "{} show acl table | grep -w CTRLPLANE | awk '{{print $1}}'".format(ip_netns_namespace_prefix)

    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))
    cacl_tables = output['stdout'].splitlines()
    return cacl_tables


# -----------------------------
# Data Traffic Helper Functions
# -----------------------------

def send_and_verify_traffic(
        tbinfo,
        src_duthost,
        dst_duthost,
        src_asic_index,
        dst_asic_index,
        ptfadapter,
        ptf_sport=None,
        ptf_dst_ports=None,
        ptf_dst_interfaces=None,
        src_ip='30.0.0.10',
        dst_ip='50.0.2.2',
        count=1,
        dscp=None,
        sport=0x1234,
        dport=0x50,
        flags=0x10,
        verify=True,
        expect_error=False
        ):
    """
    Helper function to send and verify data traffic via PTF framework.
    """

    src_asic_namespace = None if src_asic_index is None else 'asic{}'.format(src_asic_index)
    dst_asic_namespace = None if dst_asic_index is None else 'asic{}'.format(dst_asic_index)
    router_mac = src_duthost.asic_instance(src_asic_index).get_router_mac()
    src_mg_facts = src_duthost.get_extended_minigraph_facts(tbinfo, src_asic_namespace)
    dst_mg_facts = dst_duthost.get_extended_minigraph_facts(tbinfo, dst_asic_namespace)

    # port from ptf
    if not ptf_sport:
        ptf_src_ports = list(src_mg_facts["minigraph_ptf_indices"].values())
        ptf_sport = random.choice(ptf_src_ports)
    if not ptf_dst_ports:
        ptf_dst_ports = list(set(dst_mg_facts["minigraph_ptf_indices"].values()))
    if not ptf_dst_interfaces:
        ptf_dst_interfaces = list(set(dst_mg_facts["minigraph_ptf_indices"].keys()))

    # clear counters
    clear_counters(dst_duthost, namespace=dst_asic_namespace)

    # Create pkt
    pkt = testutils.simple_tcp_packet(
        eth_src=ptfadapter.dataplane.get_mac(0, ptf_sport),
        eth_dst=router_mac,
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_ttl=64,
        ip_dscp=dscp,
        tcp_sport=sport,
        tcp_dport=dport,
        tcp_flags=flags
    )
    logging.info("Packet created: {}".format(pkt))

    # Create exp packet for verification
    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

    # Send packet
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_sport, pkt, count=count)

    # Verify packet count from ptfadapter
    if verify:
        if expect_error:
            with pytest.raises(AssertionError):
                testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_ports)
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_ports)

    # verify queue counters
    if dscp:
        logging.info("Verifying queue counters for dscp {}.".format(dscp))
        exp_prio = 'prio_{}'.format(dscp)
        retry_count = 3
        retry_int = 5

        def get_counters():
            counter_exp_prio = 0
            counter_rest_prio = 0
            for interface in ptf_dst_interfaces:
                if interface.startswith('Ethernet-IB'):
                    continue
                interface_queue_count_dict = get_queue_count_all_prio(dst_duthost, interface)
                for prio, prio_counter in interface_queue_count_dict[dst_duthost.hostname][interface].items():
                    if prio != exp_prio:
                        counter_rest_prio += prio_counter
                    else:
                        counter_exp_prio += prio_counter
            return counter_exp_prio, counter_rest_prio

        for attempt in range(1, retry_count + 1):
            time.sleep(retry_int)
            counter_exp_prio, counter_rest_prio = get_counters()

            if expect_error:
                if counter_exp_prio == 0 and counter_rest_prio == 0:
                    logging.info(f"Attempt {attempt}: Expected counters verified (both zero).")
                    break
            else:
                if counter_exp_prio == count and counter_rest_prio == 0:
                    logging.info(f"Attempt {attempt}: Expected counters verified successfully.")
                    break

            if attempt < retry_count:
                logging.warning(
                    f"Attempt {attempt}: Counters not as expected. Retrying in {retry_int}s..."
                )
            else:
                logging.error("Max retries reached. Failure in queue counter verification.")

        if expect_error:
            pytest_assert(
                counter_exp_prio == 0 and counter_rest_prio == 0,
                'Found unexpected queue counter values.\n \
                Prio{} Queues Expected: 0 - Found:{}.\n \
                Rest Prio Queues Expected: 0 - Found:{}.'.format(dscp, counter_exp_prio, counter_rest_prio)
            )
        else:
            pytest_assert(
                counter_exp_prio == count and counter_rest_prio == 0,
                'Found unexpected queue counter values.\n \
                Prio{} Queues Expected:{} - Found:{}.\n \
                Rest Prio Queues Expected: 0 - Found:{}.'.format(dscp, count, counter_exp_prio, counter_rest_prio)
            )
        logger.info("Success queue counter verification - \
                    Prio{} Queues Counter:{} - \
                    Rest Prio Queues Counter:{}.".format(
                        dscp, counter_exp_prio, counter_rest_prio
                        )
                    )
