"""This module contains some auxiliary functions that are required
to support automation activities. These functions are used for various
secondary activities like convert the ansible Unicode STDOUT output
to string, get IP address in a subnet, increment an IP address, get
VLAN subnet etc.
This file is also a placeholder for auxiliary function that are
required for supporting automation with Snappi devices in future:
like collecting diagnostics, uploading and downloading files
to/from API server, processing the statistics after obtaining them
in .csv format etc.
"""

from enum import Enum
import ipaddr
import json
import re
from netaddr import IPNetwork
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from ipaddress import IPv6Network, IPv6Address
from random import getrandbits
from tests.common.portstat_utilities import parse_portstat
from collections import defaultdict


def increment_ip_address(ip, incr=1):
    """
    Increment IP address by an integer number.
    Args:
       ip (str): IP address in string format.
       incr (int): Increment by the specified number.
    Return:
       IP address in the argument incremented by the given integer.
    """
    ipaddress = ipaddr.IPv4Address(ip)
    ipaddress = ipaddress + incr
    return_value = ipaddress._string_from_ip_int(ipaddress._ip)
    return return_value


def ansible_stdout_to_str(ansible_stdout):
    """
    The stdout of Ansible host is essentially a list of unicode characters.
    This function converts it to a string.
    Args:
        ansible_stdout: stdout of Ansible
    Returns:
        Return a string
    """
    result = ""
    for x in ansible_stdout:
        result += x
    return result


def get_vlan_subnet(host_ans):
    """
    Get VLAN subnet of a T0 device
    Args:
        host_ans: Ansible host instance of the device
    Returns:
        VLAN subnet, e.g., "192.168.1.1/24" where 192.168.1.1 is gateway
        and 24 is prefix length
    """
    mg_facts = host_ans.minigraph_facts(host=host_ans.hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']

    if len(mg_vlans) != 1:
        print('There should be only one Vlan at the DUT')
        return None

    mg_vlan_intfs = mg_facts['minigraph_vlan_interfaces']
    prefix_len = mg_vlan_intfs[0]['prefixlen']
    gw_addr = ansible_stdout_to_str(mg_vlan_intfs[0]['addr'])
    return gw_addr + '/' + str(prefix_len)


def get_egress_lossless_buffer_size(host_ans):
    """
    Get egress lossless buffer size of a switch
    Args:
        host_ans: Ansible host instance of the device
    Returns:
        total switch buffer size in byte (int)
    """
    config_facts = host_ans.config_facts(host=host_ans.hostname,
                                         source="running")['ansible_facts']

    if "BUFFER_POOL" not in list(config_facts.keys()):
        return None

    buffer_pools = config_facts['BUFFER_POOL']
    profile_name = 'egress_lossless_pool'

    if profile_name not in list(buffer_pools.keys()):
        return None

    egress_lossless_pool = buffer_pools[profile_name]
    return int(egress_lossless_pool['size'])


def get_lossless_buffer_size(host_ans):
    """
    Get egress lossless buffer size of a switch, unless a Cisco 8000 switch,
    in which case, get the ingress lossless buffer size
    Args:
        host_ans: Ansible host instance of the device
    Returns:
        total switch buffer size in byte (int)
    """
    dut_asic = host_ans.asic_instance()
    config_facts = dut_asic.config_facts(host=host_ans.hostname,
                                         source="running")['ansible_facts']

    is_cisco8000_platform = True if 'cisco-8000' in host_ans.facts['platform_asic'] else False

    # Checking if platform is Broadcom-DNX.
    is_broadcom_dnx = (
            True
            if "platform_asic" in host_ans.facts and host_ans.facts["platform_asic"] == "broadcom-dnx"
            else False
            )

    if "BUFFER_POOL" not in list(config_facts.keys()):
        return None

    buffer_pools = config_facts['BUFFER_POOL']

    # Added check to select ingress_lossles_pool for Nokia7250 platform.
    profile_name = (
            'ingress_lossless_pool'
            if (is_cisco8000_platform or is_broadcom_dnx)
            else 'egress_lossless_pool'
            )

    if profile_name not in list(buffer_pools.keys()):
        return None

    lossless_pool = buffer_pools[profile_name]
    return int(lossless_pool['size'])


def get_pg_dropped_packets(duthost, phys_intf, prio, asic_value=None):
    """
    Get number of ingress packets dropped on a specific priority
    of a physical interface
    Args:
        host_ans: Ansible host instance of the device
        phys_intf (str): Name of physical interface ex. Ethernet4
        prio (int): Priority group to check ex. 4
    Returns:
        total number of dropped packets (int)
    """
    if asic_value is None:
        oid_cmd = "sonic-db-cli COUNTERS_DB HGET COUNTERS_QUEUE_NAME_MAP " + phys_intf + ":" + str(prio)
    else:
        oid_cmd = "sudo ip netns exec {} sonic-db-cli COUNTERS_DB HGET COUNTERS_QUEUE_NAME_MAP ".format(asic_value) \
                  + phys_intf + ":" + str(prio)
    oid_out = duthost.command(oid_cmd)
    oid_str = str(oid_out["stdout_lines"][0] or 1)

    if oid_str == "1":
        return None

    if asic_value is None:
        cmd = "sonic-db-cli COUNTERS_DB HGET COUNTERS:" + oid_str + " SAI_QUEUE_STAT_DROPPED_PACKETS"
    else:
        cmd = "sudo ip netns exec {} sonic-db-cli COUNTERS_DB HGET COUNTERS:".format(asic_value) \
              + oid_str + " SAI_QUEUE_STAT_DROPPED_PACKETS"
    out = duthost.command(cmd)
    dropped_packets = int(out["stdout_lines"][0] or -1)

    if dropped_packets == -1:
        return None

    return dropped_packets


def get_addrs_in_subnet(subnet, number_of_ip):
    """
    Get N IP addresses in a subnet.
    Args:
        subnet (str): IPv4 subnet, e.g., '192.168.1.1/24'
        number_of_ip (int): Number of IP addresses to get
    Return:
        Return n IPv4 addresses in this subnet in a list.
    """
    ip_addr = subnet.split('/')[0]
    ip_addrs = [str(x) for x in list(IPNetwork(subnet))]
    ip_addrs.remove(ip_addr)

    """ Try to avoid network and broadcast addresses """
    if len(ip_addrs) >= number_of_ip + 2:
        del ip_addrs[0]
        del ip_addrs[-1]

    return ip_addrs[:number_of_ip]


def get_peer_snappi_chassis(conn_data, dut_hostname):
    """
    Get the Snappi chassis connected to the DUT
    Note that a DUT can only be connected to a Snappi chassis
    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:
        {u'device_conn': {u'sonic-s6100-dut':
                        {u'Ethernet64': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port1',
                                        u'speed': u'100000'},
                        u'Ethernet68': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port2',
                                        u'speed': u'100000'},
                        u'Ethernet72': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port3',
                                        u'speed': u'100000'},
                        u'Ethernet76': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port4',
                                        u'speed': u'100000'}}},
        u'device_console_info': {u'sonic-s6100-dut': {}},
        u'device_console_link': {u'sonic-s6100-dut': {}},
        u'device_info': {u'sonic-s6100-dut':
                        {u'HwSku': u'Arista-7060CX-32S-C32',
                                            u'Type': u'DevSonic'}},
        u'device_pdu_info': {u'sonic-s6100-dut': {}},
        u'device_pdu_links': {u'sonic-s6100-dut': {}},
        u'device_port_vlans': {u'sonic-s6100-dut':
                                {u'Ethernet64': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet68': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet72': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet76': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]}}},
        u'device_vlan_list': {u'sonic-s6100-dut': [2, 2, 2, 2]},
        u'device_vlan_map_list': {u'sonic-s6100-dut': {u'19': 2}},
        u'device_vlan_range': {u'sonic-s6100-dut': [u'2']}}
        dut_hostname (str): hostname of the DUT
    Returns:
        The name of the peer Snappi chassis or None
    """

    device_conn = conn_data['device_conn']
    if dut_hostname not in device_conn:
        return None

    dut_device_conn = device_conn[dut_hostname]
    peer_devices = [dut_device_conn[port]['peerdevice'] for port in dut_device_conn]
    peer_devices = list(set(peer_devices))
    if len(peer_devices) == 1:
        return peer_devices[0]
    else:
        # in case there are other fanout devices (Arista, SONiC, etc) defined in the inventory file,
        # try to filter out the other device based on the name for now.
        peer_snappi_devices = list(filter(lambda dut_name: ('ixia' in dut_name), peer_devices))
        if len(peer_snappi_devices) == 1:
            return peer_snappi_devices[0]
        else:
            return None


def get_peer_port(conn_data, dut_hostname, dut_intf):
    """
    Get the peer port of the DUT port
    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:
        {u'device_conn': {u'sonic-s6100-dut':
                        {u'Ethernet64': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port1',
                                        u'speed': u'100000'},
                        u'Ethernet68': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port2',
                                        u'speed': u'100000'},
                        u'Ethernet72': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port3',
                                        u'speed': u'100000'},
                        u'Ethernet76': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port4',
                                        u'speed': u'100000'}}},
        u'device_console_info': {u'sonic-s6100-dut': {}},
        u'device_console_link': {u'sonic-s6100-dut': {}},
        u'device_info': {u'sonic-s6100-dut':
                        {u'HwSku': u'Arista-7060CX-32S-C32',
                                            u'Type': u'DevSonic'}},
        u'device_pdu_info': {u'sonic-s6100-dut': {}},
        u'device_pdu_links': {u'sonic-s6100-dut': {}},
        u'device_port_vlans': {u'sonic-s6100-dut':
                                {u'Ethernet64': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet68': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet72': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet76': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]}}},
        u'device_vlan_list': {u'sonic-s6100-dut': [2, 2, 2, 2]},
        u'device_vlan_map_list': {u'sonic-s6100-dut': {u'19': 2}},
        u'device_vlan_range': {u'sonic-s6100-dut': [u'2']}}
        dut_hostname (str): hostname of the DUT
        dut_intf (str): name of DUT interface
    Returns:
        The name of the peer port or None
    """
    device_conn = conn_data['device_conn']
    if dut_hostname not in device_conn:
        return None

    dut_device_conn = device_conn[dut_hostname]
    if dut_intf not in dut_device_conn:
        return None

    return dut_device_conn[dut_intf]['peerport']


def get_dut_intfs(conn_data, dut_hostname):
    """
    Get DUT's interfaces
    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:
        {u'device_conn': {u'sonic-s6100-dut':
                        {u'Ethernet64': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port1',
                                        u'speed': u'100000'},
                        u'Ethernet68': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port2',
                                        u'speed': u'100000'},
                        u'Ethernet72': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port3',
                                        u'speed': u'100000'},
                        u'Ethernet76': {u'peerdevice': u'snappi-sonic',
                                        u'peerport': u'Card4/Port4',
                                        u'speed': u'100000'}}},
        u'device_console_info': {u'sonic-s6100-dut': {}},
        u'device_console_link': {u'sonic-s6100-dut': {}},
        u'device_info': {u'sonic-s6100-dut':
                        {u'HwSku': u'Arista-7060CX-32S-C32',
                                            u'Type': u'DevSonic'}},
        u'device_pdu_info': {u'sonic-s6100-dut': {}},
        u'device_pdu_links': {u'sonic-s6100-dut': {}},
        u'device_port_vlans': {u'sonic-s6100-dut':
                                {u'Ethernet64': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet68': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet72': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]},
                                u'Ethernet76': {u'mode': u'Access',
                                                u'vlanids': u'2',
                                                u'vlanlist': [2]}}},
        u'device_vlan_list': {u'sonic-s6100-dut': [2, 2, 2, 2]},
        u'device_vlan_map_list': {u'sonic-s6100-dut': {u'19': 2}},
        u'device_vlan_range': {u'sonic-s6100-dut': [u'2']}}
        dut_hostname (str): hostname of the DUT
    Returns:
        Return the list of interface names
    """

    device_conn = conn_data['device_conn']
    if dut_hostname not in device_conn:
        return None

    dut_device_conn = device_conn[dut_hostname]
    return list(dut_device_conn.keys())


def pfc_class_enable_vector(prio_list):
    """
    Calculate class-enable vector field in PFC PAUSE frames
    Args:
        prio_list (list): list of priorities to pause, e.g., [3, 4]
    Returns:
        Return class-enable vector
    """
    vector = 0

    for p in prio_list:
        vector += (2**p)

    return vector


def get_wred_profiles(host_ans, asic_value=None):
    """
    Get all the WRED/ECN profiles of a SONiC switch
    Args:
        host_ans: Ansible host instance of the device
        asic_value: asic value of the host

    Returns:
        WRED/ECN profiles (dictionary) or None.
        Example format is given below:
        {
            u'AZURE_LOSSLESS': {
                u'ecn': u'ecn_all',
                u'green_drop_probability': u'5',
                u'green_max_threshold': u'2097152',
                u'green_min_threshold': u'250000',
                u'red_drop_probability': u'5',
                u'red_max_threshold': u'2097152',
                u'red_min_threshold': u'1048576',
                u'wred_green_enable': u'true',
                u'wred_red_enable': u'true',
                u'wred_yellow_enable': u'true',
                u'yellow_drop_probability': u'5',
                u'yellow_max_threshold': u'2097152',
                u'yellow_min_threshold': u'1048576'
            }
        }
    """
    if asic_value == "None":
        config_facts = host_ans.config_facts(
                                             host=host_ans.hostname,
                                             source="running"
                                             )['ansible_facts']
    else:
        config_facts = host_ans.config_facts(
                                            host=host_ans.hostname,
                                            source="running",
                                            namespace=asic_value
                                            )['ansible_facts']

    if "WRED_PROFILE" in list(config_facts.keys()):
        return config_facts['WRED_PROFILE']
    else:
        return None


def config_wred(host_ans, kmin, kmax, pmax, profile=None, asic_value=None):
    """
    Config a WRED/ECN profile of a SONiC switch
    Args:
        host_ans: Ansible host instance of the device
        kmin (int): RED/ECN minimum threshold in bytes
        kmax (int): RED/ECN maximum threshold in bytes
        pmax (int): RED/ECN maximum marking probability in percentage
        profile (str): name of profile to configure (None means any profile)
        asic_value: asic value of the host

    Returns:
        If configuration succeeds (bool)
    """

    asic_type = str(host_ans.facts["asic_type"])
    if not isinstance(kmin, int) or \
       not isinstance(kmax, int) or \
       not isinstance(pmax, int):
        return False

    if kmin < 0 or kmax < 0 or pmax < 0 or pmax > 100 or kmin > kmax:
        return False
    profiles = get_wred_profiles(host_ans, asic_value)
    """ Cannot find any WRED/ECN profiles """
    if profiles is None:
        return False

    """ Cannot find the profile to configure at the device """
    if profile is not None and profile not in profiles:
        return False

    color = 'green'

    # Broadcom ASIC only supports RED.
    if asic_type == 'broadcom':
        color = 'red'

    kmax_arg = '-{}max' % color[0]
    kmin_arg = '-{}min' % color[0]

    for p in profiles:
        """ This is not the profile to configure """
        if profile is not None and profile != p:
            continue

        kmin_old = int(profiles[p]['{}_min_threshold' % color])
        kmax_old = int(profiles[p]['{}_max_threshold' % color])

        if kmin_old > kmax_old:
            return False

        """ Ensure that Kmin is no larger than Kmax during the update """

        kmax_cmd = ' '.join(['sudo ecnconfig -p {}', kmax_arg, '{}'])
        kmin_cmd = ' '.join(['sudo ecnconfig -p {}', kmin_arg, '{}'])

        if asic_value is not None:
            kmax_cmd = ' '.join(['sudo ip netns exec', asic_value, 'ecnconfig -p {}', kmax_arg, '{}'])
            kmin_cmd = ' '.join(['sudo ip netns exec', asic_value, 'ecnconfig -p {}', kmin_arg, '{}'])
            if asic_type == 'broadcom':
                disable_packet_aging(host_ans, asic_value)

        if kmin > kmin_old:
            host_ans.shell(kmax_cmd.format(p, kmax))
            host_ans.shell(kmin_cmd.format(p, kmin))
        else:
            host_ans.shell(kmin_cmd.format(p, kmin))
            host_ans.shell(kmax_cmd.format(p, kmax))

    return True


def enable_ecn(host_ans, prio, asic_value=None):
    """
    Enable ECN marking on a priority

    Args:
        host_ans: Ansible host instance of the device
        prio (int): priority
        asic_value: asic value of the host

    Returns:
        N/A
    """
    if asic_value is None:
        host_ans.shell('sudo ecnconfig -q {} on'.format(prio))
        results = host_ans.shell('ecnconfig -q {}'.format(prio))
        if re.search("queue {}: on".format(prio), results['stdout']):
            return True
    else:
        host_ans.shell('sudo ip netns exec {} ecnconfig -q {} on'.format(asic_value, prio))
        results = host_ans.shell('sudo ip netns exec {} ecnconfig -q {}'.format(asic_value, prio))
        if re.search("queue {}: on".format(prio), results['stdout']):
            return True
    return False


def disable_ecn(host_ans, prio, asic_value=None):
    """
    Disable ECN marking on a priority

    Args:
        host_ans: Ansible host instance of the device
        prio (int): priority
        asic_value: asic value of the host

    Returns:
        N/A
    """
    if asic_value is None:
        host_ans.shell('sudo ecnconfig -q {} off'.format(prio))
    else:
        asic_type = str(host_ans.facts["asic_type"])
        host_ans.shell('sudo ip netns exec {} ecnconfig -q {} off'.format(asic_value, prio))
        if asic_type == 'broadcom':
            enable_packet_aging(host_ans, asic_value)


def config_buffer_alpha(host_ans, profile, alpha_log2, asic_value=None):
    """
    Configure buffer threshold (a.k.a., alpha)

    Args:
        host_ans: Ansible host instance of the device
        profile (str): buffer profile name
        alpha_log2 (int): set threshold to 2^alpha_log2
        asic_value: asic value of the host

    Returns:
        N/A
    """
    if asic_value is None:
        host_ans.shell('sudo mmuconfig -p {} -a {}'.format(profile, alpha_log2))
    else:
        host_ans.shell('sudo ip netns exec {} mmuconfig -p {} -a {}'.format(asic_value, profile, alpha_log2))


def config_ingress_lossless_buffer_alpha(host_ans, alpha_log2, asic_value=None):
    """
    Configure ingress buffer thresholds (a.k.a., alpha) of a device to 2^alpha_log2

    Args:
        host_ans: Ansible host instance of the device
        alpha_log2 (int): set threshold to 2^alpha_log2
        asic_value: asic value of the host

    Returns:
        If configuration succeeds (bool)
    """
    if not isinstance(alpha_log2, int):
        return False

    if asic_value is None:
        config_facts = host_ans.config_facts(host=host_ans.hostname, source="running")['ansible_facts']
    else:
        config_facts = host_ans.config_facts(
                                            host=host_ans.hostname,
                                            source="running",
                                            namespace=asic_value
                                            )['ansible_facts']

    if "BUFFER_PROFILE" not in list(config_facts.keys()):
        return False

    buffer_profiles = config_facts['BUFFER_PROFILE']
    ingress_profiles = []
    for profile in buffer_profiles:
        if profile.startswith('ingress_lossless') or profile.startswith('pg_lossless'):
            ingress_profiles.append(profile)

    for profile in ingress_profiles:
        config_buffer_alpha(host_ans=host_ans, profile=profile, alpha_log2=alpha_log2, asic_value=asic_value)

    """ Check if configuration succeeds """
    if asic_value is None:
        config_facts = host_ans.config_facts(host=host_ans.hostname, source="running")['ansible_facts']
    else:
        config_facts = host_ans.config_facts(
                                            host=host_ans.hostname,
                                            source="running",
                                            namespace=asic_value
                                            )['ansible_facts']

    for profile in ingress_profiles:
        dynamic_th = config_facts['BUFFER_PROFILE'][profile]['dynamic_th']
        if int(dynamic_th) != alpha_log2:
            return False

    return True


def get_pfcwd_config_attr(host_ans, config_scope, attr, asic_value=None):
    """
    Get PFC watchdog configuration attribute

    Args:
        host_ans: Ansible host instance of the device
        config_scope (str): 'GLOBAL' or interface name
        attr (str): config attribute name, e.g., 'detection_time'
        asic_value: asic value of the host

    Returns:
        config attribute (str) or None
    """
    if asic_value is None:
        config_facts = host_ans.config_facts(host=host_ans.hostname, source="running")['ansible_facts']
    else:
        config_facts = host_ans.config_facts(
                                            host=host_ans.hostname,
                                            source="running",
                                            namespace=asic_value
                                            )['ansible_facts']

    if 'PFC_WD' not in list(config_facts.keys()):
        return None

    pfcwd_config = config_facts['PFC_WD']
    if config_scope not in pfcwd_config:
        return None

    config = pfcwd_config[config_scope]
    if attr in config:
        return config[attr]

    return None


def get_pfcwd_poll_interval(host_ans, asic_value=None):
    """
    Get PFC watchdog polling interval
    Args:
        host_ans: Ansible host instance of the device
        asic_value: asic value of the host

    Returns:
        Polling interval in ms (int) or None
    """
    if asic_value is None:
        val = get_pfcwd_config_attr(host_ans=host_ans,
                                    config_scope='GLOBAL',
                                    attr='POLL_INTERVAL')
    else:
        val = get_pfcwd_config_attr(host_ans=host_ans,
                                    config_scope='GLOBAL',
                                    attr='POLL_INTERVAL',
                                    asic_value=asic_value)

    if val is not None:
        return int(val)

    return None


def get_pfcwd_detect_time(host_ans, intf, asic_value=None):
    """
    Get PFC watchdog detection time of a given interface
    Args:
        host_ans: Ansible host instance of the device
        intf (str): interface name
        asic_value: asic value of the host

    Returns:
        Detection time in ms (int) or None
    """
    if asic_value is None:
        val = get_pfcwd_config_attr(host_ans=host_ans,
                                    config_scope=intf,
                                    attr='detection_time')
    else:
        val = get_pfcwd_config_attr(host_ans=host_ans,
                                    config_scope=intf,
                                    attr='detection_time',
                                    asic_value=asic_value)

    if val is not None:
        return int(val)

    return None


def get_pfcwd_restore_time(host_ans, intf, asic_value=None):
    """
    Get PFC watchdog restoration time of a given interface
    Args:
        host_ans: Ansible host instance of the device
        intf (str): interface name
        asic_value: asic value of the host

    Returns:
        Restoration time in ms (int) or None
    """
    if asic_value is None:
        val = get_pfcwd_config_attr(host_ans=host_ans,
                                    config_scope=intf,
                                    attr='restoration_time')
    else:
        val = get_pfcwd_config_attr(host_ans=host_ans,
                                    config_scope=intf,
                                    attr='restoration_time',
                                    asic_value=asic_value)

    if val is not None:
        return int(val)

    return None


def get_pfcwd_stats(duthost, port, prio, asic_value=None):
    """
    Get PFC watchdog statistics for given interface:prio
    Args:
        duthost		: Ansible host instance of the device
        port		: Port for which stats needs to be gathered.
        prio		: Lossless priority for which stats needs to be captured.
        asic_value	: asic value of the host

    Returns:
        Dictionary with PFCWD statistics as key-value pair.
        If the entry is not present, then values are returned as zero.
    """

    pfcwd_stats = {}
    if asic_value is None:
        raw_out = duthost.shell("show pfcwd stats | grep -E 'QUEUE|{}:{}'".format(port, prio))['stdout']
    else:
        comm = "sudo ip netns exec {} show pfcwd stats | grep -E 'QUEUE|{}:{}'".format(asic_value, port, prio)
        raw_out = duthost.shell(comm)['stdout']

    val_list = []
    key_list = []
    for line in raw_out.split('\n'):
        if ('QUEUE' in line):
            key_list = (re.sub(r"(\w) (\w)", r"\1_\2", line)).split()
        else:
            val_list = line.split()
    if val_list:
        for key, val in zip(key_list, val_list):
            pfcwd_stats[key] = val
    else:
        pfcwd_stats = {key: '0/0' if '/' in key else 0 for key in key_list}

    return pfcwd_stats


def start_pfcwd(duthost, asic_value=None):
    """
    Start PFC watchdog with default setting
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        asic_value: asic value of the host

    Returns:
        N/A
    """
    if asic_value is None:
        duthost.shell('sudo pfcwd start_default')
    else:
        duthost.shell('sudo ip netns exec {} pfcwd start_default'.format(asic_value))


def stop_pfcwd(duthost, asic_value=None):
    """
    Stop PFC watchdog
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        asic_value: asic value of the host

    Returns:
        N/A
    """
    if asic_value is None:
        duthost.shell('sudo pfcwd stop')
    else:
        duthost.shell('sudo ip netns exec {} pfcwd stop'.format(asic_value))


def disable_packet_aging(duthost, asic_value=None):
    """
    Disable packet aging feature
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        asic_value: asic value of the multi chassis based linecard
    Returns:
        N/A
    """
    if isMellanoxDevice(duthost):
        duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
        duthost.command("docker cp /tmp/packets_aging.py syncd:/")
        duthost.command("docker exec syncd python /packets_aging.py disable")
        duthost.command("docker exec syncd rm -rf /packets_aging.py")
    elif "platform_asic" in duthost.facts and duthost.facts["platform_asic"] == "broadcom-dnx":
        # if asic_value is present, disable packet aging for specific asic_value.
        if (asic_value):
            try:
                duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog disable"'.format(asic_value))
            except Exception:
                duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog disable"'.format(asic_value[-1]))
        else:
            # Disabling packet aging for all asics on given DUT.
            for asic_value in duthost.facts['asics_present']:
                try:
                    duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog disable"'.format(asic_value))
                except Exception:
                    duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog disable"'.format(asic_value[-1]))


def enable_packet_aging(duthost, asic_value=None):
    """
    Enable packet aging feature
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        asic_value: asic value of the multi chassis based linecard
    Returns:
        N/A
    """
    if isMellanoxDevice(duthost):
        duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
        duthost.command("docker cp /tmp/packets_aging.py syncd:/")
        duthost.command("docker exec syncd python /packets_aging.py enable")
        duthost.command("docker exec syncd rm -rf /packets_aging.py")
    elif "platform_asic" in duthost.facts and duthost.facts["platform_asic"] == "broadcom-dnx":
        # if asic_value is present, enable packet aging for specific asic_value.
        if (asic_value):
            try:
                duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog enable"'.format(asic_value))
            except Exception:
                duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog enable"'.format(asic_value[-1]))
        else:
            # Enabling packet aging for all asics on given DUT.
            for asic_value in duthost.facts['asics_present']:
                try:
                    duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog enable"'.format(asic_value))
                except Exception:
                    duthost.shell('bcmcmd -n {} "BCMSAI credit-watchdog enable"'.format(asic_value[-1]))


def get_ipv6_addrs_in_subnet(subnet, number_of_ip):
    """
    Get N IPv6 addresses in a subnet.
    Args:
        subnet (str): IPv6 subnet, e.g., '2001::1/64'
        number_of_ip (int): Number of IP addresses to get
    Return:
        Return n IPv6 addresses in this subnet in a list.
    """

    subnet = str(IPNetwork(subnet).network) + "/" + str(subnet.split("/")[1])
    subnet = subnet.encode().decode("utf-8")
    ipv6_list = []
    for i in range(number_of_ip):
        network = IPv6Network(subnet)
        address = IPv6Address(
            network.network_address + getrandbits(
                network.max_prefixlen - network.prefixlen))
        ipv6_list.append(str(address))

    return ipv6_list


def sec_to_nanosec(secs):
    """ Convert seconds to nanoseconds """
    return secs * 1e9


def get_pfc_frame_count(duthost, port, priority, is_tx=False):
    """
    Get the PFC frame count for a given port and priority from SONiC CLI
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
        priority (int): priority of flow
        is_tx (bool): if the PFC pause frame count is for Tx or Rx
    Returns:
        int: PFC pause frame count
    """
    if is_tx:
        raw_out = duthost.shell("show pfc counters | sed -n '/Port Tx/,/^$/p' | grep {}".format(port))['stdout']
    else:
        raw_out = duthost.shell("show pfc counters | sed -n '/Port Rx/,/^$/p' | grep {}".format(port))['stdout']

    pause_frame_count = raw_out.split()[priority + 1]

    return int(pause_frame_count.replace(',', ''))


def get_port_stats(duthost, port, stat):
    """
    Get the port stats for a given port from SONiC CLI
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
        stat (str): stat name
    Returns:
        int: port stats
    """
    raw_out = duthost.shell("portstat -ji {}".format(port))['stdout']
    # matches all characters until the first line that starts with {
    # leaving the JSON intact
    raw_out_stripped = re.sub(r'^(?:(?!{).)*\n', '', raw_out, count=1)
    raw_json = json.loads(raw_out_stripped)
    port_stats = raw_json[port].get(stat)

    return int(port_stats.replace(',', '')) if port_stats else -1


def get_tx_frame_count(duthost, port):
    """
    Get the Tx_OK and Tx_DRP frame count for a given port ex. Ethernet4 from SONiC CLI
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name ex. Ethernet4
    Returns:
        tx_frame_count (int): Tx frame count
        tx_drop_frame_count (int): Tx drop frame count
    """
    tx_ok_frame_count = get_port_stats(duthost, port, "TX_OK")
    tx_drp_frame_count = get_port_stats(duthost, port, "TX_DRP")

    return tx_ok_frame_count, tx_drp_frame_count


def get_rx_frame_count(duthost, port):
    """
    Get the Rx_OK and Rx_DRP frame count for a given port ex. Ethernet4 from SONiC CLI
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name ex. Ethernet4
    Returns:
        rx_frame_count (int): Rx frame count
        rx_frame_drop_count (int): Rx drop frame count
    """
    rx_ok_frame_count = get_port_stats(duthost, port, "RX_OK")
    rx_drp_frame_count = get_port_stats(duthost, port, "RX_DRP")

    return rx_ok_frame_count, rx_drp_frame_count


def get_egress_queue_count(duthost, port, priority):
    """
    Get the egress queue count in packets and bytes for a given port and priority from SONiC CLI.
    This is the equivalent of the "show queue counters" command.
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
        priority (int): priority of flow
    Returns:
        tuple (int, int): total count of packets and bytes in the queue
    """
    # If DUT is multi-asic, asic will be used.
    if duthost.is_multi_asic:
        asic = duthost.get_port_asic_instance(port).get_asic_namespace()
        raw_out = duthost.shell("sudo ip netns exec {} show queue counters {} | sed -n '/UC{}/p'".
                                format(asic, port, priority))['stdout']
        total_pkts = "0" if raw_out.split()[2] == "N/A" else raw_out.split()[2]
        total_bytes = "0" if raw_out.split()[3] == "N/A" else raw_out.split()[3]
    else:
        raw_out = duthost.shell("show queue counters {} | sed -n '/UC{}/p'".format(port, priority))['stdout']
        total_pkts = raw_out.split()[2] if 2 < len(raw_out.split()) else "0"
        if total_pkts == "N/A":
            total_pkts = "0"

        total_bytes = raw_out.split()[3] if 3 < len(raw_out.split()) else "0"
        if total_bytes == "N/A":
            total_bytes = "0"

    return int(total_pkts.replace(',', '')), int(total_bytes.replace(',', ''))


class packet_capture(Enum):
    """
    ENUM of packet capture settings
    NO_CAPTURE - No capture
    PFC_CAPTURE - PFC capture enabled
    IP_CAPTURE - IP capture enabled
    """
    NO_CAPTURE = "No_Capture"
    PFC_CAPTURE = "PFC_Capture"
    IP_CAPTURE = "IP_Capture"


class traffic_flow_mode(Enum):
    """
    ENUM of traffic flow mode settings
    CONTINUOUS - -100
        - continuous flow of traffic with no pauses at some specific rate
    BURST - -99
        - burst of traffic with breaks in flow for a certain duration at some specific rate
    FIXED_PACKETS - -98
        - sending a specific number of packets at some specific rate
    FIXED_DURATION - -97
        - sending traffic for a specific duration at some specific rate
    """
    CONTINUOUS = -100
    BURST = -99
    FIXED_PACKETS = -98
    FIXED_DURATION = -97


def config_capture_pkt(testbed_config, port_names, capture_type, capture_name=None, format="pcapng"):
    """
    Generate the configuration to capture packets on a port for a specific type of packet

    Args:
        testbed_config (obj): L2/L3 snappi config of a testbed
        port_names (list of string): names of ixia ports to capture packets on
        capture_type (Enum): Type of packet to capture
        capture_name (str): Name of the capture
        format (str): Format of the capture (default pcapng), either pcap or pcapng
    Returns:
        N/A
    """

    cap = testbed_config.captures.capture(name=capture_name if capture_name else "PacketCapture")[-1]
    cap.port_names = []
    for p_name in port_names:
        cap.port_names.append(p_name)
    if format == "pcapng" or format == "pcap":
        cap.format = format
    else:
        raise Exception("Unsupported capture format")


def calc_pfc_pause_flow_rate(port_speed, oversubscription_ratio=2):
    """
    Calculate the pfc pause flow rate to block the flow of traffic through the port using a blocking
    factor.
    Args:
        port_speed (int): port speed in gbps ex. 100
        oversubscription_ratio (int): factor by which to block the port (default: 2)
    Returns:
        pps: pause frames to be sent per second to block port by block_factor
    """
    pause_dur = 65535 * 64 * 8.0 / (port_speed * 1e9)
    pps = int(oversubscription_ratio / pause_dur)

    return pps


def start_pfcwd_fwd(duthost, asic_value=None):
    """
    Start PFC watchdog in Forward mode.
    Stops the PFCWD cleanly before restarting it in FORWARD mode.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        asic_value: asic value of the host

    Returns:
        N/A
    """

    # Starting PFCWD in forward mode with detection and restoration duration of 200msec.
    if asic_value is None:
        stop_pfcwd(duthost)
        duthost.shell('sudo pfcwd start --action forward 200 --restoration-time 200')
    else:
        stop_pfcwd(duthost, asic_value)
        duthost.shell('sudo ip netns exec {} pfcwd start --action forward 200 --restoration-time 200'.
                      format(asic_value))


def clear_counters(duthost, port):
    """
    Clear PFC, Queuecounters, Drop and generic counters from SONiC CLI.
    Args:
        duthost (Ansible host instance): Device under test
        port (str): port name
    Returns:
        None
    """

    duthost.shell("sudo sonic-clear counters \n")
    duthost.shell("sudo sonic-clear pfccounters \n")
    duthost.shell("sudo sonic-clear priority-group drop counters \n")
    duthost.shell("sonic-clear counters \n")
    duthost.shell("sonic-clear pfccounters \n")

    if (duthost.is_multi_asic):
        asic = duthost.get_port_asic_instance(port).get_asic_namespace()
        duthost.shell("sudo ip netns exec {} sonic-clear queuecounters \n".format(asic))
        duthost.shell("sudo ip netns exec {} sonic-clear dropcounters \n".format(asic))
    else:
        duthost.shell("sonic-clear queuecounters \n")
        duthost.shell("sonic-clear dropcounters \n")


def get_interface_stats(duthost, port):
    """
    Get the Rx and Tx port failures, throughput and pkts from SONiC CLI.
    This is the equivalent of the "show interface counters" command.
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
    Returns:
        i_stats (dict): Returns various parameters for given DUT and port.
    """
    # Initializing nested dictionary i_stats
    i_stats = defaultdict(dict)

    n_out = parse_portstat(duthost.command('portstat -i {}'.format(port))['stdout_lines'])[port]
    i_stats[duthost.hostname][port] = n_out
    for k in ['rx_ok', 'rx_err', 'rx_drp', 'rx_ovr', 'tx_ok', 'tx_err', 'tx_drp', 'tx_ovr']:
        i_stats[duthost.hostname][port][k] = int("".join(i_stats[duthost.hostname][port][k].split(',')))

    # rx_err, rx_ovr and rx_drp are counted in single counter rx_fail
    # tx_err, tx_ovr and tx_drp are counted in single counter tx_fail
    rx_err = ['rx_err', 'rx_ovr', 'rx_drp']
    tx_err = ['tx_err', 'tx_ovr', 'tx_drp']
    rx_fail = 0
    tx_fail = 0
    for m in rx_err:
        rx_fail = rx_fail + n_out[m]
    for m in tx_err:
        tx_fail = tx_fail + n_out[m]

    # Any throughput below 1MBps is measured as 0 for simplicity.
    thrput = n_out['rx_bps']
    if thrput.split(' ')[1] == 'MB/s' and (thrput.split(' ')[0]) != '0.00':
        i_stats[duthost.hostname][port]['rx_thrput_Mbps'] = float(thrput.split(' ')[0]) * 8
    else:
        i_stats[duthost.hostname][port]['rx_thrput_Mbps'] = 0
    thrput = n_out['tx_bps']
    if thrput.split(' ')[1] == 'MB/s' and (thrput.split(' ')[0]) != '0.00':
        i_stats[duthost.hostname][port]['tx_thrput_Mbps'] = float(thrput.split(' ')[0]) * 8
    else:
        i_stats[duthost.hostname][port]['rx_thrput_Mbps'] = 0

    i_stats[duthost.hostname][port]['rx_pkts'] = n_out['rx_ok']
    i_stats[duthost.hostname][port]['tx_pkts'] = n_out['tx_ok']
    i_stats[duthost.hostname][port]['rx_fail'] = rx_fail
    i_stats[duthost.hostname][port]['tx_fail'] = tx_fail

    return i_stats


def get_queue_count_all_prio(duthost, port):
    """
    Get the egress queue count in packets and bytes for a given port and priority from SONiC CLI.
    This is the equivalent of the "show queue counters" command.
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
    Returns:
        queue_dict (dict): key-value with key=dut+port+prio and value=queue count
    """
    # Initializing nested dictionary queue_dict
    queue_dict = defaultdict(dict)
    queue_dict[duthost.hostname][port] = {}

    # Preparing the dictionary for all 7 priority queues.
    for priority in range(7):
        total_pkts, _ = get_egress_queue_count(duthost, port, priority)
        queue_dict[duthost.hostname][port]['prio_' + str(priority)] = total_pkts

    return queue_dict


def get_pfc_count(duthost, port):
    """
    Get the PFC frame count for a given port from SONiC CLI
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
    Returns:
        pfc_dict (dict) : Returns Rx and Tx PFC for the given DUT and interface.
    """
    pfc_dict = defaultdict(dict)
    pfc_dict[duthost.hostname][port] = {}
    raw_out = duthost.shell("show pfc counters | sed -n '/Port Tx/,/^$/p' | grep '{} '".format(port))['stdout']
    pause_frame_count = raw_out.split()
    for m in range(1, len(pause_frame_count)):
        pfc_dict[duthost.hostname][port]['tx_pfc_'+str(m-1)] = int(pause_frame_count[m].replace(',', ''))

    raw_out = duthost.shell("show pfc counters | sed -n '/Port Rx/,/^$/p' | grep '{} '".format(port))['stdout']
    pause_frame_count = raw_out.split()
    for m in range(1, len(pause_frame_count)):
        pfc_dict[duthost.hostname][port]['rx_pfc_'+str(m-1)] = int(pause_frame_count[m].replace(',', ''))

    return pfc_dict
