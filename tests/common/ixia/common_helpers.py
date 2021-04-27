"""This module contains some auxiliary functions that are required
to support automation activities. These functions are used for various
secondary activities like convert the ansible Unicode STDOUT output
to string, get IP address in a subnet, increment an IP address, get
VLAN subnet etc.

This file is also a placeholder for auxiliary function that are
required for supporting automation with Ixia devices in future:
like collecting diagnostics, uploading and downloading files
to/from API server, processing the statistics after obtaining them
in .csv format etc.
"""

import ipaddr
from netaddr import IPNetwork
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice

def increment_ip_address(ip, incr=1) :
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
    return(return_value)


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
        result += x.encode('UTF8')
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
        print 'There should be only one Vlan at the DUT'
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

    if "BUFFER_POOL" not in config_facts.keys():
        return None

    buffer_pools = config_facts['BUFFER_POOL']
    profile_name = 'egress_lossless_pool'

    if profile_name not in buffer_pools.keys():
        return None

    egress_lossless_pool = buffer_pools[profile_name]
    return int(egress_lossless_pool['size'])

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

def get_peer_ixia_chassis(conn_data, dut_hostname):
    """
    Get the IXIA chassis connected to the DUT
    Note that a DUT can only be connected to a IXIA chassis

    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:

        {
            u'device_conn': {
                u'msr-s6100-dut-1': {
                    u'Ethernet0': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port5',
                        u'speed': u'40000'
                    },
                    u'Ethernet1': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port6',
                        u'speed': u'40000'
                    },
                    u'Ethernet2': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port7',
                        u'speed': u'40000'
                    }
                }
            },
            u'device_info': [{u'HwSku': u'Dell-S6100', u'Type': u'DevSonic'}],
            u'device_port_vlans': [
                {
                    u'Ethernet0': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    },
                    u'Ethernet1': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    },
                    u'Ethernet2': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    }
                }
            ],
            u'device_vlan_list': [[]],
            u'device_vlan_map_list': {u'msr-s6100-dut-1': []},
            u'device_vlan_range': [[]]
        }

        dut_hostname (str): hostname of the DUT

    Returns:
        The name of the peer IXIA chassis or None
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
        return None

def get_peer_port(conn_data, dut_hostname, dut_intf):
    """
    Get the peer port of the DUT port

    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:

        {
            u'device_conn': {
                u'msr-s6100-dut-1': {
                    u'Ethernet0': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port5',
                        u'speed': u'40000'
                    },
                    u'Ethernet1': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port6',
                        u'speed': u'40000'
                    },
                    u'Ethernet2': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port7',
                        u'speed': u'40000'
                    }
                }
            },
            u'device_info': [{u'HwSku': u'Dell-S6100', u'Type': u'DevSonic'}],
            u'device_port_vlans': [
                {
                    u'Ethernet0': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    },
                    u'Ethernet1': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    },
                    u'Ethernet2': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    }
                }
            ],
            u'device_vlan_list': [[]],
            u'device_vlan_map_list': {u'msr-s6100-dut-1': []},
            u'device_vlan_range': [[]]
        }

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

        {
            u'device_conn': {
                u'msr-s6100-dut-1': {
                    u'Ethernet0': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port5',
                        u'speed': u'40000'
                    },
                    u'Ethernet1': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port6',
                        u'speed': u'40000'
                    },
                    u'Ethernet2': {
                        u'peerdevice': u'msr-ixia-1',
                        u'peerport': u'Card12/Port7',
                        u'speed': u'40000'
                    }
                }
            },
            u'device_info': [{u'HwSku': u'Dell-S6100', u'Type': u'DevSonic'}],
            u'device_port_vlans': [
                {
                    u'Ethernet0': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    },
                    u'Ethernet1': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    },
                    u'Ethernet2': {
                        u'mode': u'Access',
                        u'vlanids': u'',
                        u'vlanlist': []
                    }
                }
            ],
            u'device_vlan_list': [[]],
            u'device_vlan_map_list': {u'msr-s6100-dut-1': []},
            u'device_vlan_range': [[]]
        }

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

    return "{:x}".format(vector)

def get_wred_profiles(host_ans):
    """
    Get all the WRED/ECN profiles of a SONiC switch

    Args:
        host_ans: Ansible host instance of the device

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
    config_facts = host_ans.config_facts(host=host_ans.hostname,
                                         source="running")['ansible_facts']

    if "WRED_PROFILE" in config_facts.keys():
        return config_facts['WRED_PROFILE']
    else:
        return None

def config_wred(host_ans, kmin, kmax, pmax, profile=None):
    """
    Config a WRED/ECN profile of a SONiC switch

    Args:
        host_ans: Ansible host instance of the device
        kmin (int): RED/ECN minimum threshold in bytes
        kmax (int): RED/ECN maximum threshold in bytes
        pmax (int): RED/ECN maximum marking probability in percentage
        profile (str): name of profile to configure (None means any profile)

    Returns:
        If configuration succeeds (bool)
    """

    if not isinstance(kmin, int) or \
       not isinstance(kmax, int) or \
       not isinstance(pmax, int):
        return False

    if kmin < 0 or kmax < 0 or pmax < 0 or pmax > 100 or kmin > kmax:
        return False

    profiles = get_wred_profiles(host_ans)
    """ Cannot find any WRED/ECN profiles """
    if profiles is None:
        return False

    """ Cannot find the profile to configure at the device """
    if profile is not None and profile not in profiles:
        return False

    for p in profiles:
        """ This is not the profile to configure """
        if profile is not None and profile != p:
            continue

        kmin_old = int(profiles[p]['green_min_threshold'])
        kmax_old = int(profiles[p]['green_max_threshold'])

        if kmin_old > kmax_old:
            return False

        """ Ensure that Kmin is no larger than Kmax during the update """
        if kmin > kmin_old:
            host_ans.shell('sudo ecnconfig -p {} -gmax {}'.format(p, kmax))
            host_ans.shell('sudo ecnconfig -p {} -gmin {}'.format(p, kmin))

        else:
            host_ans.shell('sudo ecnconfig -p {} -gmin {}'.format(p, kmin))
            host_ans.shell('sudo ecnconfig -p {} -gmax {}'.format(p, kmax))

    return True

def enable_ecn(host_ans, prio):
    """
    Enable ECN marking on a priority

    Args:
        host_ans: Ansible host instance of the device
        prio (int): priority

    Returns:
        N/A
    """
    host_ans.shell('sudo ecnconfig -q {} on'.format(prio))

def disable_ecn(host_ans, prio):
    """
    Disable ECN marking on a priority

    Args:
        host_ans: Ansible host instance of the device
        prio (int): priority

    Returns:
        N/A
    """
    host_ans.shell('sudo ecnconfig -q {} off'.format(prio))

def config_buffer_alpha(host_ans, profile, alpha_log2):
    """
    Configure buffer threshold (a.k.a., alpha)

    Args:
        host_ans: Ansible host instance of the device
        profile (str): buffer profile name
        alpha_log2 (int): set threshold to 2^alpha_log2

    Returns:
        N/A
    """
    host_ans.shell('sudo mmuconfig -p {} -a {}'.format(profile, alpha_log2))

def config_ingress_lossless_buffer_alpha(host_ans, alpha_log2):
    """
    Configure ingress buffer thresholds (a.k.a., alpha) of a device to 2^alpha_log2

    Args:
        host_ans: Ansible host instance of the device
        alpha_log2 (int): set threshold to 2^alpha_log2

    Returns:
        If configuration succeeds (bool)
    """
    if not isinstance(alpha_log2, int):
        return False

    config_facts = host_ans.config_facts(host=host_ans.hostname,
                                         source="running")['ansible_facts']

    if "BUFFER_PROFILE" not in config_facts.keys():
        return False

    buffer_profiles = config_facts['BUFFER_PROFILE']
    ingress_profiles = []
    for profile in buffer_profiles:
        if profile.startswith('ingress_lossless') or profile.startswith('pg_lossless'):
            ingress_profiles.append(profile)

    for profile in ingress_profiles:
        config_buffer_alpha(host_ans=host_ans, profile=profile, alpha_log2=alpha_log2)

    """ Check if configuration succeeds """
    config_facts = host_ans.config_facts(host=host_ans.hostname,
                                         source="running")['ansible_facts']

    for profile in ingress_profiles:
        dynamic_th = config_facts['BUFFER_PROFILE'][profile]['dynamic_th']
        if int(dynamic_th) != alpha_log2:
            return False

    return True

def get_pfcwd_config_attr(host_ans, config_scope, attr):
    """
    Get PFC watchdog configuration attribute

    Args:
        host_ans: Ansible host instance of the device
        config_scope (str): 'GLOBAL' or interface name
        attr (str): config attribute name, e.g., 'detection_time'

    Returns:
        config attribute (str) or None
    """
    config_facts = host_ans.config_facts(host=host_ans.hostname,
                                         source="running")['ansible_facts']

    if 'PFC_WD' not in config_facts.keys():
        return None

    pfcwd_config = config_facts['PFC_WD']
    if config_scope not in pfcwd_config:
        return None

    config = pfcwd_config[config_scope]
    if attr in config:
        return config[attr]

    return None

def get_pfcwd_poll_interval(host_ans):
    """
    Get PFC watchdog polling interval

    Args:
        host_ans: Ansible host instance of the device

    Returns:
        Polling interval in ms (int) or None
    """
    val = get_pfcwd_config_attr(host_ans=host_ans,
                                config_scope='GLOBAL',
                                attr='POLL_INTERVAL')

    if val is not None:
        return int(val)

    return None

def get_pfcwd_detect_time(host_ans, intf):
    """
    Get PFC watchdog detection time of a given interface

    Args:
        host_ans: Ansible host instance of the device
        intf (str): interface name

    Returns:
        Detection time in ms (int) or None
    """
    val = get_pfcwd_config_attr(host_ans=host_ans,
                                config_scope=intf,
                                attr='detection_time')

    if val is not None:
        return int(val)

    return None

def get_pfcwd_restore_time(host_ans, intf):
    """
    Get PFC watchdog restoration time of a given interface

    Args:
        host_ans: Ansible host instance of the device
        intf (str): interface name

    Returns:
        Restoration time in ms (int) or None
    """
    val = get_pfcwd_config_attr(host_ans=host_ans,
                                config_scope=intf,
                                attr='restoration_time')

    if val is not None:
        return int(val)

    return None

def start_pfcwd(duthost):
    """
    Start PFC watchdog with default setting

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)

    Returns:
        N/A
    """
    duthost.shell('sudo pfcwd start_default')

def stop_pfcwd(duthost):
    """
    Stop PFC watchdog

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)

    Returns:
        N/A
    """
    duthost.shell('sudo pfcwd stop')

def disable_packet_aging(duthost):
    """
    Disable packet aging feature (only on MLNX switches)

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)

    Returns:
        N/A
    """
    if isMellanoxDevice(duthost):
        duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
        duthost.command("docker cp /tmp/packets_aging.py syncd:/")
        duthost.command("docker exec syncd python /packets_aging.py disable")
        duthost.command("docker exec syncd rm -rf /packets_aging.py")

def enable_packet_aging(duthost):
    """
    Enable packet aging feature (only on MLNX switches)

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)

    Returns:
        N/A
    """
    if isMellanoxDevice(duthost):
        duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
        duthost.command("docker cp /tmp/packets_aging.py syncd:/")
        duthost.command("docker exec syncd python /packets_aging.py enable")
        duthost.command("docker exec syncd rm -rf /packets_aging.py")
