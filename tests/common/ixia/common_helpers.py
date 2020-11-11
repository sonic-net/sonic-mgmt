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

def increment_ip_address (ip, incr=1) :
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

def get_next_dut_port(conn_data, dut_portname):
    """
    Given a DUT port, get the next one DUT port

    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:
        
        {
            u'device_conn': {
                u'Ethernet0': {
                    u'peerdevice': u'msr-ixia-1',
                    u'peerport': u'Card12/Port3',
                    u'speed': u'100000'
                },
                u'Ethernet4': {
                    u'peerdevice': u'msr-ixia-1',
                    u'peerport': u'Card12/Port4',
                    u'speed': u'100000'
                }
            },

            u'device_info': {
                u'HwSku': u'Arista-7060', 
                u'Type': u'DevSonic'
            },

            u'device_port_vlans': {
                u'Ethernet0': {
                    u'mode': u'Access',
                    u'vlanids': u'',
                    u'vlanlist': []
                },
                u'Ethernet4': {
                    u'mode': u'Access',
                    u'vlanids': u'',
                    u'vlanlist': []
                }
            }
        }

        dut_portname (str): DUT port name

    Return:
        Return the name of the next DUT port
    """
    device_conn = conn_data['device_conn']
    dut_ports = list(device_conn.keys())

    if dut_portname not in dut_ports:
        return None 
    else:
        id = dut_ports.index(dut_portname)
        next_id = (id + 1) % len(dut_ports)
        return dut_ports[next_id]

def get_peer_ixia_chassis(conn_data):
    """
    Get the IXIA chassis connected to the DUT
    Note that a DUT can only be connected to a IXIA chassis

    Args:
        conn_data (dict): the dictionary returned by conn_graph_fact.
        Example format of the conn_data is given below:
        
        {
            u'device_conn': {
                u'Ethernet0': {
                    u'peerdevice': u'msr-ixia-1',
                    u'peerport': u'Card12/Port3',
                    u'speed': u'100000'
                },
                u'Ethernet4': {
                    u'peerdevice': u'msr-ixia-1',
                    u'peerport': u'Card12/Port4',
                    u'speed': u'100000'
                }
            },

            u'device_info': {
                u'HwSku': u'Arista-7060', 
                u'Type': u'DevSonic'
            },

            u'device_port_vlans': {
                u'Ethernet0': {
                    u'mode': u'Access',
                    u'vlanids': u'',
                    u'vlanlist': []
                },
                u'Ethernet4': {
                    u'mode': u'Access',
                    u'vlanids': u'',
                    u'vlanlist': []
                }
            }
        }
    
    Return:
        Return the name of the peer IXIA chassis
    """
    
    device_conn = conn_data['device_conn']
    peer_devices = list(set(device_conn[port]['peerdevice'] for port in device_conn))

    if len(peer_devices) == 1:
        return peer_devices[0]
    else:
        return None 


