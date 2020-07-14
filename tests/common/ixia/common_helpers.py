import ipaddr
from netaddr import IPNetwork

def incriment_ip_address (ip, incrment=1) :
    ipaddress = ipaddr.IPv4Address(ip)
    ipaddress = ipaddress + incrment
    return_value = ipaddress._string_from_ip_int(ipaddress._ip)
    return(return_value)

def ansible_stdout_to_str(ansible_stdout):
    """
    @Summary: The stdout of Ansible host is essentially a list of unicode characters. This function converts it to a string.
    @param ansible_stdout: stdout of Ansible
    @return: Return a string
    """
    result = ""
    for x in ansible_stdout:
        result += x.encode('UTF8')
    return result

"""
@Summary: Get Vlan subnet of a T0 device
@param host_ans: Ansible host instance of the device
@return: Vlan subnet, e.g., "192.168.1.1/24" where 192.168.1.1 is gateway and 24 is prefix length
"""    
def get_vlan_subnet(host_ans):
    mg_facts = host_ans.minigraph_facts(host=host_ans.hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']

    if len(mg_vlans) != 1:
        print 'There should be only one Vlan at the DUT'
        return None

    mg_vlan_intfs = mg_facts['minigraph_vlan_interfaces']
    prefix_len = mg_vlan_intfs[0]['prefixlen']
    gw_addr = ansible_stdout_to_str(mg_vlan_intfs[0]['addr'])
    return gw_addr + '/' + str(prefix_len)

"""
@Summary: Get N IP addresses in a subnet
@param subnet: IPv4 subnet, e.g., '192.168.1.1/24'
@param n: # of IP addresses to get
@return: Retuen n IPv4 addresses in this subnet in a list
"""
def get_addrs_in_subnet(subnet, n):
    ip_addr = subnet.split('/')[0]
    ip_addrs = [str(x) for x in list(IPNetwork(subnet))]
    ip_addrs.remove(ip_addr)

    """ Try to avoid network and broadcast addresses """
    if len(ip_addrs) >= n + 2:
        del ip_addrs[0]
        del ip_addrs[-1]

    return ip_addrs[:n]
