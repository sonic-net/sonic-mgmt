from ansible_host import AnsibleHost
from netaddr import IPAddress, IPNetwork
import json
import re

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

def eos_to_linux_intf(eos_intf_name):
    """
    @Summary: Map EOS's interface name to Linux's interface name
    @param eos_intf_name: Interface name in EOS
    @return: Return the interface name in Linux
    """
    return eos_intf_name.replace('Ethernet', 'et').replace('/', '_')

def get_active_intfs(host_ans):
    """
    @Summary: Get the active interfaces of a DUT
    @param host_ans: Ansible host instance of this DUT
    @return: Return the list of active interfaces
    """
    int_status = host_ans.show_interface(command = "status")['ansible_facts']['int_status']
    active_intfs = []
    
    for intf in int_status:
        if int_status[intf]['admin_state'] == 'up' and \
           int_status[intf]['oper_state'] == 'up':
            active_intfs.append(intf)

    return active_intfs

def get_addrs_in_subnet(subnet, n):
    """ 
    @Summary: Get N IP addresses in a subnet
    @param subnet: IPv4 subnet, e.g., '192.168.1.1/24'
    @param n: # of IP addresses to get 
    @return: Retuen n IPv4 addresses in this subnet in a list
    """
    ip_addr = subnet.split('/')[0]
    ip_addrs = [str(x) for x in list(IPNetwork(subnet))]
    ip_addrs.remove(ip_addr)
    
    """ Try to avoid network and broadcast addresses """
    if len(ip_addrs) >= n + 2:
        del ip_addrs[0]
        del ip_addrs[-1]
    
    return ip_addrs[:n]

def get_neigh_ip(ip_addr, netmask):
    """
    @Summary: Given an IP address and a netmask, get another IP in this subnet. 
    @param ip_addr: IPv4 address string (e.g., "192.168.1.1")
    @param netmask: network mask string (e.g., "255.255.255.254")
    @return: Return another IP address in this subnet
    """
    prefix_len = IPAddress(netmask).netmask_bits()
    ip_addrs = get_addrs_in_subnet(ip_addr + '/' + str(prefix_len), 1)
    
    if len(ip_addrs) != 0:
        return ip_addrs[0]
    
    else:
        return None  

def gen_arp_responder_config(intfs, ip_addrs, mac_addrs, config_file):
    """
    @Summary: Generate a configuration file for ARP responder
    @param intfs: list of interfaces
    @param ip_addrs: list of IP addresses
    @param mac_addrs: list of MAC addresses
    @param config_file: configuration file path 
    return: Return true if the config file is successfully generated
    """
    if len(intfs) != len(ip_addrs) or len(intfs) != len(mac_addrs):
        return False 
    
    config = dict()
    for i in range(len(intfs)):
        config[intfs[i]] = dict()
        """ The config file accepts MAC addresses like 00112233445566 without any : """
        config[intfs[i]][ip_addrs[i]] = mac_addrs[i].replace(':', '')
    
    with open(config_file, 'w') as fp:
        json.dump(config, fp)
            
    return True 

def check_mac_table(host_ans, mac_addrs):
    """
    @Summary: Check if the DUT's MAC table (FIB) has all the MAC address information
    @param host_ans: Ansible host instance of this DUT
    @param mac_addrs: list of MAC addresses to check 
    return: Return true if the DUT's MAC table has all the MAC addresses 
    """
    if mac_addrs is None:
        return False 
    
    stdout = ansible_stdout_to_str(host_ans.command('show mac')['stdout'])
    
    for mac in mac_addrs:
        if mac.upper() not in stdout.upper():
            return False 
        
    return True

def get_mac(host_ans, ip_addr):
    """
    @Summary: Get the MAC address of a given IP address in a DUT
    @param host_ans: Ansible host instance of this DUT
    @param ip_addr: IP address
    return: Return the MAC address or None if we cannot find it
    """
    cmd = 'sudo arp -a -n %s' % (ip_addr)
    stdout = ansible_stdout_to_str(host_ans.command(cmd)['stdout']).strip()
    
    if len(stdout) == 0 or 'incomplete' in stdout:
        return None 
         
    pattern = re.compile(ur'(?:[0-9a-fA-F]:?){12}')
    results = re.findall(pattern, stdout)
    
    if len(results) == 0:
        return None 
    
    else:
        return results[0]

def config_intf_ip_mac(host_ans, intf, ip_addr, netmask, mac_addr):
    """
    @Summary: Configure IP and MAC on a intferface of a PTF
    @param host_ans: Ansible host instance of this PTF
    @param intf: interface name
    @param ip_addr: IP address, e.g., '192.168.1.1'
    @param netmask: Network mask, e.g., '255.255.255.0'  
    @param mac_addr: MAC address, e.g., '00:11:22:33:44:55'
    """
    host_ans.shell('ifconfig %s down' % intf)
    host_ans.shell('ifconfig %s hw ether %s' % (intf, mac_addr))
    host_ans.shell('ifconfig %s up' % intf)
    host_ans.shell('ifconfig %s %s netmask %s' % (intf, ip_addr, netmask))
    
    