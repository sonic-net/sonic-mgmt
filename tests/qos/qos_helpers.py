from ansible_host import AnsibleHost
from netaddr import IPAddress, IPNetwork
from qos_fixtures import lossless_prio_dscp_map, conn_graph_facts, leaf_fanouts
import json
import re
import ipaddress

def atoi(text):
    return int(text) if text.isdigit() else text

def natural_keys(text):
    return [atoi(c) for c in re.split(r'(\d+)', text)]

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

def get_phy_intfs(host_ans):
    """
    @Summary: Get the physical interfaces (e.g., EthernetX) of a DUT
    @param host_ans: Ansible host instance of this DUT
    @return: Return the list of active interfaces
    """
    intf_facts = host_ans.interface_facts()['ansible_facts']['ansible_interface_facts'] 
    phy_intfs = [k for k in intf_facts.keys() if k.startswith('Ethernet')]
    return phy_intfs 

def get_active_intfs(host_ans):
    """
    @Summary: Get the active interfaces of a DUT
    @param host_ans: Ansible host instance of this DUT
    @return: Return the list of active interfaces
    """
    int_status = host_ans.show_interface(command="status")['ansible_facts']['int_status']
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

def get_active_vlan_members(host_ans, hostname):
    """
    @Summary: Get all the active physical interfaces enslaved to a Vlan
    @param host_ans: Ansible host instance of the device
    @param hostname: host name of the device
    @return: Return the list of active physical interfaces
    """
    mg_facts = host_ans.minigraph_facts(host=hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']
    
    if len(mg_vlans) != 1:
        print 'There should be only one Vlan at the DUT'
        return None
    
    """ Get all the Vlan memebrs """
    vlan_intf = mg_vlans.keys()[0]
    vlan_members = mg_vlans[vlan_intf]['members']
    
    """ Filter inactive Vlan members """
    active_intfs = get_active_intfs(host_ans)
    vlan_members = [x for x in vlan_members if x in active_intfs]
    
    return vlan_members 

def get_vlan_subnet(host_ans, hostname):
    """
    @Summary: Get Vlan subnet of a T0 device
    @param host_ans: Ansible host instance of the device
    @param hostname: host name of the device
    @return: Return Vlan subnet, e.g., "192.168.1.1/24"
    """
    mg_facts = host_ans.minigraph_facts(host=hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']
    
    if len(mg_vlans) != 1:
        print 'There should be only one Vlan at the DUT'
        return None
    
    mg_vlan_intfs = mg_facts['minigraph_vlan_interfaces']        
    vlan_subnet = ansible_stdout_to_str(mg_vlan_intfs[0]['subnet'])
    return vlan_subnet
    
def config_testbed_t0(ansible_adhoc, testbed):
    """
    @Summary: Configure a T0 testbed
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @return: Return four values: DUT interfaces, PTF interfaces, PTF IP addresses, and PTF MAC addresses, 
    """ 
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    
    """ Get all the active physical interfaces enslaved to the Vlan """
    """ These interfaces are actually server-faced interfaces at T0 """
    vlan_members = get_active_vlan_members(dut_ans, dut_hostname)
    
    """ Get Vlan subnet """
    vlan_subnet = get_vlan_subnet(dut_ans, dut_hostname)
    
    """ Prefix length to network mask """
    vlan_subnet_mask = ipaddress.ip_network(unicode(vlan_subnet, "utf-8")).netmask
    
    """ Generate IP addresses for servers in the Vlan """
    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(vlan_members))
    
    """ Generate MAC addresses 00:00:00:00:00:XX for servers in the Vlan """
    vlan_mac_addrs = [5 * '00:' + format(k, '02x') for k in random.sample(range(1, 256), len(vlan_members))]
    
    """ Find correspoinding interfaces on PTF """
    phy_intfs = get_phy_intfs(dut_ans)
    phy_intfs.sort(key=natural_keys)
    vlan_members.sort(key=natural_keys)
    vlan_members_index = [phy_intfs.index(intf) for intf in vlan_members]
    ptf_intfs = ['eth' + str(i) for i in vlan_members_index]
   
    """ Remove existing IP addresses from PTF host """ 
    ptf_hostname = testbed['ptf']
    ptf_ans = AnsibleHost(ansible_adhoc, ptf_hostname)
    ptf_ans.script('scripts/remove_ip.sh')

    """ Clear MAC table in DUT (host memory and ASIC) """
    dut_ans.shell('sonic-clear fdb all </dev/null >/dev/null 2>&1 &')
    dut_ans.shell('sudo ip -s -s neigh flush all </dev/null >/dev/null 2>&1 &')
        
    """ Configure IP and MAC addresses on PTF """
    for i in range(len(ptf_intfs)):
        config_intf_ip_mac(ptf_ans, ptf_intfs[i], vlan_ip_addrs[i], vlan_subnet_mask, vlan_mac_addrs[i])
    
    return vlan_members, ptf_intfs, vlan_ip_addrs, vlan_mac_addrs

        