from ansible_host import AnsibleHost
from netaddr import IPAddress, IPNetwork
from qos_fixtures import lossless_prio_dscp_map, conn_graph_facts, leaf_fanouts
import json
import re
import ipaddress

PFC_GEN_FILE = 'pfc_gen.py'
PFC_GEN_LOCAL_PATH = '../../ansible/roles/test/files/helpers/pfc_gen.py'
PFC_GEN_REMOTE_PATH = '~/pfc_gen.py'

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

def start_pause(host_ans, pkt_gen_path, intf, pkt_count, pause_duration, pause_priority):
    """
    @Summary: Start priority-based/global flow control pause storm on an interface of a leaf fanout switch
    @param host_ans: Ansible host instance of this leaf fanout
    @param pkt_gen_path: path of packet generator
    @param intf: interface to send packets
    @param pkt_count: # of pause frames to send
    @pause_duration: pause time duration 
    @pause_priority: priority to pause (None means global pause)    
    """
    """ global pause """
    if pause_priority is None:
        cmd = "nohup sudo python %s -i %s -g -t %d -n %d </dev/null >/dev/null 2>&1 &" % (pkt_gen_path, intf, pause_duration, pkt_count)

    else:
        cmd = "nohup sudo python %s -i %s -p %d -t %d -n %d </dev/null >/dev/null 2>&1 &" % (pkt_gen_path, intf, 2**pause_priority, pause_duration, pkt_count)        

    print cmd 
    host_ans.shell(cmd)
     
def stop_pause(host_ans, pkt_gen_path):
    """
    @Summary: Stop priority-based/global flow control pause storm on a leaf fanout switch
    @param host_ans: Ansible host instance of this leaf fanout
    @param pkt_gen_path: path of packet generator
    """
    cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (pkt_gen_path)
    host_ans.shell(cmd)
    
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
    
def gen_testbed_t0(ansible_adhoc, testbed):
    """
    @Summary: Generate a T0 testbed configuration
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
           
    return vlan_members, ptf_intfs, vlan_ip_addrs, vlan_mac_addrs

def setup_testbed(ansible_adhoc, testbed, leaf_fanouts, ptf_local_path, ptf_remote_path):
    """
    @Summary: Set up the testbed
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param leaf_fanouts: Leaf fanout switches
    @param ptf_local_path: local path of PTF script
    @param ptf_remote_dest: remote path of PTF script
    """
    
    """ Copy the PFC generator to leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE)
        peerdev_ans.shell(cmd)
        peerdev_ans.copy(src=PFC_GEN_LOCAL_PATH, dest=PFC_GEN_REMOTE_PATH, force=True)
   
    """ Stop PFC storm at the leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        stop_pause(peerdev_ans, PFC_GEN_FILE)
                       
    """ Remove existing python scripts on PTF """
    ptf_hostname = testbed['ptf']
    ptf_ans = AnsibleHost(ansible_adhoc, ptf_hostname)
    result = ptf_ans.find(paths=['~/'], patterns="*.py")['files']
    files = [ansible_stdout_to_str(x['path']) for x in result]
    
    for file in files:
        ptf_ans.file(path=file, mode="absent")

    """ Copy the PFC test script to the PTF container """  
    ptf_ans.copy(src=ptf_local_path, dest=ptf_remote_path, force=True)