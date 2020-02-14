
from ansible_host import AnsibleHost
from qos_fixtures import *
from qos_helpers import ansible_stdout_to_str, eos_to_linux_intf, get_active_intfs, get_addrs_in_subnet, get_neigh_ip,check_mac_table, get_mac

import pytest
import os
import time
import re
import struct
import random
import ipaddress

PFC_GEN_FILE = 'pfc_gen.py'
PFC_GEN_FILE_RELATIVE_PATH = '../../ansible/roles/test/files/helpers/pfc_gen.py'
PFC_GEN_FILE_DEST = '~/pfc_gen.py'
PFC_PKT_COUNT = 1000000000

PTF_FILE_RELATIVE_PATH = '../../ansible/roles/test/files/ptftests/pfc_pause_test.py'
PTF_FILE_DEST = '~/pfc_pause_test.py'
PTF_PKT_COUNT = 50
PTF_PKT_INTVL_SEC = 0.1
PTF_PASS_RATIO_THRESH = 0.75
         
def atoi(text):
    return int(text) if text.isdigit() else text

def natural_keys(text):
    return [atoi(c) for c in re.split(r'(\d+)', text)]

def setup_testbed(ansible_adhoc, testbed, leaf_fanouts):
    """
    @Summary: Set up the testbed, including (1) copying the PFC generator to the leaf fanout switches,
    and (2) copying the PTF script to the PTF container.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param leaf_fanouts: Leaf fanout switches
    """
    
    """ Copy the PFC generator to leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE)
        peerdev_ans.shell(cmd)
        file_src = os.path.join(os.path.dirname(__file__), PFC_GEN_FILE_RELATIVE_PATH)
        peerdev_ans.copy(src=file_src, dest=PFC_GEN_FILE_DEST, force=True)
                  
    """ Remove existing python scripts on PTF """
    ptf_hostname = testbed['ptf']
    ptf_ans = AnsibleHost(ansible_adhoc, ptf_hostname)
    result = ptf_ans.find(paths=['~/'], patterns="*.py")['files']
    files = [ansible_stdout_to_str(x['path']) for x in result]
    
    for file in files:
        ptf_ans.file(path=file, mode="absent")

    """ Copy the PFC test script to the PTF container """  
    file_src = os.path.join(os.path.dirname(__file__), PTF_FILE_RELATIVE_PATH)
    ptf_ans.copy(src=file_src, dest=PTF_FILE_DEST, force=True)

def run_test_t0(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, prio, dscp, dscp_bg, queue_paused, is_pfc=True, pause_time=65535, max_test_count=128):
    """ 
    @Summary: Run a series of tests on a T0 topology.
    For the T0 topology, we only test Vlan (server-faced) interfaces.    
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param conn_graph_facts: Testbed topology
    @param leaf_fanouts: Leaf fanout switches
    @param prio: priority of PFC frame
    @param dscp: DSCP value of test data packets
    @param dscp_bg: DSCP value of background data packets
    @param queue_paused: if the queue is expected to be paused
    @param is_pfc: If this test is for PFC?
    @param pause_time: pause time quanta of PFC frames. It is 65535 (maximum pause time quanta) by default.
    @param max_test_count: maximum count of tests to run. By default, it is a very large value to cover all the interfaces.  
    return: Return # of iterations and # of passed iterations for each tested interface.   
    """
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    mg_facts = dut_ans.minigraph_facts(host=dut_hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']

    if len(mg_vlans) != 1:
        print 'There should be only one Vlan at the DUT'
        return None
    
    """ Get all the Vlan memebrs """
    vlan_intf = mg_vlans.keys()[0]
    vlan_members = mg_vlans[vlan_intf]['members']
    
    """ Filter inactive Vlan members """
    active_intfs = get_active_intfs(dut_ans)
    vlan_members = [x for x in vlan_members if x in active_intfs]

    mg_vlan_intfs = mg_facts['minigraph_vlan_interfaces']        
    vlan_subnet = ansible_stdout_to_str(mg_vlan_intfs[0]['subnet'])
    vlan_subnet_mask = ipaddress.ip_network(unicode(vlan_subnet, "utf-8")).netmask
         
    """ Generate IP addresses for servers in the Vlan """
    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(vlan_members))
    """ Generate MAC addresses 00:00:00:00:00:XX for servers in the Vlan """
    vlan_mac_addrs = [5 * '00:' + format(k, '02x') for k in random.sample(range(1, 256), len(vlan_members))]
    
    """ Find correspoinding interfaces on PTF """
    intf_facts = dut_ans.interface_facts()['ansible_facts']['ansible_interface_facts'] 
    phy_intfs = [k for k in intf_facts.keys() if k.startswith('Ethernet')]
    phy_intfs.sort(key = natural_keys)
    vlan_members.sort(key = natural_keys)
    vlan_members_index = [phy_intfs.index(intf) for intf in vlan_members]
    ptf_intfs = ['eth' + str(i) for i in vlan_members_index]
    
    ptf_hostname = testbed['ptf']
    ptf_ans = AnsibleHost(ansible_adhoc, ptf_hostname)
    
    """ Remove existing IP addresses from PTF host """ 
    ptf_ans.script('scripts/remove_ip.sh')
    
    """ Stop PFC storm at the leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE) 
        peerdev_ans.shell(cmd) 
        
    """ Clear DUT's PFC counters """
    dut_ans.sonic_pfc_counters(method = "clear")
    
    """ Disable DUT's PFC wd """
    dut_ans.shell('sudo pfcwd stop')

    time.sleep(1)
    results = dict()

    for i in range(min(max_test_count, len(ptf_intfs))):
        src_index = i
        dst_index = (i + 1) % len(ptf_intfs)
        
        src_intf = ptf_intfs[src_index]
        dst_intf = ptf_intfs[dst_index]
        
        src_ip = vlan_ip_addrs[src_index]
        dst_ip = vlan_ip_addrs[dst_index]
        
        src_mac = vlan_mac_addrs[src_index]
        dst_mac = vlan_mac_addrs[dst_index]
       
        """ DUT interface to pause """
        dut_intf_paused = vlan_members[dst_index]

        """ Configure IP and MAC on Tx and Rx interfaces of PTF """
        ptf_ans.shell('ifconfig %s down' % src_intf)
        ptf_ans.shell('ifconfig %s hw ether %s'% (src_intf, src_mac))
        ptf_ans.shell('ifconfig %s up' % src_intf)
        ptf_ans.shell('ifconfig %s %s netmask %s' % (src_intf, src_ip, vlan_subnet_mask))
        
        ptf_ans.shell('ifconfig %s down' % dst_intf)
        ptf_ans.shell('ifconfig %s hw ether %s'% (dst_intf, dst_mac))
        ptf_ans.shell('ifconfig %s up' % dst_intf)
        ptf_ans.shell('ifconfig %s %s netmask %s' % (dst_intf, dst_ip, vlan_subnet_mask))
                
        """ Clear MAC table in DUT (host memory and ASIC) """
        dut_ans.shell('sonic-clear fdb all </dev/null >/dev/null 2>&1 &')
        dut_ans.shell('sudo ip -s -s neigh flush all </dev/null >/dev/null 2>&1 &')
        time.sleep(2)
        
        """ Populate the MAC table """
        dut_ans.shell('ping -c 2 %s </dev/null >/dev/null 2>&1 &' % (src_ip))
        dut_ans.shell('ping -c 2 %s </dev/null >/dev/null 2>&1 &' % (dst_ip))
        time.sleep(2)
        
        """ Ensure the MAC table is correct """
        if not check_mac_table(dut_ans, [src_mac, dst_mac]):
            print 'MAC table of DUT is incorrect'
            continue 
                
        peer_device = conn_graph_facts['device_conn'][dut_intf_paused]['peerdevice']
        peer_port = conn_graph_facts['device_conn'][dut_intf_paused]['peerport']
        peer_port_name = eos_to_linux_intf(peer_port)
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        
        cmd = "nohup sudo python %s -i %s -g -t %d -n %d </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE_DEST, peer_port_name, pause_time, PFC_PKT_COUNT)
        
        if is_pfc:
            cmd = "nohup sudo python %s -i %s -p %d -t %d -n %d </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE_DEST, peer_port_name, 2 ** prio, pause_time, PFC_PKT_COUNT)
                
        """ Start PFC / FC storm """
        peerdev_ans.shell(cmd)
       
        """ Wait for PFC pause frame generation """
        time.sleep(2)
        
        """ Run PTF test """
        intf_info = '--interface %d@%s --interface %d@%s' % (src_index, src_intf, dst_index, dst_intf)
        test_params = 'mac_src=\'%s\';mac_dst=\'%s\';ip_src=\'%s\';ip_dst=\'%s\';dscp=%d;dscp_bg=%d;pkt_count=%d;pkt_intvl=%f;port_src=%d;port_dst=%d;queue_paused=%s' % (src_mac, dst_mac, src_ip, dst_ip, dscp, dscp_bg, PTF_PKT_COUNT, PTF_PKT_INTVL_SEC, src_index, dst_index, queue_paused)
        cmd = 'ptf --test-dir ~/ %s --test-params="%s"' % (intf_info, test_params)
        print cmd 
        stdout = ansible_stdout_to_str(ptf_ans.shell(cmd)['stdout'])
        words = stdout.split()
        
        """ 
        Expected format: "Passes: a / b" 
        where a is # of passed iterations and b is total # of iterations
        """
        if len(words) != 4:
            print 'Unknown PTF test result format'
            results[dut_intf_paused] = [0, 0]

        else:
            results[dut_intf_paused] = [int(words[1]), int(words[3])] 
        time.sleep(1)

        """ Stop PFC / FC storm """
        cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE)
        peerdev_ans.shell(cmd)
        time.sleep(1)
                
    return results


def run_test(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, prio, dscp, dscp_bg, queue_paused, is_pfc=True, pause_time=65535, max_test_count=128):
    """ 
    @Summary: Run a series of tests on a T0 topology.
    For the T0 topology, we only test Vlan (server-faced) interfaces. 
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param conn_graph_facts: Testbed topology
    @param leaf_fanouts: Leaf fanout switches
    @param prio: priority of PFC frame
    @param dscp: DSCP value of test data packets
    @param dscp_bg: DSCP value of background data packets
    @param queue_paused: if the queue is expected to be paused
    @param is_pfc: If this test is for PFC?
    @param pause_time: pause time quanta of PFC frames. It is 65535 (maximum pause time quanta) by default.
    @param max_test_count: maximum count of tests to run. By default, it is a very large value to cover all the interfaces.
    return: Return # of iterations and # of passed iterations for each test case. 
    """
    
    print testbed 
    if testbed['topo']['name'].startswith('t0'):
        return run_test_t0(ansible_adhoc=ansible_adhoc,       
                           testbed=testbed, 
                           conn_graph_facts=conn_graph_facts, leaf_fanouts=leaf_fanouts, 
                           prio=prio, 
                           dscp=dscp, 
                           dscp_bg=dscp_bg, 
                           queue_paused=queue_paused, 
                           is_pfc=is_pfc, 
                           pause_time=pause_time, 
                           max_test_count=max_test_count)
            
    else:
        return None 

def test_pfc_pause_lossless(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, lossless_prio_dscp_map):
    """ @Summary: Test if PFC pause frames can pause a lossless priority without affecting the other priorities """    
    setup_testbed(ansible_adhoc, testbed, leaf_fanouts)

    errors = []
    
    for prio in lossless_prio_dscp_map:
        """ DSCP of the other priorities """
        other_dscps = [x for x in range(64) if x not in lossless_prio_dscp_map[prio]]
        
        for dscp in lossless_prio_dscp_map[prio]:
            dscp_bg = random.choice(other_dscps)
            results = run_test(ansible_adhoc=ansible_adhoc, 
                               testbed=testbed,
                               conn_graph_facts=conn_graph_facts,
                               leaf_fanouts=leaf_fanouts, 
                               prio=prio,
                               dscp=dscp,
                               dscp_bg=dscp_bg,
                               queue_paused=True,
                               is_pfc=True,
                               pause_time=65535,
                               max_test_count=4)

            """ results should not be none """
            if results is None:
                assert 0 
            
            errors = dict()
            for intf in results:
                if len(results[intf]) != 2:
                    continue
                
                pass_count = results[intf][0]
                total_count = results[intf][1]

                if total_count == 0:
                    continue
            
                if pass_count < total_count * PTF_PASS_RATIO_THRESH:
                    errors[intf] = results[intf]

            if len(errors) > 0:
                print "errors occured:\n{}".format("\n".join(errors))
                assert 0 