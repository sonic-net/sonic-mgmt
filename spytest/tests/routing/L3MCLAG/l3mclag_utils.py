import re

from spytest import st
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *

import utilities.parallel as pll
import apis.common.asic_bcm as bcm
import apis.routing.ip as ip
import apis.routing.arp as arp
import apis.routing.evpn as evpn
import apis.system.interface as intf
import apis.switching.mclag as mclag
import apis.switching.mac as mac

import struct
import socket
import binascii

from l3mclag_vars import *

def print_log(message,alert_type="LOW"):
    '''
    Uses st.log procedure with some formatting to display proper log messages
    :param message: Message to be printed
    :param alert_level:
    :return:
    '''
    log_start =     "\n=====================================================\n"
    log_end =       "\n====================================================="
    log_delimiter = "\n#####################################################\n"

    if alert_type == "HIGH":
        st.log("{} {} {}".format(log_delimiter,message,log_delimiter))
    elif alert_type == "MED":
        st.log("{} {} {}".format(log_start,message,log_end))
    elif alert_type == "LOW":
        st.log(message)
    elif alert_type == "ERROR":
        st.error("{} {} {}".format(log_start,message,log_start))

def verify_ping_dut(src_dut,dest_ip_list):
    '''
    Verify ping to given list of IPs from src_dut (Detects IPV6 automatically)
    :param src_dut: dut in which ping initiated
    :param dest_ip_list: list of IPs which need to be ping
    :return:
    '''
    dest_ip_list = [dest_ip_list] if type(dest_ip_list) is str else dest_ip_list
    ver_flag = True
    for ip_addr in dest_ip_list:
        res = re.search(r'.*:.*',ip_addr)
        if res is None:
            result = ip.ping(src_dut, ip_addr)
        else:
            result = ip.ping(src_dut, ip_addr, family='ipv6')
        if not result:
            print_log("FAIL:Ping failed to {} ".format(ip_addr),'ERROR')
            ver_flag = False

    return ver_flag

def retry_parallel(func,dict_list=[],dut_list=[],retry_count=3,delay=5):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = pll.exec_parallel(True,dut_list,func,dict_list)
        if False not in result[0]:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def retry_func(func,**kwargs):
    retry_count = kwargs.get("retry_count", 10)
    delay = kwargs.get("delay", 3)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if kwargs.keys() == []:
            if func():
                return True
        else:
            if func(**kwargs):
                return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def verify_l3mclag_keepalive_link(**kwargs):
    leaf1, leaf2 = kwargs['duts']
    print_log("Within verify_l3mclag_keepalive_link...")
    def f1():
        res1 = verify_ping_dut(leaf1, data.keepalive_ips[1])
        arp.show_arp(leaf1)
        ip.show_ip_route(leaf1)
        if res1 is False:
            fail_msg = "ERROR: In Leaf1, ping to keepalive_link failed."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2():
        res1 = verify_ping_dut(leaf2, data.keepalive_ips[0])
        arp.show_arp(leaf2)
        ip.show_ip_route(leaf2)
        if res1 is False:
            fail_msg = "ERROR: In Leaf2, ping to keepalive_link failed."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    if False in set(res):
        fail_msg = "ERROR: Ping to keepalive_link failed."
        print_log(fail_msg, "MED")
        return False
    return True

def more_debugs(**kwargs):
    if not get_more_debugs_flag:
        print_log("Inside more_debugs: get_more_debugs_flag is set to False...")
        return True
    leaf1, leaf2, client1, client2 = kwargs['duts']
    print_log("MORE DEBUGS...", "MED")
    def f1():
        #intf.clear_interface_counters(leaf1)
        ip.show_ip_route(leaf1)
        arp.show_arp(leaf1)
        arp.show_ndp(leaf1)
        evpn.show_ip_neigh(leaf1)
        bcm.bcmcmd_l3_defip_show(leaf1)
        bcm.bcmcmd_l3_l3table_show(leaf1)
        bcm.bcmcmd_l3_ip6host_show(leaf1)
        bcm.bcmcmd_l3_ip6route_show(leaf1)
        bcm.read_l2(leaf1)
        bcm.bcm_cmd_l3_intf_show(leaf1)
        bcm.bcmcmd_show(leaf1,"l3 egress show")
        intf.show_interfaces_counters(leaf1)
        mac.get_mac(leaf1)
        ip.show_ip_route(leaf1, family='ipv6')
        mclag.verify_domain(leaf1, domain_id=data.po_domainid)
        mclag.verify_iccp_macs(leaf1,domain_id=data.po_domainid, return_type='NULL')
        mclag.show_iccp_arp(leaf1, domain_id=data.po_domainid)
        mclag.show_iccp_nd(leaf1, domain_id=data.po_domainid)
    def f2():
        #intf.clear_interface_counters(leaf2)
        ip.show_ip_route(leaf2)
        arp.show_arp(leaf2)
        arp.show_ndp(leaf2)
        evpn.show_ip_neigh(leaf2)
        bcm.bcmcmd_l3_defip_show(leaf2)
        bcm.bcmcmd_l3_l3table_show(leaf2)
        bcm.bcmcmd_l3_ip6host_show(leaf2)
        bcm.bcmcmd_l3_ip6route_show(leaf2)
        bcm.read_l2(leaf2)
        bcm.bcm_cmd_l3_intf_show(leaf2)
        bcm.bcmcmd_show(leaf2,"l3 egress show")
        intf.show_interfaces_counters(leaf2)
        mac.get_mac(leaf2)
        ip.show_ip_route(leaf2, family='ipv6')
        mclag.verify_domain(leaf2, domain_id=data.po_domainid)
        mclag.verify_iccp_macs(leaf2,domain_id=data.po_domainid, return_type='NULL')
        mclag.show_iccp_arp(leaf2, domain_id=data.po_domainid)
        mclag.show_iccp_nd(leaf2, domain_id=data.po_domainid)
    def f3():
        #intf.clear_interface_counters(client1)
        ip.show_ip_route(client1)
        arp.show_arp(client1)
        arp.show_ndp(client1)
        evpn.show_ip_neigh(client1)
        bcm.bcmcmd_l3_defip_show(client1)
        bcm.bcmcmd_l3_l3table_show(client1)
        bcm.bcmcmd_l3_ip6host_show(client1)
        bcm.bcmcmd_l3_ip6route_show(client1)
        bcm.read_l2(client1)
        bcm.bcm_cmd_l3_intf_show(client1)
        bcm.bcmcmd_show(client1,"l3 egress show")
        intf.show_interfaces_counters(client1)
        mac.get_mac(client1)
        ip.show_ip_route(client1, family='ipv6')
    def f4():
        #intf.clear_interface_counters(client2)
        ip.show_ip_route(client2)
        arp.show_arp(client2)
        arp.show_ndp(client2)
        evpn.show_ip_neigh(client2)
        bcm.bcmcmd_l3_defip_show(client2)
        bcm.bcmcmd_l3_l3table_show(client2)
        bcm.bcmcmd_l3_ip6host_show(client2)
        bcm.bcmcmd_l3_ip6route_show(client2)
        bcm.read_l2(client2)
        bcm.bcm_cmd_l3_intf_show(client2)
        bcm.bcmcmd_show(client2,"l3 egress show")
        intf.show_interfaces_counters(client2)
        mac.get_mac(client2)
        ip.show_ip_route(client2, family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    print_log("MORE DEBUGS END...", "MED")

def gen_tech_supp(**kwargs):
    if not gen_tech_support_flag:
        print_log("Inside gen_tech_sup: gen_tech_support_flag is set to False...")
        return True
    leaf1, leaf2, client1, client2 = kwargs['duts']
    print_log("TAKING TECH SUPPORT ON ALL DUTS...", "MED")
    f1=lambda x: st.generate_tech_support(leaf1, 'leaf1')
    f2=lambda x: st.generate_tech_support(leaf2, 'leaf2')
    f3=lambda x: st.generate_tech_support(client1, 'client1')
    f4=lambda x: st.generate_tech_support(client2, 'client2')
    [res, exceptions] = utils.exec_all(True, [[f1, 1], [f2, 1], [f3, 1], [f4, 1]])
    print_log(res,"MED")
    print_log(exceptions,"MED")
    print_log("END OF TECH SUPPORT")

def verify_rest_mclag_output(**kwargs):
        out=kwargs.get('output', {})
        val=kwargs.get('val', {})
        #print("out = {}".format(out))
        name_list=[]
        out_list=[]
        val_list=[]
        ret_val=True
        #print("val = {}".format(val))
        if 'domain_id' in val:
            name_list.append('domain_id')
            out_list.append(str(out['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['state']['domain-id']))
            val_list.append(str(val['domain_id']))
        if 'local_ip' in val:
            name_list.append('local_ip')
            out_list.append(out['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['state']['source-address'])
            val_list.append(val['local_ip'])
        if 'peer_ip' in val:
            name_list.append('peer_ip')
            out_list.append(out['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['state']['peer-address'])
            val_list.append(val['peer_ip'])
        if 'session_status' in val:
            name_list.append('session_status')
            out_list.append(out['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['state']['oper-status'])
            val1 = val['session_status']
            if val1 == 'OK':
                val1 = 'OPER_UP'
            val_list.append(val1)
        if 'peer_link_inf' in val:
            name_list.append('peer_link_inf')
            out_list.append(out['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['state']['peer-link'])
            val_list.append(val['peer_link_inf'])
        if 'node_role' in val:
            name_list.append('node_role')
            out_list.append(out['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['state']['role'])
            val1 = val['node_role']
            if val1 == 'Active':
                val1 = 'ROLE_ACTIVE'
            if val1 == 'Standby':
                val1 = 'ROLE_STANDBY'
            val_list.append(val1)
        if 'mclag_intfs' in val:
            name_list.append('mclag_intfs')
            out_list.append(len(out['output']['openconfig-mclag:mclag']['interfaces']['interface']))
            val_list.append(val['mclag_intfs'])
        # Converting interfaces_list to dictionary.
        intfs=out['output']['openconfig-mclag:mclag']['interfaces']['interface']
        num_intf=len(intfs)
        intf_d={}
        for i in range(num_intf):
            intf_name=str(intfs[i]['name'])
            intf_d[intf_name]=intfs[i]['state']
        #print("intf_d = {}".format(intf_d))
        # Checking for interface values.
        intf_val=False
        if 'mclag_intf' in val:
            name_list.append('mclag_intf')
            intf_val=intf_d.get(val['mclag_intf'], False)
            intf_val=intf_val if intf_val is False else str(intf_val['name'])
            out_list.append(intf_val)
            val_list.append(val['mclag_intf'])
        #print("intf_val = {}".format(intf_val))
        if 'mclag_intf_peer_state' in val and intf_val:
            name_list.append('mclag_intf_peer_state')
            out_list.append(intf_d[intf_val]['remote']['oper-status'])
            val1 = val['mclag_intf_peer_state']
            if val1 == 'Up':
                val1 = 'OPER_UP'
            if val1 == 'Down':
                val1 = 'OPER_DOWN'
            val_list.append(val1)
        if 'traffic_disable' in val and intf_val:
            name_list.append('traffic_disable')
            out_list.append(intf_d[intf_val]['local']['traffic-disable'])
            val1 = val['traffic_disable']
            if val1 == 'No':
                val1 = False
            if val1 == 'Yes':
                val1 = True
            val_list.append(val1)
        # Checking vlan and unique_ip.
        # Converting interfaces_list to dictionary.
        vlans_d={}
        vlans=out['output']['openconfig-mclag:mclag'].get('vlan-interfaces', False)
        if vlans:
            vlans=vlans['vlan-interface']
            num_vlans=len(vlans)
            for i in range(num_vlans):
                vlan_name=str(vlans[i]['name'])
                vlans_d[vlan_name]=vlans[i]['state']
        vlan_val=False
        if 'vlan' in val:
            name_list.append('vlan')
            vlan_val=vlans_d.get(val['vlan'], False)
            vlan_val=vlan_val if vlan_val is False else str(vlan_val['name'])
            out_list.append(vlan_val)
            val_list.append(val['vlan'])
        if 'unique_ip' in val and vlan_val:
            name_list.append('unique_ip')
            out_list.append(str(vlans_d[vlan_val]['unique-ip-enable']))
            val1 = val['unique_ip']
            if val1 == 'Yes':
                val1 = 'ENABLE'
            val_list.append(val1)
        # Bugs 21009 and 21013 are logged for missing values.
        for n,o,v in zip(name_list,out_list,val_list):
            if o==v:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(n,v,o))
                #print("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(n,v,o))
            else:
                st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(n,v,o))
                #print("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(n,v,o))
                ret_val = False
        return ret_val

def ip_to_int(ipstr):
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]

def int_to_ip(n):
    return socket.inet_ntoa(struct.pack('!I', n))

def incr_ipv4(ipaddr, mask=32, step=1):
    # To separate the mask if provided with ip.
    ipaddr,save_mask = [ipaddr, ''] if ipaddr.find('/') == -1 else ipaddr.split('/')
    ip_int = ip_to_int(ipaddr)
    # Saving the diff value.
    ip_int_old = ip_int
    ip_int >>= 32 - mask
    ip_int <<= 32 - mask
    ip_diff = ip_int_old - ip_int
    # Actual logic.
    ip_int >>= 32 - mask
    ip_int += step
    ip_int <<= 32 - mask
    ip_int += ip_diff
    ipaddr = int_to_ip(ip_int)
    ipaddr = '/'.join([ipaddr,save_mask]) if save_mask != '' else ipaddr
    return ipaddr

def range_ipv4(start_ip, count, mask=32):
    ip_list = []
    count = int(count)
    mask = int(mask)
    for i in range(count):
        ip_list.append(start_ip)
        start_ip = incr_ipv4(start_ip, mask)

    return ip_list

def network(ipaddr, mask=24):
    ip_int = ip_to_int(ipaddr)
    ip_int >>= 32 - mask
    ip_int <<= 32 - mask
    return int_to_ip(ip_int)

def ipv6_to_int(ipv6_addr):
    return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ipv6_addr)), 16)

def int_to_ipv6(i):
    return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex(i)[2:][:-1]))

def incr_ipv6(ipaddr, mask=128, step=1):
    # To separate the mask if provided with ipv6.
    ipaddr,save_mask = [ipaddr, ''] if ipaddr.find('/') == -1 else ipaddr.split('/')
    ip_int = ipv6_to_int(ipaddr)
    # Saving the diff value.
    ip_int_old = ip_int
    ip_int >>= 128 - mask
    ip_int <<= 128 - mask
    ip_diff = ip_int_old - ip_int
    # Actual logic.
    ip_int >>= 128 - mask
    ip_int += step
    ip_int <<= 128 - mask
    ip_int += ip_diff
    ipaddr = int_to_ipv6(ip_int)
    ipaddr = '/'.join([ipaddr,save_mask]) if save_mask != '' else ipaddr
    return ipaddr

def range_ipv6(start_ip, count, mask=128):
    ip_list = []
    count = int(count)
    mask = int(mask)
    for i in range(count):
        ip_list.append(start_ip)
        start_ip = incr_ipv6(start_ip, mask)
    return ip_list

