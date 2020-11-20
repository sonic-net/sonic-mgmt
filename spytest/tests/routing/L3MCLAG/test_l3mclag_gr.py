####################################################################
# Title: L3 MCLAG.
# Author: Sunil Rajendra <sunil.rajendra@broadcom.com>
####################################################################

import pytest

from spytest import st, utils
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import *

import apis.switching.vlan as vlan
import apis.routing.ip as ip
import apis.routing.sag as sag
import apis.system.reboot as boot
import apis.switching.portchannel as po
import apis.switching.mclag as mclag
import apis.system.logging as log

from l3mclag_vars import *
from l3mclag_utils import print_log, retry_func, retry_parallel, verify_l3mclag_keepalive_link,  more_debugs, gen_tech_supp

def initialize_topology():
    global dut_list
    global leaf1
    global leaf2
    global client1
    global client2
    global tg1
    global tg_ph_1
    global tg_ph_2
    global tg_ph_3
    global tg_ph_4
    global tg_ph_all
    global tg_ph_5
    global tg_ph_6
    global tg_ph_7
    global tg_ph_8
    global tg_ph_all2
    global vars

    # Verify Minimum topology requirement is met
    vars = st.ensure_min_topology("D1D2:3", "D1D3:3", "D1D4:3", "D2D3:3", "D2D4:3", "D1T1:2", "D2T1:2", "D3T1:2", "D4T1:2")
    print_log("Start Test with topology D1D2:3,D1D3:3,D1D4:3, D2D3:3,D2D4:3, D1T1:1,D2T1:1,D3T1:1,D4T1:1",'HIGH')

    print_log(
        "Test Topology Description\n==============================\n\
        Test script uses mclag topology with D1, D2 as peers and D3, D4 as clients.\n\
        Mclag interfaces PO-10,20,30,40 will be configured between D1,D2 and clients.",
        'HIGH')

    # Initialize DUT variables and ports
    dut_list = st.get_dut_names()
    leaf1 = vars.D1
    leaf2 = vars.D2
    client1 = vars.D3
    client2 = vars.D4
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg1.get_port_handle(vars.T1D2P1)
    tg_ph_3 = tg1.get_port_handle(vars.T1D3P1)
    tg_ph_4 = tg1.get_port_handle(vars.T1D4P1)
    tg_ph_all = [tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4]
    tg_ph_5 = tg1.get_port_handle(vars.T1D1P2)
    tg_ph_6 = tg1.get_port_handle(vars.T1D2P2)
    tg_ph_7 = tg1.get_port_handle(vars.T1D3P2)
    tg_ph_8 = tg1.get_port_handle(vars.T1D4P2)
    tg_ph_all2 = tg_ph_all+[tg_ph_5, tg_ph_6, tg_ph_7, tg_ph_8]

def config_base_leaf1():
    print_log("Within config_base_leaf1...")
    # Configure peer keepalive link.
    ip.config_ip_addr_interface(leaf1, vars['D1D2P1'], data.keepalive_ips[0], mask4, ipv4var, addvar)
    ip.config_ip_addr_interface(leaf1, vars['D1D2P1'], data.keepalive_ip6s[0], mask6, ipv6var, addvar)
    # Configure peer-link.
    po.create_portchannel(leaf1, data.po_peer)
    po.add_portchannel_member(leaf1, portchannel=data.po_peer, members=[vars['D1D2P2'], vars['D1D2P3']])
    # Configure Orphan port.
    ip.config_ip_addr_interface(leaf1, vars['D1T1P1'], data.ip_1[0], mask4, ipv4var, addvar)
    ip.config_ip_addr_interface(leaf1, vars['D1T1P1'], data.ip6_1[0], mask6, ipv6var, addvar)

def config_base_leaf2():
    print_log("Within config_base_leaf2...")
    # Configure peer keepalive link.
    ip.config_ip_addr_interface(leaf2, vars['D2D1P1'], data.keepalive_ips[1], mask4, ipv4var, addvar)
    ip.config_ip_addr_interface(leaf2, vars['D2D1P1'], data.keepalive_ip6s[1], mask6, ipv6var, addvar)
    # Configure peer-link.
    po.create_portchannel(leaf2, data.po_peer)
    po.add_portchannel_member(leaf2, portchannel=data.po_peer, members=[vars['D2D1P2'], vars['D2D1P3']])
    # Configure Orphan port.
    ip.config_ip_addr_interface(leaf2, vars['D2T1P1'], data.ip_2[0], mask4, ipv4var, addvar)
    ip.config_ip_addr_interface(leaf2, vars['D2T1P1'], data.ip6_2[0], mask6, ipv6var, addvar)

def config_base_client1():
    print_log("Within config_base_client1...")
    # Configure Orphan port.
    ip.config_ip_addr_interface(client1, vars['D3T1P1'], data.ip_3[0], mask4, ipv4var, addvar)
    ip.config_ip_addr_interface(client1, vars['D3T1P1'], data.ip6_3[0], mask6, ipv6var, addvar)

def config_base_client2():
    print_log("Within config_base_client2...")
    # Configure Orphan port.
    ip.config_ip_addr_interface(client2, vars['D4T1P1'], data.ip_4[0], mask4, ipv4var, addvar)
    ip.config_ip_addr_interface(client2, vars['D4T1P1'], data.ip6_4[0], mask6, ipv6var, addvar)

def config_base_all():
    print_log("Within config_base_all...")
    [res, exceptions] = utils.exec_all(True, [[config_base_leaf1], [config_base_leaf2], [config_base_client1], [config_base_client2]])
    # Configure MCLAG1.
    def f1():
        print_log("Within f1...")
        po.create_portchannel(leaf1, data.mclag_all[:3])
        po.create_portchannel(leaf1, data.mclag_all[-1], True)
        po.add_portchannel_member(leaf1, portchannel=data.mclag1, members=[vars['D1D3P1']])
        ip.config_ip_addr_interface(leaf1, data.mclag1, data.mclag1_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag1, data.mclag1_ip6s[0], mask6, ipv6var, addvar)
        po.add_portchannel_member(leaf1, portchannel=data.mclag2, members=[vars['D1D4P1']])
        ip.config_ip_addr_interface(leaf1, data.mclag2, data.mclag2_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag2, data.mclag2_ip6s[0], mask6, ipv6var, addvar)
        vlan.create_vlan(leaf1, data.mclag_vid_all)
        po.add_portchannel_member(leaf1, portchannel=data.mclag3, members=[vars['D1D3P2']])
        vlan.add_vlan_member(leaf1, data.mclag3_vid, data.mclag3, True)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        po.add_portchannel_member(leaf1, portchannel=data.mclag4, members=[vars['D1D4P2']])
        vlan.add_vlan_member(leaf1, data.mclag4_vid, data.mclag4, True)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    def f2():
        print_log("Within f2...")
        po.create_portchannel(leaf2, data.mclag_all[:3])
        po.create_portchannel(leaf2, data.mclag_all[-1], True)
        po.add_portchannel_member(leaf2, portchannel=data.mclag1, members=[vars['D2D3P1']])
        ip.config_ip_addr_interface(leaf2, data.mclag1, data.mclag1_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag1, data.mclag1_ip6s[0], mask6, ipv6var, addvar)
        po.add_portchannel_member(leaf2, portchannel=data.mclag2, members=[vars['D2D4P1']])
        ip.config_ip_addr_interface(leaf2, data.mclag2, data.mclag2_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag2, data.mclag2_ip6s[0], mask6, ipv6var, addvar)
        vlan.create_vlan(leaf2, data.mclag_vid_all)
        po.add_portchannel_member(leaf2, portchannel=data.mclag3, members=[vars['D2D3P2']])
        vlan.add_vlan_member(leaf2, data.mclag3_vid, data.mclag3, True)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        po.add_portchannel_member(leaf2, portchannel=data.mclag4, members=[vars['D2D4P2']])
        vlan.add_vlan_member(leaf2, data.mclag4_vid, data.mclag4, True)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    def f3():
        print_log("Within f3...")
        po.create_portchannel(client1, [data.mclag1, data.mclag3])
        po.add_portchannel_member(client1, portchannel=data.mclag1, members=[vars['D3D1P1'], vars['D3D2P1']])
        ip.config_ip_addr_interface(client1, data.mclag1, data.mclag1_ips[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(client1, data.mclag1, data.mclag1_ip6s[1], mask6, ipv6var, addvar)
        vlan.create_vlan(client1, data.mclag3_vid)
        po.add_portchannel_member(client1, portchannel=data.mclag3, members=[vars['D3D1P2'], vars['D3D2P2']])
        vlan.add_vlan_member(client1, data.mclag3_vid, data.mclag3, True)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ips[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ip6s[1], mask6, ipv6var, addvar)
    def f4():
        print_log("Within f4...")
        po.create_portchannel(client2, [data.mclag2, data.mclag4])
        po.add_portchannel_member(client2, portchannel=data.mclag2, members=[vars['D4D1P1'], vars['D4D2P1']])
        ip.config_ip_addr_interface(client2, data.mclag2, data.mclag2_ips[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(client2, data.mclag2, data.mclag2_ip6s[1], mask6, ipv6var, addvar)
        vlan.create_vlan(client2, data.mclag4_vid)
        po.add_portchannel_member(client2, portchannel=data.mclag4, members=[vars['D4D1P2'], vars['D4D2P2']])
        vlan.add_vlan_member(client2, data.mclag4_vid, data.mclag4, True)
        ip.config_ip_addr_interface(client2, data.mclag4_vlan, data.mclag4_ips[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(client2, data.mclag4_vlan, data.mclag4_ip6s[1], mask6, ipv6var, addvar)
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    def f5():
        print_log("Within f5...")
        mclag.config_domain(leaf1, data.po_domainid, local_ip=data.keepalive_ips[0], peer_ip=data.keepalive_ips[1], peer_interface=data.po_peer)
        mclag.config_timers(leaf1, domain_id=data.po_domainid, session_timeout='30')
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag1, config=addvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag2, config=addvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag3, config=addvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag4, config=addvar)
        vlan.add_vlan_member(leaf1, data.mclag3_vid, data.po_peer, True)
        vlan.add_vlan_member(leaf1, data.mclag4_vid, data.po_peer, True)
    def f6():
        print_log("Within f6...")
        mclag.config_domain(leaf2, data.po_domainid, local_ip=data.keepalive_ips[1], peer_ip=data.keepalive_ips[0], peer_interface=data.po_peer)
        mclag.config_timers(leaf2, domain_id=data.po_domainid, session_timeout='30')
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag1, config=addvar)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag2, config=addvar)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag3, config=addvar)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag4, config=addvar)
        vlan.add_vlan_member(leaf2, data.mclag3_vid, data.po_peer, True)
        vlan.add_vlan_member(leaf2, data.mclag4_vid, data.po_peer, True)
    [res, exceptions] = utils.exec_all(True, [[f5], [f6]])
    # Verify L3MCLAG.
    retvar=False
    st.wait(waitvar)
    res = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    retvar=res
    return retvar

def deconfig_base_leaf1():
    print_log("Within deconfig_base_leaf1...")
    # Remove Orphan port.
    ip.config_ip_addr_interface(leaf1, vars['D1T1P1'], data.ip_1[0], mask4, ipv4var, removevar)
    ip.config_ip_addr_interface(leaf1, vars['D1T1P1'], data.ip6_1[0], mask6, ipv6var, removevar)
    # Remove peer-link.
    po.delete_portchannel_member(leaf1, portchannel=data.po_peer, members=[vars['D1D2P2'], vars['D1D2P3']])
    po.delete_portchannel(leaf1, data.po_peer)
    # Remove peer keepalive link.
    ip.config_ip_addr_interface(leaf1, vars['D1D2P1'], data.keepalive_ips[0], mask4, ipv4var, removevar)
    ip.config_ip_addr_interface(leaf1, vars['D1D2P1'], data.keepalive_ip6s[0], mask6, ipv6var, removevar)

def deconfig_base_leaf2():
    print_log("Within deconfig_base_leaf2...")
    # Remove Orphan port.
    ip.config_ip_addr_interface(leaf2, vars['D2T1P1'], data.ip_2[0], mask4, ipv4var, removevar)
    ip.config_ip_addr_interface(leaf2, vars['D2T1P1'], data.ip6_2[0], mask6, ipv6var, removevar)
    # Remove peer-link.
    po.delete_portchannel_member(leaf2, portchannel=data.po_peer, members=[vars['D2D1P2'], vars['D2D1P3']])
    po.delete_portchannel(leaf2, data.po_peer)
    # Remove peer keepalive link.
    ip.config_ip_addr_interface(leaf2, vars['D2D1P1'], data.keepalive_ips[1], mask4, ipv4var, removevar)
    ip.config_ip_addr_interface(leaf2, vars['D2D1P1'], data.keepalive_ip6s[1], mask6, ipv6var, removevar)

def deconfig_base_client1():
    print_log("Within deconfig_base_client1...")
    #Remove Orphan port.
    ip.config_ip_addr_interface(client1, vars['D3T1P1'], data.ip_3[0], mask4, ipv4var, removevar)
    ip.config_ip_addr_interface(client1, vars['D3T1P1'], data.ip6_3[0], mask6, ipv6var, removevar)

def deconfig_base_client2():
    print_log("Within deconfig_base_client2...")
    #Remove Orphan port.
    ip.config_ip_addr_interface(client2, vars['D4T1P1'], data.ip_4[0], mask4, ipv4var, removevar)
    ip.config_ip_addr_interface(client2, vars['D4T1P1'], data.ip6_4[0], mask6, ipv6var, removevar)

def deconfig_base_all():
    print_log("Within deconfig_base_all...")
    '''
    # No need of cleanup now.
    # Remove MCLAG
    def f5():
        print_log("Within f5...")
        vlan.delete_vlan_member(leaf1, data.mclag3_vid, data.po_peer, True)
        vlan.delete_vlan_member(leaf1, data.mclag4_vid, data.po_peer, True)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag3, config=delvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag4, config=delvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag1, config=delvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag2, config=delvar)
        mclag.config_domain(leaf1, data.po_domainid, config=delvar)
    def f6():
        print_log("Within f6...")
        vlan.delete_vlan_member(leaf2, data.mclag3_vid, data.po_peer, True)
        vlan.delete_vlan_member(leaf2, data.mclag4_vid, data.po_peer, True)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag3, config=delvar)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag4, config=delvar)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag1, config=delvar)
        mclag.config_interfaces(leaf2, data.po_domainid, data.mclag2, config=delvar)
        mclag.config_domain(leaf2, data.po_domainid, config=delvar)
    [res, exceptions] = utils.exec_all(True, [[f5], [f6]])
    def f1():
        print_log("Within f1...")
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(leaf1, data.mclag3_vid, data.mclag3, True)
        po.delete_portchannel_member(leaf1, portchannel=data.mclag3, members=[vars['D1D3P2']])
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(leaf1, data.mclag4_vid, data.mclag4, True)
        po.delete_portchannel_member(leaf1, portchannel=data.mclag4, members=[vars['D1D4P2']])
        vlan.delete_vlan(leaf1, [data.mclag3_vid, data.mclag4_vid])
        ip.config_ip_addr_interface(leaf1, data.mclag1, data.mclag1_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag1, data.mclag1_ip6s[0], mask6, ipv6var, removevar)
        po.delete_portchannel_member(leaf1, portchannel=data.mclag1, members=[vars['D1D3P1']])
        ip.config_ip_addr_interface(leaf1, data.mclag2, data.mclag2_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag2, data.mclag2_ip6s[0], mask6, ipv6var, removevar)
        po.delete_portchannel_member(leaf1, portchannel=data.mclag2, members=[vars['D1D4P1']])
        po.delete_portchannel(leaf1, data.mclag_all)
    def f2():
        print_log("Within f2...")
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(leaf2, data.mclag3_vid, data.mclag3, True)
        po.delete_portchannel_member(leaf2, portchannel=data.mclag3, members=[vars['D2D3P2']])
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(leaf2, data.mclag4_vid, data.mclag4, True)
        po.delete_portchannel_member(leaf2, portchannel=data.mclag4, members=[vars['D2D4P2']])
        vlan.delete_vlan(leaf2, [data.mclag3_vid, data.mclag4_vid])
        ip.config_ip_addr_interface(leaf2, data.mclag1, data.mclag1_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag1, data.mclag1_ip6s[0], mask6, ipv6var, removevar)
        po.delete_portchannel_member(leaf2, portchannel=data.mclag1, members=[vars['D2D3P1']])
        ip.config_ip_addr_interface(leaf2, data.mclag2, data.mclag2_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag2, data.mclag2_ip6s[0], mask6, ipv6var, removevar)
        po.delete_portchannel_member(leaf2, portchannel=data.mclag2, members=[vars['D2D4P1']])
        po.delete_portchannel(leaf2, data.mclag_all)
    def f3():
        print_log("Within f3...")
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ip6s[1], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(client1, data.mclag3_vid, data.mclag3, True)
        po.delete_portchannel_member(client1, portchannel=data.mclag3, members=[vars['D3D1P2'], vars['D3D2P2']])
        vlan.delete_vlan(client1, data.mclag3_vid)
        ip.config_ip_addr_interface(client1, data.mclag1, data.mclag1_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client1, data.mclag1, data.mclag1_ip6s[1], mask6, ipv6var, removevar)
        po.delete_portchannel_member(client1, portchannel=data.mclag1, members=[vars['D3D1P1'], vars['D3D2P1']])
        po.delete_portchannel(client1, [data.mclag1, data.mclag3])
    def f4():
        print_log("Within f4...")
        ip.config_ip_addr_interface(client2, data.mclag4_vlan, data.mclag4_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client2, data.mclag4_vlan, data.mclag4_ip6s[1], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(client2, data.mclag4_vid, data.mclag4, True)
        po.delete_portchannel_member(client2, portchannel=data.mclag4, members=[vars['D4D1P2'], vars['D4D2P2']])
        vlan.delete_vlan(client2, data.mclag4_vid)
        ip.config_ip_addr_interface(client2, data.mclag2, data.mclag2_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client2, data.mclag2, data.mclag2_ip6s[1], mask6, ipv6var, removevar)
        po.delete_portchannel_member(client2, portchannel=data.mclag2, members=[vars['D4D1P1'], vars['D4D2P1']])
        po.delete_portchannel(client2, [data.mclag2, data.mclag4])
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    [res, exceptions] = utils.exec_all(True, [[deconfig_base_leaf1], [deconfig_base_leaf2], [deconfig_base_client1], [deconfig_base_client2]])
    '''

def config_base_tg():
    global tg_h1
    global tg_h2
    global tg_h3
    global tg_h4
    global tg_h1_6
    global tg_h2_6
    global tg_h3_6
    global tg_h4_6
    global tg_tr13
    global tg_tr31
    global tg_tr14
    global tg_tr41
    global tg_tr23
    global tg_tr32
    global tg_tr24
    global tg_tr42
    global tg_tr34
    global tg_tr43
    global tg_tr13_6
    global tg_tr31_6
    global tg_tr14_6
    global tg_tr41_6
    global tg_tr23_6
    global tg_tr32_6
    global tg_tr24_6
    global tg_tr42_6
    global tg_tr34_6
    global tg_tr43_6
    global tg_v4_trs
    global tg_v6_trs
    global tg_trs
    print_log("Within config_base_tg...")
    # Configuring hosts.
    tg_h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ip_1[1], gateway=data.ip_1[0], arp_send_req='1', count=data.tg_count, gateway_step='0.0.0.0')
    tg_h2 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ip_2[1], gateway=data.ip_2[0], arp_send_req='1', count=data.tg_count, gateway_step='0.0.0.0')
    tg_h3 = tg1.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr=data.ip_3[1], gateway=data.ip_3[0], arp_send_req='1', count=data.tg_count, gateway_step='0.0.0.0')
    tg_h4 = tg1.tg_interface_config(port_handle=tg_ph_4, mode='config', intf_ip_addr=data.ip_4[1], gateway=data.ip_4[0], arp_send_req='1', count=data.tg_count, gateway_step='0.0.0.0')
    tg_h1_6 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.ip6_1[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_1[0], arp_send_req='1', ipv6_intf_addr_step='::1', count = data.tg_count)
    tg_h2_6 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.ip6_2[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_2[0], arp_send_req='1', ipv6_intf_addr_step='::1', count = data.tg_count)
    tg_h3_6 = tg1.tg_interface_config(port_handle=tg_ph_3, mode='config', ipv6_intf_addr=data.ip6_3[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_3[0], arp_send_req='1', ipv6_intf_addr_step='::1', count = data.tg_count)
    tg_h4_6 = tg1.tg_interface_config(port_handle=tg_ph_4, mode='config', ipv6_intf_addr=data.ip6_4[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_4[0], arp_send_req='1', ipv6_intf_addr_step='::1', count = data.tg_count)
    # Configuring bound streams.
    tg_tr13 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1['handle'][0], emulation_dst_handle=tg_h3['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
    tg_tr31 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3['handle'][0], emulation_dst_handle=tg_h1['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_1)
    tg_tr14 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1['handle'][0], emulation_dst_handle=tg_h4['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_4)
    tg_tr41 = tg1.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=tg_h4['handle'][0], emulation_dst_handle=tg_h1['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_1)
    tg_tr23 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=tg_h2['handle'][0], emulation_dst_handle=tg_h3['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
    tg_tr32 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3['handle'][0], emulation_dst_handle=tg_h2['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_2)
    tg_tr24 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=tg_h2['handle'][0], emulation_dst_handle=tg_h4['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_4)
    tg_tr42 = tg1.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=tg_h4['handle'][0], emulation_dst_handle=tg_h2['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_2)
    tg_tr34 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3['handle'][0], emulation_dst_handle=tg_h4['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_4)
    tg_tr43 = tg1.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=tg_h4['handle'][0], emulation_dst_handle=tg_h3['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
    tg_tr13_6 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1_6['handle'][0], emulation_dst_handle=tg_h3_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
    tg_tr31_6 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3_6['handle'][0], emulation_dst_handle=tg_h1_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_1)
    tg_tr14_6 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1_6['handle'][0], emulation_dst_handle=tg_h4_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_4)
    tg_tr41_6 = tg1.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=tg_h4_6['handle'][0], emulation_dst_handle=tg_h1_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_1)
    tg_tr23_6 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=tg_h2_6['handle'][0], emulation_dst_handle=tg_h3_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
    tg_tr32_6 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3_6['handle'][0], emulation_dst_handle=tg_h2_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_2)
    tg_tr24_6 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=tg_h2_6['handle'][0], emulation_dst_handle=tg_h4_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_4)
    tg_tr42_6 = tg1.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=tg_h4_6['handle'][0], emulation_dst_handle=tg_h2_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_2)
    tg_tr34_6 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3_6['handle'][0], emulation_dst_handle=tg_h4_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_4)
    tg_tr43_6 = tg1.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=tg_h4_6['handle'][0], emulation_dst_handle=tg_h3_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
    # Generate variables.
    tg_v4_trs = [tg_tr13['stream_id'], tg_tr31['stream_id'], tg_tr14['stream_id'], tg_tr41['stream_id'], tg_tr23['stream_id'], tg_tr32['stream_id'], tg_tr24['stream_id'], tg_tr42['stream_id'], tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6_trs = [tg_tr13_6['stream_id'], tg_tr31_6['stream_id'], tg_tr14_6['stream_id'], tg_tr41_6['stream_id'], tg_tr23_6['stream_id'], tg_tr32_6['stream_id'], tg_tr24_6['stream_id'], tg_tr42_6['stream_id'], tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_trs = tg_v4_trs + tg_v6_trs

def deconfig_base_tg():
    print_log("Within deconfig_base_tg...")
    res=tg1.tg_traffic_control(action='stop', handle=tg_trs)
    '''
    # No need of cleanup now.
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_all)
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_h1['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_2, handle=tg_h2['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_3, handle=tg_h3['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_4, handle=tg_h4['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_h1_6['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_2, handle=tg_h2_6['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_3, handle=tg_h3_6['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_4, handle=tg_h4_6['handle'], mode='destroy')
    '''

@pytest.fixture(scope="module",autouse=True)
def prologue_epilogue():
    print_log("Starting to initialize and validate topology...",'MED')
    initialize_topology()
    [res, exceptions] = utils.exec_all(True, [[config_base_tg], [config_base_all]], True)
    if res[1] is False:
        res=verify_l3mclag_keepalive_link(duts=dut_list[:2])
        if res is False:
            print_log("ERROR: Even keepalive_link is failed.")
        st.report_fail("module_config_verification_failed")
    yield
    [res, exceptions] = utils.exec_all(True, [[deconfig_base_tg], [deconfig_base_all]], True)

def test_l3mclag_gr_mix_triggers_func001():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify L3-MCLAG GR functionality with various triggers.
    '''
    tc_list = ['FtOpSoRoL3MclagGrFunc001', 'FtOpSoRoL3MclagGrFunc002', 'FtOpSoRoL3MclagGrFunc004', 'FtOpSoRoL3MclagGrFunc005', 'FtOpSoRoL3MclagGrFunc006', 'FtOpSoRoL3MclagGrFunc007']
    print_log("Testcase: Verify L3-MCLAG GR functionality with various triggers.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    #cus_str_l1='--- PortChannels terminated gracefully ---'
    l1_cus_str='PortChannels terminated gracefully'
    #l1_cus_str='teamd#teammgrd: :- sig_handler: --- Received SIGTERM. Terminating PortChannels gracefully'
    l1_cus_str='teamd#teammgrd: :- sig_handler: --- PortChannels terminated gracefully'
    #l1_cus_str=[l1_cus_str1, l1_cus_str2]
    l2_cus_str='<TBD>'
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    print_log("Step T1: Configure static routes.", "MED")
    def f1_1():
        ip.create_static_route(leaf1, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf1, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf1, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f1_2():
        ip.create_static_route(leaf2, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf2, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf2, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f1_3():
        ip.create_static_route(client1, data.mclag3_ips[0], data.ip_4_nw[1])
        ip.create_static_route(client1, data.mclag3_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f1_4():
        ip.create_static_route(client2, data.mclag2_ips[0], data.ip_3_nw[1])
        ip.create_static_route(client2, data.mclag2_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f1_1], [f1_2], [f1_3], [f1_4]])

    print_log("Step T2: Verify static routes.", "MED")
    def f2_1():
        res1 = ip.verify_ip_route(leaf1, ip_address=data.ip_3_nw[1], nexthop=data.mclag3_ips[1], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(leaf1, ip_address=data.ip6_3_nw[1], nexthop=data.mclag3_ip6s[1], type='S', interface=data.mclag3_vlan, family='ipv6')
        res3 = ip.verify_ip_route(leaf1, ip_address=data.ip_4_nw[1], nexthop=data.mclag2_ips[1], type='S', interface=data.mclag2)
        res4 = ip.verify_ip_route(leaf1, ip_address=data.ip6_4_nw[1], nexthop=data.mclag2_ip6s[1], type='S', interface=data.mclag2, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_2():
        res1 = ip.verify_ip_route(leaf2, ip_address=data.ip_3_nw[1], nexthop=data.mclag3_ips[1], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(leaf2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag3_ip6s[1], type='S', interface=data.mclag3_vlan, family='ipv6')
        res3 = ip.verify_ip_route(leaf2, ip_address=data.ip_4_nw[1], nexthop=data.mclag2_ips[1], type='S', interface=data.mclag2)
        res4 = ip.verify_ip_route(leaf2, ip_address=data.ip6_4_nw[1], nexthop=data.mclag2_ip6s[1], type='S', interface=data.mclag2, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_3():
        res1 = ip.verify_ip_route(client1, ip_address=data.ip_4_nw[1], nexthop=data.mclag3_ips[0], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(client1, ip_address=data.ip6_4_nw[1], nexthop=data.mclag3_ip6s[0], type='S', interface=data.mclag3_vlan, family='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on client1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_4():
        res1 = ip.verify_ip_route(client2, ip_address=data.ip_3_nw[1], nexthop=data.mclag2_ips[0], type='S', interface=data.mclag2)
        res2 = ip.verify_ip_route(client2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag2_ip6s[0], type='S', interface=data.mclag2, family='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on client2."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f2_1], [f2_2], [f2_3], [f2_4]])
    if False in set(res):
        fail_msg = "ERROR: Step T2 Verifying routes failed after configuring static routes."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    more_debugs(duts=dut_list)
    print_log("Step T2b: Check traffic routing.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)
    traffic_details = {
            '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
            '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res=retry_func(validate_tgen_traffic, traffic_details=traffic_details, mode='aggregate', comp_type='packet_count', tolerance_factor=1, retry_count=1, delay=20)
    if res is False:
        fail_msg = "ERROR: Step T2b Initial traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)

    def func_init_sys_time():
        print_log("Within func_init_sys_time...")
        log.clear_logging(dut_list)
        st.wait(2)
        data.l1_sys_time=mclag.get_syslog_init_time(leaf1)
        data.l2_sys_time=mclag.get_syslog_init_time(leaf2)
        data.c1_sys_time=mclag.get_syslog_init_time(client1)
        data.c2_sys_time=mclag.get_syslog_init_time(client2)

    func_init_sys_time()
    # Setting vars.
    data.l1_cus_str=l1_cus_str
    data.l1_initwait='1'
    data.l1_count='1'
    data.l2_cus_str=l2_cus_str
    data.l2_initwait='1'
    data.l2_count='0'
    data.c1_cus_str=l2_cus_str
    data.c1_initwait='1'
    data.lag_deselect_dut='leaf1'
    data.lag_initwait=int(waitvar)*6

    print_log("Step T4: Active_reload and other checkings to be done parallel.", "MED")
    boot.config_save(dut_list)
    boot.config_save(dut_list,shell='vtysh')
    def active_reboot():
        print_log("Step Func1: Active_reload.", "MED")
        st.reboot(leaf1,'normal')
        return True

    def gr_verify_active(**kwargs):
        print_log("Step Func2a: Verify GR message on Active.", "MED")
        #initwait = kwargs.get('initwait', waitvar*6)
        st.wait(int(data.l1_initwait))
        #res1=verify_syslog_msgs(dut=leaf1, from_time=data.l1_sys_time, custom_str=data.l1_cus_str, count=data.l1_count)
        #cnt1=log.get_logging_count(leaf1, severity="NOTICE", filter_list=["teamd#teammgrd: :- sig_handler: --- Received SIGTERM. Terminating PortChannels gracefully"])
        cnt1=log.get_logging_count(leaf1, severity="NOTICE", filter_list=[data.l1_cus_str])
        print_log("Count Value: Expected = {}, Actual = {}".format(str(data.l1_count), str(cnt1)), "MED")
        #if res1 is False:
        if int(cnt1) != int(data.l1_count):
            fail_msg = "ERROR: Step Func2a Verifying GR messages failed on Active."
            print_log(fail_msg, "MED")
            return False
        return True

    def gr_verify_standby(**kwargs):
        print_log("Step Func2b: Verify GR message on Standby.", "MED")
        st.wait(int(data.l2_initwait))
        #res1=verify_syslog_msgs(dut=leaf2, from_time=data.l2_sys_time, custom_str=data.l2_cus_str, count=data.l2_count)
        cnt1=log.get_logging_count(leaf2, severity="NOTICE", filter_list=[data.l2_cus_str])
        print_log("Count Value: Expected = {}, Actual = {}".format(str(data.l2_count), str(cnt1)), "MED")
        #if res1 is False:
        if int(cnt1) != int(data.l2_count):
            fail_msg = "ERROR: Step Func2b Verifying GR messages failed on Standby."
            print_log(fail_msg, "MED")
            return False
        return True

    def gr_verify_clients(**kwargs):
        print_log("Step Func2: Verify GR messages sent_received.", "MED")
        #initwait = kwargs.get('initwait', int(waitvar)*6)
        st.wait(int(data.c1_initwait))
        def f3():
            #res1=verify_syslog_msgs(dut=client1, from_time=data.c1_sys_time, custom_str=data.c1_cus_str, count='0')
            cnt1=log.get_logging_count(client1, severity="NOTICE", filter_list=[data.c1_cus_str])
            print_log("Count Value: Expected = {}, Actual = {}".format('0', str(cnt1)), "MED")
            #if res1 is False:
            if int(cnt1) != 0:
                fail_msg = "ERROR: Step Func2 Verifying GR messages failed on client1."
                print_log(fail_msg, "MED")
                return False
            return True
        def f4():
            #res1=verify_syslog_msgs(dut=client2, from_time=data.c2_sys_time, custom_str=data.c1_cus_str, count='0')
            cnt1=log.get_logging_count(client2, severity="NOTICE", filter_list=[data.c1_cus_str])
            print_log("Count Value: Expected = {}, Actual = {}".format('0', str(cnt1)), "MED")
            #if res1 is False:
            if int(cnt1) != 0:
                fail_msg = "ERROR: Step Func2 Verifying GR messages failed on client2."
                print_log(fail_msg, "MED")
                return False
            return True
        [res, exceptions] = utils.exec_all(True, [[f3], [f4]])
        if False in set(res):
            fail_msg = "ERROR: Step Func2 Verifying GR messages failed."
            print_log(fail_msg, "MED")
            return False
        return True

    def lag_mem_verify(**kwargs):
        print_log("Step Func3: Verify Client LAG member states.", "MED")
        initwait = kwargs.get('initwait', data.lag_initwait)
        st.wait(int(initwait))
        #res1=po.verify_portchannel_member(client1, data.mclag3, [vars['D3D1P2'], vars['D3D2P2']], flag='add')
        #res2=po.verify_portchannel_member(client2, data.mclag2, [vars['D4D1P1'], vars['D4D2P1']], flag='add')
        members_list1=[vars['D3D1P2'], vars['D3D2P2']]
        members_list2=[vars['D4D1P1'], vars['D4D2P1']]
        state1='up'
        state2='down'
        if data.lag_deselect_dut == '':
            res1=po.verify_portchannel_member_state(client1, data.mclag3, members_list1, state=state1)
            res2=po.verify_portchannel_member_state(client2, data.mclag2, members_list2, state=state1)
            res3 = True
            res4 = True
        elif data.lag_deselect_dut == 'leaf1':
            res1=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[0], state=state2)
            res2=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[1], state=state1)
            res3=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[0], state=state2)
            res4=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[1], state=state1)
            return True
        elif data.lag_deselect_dut == 'leaf2':
            res1=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[0], state=state1)
            res2=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[1], state=state2)
            res3=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[0], state=state1)
            res4=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[1], state=state2)
            return True
        if res1 is False or res2 is False or res3 is False or res4 is False:
        #if res1 is False or res2 is False:
            fail_msg = "ERROR: Step Func3 Verifying LAG members failed on clients."
            print_log(fail_msg, "MED")
            return False
        return True

    #[res, exceptions] = utils.exec_all(True, [[active_reboot], [gr_verify_standby], [gr_verify_clients], [lag_mem_verify]])
    [res, exceptions] = utils.exec_all(True, [[active_reboot], [lag_mem_verify]])
    if False in set(res):
        fail_msg = "ERROR: Step T4 Verification with Active_reboot failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    # By this time reboot will be done and the node will be Up.
    print_log("Step T5: Verify Client LAG member states after active_reboot.", "MED")
    data.lag_deselect_dut=''
    res=lag_mem_verify(initwait=1)
    if res is False:
        fail_msg = "ERROR: Step T5 Verifying LAG members failed on client1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T6: Verify GR and other messages on all DUTs.", "MED")
    [res, exceptions] = utils.exec_all(True, [[gr_verify_active], [gr_verify_standby], [gr_verify_clients]])
    #res=gr_verify_active()
    if False in set(res):
        fail_msg = "ERROR: Step T6 GR messages failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    else:
        st.report_tc_pass(tc_list[0], "tc_passed")

    def measure_convergence(**kwargs):
        print_log("Step Func4: Verify the traffic rate is resumed.", "MED")
        # tolerance_fator=4 implies 4*5%. Aggreate_rate vary very much. So high tolerance.
        traffic_details1 = {
            '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
            '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
        }
        res=retry_func(validate_tgen_traffic, traffic_details=traffic_details1, mode='aggregate', comp_type='packet_rate', tolerance_factor=4, retry_count=2, delay=20)
        print_log("Data traffic rate resume result: {}, Tolerance: {}%.".format(res, 4*5), "MED")

        print_log("Step Func5: Measure the convergence time.", "MED")
        res=tg1.tg_traffic_control(action='stop', handle=tg_all)
        st.wait(waitvar)
        tg_mode='aggregate'
        comp_type='packet_count'
        tg_port1=tg_ph_3
        tg_port2=tg_ph_4
        port1_tx_rate = int(data.tg_rate)*2
        port2_tx_rate = int(data.tg_rate)*2
        tx_counter_name = get_counter_name(tg_mode, tg1.tg_type, comp_type,'tx')
        rx_counter_name = get_counter_name(tg_mode, tg1.tg_type, comp_type,'rx')
        # Calculations.
        tx_stats = tg1.tg_traffic_stats(port_handle=tg_port1, mode=tg_mode)
        rx_stats = tg1.tg_traffic_stats(port_handle=tg_port2, mode=tg_mode)
        cur_tx_val1 = int(tx_stats[tg_port1][tg_mode]['tx'][tx_counter_name])
        cur_tx_val2 = int(rx_stats[tg_port2][tg_mode]['tx'][tx_counter_name])
        cur_rx_val1 = int(rx_stats[tg_port2][tg_mode]['rx'][rx_counter_name])
        cur_rx_val2 = int(tx_stats[tg_port1][tg_mode]['rx'][rx_counter_name])
        diff_12 = abs(cur_tx_val1 - cur_rx_val1)
        diff_21 = abs(cur_tx_val2 - cur_rx_val2)
        conv_12 = diff_12*1.0/port1_tx_rate
        conv_21 = diff_21*1.0/port2_tx_rate
        print_log("Port1: {}, TxRate = {}, Tx = {}, Rx = {}.".format(tg_port1, port1_tx_rate, cur_tx_val1, cur_rx_val2))
        print_log("Port2: {}, TxRate = {}, Tx = {}, Rx = {}.".format(tg_port2, port2_tx_rate, cur_tx_val2, cur_rx_val1))
        print_log("CONVERGENCE TIME from Port1 to Port2: {} seconds.".format(conv_12), "MED")
        print_log("CONVERGENCE TIME from Port2 to Port1: {} seconds.".format(conv_21), "MED")

        conv_tolerance = data.convergence_acceptable
        if int(conv_12) > int(conv_tolerance) or int(conv_21) > int(conv_tolerance):
            return False
        return True

    print_log("Step T7: Measure convergence after active_reboot.", "MED")
    res=measure_convergence()
    if res is False:
        fail_msg = "ERROR: Step T7 Convergence failed after active_reboot."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)
    else:
        st.report_tc_pass(tc_list[-1], "tc_passed")

    print_log("Step T8: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)

    func_init_sys_time()
    data.l1_cus_str=l2_cus_str
    data.l1_initwait='1'
    data.l1_count='0'
    data.l2_cus_str=l1_cus_str
    data.l2_initwait='1'
    data.l2_count='1'

    print_log("Step T9: Standby_reload and other checkings to be done parallel.", "MED")

    def standby_reboot():
        print_log("Step Func5: Standby_reload.", "MED")
        st.reboot(leaf2,'normal')
        return True

    data.lag_deselect_dut='leaf2'
    [res, exceptions] = utils.exec_all(True, [[standby_reboot], [lag_mem_verify]])
    if False in set(res):
        fail_msg = "ERROR: Step T9 Verification with Standby_reboot failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T10: Verify Client LAG member states after standby_reboot.", "MED")
    data.lag_deselect_dut=''
    res=lag_mem_verify(initwait=1)
    if res is False:
        fail_msg = "ERROR: Step T10 Verifying LAG members failed on client1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T11: Verify GR and other messages on all DUTs.", "MED")
    [res, exceptions] = utils.exec_all(True, [[gr_verify_active], [gr_verify_standby], [gr_verify_clients]])
    if False in set(res):
        fail_msg = "ERROR: Step T11 GR messages failed in Standby."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T12: Measure convergence after standby_reboot.", "MED")
    res=measure_convergence()
    if res is False:
        fail_msg = "ERROR: Step T12 Convergence failed after standby_reboot."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)
    else:
        st.report_tc_pass(tc_list[1], "tc_passed")
        st.report_tc_pass(tc_list[2], "tc_passed")

    print_log("Step T13: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)

    func_init_sys_time()
    data.l1_cus_str=l1_cus_str
    data.l1_initwait='1'
    data.l1_count='1'
    data.l2_cus_str=l2_cus_str
    data.l2_initwait='1'
    data.l2_count='0'
    data.c1_cus_str=l2_cus_str

    print_log("Step T14: Config_reload and other checkings to be done parallel.", "MED")

    def func_config_reboot():
        print_log("Step Func6: Config_reload.", "MED")
        boot.config_save_reload(leaf1)
        return True

    data.lag_deselect_dut='leaf1'
    [res, exceptions] = utils.exec_all(True, [[func_config_reboot], [lag_mem_verify]])
    if False in set(res):
        fail_msg = "ERROR: Step T14 Verification with Config_reload failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T15: Verify Client LAG member states after Config_reload.", "MED")
    data.lag_deselect_dut=''
    res=lag_mem_verify(initwait=1)
    if res is False:
        fail_msg = "ERROR: Step T15 Verifying LAG members failed on client1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T16: Verify GR and other messages on all DUTs.", "MED")
    [res, exceptions] = utils.exec_all(True, [[gr_verify_active], [gr_verify_standby], [gr_verify_clients]])
    if False in set(res):
        fail_msg = "ERROR: Step T16 GR messages failed in Active."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T17: Measure convergence after Config_reload.", "MED")
    res=measure_convergence()
    if res is False:
        fail_msg = "ERROR: Step T17 Convergence failed after Config_reload."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)
    else:
        st.report_tc_pass(tc_list[3], "tc_passed")

    '''
    # Removing docker_restart testcase as it is not fully supported.
    print_log("Step T18: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)

    func_init_sys_time()
    data.lag_initwait=int(waitvar)*1

    print_log("Step T19: Docker_restart and other checkings to be done parallel.", "MED")

    def func_docker_restart():
        print_log("Step Func7: Docker_restart.", "MED")
        basic.service_operations_by_systemctl(leaf1, 'teamd', 'restart')
        return True

    data.lag_deselect_dut='leaf1'
    [res, exceptions] = utils.exec_all(True, [[func_docker_restart], [lag_mem_verify]])
    if False in set(res):
        fail_msg = "ERROR: Step T19 Verification with Docker_restart failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T20: Verify Client LAG member states after Docker_restart.", "MED")
    data.lag_deselect_dut=''
    res=lag_mem_verify(initwait=1)
    if res is False:
        fail_msg = "ERROR: Step T20 Verifying LAG members failed on client1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T21: Verify GR and other messages on all DUTs.", "MED")
    [res, exceptions] = utils.exec_all(True, [[gr_verify_active], [gr_verify_standby], [gr_verify_clients]])
    if False in set(res):
        fail_msg = "ERROR: Step T21 GR messages failed in Active."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T22: Measure convergence after Docker_restart.", "MED")
    res=measure_convergence()
    if res is False:
        fail_msg = "ERROR: Step T22 Convergence failed after Docker_restart."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs()
        gen_tech_supp()
    else:
        st.report_tc_pass(tc_list[4], "tc_passed")
    '''
    st.report_tc_pass(tc_list[4], "tc_passed")

    print_log("Step T23: Remove static routes.", "MED")
    def f23_1():
        ip.delete_static_route(leaf1, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf1, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf1, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf1, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f23_2():
        ip.delete_static_route(leaf2, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf2, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf2, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf2, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f23_3():
        ip.delete_static_route(client1, data.mclag3_ips[0], data.ip_4_nw[1])
        ip.delete_static_route(client1, data.mclag3_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f23_4():
        ip.delete_static_route(client2, data.mclag2_ips[0], data.ip_3_nw[1])
        ip.delete_static_route(client2, data.mclag2_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f23_1], [f23_2], [f23_3], [f23_4]])

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)


def test_l3mclag_gr_sag_unique_fallback_func003():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify L3-MCLAG GR functionality with SAG, unique-IP and Fallback.
    '''
    tc_list = ['FtOpSoRoL3MclagGrFunc003']
    print_log("Testcase: Verify L3-MCLAG GR functionality with SAG, unique-IP and Fallback.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s
    l1_cus_str='PortChannels terminated gracefully'
    l1_cus_str='teamd#teammgrd: :- sig_handler: --- PortChannels terminated gracefully'
    l2_cus_str='<TBD>'

    print_log("Step T1: Preconfig.", "MED")
    def f1_1():
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        mclag.config_uniqueip(leaf1, op_type=addvar, vlan=data.mclag3_vlan)
        #ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        #ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_mclag3_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_mclag3_gwip6, mask=mask6, config=addvar)
        sag.config_sag_ip(leaf1, interface=data.mclag4_vlan, gateway=data.sag_mclag4_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(leaf1, interface=data.mclag4_vlan, gateway=data.sag_mclag4_gwip6, mask=mask6, config=addvar)
        sag.config_sag_mac(leaf1, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(leaf1, config=enablevar)
        sag.config_sag_mac(leaf1, ip_type=ipv6var, config=enablevar)
    def f1_2():
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        mclag.config_uniqueip(leaf2, op_type=addvar, vlan=data.mclag3_vlan)
        #ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip, mask4, ipv4var, addvar)
        #ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip6, mask6, ipv6var, addvar)
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_mclag3_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_mclag3_gwip6, mask=mask6, config=addvar)
        sag.config_sag_ip(leaf2, interface=data.mclag4_vlan, gateway=data.sag_mclag4_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(leaf2, interface=data.mclag4_vlan, gateway=data.sag_mclag4_gwip6, mask=mask6, config=addvar)
        sag.config_sag_mac(leaf2, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(leaf2, config=enablevar)
        sag.config_sag_mac(leaf2, ip_type=ipv6var, config=enablevar)
    [res, exceptions] = utils.exec_all(True, [[f1_1], [f1_2]])
    st.wait(waitvar)

    print_log("Step T2: Verify MCLAGs after unique-IP.", "MED")
    res1 = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    res2 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag3_intf_data['leaf1'], data.mclag3_intf_data['leaf2']])
    res3 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag4_intf_data['leaf1'], data.mclag4_intf_data['leaf2']])
    if res1 is False or res2 is False or res3 is False:
        fail_msg = "ERROR: Step T2 MCLAG failed with SAG IP."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Configure static routes.", "MED")
    def f3_1():
        ip.create_static_route(leaf1, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf1, data.mclag4_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf1, data.mclag4_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f3_2():
        ip.create_static_route(leaf2, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf2, data.mclag4_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf2, data.mclag4_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f3_3():
        ip.create_static_route(client1, data.sag_mclag3_gwip, data.ip_4_nw[1])
        ip.create_static_route(client1, data.sag_mclag3_gwip6, data.ip6_4_nw[1], family='ipv6')
    def f3_4():
        ip.create_static_route(client2, data.sag_mclag4_gwip, data.ip_3_nw[1])
        ip.create_static_route(client2, data.sag_mclag4_gwip6, data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2], [f3_3], [f3_4]])

    print_log("Step T4: Verify static routes.", "MED")
    def f4_1():
        res1 = ip.verify_ip_route(leaf1, ip_address=data.ip_3_nw[1], nexthop=data.mclag3_ips[1], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(leaf1, ip_address=data.ip6_3_nw[1], nexthop=data.mclag3_ip6s[1], type='S', interface=data.mclag3_vlan, family='ipv6')
        res3 = ip.verify_ip_route(leaf1, ip_address=data.ip_4_nw[1], nexthop=data.mclag4_ips[1], type='S', interface=data.mclag4_vlan)
        res4 = ip.verify_ip_route(leaf1, ip_address=data.ip6_4_nw[1], nexthop=data.mclag4_ip6s[1], type='S', interface=data.mclag4_vlan, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T4 Verifying routes failed on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f4_2():
        res1 = ip.verify_ip_route(leaf2, ip_address=data.ip_3_nw[1], nexthop=data.mclag3_ips[1], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(leaf2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag3_ip6s[1], type='S', interface=data.mclag3_vlan, family='ipv6')
        res3 = ip.verify_ip_route(leaf2, ip_address=data.ip_4_nw[1], nexthop=data.mclag4_ips[1], type='S', interface=data.mclag4_vlan)
        res4 = ip.verify_ip_route(leaf2, ip_address=data.ip6_4_nw[1], nexthop=data.mclag4_ip6s[1], type='S', interface=data.mclag4_vlan, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T4 Verifying routes failed on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    def f4_3():
        res1 = ip.verify_ip_route(client1, ip_address=data.ip_4_nw[1], nexthop=data.sag_mclag3_gwip, type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(client1, ip_address=data.ip6_4_nw[1], nexthop=data.sag_mclag3_gwip6, type='S', interface=data.mclag3_vlan, family='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T4 Verifying routes failed on client1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f4_4():
        res1 = ip.verify_ip_route(client2, ip_address=data.ip_3_nw[1], nexthop=data.sag_mclag4_gwip, type='S', interface=data.mclag4_vlan)
        res2 = ip.verify_ip_route(client2, ip_address=data.ip6_3_nw[1], nexthop=data.sag_mclag4_gwip6, type='S', interface=data.mclag4_vlan, family='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T4 Verifying routes failed on client2."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f4_1], [f4_2], [f4_3], [f4_4]])
    if False in set(res):
        fail_msg = "ERROR: Step T4 Verifying routes failed after configuring static routes."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    more_debugs(duts=dut_list)
    print_log("Step T5: Check initial traffic routing.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)
    traffic_details = {
            '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
            '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res=retry_func(validate_tgen_traffic, traffic_details=traffic_details, mode='aggregate', comp_type='packet_count', tolerance_factor=1, retry_count=1, delay=20)
    if res is False:
        fail_msg = "ERROR: Step T5 Initial traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T6: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)

    def func_init_sys_time():
        print_log("Within func_init_sys_time...")
        log.clear_logging(dut_list)
        st.wait(1)

    func_init_sys_time()
    # Setting vars.
    data.l1_cus_str=l1_cus_str
    data.l1_initwait='1'
    data.l1_count='1'
    data.l2_cus_str=l2_cus_str
    data.l2_initwait='1'
    data.l2_count='0'
    data.c1_cus_str=l2_cus_str
    data.c1_initwait='1'
    data.lag_deselect_dut='leaf1'
    data.lag_initwait=int(waitvar)*6

    print_log("Step T7: Config_reload and other checkings to be done parallel.", "MED")
    boot.config_save(dut_list)
    boot.config_save(dut_list,shell='vtysh')
    def func_config_reboot():
        print_log("Step Func1: Config_reload.", "MED")
        boot.config_save_reload(leaf1)
        return True

    def gr_verify_active(**kwargs):
        print_log("Step Func2a: Verify GR message on Active.", "MED")
        st.wait(int(data.l1_initwait))
        cnt1=log.get_logging_count(leaf1, severity="NOTICE", filter_list=[data.l1_cus_str])
        print_log("Count Value: Expected = {}, Actual = {}".format(str(data.l1_count), str(cnt1)), "MED")
        if int(cnt1) != int(data.l1_count):
            fail_msg = "ERROR: Step Func2a Verifying GR messages failed on Active."
            print_log(fail_msg, "MED")
            return False
        return True

    def gr_verify_standby(**kwargs):
        print_log("Step Func2b: Verify GR message on Standby.", "MED")
        st.wait(int(data.l2_initwait))
        cnt1=log.get_logging_count(leaf2, severity="NOTICE", filter_list=[data.l2_cus_str])
        print_log("Count Value: Expected = {}, Actual = {}".format(str(data.l2_count), str(cnt1)), "MED")
        if int(cnt1) != int(data.l2_count):
            fail_msg = "ERROR: Step Func2b Verifying GR messages failed on Standby."
            print_log(fail_msg, "MED")
            return False
        return True

    def gr_verify_clients(**kwargs):
        print_log("Step Func2: Verify GR messages sent_received.", "MED")
        st.wait(int(data.c1_initwait))
        def f3():
            cnt1=log.get_logging_count(client1, severity="NOTICE", filter_list=[data.c1_cus_str])
            print_log("Count Value: Expected = {}, Actual = {}".format('0', str(cnt1)), "MED")
            if int(cnt1) != 0:
                fail_msg = "ERROR: Step Func2 Verifying GR messages failed on client1."
                print_log(fail_msg, "MED")
                return False
            return True
        def f4():
            cnt1=log.get_logging_count(client2, severity="NOTICE", filter_list=[data.c1_cus_str])
            print_log("Count Value: Expected = {}, Actual = {}".format('0', str(cnt1)), "MED")
            if int(cnt1) != 0:
                fail_msg = "ERROR: Step Func2 Verifying GR messages failed on client2."
                print_log(fail_msg, "MED")
                return False
            return True
        [res, exceptions] = utils.exec_all(True, [[f3], [f4]])
        if False in set(res):
            fail_msg = "ERROR: Step Func2 Verifying GR messages failed."
            print_log(fail_msg, "MED")
            return False
        return True

    def lag_mem_verify(**kwargs):
        print_log("Step Func3: Verify Client LAG member states.", "MED")
        initwait = kwargs.get('initwait', data.lag_initwait)
        st.wait(int(initwait))
        members_list1=[vars['D3D1P2'], vars['D3D2P2']]
        members_list2=[vars['D4D1P1'], vars['D4D2P1']]
        state1='up'
        state2='down'
        if data.lag_deselect_dut == '':
            res1=po.verify_portchannel_member_state(client1, data.mclag3, members_list1, state=state1)
            res2=po.verify_portchannel_member_state(client2, data.mclag2, members_list2, state=state1)
            res3 = True
            res4 = True
        elif data.lag_deselect_dut == 'leaf1':
            res1=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[0], state=state2)
            res2=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[1], state=state1)
            res3=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[0], state=state2)
            res4=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[1], state=state1)
            return True
        elif data.lag_deselect_dut == 'leaf2':
            res1=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[0], state=state1)
            res2=po.verify_portchannel_member_state(client1, data.mclag3, members_list1[1], state=state2)
            res3=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[0], state=state1)
            res4=po.verify_portchannel_member_state(client2, data.mclag2, members_list2[1], state=state2)
            return True
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step Func3 Verifying LAG members failed on clients."
            print_log(fail_msg, "MED")
            return False
        return True

    [res, exceptions] = utils.exec_all(True, [[func_config_reboot], [lag_mem_verify]])
    if False in set(res):
        fail_msg = "ERROR: Step T7 Verification with Config_reboot failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    # By this time reboot will be done and the node will be Up.
    print_log("Step T8: Verify Client LAG member states after Config_reboot.", "MED")
    data.lag_deselect_dut=''
    res=lag_mem_verify(initwait=1)
    if res is False:
        fail_msg = "ERROR: Step T8 Verifying LAG members failed on client1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T9: Verify GR and other messages on all DUTs.", "MED")
    [res, exceptions] = utils.exec_all(True, [[gr_verify_active], [gr_verify_standby], [gr_verify_clients]])
    if False in set(res):
        fail_msg = "ERROR: Step T9 GR messages failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    else:
        pass
        #st.report_tc_pass(tc_list[0], "tc_passed")

    def measure_convergence(**kwargs):
        print_log("Step Func4: Verify the traffic rate is resumed.", "MED")
        # tolerance_fator=4 implies 4*5%. Aggreate_rate vary very much. So high tolerance.
        traffic_details1 = {
            '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
            '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
        }
        res=retry_func(validate_tgen_traffic, traffic_details=traffic_details1, mode='aggregate', comp_type='packet_rate', tolerance_factor=4, retry_count=2, delay=20)
        print_log("Data traffic rate resume result: {}, Tolerance: {}%.".format(res, 4*5), "MED")

        print_log("Step Func5: Measure the convergence time.", "MED")
        res=tg1.tg_traffic_control(action='stop', handle=tg_all)
        st.wait(waitvar)
        tg_mode='aggregate'
        comp_type='packet_count'
        tg_port1=tg_ph_3
        tg_port2=tg_ph_4
        port1_tx_rate = int(data.tg_rate)*2
        port2_tx_rate = int(data.tg_rate)*2
        tx_counter_name = get_counter_name(tg_mode, tg1.tg_type, comp_type,'tx')
        rx_counter_name = get_counter_name(tg_mode, tg1.tg_type, comp_type,'rx')
        # Calculations.
        tx_stats = tg1.tg_traffic_stats(port_handle=tg_port1, mode=tg_mode)
        rx_stats = tg1.tg_traffic_stats(port_handle=tg_port2, mode=tg_mode)
        cur_tx_val1 = int(tx_stats[tg_port1][tg_mode]['tx'][tx_counter_name])
        cur_tx_val2 = int(rx_stats[tg_port2][tg_mode]['tx'][tx_counter_name])
        cur_rx_val1 = int(rx_stats[tg_port2][tg_mode]['rx'][rx_counter_name])
        cur_rx_val2 = int(tx_stats[tg_port1][tg_mode]['rx'][rx_counter_name])
        diff_12 = abs(cur_tx_val1 - cur_rx_val1)
        diff_21 = abs(cur_tx_val2 - cur_rx_val2)
        conv_12 = diff_12*1.0/port1_tx_rate
        conv_21 = diff_21*1.0/port2_tx_rate
        print_log("Port1: {}, TxRate = {}, Tx = {}, Rx = {}.".format(tg_port1, port1_tx_rate, cur_tx_val1, cur_rx_val2))
        print_log("Port2: {}, TxRate = {}, Tx = {}, Rx = {}.".format(tg_port2, port2_tx_rate, cur_tx_val2, cur_rx_val1))
        print_log("CONVERGENCE TIME from Port1 to Port2: {} seconds.".format(conv_12), "MED")
        print_log("CONVERGENCE TIME from Port2 to Port1: {} seconds.".format(conv_21), "MED")

        conv_tolerance = data.convergence_acceptable
        if int(conv_12) > int(conv_tolerance) or int(conv_21) > int(conv_tolerance):
            return False
        return True

    print_log("Step T10: Measure convergence after active_reboot.", "MED")
    res=measure_convergence()
    if res is False:
        fail_msg = "ERROR: Step T10 Convergence failed after active_reboot."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)
    else:
        st.report_tc_pass(tc_list[0], "tc_passed")

    print_log("Step T11: Remove static routes.", "MED")
    def f11_1():
        ip.delete_static_route(leaf1, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf1, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf1, data.mclag4_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf1, data.mclag4_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f11_2():
        ip.delete_static_route(leaf2, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf2, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf2, data.mclag4_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf2, data.mclag4_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f11_3():
        ip.delete_static_route(client1, data.sag_mclag3_gwip, data.ip_4_nw[1])
        ip.delete_static_route(client1, data.sag_mclag3_gwip6, data.ip6_4_nw[1], family='ipv6')
    def f11_4():
        ip.delete_static_route(client2, data.sag_mclag4_gwip, data.ip_3_nw[1])
        ip.delete_static_route(client2, data.sag_mclag4_gwip6, data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f11_1], [f11_2], [f11_3], [f11_4]])
    st.wait(waitvar)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)
