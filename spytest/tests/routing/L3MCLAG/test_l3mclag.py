####################################################################
# Title: L3 MCLAG.
# Author: Sunil Rajendra <sunil.rajendra@broadcom.com>
####################################################################

import pytest

from spytest import st
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *

import apis.switching.vlan as vlan
import apis.routing.ip as ip
import apis.routing.sag as sag
import apis.system.interface as intf
import apis.system.port as port
import apis.system.reboot as boot
import apis.switching.portchannel as po
import apis.switching.mclag as mclag
import apis.routing.arp as arp
import apis.routing.vrf as vrf
#import apis.switching.pvst as pvst
import apis.system.basic as basic
import apis.routing.bgp as bgp
from apis.routing import ip_bgp
from apis.routing import vrrp
from utilities.utils import retry_api
from utilities.rest import retry_rest_api

from l3mclag_utils import *

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
        po.create_portchannel(leaf1, data.mclag_all)
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
        po.create_portchannel(leaf2, data.mclag_all)
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
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag1, config=addvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag2, config=addvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag3, config=addvar)
        mclag.config_interfaces(leaf1, data.po_domainid, data.mclag4, config=addvar)
        vlan.add_vlan_member(leaf1, data.mclag3_vid, data.po_peer, True)
        vlan.add_vlan_member(leaf1, data.mclag4_vid, data.po_peer, True)
    def f6():
        print_log("Within f6...")
        mclag.config_domain(leaf2, data.po_domainid, local_ip=data.keepalive_ips[1], peer_ip=data.keepalive_ips[0], peer_interface=data.po_peer)
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
    #res=tg1.tg_traffic_control(action='stop', handle=tg_trs)
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_all)
    '''
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

def test_l3mclag_func001():
    '''
    Bring up L3-MCLAG interface and ping.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagFunc001', 'FtOpSoRoL3MclagFunc002', 'FtOpSoRoL3MclagFunc003']
    print_log("Testcase: Bring up L3-MCLAG interface and ping.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''

    print_log("Step T1: ping ipv4.", "MED")
    res1 = verify_ping_dut(client1, data.mclag1_ips[0])
    res2 = verify_ping_dut(client1, data.mclag3_ips[0])
    print_log("Step T1b: ping ipv6.", "MED")
    res3 = verify_ping_dut(client1, data.mclag1_ip6s[0])
    res4 = verify_ping_dut(client1, data.mclag3_ip6s[0])
    if res1 is False or res2 is False or res3 is False or res4 is False:
        fail_msg = "ERROR: Step T1 ping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T2: Verify ARP.", "MED")
    res1 = arp.verify_arp(client1, data.mclag1_ips[0])
    res2 = arp.verify_arp(client1, data.mclag3_ips[0])
    print_log("Step T2b: Verify ND.", "MED")
    res3 = arp.verify_ndp(client1, data.mclag1_ip6s[0])
    res4 = arp.verify_ndp(client1, data.mclag3_ip6s[0])
    if res1 is False or res2 is False or res3 is False or res4 is False:
        fail_msg = "ERROR: Step T2 ARP_ND failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Clear ARP and ND.", "MED")
    arp.clear_arp_table(client1)
    arp.clear_ndp_table(client1)
    st.wait(waitvar)
    #res1 = arp.verify_arp(client1)
    res1 = arp.verify_arp(client1, data.mclag1_ips[0])
    res2 = arp.verify_ndp(client1, data.mclag1_ip6s[0])
    res3 = arp.verify_arp(client1, data.mclag3_ips[0])
    res4 = arp.verify_ndp(client1, data.mclag3_ip6s[0])
    if res1 is not False and res2 is not False and res3 is not False and res4 is not False:
        fail_msg = "ERROR: Step T3 clear ARP_ND failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T4: ping ipv4 and ipv6 again and verify ARP_ND.", "MED")
    res1 = verify_ping_dut(client1, data.mclag1_ips[0])
    res2 = verify_ping_dut(client1, data.mclag1_ip6s[0])
    res3 = verify_ping_dut(client1, data.mclag3_ips[0])
    res4 = verify_ping_dut(client1, data.mclag3_ip6s[0])
    if res1 is False or res2 is False or res3 is False or res4 is False:
        fail_msg = "ERROR: Step T4 ping failed after clear ARP."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    st.wait(waitvar)
    res1 = arp.verify_arp(client1, data.mclag1_ips[0], interface=data.mclag1)
    res2 = arp.verify_ndp(client1, data.mclag1_ip6s[0], interface=data.mclag1)
    res3 = arp.verify_arp(client1, data.mclag3_ips[0], interface=data.mclag3)
    # There is issue with this API. If intf is part of vlan, no output is seen.
    # And with interface='vlan30', output line is not matched properly.
    # Both 'interface' and 'vlan' cannot be send together.
    #res4 = arp.verify_ndp(client1, data.mclag3_ip6s[0], vlan=data.mclag3_vid, interface=data.mclag3_vlan)
    res4 = arp.verify_ndp(client1, data.mclag3_ip6s[0], vlan=data.mclag3_vid)
    if res1 is False or res2 is False or res3 is False or res4 is False:
        fail_msg = "ERROR: Step T4 relearn ARP_ND failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T5: Verify ARP_ND present in both leaf1 and leaf2.", "MED")
    def f1():
        res1 = arp.verify_arp(leaf1, data.mclag1_ips[1], interface=data.mclag1)
        res2 = arp.verify_ndp(leaf1, data.mclag1_ip6s[1], interface=data.mclag1)
        res3 = arp.verify_arp(leaf1, data.mclag3_ips[1], interface=data.mclag3)
        res4 = arp.verify_ndp(leaf1, data.mclag3_ip6s[1], vlan=data.mclag3_vid)
        if (res1 is False or res2 is False) or (res3 is False or res4 is False):
            fail_msg = "ERROR: Step T5 ARP_ND on leaf1 failed."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2():
        res1 = arp.verify_arp(leaf2, data.mclag1_ips[1], interface=data.mclag1)
        res2 = arp.verify_ndp(leaf2, data.mclag1_ip6s[1], interface=data.mclag1)
        res3 = arp.verify_arp(leaf2, data.mclag3_ips[1], interface=data.mclag3)
        res4 = arp.verify_ndp(leaf2, data.mclag3_ip6s[1], vlan=data.mclag3_vid)
        if (res1 is False or res2 is False) or (res3 is False or res4 is False):
            fail_msg = "ERROR: Step T5 ARP_ND on leaf2 failed."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    if False in set(res):
        fail_msg = "ERROR: Step T5 ARP_ND after ping."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T6: Toggle the MCLAG links.", "MED")
    f1=lambda x: intf.interface_shutdown(client1, [vars['D3D1P1'], vars['D3D2P1'], vars['D3D1P2'], vars['D3D2P2']])
    f2=lambda x: intf.interface_shutdown(leaf1, [vars['D1D2P1'], vars['D1D2P2'], vars['D1D2P3']])
    [res, exceptions] = utils.exec_all(True, [[f1, 1], [f2, 1]])
    st.wait(3)
    f1=lambda x: intf.interface_noshutdown(client1, [vars['D3D1P1'], vars['D3D2P1'], vars['D3D1P2'], vars['D3D2P2']])
    f2=lambda x: intf.interface_noshutdown(leaf1, [vars['D1D2P1'], vars['D1D2P2'], vars['D1D2P3']])
    [res, exceptions] = utils.exec_all(True, [[f1, 1], [f2, 1]])
    st.wait(waitvar)

    print_log("Step T7: Verify MCLAG after toggling.", "MED")
    res1 = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    res2 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag1_intf_data['leaf1'], data.mclag1_intf_data['leaf2']])
    if res1 is False or res2 is False:
        fail_msg = "ERROR: Step T7 MCLAG failed after toggling links."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_func004():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify L3-MCLAG with data traffic.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagFunc004', 'FtOpSoRoL3MclagFunc005']
    print_log("Testcase: Verify L3-MCLAG with data traffic.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr13['stream_id'], tg_tr31['stream_id'], tg_tr23['stream_id'], tg_tr32['stream_id']]
    tg_v6s = [tg_tr13_6['stream_id'], tg_tr31_6['stream_id'], tg_tr23_6['stream_id'], tg_tr32_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    print_log("Step T1: Configure static routes.", "MED")
    def f1_1():
        ip.create_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f1_2():
        ip.create_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f1_3():
        ip.create_static_route(client1, data.mclag1_ips[0], data.ip_1_nw[1])
        ip.create_static_route(client1, data.mclag1_ips[0], data.ip_2_nw[1])
        ip.create_static_route(client1, data.mclag1_ip6s[0], data.ip6_1_nw[1], family='ipv6')
        ip.create_static_route(client1, data.mclag1_ip6s[0], data.ip6_2_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f1_1], [f1_2], [f1_3]])
    st.wait(waitvar)

    print_log("Step T2: Verify static routes.", "MED")
    def f2_1():
        res1 = ip.verify_ip_route(leaf1, ip_address=data.ip_3_nw[1], nexthop=data.mclag1_ips[1], type='S', interface=data.mclag1)
        res2 = ip.verify_ip_route(leaf1, ip_address=data.ip6_3_nw[1], nexthop=data.mclag1_ip6s[1], type='S', interface=data.mclag1, family='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_2():
        res1 = ip.verify_ip_route(leaf2, ip_address=data.ip_3_nw[1], nexthop=data.mclag1_ips[1], type='S', interface=data.mclag1)
        res2 = ip.verify_ip_route(leaf2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag1_ip6s[1], type='S', interface=data.mclag1, family='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_3():
        res1 = ip.verify_ip_route(client1, ip_address=data.ip_1_nw[1], nexthop=data.mclag1_ips[0], type='S', interface=data.mclag1)
        res2 = ip.verify_ip_route(client1, ip_address=data.ip_2_nw[1], nexthop=data.mclag1_ips[0], type='S', interface=data.mclag1)
        res3 = ip.verify_ip_route(client1, ip_address=data.ip6_1_nw[1], nexthop=data.mclag1_ip6s[0], type='S', interface=data.mclag1, family='ipv6')
        res4 = ip.verify_ip_route(client1, ip_address=data.ip6_2_nw[1], nexthop=data.mclag1_ip6s[0], type='S', interface=data.mclag1, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on client1."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f2_1], [f2_2], [f2_3]])
    if False in set(res):
        fail_msg = "ERROR: Step T2 Verifying routes failed after configuring static routes."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T4: Verify data traffic routing.", "MED")
    # exp_ratio is 0.5 for few due to ECMP and limitation with direct IP on MCLAG.
    traffic_details1 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[4]]]},
        '2':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0.5], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[5]]]},
        '3':{'tx_ports':[vars.T1D2P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[2], tg_all[6]]]},
        '4':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0.5], 'rx_ports':[vars.T1D2P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[3], tg_all[7]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T4 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T5: Shutdown one MCLAG member.", "MED")
    intf.interface_shutdown(client1, [vars['D3D1P1']])
    st.wait(waitvar)

    print_log("Step T6: Start traffic streams again.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)

    print_log("Step T7: Verify data traffic is dropped appropriately.", "MED")
    traffic_details2 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[4]]]},
        '2':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[5]]]},
        '3':{'tx_ports':[vars.T1D2P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[2], tg_all[6]]]},
        '4':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D2P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[3], tg_all[7]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details2, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T7 Data traffic dropping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T8: no-shut MCLAG member.", "MED")
    intf.interface_noshutdown(client1, [vars['D3D1P1']])
    st.wait(waitvar*4)

    print_log("Step T9: Verify data traffic is resumed.", "MED")
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T9 Data traffic resuming failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T10: Remove static routes.", "MED")
    def f10_1():
        ip.delete_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f10_2():
        ip.delete_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f10_3():
        ip.delete_static_route(client1, data.mclag1_ips[0], data.ip_1_nw[1])
        ip.delete_static_route(client1, data.mclag1_ips[0], data.ip_2_nw[1])
        ip.delete_static_route(client1, data.mclag1_ip6s[0], data.ip6_1_nw[1], family='ipv6')
        ip.delete_static_route(client1, data.mclag1_ip6s[0], data.ip6_2_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f10_1], [f10_2], [f10_3]])
    st.wait(waitvar)

    print_log("Step T11: Verify data traffic is dropped.", "MED")
    traffic_details3 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[4]]]},
        '2':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[5]]]},
        '3':{'tx_ports':[vars.T1D2P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[2], tg_all[6]]]},
        '4':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D2P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[3], tg_all[7]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details3, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T11 Data traffic dropping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T12: Ending steps.", "MED")
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_func006():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify traffic between 2 L3-MCLAGs.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagFunc006', 'FtOpSoRoL3MclagFunc009', 'FtOpSoRoL3MclagFunc011']
    print_log("Testcase: Verify traffic between 2 L3-MCLAGs.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    print_log("Step T1: Configure static routes.", "MED")
    def f1():
        ip.create_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf1, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf1, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f2():
        ip.create_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf2, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf2, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f3():
        ip.create_static_route(client1, data.mclag1_ips[0], data.ip_4_nw[1])
        ip.create_static_route(client1, data.mclag1_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f4():
        ip.create_static_route(client2, data.mclag2_ips[0], data.ip_3_nw[1])
        ip.create_static_route(client2, data.mclag2_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    st.wait(waitvar)

    print_log("Step T2: Verify static routes.", "MED")
    def f2_1():
        res1 = ip.verify_ip_route(leaf1, ip_address=data.ip_3_nw[1], nexthop=data.mclag1_ips[1], type='S', interface=data.mclag1)
        res2 = ip.verify_ip_route(leaf1, ip_address=data.ip6_3_nw[1], nexthop=data.mclag1_ip6s[1], type='S', interface=data.mclag1, family='ipv6')
        res3 = ip.verify_ip_route(leaf1, ip_address=data.ip_4_nw[1], nexthop=data.mclag2_ips[1], type='S', interface=data.mclag2)
        res4 = ip.verify_ip_route(leaf1, ip_address=data.ip6_4_nw[1], nexthop=data.mclag2_ip6s[1], type='S', interface=data.mclag2, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_2():
        res1 = ip.verify_ip_route(leaf2, ip_address=data.ip_3_nw[1], nexthop=data.mclag1_ips[1], type='S', interface=data.mclag1)
        res2 = ip.verify_ip_route(leaf2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag1_ip6s[1], type='S', interface=data.mclag1, family='ipv6')
        res3 = ip.verify_ip_route(leaf2, ip_address=data.ip_4_nw[1], nexthop=data.mclag2_ips[1], type='S', interface=data.mclag2)
        res4 = ip.verify_ip_route(leaf2, ip_address=data.ip6_4_nw[1], nexthop=data.mclag2_ip6s[1], type='S', interface=data.mclag2, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_3():
        res1 = ip.verify_ip_route(client1, ip_address=data.ip_4_nw[1], nexthop=data.mclag1_ips[0], type='S', interface=data.mclag1)
        res2 = ip.verify_ip_route(client1, ip_address=data.ip6_4_nw[1], nexthop=data.mclag1_ip6s[0], type='S', interface=data.mclag1, family='ipv6')
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

    print_log("Step T3: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T4: Verify data traffic routing.", "MED")
    traffic_details1 = {
        '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
        '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T4 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)

    print_log("Step T5: Verify ECMP.", "MED")
    #Bug in below API. Not taking values like '5,123'. Hence commenting.
    #counters = {"module_type": "mirror", "source": [data.mclag1, "rx_ok"], "destination": [data.mclag2, "tx_ok"]}
    #res=intf.verify_interface_counters(leaf1, counters)
    out1 = intf.show_interface_counters_all(leaf1)
    out2 = intf.show_interface_counters_all(leaf2)

    print_log("Step T6: Shutdown MCLAG members.", "MED")
    intf.interface_shutdown(leaf1, [vars['D1D3P1'], vars['D1D4P1']])
    st.wait(waitvar)

    print_log("Step T7: Start traffic streams again.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)

    print_log("Step T8: Verify data traffic converges appropriately.", "MED")
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T8 Data traffic dropping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)

    print_log("Step T9: no-shut MCLAG members.", "MED")
    intf.interface_noshutdown(leaf1, [vars['D1D3P1'], vars['D1D4P1']])
    st.wait(waitvar*4)

    print_log("Step T10: Verify data traffic is resumed.", "MED")
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T10 Data traffic resuming failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T11: Remove static routes.", "MED")
    def f11_1():
        ip.delete_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf1, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf1, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f11_2():
        ip.delete_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf2, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf2, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f11_3():
        ip.delete_static_route(client1, data.mclag1_ips[0], data.ip_4_nw[1])
        ip.delete_static_route(client1, data.mclag1_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f11_4():
        ip.delete_static_route(client2, data.mclag2_ips[0], data.ip_3_nw[1])
        ip.delete_static_route(client2, data.mclag2_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f11_1], [f11_2], [f11_3], [f11_4]])
    st.wait(waitvar)

    print_log("Step T12: Verify data traffic is dropped.", "MED")
    traffic_details3 = {
        '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
        '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details3, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T12 Data traffic dropping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T13: Ending steps.", "MED")
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_func007():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify traffic with Ve over L2-MCLAGs.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagFunc007', 'FtOpSoRoL3MclagFunc008', 'FtOpSoRoL3MclagFunc010']
    print_log("Testcase: Verify traffic with Ve over L2-MCLAGs.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    print_log("Step T1: Configure static routes.", "MED")
    def f1():
        ip.create_static_route(leaf1, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf1, data.mclag4_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf1, data.mclag4_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f2():
        ip.create_static_route(leaf2, data.mclag3_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag3_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf2, data.mclag4_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf2, data.mclag4_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f3():
        ip.create_static_route(client1, data.mclag3_ips[0], data.ip_4_nw[1])
        ip.create_static_route(client1, data.mclag3_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f4():
        ip.create_static_route(client2, data.mclag4_ips[0], data.ip_3_nw[1])
        ip.create_static_route(client2, data.mclag4_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])

    print_log("Step T2: Verify static routes.", "MED")
    def f2_1():
        res1 = ip.verify_ip_route(leaf1, ip_address=data.ip_3_nw[1], nexthop=data.mclag3_ips[1], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(leaf1, ip_address=data.ip6_3_nw[1], nexthop=data.mclag3_ip6s[1], type='S', interface=data.mclag3_vlan, family='ipv6')
        res3 = ip.verify_ip_route(leaf1, ip_address=data.ip_4_nw[1], nexthop=data.mclag4_ips[1], type='S', interface=data.mclag4_vlan)
        res4 = ip.verify_ip_route(leaf1, ip_address=data.ip6_4_nw[1], nexthop=data.mclag4_ip6s[1], type='S', interface=data.mclag4_vlan, family='ipv6')
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T2 Verifying routes failed on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2_2():
        res1 = ip.verify_ip_route(leaf2, ip_address=data.ip_3_nw[1], nexthop=data.mclag3_ips[1], type='S', interface=data.mclag3_vlan)
        res2 = ip.verify_ip_route(leaf2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag3_ip6s[1], type='S', interface=data.mclag3_vlan, family='ipv6')
        res3 = ip.verify_ip_route(leaf2, ip_address=data.ip_4_nw[1], nexthop=data.mclag4_ips[1], type='S', interface=data.mclag4_vlan)
        res4 = ip.verify_ip_route(leaf2, ip_address=data.ip6_4_nw[1], nexthop=data.mclag4_ip6s[1], type='S', interface=data.mclag4_vlan, family='ipv6')
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
        res1 = ip.verify_ip_route(client2, ip_address=data.ip_3_nw[1], nexthop=data.mclag4_ips[0], type='S', interface=data.mclag4_vlan)
        res2 = ip.verify_ip_route(client2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag4_ip6s[0], type='S', interface=data.mclag4_vlan, family='ipv6')
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

    print_log("Step T3: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T4: Verify data traffic routing.", "MED")
    traffic_details1 = {
        '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
        '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T4 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T5: Verify ECMP.", "MED")
    #Bug in below API. Not taking values like '5,123'. Hence commenting.
    #counters = {"module_type": "mirror", "source": [data.mclag3, "rx_ok"], "destination": [data.mclag4, "tx_ok"]}
    #res=intf.verify_interface_counters(leaf1, counters)
    out1 = intf.show_interface_counters_all(leaf1)
    out2 = intf.show_interface_counters_all(leaf2)

    print_log("Step T6: Shutdown MCLAG members.", "MED")
    intf.interface_shutdown(leaf2, [vars['D2D3P2'], vars['D2D4P2']])
    st.wait(waitvar)

    print_log("Step T7: Start traffic streams again.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)

    print_log("Step T8: Verify data traffic converges appropriately.", "MED")
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T8 Data traffic dropping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T9: no-shut MCLAG members.", "MED")
    intf.interface_noshutdown(leaf2, [vars['D2D3P2'], vars['D2D4P2']])
    st.wait(waitvar*4)

    print_log("Step T10: Verify data traffic is resumed.", "MED")
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T10 Data traffic resuming failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

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
        ip.delete_static_route(client1, data.mclag3_ips[0], data.ip_4_nw[1])
        ip.delete_static_route(client1, data.mclag3_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f11_4():
        ip.delete_static_route(client2, data.mclag4_ips[0], data.ip_3_nw[1])
        ip.delete_static_route(client2, data.mclag4_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f11_1], [f11_2], [f11_3], [f11_4]])
    st.wait(waitvar)

    print_log("Step T12: Verify data traffic is dropped.", "MED")
    traffic_details3 = {
        '1':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D4P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
        '2':{'tx_ports':[vars.T1D4P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details3, mode='streamblock', comp_type='packet_rate')
    if res is False:
        fail_msg = "ERROR: Step T12 Data traffic dropping failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T13: Ending steps.", "MED")
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_func012():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify ping over unique-IP.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagFunc012', 'FtOpSoRoL3MclagFunc013', 'FtOpSoRoL3MclagFunc014', 'FtOpSoRoL3MclagFunc016', 'FtOpSoRoL3MclagFunc017', 'FtOpSoRoL3MclagFunc018']
    print_log("Testcase: Verify ping over unique-IP.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    print_log("Step T1: Preconfig.", "MED")
    def f1():
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        mclag.config_uniqueip(leaf1, op_type=addvar, vlan=data.mclag3_vlan)
        mclag.config_uniqueip(leaf1, op_type=addvar, vlan=data.mclag4_vlan)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    def f2():
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        mclag.config_uniqueip(leaf2, op_type=addvar, vlan=data.mclag3_vlan)
        mclag.config_uniqueip(leaf2, op_type=addvar, vlan=data.mclag4_vlan)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip, mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip6, mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip, mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip6, mask6, ipv6var, addvar)
    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    st.wait(waitvar)

    print_log("Step T2: Verify MCLAGs after unique-IP.", "MED")
    res1 = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    res2 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag1_intf_data['leaf1'], data.mclag1_intf_data['leaf2']])
    if res1 is False or res2 is False:
        fail_msg = "ERROR: Step T2 MCLAG failed with unique-IP."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Verify pings from all MCLAG points.", "MED")
    def f3_1():
        res1 = verify_ping_dut(leaf1, data.mclag3_uip)
        res2 = verify_ping_dut(leaf1, data.mclag3_ips[1])
        res3 = verify_ping_dut(leaf1, data.mclag3_uip6)
        res4 = verify_ping_dut(leaf1, data.mclag3_ip6s[1])
        res5 = verify_ping_dut(leaf1, data.mclag4_uip)
        res6 = verify_ping_dut(leaf1, data.mclag4_ips[1])
        res7 = verify_ping_dut(leaf1, data.mclag4_uip6)
        res8 = verify_ping_dut(leaf1, data.mclag4_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False or res7 is False or res8 is False:
            fail_msg = "ERROR: Step T3 Ping from leaf1 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_2():
        res1 = verify_ping_dut(leaf2, data.mclag3_ips[0])
        res2 = verify_ping_dut(leaf2, data.mclag3_ips[1])
        res3 = verify_ping_dut(leaf2, data.mclag3_ip6s[0])
        res4 = verify_ping_dut(leaf2, data.mclag3_ip6s[1])
        res5 = verify_ping_dut(leaf2, data.mclag4_ips[0])
        res6 = verify_ping_dut(leaf2, data.mclag4_ips[1])
        res7 = verify_ping_dut(leaf2, data.mclag4_ip6s[0])
        res8 = verify_ping_dut(leaf2, data.mclag4_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False or res7 is False or res8 is False:
            fail_msg = "ERROR: Step T3 Ping from leaf2 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_3():
        res1 = verify_ping_dut(client1, data.mclag3_uip)
        res2 = verify_ping_dut(client1, data.mclag3_ips[0])
        res3 = verify_ping_dut(client1, data.mclag3_uip6)
        res4 = verify_ping_dut(client1, data.mclag3_ip6s[0])
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T3 Ping from client1 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_4():
        res1 = verify_ping_dut(client2, data.mclag4_uip)
        res2 = verify_ping_dut(client2, data.mclag4_ips[0])
        res3 = verify_ping_dut(client2, data.mclag4_uip6)
        res4 = verify_ping_dut(client2, data.mclag4_ip6s[0])
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T3 Ping from client2 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2], [f3_3], [f3_4]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 Ping failed in unique_IP scenario."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T4: Configure VRRP over MCLAG.", "MED")
    f1 = lambda x: vrrp.configure_vrrp(leaf1, vrid=data.vrrp_vrid, vip=data.vrrp_vip, interface=data.mclag3_vlan, priority=data.vrrp_pri_m, config=yesvar, enable='')
    f2 = lambda x: vrrp.configure_vrrp(leaf2, vrid=data.vrrp_vrid, vip=data.vrrp_vip, interface=data.mclag3_vlan, priority=data.vrrp_pri_b, config=yesvar, enable='')
    [res, exceptions] = utils.exec_all(True, [[f1, 1], [f2, 1]])
    st.wait(waitvar*2)

    print_log("Step T5: Verify VRRP over MCLAG.", "MED")
    def f5_1():
        res=vrrp.verify_vrrp(leaf1, state=data.vrrp_m_var, vrid=data.vrrp_vrid, interface=data.mclag3_vlan, current_prio=data.vrrp_pri_m)
        if res is False:
            fail_msg = "ERROR: Step T5 VRRP over MCLAG failed on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f5_2():
        res=vrrp.verify_vrrp(leaf2, state=data.vrrp_b_var, vrid=data.vrrp_vrid, interface=data.mclag3_vlan, current_prio=data.vrrp_pri_b)
        if res is False:
            fail_msg = "ERROR: Step T5 VRRP over MCLAG failed on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f5_1], [f5_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T5 VRRP over MCLAG failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T6: Remove VRRP.", "MED")
    f1 = lambda x: vrrp.configure_vrrp(leaf1, vrid=data.vrrp_vrid, interface=data.mclag3_vlan, config=novar, disable='')
    f2 = lambda x: vrrp.configure_vrrp(leaf2, vrid=data.vrrp_vrid, interface=data.mclag3_vlan, config=novar, disable='')
    [res, exceptions] = utils.exec_all(True, [[f1, 1], [f2, 1]])
    st.wait(waitvar)

    print_log("Step T10: Restore config.", "MED")
    def f10_1():
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        mclag.config_uniqueip(leaf1, op_type=delvar, vlan=data.mclag3_vlan)
        mclag.config_uniqueip(leaf1, op_type=delvar, vlan=data.mclag4_vlan)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    def f10_2():
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip, mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip6, mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip, mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip6, mask6, ipv6var, removevar)
        mclag.config_uniqueip(leaf2, op_type=delvar, vlan=data.mclag3_vlan)
        mclag.config_uniqueip(leaf2, op_type=delvar, vlan=data.mclag4_vlan)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    [res, exceptions] = utils.exec_all(True, [[f10_1], [f10_2]])

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_re001():
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify fastboot and coldboot on L3-MCLAGs.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagRe001', 'FtOpSoRoL3MclagRe002', 'FtOpSoRoL3MclagRe003', 'FtOpSoRoL3MclagRe004', 'FtOpSoRoL3MclagRe005']
    print_log("Testcase: Verify fastboot and coldboot on L3-MCLAGs.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    print_log("Step T1: Configure static routes.", "MED")
    def f1():
        ip.create_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf1, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf1, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f2():
        ip.create_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.create_static_route(leaf2, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.create_static_route(leaf2, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f3():
        ip.create_static_route(client1, data.mclag1_ips[0], data.ip_4_nw[1])
        ip.create_static_route(client1, data.mclag1_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f4():
        ip.create_static_route(client2, data.mclag2_ips[0], data.ip_3_nw[1])
        ip.create_static_route(client2, data.mclag2_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])

    print_log("Step T2: Save and reboot.", "MED")
    boot.config_save(dut_list)
    boot.config_save(dut_list,shell='vtysh')
    boot.config_save_reload(dut_list)

    print_log("Step T3: Verify all ports UP after config save-n-reload", "MED")
    [res, exceptions] = utils.exec_foreach(True, dut_list, port.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in res):
        fail_msg = "ERROR: Step T3 Ports not UP after save-n-reload."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T4: Verify MCLAG status after config save-n-reload.", "MED")
    res1 = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    res2 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag1_intf_data['leaf1'], data.mclag1_intf_data['leaf2']])
    if res1 is False or res2 is False:
        res=verify_l3mclag_keepalive_link(duts=dut_list[:2])
        if res is False:
            print_log("ERROR: Even keepalive_link is failed.")
        fail_msg = "ERROR: Step T4 MCLAG failed after config save-n-reload."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    # Seeing an issue here. So commenting below code still it is fixed.
    '''
    print_log("Step T5: Fast boot.", "MED")
    res=utils.exec_foreach(True, dut_list, st.reboot, "fast")

    print_log("Step T6: Verify MCLAG status after fastboot.", "MED")
    res1 = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    res2 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag1_intf_data['leaf1'], data.mclag1_intf_data['leaf2']])
    if res1 is False or res2 is False:
        fail_msg = "ERROR: Step T6 MCLAG failed after fastboot."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T8: Stop and Start the BGP container")
    basic.service_operations_by_systemctl(leaf1,'bgp','restart')
    st.wait(waitvar)
    '''

    print_log("Step T11: Remove static routes.", "MED")
    def f11_1():
        ip.delete_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf1, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf1, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f11_2():
        ip.delete_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
        ip.delete_static_route(leaf2, data.mclag2_ips[1], data.ip_4_nw[1])
        ip.delete_static_route(leaf2, data.mclag2_ip6s[1], data.ip6_4_nw[1], family='ipv6')
    def f11_3():
        ip.delete_static_route(client1, data.mclag1_ips[0], data.ip_4_nw[1])
        ip.delete_static_route(client1, data.mclag1_ip6s[0], data.ip6_4_nw[1], family='ipv6')
    def f11_4():
        ip.delete_static_route(client2, data.mclag2_ips[0], data.ip_3_nw[1])
        ip.delete_static_route(client2, data.mclag2_ip6s[0], data.ip6_3_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f11_1], [f11_2], [f11_3], [f11_4]])
    st.wait(waitvar)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_ceta001():
    '''
    Verify SAG over L3MCLAG having orphan port.
    CETA: SONIC-28512
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    global tg_h5
    global tg_h5_6
    tc_list = ['FtOpSoRoL3MclagFunc024']
    print_log("Testcase: Verify SAG over L3MCLAG over orphan port.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''

    print_log("Step T1: Preconfig.", "MED")
    def fc1_1():
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        sag.config_sag_mac(leaf1, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(leaf1, config=enablevar)
        sag.config_sag_mac(leaf1, ip_type=ipv6var, config=enablevar)
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=addvar)
    def fc1_2():
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        sag.config_sag_mac(leaf2, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(leaf2, config=enablevar)
        sag.config_sag_mac(leaf2, ip_type=ipv6var, config=enablevar)
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=addvar)
    [res, exceptions] = utils.exec_all(True, [[fc1_1], [fc1_2]])
    st.wait(waitvar)

    print_log("Step T2: Verify SAG output with IPv6 Gateway (dual stack) and SAG-MAC.", "MED")
    def fc2_1():
        res1=sag.verify_sag(leaf1, mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=upvar, oper=upvar)
        res2=sag.verify_sag(leaf1, ip_type='ipv6', mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, admin=upvar, oper=upvar)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T2 SAG output error on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def fc2_2():
        res1=sag.verify_sag(leaf2, mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=upvar, oper=upvar)
        res2=sag.verify_sag(leaf2, ip_type='ipv6', mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, admin=upvar, oper=upvar)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T2 SAG output error on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[fc2_1], [fc2_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T2 Initial SAG output error."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Configure orphan port.", "MED")
    vlan.add_vlan_member(leaf1, data.mclag3_vid, vars['D1T1P2'], False)
    tg_h5 = tg1.tg_interface_config(port_handle=tg_ph_5, mode='config', intf_ip_addr=data.mclag3_ips[0], gateway=data.sag_gwip, arp_send_req='1', enable_ping_response=1)
    tg_h5_6 = tg1.tg_interface_config(port_handle=tg_ph_5, mode='config', ipv6_intf_addr=data.mclag3_ip6s[0], ipv6_prefix_length=mask6, ipv6_gateway=data.sag_gwip6, arp_send_req='1', enable_ping_response=1)

    print_log("Step T4: Verify pings from all MCLAG points.", "MED")
    def fc4_1():
        res1 = verify_ping_dut(leaf1, data.sag_gwip)
        res2 = verify_ping_dut(leaf1, data.mclag3_ips[0])
        res3 = verify_ping_dut(leaf1, data.mclag3_ips[1])
        res4 = verify_ping_dut(leaf1, data.sag_gwip6)
        res5 = verify_ping_dut(leaf1, data.mclag3_ip6s[0])
        res6 = verify_ping_dut(leaf1, data.mclag3_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False:
            fail_msg = "ERROR: Step T4 Ping from leaf1 failed in non-VARP SAG scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def fc4_2():
        res1 = verify_ping_dut(leaf2, data.sag_gwip)
        res2 = verify_ping_dut(leaf2, data.mclag3_ips[0])
        res3 = verify_ping_dut(leaf2, data.mclag3_ips[1])
        res4 = verify_ping_dut(leaf2, data.sag_gwip6)
        res5 = verify_ping_dut(leaf2, data.mclag3_ip6s[0])
        res6 = verify_ping_dut(leaf2, data.mclag3_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False:
            fail_msg = "ERROR: Step T4 Ping from leaf2 failed in non-VARP SAG scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def fc4_3():
        res1 = verify_ping_dut(client1, data.sag_gwip)
        res2 = verify_ping_dut(client1, data.mclag3_ips[0])
        res3 = verify_ping_dut(client1, data.mclag3_ips[1])
        res4 = verify_ping_dut(client1, data.sag_gwip6)
        res5 = verify_ping_dut(client1, data.mclag3_ip6s[0])
        res6 = verify_ping_dut(client1, data.mclag3_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False:
            fail_msg = "ERROR: Step T4 Ping from client1 failed in non-VARP SAG scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[fc4_1], [fc4_2], [fc4_3]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 Ping failed in unique_IP scenario."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    '''
    print_log("Step T5: Changing the orphan port to trunk.", "MED")
    vlan.delete_vlan_member(leaf1, data.mclag3_vid, vars['D1T1P2'], False)
    vlan.add_vlan_member(leaf1, data.mclag3_vid, vars['D1T1P2'], True)
    tg1.tg_interface_config(port_handle=tg_ph_5, handle=tg_h5['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_5, handle=tg_h5_6['handle'], mode='destroy')
    tg_h5 = tg1.tg_interface_config(port_handle=tg_ph_5, mode='config', intf_ip_addr=data.mclag3_ips[0], gateway=data.sag_gwip, arp_send_req='1', vlan='1', vlan_id=data.mclag3_vid, vlan_id_count='1', vlan_id_step='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', enable_ping_response=1)
    tg_h5_6 = tg1.tg_interface_config(port_handle=tg_ph_5, mode='config', ipv6_intf_addr=data.mclag3_ip6s[0], ipv6_prefix_length=mask6, ipv6_gateway=data.sag_gwip6, arp_send_req='1', vlan='1', vlan_id=data.mclag3_vid, vlan_id_count='1', vlan_id_step='1', ipv6_gateway_step='0:0:0:1::', ipv6_intf_addr_step='0:0:0:1::', enable_ping_response=1)
    tg1.tg_arp_control(handle=tg_h5['handle'], arp_target='all')
    tg1.tg_arp_control(handle=tg_h5_6['handle'], arp_target='all')
    arp.clear_arp_table(leaf1)
    arp.clear_ndp_table(client1)
    res2 = verify_ping(src_obj=tg1, port_handle=tg_ph_5, dev_handle=tg_h5['handle'], dst_ip=data.sag_gwip, ping_count='3', exp_count='3')
    '''

    print_log("Step T10: Restore config.", "MED")
    def fc10_1():
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=removevar)
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=removevar)
        sag.config_sag_mac(leaf1, mac=data.sag_mac, config=removevar)
        sag.config_sag_mac(leaf1, config=disablevar2)
        sag.config_sag_mac(leaf1, ip_type=ipv6var, config=disablevar2)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        vlan.delete_vlan_member(leaf1, data.mclag3_vid, vars['D1T1P2'], False)
    def fc10_2():
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=removevar)
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=removevar)
        sag.config_sag_mac(leaf2, mac=data.sag_mac, config=removevar)
        sag.config_sag_mac(leaf2, config=disablevar2)
        sag.config_sag_mac(leaf2, ip_type=ipv6var, config=disablevar2)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
    def fc10_tgen():
        tg1.tg_interface_config(port_handle=tg_ph_5, handle=tg_h5['handle'], mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_5, handle=tg_h5_6['handle'], mode='destroy')
    [res, exceptions] = utils.exec_all(True, [[fc10_1], [fc10_2]])

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_func015():
    '''
    Verify SAG over L3MCLAG.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    #global tg_tr17_sag
    #global tg_tr71_sag
    #global tg_tr17_6_sag
    #global tg_tr71_6_sag
    global tg_v4s
    global tg_v6s
    global tg_all
    #global tg_h8_sag
    #global tg_h8_6_sag
    #global tg_tr18_sag
    #global tg_tr81_sag
    #global tg_tr18_6_sag
    #global tg_tr81_6_sag
    global tg_v4s
    global tg_v6s
    global tg_all
    tc_list = ['FtOpSoRoL3MclagFunc015', 'FtOpSoRoL3MclagFunc019', 'FtOpSoRoL3MclagFunc020', 'FtOpSoRoL3MclagFunc021', 'FtOpSoRoL3MclagFunc023']
    print_log("Testcase: Verify SAG over L3MCALG.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''

    print_log("Step T1: Preconfig.", "MED")
    print_log("Step T1a: Partial Deconfig...")
    def f1a_4():
        print_log("Within f4...")
        bgp.enable_docker_routing_config_mode(client2)
        st.config(client2, data.cmd_cp_def_conf)
        st.config(client2, data.cmd_cp_def_frr_conf)
        ip.config_ip_addr_interface(client2, data.mclag4_vlan, data.mclag4_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client2, data.mclag4_vlan, data.mclag4_ip6s[1], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(client2, data.mclag4_vid, data.mclag4, True)
        po.delete_portchannel_member(client2, portchannel=data.mclag4, members=[vars['D4D1P2'], vars['D4D2P2']])
        vlan.delete_vlan(client2, data.mclag4_vid)
        ip.config_ip_addr_interface(client2, data.mclag2, data.mclag2_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client2, data.mclag2, data.mclag2_ip6s[1], mask6, ipv6var, removevar)
        po.delete_portchannel_member(client2, portchannel=data.mclag2, members=[vars['D4D1P1'], vars['D4D2P1']])
        po.delete_portchannel(client2, [data.mclag2, data.mclag4])
        print_log("Within deconfig_base_client2...")
        #Remove Orphan port.
        #ip.config_ip_addr_interface(client2, vars['D4T1P1'], data.ip_4[0], mask4, ipv4var, removevar)
        #ip.config_ip_addr_interface(client2, vars['D4T1P1'], data.ip6_4[0], mask6, ipv6var, removevar)
    def deconfig_base_client1():
        print_log("Within deconfig_base_client1...")
        #Remove Orphan port.
        #ip.config_ip_addr_interface(client1, vars['D3T1P1'], data.ip_3[0], mask4, ipv4var, removevar)
        #ip.config_ip_addr_interface(client1, vars['D3T1P1'], data.ip6_3[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ips[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ip6s[1], mask6, ipv6var, removevar)
    def f1a_1():
        print_log("Within f1...")
        bgp.enable_docker_routing_config_mode(leaf1)
        st.config(leaf1, data.cmd_cp_def_conf)
        st.config(leaf1, data.cmd_cp_def_frr_conf)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(leaf1, data.mclag4_vid, data.mclag4, True)
        po.delete_portchannel_member(leaf1, portchannel=data.mclag4, members=[vars['D1D4P2']])
        #vlan.delete_vlan_member(leaf1, data.mclag4_vid, data.po_peer, True)
        #vlan.delete_vlan(leaf1, data.mclag4_vid)
        ip.config_ip_addr_interface(leaf1, data.mclag2, data.mclag2_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag2, data.mclag2_ip6s[0], mask6, ipv6var, removevar)
        po.delete_portchannel_member(leaf1, portchannel=data.mclag2, members=[vars['D1D4P1']])
        po.delete_portchannel(leaf1, [data.mclag4, data.mclag2])
    def f1a_2():
        print_log("Within f2...")
        bgp.enable_docker_routing_config_mode(leaf2)
        st.config(leaf2, data.cmd_cp_def_conf)
        st.config(leaf2, data.cmd_cp_def_frr_conf)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        vlan.delete_vlan_member(leaf2, data.mclag4_vid, data.mclag4, True)
        po.delete_portchannel_member(leaf2, portchannel=data.mclag4, members=[vars['D2D4P2']])
        #vlan.delete_vlan_member(leaf2, data.mclag4_vid, data.po_peer, True)
        #vlan.delete_vlan(leaf2, data.mclag4_vid)
        ip.config_ip_addr_interface(leaf2, data.mclag2, data.mclag2_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag2, data.mclag2_ip6s[0], mask6, ipv6var, removevar)
        po.delete_portchannel_member(leaf2, portchannel=data.mclag2, members=[vars['D2D4P1']])
        po.delete_portchannel(leaf2, [data.mclag4, data.mclag2])
    #[res, exceptions] = utils.exec_all(True, [[f1a_4], [deconfig_base_client1], [f1a_1], [f1a_2]])
    [res, exceptions] = utils.exec_all(True, [[deconfig_base_client1]])
    st.wait(waitvar)

    print_log("Step T1b: Config required for this testcase.")
    def f1b_4():
        print_log("Within f4...")
        vlan.create_vlan(client2, data.mclag3_vid)
        vlan.add_vlan_member(client2, data.mclag3_vid, [vars['D4D1P1'], vars['D4D2P1'], vars['D4T1P2']], True)
        ip.config_ip_addr_interface(client2, data.mclag3_vlan, data.sag_dut4_ip, mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(client2, data.mclag3_vlan, data.sag_dut4_ip6, mask6, ipv6var, addvar)
        ip.create_static_route(client2, data.mclag3_ips[0], data.ip_1_nw[1])
        ip.create_static_route(client2, data.mclag3_ip6s[0], data.ip6_1_nw[1], family='ipv6')
    def config_base_client1():
        print_log("Within config_base_client1...")
        vlan.add_vlan_member(client1, data.mclag3_vid, vars['D3T1P2'], True)
    def f1b_1():
        print_log("Within f1...")
        #vlan.add_vlan_member(leaf1, data.mclag3_vid, vars['D1D4P1'], True)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
    def f1b_2():
        print_log("Within f2...")
        #vlan.add_vlan_member(leaf2, data.mclag3_vid, vars['D2D4P1'], True)
        #ip.create_static_route(leaf2, data.keepalive_ips[0], data.ip_1_nw[1])
        #ip.create_static_route(leaf2, data.keepalive_ip6s[0], data.ip6_1_nw[1], family='ipv6')
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
    def ftgen():
        global tg_h7_sag
        global tg_h7_6_sag
        print_log("Within ftgen...")
        tg_h7_sag = tg1.tg_interface_config(port_handle=tg_ph_7, mode='config', intf_ip_addr=data.mclag3_ips[1], gateway=data.sag_gwip, arp_send_req='1', vlan='1', vlan_id=data.mclag3_vid, src_mac_addr=data.sag_tg_mac, enable_ping_response=1)
        tg_h7_6_sag = tg1.tg_interface_config(port_handle=tg_ph_7, mode='config', ipv6_intf_addr=data.mclag3_ip6s[1], ipv6_prefix_length=mask6, ipv6_gateway=data.sag_gwip6, arp_send_req='1', vlan='1', vlan_id=data.mclag3_vid, src_mac_addr=data.sag_tg_mac)
    #[res, exceptions] = utils.exec_all(True, [[f1b_4], [config_base_client1], [f1b_1], [f1b_2]])
    [res, exceptions] = utils.exec_all(True, [[config_base_client1], [f1b_1], [f1b_2]])
    '''
    pvst.config_stp_in_parallel(dut_list, feature='rpvst', mode="enable")
    pvst.config_stp_parameters(leaf1, priority='4096')
    pvst.config_stp_vlan_interface(leaf2, data.mclag3_vid, vars['D2D4P1'], '16000', 'cost')
    pvst.config_stp_vlan_interface(client2, data.mclag3_vid, vars['D4D2P1'], '16000', 'cost')
    '''
    st.wait(waitvar)

    print_log("Step T2: Verify SAG default output.", "MED")
    res1=sag.verify_sag(leaf1)
    res2=sag.verify_sag(leaf1, ip_type='ipv6')
    if res1 is True or res2 is True:
        fail_msg = "ERROR: Step T4 MAC found even without configuration."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Verify SAG output with Gateway alone config.", "MED")
    def f3_1():
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=addvar)
        st.wait(waitvar)
        res1=sag.verify_sag(leaf1, mac=notvar, status=disablevar, total=1, total_admin=0, total_oper=0, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=downvar, oper=downvar)
        #setting res2=True as they are not fixing the click/klish output diff bug now.
        res2=sag.verify_sag(leaf1, ip_type='ipv6', mac=notvar, status=disablevar)
        res2 = True
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T3 SAG output error."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_2():
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=addvar)
        st.wait(waitvar)
        res1=sag.verify_sag(leaf2, mac=notvar, status=disablevar, total=1, total_admin=0, total_oper=0, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=downvar, oper=downvar)
        res2=sag.verify_sag(leaf2, ip_type='ipv6', mac=notvar, status=disablevar)
        res2 = True
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T3 SAG output error."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 SAG output error with Gateway alone."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T4: Verify SAG output with IPv6 Gateway (dual stack) and SAG-MAC.", "MED")
    def f4_1():
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=addvar)
        sag.config_sag_mac(leaf1, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(leaf1, config=enablevar)
        sag.config_sag_mac(leaf1, ip_type=ipv6var, config=enablevar)
        st.wait(waitvar)
        res1=sag.verify_sag(leaf1, mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=upvar, oper=upvar)
        res2=sag.verify_sag(leaf1, ip_type='ipv6', mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, admin=upvar, oper=upvar)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T4 SAG output error on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f4_2():
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=addvar)
        sag.config_sag_mac(leaf2, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(leaf2, config=enablevar)
        sag.config_sag_mac(leaf2, ip_type=ipv6var, config=enablevar)
        st.wait(waitvar)
        res1=sag.verify_sag(leaf2, mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=upvar, oper=upvar)
        res2=sag.verify_sag(leaf2, ip_type='ipv6', mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, admin=upvar, oper=upvar)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T4 SAG output error on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    def f4_4():
        sag.config_sag_ip(client2, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=addvar)
        sag.config_sag_ip(client2, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=addvar)
        sag.config_sag_mac(client2, mac=data.sag_mac, config=addvar)
        sag.config_sag_mac(client2, config=enablevar)
        sag.config_sag_mac(client2, ip_type=ipv6var, config=enablevar)
        st.wait(waitvar)
        res1=sag.verify_sag(client2, mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, admin=upvar, oper=upvar)
        res2=sag.verify_sag(client2, ip_type='ipv6', mac=data.sag_mac, status=enablevar, total=1, total_admin=1, total_oper=1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, admin=upvar, oper=upvar)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T4 SAG output error on client2."
            print_log(fail_msg, "MED")
            return False
        return True
    #[res, exceptions] = utils.exec_all(True, [[f4_1], [f4_2], [f4_4]])
    [res, exceptions] = utils.exec_all(True, [[f4_1], [f4_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T4 SAG output error with IPv6 Gateway and MAC."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T5: Verify Ping.", "MED")
    [res, exceptions] = utils.exec_all(True, [[ftgen]])
    def ftgen_5():
        tg1.tg_arp_control(handle=tg_h7_sag['handle'], arp_target='all')
        tg1.tg_arp_control(handle=tg_h7_6_sag['handle'], arp_target='all')
        # Pinging from dut due to Ixia issue.
        #res1 = verify_ping(src_obj=tg1, port_handle=tg_ph_7, dev_handle=tg_h7_sag['handle'], dst_ip=data.sag_gwip, ping_count='3', exp_count='3')
        res1 = verify_ping_dut(leaf1, data.mclag3_ips[1])
        res1 = True
        res2 = verify_ping(src_obj=tg1, port_handle=tg_ph_7, dev_handle=tg_h7_6_sag['handle'], dst_ip=data.sag_gwip6, ping_count='3', exp_count='3')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T5 SAG ping error from Tgen."
            print_log(fail_msg, "MED")
            return False
        return True
    '''
    # Ping from dut to TG is not supported. So commenting out for now.
    def f1():
        res1 = verify_ping_dut(leaf1, data.mclag3_ips[1])
        res2 = verify_ping_dut(leaf1, data.mclag3_ip6s[1])
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T5 SAG ping error on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f2():
        res1 = verify_ping_dut(leaf2, data.mclag3_ips[1])
        res2 = verify_ping_dut(leaf2, data.mclag3_ip6s[1])
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T5 SAG ping error on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    '''
    [res, exceptions] = utils.exec_all(True, [[ftgen_5]])
    if False in set(res):
        fail_msg = "ERROR: Step T5 SAG ping error."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    st.wait(waitvar)

    print_log("Step T6: Verify ARP_ND present in both leaf1 and leaf2.", "MED")
    def f6_1():
        res1 = arp.verify_arp(leaf1, data.mclag3_ips[1], interface=data.mclag3)
        res2 = arp.verify_ndp(leaf1, data.mclag3_ip6s[1], vlan=data.mclag3_vid)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T6 ARP_ND on leaf1 failed."
            print_log(fail_msg, "MED")
            return False
        return True
    def f6_2():
        res1 = arp.verify_arp(leaf2, data.mclag3_ips[1], interface=data.mclag3)
        res2 = arp.verify_ndp(leaf2, data.mclag3_ip6s[1], vlan=data.mclag3_vid)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T5 ARP_ND on leaf2 failed."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f6_1], [f6_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T6 ARP_ND after ping."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    '''
    print_log("Step T7: Start the data traffic.", "MED")
    tg_tr17_sag = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1['handle'], emulation_dst_handle=tg_h7_sag['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_7, tg_ph_8])
    tg_tr71_sag = tg1.tg_traffic_config(port_handle=tg_ph_7, emulation_src_handle=tg_h7_sag['handle'], emulation_dst_handle=tg_h1['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_1, tg_ph_8])
    tg_tr17_6_sag = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1_6['handle'], emulation_dst_handle=tg_h7_6_sag['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_7, tg_ph_8])
    tg_tr71_6_sag = tg1.tg_traffic_config(port_handle=tg_ph_7, emulation_src_handle=tg_h7_6_sag['handle'], emulation_dst_handle=tg_h1_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_1, tg_ph_8])
    tg_v4s = [tg_tr17_sag['stream_id'], tg_tr71_sag['stream_id']]
    tg_v6s = [tg_tr17_6_sag['stream_id'], tg_tr71_6_sag['stream_id']]
    tg_all = tg_v4s + tg_v6s
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all2)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T8: Verify data traffic routing.", "MED")
    traffic_details1 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P2], 'rx_obj':[tg1]},
        '2':{'tx_ports':[vars.T1D3P2], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1]},
        '3':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D4P2], 'rx_obj':[tg1]},
        '4':{'tx_ports':[vars.T1D3P2], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D4P2], 'rx_obj':[tg1]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='aggregate', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T8 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)

    print_log("Step T9: Move the host to Leaf3.", "MED")
    #tg1.tg_traffic_config(mode='remove', port_handle=tg_ph_1, stream_id=tg_all[0])
    #tg1.tg_traffic_config(mode='remove', port_handle=tg_ph_1, stream_id=tg_all[2])
    tg1.tg_traffic_control(action='reset', port_handle=[tg_ph_7])
    #tg1.tg_traffic_config(mode='remove', port_handle=tg_ph_7, stream_id=tg_all[1])
    #tg1.tg_traffic_config(mode='remove', port_handle=tg_ph_7, stream_id=tg_all[3])
    tg1.tg_interface_config(port_handle=tg_ph_7, handle=tg_h7_sag['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_7, handle=tg_h7_6_sag['handle'], mode='destroy')
    tg_h8_sag = tg1.tg_interface_config(port_handle=tg_ph_8, mode='config', intf_ip_addr=data.mclag3_ips[1], gateway=data.sag_gwip, arp_send_req='1', vlan='1', vlan_id=data.mclag3_vid, src_mac_addr=data.sag_tg_mac)
    tg_h8_6_sag = tg1.tg_interface_config(port_handle=tg_ph_8, mode='config', ipv6_intf_addr=data.mclag3_ip6s[1], ipv6_prefix_length=mask6, ipv6_gateway=data.sag_gwip6, arp_send_req='1', vlan='1', vlan_id=data.mclag3_vid, src_mac_addr=data.sag_tg_mac)

    print_log("Step T10: Start the date traffic from the moved host.", "MED")
    tg_tr18_sag = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1['handle'], emulation_dst_handle=tg_h8_sag['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_7, tg_ph_8])
    tg_tr81_sag = tg1.tg_traffic_config(port_handle=tg_ph_8, emulation_src_handle=tg_h8_sag['handle'], emulation_dst_handle=tg_h1['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_1, tg_ph_7])
    tg_tr18_6_sag = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1_6['handle'], emulation_dst_handle=tg_h8_6_sag['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_7, tg_ph_8])
    tg_tr81_6_sag = tg1.tg_traffic_config(port_handle=tg_ph_8, emulation_src_handle=tg_h8_6_sag['handle'], emulation_dst_handle=tg_h1_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=[tg_ph_1, tg_ph_7])
    tg_v4s = [tg_tr18_sag['stream_id'], tg_tr81_sag['stream_id']]
    tg_v6s = [tg_tr18_6_sag['stream_id'], tg_tr81_6_sag['stream_id']]
    tg_all = tg_v4s + tg_v6s
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all2)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T11: Verify data traffic routing.", "MED")
    traffic_details2 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D4P2], 'rx_obj':[tg1]},
        '2':{'tx_ports':[vars.T1D4P2], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1]},
        '3':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P2], 'rx_obj':[tg1]},
        '4':{'tx_ports':[vars.T1D4P2], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P2], 'rx_obj':[tg1]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details2, mode='aggregate', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T11 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)

    print_log("Step T12: Verify ARP_ND present in both leaf1 and leaf2.", "MED")
    def f12_1():
        res1 = arp.verify_arp(leaf1, data.mclag3_ips[1], interface=vars['D1D4P1'])
        res2 = arp.verify_ndp(leaf1, data.mclag3_ip6s[1], vlan=data.mclag3_vid)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T12 ARP_ND on leaf1 failed."
            print_log(fail_msg, "MED")
            return False
        return True
    def f12_2():
        res1 = arp.verify_arp(leaf2, data.mclag3_ips[1], interface=data.po_peer)
        res2 = arp.verify_ndp(leaf2, data.mclag3_ip6s[1], vlan=data.mclag3_vid)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T12 ARP_ND on leaf2 failed."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f12_1], [f12_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T12 ARP_ND after host move."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)
    '''

    print_log("Step T13: Verify SAG output after removing config.", "MED")
    def f13_1():
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=removevar)
        sag.config_sag_ip(leaf1, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=removevar)
        sag.config_sag_mac(leaf1, mac=data.sag_mac, config=removevar)
        sag.config_sag_mac(leaf1, config=disablevar2)
        sag.config_sag_mac(leaf1, ip_type=ipv6var, config=disablevar2)
        st.wait(waitvar)
        res1=sag.verify_sag(leaf1)
        res2=sag.verify_sag(leaf1, ip_type='ipv6')
        if res1 is True or res2 is True:
            fail_msg = "ERROR: Step T13 SAG output error."
            print_log(fail_msg, "MED")
            return False
        return True
    def f13_2():
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=removevar)
        sag.config_sag_ip(leaf2, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=removevar)
        sag.config_sag_mac(leaf2, mac=data.sag_mac, config=removevar)
        sag.config_sag_mac(leaf2, config=disablevar2)
        sag.config_sag_mac(leaf2, ip_type=ipv6var, config=disablevar2)
        st.wait(waitvar)
        res1=sag.verify_sag(leaf2)
        res2=sag.verify_sag(leaf2, ip_type='ipv6')
        if res1 is True or res2 is True:
            fail_msg = "ERROR: Step T13 SAG output error."
            print_log(fail_msg, "MED")
            return False
        return True
    def f13_4():
        sag.config_sag_ip(client2, interface=data.mclag3_vlan, gateway=data.sag_gwip, mask=mask4, config=removevar)
        sag.config_sag_ip(client2, interface=data.mclag3_vlan, gateway=data.sag_gwip6, mask=mask6, config=removevar)
        sag.config_sag_mac(client2, mac=data.sag_mac, config=removevar)
        sag.config_sag_mac(client2, config=disablevar2)
        sag.config_sag_mac(client2, ip_type=ipv6var, config=disablevar2)
        st.wait(waitvar)
        res1=sag.verify_sag(client2)
        res2=sag.verify_sag(client2, ip_type='ipv6')
        if res1 is True or res2 is True:
            fail_msg = "ERROR: Step T13 SAG output error."
            print_log(fail_msg, "MED")
            return False
        return True
    #[res, exceptions] = utils.exec_all(True, [[f13_1], [f13_2], [f13_4]])
    [res, exceptions] = utils.exec_all(True, [[f13_1], [f13_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T13 SAG output error after removing config."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T14: Restore config.", "MED")
    def f14_1():
        print_log("Within f1...")
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        '''
        st.config(leaf1, data.cmd_restore_def_conf)
        st.config(leaf1, data.cmd_restore_def_frr_conf)
        st.config(leaf1, data.cmd_rm_json_conf)
        st.config(leaf1, data.cmd_rm_frr_conf)
        boot.config_reload(leaf1)
        '''
    def f14_2():
        print_log("Within f2...")
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        '''
        st.config(leaf2, data.cmd_restore_def_conf)
        st.config(leaf2, data.cmd_restore_def_frr_conf)
        st.config(leaf2, data.cmd_rm_json_conf)
        st.config(leaf2, data.cmd_rm_frr_conf)
        boot.config_reload(leaf2)
        '''
    def f14_3():
        print_log("Within f3...")
        vlan.delete_vlan_member(client1, data.mclag3_vid, vars['D3T1P2'], True)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ips[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(client1, data.mclag3_vlan, data.mclag3_ip6s[1], mask6, ipv6var, addvar)
        '''
        st.config(client1, data.cmd_restore_def_conf)
        st.config(client1, data.cmd_restore_def_frr_conf)
        st.config(client1, data.cmd_rm_json_conf)
        st.config(client1, data.cmd_rm_frr_conf)
        boot.config_reload(client1)
        '''
    def f14_4():
        print_log("Within f4...")
        st.config(client2, data.cmd_restore_def_conf)
        st.config(client2, data.cmd_restore_def_frr_conf)
        st.config(client2, data.cmd_rm_json_conf)
        st.config(client2, data.cmd_rm_frr_conf)
        boot.config_reload(client2)
    def ftgen_14():
        tg1.tg_traffic_control(action='reset', port_handle=[tg_ph_7, tg_ph_8])
        #tg1.tg_interface_config(port_handle=tg_ph_8, handle=tg_h8_sag['handle'], mode='destroy')
        #tg1.tg_interface_config(port_handle=tg_ph_8, handle=tg_h8_6_sag['handle'], mode='destroy')
    #[res, exceptions] = utils.exec_all(True, [[ftgen_14], [f14_1], [f14_2], [f14_3], [f14_4]], True)
    [res, exceptions] = utils.exec_all(True, [[ftgen_14], [f14_1], [f14_2], [f14_3]], True)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_sc002():
    '''
    Verify Scale for L3-MCLAG clients.
    '''
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagSc002', 'FtOpSoRoL3MclagSc003', 'FtOpSoRoL3MclagSc004', 'FtOpSoRoL3MclagRe006', 'FtOpSoRoL3MclagRe009']
    print_log("Testcase: Verify Scale for L3-MCLAG clients.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''

    print_log("Step T1: Config scale.", "MED")
    # Setting vars.
    save_scale_num = data.scale_mclag
    data.scale_mclag = '10'
    data.scale_vids=range(int(data.scale_vid), int(data.scale_vid)+int(data.scale_mclag))
    data.scale_ips_all=[range_ipv4(data.scale_ips[0], data.scale_mclag, 16),
                        range_ipv4(data.scale_ips[1], data.scale_mclag, 16),
                        range_ipv4(data.scale_ips[-1], data.scale_mclag, 16)]
    data.scale_ip6s_all=[range_ipv6(data.scale_ip6s[0], data.scale_mclag, 32),
                         range_ipv6(data.scale_ip6s[1], data.scale_mclag, 32),
                         range_ipv6(data.scale_ip6s[-1], data.scale_mclag, 32)]
    data.scale_po_all=['PortChannel00'+str(i) for i in data.scale_vids]
    data.scale_vlan_all=['Vlan'+str(i) for i in data.scale_vids]
    # Config starts.
    def f1():
        print_log("Within f1...")
        vlan.create_vlan(leaf1, data.scale_vids)
        [vlan.add_vlan_member(leaf1, vid, data.mclag3, True) for vid in data.scale_vids]
        [vlan.add_vlan_member(leaf1, vid, data.po_peer, True) for vid in data.scale_vids]
        [mclag.config_uniqueip(leaf1, op_type=addvar, vlan=vl1) for vl1 in data.scale_vlan_all]
        [ip.config_ip_addr_interface(leaf1, vl1, ip1, mask4, ipv4var, addvar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ips_all[0])]
        [ip.config_ip_addr_interface(leaf1, vl1, ip1, mask6, ipv6var, addvar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ip6s_all[0])]
    def f2():
        print_log("Within f2...")
        vlan.create_vlan(leaf2, data.scale_vids)
        [vlan.add_vlan_member(leaf2, vid, data.mclag3, True) for vid in data.scale_vids]
        [vlan.add_vlan_member(leaf2, vid, data.po_peer, True) for vid in data.scale_vids]
        [mclag.config_uniqueip(leaf2, op_type=addvar, vlan=vl1) for vl1 in data.scale_vlan_all]
        [ip.config_ip_addr_interface(leaf2, vl1, ip1, mask4, ipv4var, addvar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ips_all[1])]
        [ip.config_ip_addr_interface(leaf2, vl1, ip1, mask6, ipv6var, addvar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ip6s_all[1])]
    def f3():
        print_log("Within f3...")
        vlan.create_vlan(client1, data.scale_vids)
        [vlan.add_vlan_member(client1, vid, data.mclag3, True) for vid in data.scale_vids]
        [ip.config_ip_addr_interface(client1, vl1, ip1, mask4, ipv4var, addvar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ips_all[2])]
        [ip.config_ip_addr_interface(client1, vl1, ip1, mask6, ipv6var, addvar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ip6s_all[2])]
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3]])

    print_log("Step T2: Config iBGP and eBGP with BFD.", "MED")
    def f2_1():
        print_log("Within f1...")
        bgp.config_bgp(dut=leaf1, router_id=data.scale_ips[0], local_as=data.bgp_localas, neighbor=data.scale_ips[1], remote_as=data.bgp_localas, config='yes', redistribute='connected', keepalive=data.bgp_keepalive, holdtime=data.bgp_holdtime, config_type_list =["neighbor", "bfd", "redist", "activate"])
        bgp.config_bgp(dut=leaf1, neighbor=data.scale_ips[-1], local_as=data.bgp_localas, remote_as=data.bgp_localas, config='yes', config_type_list =["neighbor", "bfd", "activate"])
        # To add code for eBGP with client2. Commenting due to bug.
        #bgp.config_bgp(dut=leaf1, neighbor=data.mclag4_ips[1], local_as=data.bgp_localas, remote_as=data.bgp_remoteas, config='yes', config_type_list =["neighbor", "bfd", "activate", "next-hop-self"])
    def f2_2():
        print_log("Within f2...")
        bgp.config_bgp(dut=leaf2, router_id=data.scale_ips[1], local_as=data.bgp_localas, neighbor=data.scale_ips[0], remote_as=data.bgp_localas, config='yes', redistribute='connected', keepalive=data.bgp_keepalive, holdtime=data.bgp_holdtime, config_type_list =["neighbor", "bfd", "redist", "activate"])
        bgp.config_bgp(dut=leaf2, neighbor=data.scale_ips[-1], local_as=data.bgp_localas, remote_as=data.bgp_localas, config='yes', config_type_list =["neighbor", "bfd", "activate"])
    def f2_3():
        print_log("Within f3...")
        bgp.config_bgp(dut=client1, router_id=data.scale_ips[-1], local_as=data.bgp_localas, neighbor=data.scale_ips[0], remote_as=data.bgp_localas, config='yes', redistribute='connected', keepalive=data.bgp_keepalive, holdtime=data.bgp_holdtime, config_type_list =["neighbor", "bfd", "redist", "activate"])
        bgp.config_bgp(dut=client1, neighbor=data.scale_ips[1], local_as=data.bgp_localas, remote_as=data.bgp_localas, config='yes', config_type_list =["neighbor", "bfd", "activate"])
    def f2_4():
        print_log("Within f4...")
        # To add code for eBGP with client2. Commenting due to bug.
        #bgp.config_bgp(dut=client2, router_id=data.mclag4_ips[1], local_as=data.bgp_remoteas, neighbor=data.mclag4_ips[0], remote_as=data.bgp_localas, config='yes', redistribute='connected', config_type_list =["neighbor", "bfd", "redist", "activate", "next-hop-self"])
    [res, exceptions] = utils.exec_all(True, [[f2_1], [f2_2], [f2_3], [f2_4]])
    st.wait(waitvar*6)

    print_log("Step T3: Verify BGP config.", "MED")
    def f3_1():
        #res=retry_api(ip_bgp.check_bgp_session, leaf1, nbr_list=data.scale_ips[1:], state_list=['Established']*2, retry_count=15,delay=20)
        basic.poll_for_system_status(leaf1, iteration=30)
        res=retry_api(ip_bgp.check_bgp_session, leaf1, nbr_list=map(data.scale_ips.__getitem__,[1,-1]), state_list=['Established']*2, retry_count=15,delay=20)
        if res is False:
            fail_msg = "ERROR: Step T3 BGP session error on leaf1."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_2():
        basic.poll_for_system_status(leaf2, iteration=30)
        res=retry_api(ip_bgp.check_bgp_session, leaf2, nbr_list=map(data.scale_ips.__getitem__,[0,-1]), state_list=['Established']*2, retry_count=15,delay=20)
        if res is False:
            fail_msg = "ERROR: Step T3 BGP session error on leaf2."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_3():
        basic.poll_for_system_status(client1, iteration=30)
        res=retry_api(ip_bgp.check_bgp_session, client1, nbr_list=data.scale_ips[:2], state_list=['Established']*2, retry_count=15,delay=20)
        if res is False:
            fail_msg = "ERROR: Step T3 BGP session error on client1."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2], [f3_3]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 BGP session error."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)

    print_log("Step T4: Fastboot the DUTs.", "MED")
    boot.config_save(dut_list)
    boot.config_save(dut_list,shell='vtysh')
    res=utils.exec_foreach(True, [leaf1, leaf2, client1], st.reboot, "fast")
    '''
    # return value has to be enhanced from infra. So commenting this code.
    if False in set(res):
        fail_msg = "ERROR: Step T4 Fastboot error."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    '''

    print_log("Step T5: Verify BGP session after fastboot.", "MED")
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2], [f3_3]])
    if False in set(res):
        fail_msg = "ERROR: Step T5 BGP session error after fastboot."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T6: Docker restart the iccpd.", "MED")
    d1=lambda x: basic.service_operations_by_systemctl(leaf1, 'iccpd', 'restart')
    d2=lambda x: basic.service_operations_by_systemctl(leaf2, 'bgp', 'restart')
    [res, exceptions] = utils.exec_all(True, [[d1, 1], [d2, 1]])

    print_log("Step T7: Verify BGP session after docker restart.", "MED")
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2], [f3_3]])
    if False in set(res):
        fail_msg = "ERROR: Step T7 BGP session error after docker restart."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T11: DeConfig.", "MED")
    # Including BGP deconfigs.
    def f11_1():
        print_log("Within f1...")
        [ip.config_ip_addr_interface(leaf1, vl1, ip1, mask4, ipv4var, removevar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ips_all[0])]
        [ip.config_ip_addr_interface(leaf1, vl1, ip1, mask6, ipv6var, removevar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ip6s_all[0])]
        [vlan.delete_vlan_member(leaf1, vid, data.mclag3, True) for vid in data.scale_vids]
        [vlan.delete_vlan_member(leaf1, vid, data.po_peer, True) for vid in data.scale_vids]
        [mclag.config_uniqueip(leaf1, op_type=delvar, vlan=vl1) for vl1 in data.scale_vlan_all]
        vlan.delete_vlan(leaf1, data.scale_vids)
        bgp.config_bgp(dut=leaf1, removeBGP='yes', config='no', config_type_list =["removeBGP"])
    def f11_2():
        print_log("Within f2...")
        [ip.config_ip_addr_interface(leaf2, vl1, ip1, mask4, ipv4var, removevar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ips_all[1])]
        [ip.config_ip_addr_interface(leaf2, vl1, ip1, mask6, ipv6var, removevar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ip6s_all[1])]
        [vlan.delete_vlan_member(leaf2, vid, data.mclag3, True) for vid in data.scale_vids]
        [vlan.delete_vlan_member(leaf2, vid, data.po_peer, True) for vid in data.scale_vids]
        [mclag.config_uniqueip(leaf2, op_type=delvar, vlan=vl1) for vl1 in data.scale_vlan_all]
        vlan.delete_vlan(leaf2, data.scale_vids)
        bgp.config_bgp(dut=leaf2, removeBGP='yes', config='no', config_type_list =["removeBGP"])
    def f11_3():
        print_log("Within f3...")
        [ip.config_ip_addr_interface(client1, vl1, ip1, mask4, ipv4var, removevar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ips_all[2])]
        [ip.config_ip_addr_interface(client1, vl1, ip1, mask6, ipv6var, removevar) for vl1, ip1 in zip(data.scale_vlan_all, data.scale_ip6s_all[2])]
        [vlan.delete_vlan_member(client1, vid, data.mclag3, True) for vid in data.scale_vids]
        vlan.delete_vlan(client1, data.scale_vids)
        bgp.config_bgp(dut=client1, removeBGP='yes', config='no', config_type_list =["removeBGP"])
    [res, exceptions] = utils.exec_all(True, [[f11_1], [f11_2], [f11_3]])

    data.scale_mclag = save_scale_num

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_basic_rest001():
    '''
    Bring up L3-MCLAG using REST API.
    '''
    if st.get_ui_type() in ['click', 'klish']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    global tg_v4s
    global tg_v6s
    global tg_all
    tc_list = ['FtOpSoRoL3MclagRest001']
    print_log("Testcase: Bring up L3-MCLAG using REST API.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''

    print_log("Step T1: Configure static routes.", "MED")
    def f1():
        ip.create_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f2():
        ip.create_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.create_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f3():
        ip.create_static_route(client1, data.mclag1_ips[0], data.ip_1_nw[1])
        ip.create_static_route(client1, data.mclag1_ips[0], data.ip_2_nw[1])
        ip.create_static_route(client1, data.mclag1_ip6s[0], data.ip6_1_nw[1], family='ipv6')
        ip.create_static_route(client1, data.mclag1_ip6s[0], data.ip6_2_nw[1], family='ipv6')
    def ftgen():
        global tg_tr13
        global tg_tr31
        global tg_tr23
        global tg_tr32
        global tg_tr13_6
        global tg_tr31_6
        global tg_tr23_6
        global tg_tr32_6
        print_log("Reconiguring traffic streams as it will be cleaned by earlier testcase...")
        tg_tr13 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1['handle'][0], emulation_dst_handle=tg_h3['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
        tg_tr31 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3['handle'][0], emulation_dst_handle=tg_h1['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_1)
        tg_tr23 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=tg_h2['handle'][0], emulation_dst_handle=tg_h3['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
        tg_tr32 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3['handle'][0], emulation_dst_handle=tg_h2['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_2)
        tg_tr13_6 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=tg_h1_6['handle'][0], emulation_dst_handle=tg_h3_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
        tg_tr31_6 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3_6['handle'][0], emulation_dst_handle=tg_h1_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_1)
        tg_tr23_6 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=tg_h2_6['handle'][0], emulation_dst_handle=tg_h3_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_3)
        tg_tr32_6 = tg1.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=tg_h3_6['handle'][0], emulation_dst_handle=tg_h2_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_2)
    [res, exceptions] = utils.exec_all(True, [[ftgen], [f1], [f2], [f3]], True)
    st.wait(waitvar)
    tg_v4s = [tg_tr13['stream_id'], tg_tr31['stream_id'], tg_tr23['stream_id'], tg_tr32['stream_id']]
    tg_v6s = [tg_tr13_6['stream_id'], tg_tr31_6['stream_id'], tg_tr23_6['stream_id'], tg_tr32_6['stream_id']]
    tg_all = tg_v4s + tg_v6s

    def stepT2_verify():
        print_log("Step T2: Verify static routes.", "MED")
        def f1():
            res1 = ip.verify_ip_route(leaf1, ip_address=data.ip_3_nw[1], nexthop=data.mclag1_ips[1], type='S', interface=data.mclag1)
            res2 = ip.verify_ip_route(leaf1, ip_address=data.ip6_3_nw[1], nexthop=data.mclag1_ip6s[1], type='S', interface=data.mclag1, family='ipv6')
            if res1 is False or res2 is False:
                fail_msg = "ERROR: Step T2 Verifying routes failed on leaf1."
                print_log(fail_msg, "MED")
                return False
            return True
        def f2():
            res1 = ip.verify_ip_route(leaf2, ip_address=data.ip_3_nw[1], nexthop=data.mclag1_ips[1], type='S', interface=data.mclag1)
            res2 = ip.verify_ip_route(leaf2, ip_address=data.ip6_3_nw[1], nexthop=data.mclag1_ip6s[1], type='S', interface=data.mclag1, family='ipv6')
            if res1 is False or res2 is False:
                fail_msg = "ERROR: Step T2 Verifying routes failed on leaf2."
                print_log(fail_msg, "MED")
                return False
            return True
        def f3():
            res1 = ip.verify_ip_route(client1, ip_address=data.ip_1_nw[1], nexthop=data.mclag1_ips[0], type='S', interface=data.mclag1)
            res2 = ip.verify_ip_route(client1, ip_address=data.ip_2_nw[1], nexthop=data.mclag1_ips[0], type='S', interface=data.mclag1)
            res3 = ip.verify_ip_route(client1, ip_address=data.ip6_1_nw[1], nexthop=data.mclag1_ip6s[0], type='S', interface=data.mclag1, family='ipv6')
            res4 = ip.verify_ip_route(client1, ip_address=data.ip6_2_nw[1], nexthop=data.mclag1_ip6s[0], type='S', interface=data.mclag1, family='ipv6')
            if res1 is False or res2 is False or res3 is False or res4 is False:
                fail_msg = "ERROR: Step T2 Verifying routes failed on client1."
                print_log(fail_msg, "MED")
                return False
            return True
        [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3]])
        if False in set(res):
            fail_msg = "ERROR: Step T2 Verifying routes failed after configuring static routes."
            print_log(fail_msg, "MED")
            return fail_msg
        return ""

    ### REST GET
    ocdata ={ "openconfig-mclag:mclag-domains": { "mclag-domain": [ { "domain-id":int(data.po_domainid), "config": { "domain-id": int(data.po_domainid), "source-address": data.keepalive_ips[0], "peer-address": data.keepalive_ips[1], "peer-link": data.po_peer, "keepalive-interval": 1, "session-timeout": 15 } } ] }, "openconfig-mclag:interfaces": { "interface": [ { "name": data.mclag1, "config": { "name": data.mclag1, "mclag-domain-id": int(data.po_domainid)} },{ "name": data.mclag2, "config": { "name": data.mclag2, "mclag-domain-id": int(data.po_domainid) } },{ "name": data.mclag3, "config": { "name": data.mclag3, "mclag-domain-id": int(data.po_domainid) } },{ "name": data.mclag4, "config": { "name": data.mclag4, "mclag-domain-id": int(data.po_domainid) } } ] }}
    rest_urls = st.get_datastore(leaf1,'rest_urls')
    #rest_url_read = "/restconf/data/openconfig-mclag:mclag"
    rest_url_read = rest_urls['mclag_config_all']
    print_log("Step T3: Doing REST GET operation to read the MCLAG config ")
    #response1 = st.rest_read(leaf1, rest_url_read)
    response1=retry_rest_api(st.rest_read, leaf1, rest_url_read, retry_count=3, delay=20)
    print_log(response1, "MED")
    if not response1["status"] in [200, 204]:
        fail_msg ="Failed to read L3-MCLAG config details through REST API, "
        retvar = False

    print_log("Step T4: Start traffic streams.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T5: Verify data traffic routing.", "MED")
    # exp_ratio is 0.5 for few due to ECMP and limitation with direct IP on MCLAG.
    traffic_details1 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[4]]]},
        '2':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0.5], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[5]]]},
        '3':{'tx_ports':[vars.T1D2P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[2], tg_all[6]]]},
        '4':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0.5], 'rx_ports':[vars.T1D2P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[3], tg_all[7]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T5 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        fail_msg = stepT2_verify()
        fail_msgs += fail_msg

    ### REST Delete
    #rest_url_del = "/restconf/data/openconfig-mclag:mclag/mclag-domains/mclag-domain={}".format(data.po_domainid)
    rest_url_del = rest_urls['mclag_config_domain'].format(data.po_domainid)
    ## "/restconf/data/openconfig-mclag:mclag/mclag-domains/mclag-domain={}".format(data.po_domainid)
    ## "/restconf/data/openconfig-mclag:mclag/interfaces/interface={}".format(data.mclag1)
    ## "/restconf/data/openconfig-mclag:mclag/interfaces/interface={}".format(data.mclag2)
    ## "/restconf/data/openconfig-mclag:mclag/interfaces/interface={}".format(data.mclag3)
    ## "/restconf/data/openconfig-mclag:mclag/interfaces/interface={}".format(data.mclag4)
    print_log("Step T6: Doing REST Delete operation to delete the MCLAG config ")
    response2 = st.rest_delete(leaf1, rest_url_del)
    print_log(response2, "MED")
    if not response2["status"] in [200, 204]:
        fail_msg ="Failed to delete L3-MCLAG config through REST API, "
        fail_msgs += fail_msg
        retvar = False
    st.wait(waitvar)

    print_log("Step T7: Start traffic streams again.", "MED")
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)

    ### Ref: 17492. Below data traffic check is not required.
    print_log("Step T8: Verify data traffic is dropped appropriately.", "MED")
    traffic_details2 = {
        '1':{'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[4]]]},
        '2':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D1P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[5]]]},
        '3':{'tx_ports':[vars.T1D2P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D3P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[2], tg_all[6]]]},
        '4':{'tx_ports':[vars.T1D3P1], 'tx_obj':[tg1], 'exp_ratio':[0], 'rx_ports':[vars.T1D2P1], 'rx_obj':[tg1], 'stream_list':[[tg_all[3], tg_all[7]]]},
    }
    #res = validate_tgen_traffic(traffic_details=traffic_details2, mode='streamblock', comp_type='packet_rate')
    res = True
    if res is False:
        fail_msg = "ERROR: Step T7 Data traffic dropping failed after Deleting Mclag config through REST API"
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    ### REST POST
    rest_url = rest_urls['mclag_config_all']
    print_log("Step T9: Doing REST POST operation to create the MCLAG config ")
    response3 = st.rest_create(leaf1, path=rest_url, data=ocdata)
    print_log(response3, "MED")
    if not response3["status"] in [200, 201, 204]:
        fail_msg ="Failed to config L3-MCLAG through REST API ,"
        fail_msgs += fail_msg
        retvar = False
    st.wait(waitvar*4)

    print_log("Step T10: Verifying MCLAG config on the device ")
    res1 = retry_parallel(mclag.verify_domain, dut_list=[leaf1, leaf2], dict_list=[data.po_data['leaf1'], data.po_data['leaf2']])
    res2 = retry_parallel(mclag.verify_interfaces, dut_list=[leaf1, leaf2], dict_list=[data.mclag1_intf_data['leaf1'], data.mclag1_intf_data['leaf2']])
    if res1 is False or res2 is False:
        fail_msg = "ERROR:  Failed to config MCLAG via REST "
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    ### REST GET
    print_log("Step T11: Doing REST GET operation to read the MCLAG config ")
    response4=retry_rest_api(st.rest_read, leaf1, rest_url_read, retry_count=10, delay=20)
    print_log(response4, "MED")
    if not response4["status"] in [200, 204]:
        fail_msg ="Failed to read L3-MCLAG config details through REST API, "
        retvar = False

    print_log("Step T12: Verify data traffic is resumed.", "MED")
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)
    st.wait(waitvar)
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='streamblock', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T9 Data traffic resuming failed after configuring MCLAG through REST API"
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T13: Remove static routes.", "MED")
    def f13_1():
        ip.delete_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf1, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f13_2():
        ip.delete_static_route(leaf2, data.mclag1_ips[1], data.ip_3_nw[1])
        ip.delete_static_route(leaf2, data.mclag1_ip6s[1], data.ip6_3_nw[1], family='ipv6')
    def f13_3():
        ip.delete_static_route(client1, data.mclag1_ips[0], data.ip_1_nw[1])
        ip.delete_static_route(client1, data.mclag1_ips[0], data.ip_2_nw[1])
        ip.delete_static_route(client1, data.mclag1_ip6s[0], data.ip6_1_nw[1], family='ipv6')
        ip.delete_static_route(client1, data.mclag1_ip6s[0], data.ip6_2_nw[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[f13_1], [f13_2], [f13_3]])

    print_log("Step T14: Ending steps.", "MED")
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    ### REST Patch
    print_log("Step T16: Modifying MCLAG config through REST Patch operation")
    rest_patch = rest_urls['mclag_config_keepalive'].format(data.po_domainid)
    #ocyangData = { "openconfig-mclag:mclag-domain": [ { "domain-id": data.po_domainid, "config": { "domain-id": data.po_domainid, "source-address": data.keepalive_ips[0], "peer-address": data.keepalive_ips[1], "peer-link": data.po_peer, "keepalive-interval": 20, "session-timeout": 60 } } ]}
    ocyangData ={ "openconfig-mclag:keepalive-interval": 2}
    response5 = st.rest_modify(leaf1, path=rest_patch, data=ocyangData)
    print_log(response5, "MED")
    if not response5["status"] in [200, 204]:
        fail_msg ="Failed to modify L3-MCLAG config details through REST API"
        retvar = False

    ocyangData ={ "openconfig-mclag:keepalive-interval": 1}
    response6 = st.rest_modify(leaf1, path=rest_patch, data=ocyangData)
    print_log(response6, "MED")

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_uniqueip_sag_rest002():
    global tg_v4s
    global tg_v6s
    global tg_all
    global ocyang_success_code
    '''
    Verify unique-IP and SAG on L3MCLAG with REST operations.
    '''
    if st.get_ui_type() in ['click', 'klish']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagRest002']
    print_log("Testcase: Verify unique-IP and SAG on L3MCLAG with REST operations.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    tg_v4s = [tg_tr34['stream_id'], tg_tr43['stream_id']]
    tg_v6s = [tg_tr34_6['stream_id'], tg_tr43_6['stream_id']]
    tg_all = tg_v4s + tg_v6s
    ocyang_success_code = 201

    print_log("Step T1: Preconfig.", "MED")
    def f1():
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        print_log("Configuring Unique-ip using REST OCYang on leaf1")
        rest_urls = st.get_datastore(leaf1,'rest_urls')
        rest_url = rest_urls['mclag_config_all']
        oc1 ={ "vlan-interfaces": { "vlan-interface": [ { "config": { "name": data.mclag3_vlan, "unique-ip-enable": "ENABLE" }, "name": data.mclag3_vlan } ] } }
        oc2 ={ "vlan-interfaces": { "vlan-interface": [ { "config": { "name": data.mclag4_vlan, "unique-ip-enable": "ENABLE" }, "name": data.mclag4_vlan } ] } }
        r1 = st.rest_create(leaf1, path=rest_url, data=oc1)
        r2 = st.rest_create(leaf1, path=rest_url, data=oc2)
        print_log("r1 = {}".format(r1))
        print_log("r2 = {}".format(r2))
        if r1['status']!=ocyang_success_code or r2['status']!=ocyang_success_code:
            print_log("ERROR: OCyang Unique-IP config FAILED on leaf1. Status codes: {} {}".format(r1['status'], r2['status']))
        #mclag.config_uniqueip(leaf1, op_type=addvar, vlan=data.mclag3_vlan)
        #mclag.config_uniqueip(leaf1, op_type=addvar, vlan=data.mclag4_vlan)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    def f2():
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        print_log("Configuring Unique-ip using REST OCYang on leaf2")
        rest_urls = st.get_datastore(leaf1,'rest_urls')
        rest_url = rest_urls['mclag_config_all']
        oc1 ={ "vlan-interfaces": { "vlan-interface": [ { "config": { "name": data.mclag3_vlan, "unique-ip-enable": "ENABLE" }, "name": data.mclag3_vlan } ] } }
        oc2 ={ "vlan-interfaces": { "vlan-interface": [ { "config": { "name": data.mclag4_vlan, "unique-ip-enable": "ENABLE" }, "name": data.mclag4_vlan } ] } }
        r1 = st.rest_create(leaf2, path=rest_url, data=oc1)
        r2 = st.rest_create(leaf2, path=rest_url, data=oc2)
        print_log("r1 = {}".format(r1))
        print_log("r2 = {}".format(r2))
        if r1['status']!=ocyang_success_code or r2['status']!=ocyang_success_code:
            print_log("ERROR: OCyang Unique-IP config FAILED on leaf2. Status codes: {} {}".format(r1['status'], r2['status']))
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip, mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip6, mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip, mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip6, mask6, ipv6var, addvar)
    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    st.wait(waitvar*4)

    print_log("Step T2: Verify MCLAGs after unique-IP using REST GET.", "MED")
    rest_urls = st.get_datastore(leaf1,'rest_urls')
    rest_url_read = rest_urls['mclag_config_all']
    read1=retry_rest_api(st.rest_read, leaf1, rest_url_read, retry_count=10, delay=20)
    read2=retry_rest_api(st.rest_read, leaf2, rest_url_read, retry_count=10, delay=20)
    print_log("read1 = {}".format(read1))
    print_log("read2 = {}".format(read2))
    if not read1["status"] in [200, 204] or not read2["status"] in [200, 204]:
        fail_msg = "ERROR: Step T2 MCLAG failed with unique-IP via REST GET."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    r1=verify_rest_mclag_output(output=read1, val=data.po_data['leaf1'])
    r2=verify_rest_mclag_output(output=read1, val=data.mclag3_intf_data['leaf1'])
    r3=verify_rest_mclag_output(output=read1, val=data.mclag4_intf_data['leaf1'])
    r4=verify_rest_mclag_output(output=read1, val=data.mclag3_vlan_data['leaf1'])
    r5=verify_rest_mclag_output(output=read1, val=data.mclag4_vlan_data['leaf1'])
    if False in set([r1, r2, r3, r4, r5]):
        fail_msg = "ERROR: Step T2 MCLAG values failed on leaf1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    r1=verify_rest_mclag_output(output=read2, val=data.po_data['leaf2'])
    r2=verify_rest_mclag_output(output=read2, val=data.mclag2_intf_data['leaf2'])
    r3=verify_rest_mclag_output(output=read2, val=data.mclag4_intf_data['leaf2'])
    r4=verify_rest_mclag_output(output=read2, val=data.mclag3_vlan_data['leaf2'])
    r5=verify_rest_mclag_output(output=read2, val=data.mclag4_vlan_data['leaf2'])
    if False in set([r1, r2, r3, r4, r5]):
        fail_msg = "ERROR: Step T2 MCLAG values failed on leaf2."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Verify pings from all MCLAG points.", "MED")
    def f3_1():
        res1 = verify_ping_dut(leaf1, data.mclag3_uip)
        res2 = verify_ping_dut(leaf1, data.mclag3_ips[1])
        res3 = verify_ping_dut(leaf1, data.mclag3_uip6)
        res4 = verify_ping_dut(leaf1, data.mclag3_ip6s[1])
        res5 = verify_ping_dut(leaf1, data.mclag4_uip)
        res6 = verify_ping_dut(leaf1, data.mclag4_ips[1])
        res7 = verify_ping_dut(leaf1, data.mclag4_uip6)
        res8 = verify_ping_dut(leaf1, data.mclag4_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False or res7 is False or res8 is False:
            fail_msg = "ERROR: Step T3 Ping from leaf1 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_2():
        res1 = verify_ping_dut(leaf2, data.mclag3_ips[0])
        res2 = verify_ping_dut(leaf2, data.mclag3_ips[1])
        res3 = verify_ping_dut(leaf2, data.mclag3_ip6s[0])
        res4 = verify_ping_dut(leaf2, data.mclag3_ip6s[1])
        res5 = verify_ping_dut(leaf2, data.mclag4_ips[0])
        res6 = verify_ping_dut(leaf2, data.mclag4_ips[1])
        res7 = verify_ping_dut(leaf2, data.mclag4_ip6s[0])
        res8 = verify_ping_dut(leaf2, data.mclag4_ip6s[1])
        if res1 is False or res2 is False or res3 is False or res4 is False or res5 is False or res6 is False or res7 is False or res8 is False:
            fail_msg = "ERROR: Step T3 Ping from leaf2 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_3():
        res1 = verify_ping_dut(client1, data.mclag3_uip)
        res2 = verify_ping_dut(client1, data.mclag3_ips[0])
        res3 = verify_ping_dut(client1, data.mclag3_uip6)
        res4 = verify_ping_dut(client1, data.mclag3_ip6s[0])
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T3 Ping from client1 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    def f3_4():
        res1 = verify_ping_dut(client2, data.mclag4_uip)
        res2 = verify_ping_dut(client2, data.mclag4_ips[0])
        res3 = verify_ping_dut(client2, data.mclag4_uip6)
        res4 = verify_ping_dut(client2, data.mclag4_ip6s[0])
        if res1 is False or res2 is False or res3 is False or res4 is False:
            fail_msg = "ERROR: Step T3 Ping from client2 failed in uniqueip scenario."
            print_log(fail_msg, "MED")
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_1], [f3_2], [f3_3], [f3_4]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 Ping failed in unique_IP scenario."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T8: Restore config.", "MED")
    def f8_1():
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, removevar)
        print_log("Removing Unique-ip using REST OCYang on leaf1")
        rest_urls = st.get_datastore(leaf1,'rest_urls')
        rest_url_del1 = rest_urls['mclag_config_uniqueip'].format(data.mclag3_vlan)
        rest_url_del2 = rest_urls['mclag_config_uniqueip'].format(data.mclag4_vlan)
        r1 = st.rest_delete(leaf1, rest_url_del1)
        r2 = st.rest_delete(leaf1, rest_url_del2)
        print_log("r1 = {}".format(r1))
        print_log("r2 = {}".format(r2))
        if r1['status']!=204 or r2['status']!=204:
            print_log("ERROR: OCyang Unique-IP config FAILED on leaf1. Status codes: {} {}".format(r1['status'], r2['status']))
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf1, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    def f8_2():
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip, mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_uip6, mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip, mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_uip6, mask6, ipv6var, removevar)
        print_log("Removing Unique-ip using REST OCYang on leaf2")
        rest_urls = st.get_datastore(leaf1,'rest_urls')
        rest_url_del1 = rest_urls['mclag_config_uniqueip'].format(data.mclag3_vlan)
        rest_url_del2 = rest_urls['mclag_config_uniqueip'].format(data.mclag4_vlan)
        r1 = st.rest_delete(leaf2, rest_url_del1)
        r2 = st.rest_delete(leaf2, rest_url_del2)
        print_log("r1 = {}".format(r1))
        print_log("r2 = {}".format(r2))
        if r1['status']!=204 or r2['status']!=204:
            print_log("ERROR: OCyang Unique-IP config FAILED on leaf2. Status codes: {} {}".format(r1['status'], r2['status']))
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag3_vlan, data.mclag3_ip6s[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ips[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(leaf2, data.mclag4_vlan, data.mclag4_ip6s[0], mask6, ipv6var, addvar)
    [res, exceptions] = utils.exec_all(True, [[f8_1], [f8_2]])
    st.wait(waitvar*2)

    print_log("Step T9: Verify MCLAGs after removing unique-IP using REST GET.", "MED")
    rest_url_read = rest_urls['mclag_config_all']
    read1=retry_rest_api(st.rest_read, leaf1, rest_url_read, retry_count=10, delay=20)
    read2=retry_rest_api(st.rest_read, leaf2, rest_url_read, retry_count=10, delay=20)
    print_log("read1 = {}".format(read1))
    print_log("read2 = {}".format(read2))
    if not read1["status"] in [200, 204] or not read2["status"] in [200, 204]:
        fail_msg = "ERROR: Step T2 MCLAG failed with unique-IP via REST GET."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    r1=verify_rest_mclag_output(output=read1, val=data.po_data['leaf1'])
    r2=verify_rest_mclag_output(output=read1, val=data.mclag3_intf_data['leaf1'])
    r3=verify_rest_mclag_output(output=read1, val=data.mclag4_intf_data['leaf1'])
    r4=verify_rest_mclag_output(output=read1, val=data.mclag3_vlan_data['leaf1'])
    r5=verify_rest_mclag_output(output=read1, val=data.mclag4_vlan_data['leaf1'])
    if False in set([r1, r2, r3]) or True in set([r4, r5]):
        fail_msg = "ERROR: Step T9 MCLAG values failed on leaf1."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
    r1=verify_rest_mclag_output(output=read2, val=data.po_data['leaf2'])
    r2=verify_rest_mclag_output(output=read2, val=data.mclag2_intf_data['leaf2'])
    r3=verify_rest_mclag_output(output=read2, val=data.mclag4_intf_data['leaf2'])
    r4=verify_rest_mclag_output(output=read2, val=data.mclag3_vlan_data['leaf2'])
    r5=verify_rest_mclag_output(output=read2, val=data.mclag4_vlan_data['leaf2'])
    if False in set([r1, r2, r3]) or True in set([r4, r5]):
        fail_msg = "ERROR: Step T9 MCLAG values failed on leaf2."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

def test_l3mclag_sag_vrf_rest003():
    global ocyang_success_code
    global tg_h7
    global tg_h7_6
    global tg_h5
    global tg_h5_6
    global tg_tr57
    global tg_tr75
    global tg_tr57_6
    global tg_tr75_6
    global tg_v4s
    global tg_v6s
    global tg_all
    '''
    Verify Same-IP and SAG on L3MCLAG within VRF using REST operations..
    '''
    if st.get_ui_type() in ['click', 'klish']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
    tc_list = ['FtOpSoRoL3MclagRest003']
    print_log("Testcase: Verify Same-IP and SAG on L3MCLAG within VRF using REST operations.\n TCs:<{}>".format(tc_list), "HIGH")
    retvar = True
    fail_msgs = ''
    ocyang_success_code = 201

    print_log("Step T1: Initial Config...", "MED")
    def f1():
        print_log("Within f1...")
        # Adding Orphan port to Vrf.
        vrf.config_vrf(leaf1, vrf_name=data.vrf1, skip_error=True)
        st.wait(rest_waitvar)
        vrf.bind_vrf_interface(leaf1, vrf_name=data.vrf1, intf_name=vars['D1T1P2'])
        st.wait(rest_waitvar)
        ip.config_ip_addr_interface(leaf1, vars['D1T1P2'], data.ip_1[0], mask4, ipv4var, addvar)
        st.wait(rest_waitvar)
        ip.config_ip_addr_interface(leaf1, vars['D1T1P2'], data.ip6_1[0], mask6, ipv6var, addvar)
        st.wait(rest_waitvar)
        res=vrf.verify_vrf_verbose(leaf1, vrfname=[data.vrf1], interface=[[vars['D1T1P2']]])
        st.wait(rest_waitvar)
        vlan.create_vlan(leaf1, data.scale_vid)
        st.wait(rest_waitvar)
        vlan.add_vlan_member(leaf1, data.scale_vid, [data.mclag3, data.po_peer], True)
        st.wait(rest_waitvar)
        vrf.bind_vrf_interface(leaf1, vrf_name=data.vrf1, intf_name=data.scale_vlan)
        '''
        st.wait(rest_waitvar)
        ip.config_ip_addr_interface(leaf1, data.scale_vlan, data.scale_ips[0], mask4, ipv4var, addvar)
        st.wait(rest_waitvar)
        ip.config_ip_addr_interface(leaf1, data.scale_vlan, data.scale_ip6s[0], mask6, ipv6var, addvar)
        '''
    def f2():
        print_log("Within f2...")
        vrf.config_vrf(leaf2, vrf_name=data.vrf1, skip_error=True)
        st.wait(rest_waitvar)
        #res=vrf.verify_vrf_verbose(leaf2, vrfname=[data.vrf1], interface=[['']])
        st.wait(rest_waitvar)
        vlan.create_vlan(leaf2, data.scale_vid)
        st.wait(rest_waitvar)
        vlan.add_vlan_member(leaf2, data.scale_vid, [data.mclag3, data.po_peer], True)
        st.wait(rest_waitvar)
        vrf.bind_vrf_interface(leaf2, vrf_name=data.vrf1, intf_name=data.scale_vlan)
        '''
        st.wait(rest_waitvar)
        ip.config_ip_addr_interface(leaf2, data.scale_vlan, data.scale_ips[0], mask4, ipv4var, addvar)
        st.wait(rest_waitvar)
        ip.config_ip_addr_interface(leaf2, data.scale_vlan, data.scale_ip6s[0], mask6, ipv6var, addvar)
        '''
    def f3():
        print_log("Within f3...")
        vlan.create_vlan(client1, data.scale_vid)
        st.wait(rest_waitvar)
        vlan.add_vlan_member(client1, data.scale_vid, [data.mclag3, vars['D3T1P2']], True)
    [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3]])
    st.wait(waitvar)

    print_log("Step T2: Configuring SAG using REST OCYang.", "MED")
    def f2_1():
        print_log("Configuring SAG using REST OCYang on leaf1")
        #bash-4.1$ curl -u admin:broadcom -X GET "https://10.59.130.43/restconf/data/openconfig-network-instance:network-instances/network-instance=default/openconfig-network-instance-ext:global-sag" -H "accept: application/yang-data+json" -k
        rest_urls = st.get_datastore(leaf1,'rest_urls')
        rest_url = rest_urls['sag_config_basic']
        oc1 ={ "openconfig-network-instance-ext:global-sag": { "config": { "anycast-mac": data.sag_mac} }, "name": "default" }
        r1 = st.rest_create(leaf1, path=rest_url, data=oc1)
        #21621 is logged for state of gateway mac.
        #oc2 ={ "openconfig-network-instance-ext:global-sag": { "config": { "ipv4-enable": "true"} }, "name": "default" }
        #r2 = st.rest_create(leaf1, path=rest_url, data=oc2)
        # To be replaced by ocyang after the bug is fixed.
        sag.config_sag_mac(leaf1, config=enablevar)
        sag.config_sag_mac(leaf1, ip_type=ipv6var, config=enablevar)
        rest_url3 = rest_urls['sag_config_ipv4_gw'].format(data.scale_vlan)
        oc3 ={ "openconfig-interfaces-ext:sag-ipv4": { "config": { "static-anycast-gateway": [data.scale_ips[2]+'/'+mask4]} } }
        r3 = st.rest_create(leaf1, path=rest_url3, data=oc3)
        rest_url4 = rest_urls['sag_config_ipv6_gw'].format(data.scale_vlan)
        oc4 ={ "openconfig-interfaces-ext:sag-ipv6": { "config": { "static-anycast-gateway": [data.scale_ip6s[2]+'/'+mask6]} } }
        r4 = st.rest_create(leaf1, path=rest_url4, data=oc4)
        print_log("r1 = {}".format(r1))
        r2={}
        r2['status']=ocyang_success_code
        print_log("r2 = {}".format(r2))
        print_log("r3 = {}".format(r3))
        print_log("r4 = {}".format(r4))
        if r1['status']!=ocyang_success_code or r2['status']!=ocyang_success_code or r3['status']!=ocyang_success_code or r4['status']!=ocyang_success_code:
            print_log("ERROR: OCyang SAG config FAILED on leaf1. Status codes: {} {}".format(r1['status'], r2['status']))
            return False
        return True
    def f2_2():
        print_log("Configuring SAG using REST OCYang on leaf2")
        rest_urls = st.get_datastore(leaf1,'rest_urls')
        rest_url = rest_urls['sag_config_basic']
        oc1 ={ "openconfig-network-instance-ext:global-sag": { "config": { "anycast-mac": data.sag_mac} }, "name": "default" }
        r1 = st.rest_create(leaf2, path=rest_url, data=oc1)
        #21621 is logged for state of gateway mac.
        # To be replaced by ocyang after the bug is fixed.
        sag.config_sag_mac(leaf2, config=enablevar)
        sag.config_sag_mac(leaf2, ip_type=ipv6var, config=enablevar)
        rest_url3 = rest_urls['sag_config_ipv4_gw'].format(data.scale_vlan)
        oc3 ={ "openconfig-interfaces-ext:sag-ipv4": { "config": { "static-anycast-gateway": [data.scale_ips[2]+'/'+mask4]} } }
        r3 = st.rest_create(leaf2, path=rest_url3, data=oc3)
        rest_url4 = rest_urls['sag_config_ipv6_gw'].format(data.scale_vlan)
        oc4 ={ "openconfig-interfaces-ext:sag-ipv6": { "config": { "static-anycast-gateway": [data.scale_ip6s[2]+'/'+mask6]} } }
        r4 = st.rest_create(leaf2, path=rest_url4, data=oc4)
        print_log("r1 = {}".format(r1))
        r2={}
        r2['status']=ocyang_success_code
        print_log("r2 = {}".format(r2))
        print_log("r3 = {}".format(r3))
        print_log("r4 = {}".format(r4))
        if r1['status']!=ocyang_success_code or r2['status']!=ocyang_success_code or r3['status']!=ocyang_success_code or r4['status']!=ocyang_success_code:
            print_log("ERROR: OCyang SAG config FAILED on leaf2. Status codes: {} {}".format(r1['status'], r2['status']))
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f2_1], [f2_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T2 configuring SAG failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T3: Tgen Config...", "MED")
    tg_h7 = tg1.tg_interface_config(port_handle=tg_ph_7, mode='config', intf_ip_addr=data.scale_ips[-1], netmask='255.255.255.0', gateway=data.scale_ips[2], arp_send_req='1', vlan='1', vlan_id=data.scale_vid, vlan_id_count='1', gateway_step='0.1.0.0', intf_ip_addr_step='0.1.0.0', vlan_id_step='1', src_mac_addr=data.sag_tg_mac)
    tg_h7_6 = tg1.tg_interface_config(port_handle=tg_ph_7, mode='config', ipv6_intf_addr=data.scale_ip6s[-1], ipv6_prefix_length=mask6, ipv6_gateway=data.scale_ip6s[2], arp_send_req='1', vlan='1', vlan_id=data.scale_vid, vlan_id_count='1', ipv6_gateway_step='0:0:0:1::', ipv6_intf_addr_step='0:0:0:1::', vlan_id_step='1', src_mac_addr=data.scale_mac6_c1)
    tg_h5 = tg1.tg_interface_config(port_handle=tg_ph_5, mode='config', intf_ip_addr=data.ip_1[1], gateway=data.ip_1[0], arp_send_req='1')
    tg_h5_6 = tg1.tg_interface_config(port_handle=tg_ph_5, mode='config', ipv6_intf_addr=data.ip6_1[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_1[0], arp_send_req='1')

    print_log("Step T4: Send ARP_ND.", "MED")
    tg1.tg_arp_control(handle=tg_h7['handle'], arp_target='all')
    tg1.tg_arp_control(handle=tg_h7_6['handle'], arp_target='all')
    tg1.tg_arp_control(handle=tg_h5['handle'], arp_target='all')
    tg1.tg_arp_control(handle=tg_h5_6['handle'], arp_target='all')
    st.wait(waitvar)

    print_log("Step T5: Verify ARP_ND_SAG outputs.", "MED")
    rest_urls = st.get_datastore(leaf1,'rest_urls')
    # SAG state checking not possible due to bugs - 20983, 20987.
    rest_url_read1 = rest_urls['sag_show_ipv4'].format(data.scale_vlan)
    rest_url_read2 = rest_urls['sag_show_ipv6'].format(data.scale_vlan)
    name_list=[]
    out_list=[]
    out_list_2=[]
    val_list=[]
    #read1 = st.rest_read(leaf1, rest_url_read1)
    read1=retry_rest_api(st.rest_read, leaf1, rest_url_read1, retry_count=10, delay=20)
    st.wait(waitvar)
    read2=retry_rest_api(st.rest_read, leaf1, rest_url_read2, retry_count=10, delay=20)
    read1_2=retry_rest_api(st.rest_read, leaf2, rest_url_read1, retry_count=10, delay=20)
    st.wait(waitvar*1)
    read2_2=retry_rest_api(st.rest_read, leaf2, rest_url_read2, retry_count=10, delay=20)
    print_log("leaf1 read1 = {}".format(read1))
    print_log("leaf1 read2 = {}".format(read2))
    print_log("leaf2 read1_2 = {}".format(read1_2))
    print_log("leaf2 read2_2 = {}".format(read2_2))
    # IPv4
    name_list.append('neighbor_ip')
    out_list.append(str(read1['output']['openconfig-if-ip:ipv4']['neighbors']['neighbor'][0]['state']['ip']))
    out_list_2.append(str(read1_2['output']['openconfig-if-ip:ipv4']['neighbors']['neighbor'][0]['state']['ip']))
    val_list.append(data.scale_ips[-1])
    name_list.append('link-layer-address')
    out_list.append(str(read1['output']['openconfig-if-ip:ipv4']['neighbors']['neighbor'][0]['state']['link-layer-address']))
    out_list_2.append(str(read1_2['output']['openconfig-if-ip:ipv4']['neighbors']['neighbor'][0]['state']['link-layer-address']))
    val_list.append(data.sag_tg_mac)
    # Moving sag_ipv4/6 to next sub-section due to routed-vlan change.
    # IPv6
    name_list.append('neighbor_ipv6')
    out_list.append(str(read2['output']['openconfig-if-ip:ipv6']['neighbors']['neighbor'][0]['state']['ip']))
    out_list_2.append(str(read2_2['output']['openconfig-if-ip:ipv6']['neighbors']['neighbor'][0]['state']['ip']))
    val_list.append(data.scale_ip6s[-1])
    name_list.append('link-layer-address6')
    out_list.append(str(read2['output']['openconfig-if-ip:ipv6']['neighbors']['neighbor'][0]['state']['link-layer-address']))
    out_list_2.append(str(read2_2['output']['openconfig-if-ip:ipv6']['neighbors']['neighbor'][0]['state']['link-layer-address']))
    val_list.append(data.scale_mac6_c1)
    # New code after routed-vlan changes.
    rest_url_read3 = rest_urls['sag_config_ipv4_gw'].format(data.scale_vlan)
    rest_url_read4 = rest_urls['sag_config_ipv6_gw'].format(data.scale_vlan)
    read1=retry_rest_api(st.rest_read, leaf1, rest_url_read3, retry_count=10, delay=20)
    st.wait(waitvar)
    read2=retry_rest_api(st.rest_read, leaf1, rest_url_read4, retry_count=10, delay=20)
    read1_2=retry_rest_api(st.rest_read, leaf2, rest_url_read3, retry_count=10, delay=20)
    st.wait(waitvar*1)
    read2_2=retry_rest_api(st.rest_read, leaf2, rest_url_read4, retry_count=10, delay=20)
    print_log("leaf1 read1 = {}".format(read1))
    print_log("leaf1 read2 = {}".format(read2))
    print_log("leaf2 read1_2 = {}".format(read1_2))
    print_log("leaf2 read2_2 = {}".format(read2_2))
    '''
    name_list.append('self_ip')
    out_list.append(str(read1['output']['openconfig-if-ip:ipv4']['addresses']['address'][0]['state']['ip']))
    out_list_2.append(str(read1_2['output']['openconfig-if-ip:ipv4']['addresses']['address'][0]['state']['ip']))
    val_list.append(data.scale_ips[0])
    '''
    name_list.append('sag_ipv4')
    out_list.append(str(read1['output']['openconfig-if-ip:ipv4']['openconfig-interfaces-ext:sag-ipv4']['config']['static-anycast-gateway'][0]))
    out_list_2.append(str(read1_2['output']['openconfig-if-ip:ipv4']['openconfig-interfaces-ext:sag-ipv4']['config']['static-anycast-gateway'][0]))
    val_list.append(data.scale_ips[2]+'/'+mask4)
    # IPv6
    '''
    name_list.append('self_ipv6')
    out_list.append(str(read2['output']['openconfig-if-ip:ipv6']['addresses']['address'][0]['state']['ip']))
    out_list_2.append(str(read2_2['output']['openconfig-if-ip:ipv6']['addresses']['address'][0]['state']['ip']))
    val_list.append(data.scale_ip6s[0])
    '''
    name_list.append('sag_ipv6')
    out_list.append(str(read2['output']['openconfig-if-ip:ipv6']['openconfig-interfaces-ext:sag-ipv6']['config']['static-anycast-gateway'][0]))
    out_list_2.append(str(read2_2['output']['openconfig-if-ip:ipv6']['openconfig-interfaces-ext:sag-ipv6']['config']['static-anycast-gateway'][0]))
    val_list.append(data.scale_ip6s[2]+'/'+mask6)
    for n,o,v in zip(name_list*2,out_list+out_list_2,val_list*2):
        if o==v:
            st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(n,v,o))
        else:
            st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(n,v,o))
            fail_msg = "ERROR: Step T5 ARP_ND_SAG output error."
            fail_msgs += fail_msg
            print_log(fail_msg, "MED")
            retvar = False

    print_log("Step T6: Configure the data traffic streams.", "MED")
    tg_tr57 = tg1.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=tg_h5['handle'], emulation_dst_handle=tg_h7['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_7)
    tg_tr75 = tg1.tg_traffic_config(port_handle=tg_ph_7, emulation_src_handle=tg_h7['handle'], emulation_dst_handle=tg_h5['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_5)
    tg_tr57_6 = tg1.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=tg_h5_6['handle'], emulation_dst_handle=tg_h7_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_7)
    tg_tr75_6 = tg1.tg_traffic_config(port_handle=tg_ph_7, emulation_src_handle=tg_h7_6['handle'], emulation_dst_handle=tg_h5_6['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, port_handle2=tg_ph_5)

    print_log("Step T7: Start the L3 data traffic.", "MED")
    tg_v4s = [tg_tr57['stream_id'], tg_tr75['stream_id']]
    tg_v6s = [tg_tr57_6['stream_id'], tg_tr75_6['stream_id']]
    tg_all = tg_v4s + tg_v6s
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_all2)
    res=tg1.tg_traffic_control(action='run', handle=tg_all)
    st.wait(waitvar)
    res=tg1.tg_traffic_control(action='stop', handle=tg_all)

    print_log("Step T8: Verify the data traffic.", "MED")
    traffic_details1 = {
        '1':{'tx_ports':[vars.T1D1P2], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D3P2], 'rx_obj':[tg1], 'stream_list':[[tg_all[0], tg_all[2]]]},
        '2':{'tx_ports':[vars.T1D3P2], 'tx_obj':[tg1], 'exp_ratio':[1], 'rx_ports':[vars.T1D1P2], 'rx_obj':[tg1], 'stream_list':[[tg_all[1], tg_all[3]]]},
    }
    res = validate_tgen_traffic(traffic_details=traffic_details1, mode='aggregate', comp_type='packet_count')
    if res is False:
        fail_msg = "ERROR: Step T8 Data traffic routing failed."
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False
        more_debugs(duts=dut_list)
        gen_tech_supp(duts=dut_list)

    print_log("Step T9: Remove SAG using REST DELETE.", "MED")
    # '%2F' is for '/'
    rest_url_del1 = rest_urls['sag_del_ipv4'].format(data.scale_vlan,data.scale_ips[2]+'%2F'+mask4)
    rest_url_del2 = rest_urls['sag_del_ipv6'].format(data.scale_vlan,data.scale_ip6s[2]+'%2F'+mask6)
    rest_url_del3 = rest_urls['sag_del_mac']
    r1 = st.rest_delete(leaf1, rest_url_del1)
    st.wait(waitvar)
    r2 = st.rest_delete(leaf1, rest_url_del2)
    st.wait(waitvar)
    r3 = st.rest_delete(leaf1, rest_url_del3)
    r1_2 = st.rest_delete(leaf2, rest_url_del1)
    st.wait(waitvar)
    r2_2 = st.rest_delete(leaf2, rest_url_del2)
    st.wait(waitvar)
    r3_2 = st.rest_delete(leaf2, rest_url_del3)
    print_log("leaf1 r1 = {}".format(r1))
    print_log("leaf1 r2 = {}".format(r2))
    print_log("leaf1 r3 = {}".format(r3))
    print_log("leaf2 r1_2 = {}".format(r1_2))
    print_log("leaf2 r2_2 = {}".format(r2_2))
    print_log("leaf2 r3_2 = {}".format(r3_2))
    if r1['status']!=204 or r2['status']!=204 or r3['status']!=204 or r1_2['status']!=204 or r2_2['status']!=204 or r3_2['status']!=204:
        fail_msg = "ERROR: OCyang SAG DELETE FAILED.  Status codes: {} {} {} {} {} {}".format(r1['status'], r2['status'], r3['status'], r1_2['status'], r2_2['status'], r3_2['status'])
        fail_msgs += fail_msg
        print_log(fail_msg, "MED")
        retvar = False

    print_log("Step T13: DeConfig.", "MED")
    def f13_1():
        print_log("Within f1...")
        #ip.config_ip_addr_interface(leaf1, data.scale_vlan, data.scale_ips[0], mask4, ipv4var, removevar)
        #ip.config_ip_addr_interface(leaf1, data.scale_vlan, data.scale_ip6s[0], mask6, ipv6var, removevar)
        vrf.bind_vrf_interface(leaf1, vrf_name=data.vrf1, intf_name=data.scale_vlan, config='no')
        vlan.delete_vlan_member(leaf1, data.scale_vid, [data.mclag3, data.po_peer], True)
        vlan.delete_vlan(leaf1, data.scale_vid)
        ip.config_ip_addr_interface(leaf1, vars['D1T1P2'], data.ip_1[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(leaf1, vars['D1T1P2'], data.ip6_1[0], mask6, ipv6var, removevar)
        vrf.bind_vrf_interface(leaf1, vrf_name=data.vrf1, intf_name=vars['D1T1P2'], config='no')
        vrf.config_vrf(leaf1, vrf_name=data.vrf1, config='no')
    def f13_2():
        print_log("Within f2...")
        #ip.config_ip_addr_interface(leaf2, data.scale_vlan, data.scale_ips[0], mask4, ipv4var, removevar)
        #ip.config_ip_addr_interface(leaf2, data.scale_vlan, data.scale_ip6s[0], mask6, ipv6var, removevar)
        vrf.bind_vrf_interface(leaf2, vrf_name=data.vrf1, intf_name=data.scale_vlan, config='no')
        vlan.delete_vlan_member(leaf2, data.scale_vid, [data.mclag3, data.po_peer], True)
        vlan.delete_vlan(leaf2, data.scale_vid)
        vrf.config_vrf(leaf2, vrf_name=data.vrf1, config='no')
    def f13_3():
        print_log("Within f3...")
        vlan.delete_vlan_member(client1, data.scale_vid, [data.mclag3, vars['D3T1P2']], True)
        vlan.delete_vlan(client1, data.scale_vid)
    def ftgen_13():
        tg1.tg_traffic_control(action='reset', port_handle=[tg_ph_5, tg_ph_7])
        tg1.tg_interface_config(port_handle=tg_ph_5, handle=tg_h5['handle'], mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_5, handle=tg_h5_6['handle'], mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_7, handle=tg_h7['handle'], mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_7, handle=tg_h7_6['handle'], mode='destroy')
    [res, exceptions] = utils.exec_all(True, [[ftgen_13], [f13_1], [f13_2], [f13_3]], True)

    if retvar is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failure_message", fail_msgs)

