import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.arp as arp_obj
import apis.system.reboot as rb_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.system.interface as intf_obj
import apis.routing.bgp as bgp_obj
import apis.system.basic as basic_obj
import apis.switching.portchannel as portchannel_obj

from utilities.common import poll_wait
from utilities.parallel import exec_all, exec_parallel, ensure_no_exception

def init_vars():
    global vars
    vars = st.ensure_min_topology("D1D2:1")

def initialize_variables():       
    global data
    data = SpyTestDict()
    data.ipv4_prefix = "20.20.20"
    data.mask_length = "24"
    data.ipv4_address_network = data.ipv4_prefix+".0/"+data.mask_length
    data.d1_ipv4_address = data.ipv4_prefix+".1"
    data.d2_ipv4_address = data.ipv4_prefix+".2"
    data.wrong_mac_d1_ipv4_address = data.ipv4_prefix+".3"
    data.wrong_mac_d2_ipv4_address = data.ipv4_prefix+".4"
    data.port_mac_d1_ipv4_address = data.ipv4_prefix+".5"
    data.port_mac_d2_ipv4_address = data.ipv4_prefix+".6"
    data.lc_d1_ipv4_address = data.ipv4_prefix+".7"
    data.lc_d2_ipv4_address = data.ipv4_prefix+".8"
    data.ipv6_prefix = "dddd::"
    data.mask1_length = "64"
    data.ipv6_address_network = data.ipv6_prefix+"0/"+data.mask1_length
    data.d1_ipv6_address = data.ipv6_prefix+"1"
    data.d2_ipv6_address = data.ipv6_prefix+"2"
    data.wrong_mac_d1_ipv6_address = data.ipv6_prefix+"3"
    data.wrong_mac_d2_ipv6_address = data.ipv6_prefix+"4"
    data.port_mac_d1_ipv6_address = data.ipv6_prefix+"5"
    data.port_mac_d2_ipv6_address = data.ipv6_prefix+"6"
    # changing mac address from capital to mac address format
    # data.d1_mac_addr = basic_obj.get_dut_mac_address(vars.D1)["SD1"]
    # data.d1_mac_addr = data.d1_mac_addr.lower()
    # data.d1_mac_addr = ':'.join(data.d1_mac_addr[i:i+2] for i in range(0,12,2))
    data.d1_mac_addr = basic_obj.get_ifconfig_ether(vars.D1, vars.D1D2P1)
    st.log("d1 mac adress")
    print(data.d1_mac_addr)
    data.d2_mac_addr = basic_obj.get_ifconfig_ether(vars.D2, vars.D2D1P1)
    # data.d2_mac_addr = data.d2_mac_addr.lower()
    # data.d2_mac_addr = ':'.join(data.d2_mac_addr[i:i+2] for i in range(0,12,2))
    st.log("d2 mac adress")
    print(data.d2_mac_addr)
    data.wrong_mac_addr = "7a:2b:4c:8d:5e:8f"
    data.members_dut1 = [vars.D1D2P1]
    data.members_dut2 = [vars.D2D1P1]
    data.portchannel_name = "PortChannel1"
    data.cli_type = 'click'


def get_parms():
    data.platform = basic_obj.get_hwsku(vars.D1)
    data.constants = st.get_datastore(vars.D1, "constants", "default")

@pytest.fixture(scope="module", autouse=True)
def arp_static_mac_module_hooks(request):
    # add things at the start of this module
    init_vars()
    initialize_variables()
    get_parms()

def test_ipv4_basic_arp_bring_up():
    # Configuring ipv4 address for the interface on D1 and D2 
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.d1_ipv4_address, data.mask_length, family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.d2_ipv4_address, data.mask_length, family="ipv4", config='add')
    # Configuring static arp for D1 mapping with D2 mac address
    st.log("Configuring static ARP")
    arp_obj.add_static_arp(vars.D1, data.d2_ipv4_address, data.d2_mac_addr, vars.D1D2P1)
    # verifying arp entry status 
    st.log("Verifying static ARP")
    verify_arp_status(vars.D1, data.d2_ipv4_address, data.d2_mac_addr)
    #Verify if ping is reachable to configured ipv4 address
    res = ip_obj.ping(vars.D1, addresses = data.d2_ipv4_address, family = "ipv4")
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded in ipv4 bring up")
    else:
        st.log("ipv4 arp bring up failed test case")
        st.report_fail("ipv4 arp bring up failed", D1)
        raise(RuntimeError("Ping failed in ipv4 bring up"))
        st.log("Ping failed in ipv4 bring up  ")
    st.wait(5)
    st.report_pass("test_case_passed")
    #Below step will clear the configured ip configuration 
    ip_obj.clear_ip_configuration(st.get_dut_names())
    # #Below step will delete static arp entries configured in the deviceSSS
    arp_obj.delete_static_arp(vars.D1, data.d2_ipv4_address, vars.D1D2P1)

def test_ipv6_basic_arp_bring_up():

    # Configuring ipv6 address for the interface on D1 and D2 
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.d1_ipv6_address, data.mask1_length, family="ipv6", config='add')
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.d2_ipv6_address, data.mask1_length, family="ipv6", config='add')
    # Configuring static arp for D1 mapping with D2 mac address
    st.log("Configuring static ARP ipv6")
    arp_obj.config_static_ndp(vars.D1, data.d2_ipv6_address, data.d2_mac_addr, vars.D1D2P1)
    # Verifying arp entry status 
    st.log("Verifying static arp ipv6")
    if not arp_obj.verify_ndp(vars.D1, data.d2_ipv6_address):
        # raise(RuntimeError("verifying configured arp entry failed"))
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
    #Verify if ping is reachable to configured ipv6 address
    st.log("Pinging from tgen to DUT's ixia connected IPV4 interface")
    res = ip_obj.ping(vars.D1, addresses = data.d2_ipv6_address, family = "ipv6")
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded in ipv6 bring up")
    else:
        # raise(RuntimeError("Ping failed in ipv6 bring up "))
        st.log("Ping failed in ipv6 bring up ")
    st.wait(5)
    st.report_pass("test_case_passed")
    #Below step will clear the configured ip configuration 
    ip_obj.clear_ip_configuration(st.get_dut_names(), family="ipv6")
    # #Below step will delete static arp entries configured in the deviceSSS
    arp_obj.config_static_ndp(vars.D1, data.d2_ipv6_address, data.d2_mac_addr, vars.D1D2P1, operation = "del")

def test_ipv4_static_arp_after_reboot():
    '''
    Verify ipv4 static ARP route config after reboot
    '''
    verify_ipv4_static_arp_after_reboot(vars.D1, vars.D2, vars.D1D2P1, vars.D2D1P1, data.d1_ipv4_address, data.d2_ipv4_address, data.d2_mac_addr, data.mask_length, family="ipv4", config="add")

def test_ipv6_static_arp_after_reboot():
    '''
    Verify ipv6 static ARP route config after reboot
    '''
    verify_ipv6_static_arp_after_reboot(vars.D1, vars.D2, vars.D1D2P1, vars.D2D1P1, data.d1_ipv6_address, data.d2_ipv6_address, data.d2_mac_addr, data.mask1_length, family="ipv6", config="add")

def verify_ipv4_static_arp_after_reboot(dut1, dut2, interface1, interface2, ipaddress1, ipaddress2, mac_address, mask_length, family, config):
    '''
    Verify ipv4 static ARP route config after reboot
    '''
    #Configuring the ip address of the interface 
    ip_obj.config_ip_addr_interface(dut1, interface1, ipaddress1, mask_length, family= family, config=config)
    ip_obj.config_ip_addr_interface(dut2, interface2, ipaddress2, mask_length, family= family, config=config)
    st.log("Configuring static ARP")
    #Add the static arp entry 
    arp_obj.add_static_arp(dut1, ipaddress2, mac_address, interface1)
    #Reboot the device
    st.reboot(dut1)
    #verify if the arp entry is persistent 
    st.log("Verifying static ARP entries after config save")
    #save the config 
    rb_obj.config_save(vars.D1)
    st.log("saving config in vtysh mode to save static route")
    rb_obj.config_save(vars.D1, shell="vtysh")
    verify_arp_status(interface1, ipaddress2, mac_address)
    #Below step will clear all the ip configurations
    ip_obj.clear_ip_configuration(st.get_dut_names())
    # #Below step will delete static arp entries configured in the deviceSSS
    arp_obj.delete_static_arp(dut1, ipaddress2, interface1)
    st.report_pass("test_case_passed")

def verify_ipv6_static_arp_after_reboot(dut1, dut2, interface1, interface2, ipaddress1, ipaddress2, mac_address, mask_length, family, config):
    '''
    Verify ipv6 static ARP route config after reboot
    '''
    #Configuring the ip address of the interface 
    ip_obj.config_ip_addr_interface(dut1, interface1, ipaddress1, mask_length, family= family, config=config)
    ip_obj.config_ip_addr_interface(dut2, interface2, ipaddress2, mask_length, family= family, config=config)
    # Configuring static arp for D1 mapping with wrong  mac address
    st.log("Configuring static ARP")
    arp_obj.config_static_ndp(dut1, ipaddress2, mac_address, interface1)
    #Verify if ping is reachable to configured ipv6 address
    if not arp_obj.verify_ndp(dut1, ipaddress2):
        # raise(RuntimeError("verifying configured arp entry failed"))
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
    #Reboot the device
    st.reboot(dut1)
    #verify if the arp entry is persistent 
    st.log("Verifying static ARP entries after config save")
    verify_arp_status(interface1, ipaddress2, mac_address)
    #Below step will clear all the ip configurations
    ip_obj.clear_ip_configuration(st.get_dut_names())
    # #Below step will delete static arp entries configured in the deviceSSS
    arp_obj.delete_static_arp(dut1, ipaddress2, interface1)
    st.report_pass("test_case_passed")

def verify_arp_status(dut, ipaddress, macaddress=None, interface=None, vlan= None):
    '''
    Verify arp status 
    '''
    if not arp_obj.verify_arp(vars.D1, ipaddress, macaddress, ""):
        st.log("After_Reboot_ARP_static_entry_fail")
        st.report_fail("After_Reboot_ARP_entry_static_entry_fail", dut)
        raise(RuntimeError("static arp entry not available"))
    else:
        st.log("Verified that static ARP entry is present in arp table")

def test_ipv4_static_arp_with_wrong_mac():
    '''
    Test static ARP  config after configuring with ipv4  wrong mac address
    '''
    verify_static_arp_ipv4_with_wrong_mac(vars.D1, vars.D2, vars.D1D2P1, vars.D2D1P1, data.wrong_mac_d1_ipv4_address, data.wrong_mac_d2_ipv4_address, data.wrong_mac_addr, data.mask_length, family = "ipv4", config = 'add')

def test_ipv6_static_arp_with_wrong_mac():
    '''
    Test static ARP  config after configuring with ipv6  wrong mac address
    '''
    verify_static_arp_ipv6_with_wrong_mac(vars.D1, vars.D2, vars.D1D2P1, vars.D2D1P1, data.wrong_mac_d1_ipv6_address, data.wrong_mac_d2_ipv6_address, data.wrong_mac_addr, data.mask1_length, family = "ipv6", config = 'add')

def verify_static_arp_ipv4_with_wrong_mac(dut1, dut2, interface1, interface2, ipaddress1, ipaddress2, mac_address, mask_length, family, config):
    '''
    Verify static ARP  config after configuring with ipv4 wrong mac address
    '''
    # Configuring ipv4 address for the interface on D1 and D2 
    ip_obj.config_ip_addr_interface(dut1, interface1, ipaddress1, mask_length, family= family, config= config)
    ip_obj.config_ip_addr_interface(dut2, interface2, ipaddress2, mask_length, family= family, config= config)
    # Configuring static arp for D1 mapping with wrong mac address
    st.log("Configuring static ARP")
    arp_obj.add_static_arp(dut1, ipaddress2, mac_address, interface1)
    if not arp_obj.verify_arp(dut1, ipaddress2, mac_address):
        # raise(RuntimeError("verifying configured arp entry failed"))
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
        st.log("Pinging from tgen to DUT's ixia connected IPV4 interface")
    res = ip_obj.ping(dut1, addresses = ipaddress2, family = family)
    st.log("PING_RES: " + str(res))
    if res:
        st.log("wrong mac tc failed", vars.D1)
        st.report_fail("wrong mac tc failed", vars.D1)
        raise(RuntimeError("After configuring wrong mac the ping passed which is not expected"))
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    st.wait(5)
    st.report_pass("test_case_passed")
    #Below step will clear the configured ip configuration 
    ip_obj.clear_ip_configuration(st.get_dut_names())
    #Below step will delete the static arp entry 
    arp_obj.delete_static_arp(dut1, ipaddress2, interface1)

def verify_static_arp_ipv6_with_wrong_mac(dut1, dut2, interface1, interface2, ipaddress1, ipaddress2, mac_address, mask_length, family, config):
    '''
    Verify static ARP  config after configuring with ipv6 wrong mac address
    '''
    # Configuring ipv6 address for the interface on D1 and D2 
    ip_obj.config_ip_addr_interface(dut1, interface1, ipaddress1, mask_length, family= family, config= config)
    ip_obj.config_ip_addr_interface(dut2, interface2, ipaddress2, mask_length, family= family, config= config)
    # Configuring static arp for D1 mapping with wrong  mac address
    st.log("Configuring static ARP")
    arp_obj.config_static_ndp(dut1, ipaddress2, mac_address, interface1)
    #Verify if ping is reachable to configured ipv6 address
    if not arp_obj.verify_ndp(dut1, ipaddress2):
        # raise(RuntimeError("verifying configured arp entry failed"))
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
        st.log("Pinging from tgen to DUT's ixia connected IPV4 interface")
    res = ip_obj.ping(dut1, addresses = ipaddress2, family = family)
    st.log("PING_RES: " + str(res))
    if res:
        st.report_fail("ipv6 wrong mac tc failed", vars.D1)
        raise(RuntimeError("After configuring wrong mac the ping passed which is not expected"))
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    st.wait(5)
    st.report_pass("test_case_passed")
    #Below step will clear the configured ip configuration 
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='ipv6')
    arp_obj.config_static_ndp(dut1, ipaddress2, mac_address, interface1, operation = "del")

def verify_portchannel_status(portchannel_name, delay=2):
    dict1 = {'portchannel':portchannel_name, 'members_list': data.members_dut1, 'iter_delay': delay}
    dict2 = {'portchannel': portchannel_name, 'members_list': data.members_dut2, 'iter_delay': delay}
    output = exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    ensure_no_exception(output[1])

def verify_portchannel_cum_member_status(dut, portchannel, members_list, iter_count=10, iter_delay=2, state='up'):
    i = 1
    while i <= iter_count:
        st.log("Checking iteration {}".format(i))
        st.wait(iter_delay)
        if not portchannel_obj.verify_portchannel_member_state(dut, portchannel, members_list, state='up',
                                                        cli_type=data.cli_type):
            i += 1
            if i == iter_count:
                st.report_fail("portchannel_member_verification_failed", portchannel, dut, members_list)
        else:
            break

def test_static_arp_ipv4_with_port_channel():
    '''
    Verify static ARP route config with port channel
    '''
    #Configuring the PortChannel
    st.log("Configuring PortChannel")
    st.log('Creating port-channel and adding members in both DUTs')
    portchannel_obj.config_portchannel(vars.D1, vars.D2, data.portchannel_name, data.members_dut1,
                                           data.members_dut2, "add", cli_type=data.cli_type)
    #Starting up the portchannel
    dict1 = {'interfaces':data.portchannel_name, 'operation':"startup", 'skip_verify':True, 'cli_type':data.cli_type}
    output = exec_parallel(True, [vars.D1, vars.D2], intf_obj.interface_operation, [dict1, dict1])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    #Configuring the ip for the portchannel
    ip_obj.config_ip_addr_interface(vars.D1, data.portchannel_name, data.port_mac_d1_ipv4_address, data.mask_length, family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(vars.D2, data.portchannel_name, data.port_mac_d2_ipv4_address, data.mask_length, family="ipv4", config='add')
    #Adding the static arp entry on the portchannel 
    arp_obj.add_static_arp(vars.D1, data.port_mac_d2_ipv4_address, data.d2_mac_addr, data.portchannel_name)
    #verify the arp entry creation is successful
    if not arp_obj.verify_arp(vars.D1, data.port_mac_d2_ipv4_address, data.d2_mac_addr, ""):
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
    #Verify if portchannel is up or not 
    verify_portchannel_status(data.portchannel_name)
    #Verify if the ping is reachable from D1 to D2 
    res = ip_obj.ping(vars.D1, addresses = data.port_mac_d2_ipv4_address, family = "ipv4")
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping of portchannel ip succeeded.")
    else:
        st.log("PortChannel test case failure multiple bugs - id #272")
        raise(RuntimeError("PortChannel test case failure multiple bugs - id #272"))
        st.log("Ping of portchannel ip  failed.")
    st.wait(5)
    st.report_pass("test_case_passed")
    #Delete the portchannel 
    portchannel_obj.config_portchannel(vars.D1, vars.D2, data.portchannel_name, data.members_dut1,
                                           data.members_dut2, "delete", cli_type=data.cli_type)
    #Clear the ip configuration 
    ip_obj.clear_ip_configuration(st.get_dut_names())
    #Delete the static arp entry of the portchannel 
    arp_obj.delete_static_arp(vars.D1, data.port_mac_d2_ipv4_address, data.portchannel_name)

def test_static_arp_ipv6_with_port_channel():
    '''
    Verify static ARP route config with port channel
    '''
    #Configuring the PortChannel
    st.log("Configuring PortChannel")
    st.log('Creating port-channel and adding members in both DUTs')
    data.portchannel1_name = "PortChannel2"
    portchannel_obj.config_portchannel(vars.D1, vars.D2, data.portchannel1_name, data.members_dut1,
                                           data.members_dut2, "add", cli_type=data.cli_type)
    #Starting up the portchannel
    dict1 = {'interfaces':data.portchannel1_name, 'operation':"startup", 'skip_verify':True, 'cli_type':data.cli_type}
    output = exec_parallel(True, [vars.D1, vars.D2], intf_obj.interface_operation, [dict1, dict1])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        st.report_fail('interface_admin_startup_fail', data.portchannel1_name)
    #Configuring the ip for the portchannel
    ip_obj.config_ip_addr_interface(vars.D1, data.portchannel1_name, data.port_mac_d1_ipv6_address, data.mask1_length, family="ipv6", config='add')
    ip_obj.config_ip_addr_interface(vars.D2, data.portchannel1_name, data.port_mac_d2_ipv6_address, data.mask1_length, family="ipv6", config='add')
    #Adding the static arp entry on the portchannel 
    arp_obj.config_static_ndp(vars.D1, data.port_mac_d2_ipv6_address, data.d2_mac_addr, data.portchannel1_name)
    #verify the arp entry creation is successful
    if not arp_obj.verify_ndp(vars.D1, data.port_mac_d2_ipv6_address):
        # raise(RuntimeError("verifying configured arp entry failed"))
        st.report_fail("static_arp_create_fail", vars.D1)
    else:
        st.log("Verified that static ARP entry is present in arp table")
    #Verify if portchannel is up or not 
    verify_portchannel_status(data.portchannel1_name)
    #Verify if the ping is reachable from D1 to D2 
    st.log("Pinging from tgen to DUT's ixia connected IPV4 interface")
    res = ip_obj.ping(vars.D1, addresses = data.port_mac_d2_ipv6_address, family = "ipv6")
    st.log("PING_RES: " + str(res))
    if res:
        # raise(RuntimeError("After configuring wrong mac the ping passed which is not expected"))
        st.log("Ping succeeded of portchannel.")
    else:
        st.log("PortChannel test case failure multiple bugs - id #272")
        raise(RuntimeError("PortChannel test case failure multiple bugs - id #272"))
        st.log("Ping failed of portchannel.")
    st.wait(5)
    st.report_pass("test_case_passed")
    #Delete the portchannel 
    portchannel_obj.config_portchannel(vars.D1, vars.D2, data.portchannel1_name, data.members_dut1,
                                           data.members_dut2, "delete", cli_type=data.cli_type)
    #Clear the ip configuration 
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='ipv6')
    #Delete the static arp entry of the portchannel 
    arp_obj.config_static_ndp(vars.D1, data.port_mac_d2_ipv6_address, data.d2_mac_addr, data.portchannel1_name, operation = "del")






