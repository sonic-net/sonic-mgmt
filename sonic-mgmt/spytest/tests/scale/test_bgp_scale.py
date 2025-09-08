import pytest
import re, datetime, random, yaml, os, json
import sys, shutil
from spytest import st,tgapi
from spytest.dicts import SpyTestDict
from spytest.tgen.tg import tgen_obj_dict
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
from spytest.access.connection import DeviceFileUpload, DeviceConnection
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.system.interface as intapi
import apis.switching.portchannel as poapi
import apis.system.basic as basicapi
import apis.system.connection as conn_obj
import apis.system.reboot as reboot_obj
from utilities.common import poll_wait
from apis.system.interface import interface_status_show, show_interfaces_counters
from ipaddress import IPv4Network
from ipaddress import ip_network
from utilities import parallel
import random
import tests.optics.optics_util as optics_util

scaleValues = optics_util.YamlFileParser("scale_values.yaml")

def initialize_variables():
    global globalVars 
    globalVars = st.get_testbed_vars()
    global data
    data = SpyTestDict()
    data.DUTs = [globalVars.D1,globalVars.D2]
    global bgp_data
    global IPRange, IPV6addresses
    bgp_data = SpyTestDict()
    #Extracting IPV4 Values
    bgp_data.ipv4_mask = scaleValues['ipv4_mask']
    bgp_data.D1D2P1=scaleValues['D1D2P1']
    bgp_data.D2D1P1=scaleValues['D2D1P1']
    bgp_data.D1T1P1=scaleValues['D1T1P1']
    bgp_data.T1D2P1=scaleValues['T1D2P1']
    bgp_data.D2T1P1=scaleValues['D2T1P1']
    #Extracting IPV6 Values
    bgp_data.ipv6_mask = scaleValues['ipv6_mask']
    bgp_data.v6D1D2P1=scaleValues['v6D1D2P1']
    bgp_data.v6D2D1P1=scaleValues['v6D2D1P1']
    bgp_data.v6T1D2P1=scaleValues['v6T1D2P1']
    bgp_data.v6D2T1P1=scaleValues['v6D2T1P1']
    bgp_data.v6D1T1P1=scaleValues['v6D1T1P1']
    bgp_data.v6T1D1P1=scaleValues['v6T1D1P1']

    bgp_data.max_bgp_ipv4_peer=scaleValues['max_bgp_ipv4_peer']
    bgp_data.max_bgp_ipv6_peer=scaleValues['max_bgp_ipv6_peer']

    bgp_data.platform_sum_info={} 

    for dut in data.DUTs:
        bgp_data.platform_sum_info[dut]=optics_util.get_platform_summary(dut)
    
    if re.search('8101', bgp_data.platform_sum_info[globalVars.D1].get('Platform')):
        platform_type='8101' 
    elif re.search('8122', bgp_data.platform_sum_info[globalVars.D1].get('Platform')):
        platform_type='8122'
    elif re.search('8102', bgp_data.platform_sum_info[globalVars.D1].get('Platform')):
        platform_type='8102'
    elif re.search('8201', bgp_data.platform_sum_info[globalVars.D1].get('Platform')):
        platform_type='8201'
    else:
        platform_type = 'untested' 

    bgp_data.max_bgp_ipv4_prefix=scaleValues['max_bgp_ipv4_prefix'].get(platform_type, '250000')  

    bgp_data.max_bgp_ipv6_prefix=scaleValues['max_bgp_ipv6_prefix'].get(platform_type, '250000')   

    #Create 500 Devices on T1 & Configure IP Addresses
    addresses = returnIPRange(u"{}".format(scaleValues["NETWORK"]))
    IPRange = []
    for e in addresses:
        if not e.endswith(".255") and not e.endswith(".0"):
            IPRange.append(e)
    IPV6addresses = returnIPV6range(u"{}".format(scaleValues["IPV6NETWORK"]))
def verifyPortStatus(data, globalVars): #"D1T1:1","D1D2:3","D2T1:1"
    for dut,portList in zip(data.DUTs,[[globalVars.D1T1P1, globalVars.D1D2P1,globalVars.D1D2P2] ,[globalVars.D2T1P1, globalVars.D2D1P1,globalVars.D2D1P2]]):
        for port in portList:
            if not intapi.verify_interface_status(dut,port,'oper', 'up'):
                return False
    return True

@pytest.fixture(scope="function")
def bgp_cleanup(request):
    st.ensure_min_topology("D1T1:1","D1D2:2","D2T1:1")

    initialize_variables()
    tg_preconfig()

    #Verify that all ports are up
    verifyPortStatus(data, globalVars)

    #PreClean up
    cleanup()

    yield

    cleanup() 

def returnIPRange(IpSubnetInfo):
    net = IPv4Network(IpSubnetInfo)
    addresses= [str(addr) for addr in net]
    return addresses

def returnIPV6range(IpSubnetInfo):
    net = ip_network(IpSubnetInfo).hosts()
    addresses= [str(addr) for addr in net]
    return addresses

def is_prefix_in_subnet(prefix, subnet):
    """
    Checks if an IPv6 prefix is contained within a subnet.

    Args:
        prefix (str): The IPv6 prefix (e.g., "2001:db8:abcd:0012::/64").
        subnet (str): The IPv6 subnet (e.g., "2001:db8:abcd::/48").

    Returns:
        bool: True if the prefix is within the subnet, False otherwise.
    """
    prefix_network = ip_network(unicode(prefix), strict=False)
    subnet_network = ip_network(unicode(subnet), strict=False)
    return prefix_network.subnet_of(subnet_network) 

def cleanup():
    #arpapi.clear_arp_table(globalVars.D1)    
    st.config(globalVars.D1, "sonic-clear arp") 
    bgpapi.cleanup_bgp_config([globalVars.D1, globalVars.D2],cli_type="vtysh")
    for dut in [globalVars.D1, globalVars.D2]: 
        ipapi.clear_ip_configuration(dut)

    st.log(" Remove route-map " )
    for dut in [globalVars.D1, globalVars.D2]:
        ipapi.config_route_map(dut, route_map='FROM_BGP_PEER_V6', config='no', sequence='1')


    tg.clean_all()

    st.log("clean up core/dump logs before testing")
    for dut in [globalVars.D1, globalVars.D2]: 
        st.config(dut, "sudo rm -rf /var/core/*")
        st.config(dut, "sudo rm -rf /var/dump/*")

def bgp_scale_postcheck(dut,scale_number):
    error=0 

    #import pdb; pdb.set_trace() 
    out1=st.config(dut, "sudo ls -al /var/core")
    out2=st.config(dut, "sudo ls -al /var/dump")
    #st.collect_core_files(dut, 'core_file') 

    out_npu_route_table=st.config(dut, "sudo sudo show platform npu router route-table") 

    vty_bgp_sum = st.vtysh_show(dut,"show bgp summary") 
    for bgp_nbr in vty_bgp_sum:
        if bgp_nbr['neighbor'] == '192.168.0.2':
            if int(bgp_nbr['state'])!=int(scale_number) or int(bgp_nbr['pfxsnt'])!=int(scale_number):
                error+=1 
                st.error("Prefix route sent/received is not {}".format(scale_number)) 

    return error 

def tg_preconfig():
    global tg, tg1, tg2, tg_ph_1, tg_ph_2, tg_handler
    tg_handler = tgapi.get_handles(globalVars, [globalVars.T1D1P1, globalVars.T1D2P1])
    tg = tg_handler["tg"]
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")


    #Resetting the ports on TGEN
    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])


def configureBgpSonic(dut1, dut2, d1_as, d2_as, dut1_interface, dut2_interface, i1_ipaddress, i2_ipaddress, mask, family):
    #Configuring IP Addresses between D1 & D2
    ipapi.config_ip_addr_interface(dut1, dut1_interface, i1_ipaddress, mask, family=family, config='add')
    ipapi.config_ip_addr_interface(dut2, dut2_interface, i2_ipaddress, mask, family=family, config='add')
    st.wait(10) 
    result = ipapi.ping(dut1, i2_ipaddress, family)
    if not result: 
        st.report_fail("msg", "IPv6 Ping Failed")
        cleanup()
    #Configuring BGP between D1 & D2
    bgpapi.create_bgp_neighbor(dut1, d1_as, i2_ipaddress, d2_as, family=family)
    bgpapi.create_bgp_neighbor(dut2, d2_as, i1_ipaddress, d1_as, family=family)

    if not poll_wait(bgpapi.verify_bgp_summary, 90, dut1, shell='vtysh',family=family, neighbor= i2_ipaddress, state="Established"):
        st.log("Failed to form BGP neighborship")
        st.report_fail("test_case_failed")
        cleanup()

def configureBGP_with_TGEN(family, dut1, tgen_port_handle, dut_interface, dut_ipaddress, tgen_ipaddress, dut_as, tgen_as, src_mac_addr, prefixlength=64):
    #Configuring IP Address on TGEN towards DUT
    if family == "ipv4":
        ip_version = '4'
    elif family == "ipv6":
        ip_version = '6'
    tg.tg_traffic_control(action='reset', port_handle=tgen_port_handle)
    if family == "ipv4":
        res1=tg.tg_interface_config(port_handle=tgen_port_handle, mode='config', intf_ip_addr=tgen_ipaddress,gateway=dut_ipaddress,src_mac_addr=src_mac_addr, arp_send_req='1')
        st.log("INTFCONF: "+str(res1))
    elif family == "ipv6":
        res1=tg.tg_interface_config(port_handle=tgen_port_handle, mode='config', ipv6_intf_addr=tgen_ipaddress,ipv6_gateway=dut_ipaddress, ipv6_prefix_length=prefixlength,src_mac_addr=src_mac_addr, arp_send_req='1')
        st.log("INTFCONF: "+str(res1))

    #Configuring IP Address on DUT towards TGEN
    ipapi.config_ip_addr_interface(dut1, dut_interface, dut_ipaddress ,prefixlength, family=family, config='add')

    st.wait(15) 

    #Ping Validation
    result = ipapi.ping(dut1, tgen_ipaddress, family)
    if not result: 
        st.report_fail("msg", "{} Ping Failed".format(family))
        cleanup()

    bgp_rtr1 = tg.tg_emulation_bgp_config(handle=res1['handle'], mode='enable', active_connect_enable='1',ip_version=ip_version,local_as=tgen_as, remote_as=dut_as, remote_ipv6_addr=dut_ipaddress, enable_4_byte_as='1', graceful_restart_enable='1')
    tg.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')

    #BGP Configuration
    st.banner("Configuring BGP On DUT")
    bgpapi.create_bgp_neighbor(dut1, dut_as, tgen_ipaddress, tgen_as,family=family)
    if not poll_wait(bgpapi.verify_bgp_summary, 90, dut1, shell='vtysh',family=family, neighbor= tgen_ipaddress, state="Established"):
        st.log("Failed to form BGP neighborship")
        st.report_fail("test_case_failed")
        cleanup()
    return res1, bgp_rtr1


@pytest.mark.usefixtures('bgp_cleanup') 
def test_bgp_v4_prefix_scale():

    fail=0 
    st.log("## Test BGP IPv4 Prefix Scale number "+str(bgp_data.max_bgp_ipv4_peer)) 

    #Configuring IP Addresses between D1 & D2
    dict1 = {'interface_name': globalVars.D1D2P1, 'ip_address': bgp_data.D1D2P1, 'subnet': bgp_data.ipv4_mask, 'family': "ipv4", 'config': "add"}
    dict2 = {'interface_name': globalVars.D2D1P1, 'ip_address': bgp_data.D2D1P1, 'subnet': bgp_data.ipv4_mask, 'family': "ipv4", 'config': "add"}
    parallel.exec_parallel(True, data.DUTs, ipapi.config_ip_addr_interface, [dict1, dict2])
    result = ipapi.ping(globalVars.D1, bgp_data.D2D1P1)
    if not result: 
        st.report_fail("test_case_failed")
    #Configuring IP Address on T1 towards D1
    res1=tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=IPRange[1],gateway=IPRange[0], src_mac_addr='00:0a:01:00:12:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res1))

    #Configuring IP Address on D1 towards T1
    ipapi.config_ip_addr_interface(globalVars.D1, globalVars.D1T1P1, IPRange[0] ,bgp_data.ipv4_mask)

    #Ping Validation
    result = ipapi.ping(globalVars.D1, IPRange[1])
    if not result: 
        st.report_fail("msg", "IPv4 Ping Failed")

    #Configuring IP Address on T2 towards D2
    res2=tg.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=bgp_data.T1D2P1,gateway=bgp_data.D2T1P1, src_mac_addr='00:0a:01:00:12:02', arp_send_req='1')
    st.log("INTFCONF: "+str(res2))

    #Configuring IP Address on D2 towards T2
    ipapi.config_ip_addr_interface(globalVars.D2, globalVars.D2T1P1, bgp_data.D2T1P1 ,bgp_data.ipv4_mask)
    
    #Ping Validation
    result = ipapi.ping(globalVars.D2, bgp_data.T1D2P1)
    if not result: 
        st.report_fail("msg", "IPv4 Ping Failed")
    
    #Configuring BGP between D1 & D2
    bgpapi.create_bgp_neighbor(globalVars.D1, "65100", bgp_data.D2D1P1, "65300")
    bgpapi.create_bgp_neighbor(globalVars.D2, "65300", bgp_data.D1D2P1, "65100")

    if not poll_wait(bgpapi.verify_bgp_summary, 90, globalVars.D1, shell='vtysh',family='ipv4', neighbor= bgp_data.D2D1P1, state="Established"):
            st.log("Failed to form BGP neighborship")
            st.report_fail("test_case_failed")
    
    #Configuring BGP between B1 & T1

    bgp_rtr1 = tg.tg_emulation_bgp_config(handle=res1['handle'], mode='enable', active_connect_enable='1',ip_version='4',local_as="65200", remote_as="65100", remote_ip_addr=IPRange[0], enable_4_byte_as='1', graceful_restart_enable='1')
    tg.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')

    st.banner("Configuring BGP On DUT1")
    bgpapi.create_bgp_neighbor(globalVars.D1, "65100", IPRange[1], "65200")
    bgpapi.config_bgp_neighbor_properties(globalVars.D1, "65100", IPRange[1], config='yes', no_form='no', enforce_first_as = '')

    if not poll_wait(bgpapi.verify_bgp_summary, 90, globalVars.D1, shell='vtysh',family='ipv4', neighbor= IPRange[1], state="Established"):
        st.log("Failed to form BGP neighborship")
        st.report_fail("test_case_failed")
        cleanup()

    #Configuring BGP between B2 & T2
    st.banner("Configuring BGP On DUT2")
    bgpapi.create_bgp_neighbor(globalVars.D2, "65300", bgp_data.T1D2P1, "65400")
    bgpapi.config_bgp_neighbor_properties(globalVars.D2, "65300", bgp_data.T1D2P1,config='yes', no_form='no', enforce_first_as = '')

    st.banner("Configuring BGP On T2")
    bgp_rtr2 = tg.tg_emulation_bgp_config(handle=res2['handle'], mode='enable', active_connect_enable='1',ip_version='4',local_as="65400", remote_as="65300", remote_ip_addr=bgp_data.D2T1P1, enable_4_byte_as='1', graceful_restart_enable='1' )
    tg.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(5)
    #BGP Verification
    if not poll_wait(bgpapi.verify_bgp_summary, 90, globalVars.D2, shell='vtysh',family='ipv4', neighbor= bgp_data.T1D2P1, state="Established"):
        st.log("Failed to form BGP neighborship")
        st.report_fail("test_case_failed")
        cleanup()
    #Prefix advertisement from TGEN towards D1
    st.banner("Prefix advertisement from TGEN towards D1")
    #bgp_route = tg.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes='250000',prefix='172.168.1.0')
    bgp_route = tg.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes=bgp_data.max_bgp_ipv4_prefix,prefix='172.168.1.1', netmask="32",as_path='as_seq:1')

    tg.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(120)
    # Verify Routes
    st.log("Verify the prefix on D1")
    #st.log("Verify the prefix on both DUTs 
    #for dut in [globalVars.D1, globalVars.D2]:
    #    out_route_sum[dut] = ipapi.show_ip_route(dut) 

    show_output = ipapi.show_ip_route(globalVars.D1)
    received_prefixes=[]
    for entry in show_output:
        if entry['nexthop']=='192.168.0.2':
            received_prefixes.append(entry['ip_address'])

    if not len(received_prefixes) == bgp_data.max_bgp_ipv4_prefix:
        msg="Prefix advertisement Failed: Prefixes is {}, not {}".format(len(received_prefixes),bgp_data.max_bgp_ipv4_prefix)
        st.report_fail("msg",msg)
    else:
        st.log("All prefixes were advertised")

    vtysh_bgp_sum = st.vtysh_show(globalVars.D1,"show bgp summary") 

    for i, dut in enumerate([globalVars.D1, globalVars.D2]): 
        if bgp_scale_postcheck(dut,bgp_data.max_bgp_ipv4_prefix):
            st.error('BGP Post check Failed')
            fail+=1

    st.log("## Configure Traffic Stream on  TGEN port T2 towards Prefix ##") 
    tr2 = tg.tg_traffic_config(port_handle=tg_ph_2,emulation_src_handle=res2['handle'],emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv4',mode='create', high_speed_result_analysis='0',  transmit_mode='continuous', rate_percent=95, enable_stream_only_gen=0)
    stream_id2 = tr2['stream_id']

    #Running the Streamblock
    tg.tg_traffic_control(action='run', stream_handle=stream_id2)

    #Waiting for 10 seconds
    st.tg_wait(10)

    #Stopping the Stream
    tg.tg_traffic_control(action='stop', stream_handle=stream_id2)

    #Gathering received packets on TGEN-tg1
    st.banner("Gathering received packets on TGEN-tg1")
    tg_rx = tgapi.get_traffic_stats(tg, port_handle=tg_ph_1)

    #Gathering sent packets on TGEN-tg2
    st.banner("Gathering sent packets on TGEN-tg2")
    tg_tx = tgapi.get_traffic_stats(tg, port_handle=tg_ph_2)
    st.log('tg1_stats.rx.total_packets : {}'.format(tg_rx.rx.total_packets))
    st.log('tg2_stats.tx.total_packets : {}'.format(tg_tx.tx.total_packets))

    #Calculation of Percent rx
    st.banner("Calculation of Percent rx")
    percent_rx = float(int(tg_rx.rx.total_packets) - int(tg_tx.tx.total_packets)) / int(tg_tx.tx.total_packets) * 100
    st.log('percent_rx : {}'.format(percent_rx))
    if int(tg_rx.rx.total_packets) < int(tg_tx.tx.total_packets)*0.95:
        st.report_fail("msg","traffic_verification_failed")
        fail+=1 

    if fail:
        st.report_fail('msg','ipv4 prefix scale test case failed')
    else: 
        st.report_pass('test_case_passed')

@pytest.mark.usefixtures('bgp_cleanup') 
def test_bgp_v6_prefix_scale():
    
    fail=0 

    #Configuring IP Addresses between D1 & D2
    ipapi.config_ip_addr_interface(globalVars.D1, globalVars.D1D2P1, bgp_data.v6D1D2P1, bgp_data.ipv6_mask, family="ipv6", config='add')
    ipapi.config_ip_addr_interface(globalVars.D2, globalVars.D2D1P1, bgp_data.v6D2D1P1, bgp_data.ipv6_mask, family="ipv6", config='add')
    result = ipapi.ping(globalVars.D1, bgp_data.v6D2D1P1, "ipv6")
    if not result: 
        st.report_fail("msg", "IPv6 Ping Failed")
    
    #Configuring IP Address on T1 towards D1
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    res1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=bgp_data.v6T1D1P1,ipv6_gateway=bgp_data.v6D1T1P1, ipv6_prefix_length="64",src_mac_addr='00:0a:01:00:12:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res1))

    #Configuring IP Address on D1 towards T1
    ipapi.config_ip_addr_interface(globalVars.D1, globalVars.D1T1P1, bgp_data.v6D1T1P1 ,bgp_data.ipv6_mask, family="ipv6", config='add')

    #Ping Validation
    result = ipapi.ping(globalVars.D1, bgp_data.v6T1D1P1, "ipv6")
    if not result: 
        st.report_fail("msg", "IPv4 Ping Failed")

    #Configuring IP Address on T2 towards D2
    res2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=bgp_data.v6T1D2P1,ipv6_gateway=bgp_data.v6D2T1P1, ipv6_prefix_length="64", src_mac_addr='00:0a:01:00:12:02', arp_send_req='1')
    st.log("INTFCONF: "+str(res2))

    #Configuring IP Address on D2 towards T2
    ipapi.config_ip_addr_interface(globalVars.D2, globalVars.D2T1P1, bgp_data.v6D2T1P1 ,bgp_data.ipv6_mask, family="ipv6", config='add')
    
    #Ping Validation
    result = ipapi.ping(globalVars.D2, bgp_data.v6T1D2P1, "ipv6")
    if not result: 
        st.report_fail("msg", "IPv6 Ping Failed")

    st.log("## Create route-map ##")  
    for dut in [globalVars.D1, globalVars.D2]: 
        ipapi.config_route_map(dut, route_map='FROM_BGP_PEER_V6', config='yes', sequence='1')
        ipapi.config_route_map_global_nexthop(dut, route_map='FROM_BGP_PEER_V6', sequence='1', config='yes')
    #Configuring BGP between D1 & D2
    bgpapi.create_bgp_neighbor(globalVars.D1, "65100", bgp_data.v6D2D1P1, "65300", family="ipv6")
    bgpapi.create_bgp_neighbor(globalVars.D2, "65300", bgp_data.v6D1D2P1, "65100", family="ipv6")
    bgpapi.config_bgp(dut = globalVars.D1, local_as='65100', neighbor =bgp_data.v6D2D1P1, addr_family ='ipv6',config = 'yes', config_type_list =["routeMap"], routeMap ='FROM_BGP_PEER_V6', diRection='in')
    bgpapi.config_bgp(dut = globalVars.D1, local_as='65100', neighbor =bgp_data.v6D2D1P1, addr_family ='ipv6',config = 'yes', config_type_list =["allowas_in"], allowas_in ='1')

    bgpapi.config_bgp(dut = globalVars.D2, local_as='65300', neighbor =bgp_data.v6D1D2P1, addr_family ='ipv6',config = 'yes', config_type_list =["routeMap"], routeMap ='FROM_BGP_PEER_V6', diRection='in')
    bgpapi.config_bgp(dut = globalVars.D2, local_as='65300', neighbor =bgp_data.v6D1D2P1, addr_family ='ipv6',config = 'yes', config_type_list =["allowas_in"], allowas_in ='1')


    if not poll_wait(bgpapi.verify_bgp_summary, 90, globalVars.D1, shell='vtysh',family='ipv6', neighbor= bgp_data.v6D2D1P1, state="Established"):
            st.log("Failed to form BGP neighborship")
            st.report_fail("test_case_failed")
    bgpapi.config_bgp(dut = globalVars.D1, local_as='65100', neighbor =bgp_data.v6D2D1P1, addr_family ='ipv6',config = 'yes', config_type_list =["routeMap"], routeMap ='FROM_BGP_PEER_V6', diRection='in')
    

    #Configuring BGP between B1 & T1
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=res1['handle'], mode='enable', active_connect_enable='1',ip_version='6',local_as="65200", remote_as="65100", remote_ipv6_addr=bgp_data.v6D1T1P1, enable_4_byte_as='1', graceful_restart_enable='1')

    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.banner("Configuring BGP On DUT1")
    bgpapi.create_bgp_neighbor(globalVars.D1, "65100", bgp_data.v6T1D1P1, "65200", family="ipv6")
    bgpapi.config_bgp_neighbor_properties(globalVars.D1, "65100", bgp_data.v6T1D1P1, config='yes', no_form='no', enforce_first_as = '')
    bgpapi.config_bgp(dut = globalVars.D1, local_as='65100', neighbor =bgp_data.v6T1D1P1, addr_family ='ipv6',config = 'yes', config_type_list =["routeMap"], routeMap ='FROM_BGP_PEER_V6', diRection='in')
    bgpapi.config_bgp(dut = globalVars.D1, local_as='65100', neighbor =bgp_data.v6T1D1P1, addr_family ='ipv6',config = 'yes', config_type_list =["allowas_in"], allowas_in ='1')

    if not poll_wait(bgpapi.verify_bgp_summary, 90, globalVars.D1, shell='vtysh',family='ipv6', neighbor= "1093:2:1::2", state="Established"):
        st.log("Failed to form BGP neighborship")
        st.report_fail("test_case_failed")

    #Configuring BGP between B2 & T2
    st.banner("Configuring BGP On DUT2")
    bgpapi.create_bgp_neighbor(globalVars.D2, "65300", bgp_data.v6T1D2P1, "65400", family="ipv6")
    bgpapi.config_bgp_neighbor_properties(globalVars.D2, "65300", bgp_data.v6T1D2P1,config='yes', no_form='no', enforce_first_as = '')
    bgpapi.config_bgp(dut = globalVars.D2, local_as='65300', neighbor =bgp_data.v6T1D2P1, addr_family ='ipv6',config = 'yes', config_type_list =["routeMap"], routeMap ='FROM_BGP_PEER_V6', diRection='in')
    bgpapi.config_bgp(dut = globalVars.D2, local_as='65300', neighbor =bgp_data.v6T1D2P1, addr_family ='ipv6',config = 'yes', config_type_list =["allowas_in"], allowas_in ='1')

    st.banner("Configuring BGP On T2")
    bgp_rtr2 = tg2.tg_emulation_bgp_config(handle=res2['handle'], mode='enable', active_connect_enable='1',ip_version='6',local_as="65400", remote_as="65300", remote_ipv6_addr=bgp_data.v6D2T1P1, enable_4_byte_as='1', graceful_restart_enable='1' )
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(5)

    #BGP Verification
    if not poll_wait(bgpapi.verify_bgp_summary, 90, globalVars.D2, shell='vtysh',family='ipv6', neighbor= bgp_data.v6T1D2P1, state="Established"):
        st.report_fail("msg","test_case_failed due to failing to form BGP neighborship")

    #Prefix advertisement from TGEN towards D1
    st.banner("Prefix advertisement from TGEN towards D1")
    bgp_route = tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes=bgp_data.max_bgp_ipv6_prefix,prefix='67fe:1:1::1', ip_version='6',as_path='as_seq:1')
    #bgp_route = tg.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes=5, prefix='67fe:1:1::1', ipv6_prefix_length="64", ip_version='6',as_path='as_seq:1')

    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')

    st.wait(120)
    # Verify Routes
    st.log("Verify the prefix on D1")
    show_output = ipapi.show_ip_route(globalVars.D1, "ipv6")
    received_prefixes=[]
    for entry in show_output:
        st.log(entry) 

        if entry['nexthop']=='1093:2:1::2' or is_prefix_in_subnet(entry['ip_address'],"67fe:1:1::1/48"):
            received_prefixes.append(entry['ip_address'])

    if len(received_prefixes) != bgp_data.max_bgp_ipv6_prefix:
        st.log("Prefixes advertised {} ".format(len(received_prefixes))) 
        st.report_fail("test_case_failed")
    else:
        st.log("All prefixes were advertised")

    for i, dut in enumerate([globalVars.D1, globalVars.D2]):
        if bgp_scale_postcheck(dut,bgp_data.max_bgp_ipv6_prefix):
            st.error('BGP Post check Failed')
            fail+=1

    #Configuring Traffic Stream on  TGEN port T2 towards Prefix
    #tr2 = tg2.tg_traffic_config(port_handle=tg_ph_2,emulation_src_handle=res2['handle'],emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6',mode='create', high_speed_result_analysis='0',  transmit_mode='continuous', rate_percent=95)
    #import pdb; pdb.set_trace() 
    st.log("## Configure Traffic Stream on  TGEN port T2 towards Prefix ##")
    tr2 = tg.tg_traffic_config(port_handle=tg_ph_2,emulation_src_handle=res2['handle'],emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6',mode='create', high_speed_result_analysis='0',  transmit_mode='continuous', rate_percent=95, l3_protocol='ipv6',enable_stream_only_gen=0)

    
    stream_id2 = tr2['stream_id']

    #Running the Streamblock
    tg2.tg_traffic_control(action='run', stream_handle=stream_id2)

    #Waiting for 10 seconds
    st.tg_wait(10)

    #import pdb; pdb.set_trace() 
    #Stopping the Stream
    tg2.tg_traffic_control(action='stop', stream_handle=stream_id2)

    st.wait(10) 

    #Gathering received packets on TGEN-tg1
    st.banner("Gathering received packets on TGEN-tg1")
    tg_rx = tgapi.get_traffic_stats(tg, port_handle=tg_ph_1)

    #Gathering sent packets on TGEN-tg2
    st.banner("Gathering sent packets on TGEN-tg2")
    tg_tx = tgapi.get_traffic_stats(tg, port_handle=tg_ph_2)
    st.log('tg1_stats.rx.total_packets : {}'.format(tg_rx.rx.total_packets))
    st.log('tg2_stats.tx.total_packets : {}'.format(tg_tx.tx.total_packets))

    #Calculation of Percent rx
    st.banner("Calculation of Percent rx")
    percent_rx = float(int(tg_rx.rx.total_packets) - int(tg_tx.tx.total_packets)) / int(tg_tx.tx.total_packets) * 100
    st.log('percent_rx : {}'.format(percent_rx))
    if int(tg_rx.rx.total_packets) < int(tg_tx.tx.total_packets)*0.95:
        st.report_fail("traffic_verification_failed")
        cleanup()
    st.log("Test case test_bgp_scale passed")
    st.report_pass('test_case_passed')

