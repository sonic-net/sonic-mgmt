''' This script is for optics testing on a testbed with iBGP enabled between the two DUTs.
        EBGP will be created by the script. 
    Test Cases: 
        test_repeated_interface_flaps --Test interface flapping (local DUT and remote DUT)
        test_restart_docker_process -- Test restart docker process ("pmon","swss","syncd","gbsyncd")        
        Test_reload: Reload testing (6 test cases)                 
''' 
import pytest
import json
import yaml
import re, time, os
import sys, shutil
from os.path import join, split,normpath
from spytest import st,tgapi
from spytest.dicts import SpyTestDict
from spytest.tgen.tg import tgen_obj_dict
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
from spytest.access.connection import DeviceFileUpload, DeviceConnection,DeviceFileDownload
from apis.system.basic import get_docker_ps, get_and_match_docker_count, verify_docker_status
from utilities import parallel
from utilities.common import poll_wait
from datetime import datetime, timedelta
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.system.interface as intapi
import apis.switching.portchannel as poapi
import apis.system.basic as basic_obj
import apis.common.checks as common_obj
import apis.system.connection as conn_obj
import apis.system.reboot as rebootapi  
import apis.system.logging as logger
from utilities.common import poll_wait
from apis.system.interface import interface_status_show, show_interfaces_counters
#import apis.system.multi_asic as SonicHooks
from apis.common.sonic_hooks import SonicHooks 
import apis.system.logging as logapi
import apis.system.port as papi  
import apis.system.box_services as  boxapi

@pytest.fixture(scope="module", autouse=True)
def optics_module_hooks(request):
    global globalVars
    globalVars = st.get_testbed_vars()
    global data
    data = SpyTestDict()

    initialize_data() 

    data.dut_list = [globalVars.D1, globalVars.D2]  

    data.username = st.get_username(globalVars.D1)
    data.password = st.get_password(globalVars.D1)

    data.ssh_port = "22"
    data.destination_path = "/home/cisco"
    data.lc0_mgmt_ip = st.get_mgmt_ip(globalVars.D1)
    data.lc1_mgmt_ip = st.get_mgmt_ip(globalVars.D2)

    if is_multi_asic: 
        data.rp_mgmt_ip=st.get_rp_ip_address(globalVars.D1)
        data.dut_mgmt_list=[data.lc0_mgmt_ip,data.lc1_mgmt_ip,data.rp_mgmt_ip] 
        data.lc_mgmt_ip_list = [data.lc0_mgmt_ip,data.lc1_mgmt_ip]  
        data.asics_list=sonichooks.get_asic_namespace_list(globalVars.D1)  
    else: 
        data.dut_mgmt_list=[data.lc0_mgmt_ip,data.lc1_mgmt_ip] 

    data.key_devices = [globalVars.D1,globalVars.D2]
    data.allDUTs = [globalVars.D1,globalVars.D2]
    data.DUTs = [globalVars.D1,globalVars.D2]
    data.lc_name_list = [globalVars.D1,globalVars.D2]

    data.corresponding_mgmt_ip_to_dut_name = {}
    data.corresponding_dut_name_to_mgmt_ip = {}
    for dut in data.dut_list:
        mgmt_ip = st.get_mgmt_ip(dut)
        data.corresponding_mgmt_ip_to_dut_name[dut]=mgmt_ip
        data.corresponding_dut_name_to_mgmt_ip[mgmt_ip] = dut
    data.slot_name = {}
    data.slot_name[globalVars.D1] = 0
    data.slot_name[globalVars.D2] = 3  
    data.expected_down_dockers = ['sflow','nat']

    #To ensure all connections are up in our topology
    st.ensure_min_topology("D1T1:1","D1D2:1","D2T1:1")

    generate_addresses() 

    #Interface between D1(LC0) & T1
    data.d1t1_ip_addr="200.200.1.1"

    #Interface between TGEN & D1(LC0)
    data.t1d1_ip_addr="200.200.1.2"


    #Interface between TGEN & D2(LC3) 
    data.t1d2_ip_addr="200.100.1.2"

    #Interface between D2(LC3) & TGEN
    data.d2t1_ip_addr="200.100.1.1"

    #Setting subnetmask to /24
    data.mask="24"

    #DUT1(LC0) AS Number
    #data.dut_asn_list[dut1] = "65100"

    data.dut_asn_list={dut1:"65100",dut2:"65103"} 

    #TGEN Port1 AS number
    data.tgen1_asn = "65200"

    #TGEN Port2 AS Number
    data.tgen2_asn = "65203"

    data.pc1 =  "PortChannel152" 

    global tg1,tg2, tg_handle_1, tg_handle_2 
    (tg1,tg2, tg_handle_1, tg_handle_2) = get_handles()

    tg1.clean_all()
    tg2.clean_all()


    if not dut_bgp_ip_cleanup():
        st.report_fail("test_case_failed")

    time.sleep(15) 

    try: 
        ip_base_config()
        bgp_base_config()  
    except Exception as e: 
        st.error("IP/BGP Configuration Failed: "+str(e)) 
        st.report_fail("test_case_failed")

    st.log("Clear interface counters") 
    papi.clear_interface_counters(globalVars.D1)
    papi.clear_interface_counters(globalVars.D2)

    yield 
    tg1.clean_all()
    tg2.clean_all() 

    if dut_bgp_ip_cleanup(): 
        st.report_pass("test_case_passed")
    else: 
        st.report_fail("test_case_failed")


def dut_bgp_ip_cleanup(): 

    try:
        st.log("## Delete EBGP Neighbors ##")
        if is_multi_asic: 
            for i, link in enumerate(local_links_dut1):
                addr1=data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"]
                addr2=data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]
                asic_ns1=intf_ns1[globalVars.get("D1D2P{}".format(i+1))]
                asic_ns2=intf_ns2[globalVars.get("D2D1P{}".format(i+1))]

                neighbor1=bgpapi.show_bgp_ipv4_neighbor_vtysh(dut1, addr2,cli_type='vtysh-multi-asic',asic=asic_ns1.lstrip('asic'))   

                if not neighbor1: 
                    bgpapi.delete_bgp_neighbor(dut1, data.dut_asn_list[dut1], addr2, data.dut_asn_list[dut2], 'default', "vtysh-multi-asic", True, asic=asic_ns1.lstrip('asic'))

                neighbor2=bgpapi.show_bgp_ipv4_neighbor_vtysh(dut2, addr1,cli_type='vtysh-multi-asic',asic=asic_ns2.lstrip('asic'))
                if not neighbor2:
                    bgpapi.delete_bgp_neighbor(dut2, data.dut_asn_list[dut2], addr1,data.dut_asn_list[dut1], 'default', "vtysh-multi-asic", True, asic=asic_ns2.lstrip('asic'))


            st.log("### Delete EBGP between TGEN and D1/D2 ##") 

            neighbor3=bgpapi.show_bgp_ipv4_neighbor_vtysh(dut1, data.t1d1_ip_addr,cli_type='vtysh-multi-asic',asic=intf_ns1[globalVars.get("D1T1P1")].lstrip('asic'))
            if not neighbor3:

                bgpapi.delete_bgp_neighbor(dut1,data.dut_asn_list[dut1], data.t1d1_ip_addr,data.tgen1_asn,'default', "vtysh-multi-asic", True, asic=intf_ns1[globalVars.get("D1T1P1")].lstrip('asic'))
            neighbor4=bgpapi.show_bgp_ipv4_neighbor_vtysh(dut2, data.t1d2_ip_addr,cli_type='vtysh-multi-asic',asic=intf_ns2[globalVars.get("D2T1P1")].lstrip('asic'))
            if not neighbor4:
                bgpapi.delete_bgp_neighbor(dut2,data.dut_asn_list[dut2], data.t1d2_ip_addr,data.tgen2_asn,'default', "vtysh-multi-asic", True, asic=intf_ns2[globalVars.get("D2T1P1")].lstrip('asic'))

            ipapi.clear_ip_configuration(data.lc_name_list, cli_type='vtysh-multi-asic')
        else: 
            for i, link in enumerate(local_links_dut1):
                addr1=data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"]
                addr2=data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]
                bgpapi.cleanup_bgp_config(data.dut_list)

            ipapi.clear_ip_configuration(data.lc_name_list)

    except Exception as e:
        st.error('Failed with: '+str(e))
        return False  

    return True 


def generate_addresses():

    for i, link in enumerate(local_links_dut1):
        name=data.local_links_info["D1D2P{}".format(i+1)]["name"] 
        n=name.lstrip("Ethernet") 

        data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"]="100.100."+str(n)+".1"
        data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]="100.100."+str(n)+".2"
        data.local_links_info["D1D2P{}".format(i+1)]["ipv6addr"]="2012:"+str(n)+"::1"
        data.local_links_info["D2D1P{}".format(i+1)]["ipv6addr"]="2012:"+str(n)+"::2"

    data.d1t1_ip_addr = "200.200.1.1"
    data.d2t1_ip_addr = "200.100.1.1"
    data.t1d1_ip_addr = "200.200.1.2"
    data.t1d2_ip_addr = "200.100.1.2"

    data.d1t1_ip_addr_v6 = "2011::1"
    data.d2t1_ip_addr_v6 = "2013::1"
    data.static_ipv6_list = ["2011::0/64","2013::0/64","2014::0/64","2015::0/64"]
    data.mask_v6 = "64"

def initialize_data():
    global dut1, dut2, local_links_dut1, local_links_dut2, no_local_links, sonichooks
    sonichooks=SonicHooks() 

    platform_type=get_platform()

    dut1 = data.dut_list[0]
    dut2 = data.dut_list[1]
    local_links_dut1=st.get_dut_links_local(dut1)
    local_links_dut2=st.get_dut_links_local(dut2)
    global is_multi_asic, cli_type 
    is_multi_asic=sonichooks.is_multi_asic(dut1) 
    if is_multi_asic: 
        cli_type='vtysh-multi-asic'  
    else:
        cli_type='click' 

    no_local_links=len(local_links_dut1)

    data.local_links_info={}

    tgen_ports=[]

    for k,v in globalVars.items():
        if v in local_links_dut1 or v in local_links_dut2:
            data.local_links_info[k]={'name':v}

        elif re.search('T[1|2]D[1|2]P1',k) or re.search('D[1|2]T[1|2]P1',k):
            tgen_ports.append(k)

    for port in tgen_ports:
        for i in range(len(local_links_dut1)):
            key=port.split('P')[0]+'P'+str(i+1)
            data.local_links_info[key]={'name': port}

    data.local = None
    data.remote = None
    data.mask = "24"
    data.mask_v6 = "64"

    data.counters_threshold = 10
    data.tgen_stats_threshold = 20
    data.tgen_rate_pps = '1000'
    data.tgen_l3_len = '500'
    data.traffic_run_time = 20
    data.clear_parallel = True

    global PORT_STATUS_REGEX, FEC_STATUS_REGEX, XCVRD_COMM
    PORT_STATUS_REGEX = ["NOTICE swss.*#orchagent: :- doPortTask: Set port {} admin status to down",
"NOTICE swss.*#orchagent: :- updatePortOperStatus: Port {} oper state set from up to down",
"NOTICE swss.*#orchagent: :- setHostIntfsOperStatus: Set operation status DOWN to host interface {}",
"NOTICE swss.*#portsyncd: :- onMsg: Publish {}.* to state db",
"NOTICE swss.*#portmgrd: :- doTask: Configure {} admin status to up"]

    FEC_STATUS_REGEX= ["NOTICE swss.*#orchagent: :- doPortTask: Set port {} fec to none"]

    AUTO_NEGO_REGEX= ["doPortTask: Set port {} admin status to up",
"NOTICE swss.*#orchagent: :- doPortTask: Set port {} AutoNeg to 0"]

    XCVRD_COMM = "sudo docker exec -it pmon ps eaf | grep xcvrd"

    if is_multi_asic: 
        global intf_ns1, intf_ns2
        intf_ns1_all=sonichooks.get_all_interfaces_on_all_namespaces(dut1)
        intf_ns1, intf_ns2={}, {}


        for ns, intfs in intf_ns1_all.items():
            for intfs_info in intfs:
                intf_ns1[intfs_info.get("interface")]=ns

        intf_ns2_all=sonichooks.get_all_interfaces_on_all_namespaces(dut2)
        for ns, intfs in intf_ns2_all.items():
            for intfs_info in intfs:
                intf_ns2[intfs_info.get("interface")]=ns

def get_platform():
    global globalVars, data, cli_type, is_sfd_system

    global rp_list, lc_list

    globalVars =st.get_testbed_vars()

    data = SpyTestDict()

    data.dut_list = st.get_dut_names()

    rp_list = []
    lc_list = []
    for plat in globalVars.hwsku:
        if 'rp' in globalVars.hwsku[plat].lower():
            rp_list.append(plat)
        elif 'lc' in globalVars.hwsku[plat].lower():
            lc_list.append(plat)

    if rp_list == [] and lc_list == []:
        is_sfd_system=False

        lc_list=data.dut_list
        rp_list=data.dut_list

        return "Non-SF-D"
    else:
        is_sfd_system=True

        return "SF-D"

def validate_docker_status(dut,time_out=240,validate_docker_count=True):
    result = True
    if not poll_wait(verify_docker_status, time_out, dut, 'Exited'):
        st.error("Post reload, dockers are not auto recovered.")
        output = st.show(dut,'docker ps -a')
        for line in output:
            if ('Exited' in line['status']) and (line['names'] not in data.expected_down_dockers):
                result = False

    if result and validate_docker_count:
        if not poll_wait(get_and_match_docker_count, time_out, dut, data.dockers_count[dut]):
            st.error("Post reload, ALL dockers are not UP.")
            result = False

    if not result:
        st.log("Test Failed: So recovering the device by reboot.")

    return result

def source_frr():
    for i, dut in enumerate([dut1, dut2]):
        device_ip = data.corresponding_mgmt_ip_to_dut_name[dut]
        ssh_con = connect_to_device(data.lc_mgmt_ip_list[i],data.username,data.password)

        for asic_no in range(len(data.asics_list)):
            st.log("sourcing frr_cfg file") 
            command="source /home/cisco/configdb-gen/frr_cfg"+str(asic_no)+".sh" 
            output=execute_command(ssh_con, command) 
            st.config(dut, command) 


    st.banner("Sleeping for 30 seconds for interfaces to come up")
    for dut in data.dut_list:
        validate_docker_status(dut,time_out=40,validate_docker_count=False)

    st.show(globalVars.D1, "show ip bgp summary")

    st.show(globalVars.D2, "show ip bgp summary")

def ping_neighbor(dut,address,count=10,size=56,asic=None):
    if asic:
        command = "sudo ip netns exec {} ping {} -c {} -s {} -M do -i 0 ".format(asic,address, count, size) 
    else:
        command = "sudo ping -c {} {} -i 0 -s {} -M do".format(count,address,size)

    return st.config(dut, command) 

def parse_ping_output(ping_output): 
    import re 
    match=re.findall('([\d]+) +packets transmitted.*([\d]+) +received.*([\d]+)% +packet loss.*time ([\w]+)',ping_output)

    if match: 
        return (100-int(match[0][2])) 
    else:
        return False 

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)


def ip_base_config(interface_list1=[],interface_list2=[]):

    if not interface_list1 and not interface_list2: 
        interface_list1=local_links_dut1
        interface_list2=local_links_dut2 

    st.log("Assign IP address to the links between DUTs and Tgen")

    if is_multi_asic: 
        ipapi.config_ip_addr_interface(globalVars.D1, globalVars.D1T1P1, data.d1t1_ip_addr,data.mask, distributed = True, asic_ns=intf_ns1[globalVars.D1T1P1],cli_type='vtysh-multi-asic')
        ipapi.config_ip_addr_interface(globalVars.D2, globalVars.D2T1P1, data.d2t1_ip_addr,data.mask, distributed = True, asic_ns=intf_ns2[globalVars.D2T1P1],cli_type='vtysh-multi-asic') 

        st.log("Multi-asic Platform: Assign IP address to the links between D1 and D2 and Create BGP Neighbors")
        for i, link in enumerate(interface_list1):
            addr1=data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"]
            addr2=data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]
            asic_ns1=intf_ns1[globalVars.get("D1D2P{}".format(i+1))]
            asic_ns2=intf_ns2[globalVars.get("D2D1P{}".format(i+1))]
            ipapi.config_ip_addr_interface(dut1, globalVars.get("D1D2P{}".format(i+1)), addr1,data.mask,is_multi_asic=True, asic_ns=asic_ns1,cli_type='vtysh-multi-asic')
            #bgpapi.create_bgp_neighbor(dut1, data.dut_asn_list[dut1], addr2, data.dut_asn_list[dut2],cli_type="vtysh-multi-asic", asic=asic_ns1.lstrip('asic'))

            ipapi.config_ip_addr_interface(dut2, globalVars.get("D2D1P{}".format(i+1)), addr2,data.mask,asic_ns=asic_ns2,cli_type='vtysh-multi-asic')

    else:
        ipapi.config_ip_addr_interface(globalVars.D1, globalVars.D1T1P1, data.d1t1_ip_addr,data.mask)
        ipapi.config_ip_addr_interface(globalVars.D2, globalVars.D2T1P1, data.d2t1_ip_addr,data.mask)

        st.log("Assign IP address to the links between D1 and D2 and Create BGP Neighbors") 
        for i, link in enumerate(interface_list1):
            addr1=data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"] 
            addr2=data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]  
            ipapi.config_ip_addr_interface(dut1, globalVars.get("D1D2P{}".format(i+1)), addr1,data.mask)

            ipapi.config_ip_addr_interface(dut2, globalVars.get("D2D1P{}".format(i+1)), addr2,data.mask)
    
    #st.log('# Configure BGP multipath #') 

    if not st.poll_wait(intapi.verify_interface_status, 20, globalVars.D1, interface_list1+[globalVars.D1T1P1], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", [globalVars.D1D2P1, globalVars.D1T1P1])
        out=bgpapi.show_bgp_ipv4_summary_vtysh(globalVars.D1,cli_type=cli_type)
        st.log(out)

    if not st.poll_wait(intapi.verify_interface_status, 20, globalVars.D2, interface_list2+[globalVars.D2T1P1], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", [globalVars.D2D1P1, globalVars.D2T1P1])

        out=bgpapi.show_bgp_ipv4_summary_vtysh(globalVars.D2,cli_type=cli_type)
        st.log(out)

    papi.clear_interface_counters(globalVars.D1)
    papi.clear_interface_counters(globalVars.D2)

def bgp_base_config(interface_list1=[],interface_list2=[]):

    if not interface_list1 and not interface_list2:
        interface_list1=local_links_dut1
        interface_list2=local_links_dut2

    st.log("Create BGP Neighbors for the links between D1 and D2")
    if is_multi_asic: 
        for i, link in enumerate(interface_list1):
            addr1=data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"]
            addr2=data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]
            asic_ns1=intf_ns1[globalVars.get("D1D2P{}".format(i+1))]
            asic_ns2=intf_ns2[globalVars.get("D2D1P{}".format(i+1))]
            bgpapi.create_bgp_neighbor(dut1, data.dut_asn_list[dut1], addr2, data.dut_asn_list[dut2],cli_type="vtysh-multi-asic", asic=asic_ns1.lstrip('asic'))

            bgpapi.create_bgp_neighbor(dut2, data.dut_asn_list[dut2], addr1, data.dut_asn_list[dut1],cli_type="vtysh-multi-asic", asic=asic_ns2.lstrip('asic'))

        st.log("# Configure BGP on the interface towards TGEN on D1 and D2#")
        for each_dut in data.dut_list:
            if each_dut==dut1:
                asic=intf_ns1[globalVars.get("D1T1P1")]
                bgpapi.create_bgp_neighbor(dut1,  data.dut_asn_list[dut1],  data.t1d1_ip_addr, data.tgen1_asn, cli_type="vtysh-multi-asic", asic=asic.lstrip('asic'))
            else:
                asic=intf_ns2[globalVars.get("D2T1P1")]
                bgpapi.create_bgp_neighbor(dut2,  data.dut_asn_list[dut2],  data.t1d2_ip_addr, data.tgen2_asn, cli_type="vtysh-multi-asic", asic=asic.lstrip('asic'))

    else: 
        for i, link in enumerate(interface_list1):
            addr1=data.local_links_info["D1D2P{}".format(i+1)]["ipaddr"]
            addr2=data.local_links_info["D2D1P{}".format(i+1)]["ipaddr"]
            bgpapi.create_bgp_neighbor(dut1, data.dut_asn_list[dut1], addr2, data.dut_asn_list[dut2])

            bgpapi.create_bgp_neighbor(dut2, data.dut_asn_list[dut2], addr1, data.dut_asn_list[dut1])

        st.log("# Configure BGP on the interface towards TGEN on D1 and D2#")
        for each_dut in data.dut_list:
            if each_dut==dut1:
                bgpapi.create_bgp_neighbor(dut1,  data.dut_asn_list[dut1],  data.t1d1_ip_addr, data.tgen1_asn)
            else:
                bgpapi.create_bgp_neighbor(dut2,  data.dut_asn_list[dut2],  data.t1d2_ip_addr, data.tgen2_asn)


    st.log('# Configure BGP multipath #')

    try: 
        for dut in [dut1, dut2]:
            bgpapi.config_bgp(dut=dut, local_as=data.dut_asn_list[dut], config = 'yes',config_type_list =["max_path_ebgp"], max_path_ebgp ='64')

            bgpapi.config_bgp(dut=dut, local_as=data.dut_asn_list[dut], config = 'yes',addr_family ='ipv6', config_type_list =["max_path_ebgp"], max_path_ebgp ='64')

            out=bgpapi.show_bgp_ipv4_summary_vtysh(dut) 
            st.log("## Verify BGP sessions are up ##") 
            for each_bgp in out:
                if each_bgp.get("asn")==data.dut_asn_list[dut]:  
                    if re.match("^[\d]+",each_bgp.get("updown")) and re.match("^[\d]+",each_bgp.get("state")):
                        continue 
                    else:
                        st.log("Need to bring up iBGP sessions first") 
    except Exception as e:
        raise AssertionError("BGP config Error:" +str(e)) 

def config_traffic_bgp(is_multi_asic=False):
    '''
    BGP Configuration
    Traffic ingressing into LC0 & egressing out of LC1
    '''

    #====================== TGEN -> SFD ======================#
    st.log('# Configure TG Interfaces #') 
    tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

    tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

    #Creating Devices & adding IP Addresses along with ARP requests
    res1=tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:11:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res1))
    tg1_interface = res1
    res2=tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:11:02', arp_send_req='1')
    st.log("INTFCONF: "+str(res2))
    tg2_interface = res2

    st.show(globalVars.D1, "show ip interfaces")

    st.show(globalVars.D2, "show ip interfaces")

    st.log("Ping TG interface from the DUT") 

    tg_end_ip=[data.t1d1_ip_addr, data.t1d2_ip_addr] 

    iteration=0 
    while iteration<5: 
        for i in range(2): 
            if is_multi_asic: 
                asic_list=[intf_ns1[globalVars.D1T1P1], intf_ns2[globalVars.D2T1P1]]  
                result=ping_neighbor(data.dut_list[i], tg_end_ip[i], count=10,size=56,asic=asic_list[i]) 
            else: 
                result=ping_neighbor(data.dut_list[i], tg_end_ip[i]) 

            passing_rate=parse_ping_output(result) 

            if passing_rate and passing_rate > 75:
                continue 
            else:
                break 
        else:
            break 

        iteration+=1 
        time.sleep(15) 

    else:
        return False 


    iteration=0
    while iteration<5:
        result = ipapi.ping(globalVars.D2, data.t1d2_ip_addr,distributed=is_multi_asic)
        if not result:
            iteration+=1
            time.sleep(15)
        else:
            break
    else:
        return False

    #Configuring BGP on TGEN-T1D1P1 towards SFD-LC0-NPU0
    st.banner("Configuring BGP on TGEN-T1D1P1 towards SFD-LC0")
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=tg1_interface['handle'],  
            mode='enable', active_connect_enable='1',
            local_as=data.tgen1_asn, remote_as=data.dut_asn_list[dut1], remote_ip_addr=data.d1t1_ip_addr,
            enable_4_byte_as='1', graceful_restart_enable='1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start') 
    st.wait(5)

    st.banner("Configuring BGP on TGEN-T1D2P1 towards SFD-LC3")
    bgp_rtr2 = tg2.tg_emulation_bgp_config(handle=tg2_interface['handle'], 
            mode='enable', active_connect_enable='1',
            local_as=data.tgen2_asn, remote_as=data.dut_asn_list[dut2], remote_ip_addr=data.d2t1_ip_addr,
            enable_4_byte_as='1', graceful_restart_enable='1')

    #Starting the BGP on TGEN
    st.banner("Starting the BGP on TGEN")
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')

    #====================== Prefix Advertisement ======================#

    #Prefix advertisement from TGEN towards DUT1(SFD-LC0) 
    st.banner("Prefix advertisement from TGEN towards SFD-LC0")
    bgp_route = tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', 
            num_routes='100',prefix='172.168.1.0')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(15)

    #====================== Traffic Generation ======================#

    #Configuring Traffic Stream on  TGEN port2 towards DUT2(SFD-LC3) 

    st.banner("Configuring Traffic Stream on  TGEN port2 towards SFD-LC3")
    tr2 = tg2.tg_traffic_config(port_handle=tg_handle_2,emulation_src_handle=tg2_interface['handle'],
            emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv4',mode='create', 
            high_speed_result_analysis='1',  transmit_mode='continuous', rate_pps=50000000)

    data.stream_id2 = tr2['stream_id']
    return tr2['stream_id'] 

def run_traffic(): 
    #Running the Streamblock
    stream=config_traffic_bgp(is_multi_asic)
    if not stream: 
        return False 
    try: 
        result=tg2.tg_traffic_control(action='run', handle=stream)

        if not result: 
            return False 
    except Exception as e:
        st.error('Failed to run traffic: '+str(e)) 
        return False 

    st.tg_wait(10)

    return True 

def stop_traffic():   
    st.log('#Stopping the Traffic Stream') 
    tg2.tg_traffic_control(action='stop', handle=data.stream_id2)
    time.sleep(15) 

def verify_traffic(verify_packet_loss=False): 

    st.log('Check counter on the interface') 

    DUT_rx_value = papi.get_interface_counters(globalVars.D2, globalVars.D1T1P1, "rx_ok")
    DUT_tx_value = papi.get_interface_counters(globalVars.D1, globalVars.D2T1P1, "tx_ok")

    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    for i in DUT_tx_value:
        p2_txmt = i['tx_ok']
        p2_txmt = p2_txmt.replace(",","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))     

    #Gathering received packets on TGEN-tg1
    st.banner("Gathering received packets on TGEN-tg1")
    tg_rx = tgapi.get_traffic_stats(tg1, port_handle=tg_handle_1)

    #Gathering sent packets on TGEN-tg2
    st.banner("Gathering sent packets on TGEN-tg2")
    tg_tx = tgapi.get_traffic_stats(tg2, port_handle=tg_handle_2)
    st.log('tg1_stats.rx.total_packets : {}'.format(tg_rx.rx.total_packets))
    st.log('tg2_stats.tx.total_packets : {}'.format(tg_tx.tx.total_packets))

    ret_val=True 

    #Calculation of Percent rx
    st.banner("Calculation of Percent rx")
    percent_rx = float(int(tg_tx.tx.total_packets) - int(tg_rx.rx.total_packets)) / int(tg_tx.tx.total_packets) * 100

    st.log('## Test Case Info, Traffic Loss: percent_rx : {} % ## '.format(percent_rx))
    if verify_packet_loss: 
        if int(tg_rx.rx.total_packets) < int(tg_tx.tx.total_packets)*0.95:
            st.log("Test case with bgp_traffic failed") 
            ret_val = False
        else:
            st.log("Test case with bgp_traffic passed")
            ret_val = True

    return ret_val

def pre_checks(dut, port, msg):
    st.log("--------Clear syslogs-------")
    logapi.clear_logging(dut)
    st.log("--------Collect transceiver eeprom and presence before {}-------".format(msg))
    eeprom_before, presence_before = check_transceiver_info(dut, ["eeprom", "presence"], port)
    st.log("--------Check for xcrvd process before {}-------".format(msg))
    xcrvd_before = st.config(dut, XCVRD_COMM)
    return eeprom_before, presence_before, xcrvd_before

def post_checks(dut, port, msg, eeprom_before, presence_before, xcrvd_before, sys_reg):
    st.log("--------Collect transceiver eeprom and presence after {}-------".format(msg))
    eeprom_after, presence_after = check_transceiver_info(dut, ["eeprom", "presence"], port)
    st.log("--------Check for xcrvd process after {}-------".format(msg))
    xcrvd_after = st.config(dut, XCVRD_COMM)
    if eeprom_after != eeprom_before:
        st.error("eeprom details changed after {}".format(msg))
        return 0
    if presence_after != presence_before:
        st.error("transceiver presence  changed after {}".format(msg))
        return 0

    if len(xcrvd_after) != len(xcrvd_before):
        st.error("xcrvd process state changed after {} from {} to {}".format(msg, xcrvd_before, xcrvd_after))
        return 0

    st.log("Checking for syslogs")
    if not check_syslog(dut, port, sys_reg):
         st.error("Syslogs missing for {}".format(msg))
         return 0

    iteration=0 
    while iteration<10:
        if not verify_interface_health(dut, port):
            iteration+=1 
            time.sleep(15) 
        else:
            return 1 
    else:
        return 0

def verify_link_status(dut, interface="all", timeout=180):
    iteration=0
    if interface=="all":
        intf=local_links_dut1
    else:
        intf=[interface]

    while iteration<(timeout/15):
        intf_down=0

        for each in intf:
            try:
                if not intapi.verify_interface_status(dut,each,'oper', 'up'):
                    time.sleep(15)
                    iteration+=1
                    break
            except Exception as e:
                time.sleep(15)
                iteration+=1
                break

        else:
            return True
    else:
        return False

def verify_interface_health(dut, port):
    try:
        st.log("Checking if the interface is operationally up")
        if not intapi.verify_interface_status(dut,port,'oper', 'up'):
            st.error("Interface {} is not operationally up".format(port))
            return False

        st.log("Checking if the CPU utilization is below 80")
        output = basic_obj.get_processes_memory(dut)
        for row in output:
                if float(row['cpu']) > 80.0:
                    st.error("CPU utilization above 80%".format(row['command']))
                    return False

        st.log("Checking if swss, syncd and pmon are up")
        for container in ["swss", "syncd", "pmon"]:
            output = basic_obj.get_docker_ps_container(dut, container)
            if not "Up" in output['status']:
                st.error("Container {} is not up".format(container))
                return False

    except Exception as err:
        st.log("Exception occurred")
        st.error(err)
        return False
    return True

def check_syslog(dut, port, syslog_regex):
    for line in syslog_regex:
        if len(logapi.show_logging(dut, filter_list= [line.format(port)]))==0:
            return False
    return True

def check_transceiver_info(dut, modes, port):
    output = []
    for mode in modes:
        output.append(boxapi.show_interface_transceiver(dut, mode, interface=port))
    return output

def check_docker_uptime(dut, container_name,timeout=60):
    """
    Checking if container is up within $timeout "
    """
    iteration=0

    while iteration<(timeout/15):
        iteration+=1

        try:
            container_data = basic_obj.get_docker_ps_container(dut, container_name)
            if not container_data or not "Up" in container_data['status']:
                time.sleep(15)
                continue
            else:
                return True

        except Exception as err:
            raise AssertionError('Checking container failed: '+str(err))

    st.log('Container %s is not up after %d'%(container_name, timeout))
    return False

def check_optics_type(dut, interface):

    try:
        output=st.config(dut, "sudo sfputil show eeprom -d -p "+interface)
    except Exception as e:
        st.log("## Capture the show command error #")

        if re.search(r'ValueError|TypeError|Command.*returned error|Error', str(e)):
            if re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',str(e)):
                match=re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',str(e))
                optics_type=match.group(1)
                return optics_type
            else:
                return "unknown Optics Type"

        else:
            return "unknown Optics Type"

    if re.search(r'Extended Specification Compliance: +([100G|400G|40G].*)',output) or re.search(r"'module_media_interface_id': +'([100G|400G|40G][\w\-]+)",output) or re.search(r"Media Interface Code: +([100G|400G|40G][\w\-]+)",output) or re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',output):
        match1=re.search('Extended Specification Compliance.*([400G|100G|40G].*)',output)
        match2=re.search("'module_media_interface_id': +'([100G|400G|40G][\w\-]+)",output)
        match3=re.search(r"Media Interface Code: +([100G|400G|40G][\w\-]+)",output)
        match4=re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',output)


        if match1:
            return match1.group(1)
        elif match2:
            return match2.group(1)
        elif match3:
            return match3.group(1)
        elif match4:
            return match4.group(1)
        else:
            raise AssertionError("Optics Type not found in the CLI sfputil shows eeprom")

    elif re.search(r'Extended Specification Compliance:.*',output) or re.search(r"module_media_interface_id",output) or re.search(r"Media Interface Code",output) or re.search(r'Application Advertisement',output):

        match1=re.search('Extended Specification Compliance',output)
        match2=re.search('module_media_interface_id',output)
        match3=re.search(r"Media Interface Code",output)
        match4=re.search(r'Application Advertisement',output)


        if match1:
            return match1.group(0)
        elif match2:
            return match2.group(0)
        elif match3:
            return match3.group(0)
        elif match4:
            return match4.group(0)
        else:
            raise AssertionError("Optics Type not found in the CLI sfputil shows eeprom")

    else:
        #raise AssertionError("Optics Type not parsed in the CLI sfputil shows eeprom")
        output1=st.config(dut, "sudo sfputil show eeprom-hexdump -n 3 -p "+interface)
        output2=st.config(dut, "sudo sfputil show eeprom -d -p "+interface) 
        match=re.search(r'CISCO-.*|QDD-.*',output1)
        if match:
            return match.group(0) 
        else:     
            match2=re.search(r'Vendor Name:(.*)',output2) 
            match3=re.search(r'Vendor PN:(.*)',output2) 
            if not match2 or not match3: 
                return "Unknown Optics type" 
            else: 
                return "Optics with "+match2.group(0)+match.group(0) 

def flap_interface(dut,  port):
    if not is_multi_asic:
        intapi.interface_shutdown(dut, port)
        time.sleep(2)
        intapi.interface_noshutdown(dut, port)
    else:
        if dut==dut1:
            namespace=intf_ns1[port]
        else:
            namespace=intf_ns2[port]

        command="sudo config interface -n "+namespace+" shutdown "+port
        st.config(dut, command)
        time.sleep(5)
        st.config(dut, "sudo config interface -n "+namespace+" startup "+port)
        time.sleep(5)

def sfd_rp_reboot(rp_ip_address,username,password):
    ssh_RP = connect_to_device(rp_ip_address, username, password)
    if ssh_RP:
        try:
            st.log("Executing reboot command ")
            RPoutput = execute_command(ssh_RP, 'sudo reboot')
            RPoutput = RPoutput.split()
            ssh_disconnect(ssh_RP)
        except Exception as e:
            raise Exception('Reboo RP: '+str(e))
    else:
        raise Exception('SSH connection unsuccessful')

@pytest.fixture(scope="function") 
def run_traffic_over_testcase(request): 
    try: 
        tg1.clean_all()
        tg2.clean_all()

        st.log("## Start running Traffic ##") 

        if not run_traffic(): 
            st.report_fail("test_case_failed") 
    except Exception as e: 
        st.error("Run Traffic failed: "+str(e)) 
        st.report_fail("test_case_failed")  

    yield 

    stop_traffic()
    
    if not verify_traffic():
        st.report_fail("test_case_failed")

    tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

    tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

    tg1.clean_all()
    tg2.clean_all()

    time.sleep(120) 
    st.report_pass("test_case_passed") 

def run_traffic_after_reload():

    st.log("### Start Running Traffic After Reload ###")

    try:
        tg1.clean_all()
        tg2.clean_all()

        if not run_traffic():
            st.report_fail("test_case_failed")
    except Exception as e:
        st.error("Run Traffic failed: "+str(e))
        st.report_fail("test_case_failed")

    stop_traffic()

    if not verify_traffic(verify_packet_loss=True):
        st.report_fail("test_case_failed")

    tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

    tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

    tg1.clean_all()
    tg2.clean_all()


@pytest.fixture(scope='class')
def optics_class_hook(request):
    if not dut_bgp_ip_cleanup():
        st.report_fail("test_case_failed")

    time.sleep(15)

    try:
        ip_base_config()
        ## NOTES: Removed temporarily for a Bug ##
        bgp_base_config()
    except Exception as e:
        st.error("IP/BGP Configuration Failed: "+str(e))
        st.report_fail("test_case_failed")

    st.log("Clear interface counters")
    papi.clear_interface_counters(globalVars.D1)
    papi.clear_interface_counters(globalVars.D2)

@pytest.fixture(scope="function")
def reload_hook():
    data.dockers_count = {}
    for dut in data.DUTs:
        #copy_configdb_before_reload()
        st.log("# Save the runningconfig #")

        st.config(dut, "sudo config save -y")
        time.sleep(60)


        data.dockers_count[dut] = get_and_match_docker_count(dut)
        st.log('dockers count of {}: is {}'.format(dut,data.dockers_count[dut]))
        if not poll_wait(verify_docker_status, 120, dut, 'Exited'):
            data.docker_check = False
        else:
            data.docker_check = True

    if is_multi_asic:
        source_frr()
        time.sleep(60) 

    try:
        for dut in data.dut_list: 
            print("checking ip bgp summary, cli_type is, ",cli_type) 
            if is_multi_asic: 
                out=bgpapi.show_bgp_ipv4_summary_vtysh(dut,cli_type='vtysh-multi-asic')
            else:
                out=bgpapi.show_bgp_ipv4_summary_vtysh(dut)

    except Exception as e:
        st.log("CLI bug: "+str(e))
        pass


    st.log("Check optics types before reload")
    fail=0
    optics_dut1={}
    optics_dut2={}


    for i, link in enumerate(local_links_dut1):
        optics_dut1[link]=check_optics_type(dut1, link)

        link2=local_links_dut2[i]

        optics_dut2[link2]=check_optics_type(dut2,link2)

        st.log('### On dut1: Link %s with optics Type %s###'%(link,optics_dut1[link]))

        st.log('### On dut2: Link %s with optics Type %s###'%(link2,optics_dut2[link2]))

    start_time=time.time()
    yield
    time.sleep(120)
    fail=0

    st.log("Checking if the interface is operationally up")

    for i, link in enumerate(local_links_dut1):
        link2=local_links_dut2[i]
        if not st.poll_wait(intapi.verify_interface_status, 120, dut1, link, 'oper', 'up'):
            fail+=1 

        if not st.poll_wait(intapi.verify_interface_status, 120, dut2, link2, 'oper', 'up'):
            fail+=1

    st.log("After reload, it took %s seconds for the interfaces to come up"%str(time.time()-start_time))


    st.log('## Check Optics Again After System Reload##')
    optics_dut1_after, optics_dut2_after={}, {}
    for i, link in enumerate(local_links_dut1):
        optics_dut1_after[link]=check_optics_type(dut1, link)

        link2=local_links_dut2[i]

        optics_dut2_after[link2]=check_optics_type(dut2,link2)

        if optics_dut1_after[link]!=optics_dut1[link]:
            st.error('On DUT1, Optics Type on %s changed after process restart'%link)

            st.error('It was %s before restart, but now it is %s'%(optics_dut1[link], optics_dut1_after[link]))
            fail+=1

        if optics_dut2_after[link2]!=optics_dut2[link2]:
            st.error('On DUT2, Optics Type on %s changed after process restart'%link2)
            st.error('It was %s before restart, but now it is %s'%(optics_dut2[link2], optics_dut2_after[link2]))
            fail+=1


    #for dut in [dut1, dut2]:
    st.log("# Create Base BGP Config for reload test case #")
    bgp_base_config()
    time.sleep(10)


    #for dut in [dut1, dut2]:
    if is_multi_asic: 
        source_frr()


    try:
        run_traffic_after_reload()
    except Exception as e:
        st.error('Run traffic failed: '+str(e))
        st.report_failed('test_case_failed')

    if fail:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

def reload_verifier(dut,test_case_name,marker_message):
    if  data.docker_check:
        ret_docker = validate_docker_status(dut)
    else:
        time.sleep(60)
        ret_docker = True

    return ret_docker

def restart_docker_process(process_name):
    if process_name in ["syncd","gbsyncd","swss"] and is_multi_asic==True:
        process=process_name+"0"
    elif process_name=="gbsyncd" and is_multi_asic==False: 
        pytest.skip('No gbsyncd process on this platform') 
    else:
        process=process_name

    fail=0
    optics_dut1={}
    optics_dut2={}

    for i, link in enumerate(local_links_dut1):
        optics_dut1[link]=check_optics_type(dut1, link)

        link2=local_links_dut2[i]

        optics_dut2[link2]=check_optics_type(dut2,link2)

        st.log('### On dut1: Link %s with optics Type %s###'%(link,optics_dut1[link]))

        st.log('### On dut2: Link %s with optics Type %s###'%(link2,optics_dut2[link2]))


    try:
        st.log('# RESTART PROCESS %s #'%process)
        docker_data = basic_obj.get_docker_ps(dut1)
        if docker_data is None:
            raise Exception("Parsed docker data returned null")

        restart_ouput = basic_obj.docker_operation(dut1, process, "restart")
        st.wait(120)

        if not check_docker_uptime(dut1, process,360):
            st.log("docker {} container verification failed".format(process))
            raise Exception("docker {} container verification failed".format(process))


    except Exception as err:
        st.log("Process Restart Exception occured")
        st.log(err)
        st.error("Type of error occured:", sys.exc_info()[0])
        fail+=1

    iteration=0
    while iteration<10:
        try:
            intapi.poll_for_interface_status(dut1, link,'oper','up',iteration=15, delay=15)
            break
        except Exception as err:
            st.log("Type of error occured:", sys.exc_info()[0])
            iteration+=1
            time.sleep(15)
            fail+=1

    st.log('## Check Optics Again After Process Restart##')
    optics_dut1_after, optics_dut2_after={}, {}
    for i, link in enumerate(local_links_dut1):
        optics_dut1_after[link]=check_optics_type(dut1, link)

        link2=local_links_dut2[i]

        optics_dut2_after[link2]=check_optics_type(dut2,link2)

        if optics_dut1_after[link]!=optics_dut1[link]:
            st.error('On DUT1, Optics Type on %s changed after process restart'%link)
            st.error('It was %s before restart, but now it is %s'%(optics_dut1[link], optics_dut1_after[link]))
            fail+=1

        if optics_dut2_after[link2]!=optics_dut2[link2]:
            st.error('On DUT2, Optics Type on %s changed after process restart'%link2)
            st.error('It was %s before restart, but now it is %s'%(optics_dut2[link2], optics_dut2_after[link2]))
            fail+=1

    return fail 

def run_interface_flaps(dut_end):

    if dut_end=="local":
        st.log("TEST CASE: Local DUT Interfaces Flapping")
        dut=dut1
        local_links=local_links_dut1
    else:
        st.log("TEST CASE: Remote DUT Interfaces Flapping")
        dut=dut2
        local_links=local_links_dut2

    test_fail=0
    error=''

    for port in local_links:
        try:
            eeprom_before, presence_before, xcrvd_before = pre_checks(dut, port, "flap")
            flap_interface(dut, port)
            st.log("--------Interface {} flapped -------".format(port))
            st.wait(30)

            st.log("Checking if the interface is operationally up")
            if not st.poll_wait(intapi.verify_interface_status, 60, dut, [port], 'oper', 'up'):
                st.error("Interface {} is not operationally up".format(port))
                st.report_fail('test_case_failed')



            time.sleep(120)

            result=post_checks(dut, port, "flap", eeprom_before, presence_before, xcrvd_before, PORT_STATUS_REGEX)
            if not result:
                error+='Interface Flapping Testing Failed on %s\n'%(port)
                st.error('Interface Flapping Testing Failed on %s'%(port))
                test_fail+=1
        except AssertionError as e:
            st.error('Interface flapping testing failed on %s due to the following error: '%(port))
            st.error(str(e))
            test_fail+=1

    return test_fail

def test_traffic_on_each_interface():
    fail=0

    if not dut_bgp_ip_cleanup():
        st.log("dut cleanup failed")
        st.report_fail("test_case_failed")

    time.sleep(15)

    for i, intf in enumerate(local_links_dut1):
        st.log("Sending traffic on Interface %s"%intf)
        try:
            tg1.clean_all()
            tg2.clean_all()

            intf2=local_links_dut2[local_links_dut1.index(intf)]
            ip_base_config(interface_list1=[intf],interface_list2=[intf2])
            bgp_base_config([intf],[intf2])

            optics1=check_optics_type(dut1, intf)

            link2=local_links_dut2[i]

            optics2=check_optics_type(dut2,link2)

            st.log('### On dut1: Link %s with optics Type %s###'%(intf,optics1))
            st.log('### On dut2: Link %s with optics Type %s###'%(link2,optics2))


            if not run_traffic():
                fail+=1
                st.log("Running traffic failed on interface %s"%intf)

            else:
                stop_traffic()

                if not verify_traffic(True):
                    fail+=1
                    st.log("Verifying traffic failed on interface %s"%intf)

        except Exception as e:
            st.error("Error: "+str(e))
            fail+=1
        finally:
            tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])
            tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])

            tg1.clean_all()
            tg2.clean_all()

            dut_bgp_ip_cleanup()
            #ipapi.clear_ip_configuration(data.lc_name_list, distributed=is_multi_asic)

    if fail:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.usefixtures('optics_class_hook')
@pytest.mark.usefixtures('run_traffic_over_testcase')
class TestFlapInterfaces():

    def test_flap_local_interfaces(self):
        if run_interface_flaps("local"):
            st.report_fail('test_case_failed')
        else:
            st.report_pass('test_case_passed')

    def test_flap_remote_interfaces(self):
        if run_interface_flaps("remote"):
            st.report_fail('test_case_failed')
        else:
            st.report_pass('test_case_passed')

@pytest.mark.usefixtures('run_traffic_over_testcase')
class TestProcessRestart():

    def test_restart_process_pmon(self):

        if restart_docker_process("pmon"):
            st.report_fail('test_case_failed')
        else:
            st.report_pass('test_case_passed')

    def test_restart_process_swss(self):

        if restart_docker_process("swss"):
            st.report_fail('test_case_failed')
        else:
            st.report_pass('test_case_passed')

    def test_restart_process_syncd(self):

        time.sleep(60) 
        if restart_docker_process("syncd"):
            st.report_fail('test_case_failed')
        else:
            st.report_pass('test_case_passed')

    def test_restart_process_gbsyncd(self):
        time.sleep(60) 
        if not is_multi_asic:
            pytest.skip('No gbsyncd process on this platform')

        if restart_docker_process("gbsyncd"):
            st.report_fail('test_case_failed')
        else:
            st.report_pass('test_case_passed')

@pytest.mark.usefixtures('optics_class_hook')
@pytest.mark.usefixtures('reload_hook')
class Test_reload():
    def test_config_reload(self):
        try:
            fail=0
            st.log("Do config Reload")
            command="config reload -yf"
            start_time=time.time()
            st.config(dut1, command)
        except Exception as e:
            st.log("Config reload failed")
            fail=1
        finally:
            time.sleep(240)

        if not fail:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")


    def test_lc_shutdown_CLI_cmd(self):
        fail=0
        if is_sfd_system:
            try:
                st.log("Reloading the Line card with CLI shutdown")
                command="sudo shutdown -r now"
                start_time=time.time()
                st.config(dut1, command)
                time.sleep(240)
            except Exception as e:
                st.log("Line Card Shutdown failed")
                fail=1
        else:
            pytest.skip("test_case_skipped for non-SFD System")

        time.sleep(240) 

        if not fail:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_lc_Reload_from_RP(self):
        st.log('Bring back Line card from RP')

        fail=0
        if not is_sfd_system:
            pytest.skip("test_case_skipped for non-SFD System")

        else:
            try:
                ssh_RP = connect_to_device(data.rp_mgmt_ip, data.username, data.password)

                st.log("Executing reboot command ")
                start_time=time.time()
                RPoutput = execute_command(ssh_RP, 'reload.py -s 0')
                RPoutput = RPoutput.split()
                ssh_disconnect(ssh_RP)
            except Exception as e:
                st.log('Reboot RP failed: '+str(e))
                fail=1
            finally:
                time.sleep(240) 

        if fail:
            st.report_fail("test_case_failed")
        else:
            time.sleep(120)
            st.report_pass("test_case_passed")

    def test_local_dut_cold_reboot(self):

        reboot_cmd="sudo reboot"

        try:
            st.config(dut1, reboot_cmd, conf=False,
                       skip_error_check=True, max_time=300, expect_reboot=True)
        except Exception as e:
            st.log("DUT not up after Reboot: "+str(e))
            st.wait(120)
            try:
                poll_dut_up(dut1)
            except Exception as e:
                st.error("DUT is not up after 420 seconds")
                st.report_fail("test_case_failed")
        finally:
            time.sleep(240) 

        st.report_pass("test_case_passed")


    def test_remote_dut_cold_reboot(self):

        reboot_cmd="sudo reboot"

        try:
            st.config(dut2, reboot_cmd, conf=False,
                       skip_error_check=True, max_time=300, expect_reboot=True)
        except Exception as e:
            st.log("DUT not up after Reboot: "+str(e))
            st.wait(120)
            try:
                poll_dut_up(dut2)
            except Exception as e:
                st.error("DUT is not up after 420 seconds")
                st.report_fail("test_case_failed")
        finally:
            time.sleep(240)

        st.report_pass("test_case_passed")

    def test_power_cycle(self):
        try:
            st.log("About to power off switch")
            st.do_rps(dut1, "Off")
            st.log("About to power on switch")
            st.do_rps(dut1, "On")
            time.sleep(120)
        except Exception as e:
            st.error('Power Cycling failed: '+str(e))
            st.report_fail("test_case_failed")
        finally:
            time.sleep(240)

        st.report_pass("test_case_passed")

