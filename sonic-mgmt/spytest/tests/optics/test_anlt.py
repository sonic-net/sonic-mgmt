''' This script is for anlt testing on Lightning platform 
    Test Topology: 
              --------------
              |   Tgen     |
              --------------
                |       |
                |       |
          --------    ---------
          |      |----|       |
          | DUT1 |----| DUT2  |
          --------    ---------

    Test Cases: 
        Group 1: enabling ANLT 
        Group 2: test_repeated_interface_flaps --Test interface flapping (local DUT and remote DUT)
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
from apis.system.basic import get_docker_ps, get_and_match_docker_count, get_hwsku,verify_docker_status
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
from apis.common.sonic_hooks import SonicHooks 
import apis.system.logging as logapi
import apis.system.port as papi  
import apis.system.box_services as  boxapi

CurrentPath = os.path.dirname(os.path.abspath(__file__))

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
    st.ensure_min_topology("D1D2:1")

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

    time.sleep(15) 

    st.log("Clear interface counters") 
    papi.clear_interface_counters(globalVars.D1)
    papi.clear_interface_counters(globalVars.D2)

    yield 


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

    global PORT_STATUS_REGEX, FEC_STATUS_REGEX, ANLT_STATUS_REGEX, XCVRD_COMM
    PORT_STATUS_REGEX = ["swss#orchagent: :- doPortTask: Set port {} admin status to up", 
            "swss#orchagent: :- setHostIntfsOperStatus: Set operation status UP to host interface {}"] 

    ANLT_STATUS_REGEX = ["swss#orchagent: :- doPortTask: Set port {} autoneg to on",
            "swss#orchagent: :- setHostIntfsOperStatus: Set operation status UP to host interface {}"]

    FEC_STATUS_REGEX= ["NOTICE swss.*#orchagent: :- doPortTask: Set port {} fec to none"]

    AUTO_NEGO_REGEX= ["doPortTask: Set port {} admin status to up",
"NOTICE swss.*#orchagent: :- doPortTask: Set port {} AutoNeg to 0"]

    OIR_OUT_REGEX = ["{}.*Got SFP removed event", "Publish.*{}.*ok:down"] 
    OIR_IN_REGEX = ["{}.*Got SFP inserted event","Port {} oper state set from down to up"] 
    

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
            high_speed_result_analysis='1',  transmit_mode='continuous', rate_percent=100)

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

    iteration=0 
    while iteration<10:
        if not check_uptime_syslog(dut, port, sys_reg):
             iteration+=1 
             time.sleep(15) 
             continue 

        if not verify_interface_health(dut, port):
            iteration+=1 
            time.sleep(15) 
            continue 
        else:
            return 1 
    else:
        st.error("Syslogs missing for {}".format(msg))  
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

def check_uptime_syslog(dut, port,syslog_regex):
    for line in syslog_regex:
        #import pdb;pdb.set_trace() 

        if len(logapi.show_logging(dut, filter_list=[line.format(port)]))==0:
            return False
        else:
            match_syslog=logapi.show_logging(dut, filter_list=[line.format(port)]) 
            from datetime import datetime 
            for match in match_syslog:

                if syslog_regex==ANLT_STATUS_REGEX: 
                    if re.search('(.*)NOTICE swss#orchagent: :- doPortTask: Set port {} autoneg to on'.format(port),match): 
                        match1=re.search('([\d]+:[\d]+:[\d]+)\.[\d]+ .*NOTICE swss#orchagent: :- doPortTask: Set port {} autoneg to on'.format(port),match) 
                        start_time=datetime.strptime(match1.group(1), "%H:%M:%S") 
                elif syslog_regex==PORT_STATUS_REGEX:
                    if re.search('(.*)NOTICE swss#orchagent: :- doPortTask: Set port {} admin status to up'.format(port),match):
                        match1=re.search('([\d]+:[\d]+:[\d]+)\.[\d]+ .*NOTICE swss#orchagent: :- doPortTask: Set port {} admin status to up'.format(port),match)
                        start_time=datetime.strptime(match1.group(1), "%H:%M:%S")

                if re.search('swss#orchagent: :- setHostIntfsOperStatus: Set operation status UP to host interface {}'.format(port),match):         
                    match2=re.search('([\d]+:[\d]+:[\d]+)\.[\d]+ .*NOTICE swss#orchagent: :- setHostIntfsOperStatus: Set operation status UP to host interface {}'.format(port),match)
                    intf_up_time=datetime.strptime(match2.group(1), "%H:%M:%S")  

    if 'start_time' in locals() and 'intf_up_time' in locals():
        return intf_up_time-start_time
    else:
        raise AssertionError('No interface up time is captured') 

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

def check_cable_length(dut, interface):

    #import pdb; pdb.set_trace()

    try:
        output=st.config(dut, "sudo show interface transceiver eeprom "+interface)
        #output2=st.show(dut, "sudo show interface transceiver eeprom "+interface) 

        if re.search(r'Length Cable Assembly\(m\): (.*)', output):
            match=re.search(r'Length Cable Assembly\(m\): (.*)', output)
            cable_length=match.group(1)
            return cable_length
        else:
            return "unknown Optics Type"

    except Exception as e:
        raise AssertionError('No cable length found: '+str(e)) 

    return cable_length 

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

def write_results_to_file(result_str,dst_file):
    with open(dst_file,"a") as results_file:
        results_file.write(result_str)

def copy_test_results(file_name):

    dst_log_path = st.get_logs_path()
    dst_path = '/home/sonic/lightning-anlt-test-logs/' 

    if not os.path.exists(dst_path):
        os.makedirs(dst_path)
    else:
        os.system('ls -al '+dst_path) 

    dst_filename=os.path.join(dst_path, file_name) 

    cp_cmd = 'cp {} {}'.format(os.path.join(CurrentPath,file_name), os.path.join(dst_log_path,file_name))

    os.system(cp_cmd) 

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


def parse_sh_plat_npu_mac_state_output(output):

    mac_state_dump_dict={} 

    for line in output.split('\n'):
        match1=re.findall("codeword\[0-15\] = .*",line)
        match2=re.findall("codeword_uncorrectable = .*",line) 
        match3=re.findall("extrapolated_ber = .*",line)
        match4=re.findall("Frame Loss Rate \(SDK\).*",line)
        match5=re.findall("FEC BER Lane = .*",line) 

        if match1:
            codeword=[None for i in range(15)]
            exec(match1[0]) 
            import numpy as np
            mac_state_dump_dict['fec_bin']=np.where(codeword[0])[0].max()

        elif match2:
            exec(match2[0])
            try: 
                mac_state_dump_dict["codeword_uncorrectable"]=codeword_uncorrectable 
            except Exception as NameError: 
                codeword_uncorrectable=match2[0].split('=')[1]
                mac_state_dump_dict["codeword_uncorrectable"]=codeword_uncorrectable


        elif match3: 
            exec(match3[0].split(',')[0]) 
            try: 
                if 'extrapolated_ber' in locals(): 
                    mac_state_dump_dict["extrapolated_ber"]=extrapolated_ber 
                else:
                    mac_state_dump_dict["extrapolated_ber"]=match3[0].split(',')[0].split('=')[1] 
            except Exception as NameError:
                 mac_state_dump_dict["extrapolated_ber"]=match3[0].split(',')[0].split('=')[1]

        elif match4:
            mac_state_dump_dict["frame_loss_rate"]=match4[0].split(',')[0].split('=')[1].split()[0] 

        elif match5:
            mac_state_dump_dict["FEC_BER_Lane"]=eval(match5[0].split('=')[1])
            ## check if any of  them if greater than 1e-05 
            if not all(float(x)<1e-05 for x in mac_state_dump_dict["FEC_BER_Lane"]):
                print("## ISSUE: one of the FEC BER Lanes is bigger than 1e-05") 

    return mac_state_dump_dict

def test_enable_ANLT(): 

    for i, dut in enumerate([dut1, dut2]): 
        st.log('### LOG INFOR: DUT {} collect mac-state information before testing ## '.format(i)) 
        output=st.config(dut,"sudo show platform npu mac-state -a all") 

        st.log('### LOG INFOR: clear mac-state information before testing ## ')
        st.config(dut,"sudo show platform npu mac-state -a all",max_time=300)

    fail=0 

    st.log("### LOG INFOR: Create Log File and Result File")
    result_file_name=[None for i in range(2)]  
    header_str="DUT     PORT    CABLE_LENGTH    FEC_BIN     CODEWORD_UNCORRECTABLE  EXTRAPOLATED_BER    FRAME_LOSS_RATE     FEC_BER_LANE    UPTIME\n"
    for x in range(2): 
        result_file_name[x]="dut"+str(x+1)+"_Topo1_enable_anlt_final_report.txt"

        write_results_to_file(header_str,result_file_name[x])

    for i, intf in enumerate(local_links_dut1):

        intf2=local_links_dut2[local_links_dut1.index(intf)]
        optics1=check_cable_length(dut1, intf)
        link2=local_links_dut2[i]
        optics2=check_cable_length(dut2,link2)

        intf_list=[intf, link2] 
        optics_list=[optics1, optics2]
        dut_list=[dut1, dut2] 

        log_file_name=[None for i in range(2)]  

        for n in range(2):  
            header_str="===TEST LOG FOR DUT{} WITH TOPO1 ON INTERFACE {}===\n".format(n+1,intf) 
            log_file_name[n]="dut"+str(n+1)+"_Topo1_"+intf_list[n]+"_"+optics_list[n]+"_enable_anlt.log"
            write_results_to_file(header_str,log_file_name[n])

        try:
            log_str='### LOG INFOR: On DUT1: Interface %s with cable length %s###\n'%(intf,optics1) 
            st.log(log_str)
            write_results_to_file(log_str,log_file_name[0]) 

            log_str='### LOG INFOR: On DUT1, collect mac-state information before enabling ANLT ## \n "sudo show platform npu mac-state -i {}"\n'.format(intf)  
            st.log(log_str)
            write_results_to_file(log_str,log_file_name[0])

            macstate_output1=st.config(dut1,"sudo show platform npu mac-state -i %s"%(intf))
            result1=parse_sh_plat_npu_mac_state_output(macstate_output1) 
            write_results_to_file(macstate_output1,log_file_name[0])

            log_str='### LOG INFOR: clear mac-state information before testing ## \n' 
            st.log(log_str) 

            for dut in dut_list:
                st.config(dut, "sudo truncate -s 0 /var/log/syslog") 

                st.log("--------Clear syslogs-------")
                logapi.clear_logging(dut)

            log_str='### LOG INFOR: Enable ANLT mode on interface {}\nsudo config interface autoneg {} enabled\n'.format(intf,intf) 
            st.log(log_str) 
            write_results_to_file(log_str,log_file_name[0]) 

            output=st.config(dut1, "sudo config interface autoneg %s enabled"%(intf)) 
            write_results_to_file(output,log_file_name[0]) 

            st.log('### LOG INFOR: Verify Link is down')
            if not st.poll_wait(intapi.verify_interface_status, 60, dut1, [intf], 'oper', 'down'):
                st.error("## ERROR: Interface {} is not down after enabling ANLT on one DUT, while the other is not".format(intf))
                fail+=1 
                continue 

            log_str='### LOG INFOR: On DUT2, collect mac-state information on interface {} before enabling ANLT, then clear the mac-state ## \n'.format(intf2) 
            st.log(log_str) 
            write_results_to_file(log_str,log_file_name[1]) 
            macstate_output2=st.config(dut2,"sudo show platform npu mac-state -i %s"%(intf2))
            log_str="sudo show platform npu mac-state -i {}\n".format(intf2)
            write_results_to_file(log_str+macstate_output2+'\n',log_file_name[1])

            log_str='### LOG INFOR: On DUT2, Enable ANLT mode on Interface {}\n'.format(intf2)
            st.log(log_str) 
            output=st.config(dut2, "sudo config interface autoneg %s enabled"%(intf2)) 
            write_results_to_file(log_str+output+'\n',log_file_name[1])

            for n,dut in enumerate([dut1,dut2]):
                error=0 

                log_str='### LOG INFOR: Verify Link is up \n'
                st.log(log_str)
                write_results_to_file(log_str,log_file_name[n])
                if not st.poll_wait(intapi.verify_interface_status, 60, dut, intf_list[n], 'oper', 'up'):
                    st.error("Interface {} is not operationally up".format(intf_list[n]))
                    fail+=1
                    continue 
                else:
                    log_str="on DUT{}, Interface {} with ANLT enabled is up\n".format((n+1),intf_list[n])
                    write_results_to_file(log_str,log_file_name[n]) 

                st.log('### LOG INFOR: Verify ANLT Mode is set')

                log_str='### LOG INFOR: On DUT{}, collect mac-state information for Interface {} After enabling ANLT ## \n'.format((n+1),intf_list[n])
                macstate_output=st.config(dut,"sudo show platform npu mac-state -i %s"%(intf_list[n]))
                result=parse_sh_plat_npu_mac_state_output(macstate_output) 
                write_results_to_file(log_str+macstate_output+'\n',log_file_name[n])

                st.log('### LOG INFOR: Check the uptime for ANLT mode') 
                uptime=check_uptime_syslog(dut, intf_list[n],ANLT_STATUS_REGEX) 
                log_str1='### LOG INFOR: Enabling ANLT took {} to come up on dut{} interface {} ##\n'.format(uptime,n+1,intf_list[n])
                st.log(log_str1) 
                write_results_to_file(log_str1,log_file_name[n])

                if int(result.get('fec_bin'))>10:
                    err_str="ORANGE PASS for FEC BIN, it is {} on Interface {}".format(result.get('fec_bin'),intf_list[n]) 
                    st.error(err_str) 
                    error+=1 

                if int(result.get("codeword_uncorrectable"))!=0:
                    err_str="codeword_uncorrectable is not 0, it is {} on Interface {}".format(result.get('codeword_uncorrectable'),intf_list[n])
                    st.error(err_str)
                    error+=1

                if 1e-5>float(result.get("extrapolated_ber"))>1e-6: 
                    err_str="Extrapolated_BER is bigger than 1e-6, it's Orange Pass, it is {} on Interface {}".format(result.get('extrapolated_ber'),intf_list[n])
                    st.error(err_str)
                elif float(result.get("extrapolated_ber"))>1e-5:
                    err_str="Extrapolated_BER is bigger than 1e-6, it's Orange Pass, it is {} on Interface {}".format(result.get('extrapolated_ber'),intf_list[n])
                    st.error(err_str)
                    error+=1

                if float(result.get('frame_loss_rate'))>1e-17:
                    err_str="Frame Loss Rate is {} on Interface {}".format(result.get('frame_loss_rate'),intf_list[n])
                    st.error(err_str)
                    error+=1

                for each in result.get('FEC_BER_Lane'):
                    if each>1e-7:
                        err_str="FEC BER Lane is {} on Interface {}".format(each,intf_list[n])
                        st.error(err_str)
                        error+=1
                        break


                log_str="### LOG INFOR: mac-state analysis after Testing \n" 
                if error:
                    test_case="FAIL" 
                else:
                    test_case="PASS" 

                header_str="DUT     PORT    CABLE_LENGTH    FEC_BIN  CODEWORD_UNCORRECTABLE  EXTRAPOLATED_BER FRAME_LOSS_RATE    FEC_BER_LANE    UPTIME     LOG_FILE    PASS/FAIL" 
                st.log(header_str) 

                print("dut"+str(n+1),'TOPO1',intf_list[n],optics1,str(result['fec_bin']),result['codeword_uncorrectable'],result['extrapolated_ber'],result['frame_loss_rate'],str(result['FEC_BER_Lane']),str(uptime))

                st.log('### LOG INFOR: write results and Save Log file')

                result_str="dut"+str(n+1)+'\t'+intf_list[n]+"\t"+optics1+"\t"+str(result['fec_bin'])+"\t"+result['codeword_uncorrectable']+"\t"+result['extrapolated_ber']+"\t"+result['frame_loss_rate']+"\t"+str(result['FEC_BER_Lane'])+"\t"+str(uptime)+"\t"+log_file_name[n]+'\t'+test_case+'\n'  

                st.log("### LOG INFOR: result_str is")
                st.log(result_str) 
                st.log("### LOG INFOR: result_file_name is ") 
                st.log(result_file_name[n]) 
                write_results_to_file(result_str,result_file_name[n])

                copy_test_results(log_file_name[n]) 

        except Exception as e:
            st.error("Error: "+str(e))
            fail+=1

    for i in range(2):
        copy_test_results(result_file_name[i])

    for n,dut in enumerate([dut1,dut2]):
        st.config(dut, 'sudo config save -y') 


    if fail:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed") 


def test_link_flap():
    '''Link flap test case is run after test_enable_anlt, 
       ANLT needs to be enabled for this test 
    ''' 

    for i, dut in enumerate([dut1, dut2]):
        st.log('### LOG INFOR: DUT {} collect mac-state information before testing ## '.format(i))
        output=st.config(dut,"sudo show platform npu mac-state -a all")

        st.log('### LOG INFOR: clear mac-state information before testing ## ')

    fail=0

    st.log("### LOG INFOR: Create Log File and Result File")
    result_file_name=[None for i in range(2)]
    header_str="DUT     PORT    CABLE_LENGTH    FEC_BIN     CODEWORD_UNCORRECTABLE  EXTRAPOLATED_BER    FRAME_LOSS_RATE     FEC_BER_LANE    UPTIME  LOG_FILE\n"
    for i in range(2):
        result_file_name[i]="dut"+str(i+1)+"_Topo1_shut_noshut_final_report.txt"

        write_results_to_file(header_str,result_file_name[i])


    for i, intf in enumerate(local_links_dut1):

        intf2=local_links_dut2[local_links_dut1.index(intf)]
        optics1=check_cable_length(dut1, intf)
        link2=local_links_dut2[i]
        optics2=check_cable_length(dut2,link2)

        intf_list=[intf, link2]
        optics_list=[optics1, optics2]
        dut_list=[dut1, dut2]

        log_file_name=[None for i in range(2)]

        try:
            st.log('### LOG INFOR: On DUT1: Interface %s with cable length %s###'%(intf,optics1))

            st.log('### LOG INFOR: On DUT1, collect mac-state information before doing shut-noshut ## ')
            macstate_output1=st.config(dut1,"sudo show platform npu mac-state -i %s"%(intf))
            result1=parse_sh_plat_npu_mac_state_output(macstate_output1)

            for n, dut in enumerate([dut1, dut2]):
                header_str="===TEST SHUT/NOSHUT LOG FOR DUT{} WITH TOPO1 ON INTERFACE {}===\n".format(n+1,intf_list[n])
                log_file_name[n]="dut"+str(n+1)+"_Topo1_"+intf_list[n]+"_"+optics_list[n]+"_shut_noshut.log"
                write_results_to_file(header_str,log_file_name[n])

                log_str='### LOG INFOR: On DUT{}: Interface {} with cable length {}###\n'.format((n+1),intf_list[n],optics_list[n])
                st.log(log_str)
                write_results_to_file(log_str,log_file_name[n])

                st.config(dut, "sudo truncate -s 0 /var/log/syslog")

                st.log("--------Clear syslogs-------")
                logapi.clear_logging(dut)

                for ite in range(10):
                    error=0 
                    log_str='Iteration {}\n'.format(ite+1)
                    log_str2=('### LOG INFOR: Shutdown interface %s\n'%intf_list[n])
                    st.log(log_str+log_str2)
                    cmd="sudo config interface shutdown %s"%(intf_list[n])
                    output=st.config(dut, cmd)
                    write_results_to_file(log_str+log_str2+cmd+'\n'+output+'\n',log_file_name[n])


                    st.log('### LOG INFOR: Verify Link is down')
                    if not st.poll_wait(intapi.verify_interface_status, 60, dut, [intf_list[n]], 'oper', 'down'):
                        st.error("## ERROR: Interface {} is not down after enabling ANLT on one DUT, while the other is not".format(intf_list[n]))
                        fail+=1
                        continue

                    log_str='### LOG INFOR: clear mac-state information before bringup interface ## \n'
                    cmd="sudo show platform npu mac-state -i "+intf_list[n]
                    output=st.config(dut,cmd)
                    write_results_to_file(log_str+cmd+'\n'+output+'\n',log_file_name[n])


                    log_str='### LOG INFOR: Bringup interface %s\n'%intf_list[n]
                    st.log(log_str)
                    cmd="sudo config interface start %s"%(intf_list[n])
                    output=st.config(dut, cmd)

                    log_str2='### LOG INFOR: Verify Link is up\n'
                    st.log(log_str2)
                    write_results_to_file(log_str+cmd+'\n'+output+'\n'+log_str2,log_file_name[n])
                    if not st.poll_wait(intapi.verify_interface_status, 60, dut, [intf_list[n]], 'oper', 'up'):
                        st.error("## ERROR: Interface {} is not up after no shut".format(intf_list[n]))
                        fail+=1
                        continue

                    log_str='### LOG INFOR: On DUT{}, collect mac-state information After interface is up ## \n'.format(n+1)
                    st.log(log_str)
                    cmd="sudo show platform npu mac-state -i %s"%(intf_list[n])
                    macstate_output=st.config(dut,cmd)
                    result=parse_sh_plat_npu_mac_state_output(macstate_output)
                    write_results_to_file(log_str+cmd+'\n'+macstate_output+'\n',log_file_name[n])


                    st.log('### LOG INFOR: Check the uptime for shut/noshut')
                    uptime=check_uptime_syslog(dut, intf_list[n],PORT_STATUS_REGEX)
                    st.log('### LOG INFOR: dut1 interface {} took {} to come up after shut/noshut ##'.format(intf_list[n],str(uptime)))

                    log_str="### LOG INFOR: mac-state analysis after Testing \n"
                    header_str="DUT     PORT    CABLE_LENGTH    FEC_BIN  CODEWORD_UNCORRECTABLE  EXTRAPOLATED_BER FRAME_LOSS_RATE    FEC_BER_LANE    UPTIME     LOG_FILE"
                    st.log(header_str)

                    print("dut"+str(n+1),'TOPO1',intf_list[n],optics_list[n],str(result['fec_bin']),result['codeword_uncorrectable'],result['extrapolated_ber'],result['frame_loss_rate'],str(result['FEC_BER_Lane']),str(uptime),str(log_file_name[n]))

                    if int(result.get('fec_bin'))>10:
                        err_str="ORANGE PASS for FEC BIN, it is {} on Interface {}".format(result.get('fec_bin'),intf_list[n])
                        st.error(err_str)
                        error+=1

                    if int(result.get("codeword_uncorrectable"))!=0:
                        err_str="codeword_uncorrectable is not 0, it is {} on Interface {}".format(result.get('codeword_uncorrectable'),intf_list[n])
                        st.error(err_str)
                        error+=1

                    if 1e-5>float(result.get("extrapolated_ber"))>1e-6:
                        err_str="Extrapolated_BER is bigger than 1e-6, it's Orange Pass, it is {} on Interface {}".format(result.get('extrapolated_ber'),intf_list[n])
                        st.error(err_str)
                    elif float(result.get("extrapolated_ber"))>1e-5:
                        err_str="Extrapolated_BER is bigger than 1e-6, it's Orange Pass, it is {} on Interface {}".format(result.get('extrapolated_ber'),intf_list[n])
                        st.error(err_str)
                        error+=1

                    if float(result.get('frame_loss_rate'))>1e-17:
                        err_str="Frame Loss Rate is {} on Interface {}".format(result.get('frame_loss_rate'),intf_list[n])
                        st.error(err_str)
                        error+=1

                    for each in result.get('FEC_BER_Lane'): 
                        if each>1e-7:
                            err_str="FEC BER Lane is {} on Interface {}".format(each,intf_list[n])
                            st.error(err_str)
                            error+=1
                            break 

                    log_str="### LOG INFOR: mac-state analysis after Testing \n"
                    if error:
                        testcase="FAIL"
                    else:
                        testcase="PASS"

                    st.log('### LOG INFOR: write results and Save Log file')

                    result_str="dut"+str(n+1)+'\t'+intf_list[n]+"\t"+optics_list[n]+"\t"+str(result['fec_bin'])+"\t"+result['codeword_uncorrectable']+"\t"+result['extrapolated_ber']+"\t"+result['frame_loss_rate']+"\t"+str(result['FEC_BER_Lane'])+"\t"+str(uptime)+"\t"+str(log_file_name[n])+"\t"+testcase+"\n"

                    write_results_to_file(result_str,result_file_name[n])

                    st.log('Next Iteration is')
                    st.log(str(ite+1)) 

        except Exception as e:
            st.error("Error: "+str(e))
            fail+=1

    for i in range(2):
        copy_test_results(result_file_name[i])


    if fail or error:
        st.report_fail("test case_failed")
    else:
        st.report_pass("test_case_passed")


