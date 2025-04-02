'''This script performs Interface MTU testing
   devices used : Cisco device as DUT (ex: Cisco 8111) and traffic Generator 
   Connections: one connection from IXIA to Cisco 8111 and second connection from Cisco 8111 to same IXIA
   Toplogy: IXIA ----- Cisco ----- IXIA

   For each MTU size in: ["1514", "9114"]
   Perform the following test Steps:        
       (1) Send IPv4 ICMP packets and verify they are received 
       (2) Send IPv6 ICMP packets and verify they are received
       (3) Send regular IPv4 packets and verify they are received 
       (4) Send regular IPv6 packets and verify they are received

'''

import os
import time
import csv
import pytest
import yaml
import time
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.portchannel as port_obj
import apis.system.interface as intf_obj
import apis.routing.ip_bgp as ipbgp_obj
import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.switching.vlan as vlan_obj
import apis.system.reboot as reboot_obj
import apis.system.logging as logapi
import apis.system.port as papi

data = SpyTestDict()

def initialize_variables():

    data.ipv4_T1D1P1 = "200.0.1.2" 
    data.ipv4_T1D1P2 = "200.0.2.2" 
    data.ipv4_D1T1P1 = "200.0.1.3" 
    data.ipv4_D1T1P2 = "200.0.2.3" 
    data.subnet_mask = "24"
    data.tg_netmask="255.255.255.0" 
    data.dut_router_id = "10.1.0.32"
    data.T1D1P1_router_id = "192.0.0.1"
    data.T1D1P2_router_id = "192.0.0.2"
    data.dut_local_asn = "65000"
    data.T1D1P1_local_asn = "64001"
    data.T1D1P2_local_asn = "64500"
    data.keepalive = '3'
    data.holdtime = '10'
    data.dut_network = "10.1.0.32/32"
    data.ipv4_addr_family = "ipv4"
    data.bgp_route_prefix_T1D1P1 = "10.0.0.1"
    data.bgp_route_prefix_T1D1P2 = "20.0.0.1"

    ## ipv6 address ##
    data.ipv6_T1D1P1 = "2001:1::2"
    data.ipv6_T1D1P2 = "2001:2::2"
    data.ipv6_D1T1P1 = "2001:1::1"
    data.ipv6_D1T1P2 = "2001:2::1"
    data.ipv6_subnet_mask = "64"
    data.ipv6_tg_netmask="64"
    data.ipv6_addr_family = "ipv6"
    data.ipv6_dut_network = "2002:1::/64"
    data.ipv6_bgp_route_prefix_T1D1P1 = "fc00::1"
    data.ipv6_bgp_route_prefix_T1D1P2 = "fc01::1"


@pytest.fixture(scope="module", autouse=True)
def mtu_module_hooks(request) :

    global globalVars, dut, dut_to_tg_port_1, dut_to_tg_port_2, tg_handler, tg, tg1, tg2, tg_ph_1, tg_ph_2, avg_latency_data_yaml, topology_handles, topology_handles_dict 

    topology_handles_dict={} 
    # extract DUT name 
    data.my_dut_list = st.get_dut_names()
    dut = data.my_dut_list[0] 

    # ensure minimum topology
    globalVars = st.ensure_min_topology("D1T1:2")

    # DUT details
    dut_to_tg_port_1 = globalVars.D1T1P1
    dut_to_tg_port_2 = globalVars.D1T1P2

    
    # Traffic Gen details
    tg_handler = tgapi.get_handles(globalVars, [globalVars.T1D1P1, globalVars.T1D1P2])
    tg = tg_handler["tg"] 
    tg1 = tg_handler["tg1"]
    tg2 = tg_handler["tg2"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]

    initialize_variables()

    # clean up IP/PortChannel/Vlan/BGP configs on DUT.
    cleanup_dut(dut)
    tg1.clean_all()
    tg2.clean_all()

    st.log("Checking if DUT intf {} & {} connected to TGEN ports are UP".format(globalVars.D1T1P1,globalVars.D1T1P2))
    if not st.poll_wait(intf_obj.verify_interface_status, 20, dut, [globalVars.D1T1P1]+[globalVars.D1T1P2], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", dut_port)

    # configure ipv4 & ipv6 address on DUT.
    st.log("configuring ip address on DUT.")
    for ip_version in ['ipv4','ipv6']: 
        if not ip_dut_config(dut,ip_version):
            st.report_fail("test_case_failed: configuring ipv4 & ipv6 address on DUT failed.")
    
    # check if configured ip addresses on DUT are correct.
    st.log("checking if correct ip address is configured on DUT interfaces.")
    for ip_version in ['ipv4','ipv6']:
        if not verify_dut_ip_address(dut,ip_version):
            st.report_fail("test_case_failed: checking of ipv4 address on DUT failed.")

    # configure bgp between DUT and TGEN.
    st.log("Configuring BGP on DUT.")
    for ip_version in ['ipv4','ipv6']:
        bgp_dut_config(dut,ip_version)

    yield

    # clean up IP/PortChannel/Vlan/BGP configs on DUT as a part of teardown.
    cleanup_dut(dut)
    tg1.clean_all()
    tg2.clean_all()

# Configuring ipv4 on DUT interfaces to TGEN port 1 and port2.
def ip_dut_config(dut,ip_version='ipv4'):

    # configure DUT interfaces connected to TGEN port1 and port2.
    for dut_port in [dut_to_tg_port_1, dut_to_tg_port_2]:
        if dut_port == dut_to_tg_port_1:
            interface_name = dut_port
            if ip_version=='ipv4':
                ip_address = data.ipv4_D1T1P1
            else:
                ip_address = data.ipv6_D1T1P1
        else:
            interface_name = dut_port
            if ip_version=='ipv4':
                ip_address = data.ipv4_D1T1P2
            else:
                ip_address = data.ipv6_D1T1P2


        st.log("Configuring IP address on DUT intf. {}".format(dut_port))
        if ip_version == 'ipv4':
            subnet=data.subnet_mask
            family=data.ipv4_addr_family
        else:
            subnet=data.ipv6_subnet_mask
            family=data.ipv6_addr_family

        if not ip_obj.config_ip_addr_interface(dut=dut,
                                               interface_name=interface_name,
                                               ip_address=ip_address,
                                               subnet=subnet,
                                               family=family,
                                               config='add'):

            st.report_fail("interface ip add failed", dut_port)


def verify_dut_ip_address(dut,ip_version='ipv4'):

    # Check if DUT intf. connected to TGEN port 1 has the right ipv4 address configured.
    for dut_port in [dut_to_tg_port_1, dut_to_tg_port_2]:
        if dut_port == dut_to_tg_port_1:
            interface_name = dut_port
            ip_address = data.ipv4_D1T1P1 if ip_version=='ipv4' else data.ipv6_D1T1P1
            netmask=data.subnet_mask if ip_version=='ipv4' else data.ipv6_subnet_mask
            family=data.ipv4_addr_family if ip_version=='ipv4' else data.ipv6_addr_family
        else:
            interface_name = dut_port
            ip_address = data.ipv4_D1T1P2 if ip_version=='ipv4' else data.ipv6_D1T1P2
            netmask=data.subnet_mask if ip_version=='ipv4' else data.ipv6_subnet_mask
            family=data.ipv4_addr_family if ip_version=='ipv4' else data.ipv6_addr_family

        st.log("checking if DUT intf. {} has the correct ip address configured".format(dut_port))
        if not ip_obj.verify_interface_ip_address(dut=dut, 
                                              interface_name=interface_name, 
                                              ip_address="{}/{}".format(ip_address, netmask),
                                              family=family):
            st.error("ip address {} not configured on {} interface.".format(ip_address, dut_port))
            return False 

    return True 
    
# Configuring BGP on DUT
def bgp_dut_config(dut, ip_version='ipv4'):

    # create bgp neighborship between DUT and TGEN
    st.log("create DUT {} ebgp neighborship with TG Port1 {} and TG port2 {}".format(dut, tg_ph_1, tg_ph_2))
    neighbor=data.ipv4_T1D1P1 if ip_version=='ipv4' else data.ipv6_T1D1P1
    addr_family=data.ipv4_addr_family if ip_version=='ipv4' else data.ipv6_addr_family
    network=data.dut_network if ip_version=='ipv4' else data.ipv6_dut_network

    bgp_obj.config_bgp(dut=dut, 
                       config="yes",
                       router_id=data.dut_router_id, 
                       local_as=data.dut_local_asn,
                       vrf_name="default",
                       neighbor=neighbor,
                       remote_as=data.T1D1P1_local_asn,
                       keepalive=data.keepalive,
                       holdtime=data.holdtime,
                       addr_family=addr_family,
                       network=network,
                       config_type_list=["neighbor",
                                         "activate",
                                         "multipath-relax",
                                         ])

    neighbor=data.ipv4_T1D1P2 if ip_version=='ipv4' else data.ipv6_T1D1P2 
    # configuring neighbor statements for TG port2 under DUT bgp config
    bgp_obj.config_bgp(dut=dut,
                       config="yes",
                       router_id=data.dut_router_id,
                       remote_as=data.T1D1P2_local_asn,
                       neighbor=neighbor,
                       keepalive=data.keepalive,
                       holdtime=data.holdtime,
                       addr_family=addr_family,
                       network=network,
                       config_type_list=["neighbor",
                                         "activate"
                                         ])
    
    # configuring 'bgp log-neighbor-changes' cmd on DUT.
    bgp_obj.config_bgp_log_neighbor_changes(dut, data.dut_local_asn)

    # bgp graceful-restart user commands configuration
    user_commands = ["bgp graceful-restart restart-time 10", "bgp graceful-restart select-defer-time 45"]
    for user_command in user_commands:
        bgp_obj.config_bgp_graceful_restart(dut=dut,
                                            local_asn=data.dut_local_asn,
                                            config="add",
                                            preserve_state="yes",
                                            user_command=user_command)

    # configuring 'no bgp default ipv4-unicast' cmd on DUT.
    bgp_obj.config_bgp_default(dut=dut,
                               config="no",
                               local_asn=data.dut_local_asn,
                               user_command="ipv4-unicast")

    # configuring 'no bgp default ipv6-unicast' cmd on DUT.
    bgp_obj.config_bgp_default(dut=dut,
                               config="no",
                               local_asn=data.dut_local_asn,
                               user_command="ipv6-unicast")

    # saving BGP config to config_db.json on DUT
    st.log("saving the BGP config to config_db.json on DUT.")
    st.log("config save on DUT")
    reboot_obj.config_save(dut)

# Cleaning up BGP configuration on DUT
def bgp_dut_deconfig(dut):

    # clean up BGP on DUT and save config.
    bgp_obj.cleanup_router_bgp(dut)
    reboot_obj.config_save(dut)


def tgen_reset():

    # Reset and clear stats on TGEN Port1 and Port2 interfaces
    st.log("Reset TGEN {} and TGEN {} interfaces".format(tg_ph_1, tg_ph_2))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1, tg_ph_2])
    tg1.clean_all() 
    tg2.clean_all() 


# creating devices on configured TGEN Port1 and Port2.
def tgen_devices_config(mtu,ip_version='ipv4',is_icmp=False):

    tgen_reset()

    #Create a topology on IXIA TGEN ports
    num = [1, 2]
    topology_handles = []
    for i in num:
        if i == 1:
            port_handle = tg_ph_1
            num = 1
        else:
            port_handle = tg_ph_2
            num = 2

        st.log('Adding topology {} on Port {}'.format(num, num))
        device_port = tg.tg_topology_config(
            topology_name = """BGP_{} toplogy""".format(num),
            port_handle = port_handle
        )

        if device_port['status'] == '1':
            st.log(device_port['status'])
            topology_handles.append(device_port['topology_handle'])
            topology_handles_dict[port_handle]=device_port['topology_handle']
        else:
            st.report_fail("could not create topology on Port {}".format(num))

    ip_handles = []

    for i,topology_handle in enumerate(topology_handles):

        if topology_handle == topology_handles[0]:
            intf_ip_addr = data.ipv4_T1D1P1 if ip_version=='ipv4' else data.ipv6_T1D1P1 
            gateway_ip_addr = data.ipv4_D1T1P1 if ip_version=='ipv4' else data.ipv6_D1T1P1 
            mac_addr = '00:11:01:00:00:01'
            num = 1
            custom_link_local_address = "fe80::1:0:0:1e" 
        else:
            intf_ip_addr = data.ipv4_T1D1P2 if ip_version=='ipv4' else data.ipv6_T1D1P2
            gateway_ip_addr = data.ipv4_D1T1P2 if ip_version=='ipv4' else data.ipv6_D1T1P2 
            mac_addr = '00:12:01:00:00:01'
            num = 2
            custom_link_local_address = "fe80::2:0:0:1" 

        # Creating a device group in topology 
        st.log("Creating device group {} in topology {}".format(num, num))
        device_group = tg.tg_topology_config(
            topology_handle              = topology_handle,
            device_group_name            = """BGP_{} Device Group""".format(num),
            device_group_multiplier      = "1",
            device_group_enabled         = "1",
        )
        if device_group['status'] == '1':
            st.log("Successfully created device group {} on topology {}".format(num, num))
        else:
            st.report_fail("could not create device group {} on topology {}".format(num, num))
            
        deviceGroup_handle = device_group['device_group_handle']

        # Creating ethernet stack for the first Device Group 
        st.log("Creating ethernet stack for Device Group {}".format(num))
        if i==0: 

            l2_protocol = tg.tg_interface_config(
            protocol_name                = """Ethernet {}""".format(num),
            protocol_handle              = deviceGroup_handle,
            mtu                          = mtu,
            src_mac_addr                 = mac_addr
            )
        else:

            l2_protocol = tg.tg_interface_config(
            protocol_name                = """Ethernet {}""".format(num),
            protocol_handle              = deviceGroup_handle,
            mtu                          = mtu,
            src_mac_addr                 = mac_addr
            )

 
        if l2_protocol['status'] == '1':
            st.log('Successfully create ethernet {} stack on Device group {}'.format(num, num))
        else:
            st.report_fail("could not create ethernet {} stack on Device group {}".format(num, num))
    
        ethernet_handle = l2_protocol['ethernet_handle'] 


        # Creating IPv4/IPv6 Stack on top of Ethernet Stack for the first Device Group                                 
        st.log("Creating {} Stack on top of Ethernet Stack for the {} Device Group".format(ip_version,num))
        netmask = data.tg_netmask if ip_version=='ipv4' else data.ipv6_tg_netmask
        if ip_version == 'ipv4': 
            l3_protocol = tg.tg_interface_config(
            protocol_name                     = """{} device {} """.format(ip_version, num),
            protocol_handle                   = ethernet_handle,
            ipv4_resolve_gateway              = "1",
            gateway                           = gateway_ip_addr,
            intf_ip_addr                      = intf_ip_addr,
            netmask                           = netmask,
            )
        else:
            l3_protocol = tg.tg_interface_config(
            protocol_name                     = """{} device {} """.format(ip_version, num),
            protocol_handle                   = ethernet_handle,
            ipv6_resolve_gateway              = "1",
            ipv6_gateway                      = gateway_ip_addr,
            ipv6_intf_addr                    = intf_ip_addr,
            ipv6_prefix_length                = netmask,
            use_custom_link_local_address     = "0",
            custom_link_local_address = custom_link_local_address,
            ipv6_send_ra = "0",
            ipv6_discover_gateway_ip= "0",
            ipv6_include_ra_prefix= "0",
            )

        if l3_protocol['status'] == '1':
            st.log(l3_protocol['status'])
        else:
            st.report_fail("Could not create {} {} stack on top of Ethernet {} stack ".format(ip_version,num, num))
            
        ip_handle = l3_protocol['ipv4_handle'] if ip_version=='ipv4' else l3_protocol['ipv6_handle']
        ip_handles.append(ip_handle)

    # start protocols on all devices
    start_protocol = tg.tg_test_control(action='start_all_protocols')
    if start_protocol['status'] == '1':
        st.log("protocols started successfully")
    else:
        st.report_tgen_fail('start protocols failed!')
        
    # ping check between DUT and TGEN intfs.
    ping_addrs = [data.ipv4_T1D1P1, data.ipv4_T1D1P2] if ip_version=='ipv4' else [data.ipv6_T1D1P1, data.ipv6_T1D1P2] 
    for addr in ping_addrs:
        iteration = 0
        while iteration < 3:
            result = ip_obj.ping(dut, addr)
            if not result:
                iteration += 1
                time.sleep(10)
            else: 
                break
        else:
            return False
    
    # stop protocols on all devices
    stop_protocol = tg.tg_test_control(action='stop_all_protocols')
    if stop_protocol['status'] == '1':
        st.log("protocols stopped successfully")
    else:
        st.report_tgen_fail('stop protocols failed!')

    return (topology_handles,topology_handles_dict,ip_handles) 

# configuring TGEN devices with BGP.
def tgen_devices_bgp_config(mtu,ip_version='ipv4'):

    bgp_devices_handles = []

    try: 
        (topology_handles,topology_handles_dict,ip_handles) = tgen_devices_config(mtu,ip_version)
    except Exception as e:
        st.log("Tgen BGP config failed: "+str(e))
        return False 

    for ip_handle in ip_handles: 
        if ip_handle == ip_handles[0]:
            handle = ip_handles[0]
            local_as = data.T1D1P1_local_asn
            remote_ip_addr = data.ipv4_D1T1P1 if ip_version=='ipv4' else data.ipv6_D1T1P1
            local_router_id = data.T1D1P1_router_id
        else:
            handle = ip_handles[1]
            local_as = data.T1D1P2_local_asn
            remote_ip_addr = data.ipv4_D1T1P2 if ip_version=='ipv4' else data.ipv6_D1T1P2
            local_router_id = data.T1D1P2_router_id
    

        st.log("Configure BGP on TGEN device {}".format(ip_handle))
        tg.topo_handle=topology_handles_dict

        if ip_version=='ipv4': 
            bgp_device = tg.tg_emulation_bgp_config(
                                    mode='enable',
                                    handle=handle,
                                    active_connect_enable='1',
                                    local_as=local_as,
                                    local_as_step=1,
                                    local_router_id=local_router_id,
                                    ip_version='4',
                                    remote_as=data.dut_local_asn,
                                    gateway_ip_addr=remote_ip_addr,
                                    remote_ip_addr=remote_ip_addr,
                                    local_as_mode='increment',
                                    hold_time='10',
                                    keepalive_timer='3',
                                    graceful_restart_enable='1',
                                    restart_time='10',
                                    session_retry_delay_time='1',
                                    ipv4_unicast_nlri='1',
                                    neighbor_type='external'
                                    )

        else:
            bgp_device = tg.tg_emulation_bgp_config(
                                    mode='enable',
                                    handle=handle,
                                    active_connect_enable='1',
                                    local_as=local_as,
                                    local_as_step=1,
                                    local_router_id=local_router_id,
                                    ip_version='6',
                                    remote_as=data.dut_local_asn,
                                    remote_ipv6_addr=remote_ip_addr,
                                    gateway_as_remote_ipv6_addr='1', 
                                    local_as_mode='increment',
                                    hold_time='10',
                                    keepalive_timer='3',
                                    graceful_restart_enable='1',
                                    restart_time='10',
                                    session_retry_delay_time='1',
                                    ipv6_unicast_nlri='1',
                                    neighbor_type='external'
                                    )

        
        if bgp_device['status'] == '1':
            st.log("BGP config on device {} is successful.".format(handle))
            st.log(str(bgp_device))
            bgp_devices_handles.append(bgp_device['handle'])
        else:
            st.log("BGP config on device {} failed.".format(handle))
            st.log(str(bgp_device))
            st.report_fail("test_case_failed: BGP config on TGEN device {} failed.".format(handle))

    for bgp_devices_handle in bgp_devices_handles:
        st.log("add routes to TGEN BGP device {}".format(bgp_devices_handle))
        if bgp_devices_handle == bgp_devices_handles[0]:
            prefix = data.bgp_route_prefix_T1D1P1 if ip_version=='ipv4' else data.ipv6_bgp_route_prefix_T1D1P1
        else:
            prefix = data.bgp_route_prefix_T1D1P2 if ip_version=='ipv4' else data.ipv6_bgp_route_prefix_T1D1P2

        if ip_version=='ipv4': 
            bgp_device_route = tg.tg_emulation_bgp_route_config(
                                    mode='add',
                                    handle=bgp_devices_handle,
                                    num_routes=1, 
                                    prefix=prefix,
                                    netmask=data.tg_netmask,
                                    as_path='as_seq:1')
        else:
            bgp_device_route = tg.tg_emulation_bgp_route_config(
                                    mode='add',
                                    handle=bgp_devices_handle,
                                    ip_version='6', 
                                    num_routes=1,
                                    prefix=prefix,
                                    ipv6_prefix_length=data.ipv6_tg_netmask,
                                    as_path='as_seq:1')


        if bgp_device_route['status'] == '1':
            st.log("BGP route config on device {} is successful.".format(handle))
            st.log(str(bgp_device_route))
        else:
            st.error("BGP route config on device {} failed.".format(handle))
            st.error(str(bgp_device_route))

        bgp_device_start = tg.tg_emulation_bgp_control(mode='start',
                                                        handle=handle)
        
        if bgp_device_start['status'] == '1':
            st.log("BGP device {} started.".format(handle))
            st.log(str(bgp_device_start))
        else:
            st.error(str(bgp_device_start))
            st.error("BGP device {} start failed.".format(handle))
    
    verify_bgp_neighborship(ip_version)
    return (topology_handles, bgp_devices_handles,ip_handles) 


# verfiy eBGP neighborship between DUT and TGEN is in 'ESTABLISHED' state.
def verify_bgp_neighborship(ip_version='ipv4'):

    st.log("Waiting for the eBGP neighbors to get Established between DUT and TGEN emulated devices.")
    st.wait(30, "wait for BGP state to move into 'Established' state.")
    neighbors=[data.ipv4_T1D1P1, data.ipv4_T1D1P2] if ip_version=='ipv4' else [data.ipv6_T1D1P1, data.ipv6_T1D1P2]
    for neighbor in neighbors:
        bgp_state = ipbgp_obj.verify_bgp_neighbor(dut=dut, neighborip=neighbor, state='Established')

        if bgp_state:
            st.log("BGP state: 'Established' between {} and TGEN {}.".format(dut, neighbor))
            st.log("BGP state Established: {}".format(bgp_state))
        else:
            st.log("BGP state Established: {}".format(bgp_state))
            st.report_fail("BGP state: 'Not Established' between {} and TGEN {}.".format(dut, neighbor))


# creating streamblock for traffic generation between TGEN device1 and TGEN device2.
def tgen_create_streamblock(mtu,ip_version='ipv4',is_icmp=False):

    (topology_handles,dev_hdl,ip_handles) = tgen_devices_bgp_config(mtu,ip_version)

    # Create TG streams
    st.banner("creating stream for single flow between device on Port1 and device on Port2 of TGEN.")

    src_hdl=dev_hdl[0]
    dst_hdl=dev_hdl[1]

    ip_src_addr=data.ipv4_T1D1P1 if ip_version=='ipv4' else data.ipv6_T1D1P1
    ip_dst_addr=data.ipv4_T1D1P2 if ip_version=='ipv4' else data.ipv6_T1D1P2 

    if not is_icmp: 
        if ip_version=='ipv4': 
            streamblock_T1D1P1_T1D1P2 = tg1.tg_traffic_config(
                                mode='create',
                                name='StreamBlock_mtu',
                                emulation_src_handle=topology_handles[0], 
                                emulation_dst_handle=topology_handles[1],
                                ip_src_addr=ip_src_addr,
                                ip_dst_addr=ip_dst_addr, 
                                frame_size=mtu, 
                                pkts_per_burst=10, 
                                rate_percent=20, 
                                circuit_endpoint_type=ip_version,
                                ip_ttl=64, 
                                endpointset_count='1',
                                enable_data_integrity='1', 
                                track_by='traffic_item', 
                                bidirectional='0'
                                )
        else:
            streamblock_T1D1P1_T1D1P2 = tg1.tg_traffic_config(
                                mode='create',
                                name='StreamBlock_mtu',
                                emulation_src_handle=topology_handles[0],
                                emulation_dst_handle=topology_handles[1],
                                l3_protocol='ipv6',
                                l4_protocol='tcp',
                                tcp_src_port='1234',
                                tcp_dst_port='80',
                                ipv6_src_addr=ip_src_addr,
                                ipv6_dst_addr=ip_dst_addr,
                                frame_size=mtu,
                                pkts_per_burst=10, 
                                rate_percent=20,
                                circuit_endpoint_type=ip_version,
                                ip_ttl=64,
                                endpointset_count='1',
                                enable_data_integrity='1',
                                track_by='traffic_item', 
                                bidirectional='0'
             )


    else:
        if ip_version=='ipv4': 
            streamblock_T1D1P1_T1D1P2 = tg1.tg_traffic_config(
                                mode='create',
                                name='StreamBlock_mtu',
                                emulation_src_handle=topology_handles[0],
                                emulation_dst_handle=topology_handles[1],
                                ip_src_addr=ip_src_addr,
                                ip_dst_addr=ip_dst_addr,
                                frame_size=mtu,
                                circuit_endpoint_type=ip_version,
                                ip_ttl=64,
                                rate_percent=20, 
                                l3_protocol='ipv4', 
                                l4_protocol='icmp', 
                                icmp_type=8,
                                icmp_code=0,
                                enable_data_integrity='1',
                                track_by='traffic_item', 
                                bidirectional='0'
                                )
        else:
            streamblock_T1D1P1_T1D1P2 = tg1.tg_traffic_config(
                                mode='create',
                                name='StreamBlock_mtu',
                                emulation_src_handle=ip_handles[0],
                                emulation_dst_handle=ip_handles[1],
                                frame_size=mtu,
                                transmit_mode='continuous',
                                src_dest_mesh='one_to_one',
                                route_mesh='one_to_one',
                                circuit_endpoint_type=ip_version,
                                ip_ttl=64,
                                l3_protocol='ipv6',
                                l4_protocol='icmp', 
                                rate_percent=20,
                                icmp_type_mode='fixed',
                                icmp_type='128',
                                icmp_type_tracking='0',
                                icmp_id_mode='fixed',
                                icmp_code = '0',
                                icmp_id='0',
                                icmp_id_tracking='0',
                                icmp_seq_mode='fixed',
                                icmp_seq='0',
                                icmp_seq_tracking='0',
                                endpointset_count='1',
                                enable_data_integrity='1',
                                track_by='traffic_item', 
                                bidirectional='0', 
            ) 

    # checking streamblock status
    streamblock_status = streamblock_T1D1P1_T1D1P2['status']

    if (streamblock_status == '0'):
        st.log("failed to create streamblock {}".format(streamblock_T1D1P1_T1D1P2))
        st.log(str(streamblock_T1D1P1_T1D1P2))
        return False 
    else:
        st.log("streamblock created successfully {}".format(streamblock_T1D1P1_T1D1P2))
        st.log(str(streamblock_T1D1P1_T1D1P2))
        tg1_stream_id = streamblock_T1D1P1_T1D1P2["stream_id"] 
    
    return tg1_stream_id
       

# clean up IP/PortChannel/Vlan/BGP configs on DUT.
def cleanup_dut(dut):

    # Clean up interface ip addresses
    try:
        st.log("Delete ip address configuration on DUT.")
        ip_obj.clear_ip_configuration(dut, family=data.ipv4_addr_family, thread=True)
        ip_obj.clear_ip_configuration(dut, family=data.ipv6_addr_family, thread=True)
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed")

    # Clean up PortChannel config on DUT.
    try:
        st.log("Delete port channel configuration on DUT.")
        port_obj.clear_portchannel_configuration(dut, thread=True)
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed")
    
    # Clean up vlan config on DUT.
    try:
        st.log("Delete PortChannel config on DUT.")
        vlan_obj.clear_vlan_configuration(dut)
    except Exception as e:
        st.log(str(e))
        st.report_fail("test_case_failed")

    # Clean up BGP config on DUT configuring DUT with test required BGP config.
    try:
        st.log("Delete BGP config on DUT.")
        bgp_dut_deconfig(dut)
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed")

def run_traffic(mtu,ip_version='ipv4',is_icmp=False):
    stream=tgen_create_streamblock(mtu,ip_version,is_icmp)

    if not stream:
        st.error('Failed to create traffic stream: '+str(e))
        return False

    result=tg1.tg_traffic_control(action='run', handle=stream)

    if not result:
        st.error('Failed to run traffic: '+str(e))
        return False

    st.tg_wait(10)

    return stream  

def stop_traffic(stream_id):
    st.log('#Stopping the Traffic Stream')
    tg1.tg_traffic_control(action='stop', handle=stream_id)
    time.sleep(15)

def verify_traffic(verify_packet_loss=False):

    st.log('Check counter on the interface')
    stats=tg.tg_traffic_stats() 
    tg2_data_integrity_frames=stats[tg_ph_2]['aggregate']['rx']['data_int_frames_count'] 
    tg2_data_integrity_errors=stats[tg_ph_2]['aggregate']['rx']['data_int_errors_count']
    st.log("Data Integrity Frames Received")
    st.log(tg2_data_integrity_frames)
    st.log("Data Integrity Errors")
    st.log(tg2_data_integrity_errors)

    tg1_tx_count=stats[tg_ph_1]['aggregate']['tx']['pkt_count'] 
    tg1_rx_count=stats[tg_ph_1]['aggregate']['rx']['pkt_count']
    tg2_rx_count=stats[tg_ph_2]['aggregate']['rx']['pkt_count']


    st.log('tg1_stats.tx packets : {}'.format(tg1_tx_count))
    st.log('tg1_stats.rx packets : {}'.format(tg1_rx_count))

    st.log('tg2_stats.rx packets : {}'.format(tg2_rx_count))

    ret_val=True

    st.banner("Calculation of Percent rx")
    percent_rx = int(tg2_rx_count) / int(tg1_tx_count) * 100

    st.log('## Test Case Info, Traffic passing percent : {} % ## '.format(percent_rx))
    if verify_packet_loss:
        if percent_rx < 99.5: 
            st.log("bgp_traffic failed")
            ret_val = False
        else:
            st.log("bgp_traffic passed")
            ret_val = True

    if tg2_data_integrity_errors!=0 or int(tg2_data_integrity_frames)/int(tg1_tx_count) * 100 < 99.5:
        st.error('tg2_data_integrity verification Failed') 
        return False 

    return ret_val


def run_mtu_test(mtu='1514',ip_version='ipv4',is_icmp=False):

    test_fail = 0 
    st.log("## Test MTU size {} ##".format(mtu)) 
    tgen_reset() 
    st.log("## Configure MTU on the Interfaces ##")
    intf_obj.interface_properties_set(dut, [globalVars.D1T1P1]+[globalVars.D1T1P2], "mtu", mtu)

    stream1=run_traffic(mtu,ip_version,is_icmp)
    if not stream1:
        return False 

    time.sleep(15) 
    stop_traffic(stream1) 
    st.wait(30) 

    if not verify_traffic(True): 
        st.log("Test MTU {} failed due to traffic verification Failed!".format(mtu))
        test_fail+=1 

    if test_fail:
        return False 
    else:  
        return True  

@pytest.mark.parametrize("mtu", ["1514", "9114"])
def test_mtu(mtu):
    fail=0 
    ip_versions=['ipv4','ipv6'] 

    for is_icmp in [True, False]: 
        packet_type='IP' if not is_icmp else 'ICMP' 

        for ip_version in ip_versions: 
            if not run_mtu_test(mtu,'ipv4',is_icmp=is_icmp):  
                st.error("test_case with MTU {} {} {} packets Failed".format(mtu,packet_type,ip_version))
                fail+=1 

    if fail:
        st.report_fail("test case failed with MTU {}".format(mtu))
    else:
        st.report_pass("test case passed with MTU {}".format(mtu))


