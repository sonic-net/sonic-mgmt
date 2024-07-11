'''
this script performs rfc2544 latency testing
devices used : Cisco device as DUT (ex: Cisco 8111), IXIA
Connections: one connection from IXIA to Cisco 8111 and second connection from Cisco 8111 to same IXIA
Toplogy: IXIA ----- Cisco ----- IXIA

Aim of the script: (1) perform RFC2544 latency test and measure the latency numbers (avg.) for the given topology, this will gives the end-end latency
		           (2) we also calculate end-end media latency ( IXIA-IXIA latency ) just once, reason for this is explained in the step(3)
		           (3) based on step(1) and step(2), we deduce NPU latency of Cisco 8111-O64, NPU latency = latency numbers from Step(1) - (2 * latency numbers from Step(2))     
'''


import os
import time
import csv
import pandas as pd
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

data = SpyTestDict()

def initialize_variables():

    data.ipv4_T1D1P1 = "192.168.1.2" 
    data.ipv4_T1D1P2 = "192.168.2.2" 
    data.ipv4_D1T1P1 = "192.168.1.3" 
    data.ipv4_D1T1P2 = "192.168.2.3" 
    data.subnet_mask = "24"
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
    data.frame_size = ['4096']
    data.media_end_to_end_latency = media_end_end_latency()


@pytest.fixture(scope="module", autouse=True)
def rfc2544_latency_module_hooks(request) :

    global vars, dut, dut_to_tg_port_1, dut_to_tg_port_2, tg_handler, tg, tg1, tg2, tg_ph_1, tg_ph_2, avg_latency_data_yaml, topology_handles

    # extract DUT name 
    data.my_dut_list = st.get_dut_names()
    dut = data.my_dut_list[0] 

    # ensure minimum topology
    vars = st.ensure_min_topology("D1T1:2")

    # DUT details
    dut_to_tg_port_1 = vars.D1T1P1
    dut_to_tg_port_2 = vars.D1T1P2

    
    # Traffic Gen details
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])
    tg = tg_handler["tg"] 
    tg1 = tg_handler["tg1"]
    tg2 = tg_handler["tg2"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]

    # Create a topology on IXIA TGEN ports
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
        else:
            st.report_fail("could not create topology on Port {}".format(num))

    # intializing data variables for to store SpyTestDict
    initialize_variables()

    # loading contents 'expected_latency_avg.yaml' file.
    latency_yaml_file_path = 'system/latency_yaml_files/expected_latency_avg.yaml'
    with open(latency_yaml_file_path, "r") as latency_values_file:
        avg_latency_data_yaml = yaml.safe_load(latency_values_file)

    # clean up IP/PortChannel/Vlan/BGP configs on DUT.
    cleanup_dut(dut)

    # configure ipv4 address on DUT.
    try:
        st.log("configuring ipv4 address on DUT.")
        ipv4_dut_config(dut)
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed: configuring ipv4 address on DUT failed.")
    
    # check if configured ipv4 addresses on DUT are correct.
    try:
        st.log("checking if correct ipv4 address is configured on DUT interfaces.")
        verify_ipv4_dut_address(dut)
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed: checking of ipv4 address on DUT failed.")

    # configure ipv4 ebgp between DUT and TGEN.
    try:
        st.log("Configuring BGP on DUT.")
        bgp_dut_config(dut)
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed: ebgp config on DUT failed.")

    yield

    # clean up IP/PortChannel/Vlan/BGP configs on DUT as a part of teardown.
    cleanup_dut(dut)


# extract media end to end latency from 'media_end_end_latency.yaml' file based on the dut hwsku.
def media_end_end_latency():

    media_latency_file_path = 'system/latency_yaml_files/media_end_end_latency.yaml'
    with open(media_latency_file_path, "r") as file:
        media_latency_yaml = yaml.safe_load(file)

    cmd = "show interface transceiver eeprom {} | grep 'Media Interface Technology'".format(dut_to_tg_port_1)
    cable_info = st.show(dut, cmd=cmd).encode('ascii', 'ignore').split(":")[1].strip().split(" ")
    cable_info = [x.lower() for x in cable_info][0]

    media_end_end_latency = None

    for entry in media_latency_yaml['cable_type']:
        if cable_info in entry:
            latency_data = entry[cable_info]
            if 'media_end_end_latency' in latency_data:
                media_end_end_latency = latency_data['media_end_end_latency']
            break

    if media_end_end_latency is not None:
        st.log("Media End-to-End Latency for {}: {}".format(cable_info, media_end_end_latency))
    else:
        st.report_fail("Media End-to-End Latency not found for {}".format(cable_info))

    return float(media_end_end_latency)


# Configuring ipv4 on DUT interfaces to TGEN port 1 and port2.
def ipv4_dut_config(dut):
    
    # configure DUT interfaces connected to TGEN port1 and port2.
    for dut_port in [dut_to_tg_port_1, dut_to_tg_port_2]:
        if dut_port == dut_to_tg_port_1:
            interface_name = dut_port
            ip_address = data.ipv4_D1T1P1
        else:
            interface_name = dut_port
            ip_address = data.ipv4_D1T1P2
        st.log("Checking if DUT intf. {} connected to TGEN port is UP".format(dut_port))
        if not st.poll_wait(intf_obj.verify_interface_status, 20, dut, dut_port, 'oper', 'up'):
            st.report_fail("interface_is_down_on_dut", dut_port)
        st.log("Configuring IP address on DUT intf. {}".format(dut_port))
        if not ip_obj.config_ip_addr_interface(dut=dut, 
                                               interface_name=interface_name, 
                                               ip_address=ip_address, 
                                               subnet=data.subnet_mask, 
                                               family=data.ipv4_addr_family, 
                                               config='add'):
                                            
            st.report_fail("interface ip add failed", dut_port)


# Verify ipv4 address configured by func. ipv4_dut_config.
def verify_ipv4_dut_address(dut):

    # Check if DUT intf. connected to TGEN port 1 has the right ipv4 address configured.
    for dut_port in [dut_to_tg_port_1, dut_to_tg_port_2]:
        if dut_port == dut_to_tg_port_1:
            interface_name = dut_port
            ip_address = data.ipv4_D1T1P1
        else:
            interface_name = dut_port
            ip_address = data.ipv4_D1T1P2
        st.log("checking if DUT intf. {} has the correct ipv4 address configured".format(dut_port))
        if not ip_obj.verify_interface_ip_address(dut=dut, 
                                              interface_name=interface_name, 
                                              ip_address="{}/{}".format(ip_address, data.subnet_mask),
                                              family=data.ipv4_addr_family):
            st.report_fail("test_case_failed: correct ipv4 address {} not configured on {} interface.".format(ip_address, dut_port))
    

# Configuring BGP on DUT
def bgp_dut_config(dut):

    # create bgp neighborship between DUT and TGEN
    st.log("create DUT {} ebgp neighborship with TG Port1 {} and TG port2 {}".format(dut, tg_ph_1, tg_ph_2))
    bgp_obj.config_bgp(dut=dut, 
                       config="yes",
                       router_id=data.dut_router_id, 
                       local_as=data.dut_local_asn,
                       vrf_name="default",
                       neighbor=data.ipv4_T1D1P1,
                       remote_as=data.T1D1P1_local_asn,
                       keepalive=data.keepalive,
                       holdtime=data.holdtime,
                       addr_family=data.ipv4_addr_family,
                       network=data.dut_network,
                       config_type_list=["neighbor",
                                         "activate",
                                         "multipath-relax",
                                         ])

    # configuring neighbor statements for TG port2 under DUT bgp config
    bgp_obj.config_bgp(dut=dut,
                       config="yes",
                       router_id=data.dut_router_id,
                       remote_as=data.T1D1P2_local_asn,
                       neighbor=data.ipv4_T1D1P2,
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


# creating devices on configured TGEN Port1 and Port2.
def tgen_devices_config():

    tgen_reset()

    ipv4_handles = []

    for topology_handle in topology_handles:
        if topology_handle == topology_handles[0]:
            intf_ip_addr = data.ipv4_T1D1P1
            gateway_ip_addr = data.ipv4_D1T1P1
            mac_addr = '00:11:01:00:00:01'
            num = 1
        else:
            intf_ip_addr = data.ipv4_T1D1P2
            gateway_ip_addr = data.ipv4_D1T1P2
            mac_addr = '00:12:01:00:00:01'
            num = 2

        # Creating a device group in topology 
        st.log("Creating device group {} in topology {}".format(num, num))
        device_group = tg.tg_topology_config(
            topology_handle              = topology_handle,
            device_group_name            = """BGP_{} Device Group""".format(num),
            device_group_multiplier      = "1",
            device_group_enabled         = "1",
        )
        if device_group['status'] == '1':
            st.log(device_group['status'])
        else:
            st.report_fail("could not create device group {} on topology {}".format(num, num))
            
        deviceGroup_handle = device_group['device_group_handle']


        # Creating ethernet stack for the first Device Group 
        st.log("Creating ethernet stack for Device Group {}".format(num))
        l2_protocol = tg.tg_interface_config(
            protocol_name                = """Ethernet {}""".format(num),
            protocol_handle              = deviceGroup_handle,
            mtu                          = "1500",
            src_mac_addr                 = mac_addr,
            src_mac_addr_step            = "00.00.00.00.00.01",
        )
        if l2_protocol['status'] == '1':
            st.log(l2_protocol['status'])
        else:
            st.report_fail("could not create ethernet {} stack on Device group {}".format(num, num))
    
        ethernet_handle = l2_protocol['ethernet_handle'] 


        # Creating IPv4 Stack on top of Ethernet Stack for the first Device Group                                 
        st.log("Creating IPv4 Stack on top of Ethernet Stack for the {} Device Group".format(num))
        l3_protocol = tg.tg_interface_config(
            protocol_name                     = """IPv4 {}""".format(num),
            protocol_handle                   = ethernet_handle,
            ipv4_resolve_gateway              = "1",
            gateway                           = gateway_ip_addr,
            gateway_step                      = "0.0.0.0",
            intf_ip_addr                      = intf_ip_addr,
            intf_ip_addr_step                 = "0.0.0.1",
            netmask                           = "255.255.255.0",
        )
        if l3_protocol['status'] == '1':
            st.log(l3_protocol['status'])
        else:
            st.report_fail("Could not create IPv4 {} stack on top of Ethernet {} stack ".format(num, num))
            
        ipv4_handle = l3_protocol['ipv4_handle']
        ipv4_handles.append(ipv4_handle)

    # start protocols on all devices
    start_protocol = tg.tg_test_control(action='start_all_protocols')
    if start_protocol['status'] == '1':
        st.log("protocols started successfully")
    else:
        st.report_tgen_fail('start protocols failed!')
        
    # ping check between DUT and TGEN intfs.
    for addr in [data.ipv4_T1D1P1, data.ipv4_T1D1P2]:
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

    return ipv4_handles

# configuring TGEN devices with BGP.
def tgen_devices_bgp_config(num_routes):

    bgp_devices_handles = []

    ipv4_handles = tgen_devices_config()

    for ipv4_handle in ipv4_handles: 
        if ipv4_handle == ipv4_handles[0]:
            handle = ipv4_handles[0]
            local_as = data.T1D1P1_local_asn
            remote_ip_addr = data.ipv4_D1T1P1
            local_router_id = data.T1D1P1_router_id
        else:
            handle = ipv4_handles[1]
            local_as = data.T1D1P2_local_asn
            remote_ip_addr = data.ipv4_D1T1P2
            local_router_id = data.T1D1P2_router_id
    

        st.log("Configure BGP on TGEN device {}".format(ipv4_handle))
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
            prefix = data.bgp_route_prefix_T1D1P1
        else:
            prefix = data.bgp_route_prefix_T1D1P2
        bgp_device_route = tg.tg_emulation_bgp_route_config(
                                    mode='add',
                                    handle=bgp_devices_handle,
                                    num_routes=num_routes, 
                                    prefix=prefix,
                                    netmask=data.subnet_mask,
                                    as_path='as_seq:1')

        if bgp_device_route['status'] == '1':
            st.log("BGP route config on device {} is successful.".format(handle))
            st.log(str(bgp_device_route))
        else:
            st.log("BGP route config on device {} failed.".format(handle))
            st.log(str(bgp_device_route))

        bgp_device_start = tg.tg_emulation_bgp_control(mode='start',
                                                        handle=handle)
        
        if bgp_device_start['status'] == '1':
            st.log("BGP device {} started.".format(handle))
            st.log(str(bgp_device_start))
        else:
            st.log(str(bgp_device_start))
            st.log("BGP device {} start failed.".format(handle))
    
    verify_bgp_neighborship()
    return bgp_devices_handles


# verfiy eBGP neighborship between DUT and TGEN is in 'ESTABLISHED' state.
def verify_bgp_neighborship():

    st.log("Waiting for the eBGP neighbors to get Established between DUT and TGEN emulated devices.")
    st.wait(30, "wait for BGP state to move into 'Established' state.")
    for neighbor in [data.ipv4_T1D1P1, data.ipv4_T1D1P2]:
        bgp_state = ipbgp_obj.verify_bgp_neighbor(dut=dut, neighborip=neighbor, state='Established')

        if bgp_state:
            st.log("BGP state: 'Established' between {} and TGEN {}.".format(dut, neighbor))
            st.log("BGP state Established: {}".format(bgp_state))
        else:
            st.log("BGP state Established: {}".format(bgp_state))
            st.report_fail("BGP state: 'Not Established' between {} and TGEN {}.".format(dut, neighbor))


# creating streamblock for traffic generation between TGEN device1 and TGEN device2.
def tgen_create_streamblock(num_routes):

    dev_hdl = tgen_devices_bgp_config(num_routes)

    # Create TG streams
    if num_routes == 1:
        st.banner("creating stream for single flow between device on Port1 and device on Port2 of TGEN.")
    else:
        st.banner("creating stream for multiple flow between device on Port1 and device on Port2 of TGEN.")

    src_hdl=dev_hdl[0]
    dst_hdl=dev_hdl[1]

    streamblock_T1D1P1_T1D1P2 = tg1.tg_traffic_config(
                                mode='create',
                                name='StreamBlock_latency',
                                emulation_src_handle=topology_handles[0], 
                                emulation_dst_handle=topology_handles[1],
                                l3_protocol='ipv4',
                                l4_protocol='tcp',
                                tcp_src_port='1024',
                                tcp_dst_port='1024',
                                ip_ttl="255",
                                length_mode='fixed',
                                transmit_mode='continuous', 
                                circuit_endpoint_type='ipv4',
                                endpointset_count='1',
                                bidirectional='0'
                                )

    # checking streamblock status
    streamblock_status = streamblock_T1D1P1_T1D1P2['status']
    if (streamblock_status == '0'):
        st.log("failed to create streamblock {}".format(streamblock_T1D1P1_T1D1P2))
        st.log(str(streamblock_T1D1P1_T1D1P2))
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


# func to define custom load values for rfc2544 latency test.
def load_start_custom():

    load_str = ''
    load_start = 99 # for 200g -> 5, for 100g -> 2.5 ( if load_start == 10 )
    while load_start < 100: # for 200g -> 49.75, for 100g -> 24.875
        if load_start != 99.5:
            load_str += str(load_start) + ','
        else:
            load_str += str(load_start)
        if load_start < 95: # for 200g -> 47.5, for 100g -> 23.75
            load_start += 5 # for 200g -> 2.5, for 100g -> 1.25
        else:
            load_start += 0.5 # for 200g -> 0.25, for 100g -> 0.125
    return load_str


# func. to calculate extracted latency values based on media end to end latency.
def final_latency_avg(csv_file, num_routes):
    filename = open(csv_file, 'r')
    file = csv.DictReader(filename)

    avg_latency = []
    final_avg_latency = []

    for col in file:
        avg_latency.append(col['Avg Latency (ns)'])

    for latency_value in avg_latency:
        final_avg_latency.append(int(latency_value) - int(float(data.media_end_to_end_latency) * 1000))

    df = pd.read_csv(csv_file)
    df.drop(['Iteration', 'Tx Port', 'Rx Port', 'Traffic Item', 'Flow Group', 'Rx Throughput (fps)', 'Rx Throughput (Mbps)', 'Frame Loss (%)'], axis=1, inplace=True)
    df['Final Latency Avg (ns)'] = final_avg_latency

    dest_location = st.get_logs_path()
    if num_routes == 1:
        df.to_csv(dest_location+'/singleFlow_latency_results_final_avg_latency.csv', index=False)
    else:
        df.to_csv(dest_location+'/multipleFlow_latency_results_final_avg_latency.csv', index=False)

def copy_test_results(num_routes):

    import pexpect

    import pdb;pdb.set_trace()
    src_path = st.get_logs_path()
    if num_routes == 1:
        dst_dir = src_path.split("/")[-1]+'_singleFlow'
    else:
        dst_dir = src_path.split("/")[-1]+'_multipleFlow'
    dst_path = '/var/www/html/Logs/latency_results/{}'.format(dst_dir)
    server_name = 'sonic-ucs-m3-1'
    user = 'rraghav'
    password = 'roZes@123'

    scp_cmd = 'scp -r {} {}@{}:/{}'.format(src_path, user, server_name, dst_path)

    try:
        child = pexpect.spawn(scp_cmd)
        child.expect(["password:"])
        child.sendline(password)
        time.sleep(10)

    except Exception as e:
        st.log(("scp failed with: " + str(e)))


# main func. for rfc2544 latency test
def rfc2544_latency(num_routes):

    # streamblock_handle = tgen_create_streamblock(num_routes)
    tgen_create_streamblock(num_routes)

    from spytest.tgen.tg import get_ixiangpf as ixia_handle

    handle = ixia_handle()

    ixNet = handle.ixnet
    test = ixNet.add(ixNet.getRoot() + '/quickTest', 'rfc2544throughput')
    ixNet.commit()

    testId = ixNet.remapIds(test)
    print ("This is the QT id" + testId[0])

    ixNet.setMultiAttribute(testId[0] +'/testConfig', 
    '-enableMinFrameSize', 'False', 
    '-reportTputRateUnit', 'mbps', 
    '-numtrials', '1', 
    '-trafficType', 'constantLoading', 
    '-tolerance', '0.0', 
    '-staggeredStart', 'False', 
    '-rateSelect', 'percentMaxRate', 
    '-percentMaxRate', '100', 
    '-loadRateList', load_start_custom(),
    '-txDelay', '2', 
    '-delayAfterTransmit', '2', 
    '-calculateLatency', 'True', 
    '-latencyType', 'forwardingDelay',
    '-loadType', 'custom', 
    '-customLoadUnit', 'percentMaxRate',
    '-mapType', '[oneToOne]', 
    '-frameSizeMode', 'custom', 
    '-framesizeList', data.frame_size,
    '-duration', 60)

    trafficSelection = ixNet.add( testId[0], 'trafficSelection')
    ti1 = ixNet.getList(ixNet.getRoot() + '/traffic', 'trafficItem')[0]

    ixNet.setMultiAttribute(trafficSelection ,
            '-id'   ,ti1,
            '-isGenerated' ,'true')
    ixNet.commit()

    print("Starting QT ...")
    ixNet.execute('start', testId[0])
    print("Test id is %s" % testId[0])
    time.sleep(5)
    while True:
        progress = ixNet.getAttribute(testId[0] + '/results', '-progress')
        print("Progress: %s" % progress)
        status = ixNet.getAttribute(testId[0] + '/results', '-isRunning')
        if status == "false":
            print("Test finished")
            break
        time.sleep(5)
    
    source = st.get_logs_path()
    dest_location = source
    if not os.path.exists(dest_location):
        os.makedirs(dest_location)

    st.log("results copying")
    # Get csv path
    qt_csv_path = ixNet.getAttribute(testId[0]+'/results', '-{}'.format('resultPath'))
    st.log("Generating result.csv")
    qt_csv_file = os.path.join(qt_csv_path, "results.csv")

    # Copy csv path to somewhere
    if num_routes == 1:
        print("Copying singleFlow result.csv")
        ixNet.execute('copyFile', ixNet.readFrom(qt_csv_file, '-ixNetRelative'),ixNet.writeTo(dest_location+'/singleFlow_latency_results.csv', '-overwrite'))
        final_latency_avg(dest_location+'/singleFlow_latency_results.csv', num_routes)

    else:
        print("Copying multipleFlow result.csv")
        ixNet.execute('copyFile', ixNet.readFrom(qt_csv_file, '-ixNetRelative'),ixNet.writeTo(dest_location+'/multipleFlow_latency_results.csv', '-overwrite'))
        final_latency_avg(dest_location+'/multipleFlow_latency_results.csv', num_routes)

    copy_test_results(num_routes)
    st.report_pass("test_case_passed")


@pytest.mark.single_flow_latency_bgp
def test_rfc2544_single_flow_latency(num_routes=1):

    tgen_reset()
    rfc2544_latency(num_routes)


@pytest.mark.multiple_flow_latency_bgp
def test_rfc2544_multiple_flow_latency(num_routes=10):

    tgen_reset()
    rfc2544_latency(num_routes)
