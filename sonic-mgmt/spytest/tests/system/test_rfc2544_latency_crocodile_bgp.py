'''
this script performs rfc2544 latency testing
devices used : Cisco device as DUT (ex: Cisco 8111), Spirent
Connections: one connection from spirent to Cisco 8111 and second connection from Cisco 8111 to same Spirent 
Toplogy: Spirent ----- Cisco ----- Spirent

Aim of the script: (1) perform RFC2544 latency test and measure the latency numbers (avg.) for the given topology, this will gives the end-end latency
		           (2) we also calculate end-end media latency ( spiren-spirent latency ) just once, reason for this is explained in the step(3)
		           (3) based on step(1) and step(2), we deduce NPU latency of Cisco 8111-O64, NPU latency = latency numbers from Step(1) - (2 * latency numbers from Step(2))     
'''


import pytest
import yaml
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.portchannel as port_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj 
import apis.routing.ip_bgp as ipbgp_obj
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
    data.frame_size = ['1000', '1500', '9000']
    data.media_end_to_end_latency = media_end_end_latency()


@pytest.fixture(scope="module", autouse=True)
def rfc2544_latency_module_hooks(request) :

    global vars, dut, dut_to_tg_port_1, dut_to_tg_port_2, tg_handler, tg, tg1, tg2, tg_ph_1, tg_ph_2, cli_type, tgen_dev_handles, avg_latency_data_yaml

    # extract DUT name 
    data.my_dut_list = st.get_dut_names()
    dut = data.my_dut_list[0]

    # ensure minimum topology
    vars = st.ensure_min_topology("D1T1:2")

    # DUT details
    dut_to_tg_port_1 = vars.D1T1P1
    dut_to_tg_port_2 = vars.D1T1P2
    cli_type = st.get_ui_type(dut)
    if cli_type == 'click':
        data.shell = 'vtysh'
    
    # Traffic Gen details
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])
    tg = tg_handler["tg"] 
    tg1 = tg_handler["tg1"] 
    tg2 = tg_handler["tg2"]
    tg_ph_1 = tg_handler["tg_ph_1"] 
    tg_ph_2 = tg_handler["tg_ph_2"]

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

    # config TGEN port1 and port2 interfaces.
    try:
        st.log("Configuring TGEN port1 and port2.")
        tgen_dev_handles = tgen_preconfig()
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed: failed to config TGEN port1/port2 interfaces.")

    # config devices under TGEN port1 and port2 interfaces.
    try:
        st.log("adding devices under port1 and port2 on TGEN and checking ping between TGEN port1 and DUT, DUT and TGEN port2.")
        tgen_devices_config()
    except Exception as e:
        st.error(str(e))
        st.report_fail("test_case_failed: ping between devices would have failed.")

    yield

    # clean up IP/PortChannel/Vlan/BGP configs on DUT as a part of teardown.
    cleanup_dut(dut)


# extract media end to end latency from 'media_end_end_latency.yaml' file based on the dut hwsku.
def media_end_end_latency():

    media_latency_file_path = 'system/latency_yaml_files/media_end_end_latency.yaml'
    with open(media_latency_file_path, "r") as file:
        media_latency_yaml = yaml.safe_load(file)

    dut_hwsku = basic_obj.get_hwsku(dut)

    media_end_end_latency = None

    for entry in media_latency_yaml['hwsku']:
        if dut_hwsku in entry:
            latency_data = entry[dut_hwsku]
            if 'media_end_end_latency' in latency_data:
                media_end_end_latency = latency_data['media_end_end_latency']
            break

    if media_end_end_latency is not None:
        st.log("Media End-to-End Latency for {}: {}".format(dut_hwsku, media_end_end_latency))
    else:
        st.report_fail("Media End-to-End Latency not found for {}".format(dut_hwsku))

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
    reboot_obj.config_save(dut=dut,shell='vtysh')


# Cleaning up BGP configuration on DUT
def bgp_dut_deconfig(dut):

    # clean up BGP on DUT and save config.
    bgp_obj.cleanup_router_bgp(dut)
    reboot_obj.config_save(dut, shell='vtysh')


def tgen_reset():

    # Reset and clear stats on TGEN Port1 and Port2 interfaces
    st.log("Reset TGEN {} and TGEN {} interfaces".format(tg_ph_1, tg_ph_2))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1, tg_ph_2])


# configuring TGEN port1 and port2 interfaces
def tgen_preconfig():

    # for storing handles for TGEN port1 and port2.
    tgen_dev_handles = []

    tgen_reset()

    for tgen_port in [tg_ph_1, tg_ph_2]:
        if tgen_port == tg_ph_1:
            port_handle = tgen_port
            intf_ip_address = data.ipv4_T1D1P1
            gateway=data.ipv4_D1T1P1
            src_mac_addr='00:10:94:00:00:01'
        else:
            port_handle = tgen_port
            intf_ip_address = data.ipv4_T1D1P2
            gateway=data.ipv4_D1T1P2
            src_mac_addr='00:10:94:00:00:02'
        
        # Configure TGEN interface port
        st.log("Configure TGEN {} interface".format(tgen_port))
        intf_config=tg.tg_interface_config(
                                    port_handle=port_handle,
                                    mode='config',
                                    intf_ip_addr=intf_ip_address,
                                    gateway=gateway,
                                    src_mac_addr=src_mac_addr,
                                    autonegotiation='0',
                                    scheduling_mode='port_based',
                                    data_path_mode='normal',
                                    control_plane_mtu='1500',
                                    flow_control='false',
                                    arp_send_req='1',
                                    arp_req_retries='5')

        # checking the TGEN Port status
        st.log("checking if TGEN {} interface config is success or fail".format(tgen_port))
        intf_config_status = intf_config['status']
        if (intf_config_status == '0'):
            st.log("TGEN {} interface config failed ".format(tgen_port))
            st.log(str(intf_config))
        else:
            st.log("TGEN {} interface config success ".format(tgen_port))
            st.log("INTFCONF: {}".format(intf_config))
            intf_dev_hdl = intf_config['handle']
            tgen_dev_handles.append(intf_dev_hdl) 
    
    return tgen_dev_handles


# creating devices on configured TGEN Port1 and Port2.
def tgen_devices_config():

    for tgen_dev_handle in tgen_dev_handles:
        if tgen_dev_handle == tgen_dev_handles[0]:
            port_handle = tg_ph_1
            handle = tgen_dev_handle[0]
            intf_ip_addr = data.ipv4_T1D1P1
            gateway_ip_addr = data.ipv4_D1T1P1
            mac_addr = '00:10:94:00:00:01'
            router_id = data.T1D1P1_router_id
        else:
            port_handle = tg_ph_2
            handle = tgen_dev_handle[1]
            intf_ip_addr = data.ipv4_T1D1P2
            gateway_ip_addr = data.ipv4_D1T1P2
            mac_addr = '00:10:94:00:00:02'
            router_id = data.T1D1P2_router_id

        # Create device (Host) on TGEN Port
        device_port = tg.tg_emulation_device_config(
                                    mode='create',
                                    port_handle=port_handle,
                                    handle=handle,
                                    count='1',
                                    encapsulation='ethernet_ii',
                                    ip_version='ipv4',
                                    intf_ip_addr=intf_ip_addr,
                                    intf_prefix_len=data.subnet_mask,
                                    intf_ip_addr_step='0.0.0.1',
                                    use_default_phy_mac='false',
                                    gateway_ip_addr=gateway_ip_addr,
                                    gateway_ip_addr_step='0.0.0.0',
                                    mac_addr=mac_addr,
                                    mac_addr_step='00:00:00:00:00:01',
                                    tos_type='tos',
                                    tos='192',
                                    resolve_gateway_mac='true',
                                    router_id=router_id,
                                    router_id_step='0.0.0.1',
                                    enable_ping_response='1')

        # checking the status of TG device on Port
        device_port1_status = device_port['status']
        if (device_port1_status == '0'):
            st.log("TGEN {} emulation device config failed".format(port_handle))
            st.log(str(device_port))
        else:
            st.log("TGEN {} emulation device config success".format(port_handle))
            st.log(str(device_port))
    
    # verify ping between TGEN ports and DUT
    for tgen_dev_handle in tgen_dev_handles:
        if tgen_dev_handle == tgen_dev_handles[0]:
            port_handle = tg_ph_1
            dev_handle= tgen_dev_handles[0]
            dst_ip = data.ipv4_D1T1P1
            dut_handle = dut_to_tg_port_1
        else:
            port_handle = tg_ph_2
            dev_handle=tgen_dev_handles[1]
            dst_ip=data.ipv4_D1T1P2
            dut_handle = dut_to_tg_port_2

        ping_check = tgapi.verify_ping(src_obj=tg, port_handle=port_handle, dev_handle=dev_handle, dst_ip=dst_ip, ping_count='5', exp_count='5')

        if ping_check:
            st.log("Ping successful between TGEN {} and DUT port {}".format(port_handle, dut_handle))
            st.log(ping_check)
        else:
            st.log(ping_check)
            st.report_fail("ping fail between TGEN {} and DUT port {}".format(port_handle, dut_handle))


# configuring TGEN devices with BGP.
def tgen_devices_bgp_config(num_routes):

    bgp_devices_handles = []

    for tgen_dev_handle in tgen_dev_handles:
        if tgen_dev_handle == tgen_dev_handles[0]:
            handle = tgen_dev_handles[0]
            local_as = data.T1D1P1_local_asn
            remote_ip_addr = data.ipv4_D1T1P1
            prefix = data.bgp_route_prefix_T1D1P1
            local_router_id = data.T1D1P1_router_id
        else:
            handle = tgen_dev_handles[1]
            local_as = data.T1D1P2_local_asn
            remote_ip_addr = data.ipv4_D1T1P2
            prefix = data.bgp_route_prefix_T1D1P2
            local_router_id = data.T1D1P2_router_id

        st.log("Configure BGP on TGEN device {}".format(tgen_dev_handle))
        bgp_device = tg.tg_emulation_bgp_config(
                                    mode='enable',
                                    handle=handle,
                                    active_connect_enable='1',
                                    local_as=local_as,
                                    local_as_step=1,
                                    local_as_repeat_count=0,
                                    local_router_id=local_router_id,
                                    ip_version='4',
                                    remote_as=data.dut_local_asn,
                                    remote_as_mode='increment',
                                    remote_as_step=1,
                                    remote_as_repeat_count=0,
                                    gateway_asdut_enable='1',
                                    use_gateway_remote_ip_addr='true',
                                    remote_ip_addr=remote_ip_addr,
                                    remote_ip_addr_step='0.0.0.1',
                                    local_as_mode='increment',
                                    min_label='16',
                                    hold_time='10',
                                    keepalive_interval='3',
                                    graceful_restart_enable='1',
                                    restart_time='10',
                                    restart_delay='1',
                                    ipv4_unicast_nlri='1',
                                    bgp_mode='ebgp',
                                    route_refresh_mode='none',
                                    bgp_session_ip_addr='interface_ip',
                                    custom_capability_active='0')
                                    
        bgp_device_status = bgp_device['status']
        if (bgp_device_status == '1'):
            st.log("BGP config on device {} is successful.".format(handle))
            st.log(str(bgp_device))
        else:
            st.log("BGP config on device {} failed.".format(handle))
            st.log(str(bgp_device))
            st.report_fail("test_case_failed: BGP config on TGEN device {} failed.".format(handle))

        st.log("add routes to TGEN BGP device {}".format(handle))
        bgp_device_route = tg.tg_emulation_bgp_route_config(
                                    mode='add',
                                    handle=handle,
                                    num_routes=num_routes, 
                                    prefix=prefix,
                                    netmask=data.subnet_mask,
                                    as_path='as_seq:1')
        
        bgp_device_route_status = bgp_device_route['status']
        if (bgp_device_route_status == '1'):
            st.log("BGP route config on device {} is successful.".format(handle))
            st.log(str(bgp_device_route))
            bgp_devices_handles.append(bgp_device_route['handle'])
        else:
            st.log("BGP route config on device {} failed.".format(handle))
            st.log(str(bgp_device_route))

        bgp_device_start = tg.tg_emulation_bgp_control(mode='start',
                                                        handle=handle)
        
        bgp_device_start_status = bgp_device_start['status']
        if (bgp_device_start_status == '1'):
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
                                mac_discovery_gw=data.ipv4_D1T1P1,
                                port_handle=tg_ph_1,
                                port_handle2=tg_ph_2,
                                emulation_src_handle=src_hdl,
                                emulation_dst_handle=dst_hdl,
                                ip_protocol='6',
                                l2_encap="ethernet_ii",
                                l3_protocol='ipv4',
                                l4_protocol='tcp',
                                tcp_src_port='1024',
                                tcp_dst_port='1024',
                                ip_ttl="255",
                                endpoint_map='one_to_one',
                                traffic_pattern='pair',
                                enable_stream_only_gen='1',
                                traffic_state='1',
                                high_speed_result_analysis='1',
                                disable_signature='0',
                                tx_port_sending_traffic_to_self_en='false',
                                length_mode='fixed',
                                transmit_mode='continuous', 
                                circuit_endpoint_type='ipv4',
                                frame_size='128', 
                                rate_percent='10')

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

    load_list = []
    load_start = 99
    while load_start < 100:
        load_list.append(load_start)
        if load_start < 95:
            load_start += 5
        else:
            load_start += 0.5
    loads_as_strings = [str(load) for load in load_list]
    return loads_as_strings


# func. to calculate extracted latency values based on media end to end latency.
def extract_latency_avg(metrics):
    return round(float(metrics['latency_avg']) - data.media_end_to_end_latency, 3)


# main func. for rfc2544 latency test
def rfc2544_latency(num_routes):

    import sth

    streamblock_handle = tgen_create_streamblock(num_routes)

    if num_routes == 1: 
        st.banner("Start of rfc2544 single flow latency test.")
    else:
        st.banner("Start of rfc2544 multiple flow latency test.")
        
    # configuration for rfc2544 latency test
    rfc_latency_cfg = sth.test_rfc2544_config(
                                mode='create',
                                test_type='latency',
                                streamblock_handle=streamblock_handle,
                                endpoint_creation='0',
                                frame_size_mode='custom',
                                start_traffic_delay='2',
                                learning_mode='l3',
                                frame_size=data.frame_size,
                                enable_detailresults='1',
                                load_unit='percent_line_rate',
                                stagger_start_delay='0',
                                learning_frequency='learn_once',
                                enable_jitter_measure='0',
                                delay_after_transmission='5',
                                enable_cyclic_resolution='1',
                                load_type='custom',
                                test_duration_mode='seconds',
                                iteration_count='1',
                                test_duration='60',
                                enable_learning='0',
                                latency_type='LILO',
                                l3_learning_retry_count='5',
                                load_list=load_start_custom(),
                                enable_stream_only_gen='0')

    # Getting the rfc2544 config status
    status = rfc_latency_cfg['status']
    if (status == '0'):
        st.log("rfc2544 latency configuration failed")
        st.log(rfc_latency_cfg)
    else:
        st.log("rfc2544 latency configuration successful")
    

    # running the test for the config for rfc2544 latency 
    rfc_latency_ctl = sth.test_rfc2544_control(
                                action='run',
                                wait='1',
                                cleanup='1')

    # Getting the rfc2544 run status
    status = rfc_latency_ctl['status']
    if (status == '0'):
        st.log("rfc2544 latency control failed")
        st.log(str(rfc_latency_ctl))
    else:
        st.log("rfc2544 latency control successful")
    
    
    # extract the info. from the completed rfc2544 latency test
    rfc_latency_results = sth.test_rfc2544_info(
                                test_type='latency',
                                clear_result='1',
                                enable_load_detail='1')

    # get the results from the Spirent DB.
    status = rfc_latency_results['status']
    if (status == '0'):
        st.log("rfc2544 latency results failed")
        st.log(rfc_latency_results)
    else:
        st.log("rfc2544 latency results successful")
        st.log(rfc_latency_results)
    
    
    latency_avg_values = {}

    # Extract latency_avg values for different frame size and load
    iterations = rfc_latency_results['rfc2544latency']['detail']['iteration']
    for _, iteration_data in iterations.items():
        frame_sizes = iteration_data['frame_size']
        for frame_size, load_data in frame_sizes.items():
            if frame_size != 'frame_size_value':
                loads = load_data['load']
                for load, metrics in loads.items():
                    latency_avg = extract_latency_avg(metrics)
                    latency_avg_values[(frame_size, load)] = latency_avg

                    # Extract and store latency_avg values for decimal loads, ex: 96.5, 98.3
                    for key in range(1, 10):
                        key_str = str(load) + '.' + str(key)
                        if str(key) in metrics:
                            latency_avg_values[(frame_size, key_str)] = extract_latency_avg(metrics[str(key)])


    # Print the extracted latency_avg values, tag 'frame size' and 'load' for the latency_avg value.
    for (frame_size, load), final_latency_avg in latency_avg_values.items():
        st.log("Frame Size: " + str(frame_size) + ", Load: " + str(load) + ", Latency Avg: " + str(final_latency_avg))
        st.log("final latency_avg: " + str(final_latency_avg))

    if num_routes == 1: 
        st.banner("comparing single flow latency average values between extracted latency average values and predefined threshold latency average values in the 'expected_latency_avg.yaml' file")
    else:
        st.banner("comparing multiple flow latency average values between extracted latency average values and predefined threshold latency average values in the 'expected_latency_avg.yaml' file")
    
    avg_latency_data_dict = {}

    for dict_item in avg_latency_data_yaml['frame_size']: 
        for frame_size, frame_data in dict_item.items():
            avg_latency_data_dict[frame_size] = frame_data


    for frame_load, latency_value in latency_avg_values.items():
        frame_size, load_percent = frame_load
        frame_size = int(frame_size)
        load_percent = float(load_percent)

        if frame_size in avg_latency_data_dict and load_percent in avg_latency_data_dict[frame_size]['load']:
            avg_latency_yaml = float(avg_latency_data_dict[frame_size]['load'][load_percent]['latency_avg'])

            # Compare the final extracted latency average values and threshold latency average values from 'expected_latency_avg.yaml' file.
            if latency_value <= avg_latency_yaml:
                st.log("For Frame Size of: {} at Load of: {}, final extracted latency Avg : {} is below threshold latency of: {}".format(frame_size, load_percent, latency_value, avg_latency_yaml))
                st.report_pass("test_case_passed")
            else:
                st.log("For Frame Size of: {} at Load of: {}, final extracted latency Avg : {} is more than the threshold latency of: {}".format(frame_size, load_percent, latency_value, avg_latency_yaml))
                st.report_fail("test_case_failed")
        else:
            st.log("frame_size of: {} at load of: {} not found in avg_latency_data_yaml.".format(frame_size, load_percent))

    if num_routes == 1: 
        st.banner("End of rfc2544 single flow latency test.")
    else:
        st.banner("End of rfc2544 multiple flow latency test.")


@pytest.mark.single_flow_latency_bgp
def test_rfc2544_single_flow_latency(num_routes=1):

    tgen_reset()
    rfc2544_latency(num_routes)


@pytest.mark.multiple_flow_latency_bgp
def test_rfc2544_multiple_flow_latency(num_routes=10):

    tgen_reset()
    rfc2544_latency(num_routes)
