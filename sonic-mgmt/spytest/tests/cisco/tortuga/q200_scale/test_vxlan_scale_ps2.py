import os
import yaml
import re
import pytest
from spytest import st
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.system.basic as basic_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as interface_obj
from ixnetwork_restpy import SessionAssistant, StatViewAssistant
 

def get_dut_config_file(feature):
    
    dut_config = ""
    ixia_config = ""
    if feature == 'vrf_scale_1_v6vtep_v6host':
        dut_config = 'vrf_scale_1_v6vtep_v6hosts_configs.yaml'
        ixia_config = r'HW_L3VNI_V6vteps_V6hosts_Scale_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature == 'vrf_scale':
        dut_config = 'vrf_scale_configs.yaml'
        ixia_config = r'HW_L3VNI_Leaf0_LEAF1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature == 'l2vni_scale':
        dut_config = 'l2vni_scale_dut_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v4vtep_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature == 'l2vni_scale_v6host':
        dut_config = 'l2vni_scale_dut_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v4vtep_v6hosts_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature =="l2vni_host_scale":
        dut_config = 'l2vni_host_scale_configs.yaml'
        ixia_config = r'HW_32k_mac_route_1_latest_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 3, "port2": 1}

    elif feature =="l2vni_host_scale_v6host":
        dut_config = 'l2vni_host_scale_configs.yaml'
        ixia_config = r'HW_32k_mac_route_1_latest_v6host_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 3, "port2": 1}


    elif feature =="l2vni_host_scale_v6vtep_v6host":
        dut_config = 'l2vni_host_scale_v6vtep_v6host_configs.yaml'
        ixia_config = r'HW_32k_mac_route_1_latest_v6host_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 3, "port2": 1}

    elif feature =="l2vni_host_scale_v6vtep_v4host":
        dut_config = 'l2vni_host_scale_v6vtep_v6host_configs.yaml'
        ixia_config = r'HW_32k_mac_route_1_latest_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 3, "port2": 1}


    elif feature =="l2vni_1_v6vtep_v6host_100vlan":
        dut_config = 'l2vni_1_v6vtep_v6host_100vlan_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V6hosts_Leaf0_leaf1_100Vlan_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
 
    elif feature =="l2vni_1_v6vtep_v6host_100vlan_with_sag":
        dut_config = 'l2vni_1_v6vtep_v6host_100vlan_with_sag_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V6hosts_Leaf0_leaf1_100Vlan_WITH_SAG_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l2vni_1_v6vtep_v4host_100vlan_with_sag":
        dut_config = 'l2vni_1_v6vtep_v4host_100vlan_with_sag_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V4hosts_Leaf0_leaf1_100Vlan_WITH_SAG_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature == 'l2vni_scale_32v4vtep_v4hosts_with_sag':
        dut_config = 'l2vni_scale_32v4vtep_v4hosts_configs_with_sag_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v4vtep_new_from_RAM_WITH_SAG_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature == 'l2vni_scale_32v4vtep_v6hosts_with_sag': 
        dut_config = 'l2vni_scale_32v4vtep_v6hosts_configs_with_sag_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v4vtep_v6hosts_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature == 'l3vni_scale_32v4vtep_v4hosts':
        dut_config = 'l3vni_32v4vtep_v4host_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v4vtep_new_from_RAM_L3VNI_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature == 'l3vni_scale_32v4vtep_v6hosts':
        dut_config = 'l3vni_32v4vtep_v6host_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v4vtep_v6hosts_new_from_RAM_L3VNI_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}


    elif feature == 'l3vni_scale_32v6vtep_v6hosts':
        dut_config = 'l3vni_32v6vtep_v6host_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v6vtep_using_leaf1_testconfig_v6HOSTS_L3VNI_3_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature == 'l3vni_scale_32v6vtep_v4hosts':
        dut_config = 'l3vni_32v6vtep_v4host_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v6vtep_using_leaf1_testconfig_v4HOSTS_L3VNI_3_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    
    elif feature == 'l2vni_32v6vtep_v4hosts_scale':
        dut_config = 'l2vni_scale_dut_32v6vtep_v4hosts_configs.yaml'
        ixia_config = r'HW_ipv6_underlay_32_v6vtep_using_leaf1_testconfig_v4HOSTS_port24_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 2, "port2": 3}

    elif feature =="l2vni_host_scale_sag":
        dut_config = 'l2vni_host_scale_configs_sag.yaml'
        ixia_config = r'HW_L2VNI_32K_IP_prefix_SAG_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature =="l2vni_host_scale_v6vtep_sag":
        dut_config = 'l2vni_host_scale_configs_v6vtep_sag.yaml'
        ixia_config = r'HW_L2VNI_32K_IP_prefix_SAG_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    
    elif feature =="l2vni_host_scale_v4vtep_v6host_sag":
        dut_config = 'l2vni_host_v4vtep_v6host_scale_configs_sag.yaml'
        ixia_config = r'HW_L2VNI_32K_IP_prefix_v6hosts_SAG_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature =="l2vni_host_scale_v6vtep_v6host_sag":
        dut_config = 'l2vni_host_v6vtep_v6host_scale_configs_sag.yaml'
        ixia_config = r'HW_L2VNI_32K_IP_prefix_v6hosts_SAG_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}


    elif feature =="l2vni_v6vtep_v6host_customimix":
        dut_config = 'l2vni_v6vtep_v6host_customimix_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V6hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l2vni_v6vtep_v4host_customimix":
        dut_config = 'l2vni_v6vtep_v6host_customimix_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V4hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature =="l2vni_v4vtep_v4host_customimix":
        dut_config = 'l2vni_v4vtep_customimix_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V4hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature =="l2vni_v4vtep_v6host_customimix":
        dut_config = 'l2vni_v4vtep_customimix_configs.yaml'
        ixia_config = r'HW_L2VNI_V6vteps_V6hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    elif feature =="l3vni_v6vtep_v6host_customimix":
        dut_config = 'l3vni_v6vtep_v6host_customimix_configs.yaml'
        ixia_config = r'HW_L3VNI_V6vteps_V6hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_host_scale":
        dut_config = 'l3vni_v4vtep_v4host_2kip_prefix.yaml'
        ixia_config = r'HW_L3VNI_32K_IP_prefix_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_v6vtep_host_scale":
        dut_config = 'l3vni_v6vtep_v4host_2kip_prefix.yaml'
        ixia_config = r'HW_L3VNI_32K_IP_prefix_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_v4vtep_v6host_scale":
        dut_config = 'l3vni_v4vtep_v6host_2kip_prefix.yaml'
        ixia_config = r'HW_L3VNI_32K_IP_prefix_v6hosts_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_v6vtep_v4host_customimix":
        dut_config = 'l3vni_v6vtep_v4host_customimix_configs.yaml'
        ixia_config = r'HW_L3VNI_V6vteps_V4hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_v4vtep_v4host_customimix":
        dut_config = 'l3vni_v4vtep_v4host_customimix_configs.yaml'
        ixia_config = r'HW_L3VNI_V6vteps_V4hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_v4vtep_v6host_customimix":
        dut_config = 'l3vni_v4vtep_v6host_customimix_configs.yaml'
        ixia_config = r'HW_L3VNI_V6vteps_V6hosts_Leaf0_leaf1_customIMIX_1_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}
    
    elif feature =="l3vni_v6vtep_v6host_scale":
        dut_config = 'l3vni_v6vtep_v6host_2kip_prefix.yaml'
        ixia_config = r'HW_L3VNI_32K_IP_prefix_v6hosts_PS2.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": 1, "port2": 3}

    else:
        st.log("feature not found")
        st.report_fail("test_case_failed")
    return dut_config,ixia_config,port_info

def initialize_variables():
    global vars, nodes
    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()




def ixia_setup(ixia_config_file,port_info):
    ixnetwork_session = SessionAssistant(IpAddress="10.29.158.65", UserName="admin", Password="admin")
    ixnetwork = ixnetwork_session.Ixnetwork
    ixnetwork.LoadConfig(Arg1=ixia_config_file)
    st.wait(30)
    
    # Assign ports. Map physical ports to the configured vports.
    portMap = ixnetwork_session.PortMapAssistant()
    portMap.Map(IpAddress=port_info['chassis_ip'], CardId=port_info['slot'], PortId=port_info['port1'], Name=ixnetwork.Vport.find()[0].Name)
    portMap.Map(IpAddress=port_info['chassis_ip'], CardId=port_info['slot'], PortId=port_info['port2'], Name=ixnetwork.Vport.find()[1].Name)
    portMap.Connect(ForceOwnership=True)
    st.wait(10)
    ixnetwork.StartAllProtocols(Arg1='sync')
    st.wait(20)

    try:
    # Check the condition 'Sessions Down' equal to 0
        protocolSummary = ixnetwork_session.StatViewAssistant('Protocols Summary')
        protocolSummary.CheckCondition('Sessions Down', protocolSummary.EQUAL, 0)
        ixnetwork.info(protocolSummary)
        st.log("Condition met: Sessions Down is 0")
    except Exception as e:
        st.log("Error: "+str(e))
        ixnetwork.StopAllProtocols(Arg1='sync')
        st.wait(8)
        ixnetwork.StartAllProtocols(Arg1='sync')
        st.wait(30)
        st.log("Restarted protocols due to 'Sessions Down' not equal to 0")
    traffic_items = ixnetwork.Traffic.TrafficItem.find()
    for traffic_item in traffic_items:
        traffic_item.Generate()
    st.wait(5)
    ixnetwork.Traffic.Apply()
    st.wait(5)
    return ixnetwork,ixnetwork_session
    
def ixia_start_devices(ixnetwork):
    # Find all IPv4 device
    ipv4_devices = ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find().Ipv4.find()
    # Start all IPv4 devices
    for ipv4_device in ipv4_devices:
        ipv4_device.Start()
    
    traffic_items = ixnetwork.Traffic.TrafficItem.find()
    for traffic_item in traffic_items:
    # Start the traffic item
        traffic_item.Generate()
    ixnetwork.Traffic.Apply()
    st.wait(5)


def ixia_teardown(ixnetwork_session):
    # Disconnect from the IxNetwork API server
    ixnetwork_session.Session.remove()

def start_stop_traffic(ixnetwork):
    ixnetwork.Traffic.StartStatelessTrafficBlocking()
    st.wait(60)
    ixnetwork.Traffic.StopStatelessTrafficBlocking()
    st.wait(5)

def start_traffic(ixnetwork):
    ixnetwork.Traffic.StartStatelessTrafficBlocking()
    st.wait(30)

def stop_traffic(ixnetwork):
    ixnetwork.Traffic.StopStatelessTrafficBlocking()
    st.wait(5)
    

def get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = False):
    traffic_dict={}
    traffic_item_stats = ixnetwork_session.StatViewAssistant('Traffic Item Statistics')
    flow_stats = ixnetwork_session.StatViewAssistant('Flow Statistics')
    for item,value in enumerate(traffic_item_stats.Rows):
        traffic_dict[item] = {}
        traffic_dict[item]['Traffic Item'] = value['Traffic Item']
        traffic_dict[item]['TxFrames'] = value['Tx Frames']
        traffic_dict[item]['RxFrames'] = value['Rx Frames']
        traffic_dict[item]['Loss'] = value['Loss %']
        if check_pkt_loss_duration:
            traffic_dict[item]['Packet Loss Duration (ms)'] = value['Packet Loss Duration (ms)'] 
            
    st.log(traffic_dict)
    stats_dict = {}
    for item,flowStat in enumerate(flow_stats.Rows):
        stats_dict[item] = {}
        stats_dict[item]['Source/Dest Value Pair'] = flowStat['Source/Dest Value Pair']
        stats_dict[item]['TxFrames'] = flowStat['Tx Frames']
        stats_dict[item]['RxFrames'] = flowStat['Rx Frames']
        stats_dict[item]['loss'] = flowStat['Loss %']
        if check_pkt_loss_duration:
            stats_dict[item]['Packet Loss Duration (ms)'] = value['Packet Loss Duration (ms)']
    return traffic_dict,stats_dict

def validate_traffic_stats(out, pkt_loss_duration = False):
    flag = False
    get_flow_stat = False
    if pkt_loss_duration:
        threshold = .9 #(.65, .80)- Samriddhi
    else:
        threshold = .998
    for traffic_item,value in out[0].items():
        if int(value['RxFrames']) == 0:
            st.log("traffic failed for Traffic_item {}, TX: {} , RX: {}".format(value['Traffic Item'], value['TxFrames'], value['RxFrames']))
            flag = False
        else:
            if int(value['RxFrames']) >= threshold*int(value['TxFrames']):
                st.log("traffic passed for Traffic_item {}, TX: {} , RX: {}".format(value['Traffic Item'], value['TxFrames'], value['RxFrames']))
                if value.get('pkt_loss_duration'):
                    st.banner("Packet Loss Duration (ms) {}".format(value['Packet Loss Duration (ms)']))
                flag = True
            else:
                st.log("traffic loss for Traffic_item {}, TX: {} , RX: {}".format(value['Traffic Item'], value['TxFrames'], value['RxFrames']))
                flag = False
                get_flow_stat = True

    if get_flow_stat:
        for flow,value in out[1].items():
            if int(value['RxFrames']) == 0:
                st.log("traffic failed for flow {}, TX: {} , RX: {}".format(value['Source/Dest Value Pair'], value['TxFrames'], value['RxFrames']))
            else:
                if int(value['RxFrames']) >= threshold*int(value['TxFrames']):
                    st.log("traffic passed for flow {}, TX: {} , RX: {}".format(value['Source/Dest Value Pair'], value['TxFrames'], value['RxFrames']))
                else:
                    if value.get('pkt_loss_duration'):
                        st.log("traffic loss for flow {}, TX: {} , RX: {}, Packet Loss Duration (ms): {} ".format(value['Source/Dest Value Pair'], 
                        value['TxFrames'], value['RxFrames'], value['Packet Loss Duration (ms)']))
                    else:
                        st.log("traffic loss for flow {}, TX: {} , RX: {}".format(value['Source/Dest Value Pair'], value['TxFrames'], value['RxFrames']))
    return flag

@pytest.fixture(scope="function")
def vrf_scale_setup():
    config_files = get_dut_config_file('vrf_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('vrf_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def vrf_scale_1_v6vtep_v6host_setup():
    config_files = get_dut_config_file('vrf_scale_1_v6vtep_v6host')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('vrf_scale_1_v6vtep_v6host')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_scale_setup():
    config_files = get_dut_config_file('l2vni_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_scale_v6host_setup():
    config_files = get_dut_config_file('l2vni_scale_v6host')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_scale_v6host')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l2vni_host_scale_setup():
    config_files = get_dut_config_file('l2vni_host_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_host_scale_v6host_setup():
    config_files = get_dut_config_file('l2vni_host_scale_v6host')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_v6host')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l2vni_host_scale_v6vtep_v6host_setup():
    config_files = get_dut_config_file('l2vni_host_scale_v6vtep_v6host')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_v6vtep_v6host')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l2vni_host_scale_v6vtep_v4host_setup():
    config_files = get_dut_config_file('l2vni_host_scale_v6vtep_v4host')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_v6vtep_v4host')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_1_v6vtep_v6host_100vlan_setup():
    config_files = get_dut_config_file('l2vni_1_v6vtep_v6host_100vlan')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_1_v6vtep_v6host_100vlan')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_1_v6vtep_v6host_100vlan_with_sag_setup():
    config_files = get_dut_config_file('l2vni_1_v6vtep_v6host_100vlan_with_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_1_v6vtep_v6host_100vlan_with_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_1_v6vtep_v4host_100vlan_with_sag_setup():
    config_files = get_dut_config_file('l2vni_1_v6vtep_v4host_100vlan_with_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_1_v6vtep_v4host_100vlan_with_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l2vni_scale_32v4vtep_v4hosts_with_sag_setup():
    config_files = get_dut_config_file('l2vni_scale_32v4vtep_v4hosts_with_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_scale_32v4vtep_v4hosts_with_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l2vni_scale_32v4vtep_v6hosts_with_sag_setup():
    config_files = get_dut_config_file('l2vni_scale_32v4vtep_v6hosts_with_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_scale_32v4vtep_v6hosts_with_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l3vni_scale_32v4vtep_v4hosts_setup():
    config_files = get_dut_config_file('l3vni_scale_32v4vtep_v4hosts')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_scale_32v4vtep_v4hosts')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))

@pytest.fixture(scope="function")
def l3vni_scale_32v4vtep_v6hosts_setup():
    config_files = get_dut_config_file('l3vni_scale_32v4vtep_v6hosts')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_scale_32v4vtep_v6hosts')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l3vni_scale_32v6vtep_v6hosts_setup():
    config_files = get_dut_config_file('l3vni_scale_32v6vtep_v6hosts')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_scale_32v6vtep_v6hosts')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l3vni_scale_32v6vtep_v4hosts_setup():
    config_files = get_dut_config_file('l3vni_scale_32v6vtep_v4hosts')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_scale_32v6vtep_v4hosts')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))



@pytest.fixture(scope="function")
def l2vni_32v6vtep_v4hosts_scale_setup():
    config_files = get_dut_config_file('l2vni_32v6vtep_v4hosts_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_32v6vtep_v4hosts_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_host_scale_sag_setup():
    config_files = get_dut_config_file('l2vni_host_scale_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))

@pytest.fixture(scope="function")
def l2vni_host_scale_v6vtep_sag_setup():
    config_files = get_dut_config_file('l2vni_host_scale_v6vtep_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_v6vtep_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_host_scale_v4vtep_v6host_sag_setup():
    config_files = get_dut_config_file('l2vni_host_scale_v4vtep_v6host_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_v4vtep_v6host_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))

@pytest.fixture(scope="function")
def l2vni_host_scale_v6vtep_v6host_sag_setup():
    config_files = get_dut_config_file('l2vni_host_scale_v6vtep_v6host_sag')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_host_scale_v6vtep_v6host_sag')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_v6vtep_v6host_customimix_setup():
    config_files = get_dut_config_file('l2vni_v6vtep_v6host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_v6vtep_v6host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_v6vtep_v4host_customimix_setup():
    config_files = get_dut_config_file('l2vni_v6vtep_v4host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_v6vtep_v4host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_v4vtep_v4host_customimix_setup():
    config_files = get_dut_config_file('l2vni_v4vtep_v4host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_v4vtep_v4host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l2vni_v4vtep_v6host_customimix_setup():
    config_files = get_dut_config_file('l2vni_v4vtep_v6host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l2vni_v4vtep_v6host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l3vni_v6vtep_v6host_customimix_setup():
    config_files = get_dut_config_file('l3vni_v6vtep_v6host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v6vtep_v6host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l3vni_v4vtep_v6host_customimix_setup():
    config_files = get_dut_config_file('l3vni_v4vtep_v6host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v4vtep_v6host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l3vni_v6vtep_v4host_customimix_setup():
    config_files = get_dut_config_file('l3vni_v6vtep_v4host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v6vtep_v4host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l3vni_v4vtep_v4host_customimix_setup():
    config_files = get_dut_config_file('l3vni_v4vtep_v4host_customimix')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v4vtep_v4host_customimix')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l3vni_host_scale_setup():
    config_files = get_dut_config_file('l3vni_host_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_host_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))

@pytest.fixture(scope="function")
def l3vni_v6vtep_host_scale_setup():
    config_files = get_dut_config_file('l3vni_v6vtep_host_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v6vtep_host_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))

@pytest.fixture(scope="function")
def l3vni_v4vtep_v6host_scale_setup():
    config_files = get_dut_config_file('l3vni_v4vtep_v6host_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v4vtep_v6host_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


@pytest.fixture(scope="function")
def l3vni_v6vtep_v6host_scale_setup():
    config_files = get_dut_config_file('l3vni_v6vtep_v6host_scale')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    #static_config_push(config_files[0])
    get_config_out()
    get_cli_out()
    out = ixia_setup(config_files[1],config_files[2])
    yield out
    try:
        config_files = get_dut_config_file('l3vni_v6vtep_v6host_scale')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        #unconfig(config_files[0])
        router_preconfig_cleanup()
        get_config_out()
    except Exception as e:
        st.log("Error: "+str(e))


## TESTCASES ###

def test_l2vni_v4vtep_v4host_customimix(l2vni_v4vtep_v4host_customimix_setup):
    ixnetwork = l2vni_v4vtep_v4host_customimix_setup[0]
    ixnetwork_session = l2vni_v4vtep_v4host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v4vtep_v4host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v4vtep_v4host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_v4vtep_v6host_customimix(l2vni_v4vtep_v6host_customimix_setup):
    ixnetwork = l2vni_v4vtep_v6host_customimix_setup[0]
    ixnetwork_session = l2vni_v4vtep_v6host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v4vtep_v6host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v4vtep_v6host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_v4vtep_v6host_customimix(l3vni_v4vtep_v6host_customimix_setup):
    ixnetwork = l3vni_v4vtep_v6host_customimix_setup[0]
    ixnetwork_session = l3vni_v4vtep_v6host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v4vtep_v6host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v4vtep_v6host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l3vni_v4vtep_v4host_customimix(l3vni_v4vtep_v4host_customimix_setup):
    ixnetwork = l3vni_v4vtep_v4host_customimix_setup[0]
    ixnetwork_session = l3vni_v4vtep_v4host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v4vtep_v4host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v4vtep_v4host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_scale(l2vni_scale_setup):
    ixnetwork = l2vni_scale_setup[0]
    ixnetwork_session = l2vni_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_scale_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_scale_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_scale_v6host(l2vni_scale_v6host_setup):
    ixnetwork = l2vni_scale_v6host_setup[0]
    ixnetwork_session = l2vni_scale_v6host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_scale_v6host_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_scale_v6host_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l3vni_scale_32v4vtep_v4hosts(l3vni_scale_32v4vtep_v4hosts_setup):
    ixnetwork = l3vni_scale_32v4vtep_v4hosts_setup[0]
    ixnetwork_session = l3vni_scale_32v4vtep_v4hosts_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_scale_32v4vtep_v4hosts test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_scale_32v4vtep_v4hosts test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l3vni_scale_32v4vtep_v6hosts(l3vni_scale_32v4vtep_v6hosts_setup):
    ixnetwork = l3vni_scale_32v4vtep_v6hosts_setup[0]
    ixnetwork_session = l3vni_scale_32v4vtep_v6hosts_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_scale_32v4vtep_v6hosts test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_scale_32v4vtep_v6hosts test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_scale_32v4vtep_v6hosts_with_sag(l2vni_scale_32v4vtep_v6hosts_with_sag_setup):
    ixnetwork = l2vni_scale_32v4vtep_v6hosts_with_sag_setup[0]
    ixnetwork_session = l2vni_scale_32v4vtep_v6hosts_with_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_scale_32v4vtep_v6hosts_with_sag_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_scale_32v4vtep_v6hosts_with_sag_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_scale_32v4vtep_v4hosts_with_sag(l2vni_scale_32v4vtep_v4hosts_with_sag_setup):
    ixnetwork = l2vni_scale_32v4vtep_v4hosts_with_sag_setup[0]
    ixnetwork_session = l2vni_scale_32v4vtep_v4hosts_with_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_scale_32v4vtep_v4hosts_with_sag_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_scale_32v4vtep_v4hosts_with_sag_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_vrf_scale(vrf_scale_setup):
    ixnetwork = vrf_scale_setup[0]
    ixnetwork_session = vrf_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("vrf_scale_test test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("vrf_scale_test test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_host_scale(l3vni_host_scale_setup):
    ixnetwork = l3vni_host_scale_setup[0]
    ixnetwork_session = l3vni_host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l3vni_v4vtep_v6host_scale(l3vni_v4vtep_v6host_scale_setup):
    ixnetwork = l3vni_v4vtep_v6host_scale_setup[0]
    ixnetwork_session = l3vni_v4vtep_v6host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v4vtep_v6host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v4vtep_v6host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")
 
def test_l2vni_host_scale_v4vtep_v6host_sag(l2vni_host_scale_v4vtep_v6host_sag_setup):
    ixnetwork = l2vni_host_scale_v4vtep_v6host_sag_setup[0]
    ixnetwork_session = l2vni_host_scale_v4vtep_v6host_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_host_scale_v4vtep_v6host_sag_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_host_scale_v4vtep_v6host_sag test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_host_scale_sag(l2vni_host_scale_sag_setup):
    ixnetwork = l2vni_host_scale_sag_setup[0]
    ixnetwork_session = l2vni_host_scale_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_host_scale_sag_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("2vni_host_scale_sag_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")



def test_l2vni_host_scale_v6host(l2vni_host_scale_v6host_setup):
    ixnetwork = l2vni_host_scale_v6host_setup[0]
    ixnetwork_session = l2vni_host_scale_v6host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v4vtep_v6host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v4vtep_v6host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_host_scale(l2vni_host_scale_setup):
    initialize_variables()
    ixnetwork = l2vni_host_scale_setup[0]
    ixnetwork_session = l2vni_host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result1 = validate_traffic_stats(stats)
    if result1:
        st.banner("l2vni_host_scale_setup test passed")
    else:
        st.banner("l2vni_host_scale_setup test failed")
    start_traffic(ixnetwork)

    ### shut remote leaf host facing interface ###
    st.config("leaf1", "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.wait(.5)
    st.config("leaf1", "sudo config interface startup {}".format(vars.D3T1P2))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result2 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result2:
        st.banner("l2vni_host_scale_setup with remote leaf host int shut test passed")
    else:
        st.banner("l2vni_host_scale_setup with remote leaf host int shut test failed")

    #Start traffic
    start_traffic(ixnetwork)
    ### shut local leaf host facing interface ###
    st.config("leaf0", "sudo config interface shutdown {}".format(vars.D2T1P1))
    st.wait(.5)
    st.config("leaf0", "sudo config interface startup {}".format(vars.D2T1P1))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result3 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result3:
        st.banner("l2vni_host_scale_setup with local leaf host int shut test passed")
    else:
        st.banner("l2vni_host_scale_setup with local leaf host int shut test failed")



    ixia_teardown(ixnetwork_session)
    if result1 and result2 and result3:
        st.banner("l2vni_host_scale_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.banner("l2vni_host_scale_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")





def test_l2vni_v6vtep_v6host_customimix(l2vni_v6vtep_v6host_customimix_setup):
    ixnetwork = l2vni_v6vtep_v6host_customimix_setup[0]
    ixnetwork_session = l2vni_v6vtep_v6host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v6vtep_v6host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v6vtep_v6host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_v6vtep_v4host_customimix(l2vni_v6vtep_v4host_customimix_setup):
    ixnetwork = l2vni_v6vtep_v4host_customimix_setup[0]
    ixnetwork_session = l2vni_v6vtep_v4host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v6vtep_v4host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v6vtep_v4host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l3vni_v6vtep_v6host_customimix(l3vni_v6vtep_v6host_customimix_setup):
    ixnetwork = l3vni_v6vtep_v6host_customimix_setup[0]
    ixnetwork_session = l3vni_v6vtep_v6host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v6vtep_v6host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v6vtep_v6host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_v6vtep_v4host_customimix(l3vni_v6vtep_v4host_customimix_setup):
    ixnetwork = l3vni_v6vtep_v4host_customimix_setup[0]
    ixnetwork_session = l3vni_v6vtep_v4host_customimix_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v6vtep_v4host_customIMIX test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v6vtep_v4host_customIMIX test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_1_v6vtep_v6host_100vlan(l2vni_1_v6vtep_v6host_100vlan_setup):
    ixnetwork = l2vni_1_v6vtep_v6host_100vlan_setup[0]
    ixnetwork_session = l2vni_1_v6vtep_v6host_100vlan_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_1_v6vtep_v6host_100vlan test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_1_v6vtep_v6host_100vlan test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_vrf_scale_1_v6vtep_v6host(vrf_scale_1_v6vtep_v6host_setup):
    ixnetwork = vrf_scale_1_v6vtep_v6host_setup[0]
    ixnetwork_session = vrf_scale_1_v6vtep_v6host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("vrf_scale_1_v6vtep_v6host test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("vrf_scale_1_v6vtep_v6host test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_1_v6vtep_v6host_100vlan_with_sag(l2vni_1_v6vtep_v6host_100vlan_with_sag_setup):
    ixnetwork = l2vni_1_v6vtep_v6host_100vlan_with_sag_setup[0]
    ixnetwork_session = l2vni_1_v6vtep_v6host_100vlan_with_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_1_v6vtep_v6host_100vlani_with_sag test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_1_v6vtep_v6host_100vlan_with_sag test failed")
        get_cli_out()
        st.report_fail("test_case_failed")



def test_l2vni_1_v6vtep_v4host_100vlan_with_sag(l2vni_1_v6vtep_v4host_100vlan_with_sag_setup):
    ixnetwork = l2vni_1_v6vtep_v4host_100vlan_with_sag_setup[0]
    ixnetwork_session = l2vni_1_v6vtep_v4host_100vlan_with_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_1_v6vtep_v4host_100vlani_with_sag test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_1_v6vtep_v4host_100vlan_with_sag test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_v6vtep_host_scale(l3vni_v6vtep_host_scale_setup):
    ixnetwork = l3vni_v6vtep_host_scale_setup[0]
    ixnetwork_session = l3vni_v6vtep_host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v6vtep_host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v6vtep_host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_v6vtep_v6host_scale(l3vni_v6vtep_v6host_scale_setup):
    ixnetwork = l3vni_v6vtep_v6host_scale_setup[0]
    ixnetwork_session = l3vni_v6vtep_v6host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_v6vtep_v6host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_v6vtep_v6host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_host_scale_v6vtep_v6host_sag(l2vni_host_scale_v6vtep_v6host_sag_setup):
    ixnetwork = l2vni_host_scale_v6vtep_v6host_sag_setup[0]
    ixnetwork_session = l2vni_host_scale_v6vtep_v6host_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_host_scale_v6vtep_v6host_sag_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_host_scale_v6vtep_v6host_sag test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_host_scale_v6vtep_v4host(l2vni_host_scale_v6vtep_v4host_setup):
    ixnetwork = l2vni_host_scale_v6vtep_v4host_setup[0]
    ixnetwork_session = l2vni_host_scale_v6vtep_v4host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v4vtep_v6host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v4vtep_v6host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_host_scale_v6vtep_v6host(l2vni_host_scale_v6vtep_v6host_setup):
    ixnetwork = l2vni_host_scale_v6vtep_v6host_setup[0]
    ixnetwork_session = l2vni_host_scale_v6vtep_v6host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_v6vtep_v6host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_v6vtep_v6host_scale failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_host_scale_v6vtep_sag(l2vni_host_scale_v6vtep_sag_setup):
    ixnetwork = l2vni_host_scale_v6vtep_sag_setup[0]
    ixnetwork_session = l2vni_host_scale_v6vtep_sag_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_host_scale_v6vtep_sag_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_host_scale_v6vtep_sag_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_host_scale_dwnload_performance(l3vni_host_scale_setup):
    initialize_variables()
    ixnetwork = l3vni_host_scale_setup[0]
    ixnetwork_session = l3vni_host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result1 = validate_traffic_stats(stats)
    if result1:
        st.banner("l3vni_host_scale test passed")
    else:
        st.banner("l3vni_host_scale test failed")
    start_traffic(ixnetwork)

    ### shut remote leaf host facing interface ###

    st.config("leaf1", "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.wait(.5)
    st.config("leaf1", "sudo config interface startup {}".format(vars.D3T1P2))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result2 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result2:
        st.banner("l3vni_host_scale_setup with remote leaf host int shut test passed")
    else:
        st.banner("l3vni_host_scale_setup with remote leaf host int shut test failed")

    #Start traffic
    start_traffic(ixnetwork)
    ### shut local leaf host facing interface ###
    st.config("leaf0", "sudo config interface shutdown {}".format(vars.D2T1P1))
    st.wait(.5)
    st.config("leaf0", "sudo config interface startup {}".format(vars.D2T1P1))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result3 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result3:
        st.banner("l3vni_host_scale_setup with local leaf host int shut test passed")
    else:
        st.banner("l3vni_host_scale_setup with local leaf host int shut test failed")



    ixia_teardown(ixnetwork_session)
    if result1 and result2 and result3:
        st.banner("l3vni_host_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.banner("l3vni_host_scale test failed")
        get_cli_out()
        st.report_fail("test_case_failed")




def test_l3vni_v4vtep_v6host_scale_dwnload_performance(l3vni_v4vtep_v6host_scale_setup):
    initialize_variables()
    ixnetwork = l3vni_v4vtep_v6host_scale_setup[0]
    ixnetwork_session = l3vni_v4vtep_v6host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result1 = validate_traffic_stats(stats)
    if result1:
        st.banner("l3vni_v4vtep_v6host_scale test passed")
    else:
        st.banner("l3vni_v4vtep_v6host_scale test failed")
    start_traffic(ixnetwork)

    ### shut remote leaf host facing interface ###
    st.config("leaf1", "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.wait(.5)
    st.config("leaf1", "sudo config interface startup {}".format(vars.D3T1P2))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result2 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result2:
        st.banner("l3vni_host_scale_setup with remote leaf host int shut test passed")
    else:
        st.banner("l3vni_host_scale_setup with remote leaf host int shut test failed")
    #Start traffic
    start_traffic(ixnetwork)
    ### shut local leaf host facing interface ###
    st.config("leaf0", "sudo config interface shutdown {}".format(vars.D2T1P1))
    st.wait(.5)
    st.config("leaf0", "sudo config interface startup {}".format(vars.D2T1P1))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result3 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result3:
        st.banner("l3vni_host_scale_setup with local leaf host int shut test passed")
    else:
        st.banner("l3vni_host_scale_setup with local leaf host int shut test failed")

    ixia_teardown(ixnetwork_session)
    if result1 and result2 and result3:
        st.banner("test passed")
        st.report_pass('test_case_passed')
    else:
        st.banner("test failed")
        get_cli_out()
        st.report_fail("test_case_failed")



def test_l3vni_v6vtep_v6host_scale_dwnload_performance(l3vni_v6vtep_v6host_scale_setup):
    initialize_variables()
    ixnetwork = l3vni_v6vtep_v6host_scale_setup[0]
    ixnetwork_session = l3vni_v6vtep_v6host_scale_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result1 = validate_traffic_stats(stats)
    if result1:
        st.banner("l3vni_v6vtep_v6host_scale test passed")
    else:
        st.banner("l3vni_v6vtep_v6host_scale test failed")
    start_traffic(ixnetwork)

    ### shut remote leaf host facing interface ###
    st.config("leaf1", "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.wait(.5)
    st.config("leaf1", "sudo config interface startup {}".format(vars.D3T1P2))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result2 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result2:
        st.banner("l3vni_host_scale_setup with remote leaf host int shut test passed")
    else:
        st.banner("l3vni_host_scale_setup with remote leaf host int shut test failed")

    #Start traffic
    start_traffic(ixnetwork)
    ### shut local leaf host facing interface ###
    st.config("leaf0", "sudo config interface shutdown {}".format(vars.D2T1P1))
    st.wait(.5)
    st.config("leaf0", "sudo config interface startup {}".format(vars.D2T1P1))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result3 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result3:
        st.banner("l3vni_host_scale_setup with local leaf host int shut test passed")
    else:
        st.banner("l3vni_host_scale_setup with local leaf host int shut test failed")

    ixia_teardown(ixnetwork_session)
    if result1 and result2 and result3:
        st.banner("test passed")
        st.report_pass('test_case_passed')
    else:
        st.banner("test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l2vni_host_scale_v6host_mac_dwn_perf(l2vni_host_scale_v6host_setup):
    initialize_variables()
    ixnetwork = l2vni_host_scale_v6host_setup[0]
    ixnetwork_session = l2vni_host_scale_v6host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result1 = validate_traffic_stats(stats)
    if result1:
        st.banner("l2vni_host_scale_v6host_setup test passed")
    else:
        st.banner("l2vni_host_scale_v6host_setup test failed")
    start_traffic(ixnetwork)

    ### shut remote leaf host facing interface ###
    st.config("leaf1", "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.wait(.5)
    st.config("leaf1", "sudo config interface startup {}".format(vars.D3T1P2))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result2 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result2:
        st.banner("l2vni_host_scale_setup with remote leaf host int shut test passed")
    else:
        st.banner("l2vni_host_scale_setup with remote leaf host int shut test failed")

    #Start traffic
    start_traffic(ixnetwork)
    ### shut local leaf host facing interface ###
    st.config("leaf0", "sudo config interface shutdown {}".format(vars.D2T1P1))
    st.wait(.5)
    st.config("leaf0", "sudo config interface startup {}".format(vars.D2T1P1))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result3 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result3:
        st.banner("l2vni_host_scale_v6host_setup with local leaf host int shut test passed")
    else:
        st.banner("l2vni_host_scale_v6host_setup with local leaf host int shut test failed")



    ixia_teardown(ixnetwork_session)
    if result1 and result2 and result3:
        st.banner("l2vni_host_scale_v6host_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.banner("l2vni_host_scale_v6host_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_host_scale_v6vtep_v6host_mac_dwn_perf(l2vni_host_scale_v6vtep_v6host_setup):
    initialize_variables()
    ixnetwork = l2vni_host_scale_v6vtep_v6host_setup[0]
    ixnetwork_session = l2vni_host_scale_v6vtep_v6host_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result1 = validate_traffic_stats(stats)
    if result1:
        st.banner("l2vni_host_scale_v6vtep_v6host_setup test passed")
    else:
        st.banner("l2vni_host_scale_v6vtep_v6host_setup test failed")
    start_traffic(ixnetwork)

    ### shut remote leaf host facing interface ###
    st.config("leaf1", "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.wait(.5)
    st.config("leaf1", "sudo config interface startup {}".format(vars.D3T1P2))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result2 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result2:
        st.banner("l2vni_host_scale_setup with remote leaf host int shut test passed")
    else:
        st.banner("l2vni_host_scale_setup with remote leaf host int shut test failed")

    #Start traffic
    start_traffic(ixnetwork)
    ### shut local leaf host facing interface ###
    st.config("leaf0", "sudo config interface shutdown {}".format(vars.D2T1P1))
    st.wait(.5)
    st.config("leaf0", "sudo config interface startup {}".format(vars.D2T1P1))

    stats = get_traffic_stats(ixnetwork_session, check_pkt_loss_duration = True)
    #Stop Traffic
    stop_traffic(ixnetwork)
    result3 = validate_traffic_stats(stats,pkt_loss_duration = True)
    if result3:
        st.banner("l2vni_host_scale_setup with local leaf host int shut test passed")
    else:
        st.banner("l2vni_host_scale_setup with local leaf host int shut test failed")



    ixia_teardown(ixnetwork_session)
    if result1 and result2 and result3:
        st.banner("l2vni_host_scale_v6vtep_v6host_setup test passed")
        st.report_pass('test_case_passed')
    else:
        st.banner("l2vni_host_scale_v6vtep_v6host_setup test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l3vni_scale_32v6vtep_v6hosts(l3vni_scale_32v6vtep_v6hosts_setup):
    ixnetwork = l3vni_scale_32v6vtep_v6hosts_setup[0]
    ixnetwork_session = l3vni_scale_32v6vtep_v6hosts_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_scale_32v6vtep_v6hosts test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_scale_32v6vtep_v6hosts test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


def test_l3vni_scale_32v6vtep_v4hosts(l3vni_scale_32v6vtep_v4hosts_setup):
    ixnetwork = l3vni_scale_32v6vtep_v4hosts_setup[0]
    ixnetwork_session = l3vni_scale_32v6vtep_v4hosts_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l3vni_scale_32v6vtep_v4hosts test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l3vni_scale_32v6vtep_v4hosts test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

def test_l2vni_32v6vtep_v4hosts_scale(l2vni_32v6vtep_v4hosts_scale_setup):
    ixnetwork = l2vni_32v6vtep_v4hosts_scale_setup[0]
    ixnetwork_session = l2vni_32v6vtep_v4hosts_scale_setup[1]
#    import pdb; pdb.set_trace()
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("l2vni_32v6vtep_v4hosts_scale test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("l2vni_32v6vtep_v4hosts_scale test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

#####config using static configs#######
def static_config_push(config_file):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_dut(node, 'sonic', config['sonic']['config'])
            # st.wait(10)
            config_dut(node, 'bgp', config['bgp']['config'])
        st.wait(60)

#####unconfig using static configs#######
def unconfig(config_file):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + config_file) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        for node, config in config_dict.items():
            config_dut(node, 'bgp', config_dict[node]['bgp']['deconfig'])
            st.wait(60)
            config_dut(node, 'sonic', config_dict[node]['sonic']['deconfig'])
            st.wait(60)
            


def router_preconfig_cleanup():
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=True, conf=True)
    else:
        st.config(node, config, skip_error_check=True, conf=True)

def config_dut(node, config_domain, config, add=True):
    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'
    if add:
        config_node(node, config, domain)
    else:
        pass
        
###Show cli###

def get_cli_out():
    cmds = ["docker ps -a", "show vlan brief", "show interface status", "show mac", "show arp","show vxlan tunnel",
            "show vxlan remotevtep", "show vxlan vlanvnimap","show vxlan vrfvnimap", "show vxlan counters","vtysh -c 'show bgp sum'"]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.config(dut, item)
                st.log(output)
def get_config_out():
    for dut in st.get_dut_names():
        if "leaf" in dut:
            output = st.config(dut, "do show run" , type = "vtysh")
            st.log(output)

def modify_config_file(config_file,vars):
    vars = st.get_testbed_vars()
    output_yaml_file = "temp_config.yaml"
    input_yaml_file = config_file
    dir_path = os.path.dirname(os.path.realpath(__file__))+"/"
    result = os.system("cp {0}{1} {0}{2}".format(dir_path,input_yaml_file,output_yaml_file))
    if result != 0:
        st.report_fail("config file copy failed")
    st.wait(2)
    for item, value in vars.items():
        if re.match("(D.D.P.)|(D.T.P.)", item):
            find_and_replace(dir_path+output_yaml_file, item, value)
    return output_yaml_file


def find_and_replace(file_path, target_string, replacement_string):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    # Iterate through the YAML data recursively
    def replace_string(obj):
        if isinstance(obj, str):
            return obj.replace(target_string, replacement_string)
        elif isinstance(obj, dict):
            return {key: replace_string(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [replace_string(item) for item in obj]
        else:
            return obj
    updated_data = replace_string(data)
    with open(file_path, 'w') as file:
        yaml.dump(updated_data, file)


def remove_temp_config(updated_cfg_file):
    os.system("rm {}".format(updated_cfg_file))

