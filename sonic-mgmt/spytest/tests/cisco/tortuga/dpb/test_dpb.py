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
import apis.system.port as papi 


def initialize_variables():
    global vars, nodes
    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()

def get_dut_config_file(feature):
    vars = st.get_testbed_vars()
    st.log(vars)

    p1 = vars.T1D1P1
    p2 = vars.T1D2P1
    np1 = p1[-1:]
    np2 = p2[-1:]
    dut_config = ""
    ixia_config = ""
    if feature == 'dpb_subinterface':
        dut_config = 'dpb_subinterface.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_vrf":
        dut_config = 'dpb_vrf.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_bfd":
        dut_config = 'dpb_bfd.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_dhcp":
        dut_config = 'dpb_dhcp.yaml'
        ixia_config = r'DHCP relay-working.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_portch":
        dut_config = 'dpb_portchannel.yaml'
        ixia_config = r'siren_optics_l2_traffic-UDP-bidirec-vlannew_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_mtu":
        dut_config = 'dpb_mtu.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G_mtu1500.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature == 'dpb_subinterface_400G':
        dut_config = 'dpb_subinterface_400G.yaml'
        ixia_config = r'carib_carib_optics_l3_traffic_bidir_only25_1_to_25_4.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_vrf_400G":
        dut_config = 'dpb_vrf_400G.yaml'
        ixia_config = r'carib_carib_optics_l3_traffic_bidir_only25_1_to_25_4.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_bfd_400G":
        dut_config = 'dpb_bfd_400G.yaml'
        ixia_config = r'carib_carib_optics_l3_traffic_bidir_only25_1_to_25_4.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_dhcp_400G":
        dut_config = 'dpb_dhcp_400G.yaml'
        ixia_config = r'DHCP relay-working.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_portch_400G":
        dut_config = 'dpb_portchannel_400G.yaml'
        ixia_config = r'carib_carib_optics_l2_traffic-4UDP-bidirec-vlannew.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_mtu_400G":
        dut_config = 'dpb_mtu_400G.yaml'
        ixia_config = r'carib_carib_optics_l3_traffic_bidir_only25_1_to_25_4_MTU1500.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_vrf_40G":
        dut_config = 'dpb_vrf_40G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_bfd_40G":
        dut_config = 'dpb_bfd_40G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature == 'dpb_subinterface_40G':
        dut_config = 'dpb_subinterface_40G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_dhcp_40G":
        dut_config = 'dpb_dhcp_40G.yaml'
        ixia_config = r'siren-DHCP relay-working_50_to_10.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_portch_40G":
        dut_config = 'dpb_portchannel_40G.yaml'
        ixia_config = r'siren_optics_l2_traffic-UDP-bidirec-vlannew_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_mtu_40G":
        dut_config = 'dpb_mtu_40G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G_mtu1500.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_vrf_siren_10G":
        dut_config = 'dpb_vrf_siren_10G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_bfd_siren_10G":
        dut_config = 'dpb_bfd_siren_10G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature == 'dpb_subinterface_siren_10G':
        dut_config = 'dpb_subinterface_siren_10G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_dhcp_siren_10G":
        dut_config = 'dpb_dhcp_siren_10G.yaml'
        ixia_config = r'siren-DHCP relay-working_50_to_10.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_portch_siren_10G":
        dut_config = 'dpb_portchannel_siren_10G.yaml'
        ixia_config = r'siren_optics_l2_traffic-UDP-bidirec-vlannew_50_to_10G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_mtu_siren_10G":
        dut_config = 'dpb_mtu_siren_10G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_10G_mtu1500.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature == 'dpb_subinterface_siren_25G':
        dut_config = 'dpb_subinterface_siren_25G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_vrf_siren_25G":
        dut_config = 'dpb_vrf_siren_25G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_bfd_siren_25G":
        dut_config = 'dpb_bfd_siren_25G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_dhcp_siren_25G":
        dut_config = 'dpb_dhcp_siren_25G.yaml'
        ixia_config = r'DHCP relay-working.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_portch_siren_25G":
        dut_config = 'dpb_portchannel_siren_25G.yaml'
        ixia_config = r'siren_optics_l2_traffic-UDP-bidirec-vlannew_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_mtu_siren_25G":
        dut_config = 'dpb_mtu_siren_25G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G_mtu1500.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature == 'dpb_subinterface_siren_50G':
        dut_config = 'dpb_subinterface_siren_50G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_vrf_siren_50G":
        dut_config = 'dpb_vrf_siren_50G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_bfd_siren_50G":
        dut_config = 'dpb_bfd_siren_50G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    elif feature =="dpb_dhcp_siren_50G":
        dut_config = 'dpb_dhcp_siren_50G.yaml'
        ixia_config = r'DHCP relay-working.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_portch_siren_50G":
        dut_config = 'dpb_portchannel_siren_50G.yaml'
        ixia_config = r'siren_optics_l2_traffic-UDP-bidirec-vlannew_50_to_25G.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}

    elif feature =="dpb_mtu_siren_50G":
        dut_config = 'dpb_mtu_siren_50G.yaml'
        ixia_config = r'siren_optics_l3_traffic_bidir_50_to_25G_mtu1500.ixncfg'
        port_info = {"chassis_ip" : "10.29.158.194", "slot": 1, "port1": np1, "port2": np2}


    else:
        st.log("feature not found")
        st.report_fail("test_case_failed")
    return dut_config,ixia_config,port_info


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

    traffic_items = ixnetwork.Traffic.TrafficItem.find()
    for traffic_item in traffic_items:
        traffic_item.Generate()
    st.wait(5)
    ixnetwork.Traffic.Apply()
    st.wait(5)
    return ixnetwork,ixnetwork_session


def ixia_setup_dhcp(ixia_config_file,port_info):
    flag = False
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
    dhcp_addresses = ixnetwork.Topology.find(Name='Topology 2').DeviceGroup.find().Ethernet.find().Dhcpv4client.find()
    traffic_items = ixnetwork.Traffic.TrafficItem.find()
    for dhcp_item in dhcp_addresses:
        st.log(dhcp_addresses.DiscoveredAddresses)
        st.log(type(dhcp_addresses.DiscoveredAddresses))
        out = dhcp_addresses.DiscoveredAddresses
        if out[0] == '40.20.20.2':
            flag = True
    return ixnetwork,ixnetwork_session,flag

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
    st.wait(30)
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
        threshold = .9
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
def dpb_subinterface_setup():
    config_files = get_dut_config_file('dpb_subinterface')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_subinterface')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_vrf_setup():
    config_files = get_dut_config_file('dpb_vrf')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_vrf')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_bfd_setup():
    config_files = get_dut_config_file('dpb_bfd')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_bfd')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_portch_setup():
    config_files = get_dut_config_file('dpb_portch')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_portch')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_mtu_setup():
    config_files = get_dut_config_file('dpb_mtu')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_mtu')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_dhcp_setup():
    config_files = get_dut_config_file('dpb_dhcp')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup_dhcp(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_dhcp')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_subinterface_400G_setup():
    config_files = get_dut_config_file('dpb_subinterface_400G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_subinterface_400G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_vrf_400G_setup():
    config_files = get_dut_config_file('dpb_vrf_400G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_vrf_400G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_bfd_400G_setup():
    config_files = get_dut_config_file('dpb_bfd_400G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_bfd_400G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_portch_400G_setup():
    config_files = get_dut_config_file('dpb_portch_400G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_portch_400G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_mtu_400G_setup():
    config_files = get_dut_config_file('dpb_mtu_400G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_mtu_400G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_dhcp_400G_setup():
    config_files = get_dut_config_file('dpb_dhcp_400G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup_dhcp(config_files[1],config_files[2])
    get_cli_out()
    chk_interface()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_dhcp_400G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        chk_interface_back()
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_subinterface_40G_setup():
    config_files = get_dut_config_file('dpb_subinterface_40G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_subinterface_40G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_vrf_40G_setup():
    config_files = get_dut_config_file('dpb_vrf_40G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_vrf_40G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_bfd_40G_setup():
    config_files = get_dut_config_file('dpb_bfd_40G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_bfd_40G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_portch_40G_setup():
    config_files = get_dut_config_file('dpb_portch_40G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_portch_40G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_mtu_40G_setup():
    config_files = get_dut_config_file('dpb_mtu_40G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_mtu_40G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_dhcp_40G_setup():
    config_files = get_dut_config_file('dpb_dhcp_40G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup_dhcp(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_dhcp_40G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_subinterface_siren_10G_setup():
    config_files = get_dut_config_file('dpb_subinterface_siren_10G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_subinterface_siren_10G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_vrf_siren_10G_setup():
    config_files = get_dut_config_file('dpb_vrf_siren_10G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_vrf_siren_10G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_bfd_siren_10G_setup():
    config_files = get_dut_config_file('dpb_bfd_siren_10G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_bfd_siren_10G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_portch_siren_10G_setup():
    config_files = get_dut_config_file('dpb_portch_siren_10G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_portch_siren_10G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_mtu_siren_10G_setup():
    config_files = get_dut_config_file('dpb_mtu_siren_10G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_mtu_siren_10G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_dhcp_siren_10G_setup():
    config_files = get_dut_config_file('dpb_dhcp_siren_10G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup_dhcp(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_dhcp_siren_10G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_subinterface_siren_25G_setup():
    config_files = get_dut_config_file('dpb_subinterface_siren_25G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_subinterface_siren_25G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_vrf_siren_25G_setup():
    config_files = get_dut_config_file('dpb_vrf_siren_25G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_vrf_siren_25G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_bfd_siren_25G_setup():
    config_files = get_dut_config_file('dpb_bfd_siren_25G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_bfd_siren_25G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_portch_siren_25G_setup():
    config_files = get_dut_config_file('dpb_portch_siren_25G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_portch_siren_25G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_mtu_siren_25G_setup():
    config_files = get_dut_config_file('dpb_mtu_siren_25G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_mtu_siren_25G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_dhcp_siren_25G_setup():
    config_files = get_dut_config_file('dpb_dhcp_siren_25G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup_dhcp(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_dhcp_siren_25G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_subinterface_siren_50G_setup():
    config_files = get_dut_config_file('dpb_subinterface_siren_50G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_subinterface_siren_50G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_vrf_siren_50G_setup():
    config_files = get_dut_config_file('dpb_vrf_siren_50G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_vrf_siren_50G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_bfd_siren_50G_setup():
    config_files = get_dut_config_file('dpb_bfd_siren_50G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_bfd_siren_50G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()


@pytest.fixture(scope="function")
def dpb_portch_siren_50G_setup():
    config_files = get_dut_config_file('dpb_portch_siren_50G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_portch_siren_50G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_mtu_siren_50G_setup():
    config_files = get_dut_config_file('dpb_mtu_siren_50G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_mtu_siren_50G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

@pytest.fixture(scope="function")
def dpb_dhcp_siren_50G_setup():
    config_files = get_dut_config_file('dpb_dhcp_siren_50G')
    updated_cfg_file = modify_config_file(config_files[0],vars)
    static_config_push(updated_cfg_file)
    get_config_out()
    out = ixia_setup_dhcp(config_files[1],config_files[2])
    get_cli_out_speed()
    try:
        yield out
    finally:
        config_files = get_dut_config_file('dpb_dhcp_siren_50G')
        updated_cfg_file = modify_config_file(config_files[0],vars)
        unconfig(updated_cfg_file)
        remove_temp_config(updated_cfg_file)
        router_preconfig_cleanup()
        get_config_out()

## TESTCASES ###
@pytest.mark.hundred
def test_dpb_subinterface(dpb_subinterface_setup):
    ixnetwork = dpb_subinterface_setup[0]
    ixnetwork_session = dpb_subinterface_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.hundred
def test_dpb_vrf(dpb_vrf_setup):
    ixnetwork = dpb_vrf_setup[0]
    ixnetwork_session = dpb_vrf_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.hundred
def test_dpb_bfd(dpb_bfd_setup):
    ixnetwork = dpb_bfd_setup[0]
    ixnetwork_session = dpb_bfd_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.hundred
def test_dpb_portch(dpb_portch_setup):
    ixnetwork = dpb_portch_setup[0]
    ixnetwork_session = dpb_portch_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.hundred
def test_dpb_mtu(dpb_mtu_setup):
    ixnetwork = dpb_mtu_setup[0]
    ixnetwork_session = dpb_mtu_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.hundred
def test_dpb_dhcp(dpb_dhcp_setup):
    ixnetwork, ixnetwork_session, flag = dpb_dhcp_setup
    ixia_teardown(ixnetwork_session)
    st.log("dpb test passed")
    if flag:
        st.log("test_dpb_dhcp test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("test_dpb_dhcp")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.fourhundred
def test_dpb_subinterface_400G(dpb_subinterface_400G_setup):
    ixnetwork = dpb_subinterface_400G_setup[0]
    ixnetwork_session = dpb_subinterface_400G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.fourhundred
def test_dpb_vrf_400G(dpb_vrf_400G_setup):
    ixnetwork = dpb_vrf_400G_setup[0]
    ixnetwork_session = dpb_vrf_400G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.fourhundred
def test_dpb_bfd_400G(dpb_bfd_400G_setup):
    ixnetwork = dpb_bfd_400G_setup[0]
    ixnetwork_session = dpb_bfd_400G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.fourhundred
def test_dpb_portch_400G(dpb_portch_400G_setup):
    ixnetwork = dpb_portch_400G_setup[0]
    ixnetwork_session = dpb_portch_400G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.fourhundred
def test_dpb_mtu_400G(dpb_mtu_400G_setup):
    ixnetwork = dpb_mtu_400G_setup[0]
    ixnetwork_session = dpb_mtu_400G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.fourhundred
def test_dpb_dhcp_400G(dpb_dhcp_400G_setup):
    ixnetwork, ixnetwork_session, flag = dpb_dhcp_400G_setup
    ixia_teardown(ixnetwork_session)
    st.log("dpb test passed")
    if flag:
        st.log("test_dpb_dhcp test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("test_dpb_dhcp")
        get_cli_out()
        st.report_fail("test_case_failed")


@pytest.mark.forty
def test_dpb_subinterface_40G(dpb_subinterface_40G_setup):
    ixnetwork = dpb_subinterface_40G_setup[0]
    ixnetwork_session = dpb_subinterface_40G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.forty
def test_dpb_vrf_40G(dpb_vrf_40G_setup):
    ixnetwork = dpb_vrf_40G_setup[0]
    ixnetwork_session = dpb_vrf_40G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.forty
def test_dpb_bfd_40G(dpb_bfd_40G_setup):
    ixnetwork = dpb_bfd_40G_setup[0]
    ixnetwork_session = dpb_bfd_40G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.forty
def test_dpb_portch_40G(dpb_portch_40G_setup):
    ixnetwork = dpb_portch_40G_setup[0]
    ixnetwork_session = dpb_portch_40G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")

@pytest.mark.forty
def test_dpb_mtu_40G(dpb_mtu_40G_setup):
    ixnetwork = dpb_mtu_40G_setup[0]
    ixnetwork_session = dpb_mtu_40G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    chk_interface_traf()
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out()
        st.report_fail("test_case_failed")


@pytest.mark.forty
def test_dpb_dhcp_40G(dpb_dhcp_40G_setup):
    ixnetwork, ixnetwork_session, flag = dpb_dhcp_40G_setup
    ixia_teardown(ixnetwork_session)
    st.log("dpb test passed")
    if flag:
        st.log("test_dpb_dhcp test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("test_dpb_dhcp")
        get_cli_out()
        st.report_fail("test_case_failed")


@pytest.mark.sirenteng
def test_dpb_subinterface_siren_10G(dpb_subinterface_siren_10G_setup):
    ixnetwork = dpb_subinterface_siren_10G_setup[0]
    ixnetwork_session = dpb_subinterface_siren_10G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenteng
def test_dpb_vrf_siren_10G(dpb_vrf_siren_10G_setup):
    ixnetwork = dpb_vrf_siren_10G_setup[0]
    ixnetwork_session = dpb_vrf_siren_10G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenteng
def test_dpb_bfd_siren_10G(dpb_bfd_siren_10G_setup):
    ixnetwork = dpb_bfd_siren_10G_setup[0]
    ixnetwork_session = dpb_bfd_siren_10G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenteng
def test_dpb_portch_siren_10G(dpb_portch_siren_10G_setup):
    ixnetwork = dpb_portch_siren_10G_setup[0]
    ixnetwork_session = dpb_portch_siren_10G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenteng
def test_dpb_mtu_siren_10G(dpb_mtu_siren_10G_setup):
    ixnetwork = dpb_mtu_siren_10G_setup[0]
    ixnetwork_session = dpb_mtu_siren_10G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")


@pytest.mark.sirenteng
def test_dpb_dhcp_siren_10G(dpb_dhcp_siren_10G_setup):
    ixnetwork, ixnetwork_session, flag = dpb_dhcp_siren_10G_setup
    ixia_teardown(ixnetwork_session)
    st.log("dpb test passed")
    if flag:
        st.log("test_dpb_dhcp test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("test_dpb_dhcp")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirentwentyfiveg
def test_dpb_subinterface_siren_25G(dpb_subinterface_siren_25G_setup):
    ixnetwork = dpb_subinterface_siren_25G_setup[0]
    ixnetwork_session = dpb_subinterface_siren_25G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirentwentyfiveg
def test_dpb_vrf_siren_25G(dpb_vrf_siren_25G_setup):
    ixnetwork = dpb_vrf_siren_25G_setup[0]
    ixnetwork_session = dpb_vrf_siren_25G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirentwentyfiveg
def test_dpb_bfd_siren_25G(dpb_bfd_siren_25G_setup):
    ixnetwork = dpb_bfd_siren_25G_setup[0]
    ixnetwork_session = dpb_bfd_siren_25G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirentwentyfiveg
def test_dpb_portch_siren_25G(dpb_portch_siren_25G_setup):
    ixnetwork = dpb_portch_siren_25G_setup[0]
    ixnetwork_session = dpb_portch_siren_25G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirentwentyfiveg
def test_dpb_mtu_siren_25G(dpb_mtu_siren_25G_setup):
    ixnetwork = dpb_mtu_siren_25G_setup[0]
    ixnetwork_session = dpb_mtu_siren_25G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")


@pytest.mark.sirentwentyfiveg
def test_dpb_dhcp_siren_25G(dpb_dhcp_siren_25G_setup):
    ixnetwork, ixnetwork_session, flag = dpb_dhcp_siren_25G_setup
    ixia_teardown(ixnetwork_session)
    st.log("dpb test passed")
    if flag:
        st.log("test_dpb_dhcp test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("test_dpb_dhcp")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenfifty
def test_dpb_subinterface_siren_50G(dpb_subinterface_siren_50G_setup):
    ixnetwork = dpb_subinterface_siren_50G_setup[0]
    ixnetwork_session = dpb_subinterface_siren_50G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenfifty
def test_dpb_vrf_siren_50G(dpb_vrf_siren_50G_setup):
    ixnetwork = dpb_vrf_siren_50G_setup[0]
    ixnetwork_session = dpb_vrf_siren_50G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenfifty
def test_dpb_bfd_siren_50G(dpb_bfd_siren_50G_setup):
    ixnetwork = dpb_bfd_siren_50G_setup[0]
    ixnetwork_session = dpb_bfd_siren_50G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")


@pytest.mark.sirenfifty
def test_dpb_portch_siren_50G(dpb_portch_siren_50G_setup):
    ixnetwork = dpb_portch_siren_50G_setup[0]
    ixnetwork_session = dpb_portch_siren_50G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")

@pytest.mark.sirenfifty
def test_dpb_mtu_siren_50G(dpb_mtu_siren_50G_setup):
    ixnetwork = dpb_mtu_siren_50G_setup[0]
    ixnetwork_session = dpb_mtu_siren_50G_setup[1]
    start_stop_traffic(ixnetwork)
    stats = get_traffic_stats(ixnetwork_session)
    #check tx and rx packet count
    result = validate_traffic_stats(stats)
    ixia_teardown(ixnetwork_session)
    if result:
        st.log("dpb test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("dpb test failed")
        get_cli_out_speed()
        st.report_fail("test_case_failed")


@pytest.mark.sirenfifty
def test_dpb_dhcp_siren_50G(dpb_dhcp_siren_50G_setup):
    ixnetwork, ixnetwork_session, flag = dpb_dhcp_siren_50G_setup
    ixia_teardown(ixnetwork_session)
    st.log("dpb test passed")
    if flag:
        st.log("test_dpb_dhcp test passed")
        st.report_pass('test_case_passed')
    else:
        st.log("test_dpb_dhcp")
        get_cli_out_speed()
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
            config_dut(node, 'sonic', config_dict[node]['sonic']['deconfig'])
            


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
    vars = st.get_testbed_vars()
    cmds = ["docker ps -a", "show vlan brief", "show interface status", "show bfd sum", "show interface counters",
           "show ip int","show interface counters -i {}".format(vars.D1D2P2),"show interface counters -i {}".format(vars.D1D2P3),
           "show interface counters -i {}".format(vars.D1D2P4),"show interface counters -i {}".format(vars.D1D2P5)]

    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.config(dut, item)
                st.log(output)

def get_cli_out_speed():
    vars = st.get_testbed_vars()
    cmds = ["docker ps -a", "show vlan brief", "show interface status", "show bfd sum", "show interface counters",
           "show ip int","show interface counters -i {}".format(vars.D1D2P1)]

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


def chk_interface():
    vars = st.get_testbed_vars()
    output = papi.get_interface_counters_all(vars.D1)
    for entry in output:
        if entry["iface"] == vars.D1D2P2:
            st.log("Breakout works for {}".format(vars.D1D2P2))
        if entry["iface"] == vars.D1D2P3:
            st.log("Breakout works for {}".format(vars.D1D2P3))
        if entry["iface"] == vars.D1D2P4:
            st.log("Breakout works for {}".format(vars.D1D2P4))
        if entry["iface"] == vars.D1D2P5:
            st.log("Breakout works for {}".format(vars.D1D2P5))

def chk_interface_traf():
    vars = st.get_testbed_vars()
    tx1_bps = 0
    tx2_bps = 0
    tx3_bps = 0
    tx4_bps = 0
    output = papi.get_interface_counters_all(vars.D1)
    for entry in output:
        if entry["iface"] == vars.D1D2P2:
            tx1_bps = entry["tx_bps"]
        if entry["iface"] == vars.D1D2P3:
            tx2_bps = entry["tx_bps"]
        if entry["iface"] == vars.D1D2P4:
            tx3_bps = entry["tx_bps"]
        if entry["iface"] == vars.D1D2P5:
            tx4_bps = entry["tx_bps"]
    tx1_bps = tx1_bps.replace("MB/s", "")
    tx2_bps = tx2_bps.replace("MB/s", "")
    tx3_bps = tx3_bps.replace("MB/s", "")
    tx3_bps = tx3_bps.replace("MB/s", "")
    tx1_bps = tx1_bps.replace("B/s", "")
    tx2_bps = tx2_bps.replace("B/s", "")
    tx3_bps = tx3_bps.replace("B/s", "")
    tx4_bps = tx3_bps.replace("B/s", "")
    st.log("After sending traffic tx of the breakout intefaces are")
    st.log(tx1_bps)
    st.log(tx2_bps)
    st.log(tx3_bps)
    st.log(tx4_bps)



def chk_interface_back():
    vars = st.get_testbed_vars()
    output = papi.get_interface_counters_all(vars.D1)
    for entry in output:
        if entry["iface"] == vars.D1D2P1:
            st.log("Breakout to 400G works for {}".format(vars.D1D2P1))


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

