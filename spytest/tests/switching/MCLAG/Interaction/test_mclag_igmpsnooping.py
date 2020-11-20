import pytest
from spytest import st, tgapi, SpyTestDict
from utilities.common import make_list
from utilities.parallel import exec_foreach, ensure_no_exception, exec_parallel, exec_all, ExecAllFunc
import apis.switching.portchannel as portchannel
import apis.switching.vlan as vapi
import apis.routing.ip as ip
import apis.switching.mclag as mclag
import apis.switching.igmp_snooping as igmp_snp
import apis.system.interface as intf
import apis.system.basic as basic_obj
import utilities.utils as utils

data = SpyTestDict()
vars = dict()
tg_dict = dict()

@pytest.fixture(scope="module", autouse=True)
def mclag_interaction_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:3", "D1D3:1", "D2D3:1", "D1T1:1", "D2T1:1", "D3T1:1")
    module_config()
    yield
    module_unconfig()

@pytest.fixture(scope="function", autouse=True)
def mclag_interaction_function_hooks(request):
    yield

def print_topology():
    topology = """
               +--------------------+                           +--------------------+
               |                    |                           |                    |
               |                ETH +--MCLAG_1_KEEP_ALIVE_LINK--+ ETH                |
               |    MCLAG_1_A       |                           |      MCLAG_1_S     |
               |                    |                           |                    |
               |       ETH  PC5 PC2 +------MCLAG_1_PEERLINK-----+ PC2 PC5 ETH        |
               +--------+----+------+                           +----+-----+---------+
                        |    |                                       |     |
                        |    |                                       |     |
                        +    +-----------+                 +---------+     +
                       TG                |                 |              TG
                                      XXXXXXXXX MCLAG_1 XXXXXXX
                                         |                 |
                                         |                 |
                                   +-----------------------------+
                                   |    PC5               PC5    |
                                   |                             |
                                   |        MCLAG_CLIENT         |
                                   |                             |
                                   |            ETH              |
                                   +-------------+---------------+
                                                 |
                                                 |
                                                 +
                                                 TG
    """
    st.log("############################################## TOPOLOGY ##############################################")
    st.log(topology)
    st.log("######################################################################################################")
    st.log("MCLAG_1_A - D1 : {}, Platform : {}".format(data.MCLAG_1_A, data.MCLAG_1_A_HWSKU))
    st.log("MCLAG_1_S - D2 : {}, Platform : {}".format(data.MCLAG_1_S, data.MCLAG_1_S_HWSKU))
    st.log("MCLAG_CLIENT - D3 : {}, Platform : {}".format(data.MCLAG_CLIENT, data.MCLAG_CLIENT_HWSKU))
    st.log("######################################################################################################")

def init_mclag_global_variables():
    global TG_HANDLER, TG, MCLAG_1_A_TG_PORT_HANDLER, MCLAG_1_S_TG_PORT_HANDLER, MCLAG_CLIENT_TG_PORT_HANDLER
    # Initialization
    data.attributes = SpyTestDict()

    # Initialize TG and TG port handlers
    TG_HANDLER = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D2P1, vars.T1D3P1])
    TG = TG_HANDLER["tg"]
    MCLAG_1_A_TG_PORT_HANDLER = TG_HANDLER["tg_ph_1"]
    MCLAG_1_S_TG_PORT_HANDLER = TG_HANDLER["tg_ph_2"]
    MCLAG_CLIENT_TG_PORT_HANDLER = TG_HANDLER["tg_ph_3"]

    # Common variables
    data.vlan_list = [10, 20, 30, 40]
    data.normal_vlans = data.vlan_list[0:3]
    data.peer_link_vlans = data.vlan_list[3:]
    data.mask = 24
    data.wait = 30
    data.keep_alive_link_vlan_intf = False

    # MCLAG_1 variables
    data.MCLAG_1_DOMAIN_ID = 1

    # MCLAG_1_A variables
    data.MCLAG_1_A = vars.D1
    data.MCLAG_1_A_TG1 = vars.D1T1P1
    data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link = vars.D1D2P1
    data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag = "PortChannel2"
    data.MCLAG_1_A_To_MCLAG_1_S_Peer_Link_Members = [vars.D1D2P2, vars.D1D2P3]
    data.MCLAG_1_A_MC_Lag_1 = "PortChannel5"
    data.MCLAG_1_A_MC_Lag_1_Members = vars.D1D3P1
    data.MCLAG_1_A_LOCAL_IP = "192.168.1.1"
    data.MCLAG_1_A_PEERLINK_VLAN = data.peer_link_vlans[0]
    data.MCLAG_1_A_HWSKU = basic_obj.get_hwsku(data.MCLAG_1_A)

    # MCLAG_1_S variables
    data.MCLAG_1_S = vars.D2
    data.MCLAG_1_S_TG1 = vars.D2T1P1
    data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link = vars.D2D1P1
    data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag = "PortChannel2"
    data.MCLAG_1_S_To_MCLAG_1_A_Peer_Link_Members = [vars.D2D1P2, vars.D2D1P3]
    data.MCLAG_1_S_MC_Lag_1 = "PortChannel5"
    data.MCLAG_1_S_MC_Lag_1_Members = vars.D2D3P1
    data.MCLAG_1_S_LOCAL_IP = "192.168.1.2"
    data.MCLAG_1_S_PEERLINK_VLAN = data.peer_link_vlans[0]
    data.MCLAG_1_S_HWSKU = basic_obj.get_hwsku(data.MCLAG_1_S)

    # MCLAG_CLIENT variables
    data.MCLAG_CLIENT = vars.D3
    data.MCLAG_CLIENT_TG1 = vars.D3T1P1
    data.MCLAG_CLIENT_MC_Lag_1 = "PortChannel5"
    data.MCLAG_CLIENT_MC_Lag_1_Members = [vars.D3D1P1, vars.D3D2P1]
    data.MCLAG_CLIENT_HWSKU = basic_obj.get_hwsku(data.MCLAG_CLIENT)

    data.dut_list = [data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_CLIENT]
    data.attributes.MCLAG_1_A = {"vlan_members": [data.MCLAG_1_A_TG1, data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag],
                                    "peer_links": [data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link],
                                    "port_channel": {data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag: data.MCLAG_1_A_To_MCLAG_1_S_Peer_Link_Members, data.MCLAG_1_A_MC_Lag_1: data.MCLAG_1_A_MC_Lag_1_Members},
                                    "mc_lag_config": {'domain_id': data.MCLAG_1_DOMAIN_ID, 'local_ip': data.MCLAG_1_A_LOCAL_IP, 'peer_ip': data.MCLAG_1_S_LOCAL_IP, 'peer_interface': data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, 'config': 'add', 'interfaces':[data.MCLAG_1_A_MC_Lag_1], 'session_status': 'OK', 'node_role': 'Active'},
                                    "mc_lag_intf_data":{'domain_id': data.MCLAG_1_DOMAIN_ID, data.MCLAG_1_A_MC_Lag_1: {'local_state':'Up', 'remote_state':'Up', 'isolate_with_peer':'Yes', 'traffic_disable':'No'}}}
    data.attributes.MCLAG_1_S = {"vlan_members": [data.MCLAG_1_S_TG1, data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag],
                                    "peer_links": [data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link],
                                    "port_channel": {data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag: data.MCLAG_1_S_To_MCLAG_1_A_Peer_Link_Members, data.MCLAG_1_S_MC_Lag_1: data.MCLAG_1_S_MC_Lag_1_Members},
                                    "mc_lag_config": {'domain_id': data.MCLAG_1_DOMAIN_ID, 'local_ip': data.MCLAG_1_S_LOCAL_IP, 'peer_ip': data.MCLAG_1_A_LOCAL_IP, 'peer_interface': data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag, 'config': 'add', "interfaces":[data.MCLAG_1_S_MC_Lag_1], 'session_status': 'OK', 'node_role': 'Standby'},
                                    "mc_lag_intf_data":{'domain_id': data.MCLAG_1_DOMAIN_ID, data.MCLAG_1_S_MC_Lag_1: {'local_state':'Up', 'remote_state':'Up', 'isolate_with_peer':'Yes', 'traffic_disable':'No'}}}
    data.attributes.MCLAG_CLIENT = {"vlan_members": [data.MCLAG_CLIENT_TG1, data.MCLAG_CLIENT_MC_Lag_1],
                                        "port_channel": {data.MCLAG_CLIENT_MC_Lag_1: data.MCLAG_CLIENT_MC_Lag_1_Members}}

def verify_mclag_state(mclag_duts, mclag_verify_data):
    [result, exceptions] = exec_parallel(True, mclag_duts, mclag.verify_domain, mclag_verify_data)
    ensure_no_exception(exceptions)
    if False in result:
        st.report_fail("mclag_state_verification_failed", mclag_verify_data)

def verify_mclag_intf_state(mclag_duts, mclag_verify_intf_data):
    [result, exceptions] = exec_parallel(True, mclag_duts, mclag.verify_interfaces, mclag_verify_intf_data)
    ensure_no_exception(exceptions)
    if False in result:
        st.report_fail("mclag_intf_verification_failed", mclag_verify_intf_data)

def config_igmp_snooping_static_mrouter(dut, vlan, mrouter_interface, no_form):
    mroute_int_li = make_list(mrouter_interface)
    for i in mroute_int_li:
        if no_form:
            igmp_snp.config(dut, "no_form", vlan = vlan, mrouter_interface = i)
        else:
            igmp_snp.config(dut, vlan=vlan, mrouter_interface=i)

def tg_routing_interface_config(type):
    global tg_dict

    tg_dict = {"MCLAG_CLIENT": {"IGMP_v1_Query" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v1_Report" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v2_Query" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v2_Report" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v3_Query" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v3_Report_GS" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}}, "MCLAG_1_A": {"IGMP_v1_Query" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v1_Report" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v2_Query" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v2_Report" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v3_Query" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}, "IGMP_v3_Report_GS" : {"RT_HANDLE" : "", "IGMP_HANDLE" : ""}}}

    if type == "report_and_leave":
        utils.banner_log("TG configuration : MCLAG_CLIENT")
        # MCLAG_CLIENT IGMPv1 Report
        tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, mode='config', intf_ip_addr='50.50.50.3', gateway='50.50.50.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[0], ipv4_resolve_gateway=0)
        session_conf = {'mode': 'create', 'igmp_version': 'v1'}
        group_conf = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': "224.1.50.1"}
        igmp_group_conf = {'mode': 'create', 'g_filter_mode': 'include'}
        tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["IGMP_HANDLE"] = tgapi.tg_igmp_config(tg=TG, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["RT_HANDLE"]["handle"], session_var=session_conf, group_var=group_conf, igmp_group_var=igmp_group_conf)
        TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["IGMP_HANDLE"]['session']['host_handle'], mode='start')

        # MCLAG_CLIENT IGMPv2 Report
        tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, mode='config', intf_ip_addr='50.50.50.5', gateway='50.50.50.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[1], ipv4_resolve_gateway=0)
        session_conf = {'mode': 'create', 'igmp_version': 'v2'}
        group_conf = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': "224.1.50.2"}
        igmp_group_conf = {'mode': 'create', 'g_filter_mode': 'include'}
        tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"] = tgapi.tg_igmp_config(tg=TG, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["RT_HANDLE"]["handle"], session_var=session_conf, group_var=group_conf, igmp_group_var=igmp_group_conf)
        TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['session']['host_handle'], mode='start')

        # MCLAG_CLIENT IGMPv3 Report (Group and source specific)
        tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, mode='config', intf_ip_addr='50.50.50.7', gateway='50.50.50.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[2], ipv4_resolve_gateway=0)
        session_conf = {'mode': 'create', 'igmp_version': 'v3'}
        group_conf = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': "224.1.50.31"}
        source_conf = {'mode': 'create', 'num_sources': '1', 'ip_addr_start': "10.1.1.1"}
        igmp_group_conf = {'mode': 'create', 'g_filter_mode': 'include'}
        tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"] = tgapi.tg_igmp_config(tg=TG, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["RT_HANDLE"]["handle"], session_var=session_conf, group_var=group_conf, source_var=source_conf, igmp_group_var=igmp_group_conf)
        TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['session']['host_handle'], mode='start')

        utils.banner_log("TG configuration : MCLAG_1_A")
        # MCLAG_1_A IGMPv1 Report
        tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, mode='config', intf_ip_addr='30.30.30.3', gateway='30.30.30.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[0], ipv4_resolve_gateway=0)
        session_conf = {'mode': 'create', 'igmp_version': 'v1'}
        group_conf = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': "224.1.30.1"}
        igmp_group_conf = {'mode': 'create', 'g_filter_mode': 'include'}
        tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["IGMP_HANDLE"] = tgapi.tg_igmp_config(tg=TG, handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["RT_HANDLE"]["handle"], session_var=session_conf, group_var=group_conf, igmp_group_var=igmp_group_conf)
        TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["IGMP_HANDLE"]['session']['host_handle'], mode='start')

        # MCLAG_1_A IGMPv2 Report
        tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, mode='config', intf_ip_addr='30.30.30.5', gateway='30.30.30.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[1], ipv4_resolve_gateway=0)
        session_conf = {'mode': 'create', 'igmp_version': 'v2'}
        group_conf = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': "224.1.30.2"}
        igmp_group_conf = {'mode': 'create', 'g_filter_mode': 'include'}
        tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"] = tgapi.tg_igmp_config(tg=TG, handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["RT_HANDLE"]["handle"], session_var=session_conf, group_var=group_conf, igmp_group_var=igmp_group_conf)
        TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['session']['host_handle'], mode='start')

        # MCLAG_1_A IGMPv3 Report (Group and source specific)
        tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, mode='config', intf_ip_addr='30.30.30.7', gateway='30.30.30.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[2], ipv4_resolve_gateway=0)
        session_conf = {'mode': 'create', 'igmp_version': 'v3'}
        group_conf = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': "224.1.30.31"}
        source_conf = {'mode': 'create', 'num_sources': '1', 'ip_addr_start': "10.1.1.1"}
        igmp_group_conf = {'mode': 'create', 'g_filter_mode': 'include'}
        tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"] = tgapi.tg_igmp_config(tg=TG, handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["RT_HANDLE"]["handle"], session_var=session_conf, group_var=group_conf, source_var=source_conf, igmp_group_var=igmp_group_conf)
        TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['session']['host_handle'], mode='start')
    else:
        utils.banner_log("TG configuration : MCLAG_CLIENT")
        # MCLAG_CLIENT IGMPv1 Query
        tg_dict["MCLAG_CLIENT"]["IGMP_v1_Query"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, mode='config', intf_ip_addr='50.50.50.2', gateway='50.50.50.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[0], ipv4_resolve_gateway=0)
        tg_dict["MCLAG_CLIENT"]["IGMP_v1_Query"]["IGMP_HANDLE"] = TG.tg_emulation_igmp_querier_config(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Query"]["RT_HANDLE"]["handle"], mode='create', igmp_version='v1')

        # MCLAG_CLIENT IGMPv2 Query
        tg_dict["MCLAG_CLIENT"]["IGMP_v2_Query"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, mode='config', intf_ip_addr='50.50.50.4', gateway='50.50.50.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[1], ipv4_resolve_gateway=0)
        tg_dict["MCLAG_CLIENT"]["IGMP_v2_Query"]["IGMP_HANDLE"] = TG.tg_emulation_igmp_querier_config(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Query"]["RT_HANDLE"]["handle"], mode='create', igmp_version='v2')

        # MCLAG_CLIENT IGMPv3 Query
        tg_dict["MCLAG_CLIENT"]["IGMP_v3_Query"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, mode='config', intf_ip_addr='50.50.50.6', gateway='50.50.50.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[2], ipv4_resolve_gateway=0)
        tg_dict["MCLAG_CLIENT"]["IGMP_v3_Query"]["IGMP_HANDLE"] = TG.tg_emulation_igmp_querier_config(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Query"]["RT_HANDLE"]["handle"], mode='create', igmp_version='v3')

        utils.banner_log("TG configuration : MCLAG_1_A")
        # MCLAG_1_A IGMPv1 Query
        tg_dict["MCLAG_1_A"]["IGMP_v1_Query"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, mode='config', intf_ip_addr='30.30.30.2', gateway='30.30.30.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[0], ipv4_resolve_gateway=0)
        tg_dict["MCLAG_1_A"]["IGMP_v1_Query"]["IGMP_HANDLE"] = TG.tg_emulation_igmp_querier_config(handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Query"]["RT_HANDLE"]["handle"], mode='create', igmp_version='v1')

        # MCLAG_1_A IGMPv2 Query
        tg_dict["MCLAG_1_A"]["IGMP_v2_Query"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, mode='config', intf_ip_addr='30.30.30.4', gateway='30.30.30.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[1], ipv4_resolve_gateway=0)
        tg_dict["MCLAG_1_A"]["IGMP_v2_Query"]["IGMP_HANDLE"] = TG.tg_emulation_igmp_querier_config(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Query"]["RT_HANDLE"]["handle"], mode='create', igmp_version='v2')

        # MCLAG_1_A IGMPv3 Query
        tg_dict["MCLAG_1_A"]["IGMP_v3_Query"]["RT_HANDLE"] = TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, mode='config', intf_ip_addr='30.30.30.6', gateway='30.30.30.1', arp_send_req='1', vlan='1', vlan_id=data.normal_vlans[2], ipv4_resolve_gateway=0)
        tg_dict["MCLAG_1_A"]["IGMP_v3_Query"]["IGMP_HANDLE"] = TG.tg_emulation_igmp_querier_config(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Query"]["RT_HANDLE"]["handle"], mode='create', igmp_version='v3')

def tg_routing_interface_unconfig(type):
    if type == "report_and_leave":
        TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["RT_HANDLE"]["handle"], mode='destroy')
    else:
        TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Query"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Query"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Query"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Query"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Query"]["RT_HANDLE"]["handle"], mode='destroy')
        TG.tg_interface_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Query"]["RT_HANDLE"]["handle"], mode='destroy')

def module_config():
    init_mclag_global_variables()
    print_topology()

    # Creating vlan and port channel data to be used for configuring in the topology
    utils.banner_log("Creating vlan and port channel data to be used for configuring in the topology")
    vlan_data = dict()
    portchannel_data = dict()
    data.mclag_domain = list()
    data.mclag_domain_del = list()
    data.mclag_duts = list()
    data.mclag_interfaces = list()
    data.mclag_interfaces_del = list()
    data.mclag_verify_data = list()
    data.mclag_verify_intf_data = list()

    for key, value in data.attributes.items():
        data.mclag_duts.append(data[key])
        if value.get("port_channel"):
            portchannel_data[data[key]] = value.get("port_channel")

        vlan_data[data[key]] = dict()
        if value.get("vlan_members"):
            vlan_data[data[key]]["normal_vlan"] = dict()
            vlan_data[data[key]]["normal_vlan"]["vlans"] = data.normal_vlans
            vlan_data[data[key]]["normal_vlan"]["members"] = value.get("vlan_members")

        if value.get("peer_links"):
            if data.keep_alive_link_vlan_intf:
                vlan_data[data[key]]["peer_vlan"] = dict()
                tempStr = str(key) + "_PEERLINK_VLAN"
                vlan_data[data[key]]["peer_vlan"]["vlans"] = data[tempStr]
                vlan_data[data[key]]["peer_vlan"]["members"] = value.get("peer_links")

        if value.get("mc_lag_config"):
            mc_lag_config = value.get("mc_lag_config")
            data.mclag_interfaces.append([mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"]])
            data.mclag_interfaces_del.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='del'))
            data.mclag_domain.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'add', 'domain_id': mc_lag_config["domain_id"]})
            data.mclag_domain_del.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'del', 'domain_id': mc_lag_config["domain_id"]})
            mclag_verify_dict = {'domain_id': mc_lag_config["domain_id"], 'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_link_inf': mc_lag_config['peer_interface'], 'mclag_intfs': len(mc_lag_config['interfaces']), 'session_status': mc_lag_config['session_status'], 'node_role': mc_lag_config['node_role']}
            data.mclag_verify_data.append(mclag_verify_dict)

        if value.get("mc_lag_intf_data"):
            mclag_intf_data = value.get("mc_lag_intf_data")
            mclag_verify_intf_dict = {'domain_id': mclag_intf_data["domain_id"]}
            for key, value in mclag_intf_data.items():
                if key != "domain_id":
                    mclag_verify_intf_dict.update({'mclag_intf': key, 'mclag_intf_local_state': value['local_state'], 'mclag_intf_peer_state': value['remote_state'], 'isolate_peer_link': value['isolate_with_peer'], 'traffic_disable': value['traffic_disable']})
            data.mclag_verify_intf_data.append(mclag_verify_intf_dict)

    utils.banner_log("MODULE VARIABLES DATA")
    st.log("VLANS USED : vlan_list : {}, normal_vlans : {}, peer_link_vlans : {}".format(data.vlan_list, data.normal_vlans, data.peer_link_vlans))
    st.log("PORTCHANNEL DATA : {}".format(portchannel_data))
    st.log("VLAN DATA : {}".format(vlan_data))
    st.log("MCLAG DUTS : {}".format(data.mclag_duts))
    st.log("MCLAG DOMAINS : {}".format(data.mclag_domain))
    st.log("MCLAG DOMAINS DEL: {}".format(data.mclag_domain_del))
    st.log("MCLAG INTERFACES : {}".format(data.mclag_interfaces))
    st.log("MCLAG INTERFACES DEL: {}".format(data.mclag_interfaces_del))
    st.log("MCLAG DATA : {}".format(data.mclag_verify_data))
    st.log("MCLAG INTF DATA : {}".format(data.mclag_verify_intf_data))

    # Clearing of all existing vlans and port channels on all the DUTs
    utils.banner_log("Clearing of all existing vlans and port channels on all the DUTs")
    vapi.clear_vlan_configuration(data.dut_list)
    portchannel.clear_portchannel_configuration(data.dut_list)

    # Configuring port channels on all the DUTs
    utils.banner_log("Configuring port channels on all the DUTs")
    [_, exceptions] = exec_foreach(True, data.dut_list, portchannel.config_multiple_portchannels, portchannel_data)
    ensure_no_exception(exceptions)

    # Configuring vlans on all the DUTs
    utils.banner_log("Configuring vlans on all the DUTs")
    [_, exceptions] = exec_foreach(True, data.dut_list, vapi.create_multiple_vlans_and_members, vlan_data)
    ensure_no_exception(exceptions)

    # Configuring ip address on peer links
    utils.banner_log("Configuring Ip address on peer links")
    api_list = list()
    api_list.append([ip.config_ip_addr_interface, data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A_LOCAL_IP, data.mask])
    api_list.append([ip.config_ip_addr_interface, data.MCLAG_1_S, data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link, data.MCLAG_1_S_LOCAL_IP, data.mask])
    [_, exceptions] = exec_all(True, api_list)
    ensure_no_exception(exceptions)

    # Configuring MCLAG domain on the MCLAG peers
    utils.banner_log("Configuring MCLAG domain on the MLCLAG peers")
    [_, exceptions] = exec_parallel(True, data.mclag_duts, mclag.config_domain, data.mclag_domain)
    ensure_no_exception(exceptions)

    # Configuring MCLAG interfaces for all the domains
    utils.banner_log("Configuring MCLAG interfaces for all the domains")
    [_, exceptions] = exec_all(True, data.mclag_interfaces)
    ensure_no_exception(exceptions)

    st.wait(data.wait)

    # Verification of MCLAG configuration
    utils.banner_log("Verification of MCLAG configuration")
    verify_mclag_state(data.mclag_duts, data.mclag_verify_data)
    verify_mclag_intf_state(data.mclag_duts, data.mclag_verify_intf_data)

    # Configuring IGMP snooping all the DUTs
    utils.banner_log("Configuring IGMP snooping all the DUTs")
    [_, exceptions] = exec_foreach(True, data.dut_list, igmp_snp.config_igmp_snooping, data.normal_vlans[0], '1', 'enable')
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_foreach(True, data.dut_list, igmp_snp.config_igmp_snooping, data.normal_vlans[1], '2', 'enable')
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_foreach(True, data.dut_list, igmp_snp.config_igmp_snooping, data.normal_vlans[2], '3', 'enable')
    ensure_no_exception(exceptions)

    # Configuring IGMP snooping static mrouter
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[0], [data.MCLAG_CLIENT_MC_Lag_1], False)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[1], [data.MCLAG_CLIENT_MC_Lag_1], False)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[2], [data.MCLAG_CLIENT_MC_Lag_1], False)

def module_unconfig():
    # Unconfiguring IGMP snooping static mrouter
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[0], [data.MCLAG_CLIENT_MC_Lag_1], True)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[1], [data.MCLAG_CLIENT_MC_Lag_1], True)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[2], [data.MCLAG_CLIENT_MC_Lag_1], True)

    # Unconfiguring IGMP snooping all the DUTs
    utils.banner_log("Unconfiguring IGMP snooping all the DUTs")
    [_, exceptions] = exec_foreach(True, data.dut_list, igmp_snp.config_igmp_snooping, data.normal_vlans[0], '1', 'disable')
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_foreach(True, data.dut_list, igmp_snp.config_igmp_snooping, data.normal_vlans[1], '2', 'disable')
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_foreach(True, data.dut_list, igmp_snp.config_igmp_snooping, data.normal_vlans[2], '3', 'disable')
    ensure_no_exception(exceptions)

    # Unconfiguring MCLAG interfaces for all the domains
    utils.banner_log("Unconfiguring MCLAG interfaces for all the domains")
    [_, exceptions] = exec_all(True, data.mclag_interfaces_del)
    ensure_no_exception(exceptions)

    # Unconfiguring MCLAG domain on the MLCLAG peers
    utils.banner_log("Unconfiguring MCLAG domain on the MLCLAG peers")
    [_, exceptions] = exec_parallel(True, data.mclag_duts, mclag.config_domain, data.mclag_domain_del)
    ensure_no_exception(exceptions)

    # Unconfiguring Ip address on peer links
    utils.banner_log("Unconfiguring Ip address on peer links")
    api_list = list()
    api_list.append([ip.delete_ip_interface, data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A_LOCAL_IP, data.mask])
    api_list.append([ip.delete_ip_interface, data.MCLAG_1_S, data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link, data.MCLAG_1_S_LOCAL_IP, data.mask])
    [_, exceptions] = exec_all(True, api_list)
    ensure_no_exception(exceptions)

    # Clearing of configured vlans and port channels on all the DUTs
    utils.banner_log("Clearing of configured vlans and port channels on all the DUTs")
    vapi.clear_vlan_configuration(data.dut_list)
    portchannel.clear_portchannel_configuration(data.dut_list)

@pytest.fixture(scope="function")
def fixture_igmp_snooping_2(request):
    # Unconfiguring IGMP snooping static mrouter
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[0], [data.MCLAG_CLIENT_MC_Lag_1], True)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[1], [data.MCLAG_CLIENT_MC_Lag_1], True)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[2], [data.MCLAG_CLIENT_MC_Lag_1], True)

    # TG configuration
    utils.banner_log("TG configuration : MCLAG + IGMP Snooping (Query)")
    tg_routing_interface_config("query")

    yield
    # Configuring IGMP snooping static mrouter
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[0], [data.MCLAG_CLIENT_MC_Lag_1], False)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[1], [data.MCLAG_CLIENT_MC_Lag_1], False)
    config_igmp_snooping_static_mrouter(data.MCLAG_CLIENT, data.normal_vlans[2], [data.MCLAG_CLIENT_MC_Lag_1], False)

    # TG unconfiguration
    utils.banner_log("TG unconfiguration : MCLAG + IGMP Snooping (Query)")
    tg_routing_interface_unconfig("query")

def test_ft_igmp_snooping_mclag_query_sync_to_peer(fixture_igmp_snooping_2):
    test_result = []
    result7 = True

    #############################################################################################################################################
    # Verification of IGMPv1/v2/v3 query on MCLAG port and Orphan port -- STARTED.
    #############################################################################################################################################
    utils.banner_log("Verification of IGMPv1/v2/v3 query on MCLAG port and Orphan port -- STARTED.")
    # Sending IGMPv1/v2/v3 query on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.")
    TG.tg_igmp_querier_control(mode='start', handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Query"]["IGMP_HANDLE"]['handle'])
    TG.tg_igmp_querier_control(mode='start', handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Query"]["IGMP_HANDLE"]['handle'])
    TG.tg_igmp_querier_control(mode='start', handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Query"]["IGMP_HANDLE"]['handle'])
    TG.tg_igmp_querier_control(mode='start', handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Query"]["IGMP_HANDLE"]['handle'])

    st.wait(data.wait)

    # Verifying IGMPv2 query on MCLAG Peers.
    st.log("Verifying IGMPv2 query on MCLAG Peers.")
    if not igmp_snp.verify(data.MCLAG_CLIENT, mrouter_interface=[data.MCLAG_CLIENT_TG1, data.MCLAG_CLIENT_MC_Lag_1], vlan=data.normal_vlans[1]):
        result7 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "PASS"))

    if not igmp_snp.verify(data.MCLAG_1_A, mrouter_interface=[data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A_TG1], vlan=data.normal_vlans[1]):
        result7 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify(data.MCLAG_1_S, mrouter_interface=[data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag], vlan=data.normal_vlans[1]):
        result7 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "PASS"))

    # Verifying IGMPv3 query on MCLAG Peers.
    st.log("Verifying IGMPv3 query on MCLAG Peers.")
    if not igmp_snp.verify(data.MCLAG_CLIENT, mrouter_interface=[data.MCLAG_CLIENT_TG1, data.MCLAG_CLIENT_MC_Lag_1], vlan=data.normal_vlans[2]):
        result7 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_CLIENT", "PASS"))

    if not igmp_snp.verify(data.MCLAG_1_A, mrouter_interface=[data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A_TG1], vlan=data.normal_vlans[2]):
        result7 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify(data.MCLAG_1_S, mrouter_interface=[data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag], vlan=data.normal_vlans[2]):
        result7 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 query from MCLAG & ORPHAN interfaces", "MCLAG_1_S", "PASS"))
    utils.banner_log("Verification of IGMPv1/v2/v3 query on MCLAG port and Orphan port -- COMPLETED.")
    #############################################################################################################################################
    # Verification of IGMPv1/v2/v3 query on MCLAG port and Orphan port -- COMPLETED.
    #############################################################################################################################################

    utils.banner_log("MCLAG + IGMP Snooping (Query) Test Results")
    for each_line in test_result:
        st.log(each_line)
    st.log("################################################################################")

    if result7:
        st.report_tc_pass("FtOpSoSwIgFi008", "mclag_igmp_snooping_sync_to_mclag_peer_successful", "IGMPv1/v2/v3 Query")
        st.report_pass("test_case_passed")
    else:
        st.report_tc_fail("FtOpSoSwIgFi008", "mclag_igmp_snooping_sync_to_mclag_peer_unsuccessful", "IGMPv1/v2/v3 Query")
        st.report_fail("test_case_failed")

@pytest.fixture(scope="function")
def fixture_igmp_snooping_1(request):
    # TG configuration
    utils.banner_log("TG configuration : MCLAG + IGMP Snooping (Report + Leave)")
    tg_routing_interface_config("report_and_leave")

    yield
    # TG unconfiguration
    utils.banner_log("TG unconfiguration : MCLAG + IGMP Snooping (Report + Leave)")
    tg_routing_interface_unconfig("report_and_leave")

def test_ft_igmp_snooping_mclag_report_leave_sync_to_peer(fixture_igmp_snooping_1):
    test_result = []
    result1, result2, result3 = True, True, True

    #############################################################################################################################################
    # Verification of IGMPv1/v2/v3 report on MCLAG port and Orphan port -- STARTED.
    #############################################################################################################################################
    utils.banner_log("Verification of IGMPv1/v2/v3 report on MCLAG port and Orphan port -- STARTED.")
    # Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.")
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')

    st.wait(data.wait)

    # Verifying IGMPv1/v2/v3 report sent on MCLAG Interface.
    st.log("Verifying IGMPv1/v2/v3 report sent on MCLAG Interface.")
    if not igmp_snp.verify_groups(data.MCLAG_CLIENT, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.50.1", "outgoing_ports": [data.MCLAG_CLIENT_TG1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_CLIENT", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.50.1", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.50.1", "outgoing_ports": [data.MCLAG_1_S_MC_Lag_1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface", "MCLAG_1_S", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_CLIENT, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_CLIENT_TG1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_CLIENT", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_1_S_MC_Lag_1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface", "MCLAG_1_S", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_CLIENT, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_CLIENT_TG1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_CLIENT", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_1_S_MC_Lag_1]}]):
        result1 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface", "MCLAG_1_S", "PASS"))

    # Verifying IGMPv1/v2/v3 report sent on ORPHAN Interface.
    st.log("Verifying IGMPv1/v2/v3 report sent on ORPHAN Interface.")
    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.30.1", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result2 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.30.1", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result2 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface", "MCLAG_1_S", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result2 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result2 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface", "MCLAG_1_S", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result2 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result2 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface", "MCLAG_1_S", "PASS"))
    utils.banner_log("Verification of IGMPv1/v2/v3 report on MCLAG port and Orphan port -- COMPLETED.")
    #############################################################################################################################################
    # Verification of IGMPv1/v2/v3 report on MCLAG port and Orphan port -- COMPLETED.
    #############################################################################################################################################

    #############################################################################################################################################
    # Verification of IGMPv2/v3 leave on MCLAG port and Orphan port -- STARTED.
    #############################################################################################################################################
    utils.banner_log("Verification of IGMPv2/v3 leave on MCLAG port and Orphan port -- STARTED.")
    # Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 leave on MCLAG port and Orphan port.")
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')

    st.wait(data.wait)

    # Verifying IGMPv2 leave on MCLAG Peers.
    st.log("Verifying IGMPv2 leave on MCLAG Peers.")
    if igmp_snp.verify_groups(data.MCLAG_CLIENT, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_CLIENT_TG1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_CLIENT", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_A", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_A", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_1_S_MC_Lag_1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from MCLAG interface", "MCLAG_1_S", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 leave from ORPHAN interface", "MCLAG_1_S", "PASS"))

    # Verifying IGMPv3 leave on MCLAG Peers.
    st.log("Verifying IGMPv3 leave on MCLAG Peers.")
    if igmp_snp.verify_groups(data.MCLAG_CLIENT, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_CLIENT_TG1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_CLIENT", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_CLIENT", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_CLIENT", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_A", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_A", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_1_S_MC_Lag_1]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from MCLAG interface", "MCLAG_1_S", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result3 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 leave from ORPHAN interface", "MCLAG_1_S", "PASS"))
    utils.banner_log("Verification of IGMPv2/v3 leave on MCLAG port and Orphan port -- COMPLETED.")
    #############################################################################################################################################
    # Verification of IGMPv2/v3 leave on MCLAG port and Orphan port -- COMPLETED.
    #############################################################################################################################################

    utils.banner_log("MCLAG + IGMP Snooping (Report + Leave) Test Results")
    for each_line in test_result:
        st.log(each_line)
    st.log("################################################################################")

    if result1:
        st.report_tc_pass("FtOpSoSwIgFi009", "mclag_igmp_snooping_sync_to_mclag_peer_successful", "IGMPv1/v2/v3 Report (MCLAG INTF)")
    else:
        st.report_tc_fail("FtOpSoSwIgFi009", "mclag_igmp_snooping_sync_to_mclag_peer_unsuccessful", "IGMPv1/v2/v3 Report (MCLAG INTF)")

    if result2:
        st.report_tc_pass("FtOpSoSwIgFi010", "mclag_igmp_snooping_sync_to_mclag_peer_successful", "IGMPv1/v2/v3 Report (ORPHAN INTF)")
    else:
        st.report_tc_fail("FtOpSoSwIgFi010", "mclag_igmp_snooping_sync_to_mclag_peer_unsuccessful", "IGMPv1/v2/v3 Report (ORPHAN INTF)")

    if result3:
        st.report_tc_pass("FtOpSoSwIgFi011", "mclag_igmp_snooping_sync_to_mclag_peer_successful", "IGMPv2/v3 Leave (MCLAG + ORPHAN INTF)")
    else:
        st.report_tc_fail("FtOpSoSwIgFi011", "mclag_igmp_snooping_sync_to_mclag_peer_unsuccessful", "IGMPv2/v3 Leave (MCLAG + ORPHAN INTF)")

    if result1 and result2 and result3:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def test_ft_igmp_snooping_mclag_peerlink_shutdown(fixture_igmp_snooping_1):
    test_result = []
    result6 = True

    # Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.")
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')

    st.wait(data.wait)

    #############################################################################################################################################
    # Verification of shutdown of Peerlink between MCLAG_1_A and MCLAG_1_S -- STARTED.
    #############################################################################################################################################
    utils.banner_log("Verification of shutdown of Peerlink between MCLAG_1_A and MCLAG_1_S -- STARTED.")
    # Shutting down the Peerlink between MCLAG_1_A and MCLAG_1_S.
    st.log("Shutting down the Peerlink between MCLAG_1_A and MCLAG_1_S.")
    intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag , "shutdown")
    if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, "down", iteration=10, delay=1):
        st.error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, data.MCLAG_1_A))
        st.report_fail("interface_is_up_on_dut", data.MCLAG_1_A)

    st.wait(data.wait)

    # Verifying IGMPv1/v2/v3 report on MCLAG Peers after shutting down the Peerlink.
    st.log("Verifying IGMPv1/v2/v3 report on MCLAG Peers after shutting down the Peerlink.")
    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.30.1", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_A", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.30.1", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "PASS"))

    if igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink shutdown", "MCLAG_1_S", "PASS"))

    # Bringing up the Peerlink between MCLAG_1_A and MCLAG_1_S.
    st.log("Bringing up the Peerlink between MCLAG_1_A and MCLAG_1_S.")
    intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag , "startup")
    if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, "up", iteration=10, delay=1):
        st.error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, data.MCLAG_1_A))
        st.report_fail("interface_is_down_on_dut", data.MCLAG_1_A)

    st.wait(data.wait)

    # Verifying IGMPv1/v2/v3 report on MCLAG Peers after bringing up the Peerlink.
    st.log("Verifying IGMPv1/v2/v3 report on MCLAG Peers after bringing up the Peerlink.")
    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.30.1", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_A_TG1]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.30.1", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.30.2", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_S, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.30.31", "outgoing_ports": [data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag]}]):
        result6 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from ORPHAN interface and peerlink no shutdown", "MCLAG_1_S", "PASS"))

    if result6:
        st.report_tc_pass("FtOpSoSwIgFi014", "mclag_igmp_snooping_entry_check_split_brain_case_successful", "IGMPv1/v2/v3 Report")
    else:
        st.report_tc_fail("FtOpSoSwIgFi014", "mclag_igmp_snooping_entry_check_split_brain_case_unsuccessful", "IGMPv1/v2/v3")
    utils.banner_log("Verification of shutdown of Peerlink between MCLAG_1_A and MCLAG_1_S -- COMPLETED.")
    #############################################################################################################################################
    # Verification of shutdown of Peerlink between MCLAG_1_A and MCLAG_1_S -- COMPLETED.
    #############################################################################################################################################

    # Sending IGMPv1/v2/v3 leave on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 leave on MCLAG port and Orphan port.")
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')

    utils.banner_log("MCLAG + IGMP Snooping (Peerlink shut/noshut) Test Results")
    for each_line in test_result:
        st.log(each_line)
    st.log("################################################################################")

    if result6:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def test_ft_igmp_snooping_mclag_interface_shutdown(fixture_igmp_snooping_1):
    test_result = []
    result4, result5 = True, True

    # Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 report on MCLAG port and Orphan port.")
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v1_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v1_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='join')

    st.wait(data.wait)

    #############################################################################################################################################
    # Verification of shutdown of MCLAG interface on MCLAG_1_A. -- STARTED.
    #############################################################################################################################################
    utils.banner_log("Verification of shutdown of MCLAG interface on MCLAG_1_A. -- STARTED.")
    # Shutting down the MCLAG interface on MCLAG_1_A.
    st.log("Shutting down the MCLAG interface on MCLAG_1_A.")
    intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "shutdown")
    if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "down", iteration=10, delay=1):
        st.error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
        st.report_fail("interface_is_up_on_dut", data.MCLAG_1_A)

    st.wait(data.wait)

    # Verifying IGMPv1/v2/v3 report on MCLAG Peers after shutting down the MCLAG interface.
    st.log("Verifying IGMPv1/v2/v3 report on MCLAG Peers after shutting down the MCLAG interface.")
    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.50.1", "outgoing_ports": [data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag]}]):
        result4 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag]}]):
        result4 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag]}]):
        result4 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG shutdown", "MCLAG_1_A", "PASS"))

    if result4:
        st.report_tc_pass("FtOpSoSwIgFi013", "mclag_igmp_snooping_entry_check_mclag_down_case_successful", "IGMPv1/v2/v3 Report")
    else:
        st.report_tc_fail("FtOpSoSwIgFi013", "mclag_igmp_snooping_entry_check_mclag_down_case_unsuccessful", "IGMPv1/v2/v3 Report")

    # Bringing up the MCLAG interface on MCLAG_1_A.
    st.log("Bringing up the MCLAG interface on MCLAG_1_A.")
    intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "startup")
    if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "up", iteration=10, delay=1):
        st.error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
        st.report_fail("interface_is_down_on_dut", data.MCLAG_1_A)

    st.wait(data.wait)

    # Verifying IGMPv1/v2/v3 report on MCLAG Peers after bringing up the MCLAG interface.
    st.log("Verifying IGMPv1/v2/v3 report on MCLAG Peers after bringing up the MCLAG interface.")
    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[0], "source_address": "*", "group_address": "224.1.50.1", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result5 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv1 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[1], "source_address": "*", "group_address": "224.1.50.2", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result5 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv2 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "PASS"))

    if not igmp_snp.verify_groups(data.MCLAG_1_A, "groups_vlan", verify_list=[{"vlan": data.normal_vlans[2], "source_address": "10.1.1.1", "group_address": "224.1.50.31", "outgoing_ports": [data.MCLAG_1_A_MC_Lag_1]}]):
        result5 = False
        st.error("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "FAIL"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "FAIL"))
    else:
        st.log("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "PASS"))
        test_result.append("Test : {}, Verification on DUT : {}, Result : {}".format("IGMPv3 report from MCLAG interface and MCLAG no shutdown", "MCLAG_1_A", "PASS"))

    if result5:
        st.report_tc_pass("FtOpSoSwIgFi012", "mclag_igmp_snooping_entry_check_mclag_up_case_successful", "IGMPv1/v2/v3 Report")
    else:
        st.report_tc_fail("FtOpSoSwIgFi012", "mclag_igmp_snooping_entry_check_mclag_up_case_unsuccessful", "IGMPv1/v2/v3 Report")
    utils.banner_log("Verification of shutdown of MCLAG interface on MCLAG_1_A. -- COMPLETED.")
    #############################################################################################################################################
    # Verification of shutdown of MCLAG interface on MCLAG_1_A. -- COMPLETED.
    #############################################################################################################################################

    # Sending IGMPv1/v2/v3 leave on MCLAG port and Orphan port.
    st.log("Sending IGMPv1/v2/v3 leave on MCLAG port and Orphan port.")
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v2_Report"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_CLIENT"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')
    TG.tg_emulation_igmp_control(handle=tg_dict["MCLAG_1_A"]["IGMP_v3_Report_GS"]["IGMP_HANDLE"]['config']['group_handle'], mode='leave')

    utils.banner_log("MCLAG + IGMP Snooping (MCLAG Intf shut/noshut) Test Results")
    for each_line in test_result:
        st.log(each_line)
    st.log("################################################################################")

    if result4 and result5:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")
