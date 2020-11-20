from spytest import st, tgapi, SpyTestDict
from spytest.utils import filter_and_select
from utilities.parallel import exec_foreach, ensure_no_exception, exec_parallel, exec_all, ExecAllFunc
import apis.switching.portchannel as portchannel
import apis.switching.vlan as vapi
import apis.routing.ip as ip
import apis.switching.mclag as mclag
import apis.switching.mac as mac
import apis.switching.pvst as stp
import apis.system.interface as intf
import apis.system.basic as basic
import apis.system.reboot as reboot
import apis.system.logging as slog
import utilities.utils as utils
import random
import math

data = SpyTestDict()
tg_dict = dict()

def print_topology(vars):
    topology_1_tier = """
                          TG                                              TG
                           +                                               +
                           |                                               |
                           |                                               |
                +----------+----------+                         +----------+----------+
                |         ETH     PC1 +-------------------------+ PC1     ETH         |
        +-------+ ETH                 |                         |                     |
        |       |     MCLAG_2_A       |                         |      MCLAG_2_S      |
        |       |                     |                         |                     |
        |       |  PC3                |                         |            PC3      |
        |       +---+-----------------+                         +-----------------+---+
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |           |                                                             |
        |       +---+----------------+                           +----------------+---+
        |       |  PC3               |                           |         PC3        |
        |       |                ETH +--MCLAG_1_KEEP_ALIVE_LINK--+ ETH                |
        |       |    MCLAG_1_A       |                           |     MCLAG_1_S      |
        |       |                    |                           |                    |
        |       |       ETH  PC5 PC2 +------MCLAG_1_PEERLINK-----+ PC2 PC5 ETH        |
        |       +--------+----+------+                           +----+-----+---------+
        |                |    |                                       |     |
        |                |    |                                       |     |
        |                +    +-----------+                 +---------+     +
        |               TG                |                 |              TG
        |                              XXXXXXXXX MCLAG_1 XXXXXXX
        |                                 |                 |
        |                                 |                 |
        |                           +-----------------------------+
        |                           |    PC5               PC5    |
        |                           |                             |
        +---------------------------+ ETH    MCLAG_CLIENT         |
                                    |                             |
                                    |            ETH              |
                                    +-------------+---------------+
                                                  |
                                                  |
                                                  +
                                                 TG
    """
    topology_2_tier = """
                          TG                                              TG
                           +                                               +
                           |                                               |
                           |                                               |
                +----------+----------+                         +----------+----------+
                |         ETH     PC1 +----MCLAG_2_PEERLINK-----+ PC1     ETH         |
        +-------+ ETH                 |                         |                     |
        |       |     MCLAG_2_A       |                         |      MCLAG_2_S      |
        |       |                 ETH |-MCLAG_2_KEEP_ALIVE_LINK-| ETH                 |
        |       |  PC3     PC4    PC4 |                         |  PC4      PC4   PC3 |
        |       +---+-------+-------+-+                         +---+-------+-----+---+
        |           |       |       |                               |       |     |
        |           |       |       |                               |       |     |
        |           |       |       |                               |       |     |
        |           |       |    +----------------------------------+       |     |
        |           |       |    |  |                                       |     |
        |           |       |    |  |                                       |     |
        |           |       |    |  +-------------------------------+       |     |
        |           |       |    |                                  |       |     |
        |           |    XXXXXXXXXXXXXXXXXXXXXXX MCLAG_2 XXXXXXXXXXXXXXXXXXXXX    |
        |           |       |    |                                  |       |     |
        |           |       |    |                                  |       |     |
        |       +---+-------+----+---+                           +--+-------+-----+---+
        |       |  PC3     PC4  PC4  |                           | PC4     PC4   PC3  |
        |       |                ETH +--MCLAG_1_KEEP_ALIVE_LINK--+ ETH                |
        |       |    MCLAG_1_A       |                           |     MCLAG_1_S      |
        |       |                    |                           |                    |
        |       |       ETH  PC5 PC2 +------MCLAG_1_PEERLINK-----+ PC2 PC5 ETH        |
        |       +--------+----+------+                           +----+-----+---------+
        |                |    |                                       |     |
        |                |    |                                       |     |
        |                +    +-----------+                 +---------+     +
        |               TG                |                 |              TG
        |                              XXXXXXXXX MCLAG_1 XXXXXX
        |                                 |                 |
        |                                 |                 |
        |                           +-----------------------------+
        |                           |    PC5               PC5    |
        |                           |                             |
        +---------------------------+ ETH    MCLAG_CLIENT         |
                                    |                             |
                                    |            ETH              |
                                    +-------------+---------------+
                                                  |
                                                  |
                                                  +
                                                 TG
    """
    topology_1_tier_scale = """
                          TG                                              TG
                           +                                               +
                           |                                               |
                           |                                               |
                +----------+----------+                         +----------+----------+
                |         ETH     PC1 +-------------------------+ PC1     ETH         |
        +-------+ ETH                 |                         |                     |
        |       |     MCLAG_2_A       |                         |      MCLAG_2_S      |
        |       |                     |                         |                     |
        |       |  PC3                |                         |            PC3      |
        |       +---+---+----------+--+                         +---+--------+----+---+
        |           |   |          |                                |        |    |
        |           |   |          |                                |        |    |
        |           |   |          |                                |        |    |
        |           |   |          |                                |        |    |
        |           |   +->38    <-+                                +->38  <-+    |
        |           |   |  Eth     |                                |  Eth   |    |
        |           |   |  Intfs   |                                |  Intfs |    |
        |           |   |          |                                |        |    |
        |           |   |          |                                |        |    |
        |           |   |          |                                |        |    |
        |           |   |          |                                |        |    |
        |       +---+---+----------+-+                           +--+--------+----+---+
        |       |  PC3               |                           |               PC3  |
        |       |                ETH +-+MCLAG_1_KEEP_ALIVE_LINK+-+ ETH                |
        |       |    MCLAG_1_A       |                           |     MCLAG_1_S      |
        |       |                    |                           |                    |
        |       |       ETH  PC5 PC2 +-----+MCLAG_1_PEERLINK+----+ PC2 PC5 ETH        |
        |       +--------+----+------+                           +----+-----+---------+
        |                |    |                                       |     |
        |                |    |                                       |     |
        |                +    +-----------+                 +---------+     +
        |               TG                +                 +              TG
        |                              XXXXXXXXX MCLAG_1 XXXXXXX
        |                                 +                 +
        |                                 |                 |
        |                           +-----+-----------------+-----+
        |                           |    PC5               PC5    |
        |                           |                             |
        +---------------------------+ ETH    MCLAG_CLIENT         |
                                    |                             |
                                    |            ETH              |
                                    +-------------+---------------+
                                                  |
                                                  |
                                                  +
                                                 TG
    """
    st.log("############################################## TOPOLOGY ##############################################")
    if not data.topology_scale:
        if data.topology_2_tier:
            st.log(topology_2_tier)
        else:
            st.log(topology_1_tier)
    else:
        st.log(topology_1_tier_scale)

    utils.banner_log("STP vports configured in the setup is : {}".format(int(data.max_vlan_instances * len(data.MCLAG_1_A_Complete_Port_List))))

def init_mclag_global_variables(vars, topology_2_tier, stp_protocol, topology_scale):
    # Initialization
    data.attributes = SpyTestDict()
    global TG, TG_HANDLER, MCLAG_2_A_TG_PORT_HANDLER, MCLAG_2_S_TG_PORT_HANDLER, MCLAG_1_A_TG_PORT_HANDLER, MCLAG_1_S_TG_PORT_HANDLER, MCLAG_CLIENT_TG_PORT_HANDLER

    # Initialize TG and TG port handlers
    TG_HANDLER = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D2P1, vars.T1D3P1, vars.T1D4P1, vars.T1D5P1])
    TG = TG_HANDLER["tg"]
    MCLAG_2_A_TG_PORT_HANDLER = TG_HANDLER["tg_ph_1"]
    MCLAG_2_S_TG_PORT_HANDLER = TG_HANDLER["tg_ph_2"]
    MCLAG_1_A_TG_PORT_HANDLER = TG_HANDLER["tg_ph_3"]
    MCLAG_1_S_TG_PORT_HANDLER = TG_HANDLER["tg_ph_4"]
    MCLAG_CLIENT_TG_PORT_HANDLER = TG_HANDLER["tg_ph_5"]

    # Common variables
    data.vars = vars
    data.keep_alive_link_vlan_intf = False
    data.mclag_peers_as_only_root = False
    data.topology_2_tier = topology_2_tier
    data.topology_scale = topology_scale
    if data.topology_scale:
        data.max_vlan_instances = 255
        data.topology_scale_number = 5100
        data.topology_scale_ports_count = int(math.ceil(data.topology_scale_number/data.max_vlan_instances))
    else:
        data.max_vlan_instances = 3
    data.vlan_list = utils.get_random_vlans_in_sequence(count=data.max_vlan_instances+2, start=1, end=4093)
    data.normal_vlans = data.vlan_list[0:data.max_vlan_instances]
    data.peer_link_vlans = data.vlan_list[data.max_vlan_instances:]
    data.mask = 24
    data.stp_protocol = stp_protocol
    data.stp_dict = {"pvst": {"stp_wait_time": 50, "non_fwd_state": "BLOCKING", "fwd_state": "FORWARDING"}, "rpvst": {"stp_wait_time": 10, "non_fwd_state": "DISCARDING", "fwd_state": "FORWARDING"}}
    data.mclag_wait_time = 30
    data.logErrorFlag = True
    data.stable_state_check_at_test_start = True

    # MCLAG_2 variables
    data.MCLAG_2_DOMAIN_ID = 2

    # MCLAG_1 variables
    data.MCLAG_1_DOMAIN_ID = 1

    # MCLAG_2_A variables
    data.MCLAG_2_A = vars.D1
    data.MCLAG_2_A_TG1 = vars.D1T1P1
    data.MCLAG_2_A_To_MCLAG_2_S_Keep_Alive_Link = vars.D1D2P3
    data.MCLAG_2_A_To_MCLAG_2_S_Peer_Lag = "PortChannel1"
    data.MCLAG_2_A_To_MCLAG_2_S_Peer_Link_Members = [vars.D1D2P1, vars.D1D2P2]
    data.MCLAG_2_A_To_MCLAG_1_A_Lag = "PortChannel3"
    data.MCLAG_2_A_To_MCLAG_1_A_Lag_Members = [vars.D1D3P1,vars.D1D3P2]
    data.MCLAG_2_A_MC_Lag_2 = "PortChannel4"
    data.MCLAG_2_A_MC_Lag_2_Members = [vars.D1D3P3, vars.D1D4P1]
    data.MCLAG_2_A_To_MCLAG_CLIENT_INTF = vars.D1D5P1
    data.MCLAG_2_A_LOCAL_IP = "192.168.2.1"
    data.MCLAG_2_A_PEERLINK_VLAN = data.peer_link_vlans[1]
    if data.topology_2_tier:
        data.MCLAG_2_A_Complete_Port_List = [data.MCLAG_2_A_TG1, data.MCLAG_2_A_To_MCLAG_1_A_Lag, data.MCLAG_2_A_MC_Lag_2, data.MCLAG_2_A_To_MCLAG_CLIENT_INTF]
    else:
        data.MCLAG_2_A_Complete_Port_List = [data.MCLAG_2_A_TG1, data.MCLAG_2_A_To_MCLAG_2_S_Peer_Lag, data.MCLAG_2_A_To_MCLAG_1_A_Lag, data.MCLAG_2_A_To_MCLAG_CLIENT_INTF]

    # MCLAG_2_S variables
    data.MCLAG_2_S = vars.D2
    data.MCLAG_2_S_TG1 = vars.D2T1P1
    data.MCLAG_2_S_To_MCLAG_2_A_Keep_Alive_Link = vars.D2D1P3
    data.MCLAG_2_S_To_MCLAG_2_A_Peer_Lag = "PortChannel1"
    data.MCLAG_2_S_To_MCLAG_2_A_Peer_Link_Members = [vars.D2D1P1, vars.D2D1P2]
    data.MCLAG_2_S_To_MCLAG_1_S_Lag = "PortChannel3"
    data.MCLAG_2_S_To_MCLAG_1_S_Lag_Members = [vars.D2D4P1, vars.D2D4P2]
    data.MCLAG_2_S_MC_Lag_2 = "PortChannel4"
    data.MCLAG_2_S_MC_Lag_2_Members = [vars.D2D3P1, vars.D2D4P3]
    data.MCLAG_2_S_LOCAL_IP = "192.168.2.2"
    data.MCLAG_2_S_PEERLINK_VLAN = data.peer_link_vlans[1]
    if data.topology_2_tier:
        data.MCLAG_2_S_Complete_Port_List = [data.MCLAG_2_S_TG1, data.MCLAG_2_S_To_MCLAG_1_S_Lag, data.MCLAG_2_S_MC_Lag_2]
    else:
        data.MCLAG_2_S_Complete_Port_List = [data.MCLAG_2_S_TG1, data.MCLAG_2_S_To_MCLAG_2_A_Peer_Lag, data.MCLAG_2_S_To_MCLAG_1_S_Lag]

    # MCLAG_1_A variables
    data.MCLAG_1_A = vars.D3
    data.MCLAG_1_A_TG1 = vars.D3T1P1
    data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link = vars.D3D4P1
    data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag = "PortChannel2"
    data.MCLAG_1_A_To_MCLAG_1_S_Peer_Link_Members = [vars.D3D4P2, vars.D3D4P3]
    data.MCLAG_1_A_To_MCLAG_2_A_Lag = "PortChannel3"
    data.MCLAG_1_A_To_MCLAG_2_A_Lag_Members = [vars.D3D1P1, vars.D3D1P2]
    data.MCLAG_1_A_MC_Lag_1 = "PortChannel5"
    data.MCLAG_1_A_MC_Lag_1_Members = vars.D3D5P1
    data.MCLAG_1_A_MC_Lag_2 = "PortChannel4"
    data.MCLAG_1_A_MC_Lag_2_Members = [vars.D3D1P3, vars.D3D2P1]
    data.MCLAG_1_A_LOCAL_IP = "192.168.1.1"
    data.MCLAG_1_A_PEERLINK_VLAN = data.peer_link_vlans[0]
    if data.topology_2_tier:
        data.MCLAG_1_A_Complete_Port_List = [data.MCLAG_1_A_TG1, data.MCLAG_1_A_To_MCLAG_2_A_Lag, data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A_MC_Lag_2]
    else:
        data.MCLAG_1_A_Complete_Port_List = [data.MCLAG_1_A_TG1, data.MCLAG_1_A_To_MCLAG_2_A_Lag, data.MCLAG_1_A_MC_Lag_1]
        data.MCLAG_1_A_Complete_Port_List_1 = [data.MCLAG_1_A_To_MCLAG_2_A_Lag, data.MCLAG_1_A_MC_Lag_1]

    # MCLAG_1_S variables
    data.MCLAG_1_S = vars.D4
    data.MCLAG_1_S_TG1 = vars.D4T1P1
    data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link = vars.D4D3P1
    data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag = "PortChannel2"
    data.MCLAG_1_S_To_MCLAG_1_A_Peer_Link_Members = [vars.D4D3P2, vars.D4D3P3]
    data.MCLAG_1_S_To_MCLAG_2_S_Lag = "PortChannel3"
    data.MCLAG_1_S_To_MCLAG_2_S_Lag_Members = [vars.D4D2P1, vars.D4D2P2]
    data.MCLAG_1_S_MC_Lag_1 = "PortChannel5"
    data.MCLAG_1_S_MC_Lag_1_Members = vars.D4D5P1
    data.MCLAG_1_S_MC_Lag_2 = "PortChannel4"
    data.MCLAG_1_S_MC_Lag_2_Members = [vars.D4D1P1, vars.D4D2P3]
    data.MCLAG_1_S_LOCAL_IP = "192.168.1.2"
    data.MCLAG_1_S_PEERLINK_VLAN = data.peer_link_vlans[0]
    if data.topology_2_tier:
        data.MCLAG_1_S_Complete_Port_List = [data.MCLAG_1_S_TG1, data.MCLAG_1_S_To_MCLAG_2_S_Lag, data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S_MC_Lag_2]
    else:
        data.MCLAG_1_S_Complete_Port_List = [data.MCLAG_1_S_TG1, data.MCLAG_1_S_To_MCLAG_2_S_Lag, data.MCLAG_1_S_MC_Lag_1]

    # MCLAG_CLIENT variables
    data.MCLAG_CLIENT = vars.D5
    data.MCLAG_CLIENT_TG1 = vars.D5T1P1
    data.MCLAG_CLIENT_MC_Lag_1 = "PortChannel5"
    data.MCLAG_CLIENT_MC_Lag_1_Members = [vars.D5D3P1, vars.D5D4P1]
    data.MCLAG_CLIENT_To_MCLAG_2_A_INTF = vars.D5D1P1
    data.MCLAG_CLIENT_Complete_Port_List = [data.MCLAG_CLIENT_TG1, data.MCLAG_CLIENT_MC_Lag_1, data.MCLAG_CLIENT_To_MCLAG_2_A_INTF]

    data.dut_list = [data.MCLAG_2_A, data.MCLAG_2_S, data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_CLIENT]
    data.dut_to_tg_list = {data.MCLAG_2_A : data.MCLAG_2_A_TG1, data.MCLAG_2_S : data.MCLAG_2_S_TG1, data.MCLAG_1_A : data.MCLAG_1_A_TG1, data.MCLAG_1_S : data.MCLAG_1_S_TG1, data.MCLAG_CLIENT : data.MCLAG_CLIENT_TG1}
    data.attributes.MCLAG_2_A = {"vlan_members":[data.MCLAG_2_A_TG1, data.MCLAG_2_A_To_MCLAG_1_A_Lag, data.MCLAG_2_A_MC_Lag_2, data.MCLAG_2_A_To_MCLAG_2_S_Peer_Lag, data.MCLAG_2_A_To_MCLAG_CLIENT_INTF],
                                    "peer_links":[data.MCLAG_2_A_To_MCLAG_2_S_Keep_Alive_Link],
                                    "port_channel": {data.MCLAG_2_A_To_MCLAG_2_S_Peer_Lag: data.MCLAG_2_A_To_MCLAG_2_S_Peer_Link_Members, data.MCLAG_2_A_To_MCLAG_1_A_Lag: data.MCLAG_2_A_To_MCLAG_1_A_Lag_Members, data.MCLAG_2_A_MC_Lag_2: data.MCLAG_2_A_MC_Lag_2_Members},
                                    "mc_lag_config": {'domain_id': data.MCLAG_2_DOMAIN_ID, 'local_ip': data.MCLAG_2_A_LOCAL_IP, 'peer_ip': data.MCLAG_2_S_LOCAL_IP, 'peer_interface': data.MCLAG_2_A_To_MCLAG_2_S_Peer_Lag, 'config': 'add', 'interfaces':[data.MCLAG_2_A_MC_Lag_2], 'session_status': 'OK', 'node_role': 'Active'},
                                    "mc_lag_intf_data":{'domain_id': data.MCLAG_2_DOMAIN_ID, data.MCLAG_2_A_MC_Lag_2: {'local_state':'Up', 'remote_state':'Up', 'isolate_with_peer':'Yes', 'traffic_disable':'No'}}}
    data.attributes.MCLAG_2_S = {"vlan_members": [data.MCLAG_2_S_TG1, data.MCLAG_2_S_To_MCLAG_1_S_Lag, data.MCLAG_2_S_MC_Lag_2, data.MCLAG_2_S_To_MCLAG_2_A_Peer_Lag],
                                    "peer_links": [data.MCLAG_2_S_To_MCLAG_2_A_Keep_Alive_Link],
                                    "port_channel": {data.MCLAG_2_S_To_MCLAG_2_A_Peer_Lag: data.MCLAG_2_S_To_MCLAG_2_A_Peer_Link_Members, data.MCLAG_2_S_To_MCLAG_1_S_Lag: data.MCLAG_2_S_To_MCLAG_1_S_Lag_Members, data.MCLAG_2_S_MC_Lag_2: data.MCLAG_2_S_MC_Lag_2_Members},
                                    "mc_lag_config": {'domain_id': data.MCLAG_2_DOMAIN_ID, 'local_ip': data.MCLAG_2_S_LOCAL_IP, 'peer_ip': data.MCLAG_2_A_LOCAL_IP, 'peer_interface': data.MCLAG_2_S_To_MCLAG_2_A_Peer_Lag, 'config': 'add', 'interfaces':[data.MCLAG_2_S_MC_Lag_2], 'session_status': 'OK','node_role': 'Standby'},
                                    "mc_lag_intf_data":{'domain_id': data.MCLAG_2_DOMAIN_ID, data.MCLAG_2_S_MC_Lag_2: {'local_state':'Up', 'remote_state':'Up', 'isolate_with_peer':'Yes', 'traffic_disable':'No'}}}
    data.attributes.MCLAG_1_A = {"vlan_members": [data.MCLAG_1_A_TG1, data.MCLAG_1_A_To_MCLAG_2_A_Lag, data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A_MC_Lag_2, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag],
                                    "peer_links": [data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link],
                                    "port_channel": {data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag: data.MCLAG_1_A_To_MCLAG_1_S_Peer_Link_Members, data.MCLAG_1_A_To_MCLAG_2_A_Lag: data.MCLAG_1_A_To_MCLAG_2_A_Lag_Members, data.MCLAG_1_A_MC_Lag_1: data.MCLAG_1_A_MC_Lag_1_Members, data.MCLAG_1_A_MC_Lag_2: data.MCLAG_1_A_MC_Lag_2_Members},
                                    "mc_lag_config": {'domain_id': data.MCLAG_1_DOMAIN_ID, 'local_ip': data.MCLAG_1_A_LOCAL_IP, 'peer_ip': data.MCLAG_1_S_LOCAL_IP, 'peer_interface': data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, 'config': 'add', 'interfaces':[data.MCLAG_1_A_MC_Lag_1], 'session_status': 'OK', 'node_role': 'Active'},
                                    "mc_lag_intf_data":{'domain_id': data.MCLAG_1_DOMAIN_ID, data.MCLAG_1_A_MC_Lag_1: {'local_state':'Up', 'remote_state':'Up', 'isolate_with_peer':'Yes', 'traffic_disable':'No'}}}
    data.attributes.MCLAG_1_S = {"vlan_members": [data.MCLAG_1_S_TG1, data.MCLAG_1_S_To_MCLAG_2_S_Lag, data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S_MC_Lag_2, data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag],
                                    "peer_links": [data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link],
                                    "port_channel": {data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag: data.MCLAG_1_S_To_MCLAG_1_A_Peer_Link_Members, data.MCLAG_1_S_To_MCLAG_2_S_Lag: data.MCLAG_1_S_To_MCLAG_2_S_Lag_Members, data.MCLAG_1_S_MC_Lag_1: data.MCLAG_1_S_MC_Lag_1_Members, data.MCLAG_1_S_MC_Lag_2: data.MCLAG_1_S_MC_Lag_2_Members},
                                    "mc_lag_config": {'domain_id': data.MCLAG_1_DOMAIN_ID, 'local_ip': data.MCLAG_1_S_LOCAL_IP, 'peer_ip': data.MCLAG_1_A_LOCAL_IP, 'peer_interface': data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag, 'config': 'add', "interfaces":[data.MCLAG_1_S_MC_Lag_1], 'session_status': 'OK', 'node_role': 'Standby'},
                                    "mc_lag_intf_data":{'domain_id': data.MCLAG_1_DOMAIN_ID, data.MCLAG_1_S_MC_Lag_1: {'local_state':'Up', 'remote_state':'Up', 'isolate_with_peer':'Yes', 'traffic_disable':'No'}}}
    data.attributes.MCLAG_CLIENT = {"vlan_members": [data.MCLAG_CLIENT_TG1, data.MCLAG_CLIENT_MC_Lag_1, data.MCLAG_CLIENT_To_MCLAG_2_A_INTF],
                                        "port_channel": {data.MCLAG_CLIENT_MC_Lag_1: data.MCLAG_CLIENT_MC_Lag_1_Members}}

    if data.topology_2_tier:
        data.attributes.MCLAG_1_A["mc_lag_config"]["interfaces"] = [data.MCLAG_1_A_MC_Lag_1, data.MCLAG_2_A_MC_Lag_2]
        data.attributes.MCLAG_1_S["mc_lag_config"]["interfaces"] = [data.MCLAG_1_S_MC_Lag_1, data.MCLAG_2_S_MC_Lag_2]

    if data.topology_scale:
        data.MCLAG_2_A_To_MCLAG_1_A_SCALE_INTF_LIST = [vars.D1D3P3, vars.D1D3P4, vars.D1D3P5, vars.D1D3P6, vars.D1D3P7, vars.D1D3P8, vars.D1D3P9, vars.D1D3P10, vars.D1D3P11, vars.D1D3P12, vars.D1D3P13, vars.D1D3P14, vars.D1D3P15, vars.D1D3P16, vars.D1D3P17, vars.D1D3P18, vars.D1D3P19, vars.D1D3P20, vars.D1D3P21, vars.D1D3P22, vars.D1D3P23, vars.D1D3P24, vars.D1D3P25, vars.D1D3P26, vars.D1D3P27, vars.D1D3P28, vars.D1D3P29, vars.D1D3P30, vars.D1D3P31, vars.D1D3P32, vars.D1D3P33, vars.D1D3P34, vars.D1D3P35, vars.D1D3P36,vars.D1D3P37, vars.D1D3P38, vars.D1D3P39, vars.D1D3P40][0:data.topology_scale_ports_count-3]
        data.attributes.MCLAG_2_A["vlan_members"].extend(data.MCLAG_2_A_To_MCLAG_1_A_SCALE_INTF_LIST)
        data.MCLAG_2_A_Complete_Port_List.extend(data.MCLAG_2_A_To_MCLAG_1_A_SCALE_INTF_LIST)

        data.MCLAG_2_S_To_MCLAG_1_S_SCALE_INTF_LIST = [vars.D2D4P3, vars.D2D4P4, vars.D2D4P5, vars.D2D4P6, vars.D2D4P7, vars.D2D4P8, vars.D2D4P9, vars.D2D4P10, vars.D2D4P11, vars.D2D4P12, vars.D2D4P13, vars.D2D4P14, vars.D2D4P15, vars.D2D4P16, vars.D2D4P17, vars.D2D4P18, vars.D2D4P19, vars.D2D4P20, vars.D2D4P21, vars.D2D4P22, vars.D2D4P23, vars.D2D4P24, vars.D2D4P25, vars.D2D4P26, vars.D2D4P27, vars.D2D4P28, vars.D2D4P29, vars.D2D4P30, vars.D2D4P31, vars.D2D4P32, vars.D2D4P33, vars.D2D4P34, vars.D2D4P35, vars.D2D4P36, vars.D2D4P37, vars.D2D4P38, vars.D2D4P39, vars.D2D4P40][0:data.topology_scale_ports_count-3]
        data.attributes.MCLAG_2_S["vlan_members"].extend(data.MCLAG_2_S_To_MCLAG_1_S_SCALE_INTF_LIST)
        data.MCLAG_2_S_Complete_Port_List.extend(data.MCLAG_2_S_To_MCLAG_1_S_SCALE_INTF_LIST)

        data.MCLAG_1_A_To_MCLAG_2_A_SCALE_INTF_LIST = [vars.D3D1P3, vars.D3D1P4, vars.D3D1P5, vars.D3D1P6, vars.D3D1P7, vars.D3D1P8, vars.D3D1P9, vars.D3D1P10, vars.D3D1P11, vars.D3D1P12, vars.D3D1P13, vars.D3D1P14, vars.D3D1P15, vars.D3D1P16, vars.D3D1P17, vars.D3D1P18, vars.D3D1P19, vars.D3D1P20, vars.D3D1P21, vars.D3D1P22, vars.D3D1P23, vars.D3D1P24, vars.D3D1P25, vars.D3D1P26, vars.D3D1P27, vars.D3D1P28, vars.D3D1P29, vars.D3D1P30, vars.D3D1P31, vars.D3D1P32, vars.D3D1P33, vars.D3D1P34, vars.D3D1P35, vars.D3D1P36, vars.D3D1P37, vars.D3D1P38, vars.D3D1P39, vars.D3D1P40][0:data.topology_scale_ports_count-3]
        data.attributes.MCLAG_1_A["vlan_members"].extend(data.MCLAG_1_A_To_MCLAG_2_A_SCALE_INTF_LIST)
        data.MCLAG_1_A_Complete_Port_List.extend(data.MCLAG_1_A_To_MCLAG_2_A_SCALE_INTF_LIST)

        data.MCLAG_1_S_To_MCLAG_2_S_SCALE_INTF_LIST = [vars.D4D2P3, vars.D4D2P4, vars.D4D2P5, vars.D4D2P6, vars.D4D2P7, vars.D4D2P8, vars.D4D2P9, vars.D4D2P10, vars.D4D2P11, vars.D4D2P12, vars.D4D2P13, vars.D4D2P14, vars.D4D2P15, vars.D4D2P16, vars.D4D2P17, vars.D4D2P18, vars.D4D2P19, vars.D4D2P20, vars.D4D2P21, vars.D4D2P22, vars.D4D2P23, vars.D4D2P24, vars.D4D2P25, vars.D4D2P26, vars.D4D2P27, vars.D4D2P28, vars.D4D2P29, vars.D4D2P30, vars.D4D2P31, vars.D4D2P32, vars.D4D2P33, vars.D4D2P34, vars.D4D2P35, vars.D4D2P36, vars.D4D2P37, vars.D4D2P38, vars.D4D2P39, vars.D4D2P40][0:data.topology_scale_ports_count-3]
        data.attributes.MCLAG_1_S["vlan_members"].extend(data.MCLAG_1_S_To_MCLAG_2_S_SCALE_INTF_LIST)
        data.MCLAG_1_S_Complete_Port_List.extend(data.MCLAG_1_S_To_MCLAG_2_S_SCALE_INTF_LIST)

    st.set_device_alias(data.MCLAG_2_A, "MCLAG_2_A")
    st.set_device_alias(data.MCLAG_2_S, "MCLAG_2_S")
    st.set_device_alias(data.MCLAG_1_A, "MCLAG_1_A")
    st.set_device_alias(data.MCLAG_1_S, "MCLAG_1_S")
    st.set_device_alias(data.MCLAG_CLIENT, "MCLAG_CLIENT")

def tg_routing_interface_config():
    global tg_dict

    tg_dict = {"MCLAG_1_A": {"UNICAST_TRF_STR_ID_2" : "", "UNICAST_TRF_STR_ID_3" : ""}, "MCLAG_1_S": {"UNICAST_TRF_STR_ID_2" : ""}, "MCLAG_2_S": {"UNICAST_TRF_STR_ID_1" : ""}, "MCLAG_CLIENT": {"UNICAST_TRF_STR_ID_1" : "", "UNICAST_TRF_STR_ID_3" : ""}}

    tgapi.traffic_action_control(TG_HANDLER, actions=['reset'])

    vlan_cnt = data.max_vlan_instances
    vlan_step = 1
    pkt_count = vlan_cnt * 10
    pkts_per_sec = 500
    tg_wait_time = math.ceil((pkt_count*1.0)/pkts_per_sec)
    data.tg_wait_time = 3 if tg_wait_time <=3 else tg_wait_time

    # Configuring streams between MCLAG_CLIENT and MCLAG_2_S
    tg_var = TG.tg_traffic_config(port_handle=MCLAG_2_S_TG_PORT_HANDLER, port_handle2=MCLAG_CLIENT_TG_PORT_HANDLER, mode='create', transmit_mode="continuous", rate_pps=pkts_per_sec, mac_src="00:00:00:00:00:01", mac_src_mode="fixed", mac_dst="00:00:00:00:00:02", mac_dst_mode="fixed", vlan_id=data.normal_vlans[0], vlan_id_count=vlan_cnt, vlan_id_mode='increment', vlan_id_step=vlan_step, l2_encap='ethernet_ii')
    tg_dict["MCLAG_2_S"]["UNICAST_TRF_STR_ID_1"] = tg_var['stream_id']

    tg_var = TG.tg_traffic_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, port_handle2=MCLAG_2_S_TG_PORT_HANDLER, mode='create', transmit_mode="continuous", rate_pps=pkts_per_sec, mac_src="00:00:00:00:00:02", mac_src_mode="fixed", mac_dst="00:00:00:00:00:01", mac_dst_mode="fixed", vlan_id=data.normal_vlans[0], vlan_id_count=vlan_cnt, vlan_id_mode='increment', vlan_id_step=vlan_step, l2_encap='ethernet_ii')
    tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_1"] = tg_var['stream_id']

    # Configuring streams between MCLAG_1_A and MCLAG_1_S
    tg_var = TG.tg_traffic_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, port_handle2=MCLAG_1_S_TG_PORT_HANDLER, mode='create', transmit_mode="continuous", rate_pps=pkts_per_sec, mac_src="00:00:00:00:00:03", mac_src_mode="fixed", mac_dst="00:00:00:00:00:04", mac_dst_mode="fixed", vlan_id=data.normal_vlans[0], vlan_id_count=vlan_cnt, vlan_id_mode='increment', vlan_id_step=vlan_step, l2_encap='ethernet_ii')
    tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_2"] = tg_var['stream_id']

    tg_var = TG.tg_traffic_config(port_handle=MCLAG_1_S_TG_PORT_HANDLER, port_handle2=MCLAG_1_A_TG_PORT_HANDLER, mode='create', transmit_mode="continuous", rate_pps=pkts_per_sec, mac_src="00:00:00:00:00:04", mac_src_mode="fixed", mac_dst="00:00:00:00:00:03", mac_dst_mode="fixed", vlan_id=data.normal_vlans[0], vlan_id_count=vlan_cnt, vlan_id_mode='increment', vlan_id_step=vlan_step, l2_encap='ethernet_ii')
    tg_dict["MCLAG_1_S"]["UNICAST_TRF_STR_ID_2"] = tg_var['stream_id']

    # Configuring streams between MCLAG_1_A and MCLAG_CLIENT
    tg_var = TG.tg_traffic_config(port_handle=MCLAG_1_A_TG_PORT_HANDLER, port_handle2=MCLAG_CLIENT_TG_PORT_HANDLER, mode='create', transmit_mode="continuous", rate_pps=pkts_per_sec, mac_src="00:00:00:00:00:05", mac_src_mode="fixed", mac_dst="00:00:00:00:00:06", mac_dst_mode="fixed", vlan_id=data.normal_vlans[0], vlan_id_count=vlan_cnt, vlan_id_mode='increment', vlan_id_step=vlan_step, l2_encap='ethernet_ii')
    tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_3"] = tg_var['stream_id']

    tg_var = TG.tg_traffic_config(port_handle=MCLAG_CLIENT_TG_PORT_HANDLER, port_handle2=MCLAG_1_A_TG_PORT_HANDLER, mode='create', transmit_mode="continuous", rate_pps=pkts_per_sec, mac_src="00:00:00:00:00:06", mac_src_mode="fixed", mac_dst="00:00:00:00:00:05", mac_dst_mode="fixed", vlan_id=data.normal_vlans[0], vlan_id_count=vlan_cnt, vlan_id_mode='increment', vlan_id_step=vlan_step, l2_encap='ethernet_ii')
    tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_3"] = tg_var['stream_id']

    # Disable all streams
    TG.tg_traffic_config(mode='disable', stream_id=tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_3"])
    TG.tg_traffic_config(mode='disable', stream_id=tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_3"])

    utils.banner_log("TG Streams Data : {}".format(tg_dict))

def tg_routing_interface_unconfig():
    tgapi.traffic_action_control(TG_HANDLER, actions=['reset'])

def verify_traffic_send_and_receive(type, traffic_exp="forward"):
    if type == "North_To_South_Traffic":
        ph1 = data.vars.T1D2P1
        sh1 = tg_dict["MCLAG_2_S"]["UNICAST_TRF_STR_ID_1"]
        ph2 = data.vars.T1D5P1
        sh2 = tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_1"]
    elif type == "East_To_West_Traffic":
        ph1 = data.vars.T1D3P1
        sh1 = tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_2"]
        ph2 = data.vars.T1D4P1
        sh2 = tg_dict["MCLAG_1_S"]["UNICAST_TRF_STR_ID_2"]
    elif type == "MCLAG_Peer_To_Client":
        ph1 = data.vars.T1D3P1
        sh1 = tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_3"]
        ph2 = data.vars.T1D5P1
        sh2 = tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_3"]
        # Enable required streams and disable not required streams
        st.log("Enabling MCLAG traffic streams on MCLAG_1_A and MCLAG_CLIENT")
        TG.tg_traffic_config(mode='enable', stream_id=tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_3"])
        TG.tg_traffic_config(mode='enable', stream_id=tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_3"])
        TG.tg_traffic_config(mode='disable', stream_id=tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_2"])
        TG.tg_traffic_config(mode='disable', stream_id=tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_1"])

    st.log("Clearing stats before sending traffic ...")
    [_, exceptions] = exec_parallel(True, data.dut_list, intf.clear_interface_counters, [{'cli_type': "click"}] * 5)
    ensure_no_exception(exceptions)

    tgapi.traffic_action_control(TG_HANDLER, actions=['clear_stats'])
    st.wait(5)
    TG.tg_traffic_control(action='run', stream_handle=[sh1, sh2], get='vlan_id')
    st.wait(data.tg_wait_time)
    TG.tg_traffic_control(action='stop', stream_handle=[sh1, sh2])
    st.wait(5)

    if type == "MCLAG_Peer_To_Client":
        # Enable required streams and disable not required streams
        st.log("Disabling MCLAG traffic streams on MCLAG_1_A and MCLAG_CLIENT")
        TG.tg_traffic_config(mode='disable', stream_id=tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_3"])
        TG.tg_traffic_config(mode='disable', stream_id=tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_3"])
        TG.tg_traffic_config(mode='enable', stream_id=tg_dict["MCLAG_1_A"]["UNICAST_TRF_STR_ID_2"])
        TG.tg_traffic_config(mode='enable', stream_id=tg_dict["MCLAG_CLIENT"]["UNICAST_TRF_STR_ID_1"])

    traffic_details = {
        '1': {
            'tx_ports': [ph1],
            'tx_obj': [TG],
            'exp_ratio': [1],
            'rx_ports': [ph2],
            'rx_obj': [TG],
            'stream_list': [[sh1]],
        },
        '2': {
            'tx_ports': [ph2],
            'tx_obj': [TG],
            'exp_ratio': [1],
            'rx_ports': [ph1],
            'rx_obj': [TG],
            'stream_list': [[sh2]],
        },
    }

    # verify traffic mode stream level
    streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')

    st.log("Fetching unicast stats and comparing...")
    if traffic_exp == "forward" and not streamResult:
        if not data.topology_scale:
            st.log("As overall traffic failed - checking vlan level traffic stats")
            for vlan_id in [data.normal_vlans[0], data.normal_vlans[1], data.normal_vlans[2]]:
                traffic_details = {
                    '1': {
                        'tx_ports': [ph1],
                        'tx_obj': [TG],
                        'exp_ratio': [0.333],
                        'rx_ports': [ph2],
                        'rx_obj': [TG],
                        'stream_list': [[sh1]],
                        'filter_param': [['vlan']],
                        'filter_val': [[str(vlan_id)]],
                    },
                    '2': {
                        'tx_ports': [ph2],
                        'tx_obj': [TG],
                        'exp_ratio': [0.333],
                        'rx_ports': [ph1],
                        'rx_obj': [TG],
                        'stream_list': [[sh2]],
                        'filter_param': [['vlan']],
                        'filter_val': [[str(vlan_id)]],
                    },
                }
                # Verify traffic mode stream level with vlan filter
                tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='filter', comp_type='packet_count')
        log_error("Traffic verification (forward) for unicast failed ...")
    elif traffic_exp != "forward" and streamResult:
        log_error("Traffic verification (drop) for unicast failed ...")
    return True

def verify_fdb_sync(dut1, dut2, port1, port2):
    output1 = mac.get_mac(dut1)
    mac_addr_1 = []
    for entry in filter_and_select(output1, ["vlan", "macaddress", "port"], {'vlan': str(data.normal_vlans[0]), "port": port1}):
        mac_addr_1.append([entry["vlan"], entry["macaddress"], entry["port"]])
    for entry in filter_and_select(output1, ["vlan", "macaddress", "port"], {'vlan': str(data.normal_vlans[1]), "port": port1}):
        mac_addr_1.append([entry["vlan"], entry["macaddress"], entry["port"]])
    for entry in filter_and_select(output1, ["vlan", "macaddress", "port"], {'vlan': str(data.normal_vlans[2]), "port": port1}):
        mac_addr_1.append([entry["vlan"], entry["macaddress"], entry["port"]])
    mac_addr_1.sort()

    output2 = mac.get_mac(dut2)
    mac_addr_2 = []
    for entry in filter_and_select(output2, ["vlan", "macaddress", "port"], {'vlan': str(data.normal_vlans[0]), "port": port2}):
        mac_addr_2.append([entry["vlan"], entry["macaddress"], entry["port"]])
    for entry in filter_and_select(output2, ["vlan", "macaddress", "port"], {'vlan': str(data.normal_vlans[1]), "port": port2}):
        mac_addr_2.append([entry["vlan"], entry["macaddress"], entry["port"]])
    for entry in filter_and_select(output2, ["vlan", "macaddress", "port"], {'vlan': str(data.normal_vlans[2]), "port": port2}):
        mac_addr_2.append([entry["vlan"], entry["macaddress"], entry["port"]])
    mac_addr_1.sort()

    st.log("Mac addresses on {} : {}".format(dut1, mac_addr_1))
    st.log("Mac addresses on {} : {}".format(dut2, mac_addr_2))

    if mac_addr_1 == mac_addr_2:
        return True
    else:
        return False

def check_mclag_peers_stp_roles():
    res = True
    stp_roles_dict = {True : "ROOT", False : "DESIGNATED"}
    for vlan in data.normal_vlans[0:3]:
        if data.topology_2_tier:
            stp_state_MCLAG_2_A = stp.check_dut_is_root_bridge_for_vlan(data.MCLAG_2_A, vlan)
            stp_state_MCLAG_2_S = stp.check_dut_is_root_bridge_for_vlan(data.MCLAG_2_S, vlan)
            stp_state_MCLAG_1_A = stp.check_dut_is_root_bridge_for_vlan(data.MCLAG_1_A, vlan)
            stp_state_MCLAG_1_S = stp.check_dut_is_root_bridge_for_vlan(data.MCLAG_1_S, vlan)
            st.log("VLAN : {}, STP ROLES : MCLAG_1_A - {}, MCLAG_1_S - {}, MCLAG_2_A - {}, MCLAG_2_S - {}".format(vlan, stp_roles_dict[stp_state_MCLAG_1_A], stp_roles_dict[stp_state_MCLAG_1_S], stp_roles_dict[stp_state_MCLAG_2_A], stp_roles_dict[stp_state_MCLAG_2_S]))
            if (stp_state_MCLAG_2_A != stp_state_MCLAG_2_S) or (stp_state_MCLAG_1_A != stp_state_MCLAG_1_S):
                res = False
        else:
            stp_state_MCLAG_1_A = stp.check_dut_is_root_bridge_for_vlan(data.MCLAG_1_A, vlan)
            stp_state_MCLAG_1_S = stp.check_dut_is_root_bridge_for_vlan(data.MCLAG_1_S, vlan)
            st.log("VLAN : {}, STP ROLES : MCLAG_1_A - {}, MCLAG_1_S - {}".format(vlan, stp_roles_dict[stp_state_MCLAG_1_A], stp_roles_dict[stp_state_MCLAG_1_S]))
            if stp_state_MCLAG_1_A != stp_state_MCLAG_1_S:
                res = False
    return res

def check_for_stp_convergence(root_intf_check=True, root_to_exclude_intf_dict={}):
    res = True
    utils.banner_log("Checking for STP convergence : ROOT BRIDGE BASED ON CONFIGURED BRIDGE PRIORITY")
    data.dut_to_vlan_dict = {}
    data.dut_to_intf_dict = {}
    if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
        for dut, dut_data in data.stp_data.items():
            data.dut_to_vlan_dict[dut] = dut_data["vlan"]
            data.dut_to_intf_dict[dut] = dut_data["intf_list"]
            if stp.poll_for_root_switch(dut, dut_data["vlan"], iteration=10, delay=4):
                st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut, dut_data["vlan"]))
            else:
                log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(dut, dut_data["vlan"]))
                res = False
    else:
        if stp.poll_for_root_switch(data.MCLAG_1_A, data.normal_vlans[0], iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(data.MCLAG_1_A, data.normal_vlans[0]))
        else:
            log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(data.MCLAG_1_A, data.normal_vlans[0]))
            res = False
        if stp.poll_for_root_switch(data.MCLAG_1_S, data.normal_vlans[0], iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(data.MCLAG_1_S, data.normal_vlans[0]))
        else:
            log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(data.MCLAG_1_S, data.normal_vlans[0]))
            res = False
        if stp.poll_for_root_switch(data.MCLAG_1_A, data.normal_vlans[1], iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(data.MCLAG_1_A, data.normal_vlans[1]))
        else:
            log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(data.MCLAG_1_A, data.normal_vlans[1]))
            res = False
        if stp.poll_for_root_switch(data.MCLAG_1_S, data.normal_vlans[1], iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(data.MCLAG_1_S, data.normal_vlans[1]))
        else:
            log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(data.MCLAG_1_S, data.normal_vlans[1]))
            res = False
        if stp.poll_for_root_switch(data.MCLAG_1_A, data.normal_vlans[2], iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(data.MCLAG_1_A, data.normal_vlans[2]))
        else:
            log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(data.MCLAG_1_A, data.normal_vlans[2]))
            res = False
        if stp.poll_for_root_switch(data.MCLAG_1_S, data.normal_vlans[2], iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(data.MCLAG_1_S, data.normal_vlans[2]))
        else:
            log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(data.MCLAG_1_S, data.normal_vlans[2]))
            res = False

    if res:
        st.log("ROOT BRIDGE BASED ON CONFIGURED BRIDGE PRIORITY : PASSED")
    else:
        log_error("ROOT BRIDGE BASED ON CONFIGURED BRIDGE PRIORITY : FAILED")

    if root_intf_check:
        utils.banner_log("Checking for STP convergence : ROOT BRIDGE INTERFACE STATE VERIFICATION ")
        if len(root_to_exclude_intf_dict):
            if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
                dut_to_intf_dict = {k:v for k,v in data.dut_to_intf_dict.items()}
                intf_list = []
                for elem in data.dut_to_intf_dict[root_to_exclude_intf_dict['dut']]:
                    if elem not in root_to_exclude_intf_dict['intf_list']:
                        intf_list.append(elem)

                dut_to_intf_dict[root_to_exclude_intf_dict['dut']] = intf_list
                st.log("data.dut_to_vlan_dict : {}".format(data.dut_to_vlan_dict))
                st.log("data.dut_to_intf_dict : {}".format(data.dut_to_intf_dict))
                st.log("dut_to_intf_dict : {}".format(dut_to_intf_dict))
                if not stp.poll_root_bridge_interfaces(data.dut_to_vlan_dict, dut_to_intf_dict):
                    log_error("ROOT BRIDGE INTERFACE STATE VERIFICATION : FAILED")
                    res = False
                else:
                    st.log("ROOT BRIDGE INTERFACE STATE VERIFICATION : PASSED")
            else:
                if not stp.poll_root_bridge_interfaces({data.MCLAG_1_A: data.normal_vlans[0]}, {data.MCLAG_1_A: data.MCLAG_1_A_Complete_Port_List_1}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_S: data.normal_vlans[0]}, {data.MCLAG_1_S: data.MCLAG_1_S_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_A: data.normal_vlans[1]}, {data.MCLAG_1_A: data.MCLAG_1_A_Complete_Port_List_1}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_S: data.normal_vlans[1]}, {data.MCLAG_1_S: data.MCLAG_1_S_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_A: data.normal_vlans[2]}, {data.MCLAG_1_A: data.MCLAG_1_A_Complete_Port_List_1}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_S: data.normal_vlans[2]}, {data.MCLAG_1_S: data.MCLAG_1_S_Complete_Port_List}):
                    log_error("ROOT BRIDGE INTERFACE STATE VERIFICATION : FAILED")
                    res = False
                else:
                    st.log("ROOT BRIDGE INTERFACE STATE VERIFICATION : PASSED")
        else:
            if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
                st.log("data.dut_to_vlan_dict : {}".format(data.dut_to_vlan_dict))
                st.log("data.dut_to_intf_dict : {}".format(data.dut_to_intf_dict))
                if not stp.poll_root_bridge_interfaces(data.dut_to_vlan_dict, data.dut_to_intf_dict):
                    log_error("ROOT BRIDGE INTERFACE STATE VERIFICATION : FAILED")
                    res = False
                else:
                    st.log("ROOT BRIDGE INTERFACE STATE VERIFICATION : PASSED")
            else:
                if not stp.poll_root_bridge_interfaces({data.MCLAG_1_A: data.normal_vlans[0]}, {data.MCLAG_1_A: data.MCLAG_1_A_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_S: data.normal_vlans[0]}, {data.MCLAG_1_S: data.MCLAG_1_S_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_A: data.normal_vlans[1]}, {data.MCLAG_1_A: data.MCLAG_1_A_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_S: data.normal_vlans[1]}, {data.MCLAG_1_S: data.MCLAG_1_S_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_A: data.normal_vlans[2]}, {data.MCLAG_1_A: data.MCLAG_1_A_Complete_Port_List}) or not stp.poll_root_bridge_interfaces({data.MCLAG_1_S: data.normal_vlans[2]}, {data.MCLAG_1_S: data.MCLAG_1_S_Complete_Port_List}):
                    log_error("ROOT BRIDGE INTERFACE STATE VERIFICATION : FAILED")
                    res = False
                else:
                    st.log("ROOT BRIDGE INTERFACE STATE VERIFICATION : PASSED")

    utils.banner_log("Checking for STP convergence : MCLAG PEERS STP ROLES")
    if not check_mclag_peers_stp_roles():
        log_error("MCLAG PEERS STP ROLES : FAILED")
        res = False
    else:
        st.log("MCLAG PEERS STP ROLES : PASSED")
    return res

def verify_mclag_data():
    res = True
    utils.banner_log("Checking for MCLAG configurtion status")
    for _ in range(10):
        if data.topology_2_tier:
            [result, exceptions] = exec_parallel(True, data.mclag_duts, mclag.verify_domain, data.mclag_verify_data)
        else:
            [result, exceptions] = exec_parallel(True, data.mclag_duts_domain_1, mclag.verify_domain, data.mclag_verify_data_domain_1)
        ensure_no_exception(exceptions)
        if False not in result:
            break
        st.wait(1)

    if False in result:
        log_error("MCLAG STATE VERIFICATION : FAILED")
        res = False
    else:
        st.log("MCLAG STATE VERIFICATION : PASSED")

    utils.banner_log("Checking for MCLAG interface configurtion status")
    for _ in range(10):
        if data.topology_2_tier:
            [result, exceptions] = exec_parallel(True, data.mclag_duts, mclag.verify_interfaces, data.mclag_verify_intf_data)
        else:
            [result, exceptions] = exec_parallel(True, data.mclag_duts_domain_1, mclag.verify_interfaces, data.mclag_verify_intf_data_domain_1)
        ensure_no_exception(exceptions)
        if False not in result:
            break
        st.wait(1)

    if False in result:
        log_error("MCLAG INTF VERIFICATION : FAILED")
        res = False
    else:
        st.log("MCLAG INTF VERIFICATION : PASSED")
    return res

def check_traffic(type="both", traffic_exp="forward", fdb_sync_check=True):
    res = True
    if type == "both":
        utils.banner_log("Sending and verifying traffic: {} between {} and {}".format('North_To_South_Traffic', "MCLAG_2_S", "MCLAG_CLIENT"))
        if verify_traffic_send_and_receive('North_To_South_Traffic', traffic_exp):
            st.log("North_To_South_Traffic : PASSED")
        else:
            log_error("North_To_South_Traffic : FAILED")
            res = False

        utils.banner_log("Sending and verifying traffic: {} between {} and {}".format('East_To_West_Traffic', "MCLAG_1_A", "MCLAG_1_S"))
        if verify_traffic_send_and_receive('East_To_West_Traffic', traffic_exp):
            st.log("East_To_West_Traffic : PASSED")
        else:
            log_error("East_To_West_Traffic : FAILED")
            res = False
    elif type == "North_To_South_Traffic":
        utils.banner_log("Sending and verifying traffic: {} between {} and {}".format('North_To_South_Traffic', "MCLAG_2_S", "MCLAG_CLIENT"))
        if verify_traffic_send_and_receive('North_To_South_Traffic', traffic_exp):
            st.log("North_To_South_Traffic : PASSED")
        else:
            log_error("North_To_South_Traffic : FAILED")
            res = False
    elif type == "East_To_West_Traffic":
        utils.banner_log("Sending and verifying traffic: {} between {} and {}".format('East_To_West_Traffic', "MCLAG_1_A", "MCLAG_1_S"))
        if verify_traffic_send_and_receive('East_To_West_Traffic', traffic_exp):
            st.log("East_To_West_Traffic : PASSED")
        else:
            log_error("East_To_West_Traffic : FAILED")
            res = False

    if fdb_sync_check:
        if not data.topology_scale:
            if data.topology_2_tier:
                utils.banner_log("Checking FDB sync between MCLAG peers {} and {} on interfaces {},{} and {},{} respectively after sending traffic".format("MCLAG_1_A, MCLAG_1_S", "MCLAG_2_A, MCLAG_2_S", data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_S_MC_Lag_1, data.MCLAG_2_A_MC_Lag_2, data.MCLAG_2_S_MC_Lag_2))
                if verify_fdb_sync(data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_S_MC_Lag_1):
                    st.log("FDB SYNC BETWEEN MCLAG PEERS (MCLAG_1_A, MCLAG_1_S) : PASSED")
                else:
                    log_error("FDB SYNC BETWEEN MCLAG PEERS (MCLAG_1_A, MCLAG_1_S) : FAILED")
                    res = False

                if verify_fdb_sync(data.MCLAG_2_A, data.MCLAG_2_S, data.MCLAG_2_A_MC_Lag_2, data.MCLAG_2_S_MC_Lag_2):
                    st.log("FDB SYNC BETWEEN MCLAG PEERS (MCLAG_2_A, MCLAG_2_S) : PASSED")
                else:
                    log_error("FDB SYNC BETWEEN MCLAG PEERS (MCLAG_2_A, MCLAG_2_S) : FAILED")
                    res = False
            else:
                utils.banner_log("Checking FDB sync between MCLAG peers {} and {} on interfaces {},{} respectively after sending traffic".format("MCLAG_1_A", "MCLAG_1_S", data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_S_MC_Lag_1))
                if verify_fdb_sync(data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_S_MC_Lag_1):
                    st.log("FDB SYNC BETWEEN MCLAG PEERS (MCLAG_1_A, MCLAG_1_S) : PASSED")
                else:
                    log_error("FDB SYNC BETWEEN MCLAG PEERS (MCLAG_1_A, MCLAG_1_S) : FAILED")
                    res = False
    return res

def check_stable_state(stp=True, mclag=True, traffic=True, checkType="afterTrigger"):
    res_1, res_2, res_3 = True, True, True

    # Checking for setup stable state.
    utils.banner_log("Checking for setup stable state.")
    if checkType == "testStart":
        flag = data.stable_state_check_at_test_start
    elif checkType == "afterTrigger":
        flag = True

    st.log("checkType : {}".format(checkType))
    st.log("data.stable_state_check_at_test_start : {}".format(data.stable_state_check_at_test_start))
    st.log("flag : {}".format(flag))

    if flag:
        if mclag:
            res_2 = verify_mclag_data()

        if stp:
            res_1 = check_for_stp_convergence()

        if traffic:
            res_3 = check_traffic()

    if res_1 and res_2 and res_3:
        st.log("SETUP STABLE STATE CHECK : PASSED")
        return True
    else:
        log_error("SETUP STABLE STATE CHECK : FAILED")
        return False

def update_log_error_flag(flagVal):
    data.logErrorFlag = flagVal

def check_setup_status():
    if data.stable_state_check_at_test_start:
        wait_flag = False

        # Checking for setup stable state before moving to next test case
        utils.banner_log("Checking for setup stable state and bringing the setup back to stable state before moving to next test case -- STARTED")
        if not check_stable_state(stp=True, mclag=True, traffic=False):
            intf.interface_operation(data.MCLAG_1_A, [data.MCLAG_1_A_TG1, data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag], "startup")
            intf.interface_operation(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1 , "startup")

            utils.banner_log("UNCONFIG AND CONFIG OF MCLAG AND STP  -- STARTED")
            module_unconfig(data.stp_protocol, xstp=True, mlag=True, vlans_portchannel=False, tgen=False)
            module_config({}, data.stp_protocol, data.topology_2_tier, data.topology_scale, initconf=False, xstp=True, mlag=True, vlans_portchannel=False, tgen=False)
            utils.banner_log("UNCONFIG AND CONFIG OF MCLAG AND STP -- COMPLETED")
            wait_flag = True
        utils.banner_log("Checking for setup stable state and bringing the setup back to stable state before moving to next test case -- COMPLETED")

        if wait_flag:
            # Wait time for MCLAG to become stable.
            st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

            # Wait time for stp to converge
            st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

def log_error(message):
    st.error(message)
    data.stable_state_check_at_test_start = True
    if data.logErrorFlag:
        if not data.topology_scale:
            utils.banner_log("DISPLAYING STP INFO ON ALL DUTS..")
            stp.show_stp_in_parallel(data.dut_list, True)
            utils.banner_log("DISPLAYING MAC INFO ON ALL DUTS..")
            dut_li = utils.make_list(data.dut_list)
            exec_foreach(False, dut_li, mac.get_mac)
        st.report_fail('test_case_failure_message', message)

def module_config(vars, stp_protocol, topology_2_tier, topology_scale=False, initconf=True, xstp=True, mlag=True, vlans_portchannel=True, tgen=True):
    if initconf:
        init_mclag_global_variables(vars, topology_2_tier, stp_protocol, topology_scale)
        print_topology(vars)

        # Creating vlan and port channel data to be used for configuring in the topology
        utils.banner_log("Creating vlan and port channel data to be used for configuring in the topology")
        data.vlan_data = dict()
        portchannel_data = dict()
        data.mclag_domain = list()
        data.mclag_domain_1 = list()
        data.mclag_domain_2 = list()
        data.mclag_domain_del = list()
        data.mclag_domain_del_1 = list()
        data.mclag_domain_del_2 = list()
        data.mclag_duts = list()
        data.mclag_duts_domain_1 = list()
        data.mclag_duts_domain_2 = list()
        data.mclag_interfaces = list()
        data.mclag_interfaces_1 = list()
        data.mclag_interfaces_2 = list()
        data.mclag_interfaces_del = list()
        data.mclag_interfaces_del_1 = list()
        data.mclag_interfaces_del_2 = list()
        data.mclag_verify_data = list()
        data.mclag_verify_data_domain_1 = list()
        data.mclag_verify_data_domain_2 = list()
        data.mclag_verify_intf_data = list()
        data.mclag_verify_intf_data_domain_1 = list()
        data.mclag_verify_intf_data_domain_2 = list()

        for key, value in data.attributes.items():
            data.mclag_duts.append(data[key])
            if value.get("port_channel"):
                if data.topology_2_tier:
                    portchannel_data[data[key]] = value.get("port_channel")
                else:
                    temp = dict()
                    temp = value.get("port_channel")
                    if key  == "MCLAG_2_A":
                        temp.pop(data.MCLAG_2_A_MC_Lag_2, None)
                    elif key  == "MCLAG_2_S":
                        temp.pop(data.MCLAG_2_S_MC_Lag_2, None)
                    elif key  == "MCLAG_1_A":
                        temp.pop(data.MCLAG_1_A_MC_Lag_2, None)
                    elif key  == "MCLAG_1_S":
                        temp.pop(data.MCLAG_1_S_MC_Lag_2, None)
                    portchannel_data[data[key]] = temp

            data.vlan_data[data[key]] = dict()
            if value.get("vlan_members"):
                data.vlan_data[data[key]]["normal_vlan"] = dict()
                data.vlan_data[data[key]]["normal_vlan"]["vlans"] = data.normal_vlans
                if data.topology_2_tier:
                    data.vlan_data[data[key]]["normal_vlan"]["members"] = value.get("vlan_members")
                else:
                    temp1 = []
                    temp1 = value.get("vlan_members")
                    if key  == "MCLAG_2_A":
                        temp1.remove(data.MCLAG_2_A_MC_Lag_2)
                    elif key  == "MCLAG_2_S":
                        temp1.remove(data.MCLAG_2_S_MC_Lag_2)
                    elif key  == "MCLAG_1_A":
                        temp1.remove(data.MCLAG_1_A_MC_Lag_2)
                    elif key  == "MCLAG_1_S":
                        temp1.remove(data.MCLAG_1_S_MC_Lag_2)
                    data.vlan_data[data[key]]["normal_vlan"]["members"] = temp1

            if value.get("peer_links"):
                if data.keep_alive_link_vlan_intf:
                    data.vlan_data[data[key]]["peer_vlan"] = dict()
                    tempStr = str(key) + "_PEERLINK_VLAN"
                    data.vlan_data[data[key]]["peer_vlan"]["vlans"] = data[tempStr]
                    data.vlan_data[data[key]]["peer_vlan"]["members"] = value.get("peer_links")

            if value.get("mc_lag_config"):
                mc_lag_config = value.get("mc_lag_config")
                data.mclag_interfaces.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='add'))
                data.mclag_interfaces_del.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='del'))
                if mc_lag_config["domain_id"] == data.MCLAG_1_DOMAIN_ID:
                    data.mclag_interfaces_1.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='add'))
                    data.mclag_interfaces_del_1.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='del'))
                elif mc_lag_config["domain_id"] == data.MCLAG_2_DOMAIN_ID:
                    data.mclag_interfaces_2.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='add'))
                    data.mclag_interfaces_del_2.append(ExecAllFunc(mclag.config_interfaces, data[key], mc_lag_config["domain_id"], mc_lag_config["interfaces"], config='del'))

                data.mclag_domain.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'add', 'domain_id': mc_lag_config["domain_id"]})
                data.mclag_domain_del.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'del', 'domain_id': mc_lag_config["domain_id"]})
                if mc_lag_config["domain_id"] == data.MCLAG_1_DOMAIN_ID:
                    data.mclag_domain_1.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'add', 'domain_id': mc_lag_config["domain_id"]})
                    data.mclag_domain_del_1.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'del', 'domain_id': mc_lag_config["domain_id"]})
                elif mc_lag_config["domain_id"] == data.MCLAG_2_DOMAIN_ID:
                    data.mclag_domain_2.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'add', 'domain_id': mc_lag_config["domain_id"]})
                    data.mclag_domain_del_2.append({'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_interface': mc_lag_config['peer_interface'], 'config': 'del', 'domain_id': mc_lag_config["domain_id"]})

                mclag_verify_dict = {'domain_id': mc_lag_config["domain_id"], 'local_ip': mc_lag_config['local_ip'], 'peer_ip': mc_lag_config['peer_ip'], 'peer_link_inf': mc_lag_config['peer_interface'], 'mclag_intfs': len(mc_lag_config['interfaces']), 'session_status': mc_lag_config['session_status'], 'node_role': mc_lag_config['node_role']}
                data.mclag_verify_data.append(mclag_verify_dict)
                if mc_lag_config["domain_id"] == data.MCLAG_1_DOMAIN_ID:
                    data.mclag_duts_domain_1.append(data[key])
                    data.mclag_verify_data_domain_1.append(mclag_verify_dict)
                elif mc_lag_config["domain_id"] == data.MCLAG_2_DOMAIN_ID:
                    data.mclag_duts_domain_2.append(data[key])
                    data.mclag_verify_data_domain_2.append(mclag_verify_dict)

            if value.get("mc_lag_intf_data"):
                mclag_intf_data = value.get("mc_lag_intf_data")
                mclag_verify_intf_dict = {'domain_id': mclag_intf_data["domain_id"]}
                for key, value in mclag_intf_data.items():
                    if key != "domain_id":
                        mclag_verify_intf_dict.update({'mclag_intf': key, 'mclag_intf_local_state': value['local_state'], 'mclag_intf_peer_state': value['remote_state'], 'isolate_peer_link': value['isolate_with_peer'], 'traffic_disable': value['traffic_disable']})
                data.mclag_verify_intf_data.append(mclag_verify_intf_dict)
                if mclag_intf_data["domain_id"] == data.MCLAG_1_DOMAIN_ID:
                    data.mclag_verify_intf_data_domain_1.append(mclag_verify_intf_dict)
                elif mclag_intf_data["domain_id"] == data.MCLAG_2_DOMAIN_ID:
                    data.mclag_verify_intf_data_domain_2.append(mclag_verify_intf_dict)

        utils.banner_log("MODULE VARIABLES DATA")
        st.log("VLANS USED : vlan_list : {}, normal_vlans : {}, peer_link_vlans : {}".format(data.vlan_list, data.normal_vlans, data.peer_link_vlans))
        st.log("PORTCHANNEL DATA : {}".format(portchannel_data))
        st.log("VLAN DATA : {}".format(data.vlan_data))
        st.log("MCLAG DUTS : {}".format(data.mclag_duts))
        st.log("MCLAG DUTS DOMAIN 1 : {}".format(data.mclag_duts_domain_1))
        st.log("MCLAG DUTS DOMAIN 2 : {}".format(data.mclag_duts_domain_2))
        st.log("MCLAG DOMAINS : {}".format(data.mclag_domain))
        st.log("MCLAG DOMAINS 1: {}".format(data.mclag_domain_1))
        st.log("MCLAG DOMAINS 2: {}".format(data.mclag_domain_2))
        st.log("MCLAG DOMAINS DEL: {}".format(data.mclag_domain_del))
        st.log("MCLAG DOMAINS DEL 1: {}".format(data.mclag_domain_del_1))
        st.log("MCLAG DOMAINS DEL 2: {}".format(data.mclag_domain_del_2))
        st.log("MCLAG INTERFACES : {}".format(data.mclag_interfaces))
        st.log("MCLAG INTERFACES 1: {}".format(data.mclag_interfaces_1))
        st.log("MCLAG INTERFACES 2: {}".format(data.mclag_interfaces_2))
        st.log("MCLAG INTERFACES DEL: {}".format(data.mclag_interfaces_del))
        st.log("MCLAG INTERFACES DEL 1: {}".format(data.mclag_interfaces_del_1))
        st.log("MCLAG INTERFACES DEL 2: {}".format(data.mclag_interfaces_del_2))
        st.log("MCLAG DATA : {}".format(data.mclag_verify_data))
        st.log("MCLAG DATA DOMAIN 1: {}".format(data.mclag_verify_data_domain_1))
        st.log("MCLAG DATA DOMAIN 2: {}".format(data.mclag_verify_data_domain_2))
        st.log("MCLAG INTF DATA : {}".format(data.mclag_verify_intf_data))
        st.log("MCLAG INTF DATA DOMAIN 1: {}".format(data.mclag_verify_intf_data_domain_1))
        st.log("MCLAG INTF DATA DOMAIN 2: {}".format(data.mclag_verify_intf_data_domain_2))

        # Clearing of all existing vlans and port channels on all the DUTs
        utils.banner_log("Clearing of all existing vlans and port channels on all the DUTs")
        vapi.clear_vlan_configuration(data.dut_list)
        portchannel.clear_portchannel_configuration(data.dut_list)

        # Clearing logs on all DUTs
        command_list = [[slog.clear_logging, data.MCLAG_1_A], [slog.clear_logging, data.MCLAG_1_S],
                        [slog.clear_logging, data.MCLAG_2_A], [slog.clear_logging, data.MCLAG_2_S],
                        [slog.clear_logging, data.MCLAG_CLIENT]]
        [_, exceptions] = exec_all(True, command_list)
        ensure_no_exception(exceptions)

    if xstp:
        # Configuring of STP on all the DUTs
        utils.banner_log("Configuring STP on all the DUTs")
        stp.config_stp_in_parallel(data.dut_list, feature=data.stp_protocol, mode="enable")

        utils.banner_log("Configuring global STP parameters on all DUTs")
        if data.topology_scale:
            stp.config_stp_parameters(data.MCLAG_1_A, priority=0)
            stp.config_stp_parameters(data.MCLAG_1_S, priority=0)

    if vlans_portchannel:
        # Configuring port channels on all the DUTs
        utils.banner_log("Configuring port channels on all the DUTs")
        [_, exceptions] = exec_foreach(True, data.dut_list, portchannel.config_multiple_portchannels, portchannel_data)
        ensure_no_exception(exceptions)

    if mlag:
        # Configuring ip address on peer links
        utils.banner_log("Configuring Ip address on peer links")
        api_list = list()
        if data.keep_alive_link_vlan_intf:
            if data.topology_2_tier:
                api_list.append([ip.config_ip_addr_interface, data.MCLAG_2_A, 'Vlan' + str(data.MCLAG_2_A_PEERLINK_VLAN), data.MCLAG_2_A_LOCAL_IP, data.mask])
                api_list.append([ip.config_ip_addr_interface, data.MCLAG_2_S, 'Vlan' + str(data.MCLAG_2_S_PEERLINK_VLAN), data.MCLAG_2_S_LOCAL_IP, data.mask])
            api_list.append([ip.config_ip_addr_interface, data.MCLAG_1_A, 'Vlan' + str(data.MCLAG_1_A_PEERLINK_VLAN), data.MCLAG_1_A_LOCAL_IP, data.mask])
            api_list.append([ip.config_ip_addr_interface, data.MCLAG_1_S, 'Vlan' + str(data.MCLAG_1_S_PEERLINK_VLAN), data.MCLAG_1_S_LOCAL_IP, data.mask])
        else:
            if data.topology_2_tier:
                api_list.append([ip.config_ip_addr_interface, data.MCLAG_2_A, data.MCLAG_2_A_To_MCLAG_2_S_Keep_Alive_Link, data.MCLAG_2_A_LOCAL_IP, data.mask])
                api_list.append([ip.config_ip_addr_interface, data.MCLAG_2_S, data.MCLAG_2_S_To_MCLAG_2_A_Keep_Alive_Link, data.MCLAG_2_S_LOCAL_IP, data.mask])
            api_list.append([ip.config_ip_addr_interface, data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A_LOCAL_IP, data.mask])
            api_list.append([ip.config_ip_addr_interface, data.MCLAG_1_S, data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link, data.MCLAG_1_S_LOCAL_IP, data.mask])
        [_, exceptions] = exec_all(True, api_list)
        ensure_no_exception(exceptions)

        # Configuring MCLAG domain on the MCLAG peers
        utils.banner_log("Configuring MCLAG domain on the MLCLAG peers")
        if data.topology_2_tier:
            [_, exceptions] = exec_parallel(True, data.mclag_duts, mclag.config_domain, data.mclag_domain)
            ensure_no_exception(exceptions)
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_2_A, data.MCLAG_2_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "add"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)
        else:
            [_, exceptions] = exec_parallel(True, data.mclag_duts_domain_1, mclag.config_domain, data.mclag_domain_1)
            ensure_no_exception(exceptions)
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)

        # Configuring MCLAG interfaces for all the domains
        utils.banner_log("Configuring MCLAG interfaces for all the domains")
        if data.topology_2_tier:
            [_, exceptions] = exec_all(True, data.mclag_interfaces)
        else:
            [_, exceptions] = exec_all(True, data.mclag_interfaces_1)
        ensure_no_exception(exceptions)

    if vlans_portchannel:
        # Configuring vlans on all the DUTs
        utils.banner_log("Configuring vlans on all the DUTs")
        if not data.topology_scale:
            [_, exceptions] = exec_foreach(True, data.dut_list, vapi.create_multiple_vlans_and_members, data.vlan_data)
            ensure_no_exception(exceptions)
        else:
            command_list = [[vapi.config_vlan_range, data.MCLAG_1_A, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), 'add'],
                            [vapi.config_vlan_range, data.MCLAG_1_S, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), 'add'],
                            [vapi.config_vlan_range, data.MCLAG_2_A, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), 'add'],
                            [vapi.config_vlan_range, data.MCLAG_2_S, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), 'add'],
                            [vapi.config_vlan_range, data.MCLAG_CLIENT, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), 'add']]
            [_, exceptions] = exec_all(True, command_list)
            ensure_no_exception(exceptions)
            if data.keep_alive_link_vlan_intf:
                command_list = [[vapi.config_vlan_range, data.MCLAG_1_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'add'],
                                [vapi.config_vlan_range, data.MCLAG_1_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'add'],
                                [vapi.config_vlan_range, data.MCLAG_2_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'add'],
                                [vapi.config_vlan_range, data.MCLAG_2_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'add']]
                [_, exceptions] = exec_all(True, command_list)
                ensure_no_exception(exceptions)

    if xstp:
        # Configuring of STP on vlans on all the DUTs
        utils.banner_log("Configuring STP vlan parameters on all DUTs")
        if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
            if data.topology_2_tier:
                data.stp_data = {data.MCLAG_2_A: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_2_A_Complete_Port_List}, data.MCLAG_2_S: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_2_S_Complete_Port_List}, data.MCLAG_1_A: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}, data.MCLAG_CLIENT: {"vlan":data.normal_vlans[2], "priority": 0, "intf_list": data.MCLAG_CLIENT_Complete_Port_List}}
            else:
                data.stp_data = {data.MCLAG_2_A: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_2_A_Complete_Port_List}, data.MCLAG_1_A: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}, data.MCLAG_CLIENT: {"vlan":data.normal_vlans[2], "priority": 0, "intf_list": data.MCLAG_CLIENT_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data)
        else:
            data.stp_data1 = {data.MCLAG_1_A: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data1)
            data.stp_data2 = {data.MCLAG_1_A: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data2)
            data.stp_data3 = {data.MCLAG_1_A: {"vlan":data.normal_vlans[2], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[2], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data3)

        if data.topology_scale:
            data.stp_data1 = {data.MCLAG_1_A: {"vlan": data.normal_vlans[0], "priority": 32768, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan": data.normal_vlans[0], "priority": 32768, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data1)
            data.stp_data3 = {data.MCLAG_1_A: {"vlan": data.normal_vlans[2], "priority": 32768, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan": data.normal_vlans[2], "priority": 32768, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data3)

    if vlans_portchannel:
        # Configuring vlans on all the DUTs
        if data.topology_scale:
            utils.banner_log("Configuring vlan members on all the DUTs for scaled topology")
            command_list = [[vapi.config_vlan_range_members, data.MCLAG_1_A, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), data.vlan_data[data.MCLAG_1_A]["normal_vlan"]["members"], 'add'],
                            [vapi.config_vlan_range_members, data.MCLAG_1_S, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), data.vlan_data[data.MCLAG_1_S]["normal_vlan"]["members"], 'add'],
                            [vapi.config_vlan_range_members, data.MCLAG_2_A, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), data.vlan_data[data.MCLAG_2_A]["normal_vlan"]["members"], 'add'],
                            [vapi.config_vlan_range_members, data.MCLAG_2_S, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_2_S]["normal_vlan"]["members"], 'add'],
                            [vapi.config_vlan_range_members, data.MCLAG_CLIENT, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_CLIENT]["normal_vlan"]["members"], 'add']]
            [_, exceptions] = exec_all(True, command_list)
            ensure_no_exception(exceptions)
            if data.keep_alive_link_vlan_intf:
                command_list = [[vapi.config_vlan_range_members, data.MCLAG_1_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_1_A]["peer_vlan"]["members"], 'add'],
                                [vapi.config_vlan_range_members, data.MCLAG_1_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_1_S]["peer_vlan"]["members"], 'add'],
                                [vapi.config_vlan_range_members, data.MCLAG_2_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_2_A]["peer_vlan"]["members"], 'add'],
                                [vapi.config_vlan_range_members, data.MCLAG_2_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_2_S]["peer_vlan"]["members"], 'add']]
                [_, exceptions] = exec_all(True, command_list)
                ensure_no_exception(exceptions)

    if xstp:
        # Configuring the port priority so that MCLAG interaface is in forwarding state.
        stp.config_stp_vlan_interface(data.MCLAG_CLIENT, data.normal_vlans[0], data.MCLAG_CLIENT_MC_Lag_1, 1, mode='cost')
        stp.config_stp_vlan_interface(data.MCLAG_CLIENT, data.normal_vlans[1], data.MCLAG_CLIENT_MC_Lag_1, 1, mode='cost')
        stp.config_stp_vlan_interface(data.MCLAG_CLIENT, data.normal_vlans[2], data.MCLAG_CLIENT_MC_Lag_1, 1, mode='cost')

        if data.stp_protocol == "rpvst":
            # Configuring max age for RPVST test cases.
            if len(data.dut_list) <= 6:
                max_age = 6
            else:
                max_age = len(data.dut_list)
            for dut in data.dut_list:
                stp.config_stp_parameters(dut, max_age=max_age)
                stp.config_port_type(dut, data.dut_to_tg_list[dut], stp_type=data.stp_protocol, port_type='edge', no_form=False)

            hold_time = 6
            buffer = 4
            wait_time = hold_time + max_age + buffer
            data.stp_dict[data.stp_protocol]["stp_wait_time"] = wait_time
            data.stp_dict[data.stp_protocol]["stp_max_age"] = max_age
            st.log("data.stp_dict : {}".format(data.stp_dict))

            if data.mclag_peers_as_only_root:
                for intf in data.MCLAG_1_A_Complete_Port_List:
                    stp.config_stp_interface_params(data.MCLAG_1_A, intf, root_guard="enable")
                for intf in data.MCLAG_1_S_Complete_Port_List:
                    stp.config_stp_interface_params(data.MCLAG_1_S, intf, root_guard="enable")

    if initconf:
        # Wait for MCLAG to come up
        st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        # Checking for setup stable state.
        if not check_stable_state(stp=True, mclag=True, traffic=False):
            st.report_fail("module_config_verification_failed")

    if tgen:
        # TG configuration
        utils.banner_log("TG configuration : MCLAG + STP")
        tg_routing_interface_config()

def module_unconfig(stp_protocol, xstp=True, mlag=True, vlans_portchannel=True, tgen=True):
    if xstp:
        # Unconfiguring of STP on all the DUTs
        utils.banner_log("Unconfiguring STP on all the DUTs")
        stp.config_stp_in_parallel(data.dut_list, feature=data.stp_protocol, mode="disable")

    if mlag:
        # Unconfiguring MCLAG interfaces for all the domains
        utils.banner_log("Unconfiguring MCLAG interfaces for all the domains")
        if data.topology_2_tier:
            [_, exceptions] = exec_all(True, data.mclag_interfaces_del)
        else:
            [_, exceptions] = exec_all(True, data.mclag_interfaces_del_1)
        ensure_no_exception(exceptions)

        # Unconfiguring MCLAG domain on the MLCLAG peers
        utils.banner_log("Unconfiguring MCLAG domain on the MLCLAG peers")
        if data.topology_2_tier:
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_2_A, data.MCLAG_2_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "del"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)
            [_, exceptions] = exec_parallel(True, data.mclag_duts, mclag.config_domain, data.mclag_domain_del)
            ensure_no_exception(exceptions)
        else:
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)
            [_, exceptions] = exec_parallel(True, data.mclag_duts_domain_1, mclag.config_domain, data.mclag_domain_del_1)
            ensure_no_exception(exceptions)

        # Unconfiguring Ip address on peer links
        utils.banner_log("Unconfiguring Ip address on peer links")
        api_list = list()
        if data.keep_alive_link_vlan_intf:
            if data.topology_2_tier:
                api_list.append([ip.delete_ip_interface, data.MCLAG_2_A, 'Vlan' + str(data.MCLAG_2_A_PEERLINK_VLAN), data.MCLAG_2_A_LOCAL_IP, data.mask])
                api_list.append([ip.delete_ip_interface, data.MCLAG_2_S, 'Vlan' + str(data.MCLAG_2_S_PEERLINK_VLAN), data.MCLAG_2_S_LOCAL_IP, data.mask])
            api_list.append([ip.delete_ip_interface, data.MCLAG_1_A, 'Vlan' + str(data.MCLAG_1_A_PEERLINK_VLAN), data.MCLAG_1_A_LOCAL_IP, data.mask])
            api_list.append([ip.delete_ip_interface, data.MCLAG_1_S, 'Vlan' + str(data.MCLAG_1_S_PEERLINK_VLAN), data.MCLAG_1_S_LOCAL_IP, data.mask])
        else:
            if data.topology_2_tier:
                api_list.append([ip.delete_ip_interface, data.MCLAG_2_A, data.MCLAG_2_A_To_MCLAG_2_S_Keep_Alive_Link, data.MCLAG_2_A_LOCAL_IP, data.mask])
                api_list.append([ip.delete_ip_interface, data.MCLAG_2_S, data.MCLAG_2_S_To_MCLAG_2_A_Keep_Alive_Link, data.MCLAG_2_S_LOCAL_IP, data.mask])
            api_list.append([ip.delete_ip_interface, data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A_LOCAL_IP, data.mask])
            api_list.append([ip.delete_ip_interface, data.MCLAG_1_S, data.MCLAG_1_S_To_MCLAG_1_A_Keep_Alive_Link, data.MCLAG_1_S_LOCAL_IP, data.mask])
        [_, exceptions] = exec_all(True, api_list)
        ensure_no_exception(exceptions)

    if vlans_portchannel:
        # Clearing of configured vlans and port channels on all the DUTs
        utils.banner_log("Clearing of configured vlans and port channels on all the DUTs")
        if not data.topology_scale:
            vapi.clear_vlan_configuration(data.dut_list)
            portchannel.clear_portchannel_configuration(data.dut_list)
        else:
            command_list = [[vapi.config_vlan_range_members, data.MCLAG_1_A, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_1_A]["normal_vlan"]["members"], 'del'],
                            [vapi.config_vlan_range_members, data.MCLAG_1_S, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_1_S]["normal_vlan"]["members"], 'del'],
                            [vapi.config_vlan_range_members, data.MCLAG_2_A, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_2_A]["normal_vlan"]["members"], 'del'],
                            [vapi.config_vlan_range_members, data.MCLAG_2_S, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_2_S]["normal_vlan"]["members"], 'del'],
                            [vapi.config_vlan_range_members, data.MCLAG_CLIENT, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), data.vlan_data[data.MCLAG_CLIENT]["normal_vlan"]["members"], 'del']]
            [_, exceptions] = exec_all(True, command_list)
            ensure_no_exception(exceptions)
            command_list = [[vapi.config_vlan_range, data.MCLAG_1_A, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), 'del'],
                            [vapi.config_vlan_range, data.MCLAG_1_S, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), 'del'],
                            [vapi.config_vlan_range, data.MCLAG_2_A, "{} {}".format(data.normal_vlans[0],data.normal_vlans[-1]), 'del'],
                            [vapi.config_vlan_range, data.MCLAG_2_S, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), 'del'],
                            [vapi.config_vlan_range, data.MCLAG_CLIENT, "{} {}".format(data.normal_vlans[0], data.normal_vlans[-1]), 'del']]
            [_, exceptions] = exec_all(True, command_list)
            ensure_no_exception(exceptions)

            if data.keep_alive_link_vlan_intf:
                command_list = [[vapi.config_vlan_range_members, data.MCLAG_1_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_1_A]["peer_vlan"]["members"], 'del'],
                                [vapi.config_vlan_range_members, data.MCLAG_1_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_1_S]["peer_vlan"]["members"], 'del'],
                                [vapi.config_vlan_range_members, data.MCLAG_2_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_2_A]["peer_vlan"]["members"], 'del'],
                                [vapi.config_vlan_range_members, data.MCLAG_2_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), data.vlan_data[data.MCLAG_2_S]["peer_vlan"]["members"], 'del']]
                [_, exceptions] = exec_all(True, command_list)
                ensure_no_exception(exceptions)
                command_list = [[vapi.config_vlan_range, data.MCLAG_1_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'del'],
                                [vapi.config_vlan_range, data.MCLAG_1_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'del'],
                                [vapi.config_vlan_range, data.MCLAG_2_A, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'del'],
                                [vapi.config_vlan_range, data.MCLAG_2_S, "{} {}".format(data.peer_link_vlans[0], data.peer_link_vlans[-1]), 'del']]
                [_, exceptions] = exec_all(True, command_list)
                ensure_no_exception(exceptions)
    if tgen:
        # TG unconfiguration
        utils.banner_log("TG unconfiguration : MCLAG + STP")
        tg_routing_interface_unconfig()

def lib_stp_mclag_basic_tests():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    if res_1:
        data.stable_state_check_at_test_start = False
    return res_1

def lib_stp_mclag_orphan_port_shutdown():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Shutting down orphan port of MCLAG_1_A and checking traffic
        ###############################################################################################
        utils.banner_log("Shutting down orphan port of MCLAG_1_A and checking traffic -- STARTED")
        st.log("Shutting down the orphan port of MCLAG_1_A.")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_TG1 , "shutdown")
        if not intf.poll_for_interface_status(data.MCLAG_1_A, data.MCLAG_1_A_TG1, "oper", "down", iteration=10, delay=1):
            intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_TG1, "startup")
            log_error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_TG1, data.MCLAG_1_A))
            st.report_fail("interface_is_up_on_dut", data.MCLAG_1_A)

        if not verify_mclag_data():
            res_1 = False

        root_to_exclude_intf_dict = {"dut": data.MCLAG_1_A, "intf_list": data.MCLAG_1_A_TG1}
        if not check_for_stp_convergence(True, root_to_exclude_intf_dict):
            res_1 = False

        if not check_traffic("North_To_South_Traffic"):
            res_1 = False
        utils.banner_log("Shutting down orphan port of MCLAG_1_A and checking traffic -- COMPLETED")

        ###############################################################################################
        # Starting up the orphan port of MCLAG_1_A and checking traffic
        ###############################################################################################
        utils.banner_log("Starting up the orphan port of MCLAG_1_A and checking traffic -- STARTED")
        st.log("Starting up the orphan port of MCLAG_1_A.")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_TG1 , "startup")
        if not intf.poll_for_interface_status(data.MCLAG_1_A, data.MCLAG_1_A_TG1, "oper", "up", iteration=10, delay=1):
            log_error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_TG1, data.MCLAG_1_A))
            st.report_fail("interface_is_down_on_dut", data.MCLAG_1_A)

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False
        utils.banner_log(" Starting up the orphan port of MCLAG_1_A and checking traffic -- COMPLETED")

        if res_1:
            st.report_tc_pass('ft_{}_mlag_orphan_port_down'.format(data.stp_protocol),'test_case_passed')
        else:
            st.report_tc_fail('ft_{}_mlag_orphan_port_down'.format(data.stp_protocol),'test_case_failed')

    if res_1:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_path_cost():
    res_1, res_2 = True, True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1, res_2 = False, False
    else:
        MCLAG_1_A_PATH_COST = stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_pathcost")
        MCLAG_1_S_PATH_COST = stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_pathcost")

        ###############################################################################################
        # Decreasing the MCLAG stp path cost and checking for FORWARDING state
        ###############################################################################################
        utils.banner_log("Decreasing the MCLAG stp path cost and checking for FORWARDING state")
        stp.config_stp_vlan_interface(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, 1, mode='cost')
        stp.config_stp_vlan_interface(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, 1, mode='cost')

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        ###############################################################################################
        # Getting the FORWARDING ports on MCLAG peers
        ###############################################################################################
        MCLAG_1_A_MC_Lag_1_State = stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_state")
        MCLAG_1_S_MC_Lag_1_State = stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_state")
        if MCLAG_1_A_MC_Lag_1_State != data.stp_dict[data.stp_protocol]["fwd_state"] or MCLAG_1_S_MC_Lag_1_State != data.stp_dict[data.stp_protocol]["fwd_state"]:
            log_error("MCLAG_1_A_MC_Lag_1 ({}) state is not {}".format(data.MCLAG_1_A_MC_Lag_1, data.stp_dict[data.stp_protocol]["fwd_state"]))
            log_error("MCLAG_1_S_MC_Lag_1 ({}) state is not {}".format(data.MCLAG_1_S_MC_Lag_1, data.stp_dict[data.stp_protocol]["fwd_state"]))
            res_1, res_2 = False, False
        else:
            st.log("MCLAG_1_A_MC_Lag_1 ({}) state is {}".format(data.MCLAG_1_A_MC_Lag_1, data.stp_dict[data.stp_protocol]["fwd_state"]))
            st.log("MCLAG_1_S_MC_Lag_1 ({}) state is {}".format(data.MCLAG_1_S_MC_Lag_1, data.stp_dict[data.stp_protocol]["fwd_state"]))

            ###############################################################################################
            # Getting initial TCN counters and clearing TCN counters on MCLAG peers
            ###############################################################################################
            utils.banner_log("Getting initial TCN counters and clearing TCN counters on MCLAG peers")
            MCLAG_1_A_tcn_tx_cnt_before = stp.get_stp_stats(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_To_MCLAG_2_A_Lag, "st_tcntx")
            MCLAG_2_A_tcn_rx_cnt_before = stp.get_stp_stats(data.MCLAG_2_A, data.normal_vlans[2], data.MCLAG_2_A_To_MCLAG_1_A_Lag, "st_tcnrx")
            stp.stp_clear_stats(data.MCLAG_1_A, vlan=data.normal_vlans[2])
            stp.stp_clear_stats(data.MCLAG_2_A, vlan=data.normal_vlans[2])

            ###############################################################################################
            # Increasing the MCLAG stp path cost and checking for BLOCKING state
            ###############################################################################################
            utils.banner_log("Increasing the MCLAG stp path cost and checking for BLOCKING state -- STARTED")
            stp.config_stp_vlan_interface(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, 5000, mode='cost')
            stp.config_stp_vlan_interface(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, 5000, mode='cost')

            # Wait time for stp to converge
            st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

            if not check_stable_state(stp=True, mclag=True, traffic=False):
                res_1, res_2 = False, False

            if not stp.verify_stp_ports_by_state(data.MCLAG_1_A, data.normal_vlans[2], data.stp_dict[data.stp_protocol]["non_fwd_state"], data.MCLAG_1_A_MC_Lag_1):
                res_1 = False
            if not stp.verify_stp_ports_by_state(data.MCLAG_1_S, data.normal_vlans[2], data.stp_dict[data.stp_protocol]["non_fwd_state"], data.MCLAG_1_S_MC_Lag_1):
                res_1 = False
            utils.banner_log("Increasing the MCLAG stp path cost and checking for BLOCKING state -- COMPLETED")

            ###############################################################################################
            # Decreasing the MCLAG stp path cost and checking for FORWARDING state
            ###############################################################################################
            utils.banner_log("Decreasing the MCLAG stp path cost and checking for FORWARDING state -- STARTED")
            stp.config_stp_vlan_interface(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, 1, mode='cost')
            stp.config_stp_vlan_interface(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, 1, mode='cost')

            # Wait time for stp to converge
            st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

            if not check_stable_state(stp=True, mclag=True, traffic=False):
                res_1, res_2 = False, False

            if not stp.verify_stp_ports_by_state(data.MCLAG_1_A, data.normal_vlans[2], data.stp_dict[data.stp_protocol]["fwd_state"], data.MCLAG_1_A_MC_Lag_1):
                res_1 = False
            if not stp.verify_stp_ports_by_state(data.MCLAG_1_S, data.normal_vlans[2], data.stp_dict[data.stp_protocol]["fwd_state"], data.MCLAG_1_S_MC_Lag_1):
                res_1 = False
            utils.banner_log("Decreasing the MCLAG stp path cost and checking for non FORWARDING state -- COMPLETED")

            if res_1:
                st.report_tc_pass('ft_{}_mlag_path_cost'.format(data.stp_protocol),'test_case_passed')
            else:
                st.report_tc_fail('ft_{}_mlag_path_cost'.format(data.stp_protocol),'test_case_failed')

            ###############################################################################################
            # Checking FDB entries after initiating a TCN
            ###############################################################################################
            utils.banner_log("Checking FDB entries after initiating a TCN")
            c1 = mac.get_mac_address_count(data.MCLAG_1_A, data.normal_vlans[2])
            c2 = mac.get_mac_address_count(data.MCLAG_1_S, data.normal_vlans[2])
            st.log("c1 : {}, c2 : {}".format(c1, c2))
            if data.stp_protocol == "pvst":
                if int(c1) != 0 or int(c2) != 0:
                    log_error("Mac address count is not zero on MCLAG peers after TCN.")
                    res_2 = False
            elif data.stp_protocol == "rpvst":
                # Mac learnt on edge port will not be flushed. In vlan 30, mac learnt on MCLAG_1_A and MCLAG_1_S TG ports and thier entries on peerlink will not be flushed.
                if int(c1) != 2 or int(c2) != 2:
                    log_error("Mac address count is not 2 on MCLAG peers after TCN.")
                    res_2 = False

            ###############################################################################################
            # Checking TCN counters on MCLAG peers after initiating TCN
            ###############################################################################################
            utils.banner_log("Checking TCN counters on MCLAG peers after initiating TCN")
            MCLAG_1_A_tcn_tx_cnt_after = stp.get_stp_stats(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_To_MCLAG_2_A_Lag, "st_tcntx")
            MCLAG_2_A_tcn_rx_cnt_after = stp.get_stp_stats(data.MCLAG_2_A, data.normal_vlans[2], data.MCLAG_2_A_To_MCLAG_1_A_Lag, "st_tcnrx")

            if data.stp_protocol == "pvst":
                if MCLAG_1_A_tcn_tx_cnt_after <= MCLAG_1_A_tcn_tx_cnt_before or MCLAG_2_A_tcn_rx_cnt_after <= MCLAG_2_A_tcn_rx_cnt_before:
                    log_error("TCN counters are not incrementing after initiating a TCN in {} case".format(data.stp_protocol))
                    res_2 = False
                else:
                    st.log("TCN counters are incrementing after initiating a TCN in {} case".format(data.stp_protocol))
            else:
                if MCLAG_1_A_tcn_tx_cnt_after != MCLAG_1_A_tcn_tx_cnt_before or MCLAG_2_A_tcn_rx_cnt_after != MCLAG_2_A_tcn_rx_cnt_before:
                    log_error("TCN counters are incrementing after initiating a TCN in {} case".format(data.stp_protocol))
                    res_2 = False
                else:
                    st.log("TCN counters are not incrementing after initiating a TCN in {} case".format(data.stp_protocol))

            ###############################################################################################
            # Setting the MCLAG interface path cost to default value
            ###############################################################################################
            utils.banner_log("Setting the MCLAG interface path cost to default value")
            stp.config_stp_vlan_interface(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, MCLAG_1_A_PATH_COST, mode='cost')
            stp.config_stp_vlan_interface(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, MCLAG_1_S_PATH_COST, mode='cost')

            # Wait time for stp to converge
            st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

            if res_2:
                st.report_tc_pass('ft_{}_mlag_tcn_handling'.format(data.stp_protocol),'test_case_passed')
            else:
                st.report_tc_fail('ft_{}_mlag_tcn_handling'.format(data.stp_protocol),'test_case_failed')

    if res_1 and res_2:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_rootbridge_multi_instances():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Configuring MCLAG_1_A as root in multiple instances
        ###############################################################################################
        utils.banner_log("Configuring MCLAG_1_A as root in multiple instances -- STARTED")
        stp_data_config = {data.MCLAG_2_A: {"vlan":data.normal_vlans[0], "priority": 32768}, data.MCLAG_1_A: {"vlan":data.normal_vlans[0], "priority": 0}, data.MCLAG_1_S: {"vlan":data.normal_vlans[0], "priority": 0}}
        stp.config_stp_root_bridge_by_vlan(stp_data_config)

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        utils.banner_log("Checking for STP convergence : ROOT BRIDGE BASED ON CONFIGURED BRIDGE PRIORITY")
        dut_list = [data.MCLAG_1_A, data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_1_S, data.MCLAG_CLIENT]
        vlan_list = [data.normal_vlans[0], data.normal_vlans[1], data.normal_vlans[0], data.normal_vlans[1], data.normal_vlans[2]]
        for (dut, vlan) in zip(dut_list, vlan_list):
            if stp.poll_for_root_switch(dut, vlan, iteration=10, delay=4):
                st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut, vlan))
            else:
                log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(dut, vlan))
                res_1 = False

        utils.banner_log("Checking for STP convergence : ROOT BRIDGE INTERFACE STATE VERIFICATION ")
        dut_to_vlan_dict = {data.MCLAG_1_A: data.normal_vlans[0], data.MCLAG_1_A: data.normal_vlans[1], data.MCLAG_1_S: data.normal_vlans[0], data.MCLAG_1_S: data.normal_vlans[1], data.MCLAG_CLIENT: data.normal_vlans[2]}
        dut_to_intf_dict = {data.MCLAG_1_A: data.dut_to_intf_dict[data.MCLAG_1_A], data.MCLAG_1_A: data.dut_to_intf_dict[data.MCLAG_1_A], data.MCLAG_1_S: data.dut_to_intf_dict[data.MCLAG_1_S], data.MCLAG_1_S: data.dut_to_intf_dict[data.MCLAG_1_S], data.MCLAG_CLIENT: data.dut_to_intf_dict[data.MCLAG_CLIENT]}
        st.log("dut_to_vlan_dict : {}".format(dut_to_vlan_dict))
        st.log("dut_to_intf_dict : {}".format(dut_to_intf_dict))
        if not stp.poll_root_bridge_interfaces(dut_to_vlan_dict, dut_to_intf_dict):
            log_error("ROOT BRIDGE INTERFACE STATE VERIFICATION : FAILED")
            res_1 = False
        else:
            st.log("ROOT BRIDGE INTERFACE STATE VERIFICATION : PASSED")

        utils.banner_log("Checking for STP convergence : MCLAG PEERS STP ROLES")
        if not check_mclag_peers_stp_roles():
            log_error("MCLAG PEERS STP ROLES : FAILED")
            res_1 = False
        else:
            st.log("MCLAG PEERS STP ROLES : PASSED")

        if not check_traffic():
            res_1 = False
        utils.banner_log("Configuring MCLAG_1_A as root in multiple instances -- COMPLETED")

        ###############################################################################################
        # Configuring back MCLAG_1_A as root in single instance
        ###############################################################################################
        utils.banner_log("Configuring back MCLAG_1_A as root in single instance -- STARTED")
        stp_data_config = {data.MCLAG_2_A: {"vlan":data.normal_vlans[0], "priority": 0}, data.MCLAG_1_A: {"vlan":data.normal_vlans[0], "priority": 32768}, data.MCLAG_1_S: {"vlan":data.normal_vlans[0], "priority": 32768}}
        stp.config_stp_root_bridge_by_vlan(stp_data_config)

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False
        utils.banner_log("Configuring back MCLAG_1_A as root in single instance -- COMPLETED")

        if res_1:
            st.report_tc_pass('ft_{}_mlag_rootbridge_multi_instances'.format(data.stp_protocol),'test_case_passed')
        else:
            st.report_tc_fail('ft_{}_mlag_rootbridge_multi_instances'.format(data.stp_protocol),'test_case_failed')

    if res_1:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_interface_shutdown():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        utils.banner_log("Sending and verifying traffic: {} between {} and {}".format('MCLAG_Peer_To_Client', "MCLAG_1_A", "MCLAG_CLIENT"))
        if not verify_traffic_send_and_receive("MCLAG_Peer_To_Client"):
            res_1 = False

        # Checking FDB for mac address on MCLAG_1_A and MCLAG_1_S
        if mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:06", vlan=data.normal_vlans[0], port=data.MCLAG_1_A_MC_Lag_1) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:06", vlan=data.normal_vlans[1], port=data.MCLAG_1_A_MC_Lag_1) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:06", vlan=data.normal_vlans[2], port=data.MCLAG_1_A_MC_Lag_1):
            st.log("FDB check on MCLAG_1_A for MCLAG peer to client traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_A for MCLAG peer to client traffic : FAILED")
            res_1 = False

        if mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:06", vlan=data.normal_vlans[0], port=data.MCLAG_1_S_MC_Lag_1) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:06", vlan=data.normal_vlans[1], port=data.MCLAG_1_S_MC_Lag_1) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:06", vlan=data.normal_vlans[2], port=data.MCLAG_1_S_MC_Lag_1):
            st.log("FDB check on MCLAG_1_S for MCLAG peer to client traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_A for MCLAG peer to client traffic : FAILED")
            res_1 = False

        ###############################################################################################
        # Shutting down MCLAG interface on MCLAG_1_A and checking FDB and traffic
        ###############################################################################################
        utils.banner_log("Shutting down MCLAG interface on MCLAG_1_A and checking FDB and traffic -- STARTED")
        st.log("Shutting down the MCLAG interface on MCLAG_1_A.")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "shutdown")
        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "down", iteration=10, delay=1):
            intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "startup")
            log_error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            st.report_fail("interface_is_up_on_dut", data.MCLAG_1_A)

        st.wait(10)

        # Checking FDB for mac address on MCLAG_1_A and MCLAG_1_S after MCLAG interface shutdown
        if mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:06", vlan=data.normal_vlans[0], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:06", vlan=data.normal_vlans[1], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:06", vlan=data.normal_vlans[2], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag):
            st.log("FDB check on MCLAG_1_A for MCLAG peer to client traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_A for MCLAG peer to client traffic : FAILED")
            res_1 = False

        if mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:06", vlan=data.normal_vlans[0], port=data.MCLAG_1_S_MC_Lag_1) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:06", vlan=data.normal_vlans[1], port=data.MCLAG_1_S_MC_Lag_1) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:06", vlan=data.normal_vlans[2], port=data.MCLAG_1_S_MC_Lag_1):
            st.log("FDB check on MCLAG_1_S for MCLAG peer to client traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_S for MCLAG peer to client traffic : FAILED")
            res_1 = False

        utils.banner_log("Sending and verifying traffic: {} between {} and {}".format('MCLAG_Peer_To_Client', "MCLAG_1_A", "MCLAG_CLIENT"))
        if not verify_traffic_send_and_receive("MCLAG_Peer_To_Client"):
            res_1 = False
        utils.banner_log("Shutting down MCLAG interface on MCLAG_1_A and checking FDB and traffic -- COMPLETED")

        ###############################################################################################
        # Starting up the MCLAG interface on MCLAG_1_A and checking FDB and traffic
        ###############################################################################################
        utils.banner_log("Starting up the MCLAG interface on MCLAG_1_A and checking FDB and traffic -- STARTED")
        st.log("Starting up the MCLAG interface on MCLAG_1_A.")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "startup")
        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "up", iteration=10, delay=1):
            log_error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            st.report_fail("interface_is_down_on_dut", data.MCLAG_1_A)

        st.wait(10)

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False
        utils.banner_log("Starting up the MCLAG interface on MCLAG_1_A and checking FDB and traffic -- COMPLETED")

        if res_1:
            if not data.topology_scale:
                st.report_tc_pass('ft_{}_mlag_traffic_partner_port_down'.format(data.stp_protocol),'test_case_passed')
            else:
                st.report_tc_pass('ft_{}_scale_mclag_interface_shut_noshut'.format(data.stp_protocol), 'test_case_passed')
        else:
            if not data.topology_scale:
                st.report_tc_fail('ft_{}_mlag_traffic_partner_port_down'.format(data.stp_protocol),'test_case_failed')
            else:
                st.report_tc_fail('ft_{}_scale_mclag_interface_shut_noshut'.format(data.stp_protocol),'test_case_failed')
    if res_1:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_disable_enable_stp():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Disabling of STP on all the devices in the topology
        ###############################################################################################
        utils.banner_log("Disabling of STP on all the devices in the topology -- STARTED")
        # Unconfiguring of STP on all the DUTs
        utils.banner_log("Unconfiguring STP on all the DUTs")
        stp.config_stp_in_parallel(data.dut_list, feature=data.stp_protocol, mode="disable")
        utils.banner_log("Disabling of STP on all the devices in the topology -- COMPLETED")

        ###############################################################################################
        # Enabling of STP on all the devices in the topology
        ###############################################################################################
        utils.banner_log("Enabling of STP on all the devices in the topology -- STARTED")
        # Configuring of STP on all the DUTs
        utils.banner_log("Configuring STP on all the DUTs")
        stp.config_stp_in_parallel(data.dut_list, feature=data.stp_protocol, mode="enable")

        if data.stp_protocol == "rpvst":
            for dut in data.dut_list:
                stp.config_stp_parameters(dut, max_age=data.stp_dict[data.stp_protocol]["stp_max_age"])
                stp.config_port_type(dut, data.dut_to_tg_list[dut], stp_type=data.stp_protocol, port_type='edge', no_form=False)

            if data.mclag_peers_as_only_root:
                for intf in data.MCLAG_1_A_Complete_Port_List:
                    stp.config_stp_interface_params(data.MCLAG_1_A, intf, root_guard="enable")
                for intf in data.MCLAG_1_S_Complete_Port_List:
                    stp.config_stp_interface_params(data.MCLAG_1_S, intf, root_guard="enable")

        # Configuring the port priority so that MCLAG interaface is in forwarding state.
        stp.config_stp_vlan_interface(data.MCLAG_CLIENT, data.normal_vlans[0], data.MCLAG_CLIENT_MC_Lag_1, 1, mode='cost')
        stp.config_stp_vlan_interface(data.MCLAG_CLIENT, data.normal_vlans[1], data.MCLAG_CLIENT_MC_Lag_1, 1, mode='cost')
        stp.config_stp_vlan_interface(data.MCLAG_CLIENT, data.normal_vlans[2], data.MCLAG_CLIENT_MC_Lag_1, 1, mode='cost')

        # Configuring of STP on vlans on all the DUTs
        utils.banner_log("Configuring STP vlan parameters on all DUTs")
        if data.topology_scale:
            stp.config_stp_parameters(data.MCLAG_1_A, priority=0)
            stp.config_stp_parameters(data.MCLAG_1_S, priority=0)

        if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
            stp.config_stp_root_bridge_by_vlan(data.stp_data)
        else:
            data.stp_data1 = {data.MCLAG_1_A: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[0], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data1)
            data.stp_data2 = {data.MCLAG_1_A: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[1], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data2)
            data.stp_data3 = {data.MCLAG_1_A: {"vlan":data.normal_vlans[2], "priority": 0, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan":data.normal_vlans[2], "priority": 0, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data3)

        if data.topology_scale:
            data.stp_data1 = {data.MCLAG_1_A: {"vlan": data.normal_vlans[0], "priority": 32768, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan": data.normal_vlans[0], "priority": 32768, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data1)
            data.stp_data3 = {data.MCLAG_1_A: {"vlan": data.normal_vlans[2], "priority": 32768, "intf_list": data.MCLAG_1_A_Complete_Port_List}, data.MCLAG_1_S: {"vlan": data.normal_vlans[2], "priority": 32768, "intf_list": data.MCLAG_1_S_Complete_Port_List}}
            stp.config_stp_root_bridge_by_vlan(data.stp_data3)
        utils.banner_log("Enabling of STP on all the devices in the topology -- COMPLETED")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

    if res_1:
        if data.topology_2_tier:
            st.report_tc_pass('ft_{}_mlag_disable_enable_stp_2_tier'.format(data.stp_protocol),'test_case_passed')
        else:
            if not data.topology_scale:
                st.report_tc_pass('ft_{}_mlag_disable_enable_stp'.format(data.stp_protocol),'test_case_passed')
            else:
                st.report_tc_pass('ft_{}_scale_mclag_disable_enable_stp'.format(data.stp_protocol),'test_case_passed')
        data.stable_state_check_at_test_start = False
        return True
    else:
        if data.topology_2_tier:
            st.report_tc_fail('ft_{}_mlag_disable_enable_stp_2_tier'.format(data.stp_protocol),'test_case_failed')
        else:
            if not data.topology_scale:
                st.report_tc_fail('ft_{}_mlag_disable_enable_stp'.format(data.stp_protocol),'test_case_failed')
            else:
                st.report_tc_fail('ft_{}_scale_mclag_disable_enable_stp'.format(data.stp_protocol),'test_case_failed')

        return False

def lib_stp_mclag_pvst_and_rpvst_interaction():
    res_1 = True
    stp_ver = {"pvst" : "rpvst", "rpvst" : "pvst"}

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Disabling and Enabling of STP on MCLAG_2_S in the topology
        ###############################################################################################
        utils.banner_log("Disabling and Enabling of STP on MCLAG_2_S in the topology")
        stp.config_stp_in_parallel(data.MCLAG_2_S, feature=data.stp_protocol, mode="disable")
        stp.config_stp_in_parallel(data.MCLAG_2_S, feature=stp_ver[data.stp_protocol], mode="enable")

        # Wait time for stp to converge
        st.wait(data.stp_dict["pvst"]["stp_wait_time"], "Wait time for stp to converge")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

        ###############################################################################################
        # Disabling and Enabling of STP on MCLAG_2_S in the topology
        ###############################################################################################
        utils.banner_log("Disabling and Enabling of STP on MCLAG_2_S in the topology")
        stp.config_stp_in_parallel(data.MCLAG_2_S, feature=stp_ver[data.stp_protocol], mode="disable")
        stp.config_stp_in_parallel(data.MCLAG_2_S, feature=data.stp_protocol, mode="enable")

        # Wait time for stp to converge
        st.wait(data.stp_dict["pvst"]["stp_wait_time"], "Wait time for stp to converge")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

    if res_1:
        st.report_tc_pass('ft_{}_mlag_pvst_and_rpvst_interaction'.format(data.stp_protocol),'test_case_passed')
        data.stable_state_check_at_test_start = False
        return True
    else:
        st.report_tc_fail('ft_{}_mlag_pvst_and_rpvst_interaction'.format(data.stp_protocol),'test_case_failed')
        return False

def lib_stp_mclag_failover_tests():
    res_1, res_2 = True, True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1, res_2 = False, False
    else:
        if data.topology_2_tier:
            ###############################################################################################
            # Failover of MCLAG devices : Active (MCLAG_2_A) and Active (MCLAG_1_A)
            ###############################################################################################
            utils.banner_log("Failover of MCLAG devices : Active (MCLAG_2_A) and Active (MCLAG_1_A) -- STARTED")
            reboot.config_save(data.MCLAG_2_A)
            reboot.config_save(data.MCLAG_1_A)
            api_list = list()
            api_list.append([st.reboot, data.MCLAG_2_A])
            api_list.append([st.reboot, data.MCLAG_1_A])
            [_, exceptions] = exec_all(True, api_list)
            ensure_no_exception(exceptions)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_2_A'))
            if not basic.poll_for_system_status(data.MCLAG_2_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_A'))
            if not basic.poll_for_system_status(data.MCLAG_1_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")
        else:
            ###############################################################################################
            # Failover of MCLAG device : Active (MCLAG_1_A)
            ###############################################################################################
            utils.banner_log("Failover of MCLAG device : Active (MCLAG_1_A) -- STARTED")
            reboot.config_save(data.MCLAG_1_A)
            st.reboot(data.MCLAG_1_A)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_A'))
            if not basic.poll_for_system_status(data.MCLAG_1_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        # Additional wait time with reference to system up time for stp to become stable.
        st.wait(120, "Additional wait time with reference to system up time for stp to become stable.")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

        if res_1:
            if data.topology_2_tier:
                st.report_tc_pass('ft_{}_mlag_rootbridge_active_failover_2_tier'.format(data.stp_protocol),'test_case_passed')
            else:
                if not data.topology_scale:
                    st.report_tc_pass('ft_{}_mlag_rootbridge_active_failover'.format(data.stp_protocol),'test_case_passed')
                else:
                    st.report_tc_pass('ft_{}_scale_mclag_active_failover'.format(data.stp_protocol), 'test_case_passed')
        else:
            if data.topology_2_tier:
                st.report_tc_fail('ft_{}_mlag_rootbridge_active_failover_2_tier'.format(data.stp_protocol),'test_case_failed')
            else:
                if not data.topology_scale:
                    st.report_tc_fail('ft_{}_mlag_rootbridge_active_failover'.format(data.stp_protocol),'test_case_failed')
                else:
                    st.report_tc_fail('ft_{}_scale_mclag_active_failover'.format(data.stp_protocol),'test_case_failed')
        utils.banner_log("Failover of MCLAG device : Active -- COMPLETED")

        if data.topology_2_tier:
            ###############################################################################################
            # Failover of MCLAG devices : Standby (MCLAG_2_S) and Standby (MCLAG_1_S)
            ###############################################################################################
            utils.banner_log("Failover of MCLAG devices : Standby (MCLAG_2_S) and Standby (MCLAG_1_S) -- STARTED")
            reboot.config_save(data.MCLAG_2_S)
            reboot.config_save(data.MCLAG_1_S)
            api_list = list()
            api_list.append([st.reboot, data.MCLAG_2_S])
            api_list.append([st.reboot, data.MCLAG_1_S])
            [_, exceptions] = exec_all(True, api_list)
            ensure_no_exception(exceptions)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_2_S'))
            if not basic.poll_for_system_status(data.MCLAG_2_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_S'))
            if not basic.poll_for_system_status(data.MCLAG_1_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")
        else:
            ###############################################################################################
            # Failover of MCLAG device : Standby (MCLAG_1_S)
            ###############################################################################################
            utils.banner_log("Failover of MCLAG device : Standby (MCLAG_1_S) -- STARTED")
            reboot.config_save(data.MCLAG_1_S)
            st.reboot(data.MCLAG_1_S)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_S'))
            if not basic.poll_for_system_status(data.MCLAG_1_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        # Additional wait time with reference to system up time for stp to become stable.
        st.wait(120, "Additional wait time with reference to system up time for stp to become stable.")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_2 = False

        if res_2:
            if data.topology_2_tier:
                st.report_tc_pass('ft_{}_mlag_rootbridge_standby_failover_2_tier'.format(data.stp_protocol),'test_case_passed')
            else:
                if not data.topology_scale:
                    st.report_tc_pass('ft_{}_mlag_rootbridge_standby_failover'.format(data.stp_protocol),'test_case_passed')
                else:
                    st.report_tc_pass('ft_{}_scale_mclag_standby_failover'.format(data.stp_protocol),'test_case_passed')
        else:
            if data.topology_2_tier:
                st.report_tc_fail('ft_{}_mlag_rootbridge_standby_failover_2_tier'.format(data.stp_protocol),'test_case_failed')
            else:
                if not data.topology_scale:
                    st.report_tc_fail('ft_{}_mlag_rootbridge_standby_failover'.format(data.stp_protocol),'test_case_failed')
                else:
                    st.report_tc_fail('ft_{}_scale_mclag_standby_failover'.format(data.stp_protocol),'test_case_failed')
        utils.banner_log("Failover of MCLAG device : Standby -- COMPLETED")

    if res_1 and res_2:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_both_peers_reload():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        if data.topology_2_tier:
            ###############################################################################################
            # Failover of MCLAG devices : Active (MCLAG_1_A, MCLAG_2_A) and Standby (MCLAG_1_S, MCLAG_2_S)
            ###############################################################################################
            utils.banner_log("Failover of MCLAG devices : Active (MCLAG_1_A, MCLAG_2_A) and Standby (MCLAG_1_S, MCLAG_2_S) -- STARTED")
            reboot.config_save(data.MCLAG_1_A)
            reboot.config_save(data.MCLAG_2_A)
            reboot.config_save(data.MCLAG_1_S)
            reboot.config_save(data.MCLAG_2_S)
            api_list = list()
            api_list.append([st.reboot, data.MCLAG_1_A])
            api_list.append([st.reboot, data.MCLAG_2_A])
            api_list.append([st.reboot, data.MCLAG_1_S])
            api_list.append([st.reboot, data.MCLAG_2_S])
            [_, exceptions] = exec_all(True, api_list)
            ensure_no_exception(exceptions)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_A'))
            if not basic.poll_for_system_status(data.MCLAG_1_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_2_A'))
            if not basic.poll_for_system_status(data.MCLAG_2_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_S'))
            if not basic.poll_for_system_status(data.MCLAG_1_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_2_S'))
            if not basic.poll_for_system_status(data.MCLAG_2_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")
        else:
            ###############################################################################################
            # Failover of MCLAG devices : Active (MCLAG_1_A) and Standby (MCLAG_1_S)
            ###############################################################################################
            utils.banner_log("Failover of MCLAG devices : Active (MCLAG_1_A) and Standby (MCLAG_1_S) -- STARTED")
            reboot.config_save(data.MCLAG_1_A)
            reboot.config_save(data.MCLAG_1_S)
            api_list = list()
            api_list.append([st.reboot, data.MCLAG_1_A])
            api_list.append([st.reboot, data.MCLAG_1_S])
            [_, exceptions] = exec_all(True, api_list)
            ensure_no_exception(exceptions)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_A'))
            if not basic.poll_for_system_status(data.MCLAG_1_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_S'))
            if not basic.poll_for_system_status(data.MCLAG_1_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        # Additional wait time with reference to system up time for stp to become stable.
        st.wait(120, "Additional wait time with reference to system up time for stp to become stable.")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

        if res_1:
            if data.topology_2_tier:
                st.report_tc_pass('ft_{}_mlag_rootbridge_active_and_standby_failover_2_tier'.format(data.stp_protocol),'test_case_passed')
            else:
                if not data.topology_scale:
                    st.report_tc_pass('ft_{}_mlag_rootbridge_active_and_standby_failover'.format(data.stp_protocol),'test_case_passed')
                else:
                    st.report_tc_pass('ft_{}_scale_mclag_active_and_standby_failover'.format(data.stp_protocol),'test_case_passed')
        else:
            if data.topology_2_tier:
                st.report_tc_fail('ft_{}_mlag_rootbridge_active_and_standby_failover_2_tier'.format(data.stp_protocol),'test_case_failed')
            else:
                if not data.topology_scale:
                    st.report_tc_fail('ft_{}_mlag_rootbridge_active_and_standby_failover'.format(data.stp_protocol),'test_case_failed')
                else:
                    st.report_tc_fail('ft_{}_scale_mclag_active_and_standby_failover'.format(data.stp_protocol),'test_case_failed')
        utils.banner_log("Failover of MCLAG devices : Active and Standby -- COMPLETED")

    if res_1:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_config_reload():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        if data.topology_2_tier:
            ###############################################################################################
            # Config reload of MCLAG devices : Active (MCLAG_1_A, MCLAG_2_A) and Standby (MCLAG_1_S, MCLAG_2_S)
            ###############################################################################################
            utils.banner_log("Config reload of MCLAG devices : Active (MCLAG_1_A, MCLAG_2_A) and Standby (MCLAG_1_S, MCLAG_2_S) -- STARTED")
            reboot.config_save(data.MCLAG_1_A)
            reboot.config_save(data.MCLAG_2_A)
            reboot.config_save(data.MCLAG_1_S)
            reboot.config_save(data.MCLAG_2_S)
            api_list = list()
            api_list.append([reboot.config_reload, data.MCLAG_1_A])
            api_list.append([reboot.config_reload, data.MCLAG_2_A])
            api_list.append([reboot.config_reload, data.MCLAG_1_S])
            api_list.append([reboot.config_reload, data.MCLAG_2_S])
            [_, exceptions] = exec_all(True, api_list)
            ensure_no_exception(exceptions)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_A'))
            if not basic.poll_for_system_status(data.MCLAG_1_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_2_A'))
            if not basic.poll_for_system_status(data.MCLAG_2_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_S'))
            if not basic.poll_for_system_status(data.MCLAG_1_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_2_S'))
            if not basic.poll_for_system_status(data.MCLAG_2_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")
        else:
            ###############################################################################################
            # Config reload of MCLAG device : Active (MCLAG_1_A) and Standby (MCLAG_1_S)
            ###############################################################################################
            utils.banner_log("Config reload of MCLAG device : Active (MCLAG_1_A) and Standby (MCLAG_1_S) -- STARTED")
            reboot.config_save(data.MCLAG_1_A)
            reboot.config_save(data.MCLAG_1_S)
            api_list = list()
            api_list.append([reboot.config_reload, data.MCLAG_1_A])
            api_list.append([reboot.config_reload, data.MCLAG_1_S])
            [_, exceptions] = exec_all(True, api_list)
            ensure_no_exception(exceptions)

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_A'))
            if not basic.poll_for_system_status(data.MCLAG_1_A):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

            utils.banner_log("Polling for system status of DUT {}".format('MCLAG_1_S'))
            if not basic.poll_for_system_status(data.MCLAG_1_S):
                log_error("SYSTEM is not ready !!")
                st.report_fail("reboot_failed")

        # Wait for MCLAG to come up
        st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        # Additional wait time with reference to system up time for stp to become stable.
        st.wait(120, "Additional wait time with reference to system up time for stp to become stable.")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

        if res_1:
            if data.topology_2_tier:
                st.report_tc_pass('ft_{}_mlag_active_and_standby_config_reload_2_tier'.format(data.stp_protocol),'test_case_passed')
            else:
                if not data.topology_scale:
                    st.report_tc_pass('ft_{}_mlag_active_and_standby_config_reload'.format(data.stp_protocol),'test_case_passed')
                else:
                    st.report_tc_pass('ft_{}_scale_mclag_active_and_standby_config_reload'.format(data.stp_protocol),'test_case_passed')
        else:
            if data.topology_2_tier:
                st.report_tc_fail('ft_{}_mlag_active_and_standby_config_reload_2_tier'.format(data.stp_protocol),'test_case_failed')
            else:
                if not data.topology_scale:
                    st.report_tc_fail('ft_{}_mlag_active_and_standby_config_reload'.format(data.stp_protocol),'test_case_failed')
                else:
                    st.report_tc_fail('ft_{}_scale_mclag_active_and_standby_config_reload'.format(data.stp_protocol),'test_case_failed')
        utils.banner_log("Config reload of MCLAG devices : Active and Standby -- COMPLETED")

    if res_1:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_unconfig_config_mclag():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Unconfig of MCLAG on MCLAG_1_A, MCLAG_1_S, MCLAG_2_A and MCLAG_2_S
        ###############################################################################################
        # Unconfiguring MCLAG interfaces for all the domains
        utils.banner_log("Unconfiguring MCLAG interfaces for all the domains")
        if data.topology_2_tier:
            utils.banner_log("Unconfig of MCLAG on MCLAG_1_A, MCLAG_1_S, MCLAG_2_A and MCLAG_2_S -- STARTED")
            [_, exceptions] = exec_all(True, data.mclag_interfaces_del)
        else:
            utils.banner_log("Unconfig of MCLAG on MCLAG_1_A and MCLAG_1_S -- STARTED")
            [_, exceptions] = exec_all(True, data.mclag_interfaces_del_1)
        ensure_no_exception(exceptions)

        # Unconfiguring MCLAG domain on the MLCLAG peers
        utils.banner_log("Unconfiguring MCLAG domain on the MLCLAG peers")
        if data.topology_2_tier:
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_2_A, data.MCLAG_2_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "del"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)
            [_, exceptions] = exec_parallel(True, data.mclag_duts, mclag.config_domain, data.mclag_domain_del)
            ensure_no_exception(exceptions)
        else:
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "del"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)
            [_, exceptions] = exec_parallel(True, data.mclag_duts_domain_1, mclag.config_domain, data.mclag_domain_del_1)
            ensure_no_exception(exceptions)
        utils.banner_log("Unconfig of MCLAG Domains -- COMPLETED")

        # Wait time for MCLAG to stable.
        st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        if data.topology_2_tier:
            root_bridge_1 = stp.get_default_root_bridge([data.MCLAG_1_A, data.MCLAG_1_S])
            root_bridge_2 = stp.get_default_root_bridge([data.MCLAG_2_A, data.MCLAG_2_S])
            stp_data = {root_bridge_2: {"vlan":data.normal_vlans[0]}, root_bridge_1: {"vlan":data.normal_vlans[1]}, data.MCLAG_CLIENT: {"vlan":data.normal_vlans[2]}}
            for dut, dut_data in stp_data.items():
                if stp.poll_for_root_switch(dut, dut_data["vlan"], iteration=10, delay=4):
                    st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut, dut_data["vlan"]))
                else:
                    log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(dut, dut_data["vlan"]))
                    res_1 = False
        else:
            root_bridge = stp.get_default_root_bridge([data.MCLAG_1_A, data.MCLAG_1_S])
            if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
                stp_data = {data.MCLAG_2_A: {"vlan":data.normal_vlans[0]}, root_bridge: {"vlan":data.normal_vlans[1]}, data.MCLAG_CLIENT: {"vlan":data.normal_vlans[2]}}
                for dut, dut_data in stp_data.items():
                    if stp.poll_for_root_switch(dut, dut_data["vlan"], iteration=10, delay=4):
                        st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut, dut_data["vlan"]))
                    else:
                        log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(dut, dut_data["vlan"]))
                        res_1 = False
            else:
                if stp.poll_for_root_switch(root_bridge, data.normal_vlans[0], iteration=10, delay=4):
                    st.log("SUCCESSFULL : {} is root switch for vlan {}".format(root_bridge, data.normal_vlans[0]))
                else:
                    log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(root_bridge, data.normal_vlans[0]))
                    res_1 = False
                if stp.poll_for_root_switch(root_bridge, data.normal_vlans[1], iteration=10, delay=4):
                    st.log("SUCCESSFULL : {} is root switch for vlan {}".format(root_bridge, data.normal_vlans[1]))
                else:
                    log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(root_bridge, data.normal_vlans[1]))
                    res_1 = False
                if stp.poll_for_root_switch(root_bridge, data.normal_vlans[2], iteration=10, delay=4):
                    st.log("SUCCESSFULL : {} is root switch for vlan {}".format(root_bridge, data.normal_vlans[2]))
                else:
                    log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(root_bridge, data.normal_vlans[2]))
                    res_1 = False

        ###############################################################################################
        # Config of MCLAG on MCLAG_1_A, MCLAG_1_S, MCLAG_2_A and MCLAG_2_S
        ###############################################################################################
        # Configuring MCLAG domain on the MCLAG peers
        utils.banner_log("Configuring MCLAG domain on the MLCLAG peers")
        if data.topology_2_tier:
            utils.banner_log("Config of MCLAG on MCLAG_1_A, MCLAG_1_S, MCLAG_2_A and MCLAG_2_S -- STARTED")
            [_, exceptions] = exec_parallel(True, data.mclag_duts, mclag.config_domain, data.mclag_domain)
            ensure_no_exception(exceptions)
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S, data.MCLAG_2_A, data.MCLAG_2_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_2_DOMAIN_ID, 'mac': "00:00:00:00:00:22", 'config': "add"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)
        else:
            utils.banner_log("Config of MCLAG on MCLAG_1_A and MCLAG_1_S -- STARTED")
            [_, exceptions] = exec_parallel(True, data.mclag_duts_domain_1, mclag.config_domain, data.mclag_domain_1)
            ensure_no_exception(exceptions)
            duts_list = [data.MCLAG_1_A, data.MCLAG_1_S]
            command_list = list()
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            command_list.append({'domain_id': data.MCLAG_1_DOMAIN_ID, 'mac': "00:00:00:00:00:11", 'config': "add"})
            [_, exceptions] = exec_parallel(True, duts_list, mclag.config_mclag_system_mac, command_list)
            ensure_no_exception(exceptions)

        # Configuring MCLAG interfaces for all the domains
        utils.banner_log("Configuring MCLAG interfaces for all the domains")
        if data.topology_2_tier:
            [_, exceptions] = exec_all(True, data.mclag_interfaces)
        else:
            [_, exceptions] = exec_all(True, data.mclag_interfaces_1)
        ensure_no_exception(exceptions)
        utils.banner_log("Config of MCLAG Domains-- COMPLETED")

        # Wait time for MCLAG to stable.
        st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

        # Wait time for stp to converge
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

    if res_1:
        if data.topology_2_tier:
            st.report_tc_pass('ft_{}_mlag_unconfig_config_mclag_2_tier'.format(data.stp_protocol),'test_case_passed')
        else:
            st.report_tc_pass('ft_{}_mlag_unconfig_config_mclag'.format(data.stp_protocol),'test_case_passed')
        data.stable_state_check_at_test_start = False
        return True
    else:
        if data.topology_2_tier:
            st.report_tc_fail('ft_{}_mlag_unconfig_config_mclag_2_tier'.format(data.stp_protocol),'test_case_failed')
        else:
            st.report_tc_fail('ft_{}_mlag_unconfig_config_mclag'.format(data.stp_protocol),'test_case_failed')
        return False

def lib_stp_mclag_peer_link_tests():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Checking FDB for mac address on MCLAG_1_A and MCLAG_1_S
        ###############################################################################################
        utils.banner_log("Checking FDB for mac address on MCLAG_1_A and MCLAG_1_S")
        if mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:04", vlan=data.normal_vlans[0], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:04", vlan=data.normal_vlans[1], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:04", vlan=data.normal_vlans[2], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag):
            st.log("FDB check on MCLAG_1_A for East to West traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_A for East to West traffic : FAILED")
            res_1 = False

        if mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:03", vlan=data.normal_vlans[0], port=data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:03", vlan=data.normal_vlans[1], port=data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:03", vlan=data.normal_vlans[2], port=data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag):
            st.log("FDB check on MCLAG_1_S for East to West traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_S for East to West traffic : FAILED")
            res_1 = False

        ###############################################################################################
        # Shutting down the Peerlink and Keepalive link between MCLAG_1_A and MCLAG_1_S
        ###############################################################################################
        utils.banner_log("Shutting down the Peerlink and Keepalive link between MCLAG_1_A and MCLAG_1_S")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link , "shutdown")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag , "shutdown")
        if not intf.poll_for_interface_status(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, "oper", "down", iteration=10, delay=1):
            intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, "startup")
            intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, "startup")

            log_error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A))
            st.report_fail("interface_is_up_on_dut", data.MCLAG_1_A)
        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, "down", iteration=10, delay=1):
            log_error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, data.MCLAG_1_A))
            st.report_fail("interface_is_up_on_dut", data.MCLAG_1_A)

        # Wait time for MCLAG to stable.
        st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

        utils.banner_log("Checking for STP convergence : ROOT BRIDGE BASED ON CONFIGURED BRIDGE PRIORITY")
        duts_mac_list = {data.MCLAG_1_A: "010000000011", data.MCLAG_1_S: "010000000022"}
        min_mac_addr = min(duts_mac_list.values())
        root_bridge = [dut for dut, mac_addr in duts_mac_list.items() if mac_addr == min_mac_addr][0]
        root_bridge = [dut for dut in [data.MCLAG_1_A, data.MCLAG_1_S] if dut == root_bridge][0]

        st.log("ROOT BRIDGE BASED ON MCLAG SYSTEM MAC IS : {} and MCLAG SYSTEM MAC IS : {}".format(root_bridge, min_mac_addr))
        if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
            stp_data = {data.MCLAG_2_A: {"vlan":data.normal_vlans[0]}, root_bridge: {"vlan":data.normal_vlans[1]}, data.MCLAG_CLIENT: {"vlan":data.normal_vlans[2]}}
            for dut, dut_data in stp_data.items():
                if stp.poll_for_root_switch(dut, dut_data["vlan"], iteration=10, delay=4):
                    st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut, dut_data["vlan"]))
                else:
                    log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(dut, dut_data["vlan"]))
                    res_1 = False
        else:
            if stp.poll_for_root_switch(root_bridge, data.normal_vlans[0], iteration=10, delay=4):
                st.log("SUCCESSFULL : {} is root switch for vlan {}".format(root_bridge, data.normal_vlans[0]))
            else:
                log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(root_bridge, data.normal_vlans[0]))
                res_1 = False
            if stp.poll_for_root_switch(root_bridge, data.normal_vlans[1], iteration=10, delay=4):
                st.log("SUCCESSFULL : {} is root switch for vlan {}".format(root_bridge, data.normal_vlans[1]))
            else:
                log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(root_bridge, data.normal_vlans[1]))
                res_1 = False
            if stp.poll_for_root_switch(root_bridge, data.normal_vlans[2], iteration=10, delay=4):
                st.log("SUCCESSFULL : {} is root switch for vlan {}".format(root_bridge, data.normal_vlans[2]))
            else:
                log_error("UNSUCCESSFULL : {} is not root switch for vlan {}".format(root_bridge, data.normal_vlans[2]))
                res_1 = False

        if data.stp_protocol == "pvst" or (data.stp_protocol == "rpvst" and data.mclag_peers_as_only_root == False):
            if not check_traffic("both", "forward", False):
                res_1 = False

        ###############################################################################################
        # Starting up the Peerlink between MCLAG_1_A and MCLAG_1_S
        ###############################################################################################
        utils.banner_log("Starting up the Peerlink between MCLAG_1_A and MCLAG_1_S")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link , "startup")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag , "startup")
        if not intf.poll_for_interface_status(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, "oper", "up", iteration=10, delay=1):
            log_error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_To_MCLAG_1_S_Keep_Alive_Link, data.MCLAG_1_A))
            st.report_fail("interface_is_down_on_dut", data.MCLAG_1_A)
        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, "up", iteration=10, delay=1):
            log_error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag, data.MCLAG_1_A))
            st.report_fail("interface_is_down_on_dut", data.MCLAG_1_A)

        # Wait time for MCLAG to stable.
        st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

        # Wait time STP to converge.
        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")
        if not check_stable_state(stp=True, mclag=True, traffic=True):
            res_1 = False

        ###############################################################################################
        # Checking FDB for mac address on MCLAG_1_A and MCLAG_1_S
        ###############################################################################################
        utils.banner_log("Checking FDB for mac address on MCLAG_1_A and MCLAG_1_S")
        if mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:04", vlan=data.normal_vlans[0], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:04", vlan=data.normal_vlans[1], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_A, "00:00:00:00:00:04", vlan=data.normal_vlans[2], port=data.MCLAG_1_A_To_MCLAG_1_S_Peer_Lag):
            st.log("FDB check on MCLAG_1_A for East to West traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_A for East to West traffic : FAILED")
            res_1 = False

        if mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:03", vlan=data.normal_vlans[0], port=data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:03", vlan=data.normal_vlans[1], port=data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag) and mac.verify_mac_address_table(data.MCLAG_1_S, "00:00:00:00:00:03", vlan=data.normal_vlans[2], port=data.MCLAG_1_S_To_MCLAG_1_A_Peer_Lag):
            st.log("FDB check on MCLAG_1_S for East to West traffic : PASSED")
        else:
            log_error("FDB check on MCLAG_1_S for East to West traffic : FAILED")
            res_1 = False

        if res_1:
            st.report_tc_pass('ft_{}_mlag_peerlink_down'.format(data.stp_protocol),'test_case_passed')
        else:
            st.report_tc_fail('ft_{}_mlag_peerlink_down'.format(data.stp_protocol),'test_case_failed')

    if res_1:
        data.stable_state_check_at_test_start = False
        return True
    else:
        return False

def lib_stp_mclag_port_fast():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Disabling STP on MCLAG interface on MCLAG CLIENT
        ###############################################################################################
        utils.banner_log("Disabling STP on MCLAG interface on MCLAG CLIENT")
        stp.config_stp_enable_interface(data.MCLAG_CLIENT, data.MCLAG_CLIENT_MC_Lag_1, mode="disable")

        ###############################################################################################
        # Shutting down the MCLAG interface on MCLAG Peers
        ###############################################################################################
        utils.banner_log("Shutting down the MCLAG interface on MCLAG Peers")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "shutdown")
        intf.interface_operation(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1 , "shutdown")

        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "down", iteration=10, delay=1):
            intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "startup")
            log_error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, "down", iteration=10, delay=1):
            intf.interface_operation(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1 , "startup")
            log_error("Failed to shutdown interface {} on the DUT {}".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))

        ###############################################################################################
        # Starting up the MCLAG interface on MCLAG Peers
        ###############################################################################################
        utils.banner_log("Starting up the MCLAG interface on MCLAG Peers")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "startup")
        intf.interface_operation(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1 , "startup")

        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, "up", iteration=10, delay=1):
            log_error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
        if not portchannel.poll_for_portchannel_status(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, "up", iteration=10, delay=1):
            log_error("Failed to startup interface {} on the DUT {}".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))

        ###############################################################################################
        # Verification of default port fast config on MCLAG interface on both MCLAG peers
        ###############################################################################################
        utils.banner_log("Verification of default port fast config on MCLAG interface on both MCLAG peers -- STARTED")
        port_fast_A = stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_portfast")
        port_fast_S = stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_portfast")
        if port_fast_A == "N" and port_fast_S == "N":
            st.log("Port fast is by default disabled on MCLAG interface on both the MCLAG peers.")
        else:
            log_error("Port fast is by default not disabled on MCLAG interface on both the MCLAG peers.")
            res_1 = False
        utils.banner_log("Verification of default port fast config on MCLAG interface on both MCLAG peers -- COMPLETED")

        ###############################################################################################
        # Enabling port fast config on MCLAG interface on both MCLAG peers
        ###############################################################################################
        utils.banner_log("Enabling port fast config on MCLAG interface on both MCLAG peers")
        stp.config_stp_interface_params(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, portfast="enable")
        stp.config_stp_interface_params(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, portfast="enable")
        st.wait(2)
        port_fast_A = stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_portfast")
        port_fast_S = stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_portfast")
        if port_fast_A == "Y" and port_fast_S == "Y":
            st.log("Port fast is enabled on MCLAG interface on both the MCLAG peers.")
        else:
            log_error("Port fast is no enabled on MCLAG interface on both the MCLAG peers.")
            res_1 = False

        ###############################################################################################
        # Verification of portfast enabled port is immediately moved to Forwarding state after enabling port fast
        ###############################################################################################
        utils.banner_log("Verification of portfast enabled port is immediately moved to Forwarding state after enabling port fast -- STARTED")
        if not stp.poll_for_stp_status(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, 'FORWARDING', iteration=10, delay=1):
            log_error("Interface {} on dut {} is not moving to Forwarding state immediately".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            res_1 = False
        else:
            st.log("Interface {} on dut {} is moving to Forwarding state immediately".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))

        if not stp.poll_for_stp_status(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, 'FORWARDING', iteration=10, delay=1):
            log_error("Interface {} on dut {} is not moving to Forwarding state immediately".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
            res_1 = False
        else:
            st.log("Interface {} on dut {} is moving to Forwarding state immediately".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
        utils.banner_log("Verification of portfast enabled port is immediately moved to Forwarding state after enabling port fast -- COMPLETED")

        ###############################################################################################
        # Enabling STP on MCLAG interface on MCLAG CLIENT
        ###############################################################################################
        utils.banner_log("Enabling STP on MCLAG interface on MCLAG CLIENT")
        stp.config_stp_enable_interface(data.MCLAG_CLIENT, data.MCLAG_CLIENT_MC_Lag_1, mode="enable")

        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")
        if not stp.poll_for_stp_status(data.MCLAG_CLIENT, data.normal_vlans[2], data.MCLAG_CLIENT_MC_Lag_1, 'FORWARDING', iteration=10, delay=1):
            log_error("Interface {} on dut {} is not moving to Forwarding state".format(data.MCLAG_CLIENT_MC_Lag_1, data.MCLAG_CLIENT))
            res_1 = False
        else:
            st.log("Interface {} on dut {} is moving to Forwarding state".format(data.MCLAG_CLIENT_MC_Lag_1, data.MCLAG_CLIENT))

        ###############################################################################################
        # Verification of port fast config on MCLAG interface on both MCLAG peers after receiving stp bpdu
        ###############################################################################################
        utils.banner_log("Verification of port fast config on MCLAG interface on both MCLAG peers -- STARTED")
        port_fast_A = stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_portfast")
        port_fast_S = stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_portfast")
        if port_fast_A == "N" and port_fast_S == "N":
            st.log("Port fast is disabled on MCLAG interface on both the MCLAG peers after receiving stp bpdu.")
        else:
            log_error("Port fast is not disabled on MCLAG interface on both the MCLAG peers after receiving stp bpdu.")
            res_1 = False
        utils.banner_log("Verification of port fast config on MCLAG interface on both MCLAG peers after receiving stp bpdu -- COMPLETED")

        ###############################################################################################
        # Verification of portfast enabled port is moved to Forwarding state after enabling STP on MCLAG Client
        ###############################################################################################
        utils.banner_log("Verification of portfast enabled port is moved to Forwarding state after enabling STP on MCLAG Client -- STARTED")
        if not stp.poll_for_stp_status(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, 'FORWARDING', iteration=data.stp_dict[data.stp_protocol]["stp_wait_time"], delay=1):
            log_error("Interface {} on dut {} is not moving to Forwarding state after enabling STP on MCLAG Client".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            res_1 = False
        else:
            st.log("Interface {} on dut {} is moving to Forwarding state after enabling STP on MCLAG Client".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))

        if not stp.poll_for_stp_status(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, 'FORWARDING', iteration=data.stp_dict[data.stp_protocol]["stp_wait_time"], delay=1):
            log_error("Interface {} on dut {} is not moving to Forwarding state after enabling STP on MCLAG Client".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
            res_1 = False
        else:
            st.log("Interface {} on dut {} is moving to Forwarding state after enabling STP on MCLAG Client".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
        utils.banner_log("Verification of portfast enabled port is moved to Forwarding state after enabling STP on MCLAG Client -- COMPLETED")

    if not check_stable_state(stp=True, mclag=True, traffic=True):
        res_1 = False

    if res_1:
        st.report_tc_pass('ft_{}_mlag_port_fast'.format(data.stp_protocol),'test_case_passed')
        data.stable_state_check_at_test_start = False
        return True
    else:
        st.report_tc_fail('ft_{}_mlag_port_fast'.format(data.stp_protocol),'test_case_failed')
        return False

def lib_stp_mclag_bpdu_guard():
    res_1 = True

    if not check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart"):
        res_1 = False
    else:
        ###############################################################################################
        # Enabling BPDU Guard on MCLAG interface on both the MCLAG peers
        ###############################################################################################
        utils.banner_log("Enabling BPDU Guard on MCLAG interface on both the MCLAG peers")
        stp.config_stp_interface_params(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, bpdu_guard="enable")
        stp.config_stp_interface_params(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, bpdu_guard="enable")

        st.wait(5)
        if not stp.check_bpdu_guard_action(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, config_shut="No", opr_shut="NA"):
            log_error("Interface {} on DUT {} is not enabled with proper BPDU guard parameters".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} is configured with proper BPDU guard options when shutdown is not configured".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))

        if not stp.check_bpdu_guard_action(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, config_shut="No", opr_shut="NA"):
            log_error("Interface {} on DUT {} is not enabled with proper BPDU guard parameters".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} is configured with proper BPDU guard options when shutdown is not configured".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))

        ###############################################################################################
        # Enabling BPDU guard shutdown on MCLAG interface on both the MCLAG peers
        ###############################################################################################
        utils.banner_log("Enabling BPDU Guard shutdown on MCLAG interface on both the MCLAG peers")
        stp.config_stp_interface_params(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, bpdu_guard_action="--shutdown")
        stp.config_stp_interface_params(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, bpdu_guard_action="--shutdown")

        st.wait(5)
        if not stp.check_bpdu_guard_action(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, config_shut="Yes", opr_shut="Yes"):
            log_error("Interface {} on DUT {} is not enabled with BPDU guard shutdown parameters".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} is enabled with BPDU guard shutdown parameters".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))

        if not stp.check_bpdu_guard_action(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, config_shut="Yes", opr_shut="Yes"):
            log_error("Interface {} on DUT {} is not enabled with BPDU guard shutdown parameters".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} is enabled with BPDU guard shutdown parameters".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))

        st.wait(5)
        if not stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_state") == "BPDU-DIS":
            log_error("Interface {} on DUT {} did not move to disabled state when BPDU shutdown action is configured and DUT received a BPDU".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} moved to BPDU-DIS state as expected".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))

        if not stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_state") == "BPDU-DIS":
            log_error("Interface {} on DUT {} did not move to disabled state when BPDU shutdown action is configured and DUT received a BPDU".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} moved to BPDU-DIS state as expected".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))

        ###############################################################################################
        # Disabling STP on MCLAG interface on MCLAG CLIENT
        ###############################################################################################
        utils.banner_log("Disabling STP on MCLAG interface on MCLAG CLIENT")
        stp.config_stp_enable_interface(data.MCLAG_CLIENT, data.MCLAG_CLIENT_MC_Lag_1, mode="disable")

        ###############################################################################################
        # Shutting down and starting up the MCLAG interface on MCLAG Peers
        ###############################################################################################
        utils.banner_log("Shutting down and starting up the MCLAG interface on MCLAG Peers")
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "shutdown")
        intf.interface_operation(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1 , "shutdown")
        st.wait(2)
        intf.interface_operation(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1 , "startup")
        intf.interface_operation(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1 , "startup")

        st.wait(5)
        if stp.get_stp_port_param(data.MCLAG_1_A, data.normal_vlans[2], data.MCLAG_1_A_MC_Lag_1, "port_state") == "BPDU-DIS":
            log_error("Interface {} on DUT {} moved to disabled state when BPDU shutdown action is configured and DUT did not receive a BPDU".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} did not move to disabled state when BPDU shutdown action is configured and DUT did not receive a BPDU".format(data.MCLAG_1_A_MC_Lag_1, data.MCLAG_1_A))

        if stp.get_stp_port_param(data.MCLAG_1_S, data.normal_vlans[2], data.MCLAG_1_S_MC_Lag_1, "port_state") == "BPDU-DIS":
            log_error("Interface {} on DUT {} moved to disabled state when BPDU shutdown action is configured and DUT did not receive a BPDU".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))
            res_1 = False
        else:
            st.log("Interface {} on DUT {} did not move to disabled state when BPDU shutdown action is configured and DUT did not receive a BPDU".format(data.MCLAG_1_S_MC_Lag_1, data.MCLAG_1_S))

        ###############################################################################################
        # Disabling BPDU Guard on MCLAG interface on both the MCLAG peers
        ###############################################################################################
        utils.banner_log("Disabling BPDU Guard on MCLAG interface on both the MCLAG peers")
        stp.config_stp_interface_params(data.MCLAG_1_A, data.MCLAG_1_A_MC_Lag_1, bpdu_guard="disable")
        stp.config_stp_interface_params(data.MCLAG_1_S, data.MCLAG_1_S_MC_Lag_1, bpdu_guard="disable")

        ###############################################################################################
        # Enabling STP on MCLAG interface on MCLAG CLIENT
        ###############################################################################################
        utils.banner_log("Enabling STP on MCLAG interface on MCLAG CLIENT")
        stp.config_stp_enable_interface(data.MCLAG_CLIENT, data.MCLAG_CLIENT_MC_Lag_1, mode="enable")

        st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")
        if not stp.poll_for_stp_status(data.MCLAG_CLIENT, data.normal_vlans[2], data.MCLAG_CLIENT_MC_Lag_1, 'FORWARDING', iteration=10, delay=1):
            log_error("Interface {} on dut {} is not moving to Forwarding state".format(data.MCLAG_CLIENT_MC_Lag_1, data.MCLAG_CLIENT))
            res_1 = False
        else:
            st.log("Interface {} on dut {} is moving to Forwarding state".format(data.MCLAG_CLIENT_MC_Lag_1, data.MCLAG_CLIENT))

    if not check_stable_state(stp=True, mclag=True, traffic=True):
        res_1 = False

    if res_1:
        st.report_tc_pass('ft_{}_mlag_bpdu_guard'.format(data.stp_protocol),'test_case_passed')
        data.stable_state_check_at_test_start = False
        return True
    else:
        st.report_tc_fail('ft_{}_mlag_bpdu_guard'.format(data.stp_protocol),'test_case_failed')
        return False

def lib_stp_mclag_all_intf_shut_noshut():
    ###############################################################################################
    # Checking stable state of the topology before shut and no shut of all the interfaces
    ###############################################################################################
    utils.banner_log("Checking stable state of the topology before shut and no shut of all the interfaces")
    check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart")

    ###############################################################################################
    # Shutting down and starting up of all interfaces on the random DUT in the topology
    ###############################################################################################
    utils.banner_log("Shutting down and starting up of all interfaces on the random DUT in the topology")
    dut_test = random.choice(data.dut_list)
    intf_list = stp.get_stp_port_list(dut_test, data.normal_vlans[0], exclude_port="")
    intf.interface_operation(dut_test, intf_list , "shutdown")
    st.wait(5)
    intf.interface_operation(dut_test, intf_list , "startup")

    # Wait time for MCLAG to stable.
    st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

    # Wait time STP to converge.
    st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

    ###############################################################################################
    # Checking stable state of the topology after shut and no shut of all the interfaces
    ###############################################################################################
    utils.banner_log("Checking stable state of the topology after shut and no shut of all the interfaces")
    check_stable_state(stp=True, mclag=True, traffic=True)
    data.stable_state_check_at_test_start = False
    return True

def lib_stp_mclag_vlan_participation_del_add():
    ###############################################################################################
    # Checking stable state of the topology before vlan participation delete/add of all the interfaces
    ###############################################################################################
    utils.banner_log("Checking stable state of the topology before vlan participation delete/add of all the interfaces")
    check_stable_state(stp=True, mclag=True, traffic=True, checkType="testStart")

    ###############################################################################################
    # Vlan participation delete/add of all interfaces on the random DUT in the topology
    ###############################################################################################
    utils.banner_log("Vlan participation delete/add of all interfaces on the random DUT in the topology")
    dut_test = random.choice(data.dut_list)
    intf_list = stp.get_stp_port_list(dut_test, data.normal_vlans[0], exclude_port="")
    vapi.config_vlan_members(dut_test, data.normal_vlans[0], intf_list, config="del", tagged=True)
    st.wait(5)
    vapi.config_vlan_members(dut_test, data.normal_vlans[0], intf_list, config="add", tagged=True)

    # Wait time for MCLAG to stable.
    st.wait(data.mclag_wait_time, "Wait time for MCLAG to become stable.")

    # Wait time STP to converge.
    st.wait(data.stp_dict[data.stp_protocol]["stp_wait_time"], "Wait time for stp to converge")

    ###############################################################################################
    # Checking stable state of the topology after vlan participation delete/add of all the interfaces
    ###############################################################################################
    utils.banner_log("Checking stable state of the topology after vlan participation delete/add of all the interfaces")
    check_stable_state(stp=True, mclag=True, traffic=True)
    data.stable_state_check_at_test_start = False
    return True