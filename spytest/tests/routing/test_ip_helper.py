import pytest
from random import randint
from spytest import st, tgapi, SpyTestDict

from apis.routing.ip import config_unconfig_interface_ip_addresses, clear_ip_configuration, verify_interface_ip_address, get_interface_ip_address
from spytest.utils import random_vlan_list
from  apis.switching.vlan import create_vlan, add_vlan_member, clear_vlan_configuration, verify_vlan_config, show_vlan_config, delete_vlan, delete_vlan_member
import apis.routing.ip_helper as ip_helper_obj
from apis.switching.portchannel import *
from apis.system.interface import clear_interface_counters, show_interface_counters_detailed
from apis.routing.vrf import config_vrf, bind_vrf_interface, verify_vrf_verbose, get_vrf_verbose
from apis.system.reboot import config_save, verify_warm_restart
from apis.system.basic import service_operations_by_systemctl, verify_service_status, poll_for_system_status

data                    = SpyTestDict()

data.ipv4_addr_intf     = {
                           "d1t1p1_ip": "10.10.10.10",
                           "d1t1p2_ip": "20.20.20.20",
                           "d1t1p3_ip": "30.30.30.30",
                           "d1t1p4_ip": "40.40.40.40",
                          }
data.ipv4_addr_tg       = {
                           "t1d1p1_ip": "10.10.10.1",
                           "t1d1p2_ip": "20.20.20.1",
                           "t1d1p3_ip": "30.30.30.1",
                           "t1d1p4_ip": "40.40.40.1",
                          }

data.protocol_ports     = {
                           'tftp': '69',
                           'ntp': '37',
                           'dns': '53',
                           'tacacs': '49',
                           'nbname': '137',
                           'nbdatagram': '138',
                          }

data.tg_macs            = {
                           "tg1_mac": "00:00:00:00:00:11",
                           "tg2_mac": "00:00:00:00:11:22",
                           "tg3_mac": "00:00:00:00:22:33",
                           "tg4_mac": "00:00:00:00:33:44",
                          }

data.streams            = {
                           "tg1": {},
                           "tg2": {},
                          }

data.af_ipv4            = "ipv4"
data.ip_helper_address  = ["30.30.30.1", "40.40.40.1"]
data.bcast_ip           = "255.255.255.255"
data.vlan_list          = random_vlan_list(count=4)
data.port_channel       = "PortChannel{}".format(randint(1, 256))
data.bcast_mac          = "ff:ff:ff:ff:ff:ff"
data.ipv4_mask          = '24'
data.vrf_name           = ["Vrf10", "Vrf30"]
data.hlpr_debug_prints  = False

header_li               = [
                           'IP:Protocol',
                           'IP:Source',
                           'IP:Destination',
                           'UDP:Destination Port'
                          ]

proto_udp_port          = {
                           'tftp': '0045',
                           'ntp': '0025',
                           'dns': '0035',
                           'tacacs': '0031',
                           'nbname': '0089',
                           'nbdatagram': '008A',
                           'dhcp': '0043',
                           'custom1': '008C',
                           'custom2': '0096',
                           'tcp': '0045',
                          }


@pytest.fixture(scope="module", autouse=True)
def ip_helper_module_config(request):
    ip_helper_tplg()
    clear_ip_configuration(vars.D1)
    clear_ip_configuration(vars.D1, 'ipv6')
    clear_vlan_configuration(vars.D1)
    clear_portchannel_configuration(vars.D1)
    data.cli_type = st.get_ui_type(vars.D1)
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=140)
        ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=150)

    yield
    # implement this part, which is used for clean-up
    util_remove_tg_hosts()
    tgapi.traffic_action_control(tg_handler, actions=['reset', 'clear_stats'])


@pytest.fixture(scope="function", autouse=True)
def ip_helper_func_hooks(request):

    yield

    if st.get_func_name(request) == "test_ip_helper_default_protocols_on_non_default_vrf":
        if verify_vrf_verbose(vars.D1, vrfname=data.vrf_name, interface=[[client_dut_intf['c1_intf']], [server_dut_intf['s1_intf']]]):
            util_clean_up_vrf(client_dut_intf['c1_intf'], data.vrf_name[0])
            util_clean_up_vrf(server_dut_intf['s1_intf'], data.vrf_name[1])

    if st.get_func_name(request) == "test_ip_helper_default_protocols_on_vlan_routing_intf":
        if verify_vrf_verbose(vars.D1, vrfname=data.vrf_name, interface=[["Vlan{}".format(data.vlan_list[1])], ["Vlan{}".format(data.vlan_list[3])]]):
            util_clean_up_vrf("Vlan{}".format(data.vlan_list[1]), data.vrf_name[0])
            util_clean_up_vrf("Vlan{}".format(data.vlan_list[3]), data.vrf_name[1])

        if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
            ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=140)
            ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=150)

    ip_helper_obj.clear_stats(vars.D1)
    clear_interface_counters(vars.D1)
    clear_ip_configuration(vars.D1)
    delete_vlan(vars.D1, data.vlan_list)
    clear_portchannel_configuration(vars.D1)


# Create default protocol streams
def util_create_tg_streams (tg_port_handle, prot_port_di=data.protocol_ports, ip_ttl_val = 255):
    if tg_port_handle == tg_handler["tg_ph_1"]:
        st.log("Create UDP streams on TG1 port.")
        for port_key in prot_port_di.keys():
            if port_key not in data.streams["tg1"].keys():
                st.log("Creating UDP stream for {} on TG1 port.".format(port_key))
                tg1_stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"],
                                                  mode='create',
                                                  transmit_mode='single_burst',
                                                  length_mode='fixed',
                                                  l2_encap='ethernet_ii',
                                                  rate_pps='2',
                                                  pkts_per_burst='1',
                                                  mac_src=data.tg_macs['tg1_mac'],
                                                  mac_dst=data.bcast_mac,
                                                  l3_protocol='ipv4',
                                                  ip_ttl =ip_ttl_val,
                                                  ip_src_addr=data.ipv4_addr_tg["t1d1p1_ip"],
                                                  ip_dst_addr=data.bcast_ip,
                                                  l4_protocol='udp',
                                                  udp_src_port='4001',
                                                  duration=1,
                                                  udp_dst_port=prot_port_di[port_key])

                data.streams["tg1"][port_key] = tg1_stream["stream_id"]

    elif tg_port_handle == tg_handler["tg_ph_2"]:
        st.log("Create UDP streams on TG2 port.")
        for port_key in prot_port_di.keys():
            if port_key not in data.streams["tg2"].keys():
                st.log("Creating UDP stream for {} on TG2 port.".format(port_key))
                tg2_stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"],
                                                  mode='create',
                                                  transmit_mode='single_burst',
                                                  length_mode='fixed',
                                                  l2_encap='ethernet_ii',
                                                  rate_pps='2',
                                                  pkts_per_burst='1',
                                                  mac_src=data.tg_macs['tg2_mac'],
                                                  mac_dst=data.bcast_mac,
                                                  l3_protocol='ipv4',
                                                  ip_ttl =ip_ttl_val,
                                                  ip_src_addr=data.ipv4_addr_tg["t1d1p2_ip"],
                                                  ip_dst_addr=data.bcast_ip,
                                                  l4_protocol='udp',
                                                  udp_src_port='4002',
                                                  duration=1,
                                                  udp_dst_port=prot_port_di[port_key])

                data.streams["tg2"][port_key] = tg2_stream["stream_id"]
    else:
        st.log("Failed to create streams for the port.")


# Remove TG hosts which acted as servers
def util_remove_tg_hosts():
    st.log("Removing hosts config on {} and {} ports.".format(vars.T1D1P3, vars.T1D1P4))
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_3"],
                           handle=data.server1['handle'],
                           mode='destroy')

    tg.tg_interface_config(port_handle=tg_handler["tg_ph_4"],
                           handle=data.server2['handle'],
                           mode='destroy')


# Create TG hosts whcih act as servers
def util_create_tg_hosts():
    st.log("Config {} and {} as hosts which acts as servers.".format(vars.T1D1P3, vars.T1D1P4))
    data.server1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_3"],
                                          mode='config',
                                          intf_ip_addr=data.ipv4_addr_tg['t1d1p3_ip'],
                                          gateway=data.ipv4_addr_intf['d1t1p3_ip'],
                                          src_mac_addr=data.tg_macs['tg3_mac'],
                                          arp_send_req='1')

    st.log("TG3 conf: " + str(data.server1))

    data.server2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_4"],
                                          mode='config',
                                          intf_ip_addr=data.ipv4_addr_tg['t1d1p4_ip'],
                                          gateway=data.ipv4_addr_intf['d1t1p4_ip'],
                                          src_mac_addr=data.tg_macs['tg4_mac'],
                                          arp_send_req='1')
    st.log("TG4 conf: " + str(data.server2))


# Initialize TG ports
def util_tg_ports_init(vars, tg_port_list):
    st.log("Reset and clear stats for TG ports")
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler_l = tgapi.get_handles(vars, tg_port_list)
    tgapi.traffic_action_control(tg_handler_l, actions=['reset','clear_stats'])
    return tg_handler_l


"""
Topology:
                                  +---------------+
       TG1 (client-1) <---------->|               |<----------> (Server-1) TG3
                                  |     DUT       |
       TG1 (client-2) <---------->|               |<----------> (server-2) TG4
                                  +---------------+
"""


# Ensure minimum topology and initialize parameters
def ip_helper_tplg():
    global vars
    global tg_handler, tg
    global client_dut_intf, server_dut_intf

    vars = st.ensure_min_topology("D1T1:4")

    tg_handler = util_tg_ports_init(vars, [vars.T1D1P1, vars.T1D1P2, vars.T1D1P3, vars.T1D1P4])
    tg         = tg_handler["tg"]

    client_dut_intf = {'c1_intf': vars.D1T1P1, 'c2_intf': vars.D1T1P2}
    server_dut_intf = {'s1_intf': vars.D1T1P3, 's2_intf': vars.D1T1P4}

    util_create_tg_hosts()


# Packet capture and counters validation
def send_and_validate_helper_traffic(client_intf, server_intf, stream_id, tg_txhandler, tg_rxhandler, header_li, value_li, stream_duration='1', validation_param_val=None, helper_intf=None):
    if helper_intf is None:
        helper_intf = client_intf

    # Reset TG ports Tx and Rx statistics
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_txhandler)
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_rxhandler)

    # Clear relay statistics and verify that the statistics are cleared.
    ip_helper_obj.clear_stats(vars.D1)

    # Clear interface counters of DUT
    clear_interface_counters(vars.D1)

    if data.hlpr_debug_prints:
        show_interface_counters_detailed(vars.D1, server_intf)
        show_interface_counters_detailed(vars.D1, client_intf)
        ip_helper_obj.show(vars.D1, statistics=helper_intf)

    # Verify IP helper stats reset for the interface
    if not ip_helper_obj.verify(vars.D1, statistics=helper_intf, verify_list=[{'packets_received': '0'}, {'packets_relayed': '0'}]):
        st.log("Error! Interface {} helper stats are not cleared.".format(client_intf))
        return False

    # Start packet capture
    tg.tg_packet_control(port_handle=tg_rxhandler, action='start')

    # Send traffic for 1 seconds with 2 packets per second
    tg.tg_traffic_control(action='run', handle=stream_id, duration=stream_duration, enable_arp=0)
    tg.tg_traffic_control(action='stop', handle=stream_id)

    # Stop capture
    total_packets = tg.tg_packet_control(port_handle=tg_rxhandler, action='stop')
    st.log("Number packets captured = {}".format(total_packets))

    st.wait(5)
    # Save the captured packets into a variable
    pkts_captured = tg.tg_packet_stats(port_handle=tg_rxhandler, format='var')

    if data.hlpr_debug_prints:
        st.log(pkts_captured)

    """
       verify the captured UDP packets having source IP as received interface IP
       and destination IP as helper IP and destination UDP port'
    """
    rx_cap_result = tgapi.validate_packet_capture(tg_type=tg.tg_type,
                                            pkt_dict=pkts_captured,
                                            header_list=header_li,
                                            offset_list=[23, 26, 30, 36],
                                            value_list= value_li)

    # Remove if stream id is not required
    stats = tg.tg_traffic_stats(mode='aggregate', port_handle=tg_txhandler)
    tx_pkt_count = int(stats[tg_txhandler]['aggregate']['tx']['total_pkts'])

    if data.hlpr_debug_prints:
        show_interface_counters_detailed(vars.D1, server_intf)
        show_interface_counters_detailed(vars.D1, client_intf)
        ip_helper_obj.show(vars.D1, statistics=helper_intf)

    counters_client_intf = show_interface_counters_detailed(vars.D1, client_intf)
    counters_server_intf = show_interface_counters_detailed(vars.D1, server_intf)

    """
    [{
    u'dropped_as_forwarding_not_enabled': '96',
    u'invalid_ttl_packets': '22',
    u'packets_received': '1098',
    u'packets_relayed': '980',
    u'all_ones_broadcast_packets_received': '602',
    u'packets_dropped': '118',
    u'net_directed_broadcast_packets_received': '496'
    }]
    """
    helper_stats = ip_helper_obj.show(vars.D1, statistics=helper_intf)

    # Check if we need to add condition based packet size. Ex: pkt_rx_64_octets, pkt_tx_64_octets

    if counters_client_intf and counters_server_intf and tx_pkt_count:

        st.log("TG Tx pkt count = {}".format(tx_pkt_count))
        st.log("packets received on client interface {} = {}".format(client_intf, int(counters_client_intf[0]['pkt_rx_broadcast'])))
        st.log("packets sent to server on interface {} = {}".format(server_intf, int(counters_server_intf[0]['pkt_tx_unicast'])))
        st.log("packet capture validation result = {}".format(rx_cap_result))
        st.log("Interface {} helper stats {}".format(helper_intf, helper_stats[0]))

        if isinstance(validation_param_val, dict):
            #validation_param_val = dict.fromkeys(validation_param_val, 0)
            validation_param_val['tx_pkt_count_on_tg_port'] = int(tx_pkt_count)
            validation_param_val['rx_bcast_count']          = int(counters_client_intf[0]['pkt_rx_broadcast'])
            validation_param_val['tx_ucast_count']          = int(counters_server_intf[0]['pkt_tx_unicast'])
            validation_param_val['rx_cap_reslt']            = rx_cap_result
            validation_param_val['ip_helper_stats']         = helper_stats[0]
            st.log("validation parma vals = {}".format(validation_param_val))

        elif (int(tx_pkt_count) > 0 and int(counters_client_intf[0]['pkt_rx_broadcast']) > 0 and (rx_cap_result is True) and
             (int(tx_pkt_count) == int(counters_client_intf[0]['pkt_rx_broadcast']))and
             ip_helper_obj.verify(vars.D1, statistics=helper_intf, verify_list=[{'packets_received': str(tx_pkt_count)}, {'packets_relayed': str(tx_pkt_count)}])):
            return True
    else:
       st.log("Failed to get counters of interface {}".format(client_intf))

    return False


def multi_client_servers_streams_validation(**kwargs):
    for protocol_name in kwargs['protocol_list']:
        result = send_and_validate_helper_traffic(kwargs['client_intf'],
                                                  kwargs['server_intf'],
                                                  kwargs['stream_dict'][protocol_name],
                                                  kwargs['tg_handler_tx'],
                                                  kwargs['tg_handler_rx'],
                                                  kwargs['header_list'],
                                                  [kwargs['value_list'][0], kwargs['value_list'][1], kwargs['value_list'][2], proto_udp_port[protocol_name]],
                                                  helper_intf=kwargs['helper_interface'])

        if result:
            st.log("{} packets are relayed from client received on {} to the server connected to interface {}".format(protocol_name, kwargs['client_intf'], kwargs['server_intf']))
        else:
            st.log("Failed to relay {} packets received on {} to the server connected to interface {}".format(protocol_name,kwargs['client_intf'], kwargs['server_intf']))

        kwargs['test_result'][protocol_name]= "Pass" if result else "Fail"


# VRF utils
def util_create_bind_vrf(interface_name, vrf_str):
    st.log("Create vrf {} in DUT ".format(vrf_str))
    config_vrf(vars.D1, vrf_name=vrf_str, config='yes', skip_error = True)

    st.log("Bind DUT interface {} to non-default VRF {}".format(interface_name, vrf_str))
    bind_vrf_interface(vars.D1, vrf_name=vrf_str, intf_name=interface_name, config='yes', skip_error = True)


def util_clean_up_vrf(interface_name, vrf_str):
    st.log("Unbind DUT interface {} to non-default VRF {}".format(interface_name, vrf_str))
    bind_vrf_interface(vars.D1, vrf_name=vrf_str, intf_name=interface_name, config='no', skip_error = True)
    # vrf_del_cmd = redis.build(dut, redis.APPL_DB, "hdel VRF_TABLE:{} fallback vni table_id".format(vrf_str))

    st.log("Delete vrf from DUT-1")
    config_vrf(vars.D1, vrf_name=vrf_str, config='no', skip_error = True)
    # st.config(vars.D1, vrf_del_cmd)


# PortChannel utils
def util_config_portchnl_interface(pc_members, portchnl_name):
    st.log("Create port channel {} and add port {} to the same".format(portchnl_name, pc_members))
    create_portchannel(vars.D1,  portchnl_name, static=True)
    add_portchannel_member(vars.D1, portchnl_name, pc_members)

def util_unconfig_portchnl_interface(pc_members, portchnl_name):
    st.log("Create port channel {} and add port {} to the same".format(portchnl_name, pc_members))
    delete_portchannel_member(vars.D1, portchnl_name, pc_members)
    delete_portchannel(vars.D1,  portchnl_name)


# VLAN utils
def util_create_vlan_and_add_port(intf_list, vlan_list):
    create_vlan(vars.D1, data.vlan_list)

    # Config vlan member add 184 vars.D1T1P1
    for port,vlan in zip(intf_list, vlan_list):
        st.log("Adding port {} to VLAN-{}".format(port, vlan))
        add_vlan_member(vars.D1, vlan, port)

def util_delete_vlan_and_port(intf_list, vlan_list):
    for port, vlan in zip(intf_list, vlan_list):
        st.log("Deleting port {} to VLAN-{}".format(port, vlan))
        delete_vlan_member(vars.D1, vlan, port)
    delete_vlan(vars.D1, data.vlan_list)


# Case: RtIpHeAdFn001
def test_ip_helper_default_protocols_default_vrf():
    intf_ip_list       = [
                          {'name': vars.D1T1P1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          {'name': vars.D1T1P3, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                         ]
    client_intf        = client_dut_intf['c1_intf']
    server_intf        = server_dut_intf['s1_intf']
    each_stream_result = {}

    st.log("Configuring the DUT ports connected to TGen with ip addresses")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='add')

    # Check IP config on an interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    if not (verify_interface_ip_address(vars.D1,  client_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_mask)) and
            verify_interface_ip_address(vars.D1,  server_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p3_ip'], data.ipv4_mask))):
        report_msg = ", ".join([client_intf, server_intf])
        st.report_fail("IP_config_verification_failed_on_interfaces", report_msg)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], client_intf))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_intf, ip_address=data.ip_helper_address[0])

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface {}.".format(client_intf))
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_intf, 'vrf': '', 'relay_address': data.ip_helper_address[0]}]):
        st.report_fail("IP_helper_config_verification_failed", client_intf)

    util_create_tg_streams(tg_handler['tg_ph_1'])

    st.log("Initiate broadcast UDP traffic from {} and check traffic relayed to server".format(vars.T1D1P1))
    for protocol_name in data.protocol_ports.keys():
        value_list = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port[protocol_name]]
        result = send_and_validate_helper_traffic(client_intf,
                                                  server_intf,
                                                  data.streams["tg1"][protocol_name],
                                                  tg_handler['tg_ph_1'],
                                                  tg_handler['tg_ph_3'],
                                                  header_li, value_list)

        if result:
            st.log("{} packets are relayed to server to interface {}".format(protocol_name, server_intf))
        else:
            st.log("Failed to relay {} packets received on interface {}".format(protocol_name, client_intf))

        each_stream_result[protocol_name] = "Pass" if result else "Fail"

    st.log("Removing IP helper address {} on interface {}".format(data.ip_helper_address[0], client_intf))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_intf, ip_address=data.ip_helper_address[0])

    st.log("Removing IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='remove')

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if "Fail" in list(each_stream_result.values()):
        st.report_fail("Failed_to_relay_all_default_protocol", each_stream_result)

    st.report_pass("All_UDP_pkts_relayed_to_server", each_stream_result)


# Case: RtIpHeAdFn002
def test_ip_helper_default_protocols_on_non_default_vrf():
    intf_ip_list       = [
                          {'name':vars.D1T1P1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          {'name':vars.D1T1P3, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                         ]

    client_intf        = client_dut_intf['c1_intf']
    server_intf        = server_dut_intf['s1_intf']
    each_stream_result = {}

    st.log("Create and bind VRF to interfaces")
    util_create_bind_vrf(client_intf, data.vrf_name[0])
    util_create_bind_vrf(server_intf, data.vrf_name[1])

    if data.hlpr_debug_prints:
        for vrf_name in data.vrf_name:
            vrf_info = get_vrf_verbose(vars.D1, vrfname=vrf_name)
            st.log("VRF {} config: {}".format(data.vrf_name[0], vrf_info))
    st.wait(2)

    # Check VRF config
    if not verify_vrf_verbose(vars.D1, vrfname=data.vrf_name, interface=[[client_intf], [server_intf]]):
        st.report_fail("Vrf_Config_verification_failed")

    st.log("Configuring the DUT ports connected to TGen with IP addresses")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='add')

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    if not (verify_interface_ip_address(vars.D1,  client_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_mask), vrfname =  data.vrf_name[0]) and
            verify_interface_ip_address(vars.D1,  server_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p3_ip'], data.ipv4_mask), vrfname =  data.vrf_name[1])):
        st.log("Removing VRF configuration")
        util_clean_up_vrf(client_intf, data.vrf_name[0])
        util_clean_up_vrf(server_intf, data.vrf_name[1])
        report_msg = ", ".join([client_intf, server_intf])
        st.report_fail("IP_config_verification_failed_on_interfaces", report_msg)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.log("Removing VRF configuration")
        util_clean_up_vrf(client_intf, data.vrf_name[0])
        util_clean_up_vrf(server_intf, data.vrf_name[1])
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], client_intf))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_intf, vrf_name=data.vrf_name[1], ip_address=data.ip_helper_address[0])

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface {}.".format(client_intf))
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_intf, 'vrf': data.vrf_name[1], 'relay_address': data.ip_helper_address[0]}]):
        st.log("Removing VRF configuration")
        util_clean_up_vrf(client_intf, data.vrf_name[0])
        util_clean_up_vrf(server_intf, data.vrf_name[1])
        st.report_fail("IP_helper_config_verification_failed", client_intf)

    util_create_tg_streams(tg_handler["tg_ph_1"])

    st.log("Initiate broadcast UDP traffic from {} and check traffic routed to server.".format(vars.T1D1P1))
    for protocol_name in data.protocol_ports.keys():
        value_list = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port[protocol_name]]
        result = send_and_validate_helper_traffic(client_intf,
                                                  server_intf,
                                                  data.streams["tg1"][protocol_name],
                                                  tg_handler["tg_ph_1"],
                                                  tg_handler['tg_ph_3'],
                                                  header_li, value_list)

        if result:
            st.log("{} packets are relayed to server via interface {}".format(protocol_name, server_intf))
        else:
            st.log("Failed to relay {} packets received on interface {}".format(protocol_name, client_intf))

        each_stream_result[protocol_name] = "Pass" if result else "Fail"

    st.log("Removing IP helper address {} on interface {}".format(data.ip_helper_address[0], client_intf))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_intf, vrf_name=data.vrf_name[1],
                         ip_address=data.ip_helper_address[0])

    st.log("Removing IP config on dut ports connected to TGen.")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='remove')

    st.log("Removing VRF configuration")
    util_clean_up_vrf(client_intf, data.vrf_name[0])
    util_clean_up_vrf(server_intf, data.vrf_name[1])

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if "Fail" in list(each_stream_result.values()):
        st.report_fail("Failed_to_relay_all_default_protocol", each_stream_result)

    st.report_pass("All_UDP_pkts_relayed_to_server", each_stream_result)


# Case: RtIpHeAdFn003
def test_ip_helper_default_protocols_on_portchnl_routing_intf():
    intf_ip_list        = [
                           {'name': data.port_channel, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                           {'name': vars.D1T1P3, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          ]
    each_stream_result  = {}
    client_intf         = client_dut_intf['c1_intf']
    server_intf         = server_dut_intf['s1_intf']

    st.log("Creating port channel {}".format(data.port_channel))
    util_config_portchnl_interface([client_dut_intf['c1_intf'], client_dut_intf['c2_intf']], data.port_channel)

    if data.hlpr_debug_prints:
        get_portchannel(vars.D1, portchannel_name=data.port_channel)

    st.log("Verify the port channel {} status".format(data.port_channel))
    if not poll_for_portchannel_status(vars.D1, data.port_channel, state="up", iteration=20, delay=1):
        st.report_fail("portchannel_verification_failed", data.port_channel, vars.D1)

    st.log("Configuring the DUT ports connected to TGen with IP addresses")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='add')

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    if not (verify_interface_ip_address(vars.D1,  data.port_channel, "{}/{}".format(data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_mask)) and
            verify_interface_ip_address(vars.D1,  server_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p3_ip'], data.ipv4_mask))):
        report_msg = ", ".join([data.port_channel, server_intf])
        st.report_fail("IP_config_verification_failed_on_interfaces", report_msg)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], data.port_channel))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=data.port_channel, ip_address=data.ip_helper_address[0])

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface {}.".format(data.port_channel))
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': data.port_channel, 'vrf': '', 'relay_address': data.ip_helper_address[0]}]):
        st.report_fail("IP_helper_config_verification_failed", data.port_channel)

    util_create_tg_streams(tg_handler["tg_ph_1"])
    st.log("Initiate broadcast UDP traffic from TG port {} and check traffic routed to server".format(vars.T1D1P1))

    # Check if we need to pass port channel interface to get the counters?
    for protocol_name in data.protocol_ports.keys():
        value_list = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port[protocol_name]]
        #As interface counters are cleared from click/klish but getting portchannel counters can be done from click only due to SONIC-28659 will revert back once it is fixed
        clear_interface_counters(vars.D1, cli_type='click')
        result = send_and_validate_helper_traffic(data.port_channel,
                                                  server_intf,
                                                  data.streams["tg1"][protocol_name],
                                                  tg_handler["tg_ph_1"],
                                                  tg_handler['tg_ph_3'],
                                                  header_li, value_list)

        if result:
            st.log("{} packets are relayed to server to interface {}".format(protocol_name, server_intf))
        else:
            st.log("Failed to relay {} packets received on interface {}".format(protocol_name, client_intf))

        each_stream_result[protocol_name] = "Pass" if result else "Fail"

    st.log("Removing IP helper address {} on interface {}".format(data.ip_helper_address[0], data.port_channel))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=data.port_channel, ip_address=data.ip_helper_address[0])

    st.log("Remove IP configuration on interface {}".format(data.port_channel))
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='remove')

    st.log("Remove port channel configuration")
    util_unconfig_portchnl_interface([client_dut_intf['c1_intf'], client_dut_intf['c2_intf']], data.port_channel)

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if "Fail" in list(each_stream_result.values()):
        st.report_fail("Failed_to_relay_all_default_protocol", each_stream_result)

    st.report_pass("All_UDP_pkts_relayed_to_server", each_stream_result)


# Case: RtIpHeAdFn004, RtIpHeAdFn005, RtIpHeAdFn006
def test_ip_helper_default_protocols_on_vlan_routing_intf():
    client_vlan_intf_1  = "Vlan{}".format(data.vlan_list[0])
    client_vlan_intf_2  = "Vlan{}".format(data.vlan_list[1])
    server_vlan_intf_1  = "Vlan{}".format(data.vlan_list[2])
    server_vlan_intf_2  = "Vlan{}".format(data.vlan_list[3])
    vlan_intf_ip_list   = [
                           {'name': client_vlan_intf_1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                           {'name': client_vlan_intf_2, 'ip': data.ipv4_addr_intf['d1t1p2_ip'], 'subnet': 24, 'family': data.af_ipv4},
                           {'name': server_vlan_intf_1, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                           {'name': server_vlan_intf_2, 'ip': data.ipv4_addr_intf['d1t1p4_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          ]

    each_test_result    = {"tg1_to_tg3": {}, "tg1_to_tg4": {}, "tg2_to_tg3": {}, "tg2_to_tg4": {}}


    st.log("Creating VLANs")
    util_create_vlan_and_add_port([vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4], data.vlan_list)

    if data.hlpr_debug_prints:
        show_vlan_config(vars.D1)

    for vlan, intf in [
                       (str(data.vlan_list[0]), client_dut_intf['c1_intf']),
                       (str(data.vlan_list[1]), client_dut_intf['c2_intf']),
                       (str(data.vlan_list[2]), server_dut_intf['s1_intf']),
                       (str(data.vlan_list[3]), server_dut_intf['s2_intf'])
                      ]:
        if not (verify_vlan_config(vars.D1, vlan, untagged=[intf])):
            st.log("VRF {} existed, removing the same".format(", ".join(data.vrf_name)))
            config_vrf(vars.D1, vrf_name=data.vrf_name, config='no', skip_error = True)
            st.report_fail("vlan_config_verification_failed", vlan)

    st.log("Binding client interface {} to {} and server interface {} to {}".format(client_vlan_intf_2, data.vrf_name[0], server_vlan_intf_2, data.vrf_name[1]))
    util_create_bind_vrf(client_vlan_intf_2, data.vrf_name[0])
    util_create_bind_vrf(server_vlan_intf_2, data.vrf_name[1])

    if data.hlpr_debug_prints:
        for vrf_name in data.vrf_name:
            vrf_info = get_vrf_verbose(vars.D1, vrfname=vrf_name)
            st.log("VRF {} config: {}".format(vrf_name, vrf_info))
    st.wait(2)
    # Check VRF config
    if not verify_vrf_verbose(vars.D1, vrfname=data.vrf_name, interface=[[client_vlan_intf_2], [server_vlan_intf_2]]):
        st.report_fail("Vrf_Config_verification_failed")

    st.log("Configure IP on VLAN interfaces")
    config_unconfig_interface_ip_addresses(vars.D1, vlan_intf_ip_list, config='add')

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    for vlan_intf, ipv4_addr, vrf_name in [
                                 (client_vlan_intf_1, data.ipv4_addr_intf['d1t1p1_ip'], ''),
                                 (client_vlan_intf_2, data.ipv4_addr_intf['d1t1p2_ip'], data.vrf_name[0]),
                                 (server_vlan_intf_1, data.ipv4_addr_intf['d1t1p3_ip'], ''),
                                 (server_vlan_intf_2, data.ipv4_addr_intf['d1t1p4_ip'], data.vrf_name[1])
                                ]:
        if not verify_interface_ip_address(vars.D1, vlan_intf, "{}/{}".format(ipv4_addr, data.ipv4_mask), vrfname = vrf_name):
            st.log("Removing VRF config")
            util_clean_up_vrf(client_vlan_intf_2, data.vrf_name[0])
            util_clean_up_vrf(server_vlan_intf_2, data.vrf_name[1])
            st.report_fail("IP_config_verification_failed_on_interfaces", vlan_intf)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Adding ports {} {} in forwarding protocol list".format(140, 150))
    ip_helper_obj.config(vars.D1, action_str='add', protocol_or_port=140)
    ip_helper_obj.config(vars.D1, action_str='add', protocol_or_port=150)

    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, forward_protocol='')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server', '140', '150']}]):
        st.log("Removing VRF config")
        util_clean_up_vrf(client_vlan_intf_2, data.vrf_name[0])
        util_clean_up_vrf(server_vlan_intf_2, data.vrf_name[1])
        st.log("Removing custom ports {} {} in forwarding list".format(140, 150))
        ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=140)
        ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=150)
        st.report_fail("UDP_forwarding_status_verification_failed")

    for client_intf in [client_vlan_intf_1, client_vlan_intf_2]:
        st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], client_intf))
        ip_helper_obj.config(vars.D1, action_str='add',
                             intf_name=client_intf,
                             ip_address=data.ip_helper_address[0])

        st.log("Configure IP helper address {} with {} on interface {} ".format(data.ip_helper_address[1], data.vrf_name[1], client_intf))
        ip_helper_obj.config(vars.D1, action_str='add',
                             intf_name=client_intf,
                             vrf_name=data.vrf_name[1],
                             ip_address=data.ip_helper_address[1])

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface")
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_vlan_intf_1, 'vrf': '', 'relay_address': data.ip_helper_address[0]},
                                             {'interface': client_vlan_intf_1, 'vrf': data.vrf_name[1], 'relay_address': data.ip_helper_address[1]},
                                             {'interface': client_vlan_intf_2, 'vrf': '', 'relay_address': data.ip_helper_address[0]},
                                             {'interface': client_vlan_intf_2, 'vrf': data.vrf_name[1], 'relay_address': data.ip_helper_address[1]}]):
        st.log("Removing VRF config")
        util_clean_up_vrf(client_vlan_intf_2, data.vrf_name[0])
        util_clean_up_vrf(server_vlan_intf_2, data.vrf_name[1])
        st.log("Removing custom ports {} {} in forwarding list".format(140, 150))
        ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=140)
        ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=150)
        report_msg = ", ".join([client_vlan_intf_1, client_vlan_intf_2])
        st.report_fail("IP_helper_config_verification_failed", report_msg)

    util_create_tg_streams(tg_handler["tg_ph_1"])
    util_create_tg_streams(tg_handler["tg_ph_2"], prot_port_di={'tftp': '69', 'ntp': '37', 'dns': '53','tacacs': '49', 'nbname': '137', 'nbdatagram': '138', 'custom1': '140', 'custom2': '150'})

    st.log("Initiate broadcast UDP traffic from TG1:{} to TG3: {} and check traffic is forwarded to servers".format(vars.T1D1P1, vars.T1D1P3))
    value_li = ['11', '10.10.10.1', '30.30.30.1']
    multi_client_servers_streams_validation(client_intf=client_dut_intf['c1_intf'],
                                            server_intf=server_dut_intf['s1_intf'],
                                            stream_dict=data.streams["tg1"],
                                            protocol_list=['tftp', 'ntp', 'dns'],
                                            tg_handler_tx=tg_handler["tg_ph_1"],
                                            tg_handler_rx=tg_handler['tg_ph_3'],
                                            header_list=header_li, value_list=value_li,
                                            test_result=each_test_result["tg1_to_tg3"],
                                            helper_interface=client_vlan_intf_1)

    st.log("Initiate broadcast UDP traffic from TG1:{} to TG4: {} and check traffic is forwarded to servers".format(vars.T1D1P1, vars.T1D1P4))
    value_li = ['11', '10.10.10.1', '40.40.40.1']
    multi_client_servers_streams_validation(client_intf=client_dut_intf['c1_intf'],
                                            server_intf=server_dut_intf['s2_intf'],
                                            stream_dict=data.streams["tg1"],
                                            protocol_list=['tacacs', 'nbname', 'nbdatagram'],
                                            tg_handler_tx=tg_handler["tg_ph_1"],
                                            tg_handler_rx=tg_handler['tg_ph_4'],
                                            header_list=header_li, value_list=value_li,
                                            test_result=each_test_result["tg1_to_tg4"],
                                            helper_interface=client_vlan_intf_1)

    st.log("Initiate broadcast UDP traffic from TG2:{} to TG4: {} and check traffic is forwarded to servers".format(vars.T1D1P2, vars.T1D1P4))
    value_li = ['11', '20.20.20.1', '40.40.40.1']
    multi_client_servers_streams_validation(client_intf=client_dut_intf['c2_intf'],
                                            server_intf=server_dut_intf['s2_intf'],
                                            stream_dict=data.streams["tg2"],
                                            protocol_list=['tftp', 'ntp', 'dns', 'custom1'],
                                            tg_handler_tx=tg_handler["tg_ph_2"],
                                            tg_handler_rx=tg_handler['tg_ph_4'],
                                            header_list=header_li, value_list=value_li,
                                            test_result=each_test_result["tg2_to_tg4"],
                                            helper_interface=client_vlan_intf_2)

    st.log("Initiate broadcast UDP traffic from TG2:{} to TG3: {} and check traffic is forwarded to servers".format(vars.T1D1P2, vars.T1D1P3))
    value_li = ['11', '20.20.20.1', '30.30.30.1']
    multi_client_servers_streams_validation(client_intf=client_dut_intf['c2_intf'],
                                            server_intf=server_dut_intf['s1_intf'],
                                            stream_dict=data.streams["tg2"],
                                            protocol_list=['tacacs', 'nbname', 'nbdatagram', 'custom2'],
                                            tg_handler_tx=tg_handler["tg_ph_2"],
                                            tg_handler_rx=tg_handler['tg_ph_3'],
                                            header_list=header_li, value_list=value_li,
                                            test_result=each_test_result["tg2_to_tg3"],
                                            helper_interface=client_vlan_intf_2)

    ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=140)
    ip_helper_obj.config(vars.D1, action_str='remove', protocol_or_port=150)

    st.log("Remove IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, vlan_intf_ip_list, config='remove')

    # Add if we need to remove helper config on an interface

    st.log("Removing VRF config")
    util_clean_up_vrf(client_vlan_intf_2, data.vrf_name[0])
    util_clean_up_vrf(server_vlan_intf_2, data.vrf_name[1])

    st.log("Remove vlan configuration")
    util_delete_vlan_and_port([vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4], data.vlan_list)

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if ("Fail" in list(each_test_result["tg1_to_tg3"].values()) or "Fail" in list(each_test_result["tg1_to_tg4"].values()) or
        "Fail" in list(each_test_result["tg2_to_tg3"].values()) or "Fail" in list(each_test_result["tg2_to_tg4"].values())):
        st.report_fail("Failed_to_relay_all_default_protocol", each_test_result)

    st.report_pass("All_UDP_pkts_relayed_to_server", each_test_result)


# RtIpHeAdFn007, RtIpHeAdFn008, RtIpHeAdFn009, RtIpHeAdNt001
def test_ip_helper_non_udp_and_dhcp_protocols_on_vlan_routing_intf():
    client_vlan_intf_1  = "Vlan{}".format(data.vlan_list[0])
    server_vlan_intf_1  = "Vlan{}".format(data.vlan_list[2])
    vlan_intf_ip_list   = [
                           {'name': client_vlan_intf_1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                           {'name': server_vlan_intf_1, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          ]
    each_stream_result  = {"tg1_to_tg3": {}}
    stats_param_val     = {
                           'tx_pkt_count_on_tg_port': 0,
                           'rx_bcast_count': 0,
                           'tx_ucast_count': 0,
                           'rx_cap_reslt': 0,
                           'ip_helper_stats': {}
                          }

    st.log("Creating VLANs")
    util_create_vlan_and_add_port([client_dut_intf['c1_intf'], server_dut_intf['s1_intf']],
                                  [data.vlan_list[0], data.vlan_list[2]])

    if data.hlpr_debug_prints:
        show_vlan_config(vars.D1)

    for vlan, intf in [
                       (str(data.vlan_list[0]), client_dut_intf['c1_intf']),
                       (str(data.vlan_list[2]), server_dut_intf['s1_intf']),
                      ]:
        if not (verify_vlan_config(vars.D1, vlan, untagged=[intf])):
            st.report_fail("vlan_config_verification_failed", vlan)

    st.log("Configure IP on VLAN interfaces")
    config_unconfig_interface_ip_addresses(vars.D1, vlan_intf_ip_list, config='add')

    # Check ip config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    for vlan_intf, ipv4_addr in [
                                 (client_vlan_intf_1, data.ipv4_addr_intf['d1t1p1_ip']),
                                 (server_vlan_intf_1, data.ipv4_addr_intf['d1t1p3_ip']),
                                ]:
        if not verify_interface_ip_address(vars.D1, vlan_intf, "{}/{}".format(ipv4_addr, data.ipv4_mask)):
            st.report_fail("IP_config_verification_failed_on_interfaces", vlan_intf)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], client_vlan_intf_1))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_vlan_intf_1, ip_address=data.ip_helper_address[0])

    # Checking ip helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface")
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_vlan_intf_1, 'vrf': '',
                                              'relay_address': data.ip_helper_address[0]}]):
        st.report_fail("IP_helper_config_verification_failed", client_vlan_intf_1)

    st.log("Creating TCP stream on TG port{}".format(vars.T1D1P1))
    tg1_stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"],
                                      mode='create',
                                      transmit_mode='single_burst',
                                      length_mode='fixed',
                                      l2_encap='ethernet_ii',
                                      rate_pps='2',
                                      pkts_per_burst='1',
                                      mac_src=data.tg_macs['tg1_mac'],
                                      mac_dst=data.bcast_mac,
                                      l3_protocol='ipv4',
                                      ip_src_addr=data.ipv4_addr_tg["t1d1p1_ip"],
                                      ip_dst_addr=data.bcast_ip,
                                      l4_protocol='tcp',
                                      tcp_src_port='4001',
                                      tcp_dst_port='69')

    data.streams["tg1"]['tcp'] = tg1_stream["stream_id"]

    util_create_tg_streams(tg_handler["tg_ph_1"], prot_port_di={'dhcp': '67', 'custom1': '140'})

    if 'dns' in data.streams["tg1"].keys():
        tg.tg_traffic_config(mode='remove', stream_id=data.streams["tg1"]['dns'])
        del(data.streams["tg1"]['dns'])
    util_create_tg_streams(tg_handler["tg_ph_1"], prot_port_di={'dns': '53'}, ip_ttl_val=1)

    for protocol_name in ['tcp', 'dhcp', 'custom1', 'dns']:
        if protocol_name == 'tcp':
            value_li     = ['06', '10.10.10.1', '30.30.30.1', proto_udp_port[protocol_name]]
            td_header_li = ['IP:Protocol', 'IP:Source', 'IP:Destination', 'TCP:Destination Port']
        else:
            value_li     = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port[protocol_name]]
            td_header_li = header_li

        send_and_validate_helper_traffic(client_dut_intf['c1_intf'],
                                         server_dut_intf['s1_intf'],
                                         data.streams["tg1"][protocol_name],
                                         tg_handler["tg_ph_1"],
                                         tg_handler['tg_ph_3'],
                                         td_header_li, value_li,
                                         validation_param_val=stats_param_val,
                                         helper_intf=client_vlan_intf_1)

        # Relay stats and Interface stats verification.
        st.log("Stats for protocol = {} and values = {}".format(protocol_name, stats_param_val))
        if (stats_param_val['tx_pkt_count_on_tg_port'] > 0 and stats_param_val['rx_bcast_count'] > 0 and
            (stats_param_val['tx_pkt_count_on_tg_port'] == stats_param_val['rx_bcast_count']) and (not stats_param_val['rx_cap_reslt']) and
            (stats_param_val['ip_helper_stats']['packets_relayed'] == str(0))):

            # Check if we really need to verify stats_param_val['ip_helper_stats']['packets_received']
            # Check if we really need to verify stats_param_val['ip_helper_stats']['invalid_ttl_packets']
            if protocol_name == 'dns':
                msg = "'DNS packets with TTL=1 not forwarded'"
                st.report_pass("IP_helper_test_case_msg_status", msg, "passed")
            elif protocol_name == 'custom1':
                msg = "'UDP packets with port 140 not forwarded'"
                st.report_pass("IP_helper_test_case_msg_status", msg, "passed")
            else:
                st.report_pass("Dhcp_non_udp_exclude_port_packets_relay_success", protocol_name)

            each_stream_result["tg1_to_tg3"][protocol_name] = "Pass"
        else:
            st.log("Test failed for {} packets".format(protocol_name))
            st.log("Stats param values = {}".format(stats_param_val))
            each_stream_result["tg1_to_tg3"][protocol_name] = "Fail"

    st.log("Removing IP helper address {} on interface {}".format(data.ip_helper_address[0], client_vlan_intf_1))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_vlan_intf_1,
                         ip_address=data.ip_helper_address[0])

    st.log("Removing IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, vlan_intf_ip_list, config='remove')

    st.log("Removing VLAN configuration")
    util_delete_vlan_and_port([client_dut_intf['c1_intf'], server_dut_intf['s1_intf']],
                                  [data.vlan_list[0], data.vlan_list[2]])

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if 'dns' in data.streams["tg1"].keys():
        tg.tg_traffic_config(mode='remove', stream_id=data.streams["tg1"]['dns'])
        del(data.streams["tg1"]['dns'])

    if "Fail" in list(each_stream_result["tg1_to_tg3"].values()):
        st.report_fail("Dhcp_non_udp_exclude_port_packets_relay_msg", 140, "failed", each_stream_result)

    st.report_pass("Dhcp_non_udp_exclude_port_packets_relay_msg", 140, "passed", each_stream_result)


# Case: RtIpHeAdFn010
def test_ip_helper_subnet_bcast_pkt_on_vlan_routing_intf():
    client_vlan_intf_1  = "Vlan{}".format(data.vlan_list[0])
    server_vlan_intf_1  = "Vlan{}".format(data.vlan_list[2])
    vlan_intf_ip_list   = [
                           {'name': client_vlan_intf_1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                           {'name': server_vlan_intf_1, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4}
                          ]

    st.log("Creating VLANs")
    util_create_vlan_and_add_port([client_dut_intf['c1_intf'], server_dut_intf['s1_intf']],
                                  [data.vlan_list[0], data.vlan_list[2]])

    for vlan, intf in [
                       (str(data.vlan_list[0]), client_dut_intf['c1_intf']),
                       (str(data.vlan_list[2]), server_dut_intf['s1_intf']),
                      ]:
        if not (verify_vlan_config(vars.D1, vlan, untagged=[intf])):
            st.report_fail("vlan_config_verification_failed", vlan)

    st.log("Configure IP on VLAN interfaces")
    config_unconfig_interface_ip_addresses(vars.D1, vlan_intf_ip_list, config='add')

    # Check ip config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    for vlan_intf, ipv4_addr in [
                                 (client_vlan_intf_1, data.ipv4_addr_intf['d1t1p1_ip']),
                                 (server_vlan_intf_1, data.ipv4_addr_intf['d1t1p3_ip']),
                                ]:
        if not verify_interface_ip_address(vars.D1, vlan_intf, "{}/{}".format(ipv4_addr, data.ipv4_mask)):
            st.report_fail("IP_config_verification_failed_on_interfaces", vlan_intf)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='',
                                verify_list=[{'forwarding': 'Enabled', 'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS',
                                                                 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], client_vlan_intf_1))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_vlan_intf_1, ip_address=data.ip_helper_address[0])

    # Checking IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface")
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_vlan_intf_1, 'vrf': '', 'relay_address': data.ip_helper_address[0]}]):
        st.report_fail("IP_helper_config_verification_failed", client_vlan_intf_1)

    if 'tftp' in data.streams["tg1"].keys():
        tg.tg_traffic_config(mode='modify', stream_id=data.streams["tg1"]['tftp'], ip_dst_addr="10.10.10.255")
    else:
        tg1_stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"],
                                          mode='create',
                                          transmit_mode='single_burst',
                                          length_mode='fixed',
                                          l2_encap='ethernet_ii',
                                          rate_pps='2',
                                          pkts_per_burst='1',
                                          mac_src=data.tg_macs['tg1_mac'],
                                          mac_dst=data.bcast_mac,
                                          l3_protocol='ipv4',
                                          ip_src_addr=data.ipv4_addr_tg["t1d1p1_ip"],
                                          ip_dst_addr="10.10.10.255",
                                          l4_protocol='udp',
                                          udp_src_port='4001',
                                          udp_dst_port='69')

        data.streams["tg1"]['tftp'] = tg1_stream["stream_id"]

    value_li = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port['tftp']]

    result = send_and_validate_helper_traffic(client_dut_intf['c1_intf'],
                                              server_dut_intf['s1_intf'],
                                              data.streams["tg1"]['tftp'],
                                              tg_handler["tg_ph_1"],
                                              tg_handler['tg_ph_3'],
                                              header_li, value_li,
                                              helper_intf=client_vlan_intf_1)

    st.log("Removing IP helper address {} on interface {}".format(data.ip_helper_address[0], client_vlan_intf_1))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_vlan_intf_1, ip_address=data.ip_helper_address[0])

    st.log("Removing IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, vlan_intf_ip_list, config='remove')

    st.log("Remove VLAN configuration")
    util_delete_vlan_and_port([client_dut_intf['c1_intf'], server_dut_intf['s1_intf']],
                                  [data.vlan_list[0], data.vlan_list[2]])

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    msg_str = "Forwarding TFTP subnet broadcast packet"
    if not result:
        st.report_fail("IP_helper_test_case_msg_status", msg_str, "failed")

    st.report_pass("IP_helper_test_case_msg_status", msg_str, "passed")


# Cases: RtIpHeAdNt002, RtIpHeAdNt003
def test_ip_helper_address_not_reachable():
    intf_ip_list     = [
                        {'name': vars.D1T1P1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                        {'name': vars.D1T1P2, 'ip': data.ipv4_addr_intf['d1t1p2_ip'], 'subnet': 24, 'family': data.af_ipv4},
                        {'name': vars.D1T1P3, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                        {'name': vars.D1T1P4, 'ip': data.ipv4_addr_intf['d1t1p4_ip'], 'subnet': 24, 'family': data.af_ipv4},
                       ]
    helper_ip        = "30.30.30.8"
    vrf_str          = "Vrf100"
    stats_param_val  = {
                        'tx_pkt_count_on_tg_port': 0,
                        'rx_bcast_count': 0,
                        'tx_ucast_count': 0,
                        'rx_cap_reslt': 0,
                        'ip_helper_stats': {}
                       }
    each_test_result = {}

    st.log("configuring the dut ports connected to TGen with ip addresses")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='add')

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    for intf_params in intf_ip_list:
        if not (verify_interface_ip_address(vars.D1, intf_params['name'], "{}/{}".format(intf_params['ip'], data.ipv4_mask))):
            st.report_fail("IP_config_verification_failed_on_interfaces", intf_params['name'])

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='',
                                verify_list=[{'forwarding': 'Enabled', 'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS',
                                                                                       'NetBios-Name-Server',
                                                                                       'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(helper_ip, client_dut_intf['c1_intf']))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_dut_intf['c1_intf'], ip_address=helper_ip)
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_dut_intf['c1_intf'], vrf_name=vrf_str, ip_address=data.ip_helper_address[1])

    # Checking IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface")
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_dut_intf['c1_intf'], 'vrf': '', 'relay_address': helper_ip},
                                             {'interface': client_dut_intf['c1_intf'], 'vrf': vrf_str, 'relay_address': data.ip_helper_address[1]}]):
        st.report_fail("IP_helper_config_verification_failed", client_dut_intf['c1_intf'])

    util_create_tg_streams(tg_handler["tg_ph_1"], prot_port_di={'tacacs': '49'})

    st.log("Initiate broadcast UDP traffic from TG1 port {} and check traffic routed to server".format(vars.T1D1P1))
    value_list = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port['tacacs']]

    send_and_validate_helper_traffic(client_dut_intf['c1_intf'],
                                     server_dut_intf['s1_intf'],
                                     data.streams["tg1"]['tacacs'],
                                     tg_handler["tg_ph_1"],
                                     tg_handler['tg_ph_3'],
                                     header_li, value_list,
                                     validation_param_val=stats_param_val)

    if not stats_param_val['rx_cap_reslt']:

        # Check if we need add stats_param_val['ip_helper_stats']['packets_relayed'] == 0
        each_test_result["unreachable_helper_IP_case"] = "Pass"
        st.report_pass("Packet_not_relayed_to_Unreachable_helper_IP")
    else:
        st.log("Test case 'Packets to un-reachable server' failed.")
        st.log("Stats param values = {}".format(stats_param_val))
        each_test_result["unreachable_helper_IP_case"] = "Fail"

    send_and_validate_helper_traffic(client_dut_intf['c1_intf'],
                                     server_dut_intf['s2_intf'],
                                     data.streams["tg1"]['tacacs'],
                                     tg_handler["tg_ph_1"],
                                     tg_handler['tg_ph_4'],
                                     header_li, value_list,
                                     validation_param_val=stats_param_val)

    if (stats_param_val['tx_pkt_count_on_tg_port'] > 0 and stats_param_val['rx_bcast_count'] > 0 and
       (stats_param_val['tx_pkt_count_on_tg_port'] == stats_param_val['rx_bcast_count']) and
       stats_param_val['tx_ucast_count'] == 0 and (not stats_param_val['rx_cap_reslt'])):
       each_test_result["Non_existing_VRF_of_helper_IP_case"] = "Pass"
       st.report_pass("Packet_not_relayed_to_non_exist_VRF_helper_ip")
    else:
        st.log("Test case 'Packets to non-existing VRF of helper IP' failed.")
        st.log("Stats param values = {}".format(stats_param_val))
        each_test_result["Non_existing_VRF_of_helper_IP_case"] = "Fail"

    st.log("Remove IP helper address {} on interface {}".format(helper_ip, client_dut_intf['c1_intf']))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_dut_intf['c1_intf'], ip_address=helper_ip)
    st.log("Remove IP helper address {} on interface {}".format(data.ip_helper_address[1], client_dut_intf['c1_intf']))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_dut_intf['c1_intf'], vrf_name=vrf_str, ip_address=data.ip_helper_address[1])

    st.log("Removing IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='remove')

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if "Fail" in list(each_test_result.values()):
        st.report_fail("Unreachable_helper_IP_or_non_existing_VRF_of_helper_IP", each_test_result)


# Case: FtOpSfFn005
def test_ip_helper_with_max_helper_address_on_interface():
    intf_ip_list       = [
                          {'name': vars.D1T1P1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          {'name': vars.D1T1P3, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                         ]
    client_intf        = client_dut_intf['c1_intf']
    server_intf        = server_dut_intf['s1_intf']
    helper_addr_list   = ['30.30.30.1', '30.30.30.2', '30.30.30.3', '30.30.30.4']
    stats_param_val    = {
                          'tx_pkt_count_on_tg_port': 0,
                          'rx_bcast_count': 0,
                          'tx_ucast_count': 0,
                          'rx_cap_reslt': 0,
                          'ip_helper_stats': {}
                         }
    each_helper_result = {}

    st.log("configuring the dut ports connected to TGen with IP addresses")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='add')

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    if not (verify_interface_ip_address(vars.D1,  client_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_mask)) and
            verify_interface_ip_address(vars.D1,  server_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p3_ip'], data.ipv4_mask))):
        report_msg = ", ".join([client_intf, server_intf])
        st.report_fail("IP_config_verification_failed_on_interfaces", report_msg)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(', '.join(helper_addr_list), client_intf))
    if data.cli_type == "click":
        ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_intf, ip_address=helper_addr_list)
    else:
        for ip_addr in helper_addr_list:
            ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_intf, ip_address=ip_addr)

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface {}.".format(client_intf))
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_intf, 'vrf': '', 'relay_address': helper_addr_list[0]},
                                             {'interface': client_intf, 'vrf': '', 'relay_address': helper_addr_list[1]},
                                             {'interface': client_intf, 'vrf': '', 'relay_address': helper_addr_list[2]},
                                             {'interface': client_intf, 'vrf': '', 'relay_address': helper_addr_list[3]}]):
        st.report_fail("IP_helper_config_verification_failed", client_intf)

    st.log("Removing existing host config on TG port {}.".format(vars.T1D1P3))
    tg.tg_interface_config(handle=data.server1['handle'], mode='destroy')

    st.log("Config four hosts on {} which acts acts as servers.".format(vars.T1D1P3))
    data.server1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_3"],
                                          mode='config',
                                          intf_ip_addr=data.ipv4_addr_tg['t1d1p3_ip'],
                                          gateway=data.ipv4_addr_intf['d1t1p3_ip'],
                                          src_mac_addr=data.tg_macs['tg3_mac'],
                                          arp_send_req='1',
                                          gateway_step='0.0.0.0',
                                          intf_ip_addr_step='0.0.0.1',
                                          count=4)

    util_create_tg_streams(tg_handler["tg_ph_1"],  prot_port_di={'tftp': '69'})
    st.log("Initiate broadcast UDP traffic from TG port {} and check traffic relayed to server {}".format(vars.T1D1P1, vars.T1D1P3))
    protocol_name = 'tftp'
    for helper_ip in ['30.30.30.1', '30.30.30.2', '30.30.30.3', '30.30.30.4']:
        value_list = ['11','10.10.10.1', helper_ip, proto_udp_port[protocol_name]]
        send_and_validate_helper_traffic(client_intf,
                                         server_intf,
                                         data.streams["tg1"][protocol_name],
                                         tg_handler["tg_ph_1"],
                                         tg_handler['tg_ph_3'],
                                         header_li, value_list,
                                         validation_param_val=stats_param_val)

        test_key = "traffic_to_server_" + helper_ip
        if (stats_param_val['tx_pkt_count_on_tg_port'] > 0 and stats_param_val['rx_bcast_count'] > 0 and
            (stats_param_val['tx_pkt_count_on_tg_port'] == stats_param_val['rx_bcast_count'] == int(stats_param_val['ip_helper_stats']['packets_relayed'])) and
            stats_param_val['rx_cap_reslt'] is True):
            st.log("{} packets received to server {}".format(protocol_name, helper_ip))
            each_helper_result[test_key] = "Pass"
        else:
            each_helper_result[test_key] = "Fail"
            st.log("Stats param values = {}".format(stats_param_val))
            st.report_fail("Failed_to_relay_pkts_to_helper_ip", helper_ip, each_helper_result)

    st.log("Remove IP helper address {} on interface {}".format(', '.join(helper_addr_list), client_intf))
    if data.cli_type == "click":
        ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_intf, ip_address=helper_addr_list)
    else:
        for ip_addr in helper_addr_list:
            ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_intf, ip_address=ip_addr)

    st.log("Removing IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='remove')

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    st.log("Removing four hosts config on TG port {}.".format(vars.T1D1P3))
    tg.tg_interface_config(handle=data.server1['handle'], mode='destroy')

    st.log("Re-Configure {} single host which acts as server.".format(vars.T1D1P3))
    data.server1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_3"],
                                          mode='config',
                                          intf_ip_addr=data.ipv4_addr_tg['t1d1p3_ip'],
                                          gateway=data.ipv4_addr_intf['d1t1p3_ip'],
                                          src_mac_addr=data.tg_macs['tg3_mac'],
                                          arp_send_req='1')

    st.log("TG3 conf: " + str(data.server1))

    st.report_pass("All_configured_servers_received_packets", each_helper_result)


def poll_for_ip_address_verification_status(dut, client_intf, server_intf, client_ip, server_ip, iteration=1, delay=1):
    itercount = 1
    st.log("Iterations = {} and iterdelay = {}".format(iteration, delay))
    while True:
        if (verify_interface_ip_address(dut,  client_intf, "{}/{}".format(client_ip, data.ipv4_mask)) and
            verify_interface_ip_address(dut,  server_intf, "{}/{}".format(server_ip, data.ipv4_mask))):
            return True
        if itercount > iteration:
            st.log("For IP config verification max iteration count {} reached".format(itercount))
            return False
        itercount += delay
        st.wait(delay)


def poll_for_warm_restart_orchagent_status(dut, iteration=20, delay=2):
    itercount = 1
    st.log("Warm restart orchagent status verification, iterations = {} and iterdelay = {}".format(iteration, delay))
    while True:
        if verify_warm_restart(dut, mode='state', name='orchagent', state='reconciled'):
            return True
        if itercount > iteration:
            st.log("For warm restart orchagent status verification max iteration count {} reached".format(itercount))
            return False
        itercount += delay
        st.wait(delay)


def poll_for_warm_restart_aclsvcd_status(dut, iteration=20, delay=2):
    itercount = 1
    st.log("Warm restart aclsvcd status verification, iterations = {} and iterdelay = {}".format(iteration, delay))
    while True:
        if verify_warm_restart(dut, mode='state', name='aclsvcd', state='reconciled'):
            return True
        if itercount > iteration:
            st.log("For warm restart aclsvcd status verification max iteration count {} reached".format(itercount))
            return False
        itercount += delay
        st.wait(delay)


def reboot_or_docker_restart_test(boottype=''):
    intf_ip_list       = [
                          {'name': vars.D1T1P1, 'ip': data.ipv4_addr_intf['d1t1p1_ip'], 'subnet': 24, 'family': data.af_ipv4},
                          {'name': vars.D1T1P3, 'ip': data.ipv4_addr_intf['d1t1p3_ip'], 'subnet': 24, 'family': data.af_ipv4},
                         ]
    client_intf        = client_dut_intf['c1_intf']
    server_intf        = server_dut_intf['s1_intf']

    st.log("configuring the dut ports connected to TGen with ip addresses")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='add')

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    if not (verify_interface_ip_address(vars.D1, client_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_mask)) and
            verify_interface_ip_address(vars.D1, server_intf, "{}/{}".format(data.ipv4_addr_intf['d1t1p3_ip'], data.ipv4_mask))):
        report_msg = ", ".join([client_intf, server_intf])
        st.report_fail("IP_config_verification_failed_on_interfaces", report_msg)

    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    st.log("Verifying IP helper status")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    st.log("Configure IP helper address {} on interface {}".format(data.ip_helper_address[0], client_intf))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=client_intf, ip_address=data.ip_helper_address[0])

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("Verify the IP helper address configuration on interface {}.".format(client_intf))
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_intf, 'vrf': '', 'relay_address': data.ip_helper_address[0]}]):
        st.report_fail("IP_helper_config_verification_failed", client_intf)

    st.log("Performing Config save")
    config_save(vars.D1)

    # Check the docker part
    if boottype == '':
        st.log("Swss docker restart")
        service_operations_by_systemctl(vars.D1, "swss", "restart")
        st.log("Wait for swss docker restart")
        if not poll_for_system_status(vars.D1):
            st.report_fail("service_not_running", 'swss')
        if not verify_service_status(vars.D1, 'swss'):
            st.report_fail("IP_helper_service_is_not_up")
    else:
        st.log("Performing {} Reboot".format(boottype))
        st.reboot(vars.D1, boottype)

    st.log("Verifying IP Helper configuration post reboot")
    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                'enable_ports': ['TFTP', 'NTP', 'DNS', 'TACACS', 'NetBios-Name-Server', 'NetBios-Datagram-Server']}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    # Check IP helper config
    if data.hlpr_debug_prints:
        ip_helper_obj.show(vars.D1, helper_address='')

    st.log("After reboot, verify the IP helper address configuration on interface {}.".format(client_intf))
    if not ip_helper_obj.verify(vars.D1, helper_address='',
                                verify_list=[{'interface': client_intf, 'vrf': '', 'relay_address': data.ip_helper_address[0]}]):
        st.report_fail("IP_helper_config_verification_failed", client_intf)

    # Check IP config on interface
    if data.hlpr_debug_prints:
        get_interface_ip_address(vars.D1)

    if boottype == 'warm':
        ip_config_status = poll_for_ip_address_verification_status(vars.D1, client_intf, server_intf, data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_addr_intf['d1t1p3_ip'], iteration=20, delay=2)
    else:
        ip_config_status = poll_for_ip_address_verification_status(vars.D1, client_intf, server_intf, data.ipv4_addr_intf['d1t1p1_ip'], data.ipv4_addr_intf['d1t1p3_ip'])

    if not ip_config_status:
        report_msg = ", ".join([client_intf, server_intf])
        st.report_fail("IP_config_verification_failed_on_interfaces", report_msg)

    if st.is_feature_supported("warm-reboot"):
        if boottype == 'warm':
            if not poll_for_warm_restart_orchagent_status(vars.D1):
                st.log("Warm restart orchagent verification failed")
                st.report_fail("IP_helper_test_case_msg_status", "failed",
                               "due to orchagent is not in reconciled state after warm-restart")
            if not poll_for_warm_restart_aclsvcd_status(vars.D1):
                st.log("Warm restart aclsvcd verification failed")
                st.report_fail("IP_helper_test_case_msg_status", "failed", "due to aclsvcd is not in reconciled state after warm-restart")
            #st.wait(4)

    st.wait(5)
    util_create_tg_streams(tg_handler["tg_ph_1"],  prot_port_di={'tftp': '69'})

    st.log("Initiate broadcast UDP traffic from TG1 and check traffic relayed to server")
    protocol_name = 'tftp'
    value_list = ['11', '10.10.10.1', '30.30.30.1', proto_udp_port[protocol_name]]
    result = send_and_validate_helper_traffic(client_intf,
                                              server_intf,
                                              data.streams["tg1"][protocol_name],
                                              tg_handler["tg_ph_1"],
                                              tg_handler['tg_ph_3'],
                                              header_li, value_list)

    st.log("Removing helper config on {}".format(client_intf))
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=client_intf, ip_address=data.ip_helper_address[0])

    st.log("Removing IP configuration")
    config_unconfig_interface_ip_addresses(vars.D1, intf_ip_list, config='remove')

    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='disable')

    if boottype == '':
        boot_type = "docker restart"
    else:
        boot_type = boottype+" reboot"

    if not result:
        st.report_fail("Failed_to_relay_UDP_packets_after_restart", boot_type)

    st.report_pass("Pkts_to_relay_UDP_packets_after_restart", boot_type)


# Case: RtIpHeAdFn012
def test_ip_helper_cold_reboot():
    reboot_or_docker_restart_test(boottype='normal')


# Case: RtIpHeAdFn013
def test_ip_helper_fast_reboot():
    reboot_or_docker_restart_test(boottype='fast')


# Case: RtIpHeAdFn015
def test_ip_helper_docker_restart():
    reboot_or_docker_restart_test()


# Case: RtIpHeAdFn014
def test_ip_helper_warm_reboot():
    reboot_or_docker_restart_test(boottype='warm')

