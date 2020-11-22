
import re

from spytest import st,utils
from spytest.tgen.tgen_utils import validate_tgen_traffic

from dpb_vars import data
import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.ospf as ospf_api
import apis.system.basic as basic_api
import apis.system.interface as intf_api
import apis.system.lldp as lldp_api
import apis.switching.pvst as stp_api
import apis.routing.bgp as bgp_api
import apis.system.port as port_api
import apis.routing.vrrp as vrrp_api
import apis.switching.udld as udld_api
import apis.routing.ip_bgp as ipbgp_api
import apis.qos.acl_dscp as acl_dscp_api
import apis.common.asic_bcm as asic_api

from utilities import parallel
from utilities.utils import retry_api
import utilities.common as utils_api


def dpb_base_config():
    ###################################################
    st.banner("########## BASE Config Starts ########")
    ###################################################
    debug_enable()
    config_lag()
    config_vlan()
    result = verify_lag()
    if not result:
        config_lag('no')
        return False
    ###################################################
    st.banner("########## BASE Config End ########")
    ###################################################
    return True

def config_tgen():
    config_stream(config='yes')

def deconfig_tgen():
    config_stream('no')

def dpb_base_deconfig():
    ###################################################
    st.banner("########## BASE De-Config Starts ########")
    ###################################################
    api_list = [[deconfig_tgen]]
    parallel.exec_all(True, api_list, True)
    st.log("Reverting the speed back to the original speed value")
    port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[0],speed=data.base_speed,skip_error="yes")
    if not retry_api(port_api.verify_dpb_status,data.dut1,interface=data.d1d2_ports[0],status='Completed',retry_count=12, delay=5):
        st.log("No change in port breakout mode since the speed is {}".format(data.base_speed))

    ###################################################
    st.banner("########## BASE De-Config End ########")
    ###################################################
    return True

def debug_enable(config='yes'):
    pass

def config_lag(config='yes'):
    if config == 'yes':
        member_flag = 'add'
        ###################################################
        st.banner("LAG-Config: Configure {} between D1 and D2 with 2 member ports".format(data.lag_intf))
        ###################################################

        utils.exec_all(True, [[pc.create_portchannel, data.dut1, [data.lag_intf], False],
                              [pc.create_portchannel, data.dut2, [data.lag_intf], False]])

        ###################################################################
        st.banner("LAG-Config: {} member ports to {} on D1 and D3".format(member_flag,data.lag_intf))
        ###################################################################
        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut1,data.lag_intf,data.d1d2_ports,member_flag],
                          [pc.add_del_portchannel_member, data.dut2, data.lag_intf,data.d2d1_ports,member_flag]])


    else :

        ###################################################################
        st.banner("Cleaning up the Port-channel and its memeber ports")
        ###################################################################

        member_flag = 'del'

        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut1,data.lag_intf,data.d1d2_ports,member_flag],
                              [pc.add_del_portchannel_member, data.dut2, data.lag_intf,data.d2d1_ports,member_flag]])

        utils.exec_all(True, [[pc.delete_portchannel, data.dut1, [data.lag_intf]],
                              [pc.delete_portchannel, data.dut2, [data.lag_intf]]])

def verify_lag():
    ###################################################################
    st.banner("Verify Port-Channels are UP on DUT1 and DUT2")
    ###################################################################
    ret_val = True
    err_list = []
    result = retry_api(pc.verify_portchannel_state, data.dut1, portchannel=data.lag_intf)
    if result is False:
        err_list.append("{} did not come up on dut1".format(data.lag_intf))
        ret_val = False
    return ret_val


def config_po_vlan(config='yes'):
    if config == 'yes':
        ###################################################################
        st.banner("Vlan-Config: Configure Vlan {} on D1 and D2".format(data.d1tg_vlan_id))
        ###################################################################
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, data.d1tg_vlan_id],
                              [vlan_api.create_vlan, data.dut2, data.d1tg_vlan_id]])

        ###################################################################
        st.banner("Vlan-Config: Configure a tagged Vlan member between D1 and D2 and assign portchannel {} as part of vlan {}".format(data.lag_intf,data.d1tg_vlan_id))
        ###################################################################
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.d1tg_vlan_id, data.lag_intf, True],
                              [vlan_api.add_vlan_member, data.dut2, data.d1tg_vlan_id, data.lag_intf, True]])

        st.log ("Configuring Ipv4 address on the Vlan interface")
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1tg_vlan_intf, data.vrrp_d1_ip, data.mask_v4],
                          [ip_api.config_ip_addr_interface, data.dut2, data.d1tg_vlan_intf, data.vrrp_d2_ip, data.mask_v4]])


    else:

        st.log ("Remove the Ipv4 address on the lag interface")
        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1tg_vlan_intf, data.vrrp_d1_ip, data.mask_v4],
                      [ip_api.delete_ip_interface, data.dut2, data.d1tg_vlan_intf, data.vrrp_d2_ip, data.mask_v4]])
        ###################################################################
        st.banner("Vlan-DeConfig: Remove all Vlan membership from ports on all DUTs")
        ###################################################################
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.d1tg_vlan_id, data.lag_intf,True],
                              [vlan_api.delete_vlan_member, data.dut2, data.d1tg_vlan_id, data.lag_intf,True]])


        ###################################################################
        st.banner("Vlan-DeConfig: Delete Vlans on all DUTs")
        ###################################################################
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, data.d1tg_vlan_id],
                              [vlan_api.create_vlan, data.dut2, data.d1tg_vlan_id]])



def get_intf_count(portlist=None):
    intf_count = 0
    if portlist is None: portlist = data.d1d2_ports
    intf_api.clear_interface_counters(data.dut1,Interface_Type=all)
    st.wait(5)
    for dut_port in portlist:
        DUT_TX = intf_api.get_interface_counters(data.dut1, dut_port, "tx_ok")
        for i in DUT_TX:
            d1_tx = i['tx_ok']
            d1_tx = int(d1_tx.replace(",",""))
        if d1_tx > 1000:
            st.log("Traffic is getting forwarded on the port {}".format(dut_port))
            intf_count += 1
    return intf_count


def verify_forwd_counters(portlist=None):

    '''
    :param portlist:
    :return:
    This proc is used to verify the traffic is not flooded instead forwarded over the single port
    '''

    ret_val = True
    traf_intf_count = 0
    traf_not_intf_count = 0
    if portlist is None: portlist = data.d1d2_ports
    intf_api.clear_interface_counters(data.dut1,Interface_Type=all)
    st.wait(5)
    for dut_port in portlist:
        DUT_TX = intf_api.get_interface_counters(data.dut1, dut_port, "tx_ok")
        for i in DUT_TX:
            d1_tx = i['tx_ok']
            d1_tx = int(d1_tx.replace(",",""))
        if d1_tx > 1000:
            st.log("Traffic is getting forwarded on the port {}".format(dut_port))
            traf_intf_count += 1
        else:
            st.log("Traffic is not getting forwarded on the port {}".format(dut_port))
            traf_not_intf_count += 1

    if traf_intf_count != 1 and traf_not_intf_count != 4:
        st.log('Traffic is getting forwarded/flooded on the port, please check the counters')
        debug_traffic(clear='no')
        ret_val = False

    return ret_val



def config_vlan(config='yes'):
    if config == 'yes':
        ###################################################################
        st.banner("Vlan-Config: Configure Vlan {} on D1 and D2".format(data.d1tg_vlan_id))
        ###################################################################
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, data.d1tg_vlan_id],
                              [vlan_api.create_vlan, data.dut2, data.d1tg_vlan_id]])

        ###################################################################
        st.banner("Vlan-Config: Configure a tagged Vlan member between D1 and D2, Tgen and nodes on vlan {}".format(data.d1tg_vlan_id))
        ###################################################################
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.d1tg_vlan_id, data.d1ports, True],
                              [vlan_api.add_vlan_member, data.dut2, data.d1tg_vlan_id, data.d2ports, True]])

        data.tg_d1_dest_mac = basic_api.get_ifconfig(data.dut1,data.d1tg_vlan_intf)[0]['mac']
        data.tg_d1_dest_mac_phy = basic_api.get_ifconfig(data.dut1, data.d1tg_ports[0])[0]['mac']

    else:
        ###################################################################
        st.banner("Vlan-DeConfig: Remove all Vlan membership from ports on all DUTs")
        ###################################################################
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.d1tg_vlan_id, data.d1ports,True],
                              [vlan_api.delete_vlan_member, data.dut2, data.d1tg_vlan_id, data.d2ports,True]])


        ###################################################################
        st.banner("Vlan-DeConfig: Delete Vlans on all DUTs")
        ###################################################################
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, data.d1tg_vlan_id],
                              [vlan_api.create_vlan, data.dut2, data.d1tg_vlan_id]])


def verify_vlan(vlan_list=data.d1tg_vlan_id,port_list=None):
    ###################################################################
    st.log("Verify-Vlan-Config: Make sure the ports are part of the Vlan {} on both the nodes".format(vlan_list))
    ###################################################################

    if port_list is None: port_list = [data.d1ports,data.d2ports]

    ret_val= True
    for i,j in zip([data.dut1,data.dut2],port_list):
        if not vlan_api.verify_vlan_config(dut=i,vlan_list=data.d1tg_vlan_id, tagged=j):
            ret_val = False
            st.log('Port {} are not part of the vlan {}'.format(j,data.d1tg_vlan_id))
    return ret_val


def get_intf_counters(portlist=None,debug=None,tx_pkt=None,wait=None):
    ret_val = True
    if portlist is None: portlist = data.d1d2_ports
    if debug is None: debug = 'yes'
    if tx_pkt is None: tx_pkt = 1000
    if wait is None: wait = 5

    intf_api.clear_interface_counters(data.dut1,Interface_Type=all)
    st.wait(wait)
    for dut_port in portlist:
        DUT_TX = intf_api.get_interface_counters(data.dut1, dut_port, "tx_ok")
        for i in DUT_TX:
            d1_tx = i['tx_ok']
            d1_tx = int(d1_tx.replace(",",""))
        if d1_tx > tx_pkt:
            st.log("Traffic is forwarded on the port {}".format(dut_port))
        else:
            st.log("Traffic is not getting forwarded on the port {}".format(dut_port))
            if debug == 'yes':
                debug_traffic(clear='no')
            ret_val = False

    return ret_val

def router_config(config='yes',addr='V4'):
    if config == 'yes':

        #################################################
        st.banner("Configure Vlan and IP address before enabling the routing protocol")
        #################################################

        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, data.vlan_list_id[:2]],
                              [vlan_api.create_vlan, data.dut2, data.vlan_list_id[1:]]])

        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.access_vlan_id, data.d1d2_ports[0], True],
                              [vlan_api.add_vlan_member, data.dut2, data.access_vlan_id, data.d2d1_ports[0], True]])

        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.vlan_list_id[0], data.d1tg_ports[0], True],
                              [vlan_api.add_vlan_member, data.dut2, data.vlan_list_id[-1], data.d2tg_ports[0], True]])

        st.log ("Configuring Ipv4 address on the vlan interface")
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.lag_vlan_intf, data.d1tg_ip_list[-1], data.mask_v4],
                              [ip_api.config_ip_addr_interface, data.dut2, data.d1tg_vlan_intf, data.d3tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.access_vlan_intf , data.d2tg_ip_list[0], data.mask_v4],
                              [ip_api.config_ip_addr_interface, data.dut2, data.access_vlan_intf , data.d2tg_ip_list[-1], data.mask_v4]])


        st.log ("Configuring Ipv4 address on the loopback interface")
        ip_api.configure_loopback(data.dut1, loopback_name=data.loopback_intf)
        ip_api.configure_loopback(data.dut2, loopback_name=data.loopback_intf)

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.loopback_intf, data.d1_router_id, data.mask_lo_v4 ],
                              [ip_api.config_ip_addr_interface, data.dut2, data.loopback_intf, data.d2_router_id
                                  , data.mask_lo_v4 ]])

        if addr == 'V6':

            #################################################
            st.banner("Configure IPv6 address before enabling the protocol")
            #################################################


            dict1 = {'family':'ipv6', 'config':'add', 'interface_name':data.lag_vlan_intf, 'ip_address':data.d1tg_ipv6_list[-1], 'subnet':data.mask_v6}
            dict2 = {'family':'ipv6', 'config':'add', 'interface_name':data.d1tg_vlan_intf, 'ip_address':data.d3tg_ipv6_list[-1], 'subnet':data.mask_v6 }
            dict3 = {'family':'ipv6', 'config':'add', 'interface_name':data.access_vlan_intf, 'ip_address':data.d2tg_ipv6_list[0], 'subnet':data.mask_v6}
            dict4 = {'family':'ipv6', 'config':'add', 'interface_name':data.access_vlan_intf, 'ip_address':data.d2tg_ipv6_list[-1], 'subnet':data.mask_v6 }
            dict5 = {'family':'ipv6', 'config':'add', 'interface_name':data.loopback_intf, 'ip_address':data.d1loop_ipv6_addr, 'subnet':data.mask_lo_v6}
            dict6 = {'family':'ipv6', 'config':'add', 'interface_name':data.loopback_intf, 'ip_address':data.d2loop_ipv6_addr, 'subnet':data.mask_lo_v6 }

            parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict1,dict2])
            parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict3,dict4])
            parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict5,dict6])


    else:
        ######################################
        st.banner("Remove the router configurations from both the nodes")
        ######################################

        st.log ("Un-Configuring Ipv4 address")
        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.lag_vlan_intf, data.d1tg_ip_list[-1], data.mask_v4],
                              [ip_api.delete_ip_interface, data.dut2, data.d1tg_vlan_intf, data.d3tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.access_vlan_intf , data.d2tg_ip_list[0], data.mask_v4],
                              [ip_api.delete_ip_interface, data.dut2, data.access_vlan_intf , data.d2tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.access_vlan_id, data.d1d2_ports[0], True],
                              [vlan_api.delete_vlan_member, data.dut2, data.access_vlan_id, data.d2d1_ports[0], True]])

        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.vlan_list_id[0], data.d1tg_ports[0], True],
                              [vlan_api.delete_vlan_member, data.dut2, data.vlan_list_id[-1], data.d2tg_ports[0], True]])

        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, data.vlan_list_id[:2]],
                              [vlan_api.delete_vlan, data.dut2, data.vlan_list_id[1:]]])

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.loopback_intf, data.d1_router_id, data.mask_lo_v4 ],
                              [ip_api.delete_ip_interface, data.dut2, data.loopback_intf, data.d2_router_id
                                  , data.mask_lo_v4 ]])

        if addr == 'V6':

            #################################################
            st.banner("Removing  IPv6 address from the interface")
            #################################################

            dict1 = {'family':'ipv6', 'config':'remove', 'interface_name':data.lag_vlan_intf, 'ip_address':data.d1tg_ipv6_list[-1], 'subnet':data.mask_v6}
            dict2 = {'family':'ipv6', 'config':'remove', 'interface_name':data.d1tg_vlan_intf, 'ip_address':data.d1tg_ipv6_list[-1], 'subnet':data.mask_v6 }
            dict3 = {'family':'ipv6', 'config':'remove', 'interface_name':data.access_vlan_intf, 'ip_address':data.d2tg_ipv6_list[0], 'subnet':data.mask_v6}
            dict4 = {'family':'ipv6', 'config':'remove', 'interface_name':data.access_vlan_intf, 'ip_address':data.d2tg_ipv6_list[-1], 'subnet':data.mask_v6 }
            dict5 = {'family':'ipv6', 'config':'remove', 'interface_name':data.loopback_intf, 'ip_address':data.d1loop_ipv6_addr, 'subnet':data.mask_lo_v6}
            dict6 = {'family':'ipv6', 'config':'remove', 'interface_name':data.loopback_intf, 'ip_address':data.d2loop_ipv6_addr, 'subnet':data.mask_lo_v6}

            parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict1,dict2])
            parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict3,dict4])
            parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict5,dict6])


        ip_api.configure_loopback(data.dut1, loopback_name=data.loopback_intf,config='no')
        ip_api.configure_loopback(data.dut2, loopback_name=data.loopback_intf,config='no')


def config_stream(config='yes'):
    if config == 'yes':
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, data.lag_vlan_id],
                              [vlan_api.create_vlan, data.dut2, data.d1tg_vlan_id]])
        dut1_gw_mac = basic_api.get_ifconfig(data.dut1, data.lag_vlan_intf)[0]['mac']
        dut2_gw_mac = basic_api.get_ifconfig(data.dut2, data.d1tg_vlan_intf)[0]['mac']
        data.tg1.tg_traffic_control(action='reset', port_handle=data.tg_handles)
        data.tg2.tg_traffic_control(action='reset', port_handle=data.tg_handles)
        data.stream_handles = {}
        data.stream_details = {}
        data.host_handles ={}

        st.log('the pps for the arp traffic is set to {}'.format(data.sent_rate_pps))

        ##########################################################################
        st.banner("TGEN: Configure L3 host for ARP resolution")
        ##########################################################################

        data.tg1.tg_interface_config(port_handle=data.tg_handles[0], mode='config', intf_ip_addr=data.d1tg_ip_list[0], \
                                     gateway=data.d1tg_ip_list[-1], src_mac_addr=data.src_mac[data.tgd1_handles[0]],vlan=1,vlan_id =data.lag_vlan_id, arp_send_req='1',enable_ping_response=1)

        data.tg2.tg_interface_config(port_handle=data.tg_handles[2], mode='config', intf_ip_addr=data.d3tg_ip_list[0], \
                                     gateway=data.d3tg_ip_list[-1], src_mac_addr=data.src_mac[data.tgd2_handles[0]],vlan=1,vlan_id =data.d1tg_vlan_id, arp_send_req='1',enable_ping_response=1)
        data.tg1.tg_interface_config(port_handle=data.tg_handles[0], mode='config', ipv6_intf_addr=data.d1tg_ipv6_list[0], \
                                     ipv6_gateway=data.d1tg_ipv6_list[-1], src_mac_addr=data.src_mac[data.tgd1_handles[0]],
                                     vlan=1, vlan_id=data.lag_vlan_id, arp_send_req='1', enable_ping_response=1)

        data.tg2.tg_interface_config(port_handle=data.tg_handles[2], mode='config', ipv6_intf_addr=data.d3tg_ipv6_list[0], \
                                     ipv6_gateway=data.d3tg_ipv6_list[-1], src_mac_addr=data.src_mac[data.tgd2_handles[0]],
                                     vlan=1, vlan_id=data.d1tg_vlan_id, arp_send_req='1', enable_ping_response=1)


        ##########################################################################
        st.banner("TGEN: Configure L2 unknown unicast stream")
        ##########################################################################

        data.l2_streams = []
        data.l3_streams = []
        data.l3_Ipv6_streams = []
        data.arp_streams = []
        l2_flood_stream_1 = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.dst_mac_l2,
                                                       l2_encap='ethernet_ii_vlan',
                                                       vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                       rate_pps=data.traffic_rate, \
                                                       mode='create', port_handle=data.tg_handles[0],
                                                       transmit_mode='continuous')

        data.stream_handles['l2_flood_1'] = l2_flood_stream_1['stream_id']
        st.log("L2 stream {} is created for Tgen port {}".format(data.stream_handles['l2_flood_1'],data.dut1))
        data.l2_streams.append(data.stream_handles['l2_flood_1'])

        ##########################################################################
        st.banner("TGEN: Configure L2 known unicast stream")
        ##########################################################################

        l2_flood_stream_2 = data.tg2.tg_traffic_config(mac_src=data.src_mac[data.tgd2_handles[0]], mac_dst=data.dst_mac_l1,
                                                           l2_encap='ethernet_ii_vlan',
                                                           vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                           rate_pps=data.traffic_rate, \
                                                           mode='create', port_handle=data.tg_handles[2],
                                                           transmit_mode='continuous')

        data.stream_handles['l2_flood_2'] = l2_flood_stream_2['stream_id']
        st.log("L2 stream {} is created for Tgen port {}".format(data.stream_handles['l2_flood_2'],data.dut2))
        data.l2_streams.append(data.stream_handles['l2_flood_2'])

        ##########################################################################
        st.banner("TGEN: Configure Ipv4 traffic stream")
        ##########################################################################

        stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]],
                                      mac_dst=dut1_gw_mac, rate_pps=1000, mode='create', port_handle=data.tg_handles[0],
                                      l2_encap='ethernet_ii_vlan', transmit_mode='continuous', ip_src_count=1,
                                      ip_src_addr=data.d1tg_ip_list[0], ip_src_step="0.0.0.1",
                                      ip_dst_addr=data.d3tg_ip_list[0], ip_dst_count=1, ip_dst_step="0.0.0.1",
                                      l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                      vlan_id=data.lag_vlan_id, vlan="enable",
                                      mac_discovery_gw=data.d1tg_ip_list[-1])

        stream3 = stream['stream_id']
        st.log("Ipv4 stream {} is created for Tgen port {}".format(stream3, data.d1tg_ports[0]))
        data.l3_streams.append(stream3)


        stream = data.tg2.tg_traffic_config(mac_src=data.src_mac[data.tgd2_handles[0]],
                                      mac_dst=dut2_gw_mac, rate_pps=1000, mode='create', port_handle=data.tg_handles[2],
                                      l2_encap='ethernet_ii_vlan', transmit_mode='continuous', ip_src_count=1,
                                      ip_src_addr=data.d3tg_ip_list[0], ip_src_step="0.0.0.1",
                                      ip_dst_addr=data.d1tg_ip_list[0], ip_dst_count=1, ip_dst_step="0.0.0.1",
                                      l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                      vlan_id=data.d1tg_vlan_id, vlan="enable",
                                      mac_discovery_gw=data.d3tg_ip_list[-1])

        stream4 = stream['stream_id']
        st.log("Ipv4 stream {} is created for Tgen port {}".format(stream4, data.d2tg_ports[0]))
        data.l3_streams.append(stream4)

        ##########################################################################
        st.banner("TGEN: Configure Ipv6 traffic stream")
        ##########################################################################

        stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[1]], mac_dst=dut1_gw_mac, rate_pps=1000, mode='create', port_handle=data.tg_handles[0],
                                            l2_encap='ethernet_ii_vlan', transmit_mode='continuous',l3_protocol='ipv6', vlan_id=data.lag_vlan_id, vlan="enable",ipv6_src_addr=data.d1tg_ipv6_list[0]
                                            , ipv6_dst_addr=data.d3tg_ipv6_list[0], mac_discovery_gw=data.d1tg_ipv6_list[-1])

        stream5 = stream['stream_id']
        st.log("Ipv6 stream {} is created for Tgen port {}".format(stream5, data.d1tg_ports[0]))
        data.l3_Ipv6_streams.append(stream5)


        stream = data.tg2.tg_traffic_config(mac_src=data.src_mac[data.tgd2_handles[1]],
                                            mac_dst=dut2_gw_mac, rate_pps=1000, mode='create', port_handle=data.tg_handles[2], l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                            vlan_id=data.d1tg_vlan_id, vlan="enable",l3_protocol='ipv6',ipv6_src_addr=data.d3tg_ipv6_list[0], ipv6_dst_addr=data.d1tg_ipv6_list[0], mac_discovery_gw=data.d3tg_ipv6_list[-1])

        stream6 = stream['stream_id']
        st.log("Ipv6 stream {} is created for Tgen port {}".format(stream6, data.d2tg_ports[0]))
        data.l3_Ipv6_streams.append(stream6)

        ##########################################################################
        st.banner("TGEN: Configure a control packet stream(ARP) to verify the COPP behavior")
        ##########################################################################



        stream = data.tg1.tg_traffic_config(port_handle=data.tg_handles[0], mac_src="00:00:00:11:11:80", mac_dst="FF:FF:FF:FF:FF:FF",
                             mode='create', transmit_mode='continuous',rate_pps=data.sent_rate_pps, l2_encap='ethernet_ii',
                             l3_protocol='arp', arp_src_hw_addr="00:00:00:11:11:80", arp_dst_hw_addr="00:00:00:00:00:00",
                             arp_operation='arpRequest', ip_src_addr=data.d1tg_ip_list[0], ip_dst_addr=data.d1tg_ip_list[1])
        stream7 = stream['stream_id']
        st.log("ARP control stream {} is created for Tgen port {}".format(stream7, data.d1tg_ports[0]))
        data.arp_streams.append(stream7)


    else:
        ##########################################################################
        st.banner("TGEN-DeConfig: Delete Traffic Streams on all TG ports ")
        ##########################################################################

        data.tg1.tg_traffic_control(action='reset', port_handle=data.tg_handles)
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, data.lag_vlan_id],
                              [vlan_api.delete_vlan, data.dut2, data.d1tg_vlan_id]])


def run_traffic(action='start',stream_handle=[]):
    if type(stream_handle) is not list : stream_handle =[stream_handle]
    if action =='start': st.log(" #### Starting Traffic for  streams #####")
    if action == 'stop': st.log(" #### Stopping Traffic for streams  #####")
    if action == 'start':
        data.tg1.tg_traffic_control(action='clear_stats',port_handle=data.tg_handles)
        data.tg1.tg_traffic_control(action='run', stream_handle=stream_handle)
        st.wait(4)
    else:
        data.tg1.tg_traffic_control(action='stop', stream_handle=stream_handle)


def verify_traffic(src_tg_obj=None,dest_tg_obj=None,src_port=None,dest_port=None,exp_ratio=1,comp_type='packet_rate',**kwargs):
    ret_val= True
    if src_tg_obj is None: src_tg_obj = data.tg1
    if dest_tg_obj is None : dest_tg_obj = data.tg2
    if src_port is None : src_port = data.tgd1_ports[0]
    if dest_port is None: dest_port = data.tgd2_ports[0]
    traffic_data = {
        '1': {
            'tx_ports': [src_port],
            'tx_obj': [src_tg_obj],
            'exp_ratio': [exp_ratio],
            'rx_ports': [dest_port],
            'rx_obj': [dest_tg_obj]
        }
    }
    delay = kwargs.pop('delay',data.delay_factor)
    retry_count = kwargs.pop('retry_count',2)
    for iteration in range(retry_count):
        st.log("\n>>>>   ITERATION : {} <<<<<\n".format(iteration+1))
        aggregate_result = validate_tgen_traffic(traffic_details=traffic_data, mode='aggregate', comp_type=comp_type, delay_factor=delay)
        if aggregate_result:
            st.log('Traffic verification passed ')
            ret_val = True
            break
        else:
            ret_val =False
            st.log('Traffic verification Failed ')
            debug_traffic()
            continue
    return ret_val


def verify_flood_counters(portlist=None,intf_count=None):
    '''

    :param portlist:
    :param intf_count:
    :return:
    This proc is to verify the traffic is getting flooded over all the ports
    '''
    ret_val= True
    if portlist is None: portlist = data.d1d2_ports
    if intf_count is None: intf_count = 5
    intf_api.clear_interface_counters(data.dut1,Interface_Type=all)
    #intf_api.clear_interface_counters(data.dut2,Interface_Type=all)
    st.wait(5)
    for dut_port in portlist:
        DUT_TX = intf_api.get_interface_counters(data.dut1, dut_port, "tx_ok")
        for i in DUT_TX:
            d1_tx = i['tx_ok']
            d1_tx = int(d1_tx.replace(",",""))
        if d1_tx > 10000:
            st.log("Traffic is getting flooded on the port {}".format(dut_port))
            intf_count -= 1
        else:
            st.log(" Traffic is not getting flooded on the {}  port".format(dut_port))

    if intf_count != 0:
        st.log('Traffic is not as expected, please check the debug logs')
        debug_traffic(clear = 'no')
        ret_val = False

    return ret_val


def verify_lldp(portlist=None,dut=None):
    ret_val = True
    if portlist is None: portlist = data.d1d2_ports[:-1]
    if dut is None: dut = data.dut1
    for dut_port in portlist:
        lldp_info = lldp_api.get_lldp_neighbors(dut,interface=dut_port)
        if not lldp_info:
            st.error("No lldp entries are available for the interface {}".format(dut_port))
            ret_val = False
    return ret_val


def verify_stp(portlist=None,dut=None):
    ret_val = True
    Sf = 0
    Sd = 0
    if portlist is None: portlist = data.d1d2_ports
    if dut is None: dut = data.dut1
    for dut_port in portlist:
        state = stp_api.show_stp_vlan_iface(data.dut1,vlan=data.d1tg_vlan_id,iface=dut_port)[0]['port_state']
        if state == 'FORWARDING':
            Sf += 1
        elif state == 'DISCARDING':
            Sd += 1
        else:
            st.error('STP state expected (FORWARDING/DISCARDING), Actual is {}'.format(state))
            ret_val = False

    if Sf == 1 and Sd == 4:
        st.log('STP port states are as expected')
    else:
        st.error('STP port states are not as expected, Expected: 1 forwarding, 4 Discarding but actual {} forwarding, {} Discarding'.format(Sf,Sd))
        ret_val = False

    return ret_val


def unnum_config(config='yes'):

    if config == 'yes':

        #################################################
        st.banner("Configure the loopback and unnumbered interface")
        #################################################

        dict1 = {'family':'ipv4', 'action':'add','interface':data.d1d2_ports[-1], 'loop_back':data.loopback_intf}
        dict2 = {'family':'ipv4', 'action':'add','interface':data.d2d1_ports[-1], 'loop_back':data.loopback_intf}

        parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_unnumbered_interface,[dict1,dict2])

    else:

        ######################################
        st.banner("Unconfiguring the Ip unnumbered config")
        ######################################

        dict1 = {'family':'ipv4', 'action':'del','interface':data.d1d2_ports[-1], 'loop_back':data.loopback_intf}
        dict2 = {'family':'ipv4', 'action':'del','interface':data.d2d1_ports[-1], 'loop_back':data.loopback_intf}

        parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_unnumbered_interface,[dict1,dict2])

def config_ospf(config='yes'):
    if config == 'yes':

        #################################################
        st.banner("Configure OSPF neighbors between D1 and D2")
        #################################################

        dict1 = {'router_id': data.d1_router_id}
        dict2 = {'router_id': data.d2_router_id}
        parallel.exec_parallel(True, [data.dut1,data.dut2], ospf_api.config_ospf_router_id, [dict1, dict2])

        dict1 = {'interfaces':[data.lag_vlan_intf,data.access_vlan_intf,data.d1d2_ports[-1],data.loopback_intf],'ospf_area':'0.0.0.0'}
        dict2 = {'interfaces': [data.d1tg_vlan_intf, data.access_vlan_intf, data.d2d1_ports[-1],data.loopback_intf], 'ospf_area': '0.0.0.0'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],ospf_api.config_interface_ip_ospf_area,[dict1,dict2])

        ospf_api.config_interface_ip_ospf_network_type(data.dut1,interfaces=data.d1d2_ports[-1],nw_type='point-to-point')
        ospf_api.config_interface_ip_ospf_network_type(data.dut2,interfaces=data.d2d1_ports[-1],nw_type='point-to-point')

        ospf_api.config_interface_ip_ospf_cost(data.dut1,interfaces=data.d1d2_ports[-1],cost='500')


    else:
        ######################################
        st.banner("Remove OSPF config")
        ######################################

        ospf_api.config_interface_ip_ospf_cost(data.dut1,interfaces=data.d1d2_ports[-1],cost=500,config='no')

        dict1 = {'interfaces':[data.lag_vlan_intf,data.access_vlan_intf,data.d1d2_ports[-1],data.loopback_intf],'ospf_area':'0.0.0.0','config':'no'}
        dict2 = {'interfaces': [data.d1tg_vlan_intf, data.access_vlan_intf, data.d2d1_ports[-1],data.loopback_intf], 'ospf_area': '0.0.0.0','config':'no'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],ospf_api.config_interface_ip_ospf_area,[dict1,dict2])

        ospf_api.config_interface_ip_ospf_network_type(data.dut1,interfaces=data.d1d2_ports[-1],nw_type='point-to-point',config='no')
        ospf_api.config_interface_ip_ospf_network_type(data.dut2,interfaces=data.d2d1_ports[-1],nw_type='point-to-point',config='no')
        ospf_api.config_interface_ip_ospf_cost(data.dut1,interfaces=data.d1d2_ports[-1],cost='500',config='no')

        dict1 = {'config': 'no'}
        parallel.exec_parallel(True, [data.dut1,data.dut2], ospf_api.config_ospf_router, [dict1, dict1])


def verify_ospf(dut1_ospf_intf=None):

    if dut1_ospf_intf is None: dut1_ospf_intf = [data.access_vlan_intf,data.d1d2_ports[-1]]

    for data.vlan in dut1_ospf_intf:
        result = retry_api(ospf_api.verify_ospf_neighbor_state, data.dut1, ospf_links = [data.vlan],
                       states = ['Full'],retry_count=6,delay=10)
        if not result:
            st.warn("OSPF session did not come up on the interface {}".format(data.vlan))
            return False

    return True


def config_bgp(config='yes'):
    if config == 'yes':

        #################################################
        st.banner("Configure BGP neighbors between D1 and D2")
        #################################################

        bgp_input1 = {"router_id": data.d1_router_id, "local_as": data.bgp1_las,
                      "neighbor": data.d2tg_ip_list[-1],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": data.bgp2_las, "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9","weight":100}

        bgp_input2 = {"router_id": data.d2_router_id, "local_as": data.bgp2_las,
                      "neighbor": data.d2tg_ip_list[0],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": data.bgp1_las, "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9"}

        bgp_input3 = {"router_id": data.d1_router_id, "local_as": data.bgp1_las,
                      "neighbor": data.d4tg_ip_list[-1],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": data.bgp2_las, "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9"}

        bgp_input4 = {"router_id": data.d2_router_id, "local_as": data.bgp2_las,
                      "neighbor": data.d4tg_ip_list[0],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": data.bgp1_las, "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9"}

        bgp_input6 = {"local_asn": data.bgp1_las,
                      "neighbor_ip": data.d2tg_ip_list[-1],
                      "remote_asn": data.bgp2_las, 'connect_retry': 3}

        bgp_input7 = {"local_asn": data.bgp2_las,
                       "neighbor_ip": data.d2tg_ip_list[0],
                       "remote_asn": data.bgp1_las, 'connect_retry': 3}

        bgp_input8 = {"local_asn": data.bgp1_las,
                      "neighbor_ip": data.d4tg_ip_list[-1],
                      "remote_asn": data.bgp2_las, 'connect_retry': 3}

        bgp_input9 = {"local_asn": data.bgp2_las,
                      "neighbor_ip": data.d4tg_ip_list[0],
                      "remote_asn": data.bgp1_las, 'connect_retry': 3}



        utils.exec_all(True,[[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[-1] , data.d4tg_ip_list[0], data.mask_v4],
                            [ip_api.config_ip_addr_interface, data.dut2, data.d2d1_ports[-1] , data.d4tg_ip_list[-1], data.mask_v4]])

        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp,[bgp_input1,bgp_input2])
        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp,[bgp_input3,bgp_input4])

        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp_neighbor,[bgp_input6,bgp_input7])
        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp_neighbor,[bgp_input8,bgp_input9])

    else:

        bgp_input11 = {"config_type_list": ["removeBGP"], "local_as": data.bgp1_las,
                       "config" : "no", "removeBGP" : "yes"}

        bgp_input12 = {"config_type_list": ["removeBGP"], "local_as": data.bgp2_las,
                       "config" : "no", "removeBGP" : "yes"}

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1d2_ports[-1] , data.d4tg_ip_list[0], data.mask_v4],
                              [ip_api.delete_ip_interface, data.dut2, data.d2d1_ports[-1] , data.d4tg_ip_list[-1], data.mask_v4]])

        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp,[bgp_input11,bgp_input12])


def verify_bgp(dut1_bgp_neigh=None):

    if dut1_bgp_neigh is None: dut1_bgp_neigh = [data.d2tg_ip_list[-1],data.d4tg_ip_list[-1]]

    for data.neigh in dut1_bgp_neigh:
        result = retry_api(bgp_api.verify_bgp_neighbor,data.dut1,neighbor_ip=data.neigh,state='Established')
        if result is False:
            st.warn("BGP session did not come up on the interface {}".format(data.neigh))
            return False

    return True

def config_static(config='yes'):
    if config == 'yes':
        api_name = ip_api.create_static_route
        #################################################
        st.banner("Configure Static route to reach the edge ports on both D1 and D2")
        #################################################

        dict1 = {'family':'ipv6', 'config':'add', 'interface_name':data.d1d2_ports[-1], 'ip_address':data.d4tg_ipv6_list[0], 'subnet':data.mask_v6}
        dict2 = {'family':'ipv6', 'config':'add', 'interface_name':data.d2d1_ports[-1], 'ip_address':data.d4tg_ipv6_list[-1], 'subnet':data.mask_v6 }

        parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict1,dict2])

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[-1] , data.d4tg_ip_list[0], data.mask_v4],
                              [ip_api.config_ip_addr_interface, data.dut2, data.d2d1_ports[-1] , data.d4tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.vlan_list_id[0], data.d1tg_ports[1], True],
                              [vlan_api.add_vlan_member, data.dut2, data.vlan_list_id[-1], data.d2tg_ports[1], True]])


    else:
        api_name = ip_api.delete_static_route
        #################################################
        st.banner("Delete the Static route entry on both D1 and D2")
        #################################################

        dict1 = {'family':'ipv6', 'config':'remove', 'interface_name':data.d1d2_ports[-1], 'ip_address':data.d4tg_ipv6_list[0], 'subnet':data.mask_v6}
        dict2 = {'family':'ipv6', 'config':'remove', 'interface_name':data.d2d1_ports[-1], 'ip_address':data.d4tg_ipv6_list[-1], 'subnet':data.mask_v6 }

        parallel.exec_parallel(True,[data.dut1,data.dut2],ip_api.config_ip_addr_interface,[dict1,dict2])

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1d2_ports[-1] , data.d4tg_ip_list[0], data.mask_v4],
                              [ip_api.delete_ip_interface, data.dut2, data.d2d1_ports[-1] , data.d4tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.vlan_list_id[0], data.d1tg_ports[1], True],
                      [vlan_api.delete_vlan_member, data.dut2, data.vlan_list_id[-1], data.d2tg_ports[1], True]])


    api_name(data.dut1, next_hop=data.d2tg_ip_list[-1], static_ip=data.static_ip_list[-1])
    api_name(data.dut1, next_hop=data.d4tg_ip_list[-1], static_ip=data.static_ip_list[-1], distance=10)
    api_name(data.dut1, next_hop=data.d2tg_ip_list[-1], static_ip=data.d2loop_ip_list)
    api_name(data.dut1, next_hop=data.d4tg_ip_list[-1], static_ip=data.d2loop_ip_list, distance=10)

    api_name(data.dut2, next_hop=data.d2tg_ip_list[0], static_ip=data.static_ip_list[0])
    api_name(data.dut2, next_hop=data.d4tg_ip_list[0], static_ip=data.static_ip_list[0], distance=10)
    api_name(data.dut2, next_hop=data.d2tg_ip_list[0], static_ip=data.d1loop_ip_list)
    api_name(data.dut2, next_hop=data.d4tg_ip_list[0], static_ip=data.d1loop_ip_list, distance=10)


    api_name(data.dut1, next_hop=data.d2tg_ipv6_list[-1], static_ip=data.static_ipv6_list[-1],family='ipv6')
    api_name(data.dut1, next_hop=data.d4tg_ipv6_list[-1], static_ip=data.static_ipv6_list[-1],family='ipv6', distance=10)
    api_name(data.dut1, next_hop=data.d2tg_ipv6_list[-1], static_ip=data.d2loop_ipv6_list,family='ipv6')
    api_name(data.dut1, next_hop=data.d4tg_ipv6_list[-1], static_ip=data.d2loop_ipv6_list,family='ipv6', distance=10)

    api_name(data.dut2, next_hop=data.d2tg_ipv6_list[0], static_ip=data.static_ipv6_list[0],family='ipv6')
    api_name(data.dut2, next_hop=data.d4tg_ipv6_list[0], static_ip=data.static_ipv6_list[0],family='ipv6', distance=10)
    api_name(data.dut2, next_hop=data.d2tg_ipv6_list[0], static_ip=data.d1loop_ipv6_list,family='ipv6')
    api_name(data.dut2, next_hop=data.d4tg_ipv6_list[0], static_ip=data.d1loop_ipv6_list,family='ipv6', distance=10)


def verify_ping():

    st.log('Verifying Ipv4 ping')
    if not ip_api.ping(data.dut1, data.d3tg_ip_list[-1], family='ipv4',count=5):
        st.warn('Ipv4 ping is failing for the IP address {}'.format(data.d3tg_ip_list[0]))
        return False

    st.log('Verifying Ipv6 ping')
    if not ip_api.ping(data.dut1, data.d3tg_ipv6_list[-1], family='ipv6',count=5):
        st.warn('Ipv6 ping is failing for the IP address {}'.format(data.d3tg_ipv6_list[0]))
        return False

    return True


def config_vrrp(config='yes'):
    if config == 'yes':
        ##############################################################################
        st.log("Configure a VRRP sessions with dut1 Master and dut2 as backup while enabling tracking the breakout port on dut1")
        ##############################################################################

        dict1 = {'vrid': data.vrrp_id, 'vip': data.vrrp_vip, 'interface': data.d1tg_vlan_intf, 'priority': data.vrrp_prio,'config':'yes','enable':'', 'track_interface_list':[data.d1d2_ports[2]],'track_priority_list':[10]}
        dict2 = {'vrid': data.vrrp_id, 'vip': data.vrrp_vip, 'interface': data.d1tg_vlan_intf, 'config':'yes','enable':''}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp_api.configure_vrrp, [dict1, dict2])

    else:
        ##############################################################################
        st.log("Remove the VRRP sessions on both the nodes")
        ##############################################################################

        dict1 = {'vrid': data.vrrp_id, 'interface': data.d1tg_vlan_intf, 'config':'no','disable':''}
        dict2 = {'vrid': data.vrrp_id, 'interface': data.d1tg_vlan_intf, 'config':'no','disable':''}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp_api.configure_vrrp, [dict1, dict2])


def verify_master_backup(master_dut=None,backup_dut=None):
    if master_dut is None: master_dut=data.dut1
    if backup_dut is None: backup_dut=data.dut2
    st.wait(5)

    #########################################################
    st.log("VRID : {} Interface : {} Verify {} is Master and {} is Backup ".format(data.vrrp_id,data.lag_intf,master_dut,backup_dut))
    #########################################################

    dict1 = {'interface': data.d1tg_vlan_intf, 'state': 'Master', 'vrid': data.vrrp_id, 'vip':data.vrrp_vip}
    dict2 = {'interface': data.d1tg_vlan_intf, 'state': 'Backup', 'vrid': data.vrrp_id, 'vip':data.vrrp_vip}
    result = parallel.exec_parallel(True,[master_dut,backup_dut], vrrp_api.verify_vrrp,[dict1,dict2])
    if result is False:
        st.error("{} not elected as VRRP Master for VRID".format(master_dut))
        return False

    return True

def verify_vrrp_track(vrrp_curr_prio = None,vrrp_track_intf= None,vrrp_track_prio= None,vrrp_track_state= None):
    if vrrp_curr_prio is None: vrrp_curr_prio = 105
    if vrrp_track_intf is None: vrrp_track_intf=[data.d1d2_ports[2]]
    if vrrp_track_prio is None: vrrp_track_prio = ['10']
    if vrrp_track_state is None: vrrp_track_state = ['Up']

    result = retry_api(vrrp_api.verify_vrrp,data.dut1, vrid=data.vrrp_id, interface=data.d1tg_vlan_intf,current_prio=vrrp_curr_prio,track_interface_list=vrrp_track_intf, track_priority_list=vrrp_track_prio,track_state_list =vrrp_track_state,retry_count=3, delay=2)
    if result is False:
        st.error('Vrrp track priority {} or vrrp track state {} is not as expected'.format(vrrp_track_prio,vrrp_track_state))
        return False

    return True

def udld_enable(config='yes'):

    if config == 'yes':
        ##############################################################################
        st.log("Configure a UDLD on both dut1 & dut2")
        ##############################################################################

        dict1 = {'udld_enable': 'yes', 'config': 'yes'}
        dict2 = {'udld_enable': 'yes', 'config': 'yes'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],udld_api.config_udld_global, [dict1, dict2])
        st.wait(3)
        dict1 = {'intf': data.d1d2_ports[3],'udld_enable': 'yes', 'config': 'yes'}
        dict2 = {'intf': data.d2d1_ports[3],'udld_enable': 'yes', 'config': 'yes'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],udld_api.config_intf_udld, [dict1, dict2])
        st.wait(3)

    else:
        ##############################################################################
        st.log("Remove the UDLD session on both dut1 & dut2")
        ##############################################################################

        dict1 = {'intf': data.d1d2_ports[3],'udld_enable': '', 'config': 'no'}
        dict2 = {'intf': data.d2d1_ports[3],'udld_enable': '', 'config': 'no'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],udld_api.config_intf_udld, [dict1, dict2])

        dict1 = {'udld_enable': '', 'config': 'no'}
        dict2 = {'udld_enable': '' ,'config': 'no'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],udld_api.config_udld_global, [dict1, dict2])


def verify_udld():

    result = udld_api.verify_udld_neighbors(data.dut1,local_port=data.d1d2_ports[3],
                                   remote_port=data.d2d1_ports[3], \
                                   neighbor_state=['Bidirectional'])

    if result is False:
        st.error('UDLD neighbor state is not as expected')
        return False

    return True


def config_bgp_5549(config='yes'):
    if config == 'yes':

        #################################################
        st.banner("Configure BGP neighbors between D1 and D2")
        #################################################

        bgp_input1 = {"router_id": data.d1_router_id, "local_as": data.bgp1_las,
                      "neighbor": data.d1d2_ports[0],
                      "config_type_list": ['redist','neighbor'],
                       "remote_as": 'external', "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9","weight":100}

        bgp_input2 = {"router_id": data.d2_router_id, "local_as": data.bgp2_las,
                      "neighbor": data.d2d1_ports[0],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": 'external', "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9"}

        bgp_input3 = {"router_id": data.d1_router_id, "local_as": data.bgp1_las,
                      "neighbor": data.d1d2_ports[-1],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": 'external', "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9"}

        bgp_input4 = {"router_id": data.d2_router_id, "local_as": data.bgp2_las,
                      "neighbor": data.d2d1_ports[-1],
                      "config_type_list": ['redist','neighbor'],
                      "remote_as": 'external', "redistribute": "connected",
                      "keepalive":'3',"holdtime":"9"}

        bgp_input6 = {"local_asn": data.bgp1_las,
                      "neighbor_ip": 'interface '+ data.d1d2_ports[0],
                      "remote_asn": 'external', 'connect_retry': 3}

        bgp_input7 = {"local_asn": data.bgp2_las,
                      "neighbor_ip": 'interface '+ data.d2d1_ports[0],
                      "remote_asn": 'external', 'connect_retry': 3}

        bgp_input8 = {"local_asn": data.bgp1_las,
                      "neighbor_ip": 'interface '+ data.d1d2_ports[-1],
                      "remote_asn": 'external', 'connect_retry': 3}

        bgp_input9 = {"local_asn": data.bgp2_las,
                      "neighbor_ip": 'interface '+ data.d2d1_ports[-1],
                      "remote_asn": 'external', 'connect_retry': 3}


        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[-1] , data.d4tg_ip_list[0], data.mask_v4],
                              [ip_api.config_ip_addr_interface, data.dut2, data.d2d1_ports[-1] , data.d4tg_ip_list[-1], data.mask_v4]])

        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp,[bgp_input1,bgp_input2])
        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp,[bgp_input3,bgp_input4])

        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp_neighbor,[bgp_input6,bgp_input7])
        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp_neighbor,[bgp_input8,bgp_input9])


    else:

        bgp_input11 = {"config_type_list": ["removeBGP"], "local_as": data.bgp1_las,
                       "config" : "no", "removeBGP" : "yes"}

        bgp_input12 = {"config_type_list": ["removeBGP"], "local_as": data.bgp2_las,
                       "config" : "no", "removeBGP" : "yes"}

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1d2_ports[-1] , data.d4tg_ip_list[0], data.mask_v4],
                              [ip_api.delete_ip_interface, data.dut2, data.d2d1_ports[-1] , data.d4tg_ip_list[-1], data.mask_v4]])

        parallel.exec_parallel(True,[data.dut1,data.dut2],bgp_api.config_bgp,[bgp_input11,bgp_input12])


def router_config_5549(config='yes'):
    if config == 'yes':

        #################################################
        st.banner("Configure Vlan and IP address before enabling the routing protocol")
        #################################################

        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, data.vlan_list_id[:2]],
                              [vlan_api.create_vlan, data.dut2, data.vlan_list_id[1:]]])

        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.vlan_list_id[0], [data.d1tg_ports[0],data.d1d2_ports[2]], True],
                              [vlan_api.add_vlan_member, data.dut2, data.vlan_list_id[-1], data.d2tg_ports[0], True]])

        st.log ("Configuring Ipv4 address on the vlan interface & enable link local on the DPB ports between the nodes")
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.lag_vlan_intf, data.d1tg_ip_list[-1], data.mask_v4],
                              [ip_api.config_ip_addr_interface, data.dut2, data.d1tg_vlan_intf, data.d3tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[ip_api.config_interface_ip6_link_local, data.dut1, [data.d1d2_ports[0],data.d1d2_ports[-1]]],
                              [ip_api.config_interface_ip6_link_local, data.dut2, [data.d2d1_ports[0],data.d2d1_ports[-1]]]])

        st.log ("Configuring Ipv4 address on the loopback interface")
        ip_api.configure_loopback(data.dut1, loopback_name=data.loopback_intf)
        ip_api.configure_loopback(data.dut2, loopback_name=data.loopback_intf)

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.loopback_intf, data.d1_router_id, data.mask_lo_v4 ],
                              [ip_api.config_ip_addr_interface, data.dut2, data.loopback_intf, data.d2_router_id
                                  , data.mask_lo_v4 ]])

    else:
        ######################################
        st.banner("Remove the router configurations from both the nodes")
        ######################################

        action='disable'

        st.log ("Un-Configuring Ipv4 address")
        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.lag_vlan_intf, data.d1tg_ip_list[-1], data.mask_v4],
                              [ip_api.delete_ip_interface, data.dut2, data.d1tg_vlan_intf, data.d3tg_ip_list[-1], data.mask_v4]])

        utils.exec_all(True, [[ip_api.config_interface_ip6_link_local, data.dut1, [data.d1d2_ports[0],data.d1d2_ports[-1]],action],
                              [ip_api.config_interface_ip6_link_local, data.dut2, [data.d2d1_ports[0],data.d2d1_ports[-1]],action]])

        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.vlan_list_id[0], [data.d1tg_ports[0],data.d1d2_ports[2]], True],
                              [vlan_api.delete_vlan_member, data.dut2, data.vlan_list_id[-1], data.d2tg_ports[0], True]])

        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, data.vlan_list_id[:2]],
                              [vlan_api.delete_vlan, data.dut2, data.vlan_list_id[1:]]])

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.loopback_intf, data.d1_router_id, data.mask_lo_v4 ],
                              [ip_api.delete_ip_interface, data.dut2, data.loopback_intf, data.d2_router_id
                                  , data.mask_lo_v4 ]])

        ip_api.configure_loopback(data.dut1, loopback_name=data.loopback_intf,config='no')
        ip_api.configure_loopback(data.dut2, loopback_name=data.loopback_intf,config='no')


def verify_bgp_5549(dut1_bgp_neigh=None):

    if dut1_bgp_neigh is None: dut1_bgp_neigh = [data.d2tg_ip_list[-1],data.d4tg_ip_list[-1]]

    for data.neigh in dut1_bgp_neigh:
        result = retry_api(ipbgp_api.check_bgp_session,data.dut1,nbr_list=[data.neigh],state_list=["Established"])
        if result is False:
            st.warn("BGP session did not come up on the interface {}".format(data.neigh))
            return False

    return True


def pbr_router_config(config='yes'):
    if config == 'yes':

        #################################################
        st.banner("Configure the classifier and policy map such that the traffic takes the first port")
        #################################################
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_permit_ip,match_type='fields',
                                             class_criteria=['--dst-ip'],
                                             criteria_value=[data.d3tg_ip_list[0]])

        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_vlan,policy_type='forwarding',
                                              class_name=data.class_permit_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.d2tg_ip_list[-1]],next_hop_priority=[100])

        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_vlan,policy_type='forwarding',
                                              class_name=data.class_permit_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.d4tg_ip_list[-1]],next_hop_priority=[80])

        acl_dscp_api.config_service_policy_table(data.dut1,interface_name=data.lag_vlan_intf,service_policy_name=data.policy_class_vlan,
                                                 policy_kind='bind',policy_type='forwarding')


    else:
        ######################################
        st.banner("Remove the classifier and policy map config")
        ######################################


        acl_dscp_api.config_service_policy_table(data.dut1,interface_name=data.lag_vlan_intf,service_policy_name=data.policy_class_vlan,
                                         policy_kind='unbind',policy_type='forwarding')

        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_vlan,
                                              class_name=data.class_permit_ip, policy_type='forwarding')

        acl_dscp_api.config_classifier_table(data.dut1,enable='del',class_name=data.class_permit_ip,match_type='fields')


def verify_pbr_config():

    #############################################
    st.banner('Verify all Policy configs ')
    #############################################

    match_vlan = [{'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ip,
                   'next_hop':data.d2tg_ip_list[-1]},
                  {'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ip,
                   'next_hop':data.d4tg_ip_list[-1]}]

    result = acl_dscp_api.verify(data.dut1, 'policy', verify_list=match_vlan)
    if not result:
        st.warn('Policy verification failed')
        return False
    else:
        st.log('Policy verification passed')

    return True

def verify_selected_next_hop(nh=[]):
    if nh == []: nh= data.d2tg_ip_list[-1]

    match_pbr = [{'policy_name':data.policy_class_vlan,'class_name':data.class_permit_ip,'next_hop':nh,'selected':'Selected','flow_state':'(Active)'}]

    result = retry_api(acl_dscp_api.verify,data.dut1,service_policy_interface=data.lag_vlan_intf,verify_list=match_pbr,retry_count=5,delay=1)
    if not result:
        st.warn("nexthop Selection check failed")
        return False
    return True

def config_default(config='yes'):
    if config == 'yes':
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.vlan_list_id[0], data.d1d2_ports[2], True]])
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[3],data.phy_ip_list[0], data.mask_v4]])
    else:
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.vlan_list_id[0], data.d1d2_ports[2], True]])
        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1d2_ports[3],data.phy_ip_list[0], data.mask_v4]])

def verify_default_config():

    count = 0
    if vlan_api.verify_vlan_config(dut=data.dut1,vlan_list=data.vlan_list_id[0], tagged=data.d1d2_ports[2]):
        st.log('{} is  part of vlan {}'.format(data.d1d2_ports[2],data.vlan_list_id[0]))
        count +=1
    else:
        st.log('{} is part of vlan {}'.format(data.d1d2_ports[2],data.vlan_list_id[0]))

    if retry_api(ip_api.verify_ip_route, data.dut1, ip_address=data.def_route[0],interface=data.d1d2_ports[3], family='ipv4',retry_count=2,delay=2):
        st.log('{} does have the ip address {}'.format(data.d1d2_ports[3],data.phy_ip_list[0]))
        count +=1
    else:
        st.log('{} does not have the ip address {}'.format(data.d1d2_ports[3],data.phy_ip_list[0]))

    if count == 0:
        return True
    else:
        return False



def verify_counter_cpu():
    queue = '10'
    tol = 0.05
    value=data.copp_cir_arp
    cli_out = asic_api.bcmcmd_show_c(data.dut1,interface='cpu')
    queue = 'PERQ_PKT(' + queue + ').cpu0'
    fil_out = utils_api.filter_and_select(cli_out, ["time"], {"key": queue})
    if not fil_out:
        st.error('queue: {} not found in output: {}'.format(queue, cli_out))
        return False
    else:
        fil_out = fil_out[0]

    fil_out['time'] = re.sub(r'|'.join((',', '/s')), "", fil_out['time'])
    ob_value = int(fil_out['time'])
    start_value = int(value) - int(tol)
    end_value = int(value) + int(tol)
    if ob_value >= start_value and ob_value <= end_value:
        st.log('obtained value {} for queue: {} is in the range b/w '
               '{} and {}'.format(ob_value,queue,start_value,end_value))
    else:
        st.error('obtained value {} for queue: {} is NOT in the range b/w '
                 '{} and {}'.format(ob_value, queue, start_value, end_value))



def debug_traffic(clear = 'yes'):
    global vars
    vars = st.get_testbed_vars()
    ############################################################################################
    st.banner(" \n######### Debugs for traffic failure ##########\n")
    ############################################################################################
    if clear == 'yes':
        st.log("Clearing all counters on Dut1 and Dut2\n")
        input1={"confirm" : "y"}
        parallel.exec_parallel(True, [data.dut1,data.dut2], intf_api.clear_interface_counters,[input1,input1])
        st.wait(2)

    utils.exec_all(True, [[ vlan_api.verify_vlan_config,data.dut1,data.lag_vlan_id],[vlan_api.verify_vlan_config,data.dut2,data.d1tg_vlan_id]])
    utils.exec_all(True, [[intf_api.show_interface_counters_all,data.dut1],[intf_api.show_interface_counters_all,data.dut2]])
    utils.exec_all(True, [[ip_api.show_ip_route,data.dut1],[ip_api.show_ip_route,data.dut2]])
    #utils.exec_all(True, [[arp.show_arp,data.dut1],[arp.show_arp,data.dut2]])
    utils.exec_all(True, [[asic_api.bcmcmd_l3_defip_show,data.dut1],[asic_api.bcmcmd_l3_defip_show,data.dut2]])
    utils.exec_all(True, [[asic_api.bcm_cmd_l3_intf_show,data.dut1],[asic_api.bcm_cmd_l3_intf_show,data.dut2]])
    ############################################################################################
    st.banner(" \n######### Debug END - Debugs for traffic failure ##########\n")
    ############################################################################################

