
import re

from spytest import st, tgapi, utils

from ptp_vars_new import data
import apis.system.ptp as ptp_obj
import utilities.utils as util_obj
import apis.routing.ip as ip_obj
import apis.system.port as port_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import apis.switching.vlan as vlan_obj
import apis.switching.pvst as stp_obj
import apis.routing.bgp as bgp_obj
import apis.routing.bfd as bfd_obj
import apis.routing.ip_bgp as ip_bgp
import apis.routing.arp as arp_obj
import apis.system.Calnex.paragon as clx_obj


def initialize_topology():
# code for ensuring min topology

    if data.skip_traffic:
        vars = st.ensure_min_topology('D1D2:1','D1D3:1','D1D4:0','D2D3:0','D2D4:1','D3D4:1')
        data.my_dut_list = st.get_dut_names()
        data.d1, data.d2, data.d3, data.d4 = data.my_dut_list[0], data.my_dut_list[1], data.my_dut_list[2], data.my_dut_list[3]
    else:
        vars = st.ensure_min_topology('D1D2:1','D1D3:1','D1D4:0','D2D3:0','D2D4:1','D3D4:1','D1T1:1', 'D4T1:1')
        data.my_dut_list = st.get_dut_names()
        data.d1, data.d2, data.d3, data.d4 = data.my_dut_list[0], data.my_dut_list[1], data.my_dut_list[2], data.my_dut_list[3]
        data.d1_tg_intf_1, data.tg_d1_intf_1 = vars.D1T1P1, vars.T1D1P1
        data.d4_tg_intf_1, data.tg_d4_intf_1 = vars.D4T1P1, vars.T1D4P1

        data.tg_d1_obj_1, data.tg_d1_ph_1 = tgapi.get_handle_byname("T1D1P1")
        data.tg_d4_obj_1, data.tg_d4_ph_1 = tgapi.get_handle_byname("T1D4P1")
        data.alias_mode = vars.config.ifname_type

        get_dut_version()

        data.d1_tg_intf_1_mac = str(basic_obj.get_ifconfig(data.d1, data.d1_tg_intf_1)[0]['mac'])
        data.d4_tg_intf_1_mac = str(basic_obj.get_ifconfig(data.d4, data.d4_tg_intf_1)[0]['mac'])

        if 'ixia' in vars['tgen_list'][0]:
            data.delay_factor = 2
        else:
           data.delay_factor = 1

    data.d1_d2_intf_1, data.d2_d1_intf_1 = vars.D1D2P1, vars.D2D1P1
    data.d1_d3_intf_1, data.d3_d1_intf_1 = vars.D1D3P1, vars.D3D1P1
    data.d2_d4_intf_1, data.d4_d2_intf_1 = vars.D2D4P1, vars.D4D2P1
    data.d3_d4_intf_1,  data.d4_d3_intf_1 = vars.D3D4P1, vars.D4D3P1

    data.clx_chassis_ip = util_obj.ensure_service_params(data.d1, "calnex", "chassis_ip")
    data.clx_controller_ip = util_obj.ensure_service_params(data.d1, "calnex", "controller_ip")
    st.log('Calnex: chassis_ip {}, controller_ip {}'.format(data.clx_chassis_ip, data.clx_controller_ip))

    calnex_d1 = st.get_device_param(data.d1, "calnex", None)
    if calnex_d1:
        data.clx_d1_intf_1, data.d1_clx_intf_1 = calnex_d1[0], calnex_d1[1]
        data.clx_d1_intf_1_portnum = re.search(r'port(\d+)', data.clx_d1_intf_1).group(1)
        if vars.config.ifname_type == 'alias':
            data.d1_clx_intf_1 = st.get_other_names(data.d1, [data.d1_clx_intf_1])[0]
            st.log('ALIAS NAME: {}'.format(data.d1_clx_intf_1))
        port_obj.set_status(data.d1, [data.d1_clx_intf_1],'startup')

    calnex_d4= st.get_device_param(data.d4, "calnex", None)
    if calnex_d4:
        data.clx_d4_intf_1, data.d4_clx_intf_1 = calnex_d4[0], calnex_d4[1]
        data.clx_d4_intf_1_portnum = re.search(r'port(\d+)', data.clx_d4_intf_1).group(1)
        if vars.config.ifname_type == 'alias':
            data.d4_clx_intf_1 = st.get_other_names(data.d4, [data.d4_clx_intf_1])[0]
            st.log('ALIAS NAME: {}'.format(data.d4_clx_intf_1))
        port_obj.set_status(data.d4, [data.d4_clx_intf_1],'startup')
    data.ptp_port_list_all = [
        [data.d1_d2_intf_1, data.d1_d3_intf_1, data.d1_clx_intf_1],
        [data.d2_d1_intf_1, data.d2_d4_intf_1],
        [data.d3_d1_intf_1, data.d3_d4_intf_1],
        [data.d4_d2_intf_1, data.d4_d3_intf_1, data.d4_clx_intf_1]
    ]

    print_topology()
    get_base_mac_address()



def retry_api(func, **kwargs):
    retry_count = kwargs.get("retry_count", 7)
    delay = kwargs.get("delay", 10)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(**kwargs):
            st.log('API_Call: {} Successful'.format(func))
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def print_topology():
    topology = r"""

                            |---{}-----{}---D2---{}-----{}---|
                            |                                                               |
Clx---{}-----{}---D1                                                              D4---{}-----{}---Calnex
                            |                                                               |
                            |---{}-----{}---D3---{}-----{}---|

    """.format(data.d1_d2_intf_1, data.d2_d1_intf_1, data.d2_d4_intf_1, data.d4_d2_intf_1, data.clx_d1_intf_1, data.d1_clx_intf_1, data.d4_clx_intf_1, data.clx_d4_intf_1, data.d1_d3_intf_1, data.d3_d1_intf_1, data.d3_d4_intf_1, data.d4_d3_intf_1)
    st.log(topology)


def config_traffic(traffic_type='l2'):
    if data.skip_traffic:
        return True

    data.tg_d1_obj_1.tg_traffic_control(action='reset', port_handle=[data.tg_d1_ph_1, data.tg_d4_ph_1])

    if traffic_type == 'l2':
        ptp_stream1 = data.tg_d1_obj_1.tg_traffic_config(mac_src=data.tg_d1_intf_1_mac, mac_dst=data.tg_d4_intf_1_mac, l2_encap='ethernet_ii', rate_pps=data.tg_traffic_rate, mode='create', port_handle=data.tg_d1_ph_1, transmit_mode='continuous', l3_protocol='ipv4')
        ptp_stream2 = data.tg_d4_obj_1.tg_traffic_config(mac_src=data.tg_d4_intf_1_mac, mac_dst=data.tg_d1_intf_1_mac, l2_encap='ethernet_ii', rate_pps=data.tg_traffic_rate, mode='create', port_handle=data.tg_d4_ph_1, transmit_mode='continuous', l3_protocol='ipv4')
        data.tg_d1_sid_list = [ptp_stream1['stream_id']]
        data.tg_d4_sid_list = [ptp_stream2['stream_id']]

    if traffic_type == 'l3':
        ptp_stream1 = data.tg_d1_obj_1.tg_traffic_config(mac_src=data.tg_d1_intf_1_mac, mac_dst=data.d1_tg_intf_1_mac, l2_encap='ethernet_ii', rate_pps=data.tg_traffic_rate, mode='create', port_handle=data.tg_d1_ph_1, transmit_mode='continuous', l3_protocol='ipv4', ip_src_addr=data.tg_d1_intf_1_ip, ip_dst_addr=data.tg_d4_intf_1_ip)
        ptp_stream2 = data.tg_d4_obj_1.tg_traffic_config(mac_src=data.tg_d4_intf_1_mac, mac_dst=data.d4_tg_intf_1_mac, l2_encap='ethernet_ii', rate_pps=data.tg_traffic_rate, mode='create', port_handle=data.tg_d4_ph_1, transmit_mode='continuous', l3_protocol='ipv4', ip_src_addr=data.tg_d4_intf_1_ip, ip_dst_addr=data.tg_d1_intf_1_ip)

        ptp_stream3 = data.tg_d1_obj_1.tg_traffic_config(mac_src=data.tg_d1_intf_1_mac, mac_dst=data.d1_tg_intf_1_mac, l2_encap='ethernet_ii', rate_pps=data.tg_traffic_rate, mode='create', port_handle=data.tg_d1_ph_1, transmit_mode='continuous', l3_protocol='ipv6', ipv6_src_addr=data.tg_d1_intf_1_ip6, ipv6_dst_addr=data.tg_d4_intf_1_ip6)
        ptp_stream4 = data.tg_d4_obj_1.tg_traffic_config(mac_src=data.tg_d4_intf_1_mac, mac_dst=data.d4_tg_intf_1_mac, l2_encap='ethernet_ii', rate_pps=data.tg_traffic_rate, mode='create', port_handle=data.tg_d4_ph_1, transmit_mode='continuous', l3_protocol='ipv6', ipv6_src_addr=data.tg_d4_intf_1_ip6, ipv6_dst_addr=data.tg_d1_intf_1_ip6)

        data.tg_d1_sid_list = [ptp_stream1['stream_id'], ptp_stream3['stream_id']]
        data.tg_d4_sid_list = [ptp_stream2['stream_id'], ptp_stream4['stream_id']]


def control_traffic(action='run',clear_stats='yes'):
    if data.skip_traffic:
        return True
    if clear_stats == 'yes':
        data.tg_d1_obj_1.tg_traffic_control(action='clear_stats',port_handle=[data.tg_d1_ph_1, data.tg_d4_ph_1])
    data.tg_d1_obj_1.tg_traffic_control(action=action, handle=data.tg_d1_sid_list)
    data.tg_d4_obj_1.tg_traffic_control(action=action, handle=data.tg_d4_sid_list)

def verify_tgen_traffic():
    if data.skip_traffic:
        return True
    traffic_data = {
        '1': {
            'tx_ports': [data.tg_d1_intf_1],
            'tx_obj': [data.tg_d1_obj_1],
            'exp_ratio': [1],
            'rx_ports': [data.tg_d4_intf_1],
            'rx_obj': [data.tg_d4_obj_1]
        },
        '2': {
            'tx_ports': [data.tg_d4_intf_1],
            'tx_obj': [data.tg_d4_obj_1],
            'exp_ratio': [1],
            'rx_ports': [data.tg_d1_intf_1],
            'rx_obj': [data.tg_d1_obj_1]
        }
    }

    return True if tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='aggregate', comp_type='packet_rate', delay_factor=data.delay_factor) else False



def connect_to_calnex():
    st.log('Connect to Calnex')
    if clx_obj.connect(data.clx_chassis_ip, data.clx_controller_ip):
        st.log('Error while connecting to Calnex')
        return False
    return True

def load_config_on_calnex(filename):

    #Enable Master/Slave Emulation
    clx_obj.paragonset("MasterSlave Master #0 Enabled","FALSE")
    st.log('Loading config file {} on Calnex'.format(filename))
    if clx_obj.paragonset('Rst', 'TRUE'):
        st.log('Error in reset')

    if clx_obj.recall(data.clx_config_file_path + filename):
        st.log('Error in config file recall')
        return False

    #Enable Master/Slave Emulation
    if clx_obj.paragonset("MasterSlave Master #0 Enabled", "TRUE"):
        st.log('Error while enabling MasterSlave')
        return False

    return True

def configure_alias_mode():
    def f1():
        intf_obj.config_ifname_type(data.d1)
    def f2():
        intf_obj.config_ifname_type(data.d2)
    def f3():
        intf_obj.config_ifname_type(data.d3)
    def f4():
        intf_obj.config_ifname_type(data.d4)

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def configure_breakout_ports():
    def f1():
        br_port_list = st.get_breakout(data.d1)
        if br_port_list:
            for port_list in br_port_list:
                port_obj.breakout(data.d1, data=port_list, brk_verify=True)
    def f2():
        br_port_list = st.get_breakout(data.d2)
        if br_port_list:
            for port_list in br_port_list:
                port_obj.breakout(data.d2, data=port_list, brk_verify=True)
    def f3():
        br_port_list = st.get_breakout(data.d3)
        if br_port_list:
            for port_list in br_port_list:
                port_obj.breakout(data.d3, data=port_list, brk_verify=True)
    def f4():
        br_port_list = st.get_breakout(data.d4)
        if br_port_list:
            for port_list in br_port_list:
                port_obj.breakout(data.d4, data=port_list, brk_verify=True)

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def get_dut_version():
    def f1():
        dut_version = basic_obj.show_version(data.d1)
        return dut_version['version']
    def f2():
        dut_version = basic_obj.show_version(data.d2)
        return dut_version['version']
    def f3():
        dut_version = basic_obj.show_version(data.d3)
        return dut_version['version']
    def f4():
        dut_version = basic_obj.show_version(data.d4)
        return dut_version['version']

    [res, _] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    data.dut_version_list = list()
    for i in range(len(data.my_dut_list)):
        data.dut_version_list.append(res[i])
    st.log('Version_List: {}'.format(data.dut_version_list))


def get_base_mac_address():
    def f1():
        base_mac = stp_obj.get_duts_mac_address([data.d1])
        return base_mac[data.d1]
    def f2():
        base_mac = stp_obj.get_duts_mac_address([data.d2])
        return base_mac[data.d2]
    def f3():
        base_mac = stp_obj.get_duts_mac_address([data.d3])
        return base_mac[data.d3]
    def f4():
        base_mac = stp_obj.get_duts_mac_address([data.d4])
        return base_mac[data.d4]

    [res, _] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    data.base_mac_list = list()
    data.clock_id_list = list()
    for i in range(len(data.my_dut_list)):
        data.base_mac_list.append(res[i])
        clock_id = re.sub(r'(\w{6})(\w{6})',r'\1.fffe.\2',res[i])
        data.clock_id_list.append(str(clock_id).lower())

    st.log('Clock_ID_List: {}'.format(data.clock_id_list))

def configure_profile(profile='l3'):
    def f1():
        basic_obj.set_config_profiles(data.d1, profile=profile)
    def f2():
        basic_obj.set_config_profiles(data.d2, profile=profile)
    def f3():
        basic_obj.set_config_profiles(data.d3, profile=profile)
    def f4():
        basic_obj.set_config_profiles(data.d4, profile=profile)

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def shutdown_all_but_needed_ports():
    def f1():
        intf_list = port_obj.get_interfaces_all(data.d1)
        port_obj.set_status(data.d1,intf_list,'shutdown')
    def f2():
        intf_list = port_obj.get_interfaces_all(data.d2)
        port_obj.set_status(data.d2,intf_list,'shutdown')
    def f3():
        intf_list = port_obj.get_interfaces_all(data.d3)
        port_obj.set_status(data.d3,intf_list,'shutdown')
    def f4():
        intf_list = port_obj.get_interfaces_all(data.d4)
        port_obj.set_status(data.d4,intf_list,'shutdown')

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def remove_ptp_ports_from_default_vlan():
    '''
    def f1():
        vlan_obj.add_vlan_member(data.d1, vlan=1, port_list=[data.d1_clx_intf_1, data.d1_d2_intf_1, data.d1_d3_intf_1, data.d1_tg_intf_1], no_form=True)
    def f2():
        vlan_obj.add_vlan_member(data.d2, vlan=1, port_list=[data.d2_d1_intf_1, data.d2_d4_intf_1], no_form=True)
    '''
    def f3():
        vlan_obj.add_vlan_member(data.d3, vlan=1, port_list=[data.d3_d1_intf_1, data.d3_d4_intf_1], no_form=True)
    def f4():
        vlan_obj.add_vlan_member(data.d4, vlan=1, port_list=[data.d4_clx_intf_1, data.d4_d2_intf_1, data.d4_d3_intf_1, data.d4_tg_intf_1], no_form=True)

    utils.exec_all(True, [[f3], [f4]])

def bring_up_ptp_ports():
    def f1():
        port_obj.set_status(data.d1, [data.d1_clx_intf_1, data.d1_d2_intf_1, data.d1_d3_intf_1, data.d1_tg_intf_1],'startup')
    def f2():
        port_obj.set_status(data.d2, [data.d2_d1_intf_1, data.d2_d4_intf_1],'startup')
    def f3():
        port_obj.set_status(data.d3, [data.d3_d1_intf_1, data.d3_d4_intf_1],'startup')
    def f4():
        port_obj.set_status(data.d4, [data.d4_clx_intf_1, data.d4_d2_intf_1, data.d4_d3_intf_1, data.d4_tg_intf_1],'startup')

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def show_stp_all():
    def f1():
        stp_obj.show_stp(data.d1,sub_cmd='vlan 1 interface Ethernet0')
        stp_obj.show_stp(data.d1,sub_cmd='vlan 1 interface Ethernet24')
    def f2():
        stp_obj.show_stp(data.d2,sub_cmd='vlan 1 interface Ethernet0')
        stp_obj.show_stp(data.d2,sub_cmd='vlan 1 interface Ethernet31')
    def f3():
        stp_obj.show_stp(data.d3,sub_cmd='vlan 1 interface Ethernet0')
        stp_obj.show_stp(data.d3,sub_cmd='vlan 1 interface Ethernet18')
    def f4():
        stp_obj.show_stp(data.d4,sub_cmd='vlan 1 interface Ethernet0')
        stp_obj.show_stp(data.d4,sub_cmd='vlan 1 interface Ethernet15')

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])



def configure_stp_all(stp_type, stp_mode):
    def f1():
#        stp_obj.config_spanning_tree(data.d1, feature=stp_type, mode=stp_mode)
        stp_obj.config_stp_parameters(data.d1,priority=0)
    def f2():
#        stp_obj.config_spanning_tree(data.d2, feature=stp_type, mode=stp_mode)
        stp_obj.config_stp_parameters(data.d2,priority=4096)
    def f3():
#        stp_obj.config_spanning_tree(data.d3, feature=stp_type, mode=stp_mode)
        stp_obj.config_stp_parameters(data.d3,priority=8192)
    def f4():
#        stp_obj.config_spanning_tree(data.d4, feature=stp_type, mode=stp_mode)
        stp_obj.config_stp_parameters(data.d4,priority=12288)

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def configure_ptp_default(nw_transport='L2 multicast'):
    def f1():
        ptp_obj.config_ptp(data.d1, domain_profile='default', network_transport=nw_transport, priority1=128, priority2=128, two_step='enable')
        ptp_obj.config_ptp(data.d1, mode='disable')

    def f2():
        ptp_obj.config_ptp(data.d2, domain_profile='default', network_transport=nw_transport, priority1=128, priority2=128, two_step='enable')
        ptp_obj.config_ptp(data.d2, mode='disable')

    def f3():
        ptp_obj.config_ptp(data.d3, domain_profile='default', network_transport=nw_transport, priority1=128, priority2=128, two_step='enable')
        ptp_obj.config_ptp(data.d3, mode='disable')

    def f4():
        ptp_obj.config_ptp(data.d4, domain_profile='default', network_transport=nw_transport, priority1=128, priority2=128, two_step='enable')
        ptp_obj.config_ptp(data.d4, mode='disable')

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def configure_ptp_on_duts(api_name, param_dict_list):
    api_to_call = getattr(ptp_obj, api_name)
    def f1():
        param_dict = param_dict_list[0]
        return True if not param_dict else api_to_call(data.d1, **param_dict)
        #api_to_call(data.d1, **param_dict)

    def f2():
        param_dict = param_dict_list[1]
        return True if not param_dict else api_to_call(data.d2, **param_dict)
        #api_to_call(data.d2, **param_dict)

    def f3():
        param_dict = param_dict_list[2]
        return True if not param_dict else api_to_call(data.d3, **param_dict)

    def f4():
        param_dict = param_dict_list[3]
        return True if not param_dict else api_to_call(data.d4, **param_dict)
        #api_to_call(data.d4, **param_dict)

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])



def verify_ptp_on_duts(api_name, param_dict_list):
    api_to_call = getattr(ptp_obj, api_name)
    def f1():
        param_dict = param_dict_list[0]
        return True if not param_dict else api_to_call(data.d1, **param_dict)
    def f2():
        param_dict = param_dict_list[1]
        return True if not param_dict else api_to_call(data.d2, **param_dict)
    def f3():
        param_dict = param_dict_list[2]
        return True if not param_dict else api_to_call(data.d3, **param_dict)
    def f4():
        param_dict = param_dict_list[3]
        return True if not param_dict else api_to_call(data.d4, **param_dict)

    [res, _] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    return False if  False in res else True



def verify_bgp_config():
    def f1():
        return ip_bgp.check_bgp_session(data.d1, nbr_list=[data.d2_d1_intf_1_ip, data.d3_d1_intf_1_ip, data.d2_d1_intf_1_ip6, data.d3_d1_intf_1_ip6], state_list=['Established']*4)
    def f2():
        return ip_bgp.check_bgp_session(data.d2, nbr_list=[data.d1_d2_intf_1_ip, data.d4_d2_intf_1_ip, data.d1_d2_intf_1_ip6, data.d4_d2_intf_1_ip6], state_list=['Established']*4)
    def f3():
        return ip_bgp.check_bgp_session(data.d3, nbr_list=[data.d1_d3_intf_1_ip, data.d4_d3_intf_1_ip, data.d1_d3_intf_1_ip6, data.d4_d3_intf_1_ip6], state_list=['Established']*4)
    def f4():
        return ip_bgp.check_bgp_session(data.d4, nbr_list=[data.d2_d4_intf_1_ip, data.d3_d4_intf_1_ip, data.d2_d4_intf_1_ip6, data.d3_d4_intf_1_ip6], state_list=['Established']*4)

    [res, _] = utils.exec_all(True, [[f1], [f2], [f3], [f4]])
    return False if  False in res else True


def config_dynamic_routing(config='yes'):

    if config == 'yes':
        def f1():
             bgp_obj.enable_docker_routing_config_mode(data.d1)
             bgp_obj.config_bgp(data.d1, local_as=data.as_list[0], router_id=data.router_id[0], remote_as=data.as_list[2], neighbor=data.d3_d1_intf_1_ip, config_type_list=['router_id','neighbor'])
             bgp_obj.config_bgp(data.d1, local_as=data.as_list[0], remote_as=data.as_list[1], neighbor=data.d2_d1_intf_1_ip, redistribute='connected', weight=65535, config_type_list=['neighbor', 'redist', 'weight'])
             bgp_obj.config_bgp(data.d1, local_as=data.as_list[0], remote_as=data.as_list[2], neighbor=data.d3_d1_intf_1_ip6, addr_family='ipv6', activate='yes', config_type_list=['neighbor', 'activate'])
             bgp_obj.config_bgp(data.d1, local_as=data.as_list[0], remote_as=data.as_list[1], neighbor=data.d2_d1_intf_1_ip6, addr_family='ipv6', activate='yes', redistribute='connected', weight=65535, config_type_list=['neighbor', 'activate', 'redist', 'weight'])

        def f2():
             bgp_obj.enable_docker_routing_config_mode(data.d2)
             bgp_obj.config_bgp(data.d2, local_as=data.as_list[1], router_id=data.router_id[1], remote_as=data.as_list[0], neighbor=data.d1_d2_intf_1_ip, config_type_list=['router_id','neighbor'])
             bgp_obj.config_bgp(data.d2, local_as=data.as_list[1], remote_as=data.as_list[3], neighbor=data.d4_d2_intf_1_ip, redistribute='connected', config_type_list=['neighbor', 'redist'])
             bgp_obj.config_bgp(data.d2, local_as=data.as_list[1], remote_as=data.as_list[0], neighbor=data.d1_d2_intf_1_ip6, addr_family='ipv6', activate='yes', config_type_list=['neighbor', 'activate'])
             bgp_obj.config_bgp(data.d2, local_as=data.as_list[1], remote_as=data.as_list[3], neighbor=data.d4_d2_intf_1_ip6, addr_family='ipv6', activate='yes', redistribute='connected', config_type_list=['neighbor', 'activate', 'redist'])

        def f3():
             bgp_obj.enable_docker_routing_config_mode(data.d3)
             bgp_obj.config_bgp(data.d3, local_as=data.as_list[2], router_id=data.router_id[2], remote_as=data.as_list[0], neighbor=data.d1_d3_intf_1_ip, config_type_list=['router_id','neighbor'])
             bgp_obj.config_bgp(data.d3, local_as=data.as_list[2], remote_as=data.as_list[3], neighbor=data.d4_d3_intf_1_ip, redistribute='connected', config_type_list=['neighbor', 'redist'])
             bgp_obj.config_bgp(data.d3, local_as=data.as_list[2], remote_as=data.as_list[0], neighbor=data.d1_d3_intf_1_ip6, addr_family='ipv6', activate='yes', config_type_list=['neighbor', 'activate'])
             bgp_obj.config_bgp(data.d3, local_as=data.as_list[2], remote_as=data.as_list[3], neighbor=data.d4_d3_intf_1_ip6, addr_family='ipv6', activate='yes', redistribute='connected', config_type_list=['neighbor', 'activate', 'redist'])

        def f4():
             bgp_obj.enable_docker_routing_config_mode(data.d4)
             bgp_obj.config_bgp(data.d4, local_as=data.as_list[3], router_id=data.router_id[3], remote_as=data.as_list[2], neighbor=data.d3_d4_intf_1_ip, config_type_list=['router_id','neighbor'])
             bgp_obj.config_bgp(data.d4, local_as=data.as_list[3], remote_as=data.as_list[1], neighbor=data.d2_d4_intf_1_ip, redistribute='connected',  weight=65535, config_type_list=['neighbor', 'redist', 'weight'])
             bgp_obj.config_bgp(data.d4, local_as=data.as_list[3], remote_as=data.as_list[2], neighbor=data.d3_d4_intf_1_ip6, addr_family='ipv6', activate='yes', config_type_list=['neighbor', 'activate'])
             bgp_obj.config_bgp(data.d4, local_as=data.as_list[3], remote_as=data.as_list[1], neighbor=data.d2_d4_intf_1_ip6, addr_family='ipv6', activate='yes', redistribute='connected',  weight=65535, config_type_list=['neighbor', 'activate', 'redist', 'weight'])

        utils.exec_all(True, [[f1], [f2], [f3], [f4]])

    if config == 'no':
        def f11():
            bgp_obj.config_bgp(data.d1, local_as=data.as_list[0], config='no', removeBGP='yes', config_type_list=['removeBGP'])
        def f12():
            bgp_obj.config_bgp(data.d2, local_as=data.as_list[1], config='no', removeBGP='yes', config_type_list=['removeBGP'])
        def f13():
            bgp_obj.config_bgp(data.d3, local_as=data.as_list[2], config='no', removeBGP='yes', config_type_list=['removeBGP'])
        def f14():
            bgp_obj.config_bgp(data.d4, local_as=data.as_list[3], config='no', removeBGP='yes', config_type_list=['removeBGP'])

        utils.exec_all(True, [[f11], [f12], [f13], [f14]])


def config_bfd(config='yes'):
    def f1():
        bfd_obj.configure_bfd(data.d1, local_asn=data.as_list[0], neighbor_ip=[data.d2_d1_intf_1_ip, data.d3_d1_intf_1_ip, data.d2_d1_intf_1_ip6, data.d3_d1_intf_1_ip6])
    def f2():
        bfd_obj.configure_bfd(data.d2, local_asn=data.as_list[1], neighbor_ip=[data.d1_d2_intf_1_ip, data.d4_d2_intf_1_ip, data.d1_d2_intf_1_ip6, data.d4_d2_intf_1_ip6])
    def f3():
        bfd_obj.configure_bfd(data.d3, local_asn=data.as_list[2], neighbor_ip=[data.d1_d3_intf_1_ip, data.d4_d3_intf_1_ip, data.d1_d3_intf_1_ip6, data.d4_d3_intf_1_ip6])
    def f4():
        bfd_obj.configure_bfd(data.d4, local_asn=data.as_list[3], neighbor_ip=[data.d3_d4_intf_1_ip, data.d2_d4_intf_1_ip, data.d2_d4_intf_1_ip6, data.d3_d4_intf_1_ip6])

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def ping_bgp_neighbors():
    def f1():
        ip_obj.ping(data.d1, data.d2_d1_intf_1_ip, timeout=7)
        ip_obj.ping(data.d1, data.d3_d1_intf_1_ip, timeout=7)
        ip_obj.ping(data.d1, data.d2_d1_intf_1_ip6, timeout=7, family='ipv6')
        ip_obj.ping(data.d1, data.d3_d1_intf_1_ip6, timeout=7, family='ipv6')
    def f4():
        ip_obj.ping(data.d4, data.d2_d4_intf_1_ip, timeout=7)
        ip_obj.ping(data.d4, data.d3_d4_intf_1_ip, timeout=7)
        ip_obj.ping(data.d4, data.d2_d4_intf_1_ip6, timeout=7, family='ipv6')
        ip_obj.ping(data.d4, data.d3_d4_intf_1_ip6, timeout=7, family='ipv6')

    utils.exec_all(True, [[f1], [f4]])


def config_static_routing(config='yes'):
    api_to_call = getattr(ip_obj, 'create_static_route') if config == 'yes' else getattr(ip_obj, 'delete_static_route')
    def f1():
        api_to_call(data.d1, data.d2_d1_intf_1_ip, '{}/{}'.format(data.d4_d2_intf_1_ip_nw,data.def_ipv4_mask))
        api_to_call(data.d1, data.d2_d1_intf_1_ip, '{}/{}'.format(data.d4_clx_intf_1_ip_nw,data.def_ipv4_mask))
        api_to_call(data.d1, data.d2_d1_intf_1_ip6, '{}/{}'.format(data.d4_d2_intf_1_ip6_nw,data.def_ipv6_mask))
        api_to_call(data.d1, data.d2_d1_intf_1_ip6, '{}/{}'.format(data.d4_clx_intf_1_ip6_nw,data.def_ipv6_mask))

    def f2():
        api_to_call(data.d2, data.d1_d2_intf_1_ip, '{}/{}'.format(data.d1_clx_intf_1_ip_nw,data.def_ipv4_mask))
        api_to_call(data.d2, data.d4_d2_intf_1_ip, '{}/{}'.format(data.d4_clx_intf_1_ip_nw,data.def_ipv4_mask))
        api_to_call(data.d2, data.d1_d2_intf_1_ip6, '{}/{}'.format(data.d1_clx_intf_1_ip6_nw,data.def_ipv6_mask))
        api_to_call(data.d2, data.d4_d2_intf_1_ip6, '{}/{}'.format(data.d4_clx_intf_1_ip6_nw,data.def_ipv6_mask))

    def f4():
        api_to_call(data.d4, data.d2_d4_intf_1_ip, '{}/{}'.format(data.d1_d2_intf_1_ip_nw,data.def_ipv4_mask))
        api_to_call(data.d4, data.d2_d4_intf_1_ip, '{}/{}'.format(data.d1_clx_intf_1_ip_nw,data.def_ipv4_mask))
        api_to_call(data.d4, data.d2_d4_intf_1_ip6, '{}/{}'.format(data.d1_d2_intf_1_ip6_nw,data.def_ipv6_mask))
        api_to_call(data.d4, data.d2_d4_intf_1_ip6, '{}/{}'.format(data.d1_clx_intf_1_ip6_nw,data.def_ipv6_mask))

    utils.exec_all(True, [[f1], [f2], [f4]])


def config_l3_topo(config='yes'):
    user_config = config
    config = 'add' if user_config == 'yes' else 'remove'
    config_1 = 'add' if user_config == 'yes' else 'del'
    def f1():
        if not data.skip_traffic and config_1 == 'del':
            arp_obj.delete_static_arp(data.d1, data.tg_d1_intf_1_ip, data.tg_d1_intf_1_mac)
            arp_obj.config_static_ndp(data.d1, data.tg_d1_intf_1_ip6, data.tg_d1_intf_1_mac, data.d1_tg_intf_1, operation=config_1)

        ip_obj.config_ip_addr_interface(data.d1, data.d1_clx_intf_1, data.d1_clx_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d1, data.d1_clx_intf_1, data.d1_clx_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d2_intf_1, data.d1_d2_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d3_intf_1, data.d1_d3_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d2_intf_1, data.d1_d2_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d3_intf_1, data.d1_d3_intf_1_ip6, data.def_ipv6_mask, 'ipv46', config=config)

        if not data.skip_traffic:
            ip_obj.config_ip_addr_interface(data.d1, data.d1_tg_intf_1, data.d1_tg_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
            ip_obj.config_ip_addr_interface(data.d1, data.d1_tg_intf_1, data.d1_tg_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        if config_1 == 'add':
            arp_obj.add_static_arp(data.d1, data.tg_d1_intf_1_ip, data.tg_d1_intf_1_mac, data.d1_tg_intf_1)
            arp_obj.config_static_ndp(data.d1, data.tg_d1_intf_1_ip6, data.tg_d1_intf_1_mac, data.d1_tg_intf_1, operation=config_1)


    def f2():
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d1_intf_1, data.d2_d1_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d4_intf_1, data.d2_d4_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d1_intf_1, data.d2_d1_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d4_intf_1, data.d2_d4_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)

    def f3():
        ip_obj.config_ip_addr_interface(data.d3, data.d3_d1_intf_1, data.d3_d1_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d3, data.d3_d4_intf_1, data.d3_d4_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d3, data.d3_d1_intf_1, data.d3_d1_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        ip_obj.config_ip_addr_interface(data.d3, data.d3_d4_intf_1, data.d3_d4_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)

    def f4():
        if not data.skip_traffic and config_1 == 'del':
            arp_obj.delete_static_arp(data.d4, data.tg_d4_intf_1_ip, data.tg_d4_intf_1_mac)
            arp_obj.config_static_ndp(data.d4, data.tg_d4_intf_1_ip6, data.tg_d4_intf_1_mac, data.d4_tg_intf_1, operation=config_1)

        ip_obj.config_ip_addr_interface(data.d4, data.d4_d2_intf_1, data.d4_d2_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d4, data.d4_d3_intf_1, data.d4_d3_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d4, data.d4_d2_intf_1, data.d4_d2_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        ip_obj.config_ip_addr_interface(data.d4, data.d4_d3_intf_1, data.d4_d3_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        ip_obj.config_ip_addr_interface(data.d4, data.d4_clx_intf_1, data.d4_clx_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
        ip_obj.config_ip_addr_interface(data.d4, data.d4_clx_intf_1, data.d4_clx_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)

        if not data.skip_traffic:
            ip_obj.config_ip_addr_interface(data.d4, data.d4_tg_intf_1, data.d4_tg_intf_1_ip, data.def_ipv4_mask, 'ipv4', config=config)
            ip_obj.config_ip_addr_interface(data.d4, data.d4_tg_intf_1, data.d4_tg_intf_1_ip6, data.def_ipv6_mask, 'ipv6', config=config)
        if config_1 == 'add':
            arp_obj.add_static_arp(data.d4, data.tg_d4_intf_1_ip, data.tg_d4_intf_1_mac, data.d4_tg_intf_1)
            arp_obj.config_static_ndp(data.d4, data.tg_d4_intf_1_ip6, data.tg_d4_intf_1_mac, data.d4_tg_intf_1, operation=config_1)

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])


def verify_ping():
        ping_res1 = ip_obj.ping(data.d1, data.d4_d2_intf_1_ip, timeout=7)
        ping_res2 = ip_obj.ping(data.d1, data.d4_clx_intf_1_ip, timeout=7)
        ping_res3 = ip_obj.ping(data.d1, data.d4_d2_intf_1_ip6, timeout=7, family='ipv6')
        ping_res4 = ip_obj.ping(data.d1, data.d4_clx_intf_1_ip6, timeout=7, family='ipv6')
        if ping_res1 and ping_res2 and ping_res3 and ping_res4:
            return True
        else:
            return False


def verify_ptp_test_result(ts_name, tc_id, verify_traffic=0):
    result = 0
    if data.skip_traffic:
        verify_traffic = 0
    if verify_traffic == 1 and not retry_api(verify_tgen_traffic, delay=0):
        st.log('{} Scenario: {} TCID: {}  Summary: {} - Traffic Failed'.format(tc_id, ts_name, data[ts_name]['testcase_id'][tc_id], data[ts_name]['testcase_summary'][tc_id]))
        result += 1

    st.log('Verify PTP, PTP Clock and PTP parents on all devices - Scenario: {} TCID: {}'.format(ts_name, tc_id))
    if not retry_api(verify_ptp_on_duts, api_name='verify_ptp', param_dict_list=data[ts_name]['verify_ptp']):
        result += 1
    if not retry_api(verify_ptp_on_duts, api_name='verify_ptp_clock', param_dict_list=data[ts_name]['verify_ptp_clock']):
        result += 1
    if not retry_api(verify_ptp_on_duts, api_name='verify_ptp_parent', param_dict_list=data[ts_name]['verify_ptp_parent']):
        result += 1

    if result == 0:
        st.log('{} Scenario: {} TCID: {}  Summary: {} - Passed'.format(tc_id, ts_name, data[ts_name]['testcase_id'][tc_id], data[ts_name]['testcase_summary'][tc_id]))
        st.report_tc_pass('{}'.format(data[ts_name]['testcase_id'][tc_id]), 'test_case_passed')
    else:
        st.log('{} Scenario: {} TCID: {}  Summary: {} - Failed'.format(tc_id, ts_name, data[ts_name]['testcase_id'][tc_id], data[ts_name]['testcase_summary'][tc_id]))
        st.report_tc_fail('{}'.format(data[ts_name]['testcase_id'][tc_id]), 'test_case_failed')

    return result


def print_debug():
    def f1():
        port_obj.get_status(data.d1)
        ip_obj.get_interface_ip_address(data.d1)
        ip_obj.get_interface_ip_address(data.d1,family='ipv6')
        ip_obj.show_ip_route(data.d1)
        ip_obj.show_ip_route(data.d1,family='ipv6')
    def f2():
        port_obj.get_status(data.d2)
        ip_obj.get_interface_ip_address(data.d2)
        ip_obj.get_interface_ip_address(data.d2,family='ipv6')
        ip_obj.show_ip_route(data.d2)
        ip_obj.show_ip_route(data.d2,family='ipv6')
    def f3():
        port_obj.get_status(data.d3)
        ip_obj.get_interface_ip_address(data.d3)
        ip_obj.get_interface_ip_address(data.d3,family='ipv6')
        ip_obj.show_ip_route(data.d3)
        ip_obj.show_ip_route(data.d3,family='ipv6')
    def f4():
        port_obj.get_status(data.d4)
        ip_obj.get_interface_ip_address(data.d4)
        ip_obj.get_interface_ip_address(data.d4,family='ipv6')
        ip_obj.show_ip_route(data.d4)
        ip_obj.show_ip_route(data.d4,family='ipv6')

    utils.exec_all(True, [[f1], [f2], [f3], [f4]])
