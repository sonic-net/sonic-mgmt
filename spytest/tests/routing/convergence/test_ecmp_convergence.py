##############################################################################
#Script Title : Underlay ECMP convergence
#Author       : Sooriya
#Mail-id      : Sooriya.Gajendrababu@broadcom.com
###############################################################################

import pytest
from spytest import st, tgapi
import apis.routing.bgp as bgp_api
from utilities.utils import retry_api
import apis.system.interface as Intf
import apis.routing.ip as ip_api
import apis.routing.ospf as ospf
from spytest.dicts import SpyTestDict
from apis.system import basic
from tabulate import tabulate
import apis.system.port as port_api
import apis.routing.ip_bgp as ip_bgp
import apis.system.reboot as reboot_api

data = SpyTestDict()
data.iteration_count = 3
data.threshold = 1.0
data.ipv4_routes = 128000
data.ipv4_routes_per_port = data.ipv4_routes/2
data.d1d2_ip_list = ['12.12.1.1','12.12.2.1','12.12.3.1','12.12.4.1']
data.d2d1_ip_list = ['12.12.1.2','12.12.2.2','12.12.3.2','12.12.4.2']
data.d1tg_ip_list = ['100.1.1.1','100.1.1.2']
data.d2tg_ip_list = ['110.1.1.1','110.1.1.2']
data.route_prefix_start = ['120.0.0.0','160.0.0.0']
data.mask_v4 = '24'
data.dut1_as = '100'
data.dut2_as = '200'
data.tgd1_as = '300'
data.tgd2_as = '400'
data.traffic_rate = 50000

def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2","D2T1:2","D1CHIP=TD3","D2CHIP=TD3")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]

    for dut in data.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    data.d1d2_ports = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    data.d2d1_ports = [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4]
    data.d1tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.d2tg_ports = [vars.D2T1P1,vars.D2T1P2]
    handles = tgapi.get_handles(vars, [vars.T1D1P1,vars.T1D1P2, vars.T1D2P1, vars.T1D2P2])
    data.tg1 = data.tg2 = handles["tg1"]
    data.tgd1_ports = [vars.T1D1P1,vars.T1D1P2]
    data.tgd2_ports = [vars.T1D2P1, vars.T1D2P2]
    data.tgd1_handles = [handles["tg_ph_1"], handles["tg_ph_2"]]
    data.tgd2_handles = [handles["tg_ph_3"], handles["tg_ph_4"]]
    data.tg_handles = data.tgd1_handles + data.tgd2_handles
    data.src_mac = {}
    data.src_mac[data.tgd1_handles[0]] = '00:00:00:11:11:33'
    data.src_mac[data.tgd1_handles[1]] = '00:00:00:11:22:33'
    data.src_mac[data.tgd2_handles[0]] = '00:00:00:22:11:33'
    data.src_mac[data.tgd2_handles[1]] = '00:00:00:22:22:33'

    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type='ixia'
        data.delay_factor = 1
    else:
        data.tgen_type = 'stc'
        data.delay_factor = 0.2


@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped", "Not supported for ui_type - click")
    st.banner("Configure max route-scale profile and reboot duts beofre Test")
    st.exec_all([[ip_api.config_system_max_routes, data.dut1], [ip_api.config_system_max_routes, data.dut2]])
    st.exec_all([[reboot_api.config_save, data.dut1], [reboot_api.config_save, data.dut2]])
    st.exec_all([[st.reboot, data.dut1], [st.reboot, data.dut2]])
    base_ecmp_config()
    if not verify_bgp():
        st.report_fail('test_execution_skipped', 'Error in module config')
    if not verify_installed_routes():
        st.report_fail('test_execution_skipped', 'Error in module config')
    yield
    base_ecmp_deconfig()


def test_convergence_ecmp_underlay(prologue_epilogue):
    func_result=True
    table = {}
    ecmp_intf_list = data.d2d1_ports
    port_flap_list = data.d2d1_ports
    port_flap_list_1 = data.d1d2_ports
    header1 = ['link_{}_shut'.format(i+1) for i in range(len(port_flap_list[:-1]))]
    header2 = ['link_{}_noshut'.format(i + 1) for i in range(len(port_flap_list[1:]))][::-1]
    data['table_header'] = ['Underlay ECMP']+header1+header2

    ################################################
    st.banner("Verify Traffic is getting hashed along all ECMP paths between D1 & D2")
    ################################################

    start_traffic(stream_han_list=data['underlay_ecmp'],tgen_obj=data.tg1)
    st.wait(10,'Wait for 10 sec before checking ECMP hashing')
    if not retry_api(verify_ecmp_hashing,data.dut2,ecmp_intf_list):
        err = 'Traffic hashing did not happen across ecmp paths '
        st.report_fail('test_case_failure_message',err)

    start_traffic(action='stop', stream_han_list=data['underlay_ecmp'],tgen_obj=data.tg1)
    for dut,port_list in zip([data.dut2,data.dut1],[port_flap_list,port_flap_list_1]):
        st.banner(">>> ECMP test with port flap on DUT {} <<<<".format(dut))
        data['table_data'] = []
        for iter in range(int(data.iteration_count)):
            st.banner("\n\n >>>>> Iteration : {} <<<<<\n\n".format(iter+1))
            result = convergence_ecmp_underlay(dut,port_list,streams=data['underlay_ecmp'],iteration=(iter+1))
            data['table_data'].append(data['table_data_{}'.format(iter+1)])
            if not result: func_result=False

        table[dut] = tabulate(data['table_data'], headers=data['table_header'], tablefmt="grid")

    for dut in [data.dut2,data.dut1]:
        st.log("\n\n>>>> ECMP Convergence Table with port flap done on {} <<<<<\n\n".format(dut))
        st.log("\n\n" + table[dut])

    if not func_result:
        st.report_fail('test_case_failure_message','Underlay BGP ECMP convergence test failed')
    st.report_pass('test_case_passed')



def convergence_ecmp_underlay(dut,port_flap_list,streams,iteration):
    traffic_rate=data.traffic_rate
    streams = [streams] if type(streams) is not list else list(streams)
    direction= '1'
    result = True;
    tech_support = True

    data['table_data_{}'.format(iteration)] = ['Iteration-{}'.format(iteration)]
    ####################################
    st.log("\n\n>>>>>>> Start Traffic <<<<<<<\n\n")
    ####################################
    clear_stats(data.tgd1_handles + data.tgd2_handles,tgen_obj=data.tg1)
    st.exec_all([[Intf.clear_interface_counters, data.dut1],
                 [Intf.clear_interface_counters, data.dut2]])

    tx_tgen = data.tgd1_handles[0];
    tx_tgen_port = data.tgd1_ports[0]
    rx_tgen_port = data.tgd2_ports[0]
    rx_stream = [data['underlay_ecmp'][1]]
    tx_stream = [data['underlay_ecmp'][0]]
    if not retry_api(verify_installed_routes):
        result = False
        if tech_support:st.generate_tech_support(dut=None,name='underlay_ecmp_onfail')
        tech_support = False

    start_traffic(stream_han_list=streams,tgen_obj=data.tg1)
    #####################################################################
    st.log("\n\n>>>>>>>>>> Verify Traffic getting forwarded before doing Triggers <<<<<<<<\n\n")
    #####################################################################
    if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=rx_tgen_port,field='packet_rate',
                     tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=3,tgen_obj=data.tg1):
        st.error("Traffic Dropped before doing ecmp triggers")
        result =  False
        if tech_support:st.generate_tech_support(dut=None,name='underlay_ecmp_onfail')
        tech_support = False

    for port in port_flap_list[:-1]:
        ################################################
        st.log("\n\nStop and restart traffic after clearing tgen stats\n\n")
        ################################################
        data.tg1.tg_traffic_control(action='stop', stream_handle=streams)
        clear_stats(data.tgd1_handles + data.tgd2_handles,tgen_obj=data.tg1)
        st.exec_all([[Intf.clear_interface_counters, data.dut1],
                     [Intf.clear_interface_counters,data.dut2]])
        start_traffic(stream_han_list=streams,tgen_obj=data.tg1)
        st.wait(5)

        ##########################################################
        st.log("\n\n>>>>>>>> Shutdown port {} <<<<<<\n\n".format(port))
        ##########################################################
        port_api.shutdown(dut,port)
        ####################################################
        st.log("\n\n>>>>>>> Verify Traffic recovered after Trigger <<<<<<<<<\n\n")
        ####################################################
        if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=rx_tgen_port,field='packet_rate',tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=5,tgen_obj=data.tg1):
            st.error("Traffic not recovered after shutdown of {}".format(port))
            result = False
            if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
            tech_support = False
        #####################################################
        st.log("\n\n>>>>>> Stop Traffic for convergence measurement <<<<<<<<\n\n")
        #####################################################
        data.tg1.tg_traffic_control(action='stop',stream_handle=streams)
        st.wait(5,'Wait for 5 sec after stopping traffic')

        total_tx_count,total_rx_count = get_traffic_counters(tx_tgen,tx_stream,rx_handle=data.tgd2_handles[0],tgen_obj=data.tg1)

        if int(total_rx_count) == 0:
            st.error("Traffic Failed: RX port did not receive any packets after {}".format(port))
            result =False
            if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
            tech_support = False
        if result:
            drop = abs(float(total_tx_count) - float(total_rx_count))
            total_tx_streams = float(len(tx_stream))
            convergence_time = (float(drop)/float(traffic_rate))/total_tx_streams
            convergence_time = round(convergence_time,4)
            st.log("Traffic Convergence time : {} sec".format(convergence_time))

            if convergence_time > 1.0:
                st.error("Convergence time {} more than expected".format(convergence_time))
                result = False
                if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
                tech_support = False
        else:
            convergence_time = 'Fail'
            if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
            tech_support = False;result=False

        data['table_data_{}'.format(iteration)].append(convergence_time)

    for port in port_flap_list[::-1][1:]:
        ################################################
        st.log("\n\nStop and restart traffic after clearing tgen stats\n\n")
        ################################################
        data.tg1.tg_traffic_control(action='stop', stream_handle=streams)
        clear_stats(data.tgd1_handles+data.tgd2_handles,tgen_obj=data.tg1)
        st.exec_all([[Intf.clear_interface_counters, data.dut1],
                     [Intf.clear_interface_counters, data.dut2]])
        start_traffic(stream_han_list=streams,tgen_obj=data.tg1)
        st.wait(5)
        ##########################################################
        st.log("\n\n>>>>>>>> Bring back port {} admin up<<<<<<\n\n".format(port))
        ##########################################################
        port_api.noshutdown(dut,port)
        ####################################################
        st.log("\n\n>>>>>>> Verify Traffic recovered after Trigger <<<<<<<<<\n\n")
        ####################################################
        if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=rx_tgen_port,field='packet_rate',
                         tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=5,tgen_obj=data.tg1):
            st.error("Traffic not recovered after shutdown of {}".format(port))
            result = False
            if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
            tech_support = False
        #####################################################
        st.log("\n\n>>>>>> Stop Traffic for convergence measurement <<<<<<<<\n\n")
        #####################################################
        data.tg1.tg_traffic_control(action='stop',stream_handle=streams)
        st.wait(5, 'Wait for 5 sec after stopping traffic')
        total_tx_count,total_rx_count = get_traffic_counters(tx_tgen,tx_stream,rx_handle=data.tgd2_handles[0],tgen_obj=data.tg1)

        if int(total_rx_count) == 0:
            st.error("Traffic Failed: RX port did not receive any packets after {}".format(port))
            result =False
            if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
            tech_support = False
        if result:
            drop = abs(float(total_tx_count) - float(total_rx_count))
            total_tx_streams = float(len(tx_stream))
            convergence_time = (float(drop)/float(traffic_rate))/total_tx_streams
            convergence_time = round(convergence_time,4)
            st.log("Traffic Convergence time : {} sec".format(convergence_time))
            if convergence_time > 1.0:
                st.error("Convergence time {} more than expected".format(convergence_time))
                result = False
                if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
                tech_support = False
        else:
            convergence_time = 'Fail'
            if tech_support: st.generate_tech_support(dut=None, name='underlay_ecmp_onfail')
            tech_support = False;result=False
        data['table_data_{}'.format(iteration)].append(convergence_time)

    return result


def base_ecmp_config():
    config_ip()
    config_bgp()
    emulate_bgp()
    create_stream()

def base_ecmp_deconfig():
    config_bgp('no')
    config_ip('no')


def config_ip(config='yes'):
    def dut1():
        for intf,ip in zip(data.d1d2_ports,data.d1d2_ip_list):
            ip_api.config_ip_addr_interface(dut=data.dut1,interface_name=intf,ip_address=ip, subnet=data.mask_v4)
        ip_api.config_ip_addr_interface(dut=data.dut1, interface_name=data.d1tg_ports[0], ip_address=data.d1tg_ip_list[0], subnet=data.mask_v4)

    def dut2():
        for intf,ip in zip(data.d2d1_ports,data.d2d1_ip_list):
            ip_api.config_ip_addr_interface(dut=data.dut2,interface_name=intf,ip_address=ip, subnet=data.mask_v4)
        ip_api.config_ip_addr_interface(dut=data.dut2, interface_name=data.d2tg_ports[0], ip_address=data.d2tg_ip_list[0],
                                    subnet=data.mask_v4)

    def dut1_no():
        for intf,ip in zip(data.d1d2_ports,data.d1d2_ip_list):
            ip_api.delete_ip_interface(dut=data.dut1,interface_name=intf,ip_address=ip, subnet=data.mask_v4)
        ip_api.delete_ip_interface(dut=data.dut1, interface_name=data.d1tg_ports[0], ip_address=data.d1tg_ip_list[0], subnet=data.mask_v4)

    def dut2_no():
        for intf,ip in zip(data.d2d1_ports,data.d2d1_ip_list):
            ip_api.delete_ip_interface(dut=data.dut2,interface_name=intf,ip_address=ip, subnet=data.mask_v4)
        ip_api.delete_ip_interface(dut=data.dut2, interface_name=data.d2tg_ports[0], ip_address=data.d2tg_ip_list[0],
                                    subnet=data.mask_v4)

    if config == 'yes':
        st.exec_all([[dut1], [dut2]])
    else:
        st.exec_all([[dut1_no], [dut2_no]])

def config_bgp(config='yes'):
    def dut1():
        for neigh in data.d2d1_ip_list:
            bgp_api.config_bgp(dut=data.dut1, local_as=data.dut1_as, config='yes',
                       config_type_list=["neighbor", 'bfd', 'connect'], remote_as=data.dut2_as, neighbor=neigh,connect=1)
        bgp_api.config_bgp(dut=data.dut1, local_as=data.dut1_as, config='yes',
                   config_type_list=["neighbor", 'connect','max_path_ebgp'],
                           max_path_ebgp=10,remote_as=data.tgd1_as, neighbor=data.d1tg_ip_list[1],connect=1)

    def dut2():
        for neigh in data.d1d2_ip_list:
            bgp_api.config_bgp(dut=data.dut2, local_as=data.dut2_as, config='yes',
                       config_type_list=["neighbor", 'bfd', 'connect'], remote_as=data.dut1_as, neighbor=neigh,connect=1)
        bgp_api.config_bgp(dut=data.dut2, local_as=data.dut2_as, config='yes',
                   config_type_list=["neighbor", 'connect','max_path_ebgp'],max_path_ebgp=10,remote_as=data.tgd2_as,
                           neighbor=data.d2tg_ip_list[1],connect=1)

    def dut1_no():
        bgp_api.config_bgp(dut=data.dut1,config='no',removeBGP='yes',config_type_list=['removeBGP'])

    def dut2_no():
        bgp_api.config_bgp(dut=data.dut2, config='no', removeBGP='yes', config_type_list=['removeBGP'])

    if config =='yes':
        st.exec_all([[dut1], [dut2]])
    else:
        st.exec_all([[dut1_no], [dut2_no]])


def emulate_bgp():
    tg = data.tg1
    host1 = tg.tg_interface_config(port_handle=data.tgd1_handles[0], mode='config',
                                   intf_ip_addr=data.d1tg_ip_list[1],
                                   gateway=data.d1tg_ip_list[0],
                                   src_mac_addr=data.src_mac[data.tgd1_handles[0]],
                                   arp_send_req='1', netmask='255.255.255.0')
    host2 = tg.tg_interface_config(port_handle=data.tgd2_handles[0], mode='config',
                                   intf_ip_addr=data.d2tg_ip_list[1],
                                   gateway=data.d2tg_ip_list[0],
                                   src_mac_addr=data.src_mac[data.tgd2_handles[0]],
                                   arp_send_req='1', netmask='255.255.255.0')
    bgp_r1 = tg.tg_emulation_bgp_config(handle=host1['handle'], mode='enable', active_connect_enable='1',
                                        local_as=data.tgd1_as, remote_as=data.dut1_as,
                                        remote_ip_addr=data.d1tg_ip_list[0])
    bgp_r2 = tg.tg_emulation_bgp_config(handle=host2['handle'], mode='enable', active_connect_enable='1',
                                        local_as=data.tgd2_as,remote_as=data.dut2_as,
                                        remote_ip_addr=data.d2tg_ip_list[0])
    tg.tg_emulation_bgp_route_config(handle=bgp_r1['handle'], mode='add', num_routes=data.ipv4_routes_per_port,
                                                 prefix=data.route_prefix_start[0],
                                                 as_path='as_seq:'+data.tgd1_as)
    tg.tg_emulation_bgp_route_config(handle=bgp_r2['handle'], mode='add', num_routes=data.ipv4_routes_per_port,
                                                 prefix=data.route_prefix_start[1],
                                                 as_path='as_seq:'+data.tgd2_as)
    tg.tg_emulation_bgp_control(handle=bgp_r1['handle'], mode='start')
    tg.tg_emulation_bgp_control(handle=bgp_r2['handle'], mode='start')

def create_stream():
    tg= data.tg1
    data.streams={}
    data.d1tg_mac = basic.get_ifconfig(data.dut1, data.d1tg_ports[0])[0]['mac']
    data.d2tg_mac = basic.get_ifconfig(data.dut2, data.d2tg_ports[0])[0]['mac']
    stream = tg.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], enable_stream_only_gen=0,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=data.d1tg_mac,
                                  rate_pps=data.traffic_rate, mode='create',l2_encap='ethernet_ii',
                                  port_handle=data.tgd1_handles[0],transmit_mode='continuous',
                                  l3_protocol='ipv4', ip_src_addr=data.route_prefix_start[0],
                                  ip_dst_addr=data.route_prefix_start[1],
                                  mac_discovery_gw=data.d1tg_ip_list[0], ip_dst_step='0.0.1.0',
                                  ip_dst_mode='increment', ip_dst_count=data.ipv4_routes_per_port,port_handle2=data.tgd2_handles[0])
    stream1 = stream['stream_id']
    data['streams']["v4scale_1"] = [stream1]
    stream = tg.tg_traffic_config(mac_src=data.src_mac[data.tgd2_handles[0]], enable_stream_only_gen=0,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=data.d2tg_mac,
                                  rate_pps=data.traffic_rate, mode='create',l2_encap='ethernet_ii',
                                  port_handle=data.tgd2_handles[0],transmit_mode='continuous',
                                  l3_protocol='ipv4', ip_src_addr=data.route_prefix_start[1],
                                  ip_dst_addr=data.route_prefix_start[0],
                                  mac_discovery_gw=data.d2tg_ip_list[0], ip_dst_step='0.0.1.0',
                                  ip_dst_mode='increment', ip_dst_count=data.ipv4_routes_per_port,port_handle2=data.tgd1_handles[0])
    stream2 = stream['stream_id']
    data['streams']["v4scale_2"] = [stream2]
    data['underlay_ecmp'] = [stream1,stream2]

def verify_bgp():
    nbr_list = data.d2d1_ip_list +[data.d1tg_ip_list[1]]
    result = retry_api(ip_bgp.check_bgp_session,data.dut1,nbr_list=nbr_list,
                       state_list=['Established']*len(nbr_list),retry_count=30,delay=1)
    if result is False:
        st.error("One or more BGP sessions did not come up on DUT1")
        return False
    return True


def verify_installed_routes():
    v4_leaf1_count = ospf.fetch_ip_route_summary(data.dut1, key='ebgp')
    v4_leaf2_count = ospf.fetch_ip_route_summary(data.dut2, key='ebgp')

    st.log('D1 IPv4 routes : {}'.format(v4_leaf1_count))
    st.log('D2 IPv4 routes : {}'.format(v4_leaf2_count))

    if int(v4_leaf1_count) < data.ipv4_routes or int(v4_leaf2_count) < data.ipv4_routes:
        st.error("MAX ipv4 routes not installed")
        return False
    return True

def verify_ecmp_hashing(dut,ecmp_intf_list=[],total_streams=2,**kwargs):
    rate = kwargs.get('traffic_rate',data.traffic_rate)
    ret_val = True
    tolerance = 0.2
    total_paths = len(ecmp_intf_list)
    exp_rate_per_path = (int(rate)*total_streams)/total_paths
    exp_rate = exp_rate_per_path *tolerance
    for intf in ecmp_intf_list:
        output =  port_api.get_interface_counters_all(dut,port=intf)
        if output:
            tx_rate = int(output[0]['tx_pps'])
            if tx_rate < exp_rate:
                st.error("Traffic did not hash through ECMP path {}".format(intf))
                ret_val=False
    return ret_val


def start_traffic(stream_han_list=[],port_han_list=[],action="run",**kwargs):
    tg_obj = kwargs.get('tgen_obj', data.tg1)
    if action=="run":
        if tg_obj.tg_type == 'stc':
            tg_obj.tg_traffic_control(action="run", stream_handle=stream_han_list)
        else:
            tg_obj.tg_traffic_control(action="run", stream_handle=stream_han_list)
    else:
        if port_han_list:
            tg_obj.tg_traffic_control(action="stop", port_handle=port_han_list)
        else:
            tg_obj.tg_traffic_control(action="stop", stream_handle=stream_han_list)


def clear_stats(port_han_list=[],**kwargs):
    tg_obj = kwargs.get('tgen_obj', data.tg1)
    if port_han_list:
        tg_obj.tg_traffic_control(action='clear_stats',port_handle=port_han_list)
    else:
        tg_obj.tg_traffic_control(action='clear_stats',port_handle=data.tgd1_handles + data.tgd2_handles)


def verify_traffic(tx_port="", rx_port="", tx_ratio=1, rx_ratio=1,
                       field="packet_count",direction="2", **kwargs):
    '''
    :param tx_port:
    :param rx_port:
    :param tx_ratio:
    :param rx_ratio:
    :param field:
    :param direction:
    :param kwargs["tx_stream_list"]:
    :param kwargs["rx_stream_list"]:
    :return:
    '''


    tg_obj = kwargs.get('tgen_obj',data.tg1)

    if int(direction) == 2:
        traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg_obj],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg_obj],
                'stream_list': [tuple(kwargs["tx_stream_list"])]
            },
            '2': {
                'tx_ports': [rx_port],
                'tx_obj': [tg_obj],
                'exp_ratio': [rx_ratio],
                'rx_ports': [tx_port],
                'rx_obj': [tg_obj],
                'stream_list': [tuple(kwargs["rx_stream_list"])]
            }
        }
    else:
        traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg_obj],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg_obj],
                'stream_list': [tuple(kwargs["tx_stream_list"])]
            }
        }
    return tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode="streamblock",
                                       comp_type=field, tolerance_factor=1)


def get_traffic_counters(tx_handle,tx_stream,**kwargs):
    rx_handle = kwargs.get('rx_handle',data.tgd2_handles[0])
    tg_obj = kwargs.get('tgen_obj',data.tg1)
    total_tx_count = 0
    total_rx_count = 0
    mode='streams' if 'stc' in data.tgen_type else 'stream'
    tx_count = tg_obj.tg_traffic_stats(port_handle=tx_handle, mode=mode)
    if 'stc' not in data.tgen_type:
        rx_count = tg_obj.tg_traffic_stats(port_handle=rx_handle, mode=mode)
    for traffic_item in tx_stream:
        total_tx_count += int(tx_count[tx_handle]['stream'][traffic_item]['tx']['total_pkts'])
        if 'stc' not in data.tgen_type:
            total_rx_count += int(rx_count[rx_handle]['stream'][traffic_item]['rx']['total_pkts'])
        else:
            total_rx_count += int(tx_count[tx_handle]['stream'][traffic_item]['rx']['total_pkts'])
    st.log("Total Tx pkt count : {}".format(total_tx_count))
    st.log("Total Rx pkt count : {}".format(total_rx_count))
    return total_tx_count,total_rx_count