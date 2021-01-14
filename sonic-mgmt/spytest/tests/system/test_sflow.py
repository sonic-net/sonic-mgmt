# This file contains the list of sFlow tests
# Author: Vennapusa Sreenivasula Reddy  (sreenivasula.reddy@broadcom.com)

import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ipfeature
from apis.routing.arp import show_arp
from apis.system.basic import get_ifconfig_ether,get_ifconfig,service_operations_by_systemctl,poll_for_system_status,verify_service_status
import apis.system.sflow as sflow
from apis.system.logging import show_logging
from apis.system.interface import clear_interface_counters,show_interface_counters_detailed, interface_status_show
from apis.switching.portchannel import add_del_portchannel_member,delete_all_portchannels,create_portchannel,\
                                      clear_portchannel_configuration, get_portchannel_list
from apis.system.reboot import config_save
from apis.system.gnmi import gnmi_get,gnmi_set

from utilities.common import filter_and_select
from utilities.parallel import exec_all, exec_foreach
from utilities.utils import util_ip_addr_to_hexa_conv,util_int_to_hexa_conv,ensure_service_params

data = SpyTestDict()

def initialize_variables():
    data.clear()
    data.dut_list = [vars.D1, vars.D2]
    data.af_ipv4 = "ipv4"
    data.af_ipv6 = "ipv6"
    data.collector_name_1 = "collector_1"
    data.collector_name_2 = "collector_2"
    data.unreachable_sflow_collector_IP = "1.1.1.1"
    data.shell_sonic = "sonic"
    data.tg_mac1 = "00:00:00:00:00:0A"
    data.tg_mac2 = "00:00:00:00:00:0B"
    data.tg_mac3 = "00:00:00:00:00:0C"
    data.shell_vtysh = "vtysh"
    data.ip4_addr = ["192.168.1.1", "192.168.1.2", "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.3",
                     "192.168.4.1", "192.168.4.4"]
    data.ip6_addr = ["2001::1", "2001::2","2001::3"]
    data.static_ip_rt_tg2 = "192.168.3.0/24"
    data.static_ip_rt_tg1 = "192.168.1.0/24"
    data.ip_protocol = "17"
    data.members_dut2 = [vars.D2T1P2]
    data.non_default_udp_port = "4451"
    data.default_udp_port = "6343"
    data.non_default_sampling_rate = 2000
    data.default="default"
    data.non_default="non-default"
    data.polling_interval="polling interval"
    data.sampling_rate="sampling rate"
    data.portchannel_name = "PortChannel7"
    data.vrf_name = "Vrf_test_01"
    data.address_type_ipv4 = "1"
    data.address_type_ipv6 = "2"
    data.sflow_flow_sample_version = "1"
    data.sflow_counter_sample_version = "2"
    data.invalid_interface = "Ethernet1001"
    data.invalid_data_string = "BCMSONIC"
    data.invalid_ip_address_1 = "0.0.0.0"
    data.invalid_ip_address_2 = "239.1.1.1"
    data.invalid_ip_address_3 = "255.255.255.255"
    data.pps_1 = 100000
    data.pps_2 = 5000
    data.capture_support = True
    if st.is_soft_tgen():
        data.capture_support = False
        data.pps_2 = 200
        data.non_default_sampling_rate = 256
    data.agent_id = util_ip_addr_to_hexa_conv(data.ip4_addr[6])
    data.hex_address_type_v4 = util_int_to_hexa_conv(data.address_type_ipv4,z_fill=7)
    data.hex_address_type_v6 = util_int_to_hexa_conv(data.address_type_ipv6,z_fill=7)
    data.hex_flow_sample = util_int_to_hexa_conv(data.sflow_flow_sample_version,z_fill=7)
    data.hex_counter_sample = util_int_to_hexa_conv(data.sflow_counter_sample_version,z_fill=7)
    data.hex_sampling_rate = util_int_to_hexa_conv(data.non_default_sampling_rate,z_fill=7)

def validate_packet_capture(**kwargs):
    if not data.capture_support: return True
    return tgapi.validate_packet_capture(**kwargs)

def debug_dump(msg=""):
    st.banner("SFLOW configuration {}".format(msg))
    sflow.show(vars.D2)
    sflow.show_interface(vars.D2)

@pytest.fixture(scope="module", autouse=True)
def sflow_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1T1:1", "D2T1:2", "D1D2:1")
    initialize_variables()
    [output, _] = exec_all(True, [[interface_status_show, vars.D1, [vars.D1T1P1, vars.D1D2P1, vars.D1D2P2]],
                                  [interface_status_show, vars.D2, [vars.D2T1P1, vars.D2D1P1, vars.D2D1P2]]])
    dut1_intf_counters, dut2_intf_counters = output
    data.port_speed = {vars.D1:{vars.D1T1P1:None, vars.D1D2P1:None, vars.D1D2P2:None},
                       vars.D2:{vars.D2T1P1:None, vars.D2D1P1:None, vars.D2D1P2:None}}
    for port in [vars.D1T1P1, vars.D1D2P1, vars.D1D2P2]:
        data.port_speed[vars.D1][port] = filter_and_select(dut1_intf_counters, ['speed'], {'interface': port})[0]['speed'].replace('G', '000')
    for port in [vars.D2T1P1, vars.D2D1P1, vars.D2D1P2]:
        data.port_speed[vars.D2][port] = filter_and_select(dut2_intf_counters, ['speed'], {'interface': port})[0]['speed'].replace('G', '000')
    st.log("The port speed info is: {}".format(data.port_speed))
    data.dut_rt_int_mac1 = get_ifconfig_ether(vars.D1, vars.D1T1P1)
    exec_all(True, [[tg_prolog], [sflow_module_prolog]], first_on_main=True)
    yield
    exec_all(True, [[tg_epilog], [sflow_module_epilog]], first_on_main=True)


@pytest.fixture(scope="function", autouse=True)
def sflow_func_hooks(request):
    debug_dump("Function Prolog")
    yield
    debug_dump("Function Epilog")
    if st.get_func_name(request) == "test_ft_sflow_sampling_v4_sFlow_collector":
        sflow.config_attributes(vars.D2, sample_rate=data.port_speed[vars.D2][vars.D2D1P1], interface_name=vars.D2D1P1, no_form=True)
        sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                                port_number=data.non_default_udp_port, action="del")
        sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=data.default_udp_port, action="add")
    if st.get_func_name(request) == "test_ft_sflow_sampling_v6_sFlow_collector":
        module_config_retain()



def config_routing_interfaces(dut, params):
    if dut in params:
        for data in params[dut]:
            if not ipfeature.config_ip_addr_interface(dut, data["interface"], data["ip_address"], data["subnet"],
                                                      data["family"]):
                if data["family"] == "ipv4":
                    st.report_fail("ip_routing_int_create_fail", data["interface"])
                elif data["family"] == "ipv6":
                    st.report_fail("ip6_routing_int_create_fail", data["interface"])


def sflow_module_prolog():
    debug_dump("Module Prolog Start")
    st.log("Routing configuration on all duts")
    params = {
        vars.D1: [{"ip_address": data.ip4_addr[1], "interface": vars.D1T1P1, "subnet": 24, "family": data.af_ipv4},
                  {"ip_address": data.ip4_addr[2], "interface": vars.D1D2P1, "subnet": 24, "family": data.af_ipv4}],
        vars.D2: [{"ip_address": data.ip4_addr[3], "interface": vars.D2D1P1, "subnet": 24, "family": data.af_ipv4},
                  {"ip_address": data.ip4_addr[4], "interface": vars.D2T1P1, "subnet": 24, "family": data.af_ipv4},
                  {"ip_address": data.ip4_addr[6], "interface": vars.D2T1P2, "subnet": 24, "family": data.af_ipv4},
                  {"ip_address": data.ip6_addr[0], "interface": vars.D2T1P2, "subnet": 64, "family": data.af_ipv6}]}
    exec_foreach(True, data.dut_list, config_routing_interfaces, params)
    st.log("Adding static routes on D1 and D2")
    exec_all(True, [[ipfeature.create_static_route, vars.D1, data.ip4_addr[3], data.static_ip_rt_tg2, data.shell_vtysh, data.af_ipv4],
                   [ipfeature.create_static_route, vars.D2, data.ip4_addr[2], data.static_ip_rt_tg1, data.shell_vtysh, data.af_ipv4]])
    st.log("sFlow MODULE configuration - INIT")
    sflow.enable_disable_config(vars.D2, interface=False, interface_name=None, action="enable")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=None, action="add")
    st.log("Configuring non reachable sFlow Collector")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2,
                            ip_address=data.unreachable_sflow_collector_IP,
                            action="add")
    sflow.add_del_agent_id(vars.D2, interface_name=vars.D2T1P2, action="add")
    st.log("About to configure sFlow polling interval to non default value 0 means stopping sflow counter samples")
    sflow.config_attributes(vars.D2, polling_interval="0")
    debug_dump("Module Prolog End")


def sflow_module_epilog():
    debug_dump("Module Epilog Start")
    sflow.enable_disable_config(vars.D2, interface=False, interface_name=None, action="disable")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1,ip_address=data.ip4_addr[7],
                            port_number=None, action="del")
    sflow.add_del_agent_id(vars.D2, action="del")
    st.log("sFlow MODULE configuration - CLEAN UP")
    ipfeature.clear_ip_configuration(data.dut_list, 'all')
    clear_portchannel_configuration([vars.D2])
    exec_all(True, [[ipfeature.delete_static_route, vars.D1,data.ip4_addr[3], data.static_ip_rt_tg2],
                    [ipfeature.delete_static_route, vars.D2,data.ip4_addr[2], data.static_ip_rt_tg1]])
    debug_dump("Module Epilog End")


def verify_sflow_config():
    st.log("About to verify sFlow configuration")
    report_flag = 0
    filter_data = [{'collector_ip': data.unreachable_sflow_collector_IP, 'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2, 'port': data.default_udp_port},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        # st.report_tc_fail("FtOpSfFn006","failed_to_config_sflow")
        report_flag = 1
    if report_flag:
        st.report_tc_fail("FtOpSfFn006", "failed_to_config_sflow")
    else:
        st.report_tc_pass("FtOpSfFn006","sflow_test_case_passed")
    report_flag = 0
    if not show_logging(vars.D2, filter_list="Starting hsflowd service", lines=None):
        # st.report_tc_fail("FtOpSfFn02","failed_to_generate_sflow_log_in_syslog")
        report_flag = 1
    if report_flag:
        st.report_tc_fail("FtOpSfFn02","failed_to_generate_sflow_log_in_syslog")
    else:
        st.report_tc_pass("FtOpSfFn020", "sflow_test_case_passed")


def tg_prolog():
    global h1, h2, h3, tr1, tg, tg_ph_1, tg_ph_2, tg_ph_3, tg_handler
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D2P1, vars.T1D2P2])
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
    st.log("Routing configuration on all TGs")
    h1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ip4_addr[0],
                                gateway=data.ip4_addr[1], src_mac_addr=data.tg_mac1, arp_send_req='1')
    h2 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ip4_addr[5],
                                gateway=data.ip4_addr[4], src_mac_addr=data.tg_mac2, arp_send_req='1')
    h3 = tg.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr=data.ip4_addr[7],
                                gateway=data.ip4_addr[6], src_mac_addr=data.tg_mac3, arp_send_req='1')
    tg.tg_interface_config(port_handle=tg_ph_3, mode='config', ipv6_intf_addr=data.ip6_addr[1],
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[0], arp_send_req='1')
    st.log("stream configuration on	all TG's")
    tr1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', pkts_per_burst=data.pps_1,
          ip_protocol=data.ip_protocol, length_mode='fixed', rate_pps=data.pps_1, l3_protocol='ipv4', mac_src=data.tg_mac1,
          mac_dst=data.dut_rt_int_mac1, ip_src_addr=data.ip4_addr[0], ip_dst_addr=data.ip4_addr[5], l4_protocol='tcp',
          high_speed_result_analysis=0)

def tg_epilog():
    tg.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    tg.tg_interface_config(port_handle=tg_ph_3, handle=h3['handle'], mode='destroy')

def module_config_retain():
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip6_addr[1],
                            port_number=None, action="del")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=data.default_udp_port, action="add")
    sflow.config_attributes(vars.D2, polling_interval="0")

def poch_config_remove():
    ipfeature.config_ip_addr_interface(vars.D2, interface_name=data.portchannel_name, ip_address=data.ip4_addr[6]
                                       , subnet='24', family="ipv4", config='remove')
    add_del_portchannel_member(vars.D2, portchannel=data.portchannel_name,
                                       members=data.members_dut2, flag="del")
    delete_all_portchannels(vars.D2)
    ipfeature.config_ip_addr_interface(vars.D2, interface_name=vars.D2T1P2, ip_address=data.ip4_addr[6],
                                       subnet="24", family="ipv4", config="add")

    ipfeature.config_ip_addr_interface(vars.D2, interface_name=vars.D2T1P2, ip_address=data.ip6_addr[0], subnet="64",
                                       family="ipv6", config="add")
    if not ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4"):
        show_arp(vars.D2)
        ipfeature.show_ip_route(vars.D2)


@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_sampling_v4_sFlow_collector
def test_ft_sflow_sampling_v4_sFlow_collector():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn003 : Verify sFlow sampling functionality through Front end port on
    physical interfaces using IPv4 connectivity to sFlow collector.
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                        TG3(sFlow collector)
    """
    verify_sflow_config()
    report_flag, module_flag = 0, 0
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])

    st.banner("About to check initial psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val1 = sflow_samples_init.get("psample_cb", -1)
    sflow.hsflowd_status(vars.D2)
    if not ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4"):
        show_arp(vars.D2)
        ipfeature.show_ip_route(vars.D2)
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(2)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.wait(1)

    st.banner('About to validate sflow packet received by sflow collector', width=100)
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[46, 50, 70],
                                             value_list=[data.hex_address_type_v4, data.agent_id, data.hex_flow_sample])
    if not capture_result:
        st.report_msg("failed_to_receive_sflow_packets", data.default,data.sampling_rate)
        report_flag, module_flag = 1, 1

    st.banner("About to validate psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val2 = sflow_samples_init.get("psample_cb", -1)
    if psample_cb_val1 == -1 or psample_cb_val2 == -1 or (psample_cb_val2 < psample_cb_val1):
        st.log("PSAMPLE CB verification failed")
    psample_sflow_stats = int(psample_cb_val2) - int(psample_cb_val1)
    if psample_sflow_stats <= 3:
        st.report_msg("failed_to_receive_sflow_packets", data.default, data.sampling_rate)
        report_flag, module_flag = 1, 1

    st.banner('About to validate sflow collector interface counters', width=100)
    ing_count = show_interface_counters_detailed(vars.D2, vars.D2T1P2)
    if ing_count:
        st.log("ingress_sample_count_128_255 ={} ".format(ing_count[0]['pkt_tx_128_255_octets']))
        st.log("ingress_sample_count_256_511 ={} ".format(ing_count[0]['pkt_tx_256_511_octets']))
        st.log("ingress_sample_count_512_1023 ={} ".format(ing_count[0]['pkt_tx_512_1023_octets']))
        st.log("ingress_sample_count_1024_1518 ={} ".format(ing_count[0]['pkt_tx_1024_1518_octets']))
        if (int(str(ing_count[0]['pkt_tx_128_255_octets']).replace(',', '')) + int(str(ing_count[0]['pkt_tx_256_511_octets']).replace(',', '')) +
            int(str(ing_count[0]['pkt_tx_512_1023_octets'])) + int(str(ing_count[0]['pkt_tx_1024_1518_octets']).replace(',', ''))) < 4:
            st.report_msg("failed_to_receive_sflow_packets", data.default, data.sampling_rate)
            report_flag, module_flag = 1, 1
    if report_flag:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        st.report_tc_fail("FtOpSfFn003","failed_to_receive_sflow_packets", data.default, data.sampling_rate)
        st.report_tc_fail("FtOpSfFn010","failed_to_receive_sflow_packets", data.default, data.sampling_rate)
        st.report_tc_fail("FtOpSfFn024","failed_to_receive_sflow_packets", data.default, data.sampling_rate)
    else:
        st.report_tc_pass("FtOpSfFn003", "sflow_test_case_passed")
        st.report_tc_pass("FtOpSfFn010","sflow_test_case_passed")
        st.report_tc_pass("FtOpSfFn024","sflow_test_case_passed")

    report_flag = 0
    st.banner('About to send udp data traffic with non default sampling rate and non default udp collector port',
                  width=100)
    st.banner('About to Config sFlow sampling rate to non default value', width=100)
    sflow.config_attributes(vars.D2, sample_rate=data.non_default_sampling_rate, interface_name=vars.D2D1P1)
    # if not sflow.verify_interface(vars.D2, interface_name=vars.D2D1P1, sampling_rate=data.non_default_sampling_rate,
    #                               cli_type=data.sflow_cli_type):
    #     st.report_fail("failed_to_config_non_default_sampling_rate")
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    st.banner('About to check initial psample stats', width=100)
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val1 = sflow_samples_init.get("psample_cb", -1)
    st.banner('About to config non default udp collector port',width = 100)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=None, action="del")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=data.non_default_udp_port, action="add")
    sflow.hsflowd_status(vars.D2)
    ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4")
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.banner('About to send udp data traffic', width=100)
    tr2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', pkts_per_burst=data.pps_2,
          ip_protocol=data.ip_protocol, length_mode='fixed', rate_pps=data.pps_2, l3_protocol='ipv4', mac_src=data.tg_mac1,
          mac_dst=data.dut_rt_int_mac1, ip_src_addr=data.ip4_addr[0], ip_dst_addr=data.ip4_addr[5], l4_protocol='udp',
          high_speed_result_analysis=0)
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr2['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr2['stream_id'])
    st.wait(2)
    st.log("Checking the data stats for traffic flow")
    tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
    tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
    total_tx_tg1 = tg_1_stats.tx.total_packets
    total_rx_tg2 = tg_2_stats.rx.total_packets
    tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100
    st.log("total_tx_tg1={}".format(total_tx_tg1))
    st.log("total_rx_tg2={}".format(total_rx_tg2))
    st.log("tx_tg1_95_precentage={}".format(tx_tg1_95_precentage))
    if not tx_tg1_95_precentage <= total_rx_tg2:
        st.log("traffic_verification_failed")

    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    # st.banner('About to validate sflow packet received by sflow collector', width=100)
    # pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    # capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
    #                                          offset_list=[46, 50, 70, 86],
    #                                          value_list=[data.hex_address_type_v4, data.agent_id,
    #                                                     data.hex_flow_sample,data.hex_sampling_rate])
    # if not capture_result:
    #     st.report_msg("failed_to_receive_sflow_packets", data.non_default,data.sampling_rate)
    #     report_flag, module_flag = 1, 1
    st.banner('About to validate psample stats', width=100)
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val2 = sflow_samples_init.get("psample_cb", -1)
    if psample_cb_val1 == -1 or psample_cb_val2 == -1 or (psample_cb_val2 < psample_cb_val1):
        st.log("PSAMPLE CB verification failed")
    psample_sflow_stats = int(psample_cb_val2) - int(psample_cb_val1)
    if psample_sflow_stats <= 9:
        st.report_msg("failed_to_receive_sflow_packets", data.non_default, data.sampling_rate)
        report_flag, module_flag = 1, 1
    st.banner('About to validate sflow collector interface counters', width=100)
    ing_count = show_interface_counters_detailed(vars.D2, vars.D2T1P2)
    if ing_count:
        st.log("ingress_sample_count_128_255 ={} ".format(ing_count[0]['pkt_tx_128_255_octets']))
        st.log("ingress_sample_count_256_511 ={} ".format(ing_count[0]['pkt_tx_256_511_octets']))
        st.log("ingress_sample_count_512_1023 ={} ".format(ing_count[0]['pkt_tx_512_1023_octets']))
        st.log("ingress_sample_count_1024_1518 ={} ".format(ing_count[0]['pkt_tx_1024_1518_octets']))
        if (int(str(ing_count[0]['pkt_tx_128_255_octets']).replace(',', '')) + int(str(ing_count[0]['pkt_tx_256_511_octets']).replace(',', '')) +
            int(str(ing_count[0]['pkt_tx_512_1023_octets']).replace(',', '')) + int(str(ing_count[0]['pkt_tx_1024_1518_octets']).replace(',', ''))) < 9:
            st.report_msg("failed_to_receive_sflow_packets", data.non_default, data.sampling_rate)
            report_flag, module_flag = 1, 1
    ##
    if report_flag:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        st.report_tc_fail("FtOpSfFn007","failed_to_receive_sflow_packets", data.non_default, data.sampling_rate)
        st.report_tc_fail("FtOpSfFn022", "failed_to_receive_sflow_packets", data.non_default, data.sampling_rate)
    else:
        st.report_tc_pass("FtOpSfFn007","sflow_test_case_passed")
        st.report_tc_pass("FtOpSfFn022", "sflow_test_case_passed")

    if module_flag:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        st.report_fail("failed_to_receive_sflow_packets", data.non_default, data.sampling_rate)
    else:
        st.report_pass("sflow_test_case_passed")



@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_sampling_v4_sFlow_collector
def test_ft_sflow_sampling_v6_sFlow_collector():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn004 : Verify sFlow sampling functionality through Front end port on physical interfaces
    using IPV6 connectivity to sFlow collector.
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |(2001::1/64)
                                                                                |
                                                                                |(2001::2
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    """
    report_flag, module_flag = 0, 0
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=data.default_udp_port, action="del")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip6_addr[1],
                            port_number=None, action="add")
    sflow.enable_disable_config(vars.D2, interface=True, interface_name=vars.D2D1P1, action="disable")
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    sflow.psample_stats(vars.D2, ['psample_cb'])
    sflow.hsflowd_status(vars.D2)
    if not ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4"):
        show_arp(vars.D2)
        ipfeature.show_ip_route(vars.D2)
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.banner('About to validate sflow packet received by sflow collector')
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[50, 70],
                                             value_list=[data.hex_address_type_v6, data.agent_id])
    if capture_result:
        st.report_msg("sflow_negative_verifcation_failed")
        report_flag, module_flag = 1, 1
    if report_flag:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_tc_fail("FtOpSfFn008","sflow_negative_verifcation_failed")
    else:
        st.report_tc_pass("FtOpSfFn008","sflow_test_case_passed")

    report_flag = 0

    #sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip6_addr[1], port_number=None, action="add")
    sflow.enable_disable_config(vars.D2, interface=True, interface_name=vars.D2D1P1, action="enable")
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    st.log("About to check initial psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val1 = sflow_samples_init.get("psample_cb", -1)
    sflow.hsflowd_status(vars.D2)
    ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4")
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(2)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.wait(1)
    st.banner('About to validate sflow packet received by sflow collector', width=100)
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[50, 70],
                                             value_list=[data.hex_address_type_v6, data.agent_id])
    if not capture_result:
        st.report_msg("failed_to_receive_sflow_packets", data.default,data.sampling_rate)
        report_flag, module_flag = 1, 1

    st.log("About to validate psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val2 = sflow_samples_init.get("psample_cb", -1)
    if psample_cb_val1 == -1 or psample_cb_val2 == -1 or (psample_cb_val2 < psample_cb_val1):
        st.log("PSAMPLE CB verification failed")
    psample_sflow_stats = int(psample_cb_val2) - int(psample_cb_val1)
    if psample_sflow_stats <= 3:
        st.report_msg("failed_to_receive_sflow_packets", data.default,data.sampling_rate)
        report_flag, module_flag = 1, 1
    st.banner('About to validate sflow collector interface counters', width=100)
    ing_count = show_interface_counters_detailed(vars.D2, vars.D2T1P2)
    if ing_count:
        st.log("ingress_sample_count_128_255 ={} ".format(ing_count[0]['pkt_tx_128_255_octets']))
        st.log("ingress_sample_count_256_511 ={} ".format(ing_count[0]['pkt_tx_256_511_octets']))
        if (int(str(ing_count[0]['pkt_tx_128_255_octets']).replace(',', '')) + int(str(ing_count[0]['pkt_tx_256_511_octets']).replace(',', '')) +
            int(str(ing_count[0]['pkt_tx_512_1023_octets']).replace(',', '')) + int(str(ing_count[0]['pkt_tx_1024_1518_octets']).replace(',', ''))) < 4:
            st.report_msg("failed_to_receive_sflow_packets", data.default,data.sampling_rate)
            report_flag, module_flag = 1, 1
    if report_flag:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        st.report_tc_fail("FtOpSfFn004","failed_to_receive_sflow_packets", data.default, data.sampling_rate)
    else:
        st.report_tc_pass("FtOpSfFn004", "sflow_test_case_passed")

    if module_flag:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        st.report_fail("failed_to_receive_sflow_packets", data.default,data.sampling_rate)
    else:
        st.report_pass("sflow_test_case_passed")



@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_counter_samples_polling_interval
def test_ft_sflow_counter_samples_polling_interval():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn012 : Verify that counter samples are updated for non default polling interval
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                        TG3(sFlow collector)
    """
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    sflow.psample_stats(vars.D2, ['psample_cb'])
    st.log("About to configure sFlow polling interval to  non default value ")
    sflow.config_attributes(vars.D2, polling_interval="30")
    st.log("About to verify sFlow polling interval configuration")
    filter_data = [{'collector_ip': data.unreachable_sflow_collector_IP, 'polling_interval': '30',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2, 'port': data.default_udp_port},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        module_config_retain()
        st.report_fail("failed_to_config_sflow")

    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(32)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    # st.banner('About to validate counter sample sflow packet received by sflow collector')
    # pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    # capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
    #                                          offset_list=[46, 50, 70],
    #                                          value_list=[data.hex_address_type_v4,
    #                                                      data.agent_id, data.hex_counter_sample])
    # if not capture_result:
    #     st.report_fail("failed_to_receive_sflow_packets", data.default,data.polling_interval)
    ing_count = show_interface_counters_detailed(vars.D2, vars.D2T1P2)
    if ing_count:
        st.log("ingress_sample_count_128_255 ={} ".format(ing_count[0]['pkt_tx_128_255_octets']))
        st.log("ingress_sample_count_256_511 ={} ".format(ing_count[0]['pkt_tx_256_511_octets']))
        st.log("ingress_sample_count_512_1023 ={} ".format(ing_count[0]['pkt_tx_512_1023_octets']))
        st.log("ingress_sample_count_1024_1518 ={} ".format(ing_count[0]['pkt_tx_1024_1518_octets']))
        if (int(str(ing_count[0]['pkt_tx_128_255_octets']).replace(',', '')) + int(str(ing_count[0]['pkt_tx_256_511_octets']).replace(',', '')) +
            int(str(ing_count[0]['pkt_tx_512_1023_octets']).replace(',', ''))+int(str(ing_count[0]['pkt_tx_1024_1518_octets']).replace(',', ''))) <= 9:
            sflow.psample_stats(vars.D2, ['psample_cb'])
            exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
            exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
            st.report_fail("failed_to_receive_sflow_packets", data.default, data.polling_interval)
    st.report_pass("sflow_test_case_passed")

@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_max_sflow_collector_config
def test_ft_sflow_max_sflow_collector_config():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn005 : Verify max sFlow collectors configuration with different
    combinations (2 IPV4,2 IPV6,combination of both).
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                        TG3(sFlow collector)
    """
    sflow.config_attributes(vars.D2, polling_interval="0")
    sflow.hsflowd_status(vars.D2)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2, ip_address=data.unreachable_sflow_collector_IP,
                            action="del")
    sflow.hsflowd_status(vars.D2)
    st.banner('About to add IPv4 and IPv6 max sflow collector combination')
    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2, ip_address=data.ip6_addr[1],
                            port_number=None, action="add")
    filter_data = [{'collector_ip': data.ip6_addr[1], 'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2, 'port': data.default_udp_port},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")

    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=data.default_udp_port, action="del")
    sflow.hsflowd_status(vars.D2)
    st.banner('About to add max IPv6 sflow collectors')
    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip6_addr[2],
                            port_number=None, action="add")
    filter_data = [{'collector_ip': data.ip6_addr[1], 'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2, 'port': data.default_udp_port},
                   {'port': data.default_udp_port, 'collector_ip': data.ip6_addr[2]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")

    sflow.hsflowd_status(vars.D2)
    st.banner('About to delete IPv4 sflow collectors')
    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip6_addr[2],
                            port_number=None, action="del")
    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2, ip_address=data.ip6_addr[1],
                            port_number=None, action="del")
    filter_data = [{'polling_interval': '0',
                    'collectors_cnt': '0', 'state': 'up', 'agent_id': vars.D2T1P2}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")

    sflow.hsflowd_status(vars.D2)
    st.banner('About to add max IPv4 sflow collectors')
    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.ip4_addr[7],
                            port_number=None, action="add")
    st.wait(1)
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2,
                            ip_address=data.unreachable_sflow_collector_IP,
                            action="add")
    filter_data = [{'collector_ip': data.unreachable_sflow_collector_IP, 'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2, 'port': data.default_udp_port},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")

    sflow.hsflowd_status(vars.D2)
    st.report_pass("sflow_test_case_passed")

@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_sampling_sFlow_collector_management_port
def test_ft_sflow_sampling_sFlow_collector_management_port():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn001 : Verify sFlow sampling functionality through management port connectivity to
    sFlow collector.
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    """
    sflow_collector_ip = ensure_service_params(vars.D1, "chef", "ip")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2,
                            ip_address=data.unreachable_sflow_collector_IP, action="del")
    sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2, ip_address=sflow_collector_ip,
                            port_number=None, action="add")
    st.poll_wait(ipfeature.ping, 3, vars.D2, sflow_collector_ip, family="ipv4")
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    eth0_params = get_ifconfig(vars.D2)
    init_eth0_param=eth0_params[0]["tx_packets"]
    st.log("About to check initial psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val1 = sflow_samples_init.get("psample_cb", -1)
    sflow.hsflowd_status(vars.D2)
    if not ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4"):
        show_arp(vars.D2)
        ipfeature.show_ip_route(vars.D2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(12)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("Checking the data stats for traffic flow")
    tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
    tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
    total_tx_tg1 = tg_1_stats.tx.total_packets
    total_rx_tg2 = tg_2_stats.rx.total_packets
    tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100
    st.log("total_tx_tg1={}".format(total_tx_tg1))
    st.log("total_rx_tg2={}".format(total_rx_tg2))
    st.log("tx_tg1_95_precentage={}".format(tx_tg1_95_precentage))
    if not tx_tg1_95_precentage <= total_rx_tg2:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_fail("traffic_verification_failed")
    st.log("About to validate psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val2 = sflow_samples_init.get("psample_cb", -1)
    if psample_cb_val1 == -1 or psample_cb_val2 == -1 or (psample_cb_val2 < psample_cb_val1):
        st.log("PSAMPLE CB verification failed")
    psample_sflow_stats = int(psample_cb_val2) - int(psample_cb_val1)
    if psample_sflow_stats <= 3:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_fail("failed_to_receive_sflow_packets", data.default,data.sampling_rate)
    eth0_params = get_ifconfig(vars.D2)
    fin_eth0_param = eth0_params[0]["tx_packets"]
    if (int(fin_eth0_param)-int(init_eth0_param))<=3:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_fail("failed_to_receive_sflow_packets", data.default, data.sampling_rate)
    st.report_pass("sflow_test_case_passed")

@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_collector_port_poch
def test_ft_sflow_collector_port_poch():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn016 : Verify sFlow functionality when sflow collector interface is
    participated in PortChannel
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    """
    ipfeature.delete_ip_interface(vars.D2, interface_name=vars.D2T1P2, ip_address=data.ip4_addr[6],
                                  subnet="24", family="ipv4")
    ipfeature.delete_ip_interface(vars.D2, interface_name=vars.D2T1P2, ip_address=data.ip6_addr[0], subnet="64",
                                  family="ipv6")
    create_portchannel(vars.D2, portchannel_list=data.portchannel_name, fallback=False,
                                   min_link="", static=True)
    add_del_portchannel_member(vars.D2, portchannel=data.portchannel_name,
                               members=data.members_dut2, flag="add")
    ipfeature.config_ip_addr_interface(vars.D2, interface_name=data.portchannel_name, ip_address=data.ip4_addr[6]
                                       , subnet='24', family="ipv4", config='add')
    if not ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4"):
        show_arp(vars.D2)
        ipfeature.show_ip_route(vars.D2)
    sflow.get_psample_list_groups(vars.D2)
    collector_data = [{'collector_ip': data.ip4_addr[7], 'collector_name': data.collector_name_1}]
    if not st.poll_wait(sflow.verify_config, 30, vars.D2, data=collector_data):
        poch_config_remove()
        st.report_fail("failed_to_config_sflow")
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    sflow.psample_stats(vars.D2, ['psample_cb'])
    sflow.hsflowd_status(vars.D2)
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(12)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(2)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.wait(1)
    st.banner('About to validate sflow packet received by sflow collector', width=100)
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[46, 50, 70],
                                             value_list=[data.hex_address_type_v4, data.agent_id, data.hex_flow_sample])
    if not capture_result:
        get_portchannel_list(vars.D2)
        sflow.psample_stats(vars.D2, ['psample_cb'])
        sflow.get_psample_list_groups(vars.D2)
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        poch_config_remove()
        st.report_fail("failed_to_receive_sflow_packets", data.default, data.sampling_rate)
    poch_config_remove()
    st.report_pass("sflow_test_case_passed")

@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_samples_control_plane_traffic
def test_ft_sflow_samples_control_plane_traffic():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn023 : Verify sFlow functionality for control Plane traffic.
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    """
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    st.log("About to check initial psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val1 = sflow_samples_init.get("psample_cb", -1)
    st.banner('About to Config sFlow sampling rate to non default value', width=100)
    sflow.config_attributes(vars.D2, sample_rate="256", interface_name=vars.D2D1P1)
    sflow.hsflowd_status(vars.D2)
    ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4")
    st.log("###### Ping iteration started ########")
    for Iter in range(5):
        st.log("Iteration count is : {}" .format(Iter))
        ipfeature.ping(vars.D1, data.ip4_addr[5], family="ipv4",count="100")
    #ipfeature.ping(vars.D1, data.ip4_addr[5], family="ipv4",count="1000")
    st.log("About to validate psample stats")
    sflow_samples_init = sflow.psample_stats(vars.D2, ['psample_cb'])
    psample_cb_val2 = sflow_samples_init.get("psample_cb", -1)
    if psample_cb_val1 == -1 or psample_cb_val2 == -1 or (psample_cb_val2 < psample_cb_val1):
        st.log("PSAMPLE CB verification failed")
    psample_sflow_stats = int(psample_cb_val2) - int(psample_cb_val1)
    if psample_sflow_stats < 1:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        sflow.config_attributes(vars.D2, sample_rate=data.port_speed[vars.D2][vars.D2D1P1], interface_name=vars.D2D1P1, no_form=True)
        st.report_fail("sflow_control_plane_traffic_status", "failed")
    sflow.config_attributes(vars.D2, sample_rate=data.port_speed[vars.D2][vars.D2D1P1], interface_name=vars.D2D1P1, no_form=True)
    st.report_pass("sflow_control_plane_traffic_status","succeeded")

@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_func_docker_restart
def test_ft_sflow_docker_restart():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn015 : Verify that sFlow functionality after sflow docker restart
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    """
    st.log("Checking the sflow functionality with docker restart")
    service_name = "sflow"
    service_operations_by_systemctl(vars.D2, service_name, 'restart')
    if not poll_for_system_status(vars.D2, service_name, 15, 1):
        st.report_fail("service_not_running", service_name)
    if not verify_service_status(vars.D2, service_name):
        st.report_fail("lldp_service_not_up")
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    sflow.psample_stats(vars.D2, ['psample_cb'])
    sflow.hsflowd_status(vars.D2)
    if not ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4"):
        show_arp(vars.D2)
        ipfeature.show_ip_route(vars.D2)
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(2)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.wait(1)
    st.banner('About to validate sflow packet received by sflow collector', width=100)
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[46, 50, 70],
                                             value_list=[data.hex_address_type_v4, data.agent_id, data.hex_flow_sample])
    if capture_result:
        st.report_pass("sflow_docker_restart_status","succeeded")
    else:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_fail("sflow_docker_restart_status", "failed")


@pytest.mark.test_ft_sflow_save_reboot
def test_ft_system_config_mgmt_verifying_config_with_save_reboot_sflow():
    st.log("performing Config save")
    config_save(vars.D2)
    st.log("performing Reboot")
    st.reboot(vars.D2)
    st.log("verifying sFlow after save and reboot")
    filter_data = [{'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")
    st.log("configuration successfully stored to config_db file after save and reboot")
    st.report_pass("test_case_passed")


@pytest.mark.test_ft_sflow
@pytest.mark.test_ft_sflow_fast_reboot
def test_ft_sflow_fast_reboot():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn018 : Verify that sFlow functionality after fast reboot
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    """
    st.log("Performing Config save")
    config_save(vars.D2)
    st.log("Performing fast Reboot")
    st.reboot(vars.D2, "fast")
    st.log("Verifying sflow configuration post reboot")
    st.log("About to verify sFlow configuration")
    filter_data = [{'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")
    st.banner("After reboot and hsflowd is UP, it takes about a min to start sending samples,as the refresh cycle is 60 second")
    st.wait(40)
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    sflow.psample_stats(vars.D2, ['psample_cb'])
    sflow.hsflowd_status(vars.D2)
    ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4")
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(2)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.wait(1)
    st.banner('About to validate sflow packet received by sflow collector', width=100)
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[46, 50, 70],
                                             value_list=[data.hex_address_type_v4, data.agent_id, data.hex_flow_sample])
    if capture_result:
        st.report_pass("sflow_fast_reboot_status","succeeded")
    else:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_fail("sflow_fast_reboot_status", "failed")


@pytest.mark.test_ft_sflow_warm_reboot
def test_ft_sflow_warm_reboot():
    """
    Author Details:
    Name: Sreenivasula Reddy Vennapusa
    Email:  sreenivasula.reddy@broadcom.com
    Objective - FtOpSfFn019 : Verify that sFlow functionality after warm reboot
    Test bed details:
    TG1(192.168.1.1)---(192.168.1.2)Partner(192.168.2.1/24)---(192.168.2.2/24)DUT(192.168.3.1)---(192.168.3.3/24)TG2
                                                                                |(192.168.4.1/24)
                                                                                |
                                                                                |
                                                                                |(192.168.4.4/24)
                                                                            TG3(sFlow collector)
    After warm reboot and after hsflowd is UP, it takes about a min to start sending samples.
    this is the expected behavior as the refresh cycle is 60 second
    """
    st.log("Performing Config save")
    config_save(vars.D2)
    st.log("Performing warm Reboot")
    st.reboot(vars.D2, "warm")
    st.log("Verifying sflow configuration post reboot")
    st.log("About to verify sFlow configuration")
    filter_data = [{'polling_interval': '0',
                    'collectors_cnt': '2', 'state': 'up', 'agent_id': vars.D2T1P2},
                   {'port': data.default_udp_port, 'collector_ip': data.ip4_addr[7]}]
    if not sflow.verify_config(vars.D2, data=filter_data):
        st.report_fail("failed_to_config_sflow")
    st.banner("After reboot and hsflowd is UP, it takes about a min to start sending samples,as the refresh cycle is 60 second")
    st.wait(40)
    exec_all(True, [[clear_interface_counters, vars.D1],[clear_interface_counters, vars.D2]])
    sflow.psample_stats(vars.D2, ['psample_cb'])
    sflow.hsflowd_status(vars.D2)
    ipfeature.ping_poll(vars.D2, data.ip4_addr[7], family="ipv4", iter=3, count="4")
    tg.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.wait(2)
    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(2)
    st.log("stop the capture")
    tg.tg_packet_control(port_handle=tg_ph_3, action='stop')
    st.wait(1)
    st.banner('About to validate sflow packet received by sflow collector', width=100)
    pkts_captured = tg.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    capture_result = validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[46, 50, 70],
                                             value_list=[data.hex_address_type_v4, data.agent_id, data.hex_flow_sample])
    if capture_result:
        st.report_pass("sflow_warm_reboot_status","succeeded")
    else:
        sflow.psample_stats(vars.D2, ['psample_cb'])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1T1P1], [show_interface_counters_detailed, vars.D2, vars.D2T1P1]])
        exec_all(True, [[show_interface_counters_detailed, vars.D1, vars.D1D2P1], [show_interface_counters_detailed, vars.D2, vars.D2D1P1]])
        show_interface_counters_detailed(vars.D2, vars.D2T1P2)
        st.report_fail("sflow_warm_reboot_status", "failed")


@pytest.mark.test_ft_sflow_invalid_config
def test_ft_sflow_invalid_config():
    st.log("About to config invalid interface and invalid string as sflow agent-id")
    out = sflow.add_del_agent_id(vars.D1, interface_name=data.invalid_interface, action="add", skip_error_check = True)
    cli_type = st.get_ui_type(vars.D1, cli_type='')
    if cli_type == 'klish':
        if not "%Error" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "agent-id")
    elif cli_type == 'click':
        if not "Invalid interface name" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "agent-id")

    out = sflow.add_del_agent_id(vars.D1, interface_name=data.invalid_data_string, action="add" , skip_error_check = True)
    if cli_type == 'klish':
        if not "Error" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "agent-id")
    elif cli_type == 'click':
        if not "Invalid interface name" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "agent-id")


    st.log("About to config invalid IPv4 address as sflow collecteor")
    out = sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.invalid_ip_address_1,
                            port_number=None, action="add", skip_error_check = True)
    if cli_type == 'klish':
        if not "%Error" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "collector address")
    elif cli_type == 'click':
        if not "Invalid" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "collector address")

    out = sflow.add_del_collector(vars.D2, collector_name=data.collector_name_2, ip_address=data.invalid_ip_address_2,
                            port_number=None, action="add", skip_error_check = True)
    if cli_type == 'klish':
        if not "%Error" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "collector address")
    elif cli_type == 'click':
        if not "Invalid" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "collector address")

    out = sflow.add_del_collector(vars.D2, collector_name=data.collector_name_1, ip_address=data.invalid_ip_address_3,
                            port_number=None, action="add", skip_error_check = True)
    if cli_type == 'klish':
        if not "%Error" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "collector address")
    elif cli_type == 'click':
        if not "Invalid" in out:
            st.error("The output is: {}".format(out))
            st.report_fail("sflow_invalid_config_status", "not", "collector address")
    st.report_pass("sflow_invalid_config_status","successfully","parameters")


@pytest.mark.test_ft_sflow_rest
def test_ft_sflow_rest_conf():
    st.log("sFlow configuration through REST")
    try:
        sflow.enable_disable_config(vars.D2, interface=False, interface_name=None, action="disable",
                                    cli_type="rest")
        st.log("About to configure sFlow polling interval to  non default value ")
        sflow.config_attributes(vars.D2, polling_interval="90", cli_type="rest")
        st.log("About to verify sFlow configuration")
        filter_data = [{'polling_interval': '90','state': 'down'}]
        if not sflow.verify_config(vars.D2, data=filter_data):
            st.report_fail("sflow_REST_config_status", "failed")
        st.report_pass("sflow_REST_config_status", "succeeded")
    except Exception as e:
        st.log(e)
        st.report_fail("exception_observed", e)


@pytest.mark.test_ft_sflow_gnmi
def test_ft_sflow_gnmi():
    data.get_get_xpath = "/sonic-sflow:sonic-sflow/SFLOW/SFLOW_LIST[sflow_key=global]/admin_state"
    data.get_set_xpath = "/sonic-sflow:sonic-sflow/SFLOW/SFLOW_LIST"
    data.json_data = {"sonic-sflow:SFLOW_LIST": [{"sflow_key": "global", "admin_state": "up"}]}
    gnmi_set_output = gnmi_set(vars.D1, xpath=data.get_set_xpath, json_content=data.json_data)
    st.log(gnmi_set_output)
    if not gnmi_set_output:
        st.report_fail('sflow_gNMI_config_status', "config","set","failed")
    if not "op: UPDATE" in str(gnmi_set_output):
        st.report_fail('sflow_gNMI_config_status', "config","set","failed")
    gnmi_get_output = gnmi_get(vars.D1, xpath = data.get_get_xpath)
    st.log(gnmi_get_output)
    if not gnmi_get_output:
        st.report_fail('sflow_gNMI_config_status', "status","get","failed")
    if "sonic-sflow:admin_state" not in str(gnmi_get_output):
        st.report_fail('sflow_gNMI_config_status', "status","get","failed")
    st.report_pass('sflow_gNMI_config_status', "operation","get and set","successful")

