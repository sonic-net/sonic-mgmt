import pytest
from spytest import st, SpyTestDict, tgapi
import apis.routing.ip as ipfeature
import apis.system.interface as ifapi
import apis.system.basic as basic_obj
from apis.system.rest import config_rest, get_rest

vars = dict()
data = SpyTestDict()
data.ip4_addr_t1 = "192.168.1.1"
data.ip4_addr_t1_tg = "192.168.1.2"
data.ip4_addr_t2 = "192.168.2.1"
data.ip4_addr_t2_tg = "192.168.2.2"
data.ipv4_mask = '24'
data.tg_mac1 = "00:00:00:EA:23:0F"
data.tg_mac2 = "00:00:11:0A:45:33"
data.rate_pps = 2000

@pytest.fixture(scope="module", autouse=True)
def ip_module_hooks(request):
    global vars, tg_handler, tg
    # Min topology verification
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:2")

    # Initialize TG and TG port handlers
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    tg = tg_handler["tg"]
    yield
    ipfeature.clear_ip_configuration(vars.D1)
    

@pytest.fixture(scope="function", autouse=True)
def ip_func_hooks(request):
    yield

@pytest.mark.rest
def test_ft_l3_fwding():
    """
    Testcase : verify the basic L3 traffic validation
    Author : Praveen Kumar Kota <praveenkumar.kota@broadcom.com>
    """
    sub_intf = 0
    operation_tg1 = {"openconfig-if-ip:config": {
    "ip": "192.168.1.1",
    "prefix-length": 24 }}
    operation_tg2 = {"openconfig-if-ip:config": {
        "ip": "192.168.2.1",
        "prefix-length": 24}}
    rest_urls = st.get_datastore(vars.D1, "rest_urls")
    url = rest_urls['ip_config'].format(vars.D1T1P1, sub_intf, data.ip4_addr_t1)
    url2 = rest_urls['ip_config'].format(vars.D1T1P2, sub_intf, data.ip4_addr_t2)
    rest_put_out = config_rest(vars.D1, http_method= "rest-patch",  rest_url = url,  json_data=operation_tg1)

    rest_get_out = get_rest(vars.D1, rest_url = url)
    
    rest_put_out1 = config_rest(vars.D1, http_method = "rest-patch",  rest_url = url2, json_data=operation_tg2)

    rest_get_out1 = get_rest(vars.D1, rest_url = url2)
    
    
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', intf_ip_addr=data.ip4_addr_t1_tg,
                                gateway=data.ip4_addr_t1, src_mac_addr=data.tg_mac1, arp_send_req='1')
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', intf_ip_addr=data.ip4_addr_t2_tg,
                                gateway=data.ip4_addr_t2, src_mac_addr=data.tg_mac2, arp_send_req='1')
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'],
                            dst_ip=data.ip4_addr_t2_tg, ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")
    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=1000, length_mode='fixed', rate_pps=1000, l3_protocol='ipv4', mac_src=data.tg_mac1, \
                               mac_dst=dut_rt_int_mac1, ip_src_addr=data.ip4_addr_t1_tg, ip_dst_addr=data.ip4_addr_t2_tg)
    ifapi.clear_interface_counters(vars.D1, interface_type="all")
    ifapi.show_interface_counters_all(vars.D1)
    tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.wait(2)
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.wait(2)
    ifapi.show_interface_counters_all(vars.D1)
    tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
    tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
    counter1 = tg_2_stats.rx.total_packets
    counter2 = tg_1_stats.tx.total_packets
    if not counter1>=counter2 :
        ifapi.show_interface_counters_all(vars.D1)
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")
    