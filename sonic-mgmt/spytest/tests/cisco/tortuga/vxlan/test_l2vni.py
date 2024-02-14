import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.system.box_services as boxserv_obj

import apis.routing.ip as ipfeature
import apis.switching.vlan as vapi
import apis.system.port as papi
import apis.system.interface as intapi
import apis.routing.ip as ip_obj
import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.system.basic as basic_obj


##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

## Spirent Stream Config
data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None

data.d3t1_ip_addr = "1.1.1.1"
data.t1d3_ip_addr = "1.1.1.2"
data.t1d3_mac_addr = "00:00:00:00:00:01"

data.d3t4_ip_addr = "1.1.1.1"
data.t1d4_ip_addr = "1.1.1.3"
data.t1d4_mac_addr = "00:00:00:00:00:02"
data.pkts_per_burst = "1000"
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 20
data.clear_parallel = True
## Spirent Stream Config


pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D2D3:4","D2D4:4", "D3T1:1", "D4T1:1")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]

    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

CONFIGS_FILE = 'vxlan_l2vni_configs.yaml'
LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


####################
@pytest.fixture()
def setup_teardown_l2vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            # Disabling drake so that there are no automatic underlay configs
            st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)

            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    st.wait(5)
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.201'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.200'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_l2vni'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)


def verify_vtep_state (nodes):
    leaf0_vtep_ip = LEAF0_VXLAN_IP
    leaf1_vtep_ip = LEAF1_VXLAN_IP

    leaf0_output = st.show(nodes['leaf0'], "show vxlan remotevtep", skip_tmpl=True)

    leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep",
                                 leaf0_output, "show_vxlan_remote.tmpl")

    leaf1_output = st.show(nodes['leaf1'], "show vxlan remotevtep", skip_tmpl=True)

    leaf1_parsed = st.parse_show(nodes['leaf1'], "show vxlan remotevtep",
                                 leaf1_output, "show_vxlan_remote.tmpl")

    if len(leaf0_parsed) == 0:
        report_fail(nodes['leaf0'], msg='No remote VTEP found in leaf0')

    vtep_num = 0
    for path in leaf0_parsed:
        vtep_num += 1
        if path['tun_src'] != 'EVPN':
            report_fail(nodes['leaf0'], msg='Unexpected tunnel type {} in leaf0'.format(path['tun_type']))
        if path['src_vtep'] != leaf0_vtep_ip:
            report_fail(nodes['leaf0'], msg='No local vtep {} found in leaf0'.format(leaf0_vtep_ip))
        if path['dst_vtep'] != leaf1_vtep_ip:
            report_fail(nodes['leaf0'], msg='Unexpected vtep {} found in leaf0'.format(path['rem_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail(nodes['leaf0'], msg='Tunnel is not in up status in leaf0')
    if vtep_num != 1:
        report_fail(nodes['leaf0'], msg='Incorrect number of VTEPs found in leaf0')

    if len(leaf1_parsed) == 0:
        report_fail(nodes['leaf1'], msg='No remote VTEP found in leaf1')
    vtep_num = 0
    for path in leaf1_parsed:
        vtep_num += 1
        if path['tun_src'] != 'EVPN':
            report_fail(nodes['leaf1'], msg='Unexpected tunnel type {} in leaf1'.format(path['tun_type']))
        if path['src_vtep'] != leaf1_vtep_ip:
            report_fail(nodes['leaf1'], msg='No local vtep {} found in leaf1'.format(leaf1_vtep_ip))
        if path['dst_vtep'] != leaf0_vtep_ip:
            report_fail(nodes['leaf1'], msg='Unexpected vtep {} found in leaf1'.format(path['rem_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail(nodes['leaf1'], msg='Tunnel is not in up status in leaf1')
    if vtep_num != 1:
        report_fail(nodes['leaf1'], msg='Incorrect number of VTEPs found in leaf1')


@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

def test_l2vni_vtep_setup (setup_teardown_l2vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.wait(60)

    verify_vtep_state(nodes)
    ## Run Traffic: Bi-directional Ping and Burst of 1000 Packets
    run_traffic_test(nodes)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l2vni_vtep_delete_add (setup_teardown_l2vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.wait(60)

    verify_vtep_state(nodes)
    #run_traffic_test(nodes)

    test_node = 'leaf0'
    config_static(test_node, 'bgp', add=False)
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    config_static(test_node, 'bgp', add=True)
    st.wait(10)

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.201'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.200'), skip_tmpl=True, skip_error_check=True)

    st.wait(30)

    verify_vtep_state(nodes)
    #run_traffic_test(nodes)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D3P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D4P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

def clear_counters():

    vars = st.get_testbed_vars() 
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]

    for _dut in dut_list:
       st.config(_dut, "sudo sonic-clear fdb all")
       st.config(_dut, "sudo sonic-clear rifcounters")
       st.config(_dut, "sudo sonic-clear counters")


##
## Spirent Traffic Mode:  Ping : 5 Pings between TG1<->TG2
##                        Burst: 1000 Single Burst Between TG1<->TG2
##
def traffic_allow(_mode):
    data.my_dut_list = st.get_dut_names()
 
    clear_counters()

    tg_handler = tgapi.get_handles_byname("T1D3P1", "T1D4P1")
    tg = tg_handler["tg"]

    #tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    #tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    vars = st.get_testbed_vars()
    dut_lists = [vars.D3, vars.D4]

    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()

    #tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    #tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d3_ip_addr,
    gateway=data.t1d4_ip_addr, src_mac_addr='00:0a:01:00:11:01', arp_send_req='2', enable_ping_response=1)
    st.log("INTFCONF: "+str(res))
    handle1 = res['handle']

    res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d4_ip_addr,
    gateway=data.t1d3_ip_addr, src_mac_addr='00:0a:01:00:12:01', arp_send_req='2',enable_ping_response=1)
    st.log("INTFCONF: "+str(res))
    handle2 = res['handle']
    st.wait(5)

    # Ping Between tgen1 to tgen2
    for _dut in dut_lists:
        st.wait(2)
        st.show(_dut, "sudo show mac")

    st.banner("Ping from TG1(D3) to TG2(D4)")

    ping_res1 = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=handle1,
               dst_ip=data.t1d4_ip_addr, ping_count='5', exp_count='5')
    st.wait(5)
    print(ping_res1)

    ping_res2 = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_2"], dev_handle=handle2,
               dst_ip=data.t1d3_ip_addr, ping_count='5', exp_count='5')
    st.wait(5)
    print(ping_res2)

    ## Update Ping Result for Ping Test:
    if _mode == "_ping":
      if ping_res1:
         st.log("5 Ping from TG1(D3) to TG2(D4) succeeded.")
      else:
         st.warn("5 Ping TG1(D3) to TG2(D4) failed.")
         st.log("5 Ping TG1(D3) to TG2(D4) failed.")
         st.report_fail("test_case_failed", "5 Ping TG1(D3) to TG2(D4) failed.")

      st.report_pass("test_case_passed", "5 Ping TG1(D3) to TG2(D4) Passed")

      # Ping from tgen2 to tgen1
      for _dut in dut_lists:
         st.show(_dut,"sudo show mac")
         st.wait(2)
         st.show(_dut,"sudo show mac")
      st.banner("Ping from TG1(D3) to TG2(D4)")

      if ping_res2:
         st.log("5 Ping from TG2(D4) to TG1(D3) succeeded.")
      else:
         st.warn("5 Ping TG2(D4) to TG1(D3) failed.")
         st.report_fail("test_case_failed", "5 Ping TG2(D4) to TG1(D3) failed.")

      st.report_pass("test_case_passed", "5 Ping TG2(D4) to TG1(D3) Passed")

      for _dut in dut_lists:
         st.show(_dut,"sudo show mac")
         st.wait(2)
         st.show(_dut,"sudo show mac")
      st.banner("Ping from TG2(D4) to TG1(D3)")

    ## Update Traffic Result for Burst  Test:
     
    for _dut in dut_lists:
      papi.clear_interface_counters(_dut)
      st.config(_dut, "sudo sonic-clear counters")

    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst', length_mode='fixed',
            pkts_per_burst=data.pkts_per_burst, l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps,
            emulation_src_handle=handle1, emulation_dst_handle=handle2)
    st.wait(5)

    tr2=tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst', length_mode='fixed',
            pkts_per_burst=data.pkts_per_burst, l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps,
            emulation_src_handle=handle2, emulation_dst_handle=handle1)

    st.wait(5)
    #tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst', length_mode='fixed',
    #l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle2, emulation_dst_handle=handle1)

    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')

    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    st.log("TRAFCONF - TR1: " + str(tr1) + " TR2: " + str(tr2))
    for _dut in dut_lists:
      papi.clear_interface_counters(_dut)
      st.config(_dut, "sudo sonic-clear counters")
      st.wait(1)

    t_run1=tg1.tg_traffic_control(action='run', port_handle=tg_ph_1)
    t_run2=tg2.tg_traffic_control(action='run', port_handle=tg_ph_2)
    st.wait(data.traffic_run_time)

    st.log("TR_CTRL: " + str(t_run1) + " t run2 " + str(t_run2))
    #st.log("Checking the stats and verifying the traffic flow")

    tg1.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='stop', port_handle=tg_ph_2)

    st.wait(5)
    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')

    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
    total_tg1_tx = stats_tg1[tg_ph_1]['aggregate']['tx']['total_pkts']
    total_tg1_rx = stats_tg1[tg_ph_1]['aggregate']['rx']['total_pkts']

    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
    total_tg2_tx = stats_tg2[tg_ph_2]['aggregate']['tx']['total_pkts']
    total_tg2_rx = stats_tg2[tg_ph_2]['aggregate']['rx']['total_pkts']

    st.log("Tgen Sent Packets on D3T1P1: {} and Received Packets on D4T1P1: {}".format(total_tg1_tx, total_tg2_rx))
    st.log("Tgen Sent Packets on D4T1P1: {} and Received Packets on D3T1P1: {}".format(total_tg2_tx, total_tg1_rx))

    st.banner("Tgen Sent Packets on D3T1P1: {} and Received Packets on D4T1P1: {}".format(total_tg1_tx, total_tg2_rx))
    st.banner("Tgen Sent Packets on D4T1P1: {} and Received Packets on D3T1P1: {}".format(total_tg2_tx, total_tg1_rx))

    if _mode == "_burst":
      if (int(total_tg1_tx) == 0) | (int(total_tg2_tx) == 0):
        st.log("Traffic Validation Failed")
        st.report_fail("test_case_failed", "Single Burst of 1000 Packets Test  Failed")
      elif (abs(int(total_tg1_tx)-int(total_tg2_rx)) > data.tgen_stats_threshold):
        st.log("Traffic Validation Failed")
        #st.report_fail("test_case_failed")
        st.report_fail("test_case_failed", "Single Burst of 1000 Packets Test  Failed")
      elif (abs(int(total_tg2_tx)-int(total_tg1_rx)) > data.tgen_stats_threshold):
        st.log("Traffic Validation Failed")
        #st.report_fail("test_case_failed")
        st.report_fail("test_case_failed", "Single Burst of 1000 Packets Test  Failed")


      #Getting interfaces counter values on DUT
      DUT_rx_value = papi.get_interface_counters(vars.D3, vars.D3T1P1, "rx_ok")
      DUT_tx_value = papi.get_interface_counters(vars.D4, vars.D4T1P1, "tx_ok")

      for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

      for i in DUT_tx_value:
        p2_txmt = i['tx_ok']
        p2_txmt = p2_txmt.replace(",","")

      st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))
      st.banner("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))

      st.report_pass("test_case_passed",  "Single Burst of 1000 Packets Test Passed")

## Spirent Traffic : Bi-Directional Ping and Burst of 1000 Packets
def run_traffic_test (nodes):

    # ping test
    traffic_allow("_ping") 
    st.wait(1)

    # traffic test
    traffic_allow("_burst") 
    st.wait(1)

    # BUM test
    #st.wait(1)
    #report_fail(nodes['leaf0'], msg='Traffic test failed')
