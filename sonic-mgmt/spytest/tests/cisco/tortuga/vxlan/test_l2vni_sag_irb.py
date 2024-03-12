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
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##  T1  -- SPT
##
##  SPT data0 (tp1) --- SD3 ------ SD4 --- SPT data1 (tp2)
##  SPT data2 (tp3) --- SD3 ------ SD4 --- SPT data3 (tp4)
##  tp1: SPT data0
##  tp2: SPT data1
##  tp3: SPT data2
##  tp4: SPT data3

## Spirent Stream Config
data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None

data.d3tp1_ip_addr = "100.200.200.1"
data.tp1d3_ip_addr = "100.200.200.2"
data.tp1d3_mac_addr = "00:0a:01:00:11:01"

data.d4tp2_ip_addr = "100.200.200.1"
data.tp2d4_ip_addr = "100.200.200.3"
data.tp2d4_mac_addr = "00:0a:01:00:12:01"

data.d3tp3_ip_addr = "200.200.200.1"
data.tp3d3_ip_addr = "200.200.200.2"
data.tp3d3_mac_addr = "00:0a:01:00:11:02"

data.d4tp4_ip_addr = "200.200.200.1"
data.tp4d4_ip_addr = "200.200.200.3"
data.tp4d4_mac_addr = "00:0a:01:00:12:02"

data.pkts_per_burst = "500"
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '100'
data.tgen_l3_len = '500'
data.traffic_run_time = 20
data.clear_parallel = True
## Spirent Stream Config


pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D2D3:4","D2D4:4", "D3T1:2", "D4T1:2")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield


CONFIGS_FILE = 'vxlan_l2vni_sag_irb_configs.yaml'
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
def setup_teardown_l2vni_sag():
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
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)

            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
            st.wait(2)

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    st.wait(5)
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.201'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.200'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_l2vni_sag'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)



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
            report_fail(nodes['leaf0'], msg='Unexpected tunnel type {} in leaf0'.format(path['tun_src']))
        if path['src_vtep'] != leaf0_vtep_ip:
            report_fail(nodes['leaf0'], msg='No local vtep {} found in leaf0'.format(leaf0_vtep_ip))
        if path['dst_vtep'] != leaf1_vtep_ip:
            report_fail(nodes['leaf0'], msg='Unexpected vtep {} found in leaf0'.format(path['dst_vtep']))
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
            report_fail(nodes['leaf1'], msg='Unexpected tunnel type {} in leaf1'.format(path['tun_src']))
        if path['src_vtep'] != leaf1_vtep_ip:
            report_fail(nodes['leaf1'], msg='No local vtep {} found in leaf1'.format(leaf1_vtep_ip))
        if path['dst_vtep'] != leaf0_vtep_ip:
            report_fail(nodes['leaf1'], msg='Unexpected vtep {} found in leaf1'.format(path['dst_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail(nodes['leaf1'], msg='Tunnel is not in up status in leaf1')
    if vtep_num != 1:
        report_fail(nodes['leaf1'], msg='Incorrect number of VTEPs found in leaf1')


@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_l2vni_sym_irb_sag_with_traffic(setup_teardown_l2vni_sag, traffic_setup):
    vars = st.get_testbed_vars()


    st.banner("Start to test sag with ping and traffic")
  
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.wait(60)

    verify_vtep_state(nodes)

    ## Run Traffic: Bi-directional Ping and Burst of 500 Packets
    run_traffic_test(nodes)
	
    st.warn("test_case_passed: test_l2vni_sym_irb_sag_with_traffic passed with ping and traffic!")
    st.report_pass("test_case_passed", "test_l2vni_sym_irb_sag_with_traffic passed with ping and traffic")


def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D3P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D4P1")
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D3P2")
    tg4, tg_ph_4 = tgapi.get_handle_byname("T1D4P2")
    return (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4)

def clear_counters():

    vars = st.get_testbed_vars() 
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]

    for _dut in dut_list:
       st.config(_dut, "sudo sonic-clear fdb all")
       st.config(_dut, "sudo sonic-clear rifcounters")
       st.config(_dut, "sudo sonic-clear counters")


##
## Spirent Traffic Mode:  Ping : 5 Pings between hosts
##                        Burst: 500 Single Burst Between hosts
##
@pytest.fixture(scope="function")
def traffic_setup():
    data.my_dut_list = st.get_dut_names()
 
    clear_counters()

    global h1, h2, h3, h4

    tg_handler = tgapi.get_handles_byname("T1D3P1", "T1D3P2", "T1D4P1", "T1D4P2")
    tg = tg_handler["tg"]

    vars = st.get_testbed_vars()
    dut_lists = [vars.D3, vars.D4]

    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()

    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    # This config is used to set real gw, tg_ph_1 <--> tg_ph_2 in same l2vni
    res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.tp1d3_ip_addr,
    gateway=data.d3tp1_ip_addr, src_mac_addr=data.tp1d3_mac_addr, arp_send_req='5', enable_ping_response=1)
    st.log("INTFCONF: "+str(res))
    handle1 = res['handle']

    res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.tp2d4_ip_addr,
    gateway=data.d4tp2_ip_addr, src_mac_addr=data.tp2d4_mac_addr, arp_send_req='5',enable_ping_response=1)
    st.log("INTFCONF: "+str(res))
    handle2 = res['handle']
    st.wait(5)

    # tg_ph_3 <---> tg_ph_4 in same l2vni
    res=tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr=data.tp3d3_ip_addr,
    gateway=data.d3tp3_ip_addr, src_mac_addr=data.tp3d3_mac_addr, arp_send_req='5', enable_ping_response=1)
    st.log("INTFCONF: "+str(res))
    handle3 = res['handle']

    res=tg4.tg_interface_config(port_handle=tg_ph_4, mode='config', intf_ip_addr=data.tp4d4_ip_addr,
    gateway=data.d4tp4_ip_addr, src_mac_addr=data.tp4d4_mac_addr, arp_send_req='5',enable_ping_response=1)
    st.log("INTFCONF: "+str(res))
    handle4 = res['handle']
    st.wait(5)

    h1, h2, h3, h4 = (handle1, handle2, handle3, handle4)
    yield

    st.log("Test traffic gen Fixture Cleanup.")
    tg.tg_interface_config(port_handle=tg_ph_1, handle=h1, mode='destroy')
    tg.tg_interface_config(port_handle=tg_ph_2, handle=h2, mode='destroy')
    tg.tg_interface_config(port_handle=tg_ph_3, handle=h3, mode='destroy')
    tg.tg_interface_config(port_handle=tg_ph_4, handle=h4, mode='destroy')



def get_dst_ip(host):
    if host == "T1D3P1":
        dst_ip = data.tp1d3_ip_addr		
    elif host == "T1D4P1":
        dst_ip = data.tp2d4_ip_addr
    elif host == "T1D3P2":
        dst_ip = data.tp3d3_ip_addr
    elif host == "T1D4P2":
        dst_ip = data.tp4d4_ip_addr
    else:
       st.report_fail("test_case_failed", "Wrong host name to get the port ip address!")

    return (dst_ip)

def get_dut_port(host):
    vars = st.get_testbed_vars()
    if host == "T1D3P1":
        dut = vars.D3
        port = vars.D3T1P1
    elif host == "T1D4P1":
        dut = vars.D4
        port = vars.D4T1P1
    elif host == "T1D3P2":
        dut = vars.D3
        port = vars.D3T1P2
    elif host == "T1D4P2":
        dut = vars.D4
        port = vars.D4T1P2
    else:
       st.report_fail("test_case_failed", "Wrong host name to get dut!")

    return (dut, port)


def traffic_ping(host1, host2, dev_handles):

    vars = st.get_testbed_vars()
    dut_lists = [vars.D3, vars.D4]

    # Ping Between tp1 to tp2 (host communication in same l2vni)
    for _dut in dut_lists:
        st.wait(2)
        st.show(_dut, "sudo show arp")

    st.banner("Ping from Host {} to Host {}".format(host1, host2))

    tg1, tg_ph_1 = tgapi.get_handle_byname(host1)
    tg2, tg_ph_2 = tgapi.get_handle_byname(host2)

    host1_ip = get_dst_ip(host1)
    host2_ip = get_dst_ip(host2)

    ping_res1 = tgapi.verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=dev_handles[host1],
               dst_ip=host2_ip, ping_count='5', exp_count='5')
    st.wait(5)
    print(ping_res1)

    ## Update Ping Result for Ping Test:
    if ping_res1:
       st.log("5 Ping from Host {} to Host {} succeeded.".format(host1, host2))
    else:
       st.warn("5 Ping Host {} to Host {} failed.".format(host1, host2))
       st.report_fail("test_case_failed", "5 Ping Host {} to Host {} failed.".format(host1, host2))

    for _dut in dut_lists:
       st.show(_dut,"sudo show arp")
       st.wait(2)
       st.show(_dut,"sudo show arp")

   
    st.warn("test_case_passed: 5 Ping Host {} to Host {} passed.".format(host1, host2))
    st.report_pass("test_case_passed", "5 Ping Host {} to Host {} passed.".format(host1, host2))


    # Ping from Host TP2 to Host TP1
    st.banner("Ping from Host {} to Host {}".format(host2, host1))
    ping_res2 = tgapi.verify_ping(src_obj=tg2, port_handle=tg_ph_2, dev_handle=dev_handles[host2],
               dst_ip=host1_ip, ping_count='5', exp_count='5')
    st.wait(5)
    print(ping_res2)

    if ping_res2:
       st.log("5 Ping from Host {} to Host {} succeeded.".format(host2, host1))
    else:
       st.warn("5 Ping Host {} to Host {} failed.".format(host2, host1))
       st.report_fail("test_case_failed", "5 Ping Host {} to Host {} failed.".format(host2, host1))

    for _dut in dut_lists:
       st.show(_dut,"sudo show arp")
       st.wait(2)
       st.show(_dut,"sudo show arp")

    st.warn("test_case_passed: 5 Ping Host {} to Host {} passed.".format(host2, host1))
    st.report_pass("test_case_passed", "5 Ping Host {} to Host {} passed.".format(host2, host1))
 

def traffic_burst(host1, host2, dev_handles):

    vars = st.get_testbed_vars()
    dut_lists = [vars.D3, vars.D4]

    st.banner("Test Traffic burst between {} and {}".format(host1, host2))

    tg1, tg_ph_1 = tgapi.get_handle_byname(host1)
    tg2, tg_ph_2 = tgapi.get_handle_byname(host2)

    for _dut in dut_lists:
      papi.clear_interface_counters(_dut)
      st.config(_dut, "sonic-clear counters")

    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst', length_mode='fixed',
            pkts_per_burst=data.pkts_per_burst, l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps,
            emulation_src_handle=dev_handles[host1], emulation_dst_handle=dev_handles[host2])
    st.wait(5)

    tr2=tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst', length_mode='fixed',
            pkts_per_burst=data.pkts_per_burst, l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps,
            emulation_src_handle=dev_handles[host2], emulation_dst_handle=dev_handles[host1])
    st.wait(5)


    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    st.log("TRAFCONF - TR1: " + str(tr1) + " TR2: " + str(tr2))
    for _dut in dut_lists:
      papi.clear_interface_counters(_dut)
      st.config(_dut, "sonic-clear counters")
      st.wait(1)

    t_run1=tg1.tg_traffic_control(action='run', port_handle=tg_ph_1)
    t_run2=tg2.tg_traffic_control(action='run', port_handle=tg_ph_2)
    st.wait(data.traffic_run_time)

    st.log("TR_CTRL: " + str(t_run1) + " t run2 " + str(t_run2))

    tg1.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='stop', port_handle=tg_ph_2)
    st.wait(5)

    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1, mode='aggregate')
    total_tg1_tx = stats_tg1[tg_ph_1]['aggregate']['tx']['total_pkts']
    total_tg1_rx = stats_tg1[tg_ph_1]['aggregate']['rx']['total_pkts']

    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
    total_tg2_tx = stats_tg2[tg_ph_2]['aggregate']['tx']['total_pkts']
    total_tg2_rx = stats_tg2[tg_ph_2]['aggregate']['rx']['total_pkts']

    st.log("Tgen Sent Packets on {}: {} and Received Packets on {}: {}".format(host1, total_tg1_tx, host2, total_tg2_rx))
    st.log("Tgen Sent Packets on {}: {} and Received Packets on {}: {}".format(host2, total_tg2_tx, host1, total_tg1_rx))

    if (int(total_tg1_tx) == 0) | (int(total_tg2_tx) == 0):
        st.log("Traffic Validation Failed")
        st.report_fail("test_case_failed", "Single Burst of 500 Packets Test Failed")
    elif (int(int(total_tg1_tx)-int(total_tg2_rx)) > data.tgen_stats_threshold):
        st.log("Traffic Validation Failed")
        st.report_fail("test_case_failed", "Single Burst of 500 Packets Test Failed")
    elif (int(int(total_tg2_tx)-int(total_tg1_rx)) > data.tgen_stats_threshold):
        st.log("Traffic Validation Failed")
        st.report_fail("test_case_failed", "Single Burst of 500 Packets Test Failed")


    #Getting interfaces counter values on DUT
    dut1, port1 = get_dut_port(host1)
    DUT_rx_value = papi.get_interface_counters(dut1, port1, "rx_ok")
    dut2, port2 = get_dut_port(host2)
    DUT_tx_value = papi.get_interface_counters(dut2, port2, "tx_ok")

    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    for i in DUT_tx_value:
        p2_txmt = i['tx_ok']
        p2_txmt = p2_txmt.replace(",","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))

    st.warn("test_case_passed: Single Burst of 500 Packets Test Passed between {} and {}".format(host1, host2))
    st.report_pass("test_case_passed",  "Single Burst of 500 Packets Test Passed between {} and {}".format(host1, host2))


## Spirent Traffic : Bi-Directional Ping and Burst of 500 Packets
# Hosts: ("T1D3P1", "T1D3P2", "T1D4P1", "T1D4P2"
# T1D3P1: TP1D3
# T1D3P2: TP3D3
# T1D4P1: TP2D4
# T1D4P2: TP4D4
def run_traffic_test (nodes):

    # setup
    #handleTP1D3, handleTP2D4, handleTP3D3, handleTP4D4 = traffic_setup()
    dev_handles = {}
    dev_handles["T1D3P1"] = h1 #handle of TP1D3
    dev_handles["T1D3P2"] = h3 #handle of TP3D3
    dev_handles["T1D4P1"] = h2 #handle of TP2D4
    dev_handles["T1D4P2"] = h4 #handle of TP4D4


    # Ping test between all hosts
    # T1D3P1 --- l2vni --- T1D4P1
    # T1D3P2 --- l2vni --- T1D4P2
    # T1D3P1 --- SAG + vrf + SAG ---T1D3P2
    # T1D3P1 --- SAG + L3VNI +SAG ---T1D4P2
    # T1D3P2 --- SAG + L3VNI +SAG ---T1D4P1
    traffic_ping("T1D3P1", "T1D4P1", dev_handles)
    st.wait(1)

    traffic_ping("T1D3P1", "T1D3P2", dev_handles)
    st.wait(1)

    traffic_ping("T1D3P1", "T1D4P2", dev_handles)
    st.wait(1)

    traffic_ping("T1D3P2", "T1D4P2", dev_handles)
    st.wait(1)

    traffic_ping("T1D3P2", "T1D4P1", dev_handles)
    st.wait(1)


    # traffic burst test
    # L2VNI intra-subnet traffic 
    traffic_burst("T1D3P1", "T1D4P1", dev_handles)
    st.wait(1)

    # local routing inter-subnet traffic
    traffic_burst("T1D3P1", "T1D3P2", dev_handles)
    st.wait(1)

    # l3vni routing inter-subnet traffic (cross l2vni)
    traffic_burst("T1D3P1", "T1D4P2", dev_handles)
    st.wait(1)

    # l2vin intra-subnet traffic
    traffic_burst("T1D3P2", "T1D4P2", dev_handles)
    st.wait(1)

    # l3vni routing inter-subnet traffic (cross l2vni)
    traffic_burst("T1D3P2", "T1D4P1", dev_handles)
    st.wait(1)


