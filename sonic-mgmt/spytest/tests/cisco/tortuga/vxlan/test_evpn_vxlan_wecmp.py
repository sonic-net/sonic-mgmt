import re
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as interface_obj
import vxlan_utils as vxlan_obj
import tortuga_common_utils as common_obj
import time

## config: eBGP + W-ECMP
##  Topology : 2x Spine + 2 Leafs
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4

## tgen Stream Config
data = SpyTestDict()
data.config_vrfs = []
CONFIGS_FILE = 'wecmp_cfg.yaml'
LEAF0_VTEP_IP = '2.2.2.2'
LEAF1_VTEP_IP = '3.3.3.3'

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "continuous"
        data.pkts_per_burst = "1000"
        data.rate_percent = "0.005"
        data.frame_size = "200"
        data.tgen_rate_pps = '200'
    else:
        data.mode ="create"
        data.transmit_mode = "continuous"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.frame_size = "1000"
    yield

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

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

def test_v4_evpn_vxlan_ucmp():
    st.banner("Start to test load balancing with EVPN VXLAN config with IPv4 traffic")
    time.sleep(60) #sleep 60 sec for config to load
    get_cli_out()

    data.d3t1_ip_addr = "60.60.60.1"    #gateway
    data.t1d3_ip_addr = "60.60.60.2"  #source ip
    data.t1d3_mac_addr = "00:11:01:00:00:01" 

    data.d4t1_ip_addr = "70.70.70.1" #gateway
    data.t1d4_ip_addr = "70.70.70.2" #source ip
    data.t1d4_mac_addr = "00:12:01:00:00:01"
    
    #setup traffic
    data.circuit_endpoint_type = "ipv4"
    vars = st.get_testbed_vars()
    int_dict = {"T1D3P1": {"host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"T1D4P1": {"host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict, "ipv4")
    stream_list = {"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }}
    
    vxlan_obj.create_udp_traffic_stream(handles, data, stream_list,timeout=30)
    src_port = stream_list['src_endpoint']['port']
    dst_port = stream_list['dst_endpoint']['port']
    receive = handles[src_port]["tg_handle"].tg_traffic_config(mode='create', transmit_mode=data.transmit_mode,pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent,circuit_endpoint_type=data.circuit_endpoint_type,frame_size=data.frame_size,emulation_src_handle=handles[src_port]["int_handle"],emulation_dst_handle=handles[dst_port]["int_handle"],track_by = 'trackingenabled0',l4_protocol='udp',udp_dst_port_mode='incr',udp_dst_port_count=1000,udp_dst_port_step=1,udp_src_port_mode='incr',udp_src_port_count=1000,udp_src_port_step=10)
    stream_id = receive["stream_id"]

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    #check for oper_up status
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VTEP_IP,"LEAF1_VXLAN_IP":LEAF1_VTEP_IP})

    st.config(vars.D3, "sonic-clear counters")
    vxlan_obj.send_udp_traffic(handles, data, stream_list, stream_id, timeout=680)
    counter_info = st.config(vars.D3, "show int counters")
    route_info = st.config(vars.D3, "ip route show")
 
    rx_pkts = get_rx(counter_info)
    tx_pkts = get_tx(counter_info)
    weight_dict = get_weights(route_info,LEAF1_VTEP_IP)
    pkts_received = rx_pkts["ingress_rx_ok"]
    load_balance = check_load_balancing(weight_dict,tx_pkts,pkts_received)

    st.log("Received ingress RX_OK packets")
    st.log(rx_pkts)
    st.log("Received egress TX_OK packets")
    st.log(tx_pkts)

    if load_balance:
        st.report_pass("test_case_passed", "EVPN fabric wecmp load-balancing for IPv4 traffic passed")
    else:
        st.report_fail("test_case_failed", "EVPN fabric wecmp load-balancing for IPv4 traffic failed") 

def test_v6_evpn_vxlan_ucmp():
    st.banner("Start to test load balancing with EVPN VXLAN config with IPv6 traffic")
    time.sleep(60) #sleep 60 sec for config to load
    get_cli_out()

    data.circuit_endpoint_type = "ipv6"
    data.d3t1_ip_addr = "6000::1"    #gateway
    data.t1d3_ip_addr = "6000::2"  #source ip
    data.t1d3_mac_addr = "00:11:01:00:00:01" 

    data.d4t1_ip_addr = "7000::1" #gateway
    data.t1d4_ip_addr = "7000::2" #source ip
    data.t1d4_mac_addr = "00:12:01:00:00:01"

    #setup traffic
    vars = st.get_testbed_vars()
    int_dict = {"T1D3P1": {"host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"T1D4P1": {"host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict, "ipv6")
    stream_list = {"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }}
    
    vxlan_obj.create_udp_traffic_stream(handles, data, stream_list,timeout=30)
    src_port = stream_list['src_endpoint']['port']
    dst_port = stream_list['dst_endpoint']['port']
    receive = handles[src_port]["tg_handle"].tg_traffic_config(mode='create', transmit_mode=data.transmit_mode,pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent,circuit_endpoint_type=data.circuit_endpoint_type,frame_size=data.frame_size,emulation_src_handle=handles[src_port]["int_handle"],emulation_dst_handle=handles[dst_port]["int_handle"],track_by = 'trackingenabled0',l4_protocol='udp',udp_dst_port_mode='incr',udp_dst_port_count=1000,udp_dst_port_step=1,udp_src_port_mode='incr',udp_src_port_count=1000,udp_src_port_step=10)
    stream_id = receive["stream_id"]

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    st.config(vars.D3, "sonic-clear counters")
    vxlan_obj.send_udp_traffic(handles, data, stream_list, stream_id, timeout=680)
    counter_info = st.config(vars.D3, "show int counters")
    route_info = st.config(vars.D3, "ip -6 route show")
    rx_pkts = get_rx(counter_info)
    tx_pkts = get_tx(counter_info)
    weight_dict = get_weights(route_info,"3333::3")
    pkts_received = rx_pkts["ingress_rx_ok"]
    load_balance = check_load_balancing(weight_dict,tx_pkts,pkts_received)
    st.log("Received ingress RX_OK packets")
    st.log(rx_pkts)
    st.log("Received egress TX_OK packets")
    st.log(tx_pkts)

    if load_balance:
        st.report_pass("test_case_passed", "EVPN fabric wecmp load-balancing for IPv6 traffic passed")
    else:
        st.report_fail("test_case_failed", "EVPN fabric wecmp load-balancing for IPv6 traffic failed") 

def test_v4_lb_link_down():
    st.banner("check load balancing for IPv4 traffic with one link from leaf1 to spine0")

    time.sleep(60) #sleep 60 sec for config to load
    data.d3t1_ip_addr = "60.60.60.1"    #gateway
    data.t1d3_ip_addr = "60.60.60.2"  #source ip
    data.t1d3_mac_addr = "00:11:01:00:00:01" 

    data.d4t1_ip_addr = "70.70.70.1" #gateway
    data.t1d4_ip_addr = "70.70.70.2" #source ip
    data.t1d4_mac_addr = "00:12:01:00:00:01"

    #setup traffic
    data.circuit_endpoint_type = "ipv4"
    vars = st.get_testbed_vars()
    int_dict = {"T1D3P1": {"host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"T1D4P1": {"host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict, "ipv4")
    stream_list = {"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }}
    
    vxlan_obj.create_udp_traffic_stream(handles, data, stream_list,timeout=30)
    src_port = stream_list['src_endpoint']['port']
    dst_port = stream_list['dst_endpoint']['port']
    receive = handles[src_port]["tg_handle"].tg_traffic_config(mode='create', transmit_mode=data.transmit_mode,pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent,circuit_endpoint_type=data.circuit_endpoint_type,frame_size=data.frame_size,emulation_src_handle=handles[src_port]["int_handle"],emulation_dst_handle=handles[dst_port]["int_handle"],track_by = 'trackingenabled0',l4_protocol='udp',udp_dst_port_mode='incr',udp_dst_port_count=1000,udp_dst_port_step=1,udp_src_port_mode='incr',udp_src_port_count=1000,udp_src_port_step=10)
    stream_id = receive["stream_id"]

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    interface_obj.interface_shutdown(vars.D4, vars.D4D1P1, skip_verify=False)
    get_cli_out()

    #check for oper_up status
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VTEP_IP,"LEAF1_VXLAN_IP":LEAF1_VTEP_IP})
    
    st.config(vars.D3, "sonic-clear counters")
    vxlan_obj.send_udp_traffic(handles, data, stream_list, stream_id, timeout=680)
    counter_info = st.config(vars.D3, "show int counters")
    route_info = st.config(vars.D3, "ip route show")
 
    rx_pkts = get_rx(counter_info)
    tx_pkts = get_tx(counter_info)
    weight_dict = get_weights(route_info,LEAF1_VTEP_IP)
    pkts_received = rx_pkts["ingress_rx_ok"]
    load_balance = check_load_balancing(weight_dict,tx_pkts,pkts_received)

    st.log("Received ingress RX_OK packets")
    st.log(rx_pkts)
    st.log("Received egress TX_OK packets")
    st.log(tx_pkts)

    interface_obj.interface_noshutdown(vars.D4, vars.D4D1P1, skip_verify=False)

    if load_balance:
        st.report_pass("test_case_passed", "EVPN fabric wecmp link-down load-balancing for IPv4 traffic passed")
    else:
        st.report_fail("test_case_failed", "EVPN fabric wecmp link-down load-balancing for IPv4 traffic failed")

    

def test_v6_lb_link_down():
    st.banner("check load balancing for IPv6 traffic with one link from leaf1 to spine0")

    time.sleep(60) #sleep 60 sec for config to load

    data.circuit_endpoint_type = "ipv6"
    data.d3t1_ip_addr = "6000::1"    #gateway
    data.t1d3_ip_addr = "6000::2"  #source ip
    data.t1d3_mac_addr = "00:11:01:00:00:01" 

    data.d4t1_ip_addr = "7000::1" #gateway
    data.t1d4_ip_addr = "7000::2" #source ip
    data.t1d4_mac_addr = "00:12:01:00:00:01"

    #setup traffic
    vars = st.get_testbed_vars()
    int_dict = {"T1D3P1": {"host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"T1D4P1": {"host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict, "ipv6")
    stream_list = {"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },"dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }}
    
    vxlan_obj.create_udp_traffic_stream(handles, data, stream_list,timeout=30)
    src_port = stream_list['src_endpoint']['port']
    dst_port = stream_list['dst_endpoint']['port']
    receive = handles[src_port]["tg_handle"].tg_traffic_config(mode='create', transmit_mode=data.transmit_mode,pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent,circuit_endpoint_type=data.circuit_endpoint_type,frame_size=data.frame_size,emulation_src_handle=handles[src_port]["int_handle"],emulation_dst_handle=handles[dst_port]["int_handle"],track_by = 'trackingenabled0',l4_protocol='udp',udp_dst_port_mode='incr',udp_dst_port_count=1000,udp_dst_port_step=1,udp_src_port_mode='incr',udp_src_port_count=1000,udp_src_port_step=10)
    stream_id = receive["stream_id"]

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    interface_obj.interface_shutdown(vars.D4, vars.D4D1P1, skip_verify=False)
    get_cli_out()

    st.config(vars.D3, "sonic-clear counters")
    vxlan_obj.send_udp_traffic(handles, data, stream_list, stream_id, timeout=680)
    counter_info = st.config(vars.D3, "show int counters")
    route_info = st.config(vars.D3, "ip -6 route show")
    rx_pkts = get_rx(counter_info)
    tx_pkts = get_tx(counter_info)
    weight_dict = get_weights(route_info,"3333::3")
    pkts_received = rx_pkts["ingress_rx_ok"]
    load_balance = check_load_balancing(weight_dict,tx_pkts,pkts_received)
    st.log("Received ingress RX_OK packets")
    st.log(rx_pkts)
    st.log("Received egress TX_OK packets")
    st.log(tx_pkts)
    
    interface_obj.interface_noshutdown(vars.D4, vars.D4D1P1, skip_verify=False)

    if load_balance:
        st.report_pass("test_case_passed", "EVPN fabric wecmp link-down load-balancing for IPv6 traffic passed")
    else:
        st.report_fail("test_case_failed", "EVPN fabric wecmp link-down load-balancing for IPv6 traffic failed") 


#HELPER FUNCTIONS

def isclose(a, b, rel_tol=0.01):
    a = round(float(a), 2)
    b = round(float(b), 2)
    return abs(a - b) <= rel_tol * max(abs(a), abs(b))

def check_load_balancing(weight_dict, pkts_dict, pkts_received):
    matched = False
    checkAll = True
    for interface, weight in weight_dict.items():
        for entry in pkts_dict['forwarding_interfaces']:
            if entry['interface'] == interface:
                tx_ok = entry['egress_tx_ok']
                percentage = (float(tx_ok) / pkts_received) * 100
                if isclose(weight, percentage, rel_tol=0.15): #allow 15% deviation to account for traffic coming in naturally
                    matched = True
                else:
                    checkAll = False           
        if not checkAll:
            return False
    return matched

def get_rx(counters): #helper function to get ingress packets amount
    result = {
        'ingress_interface': None,
        'ingress_rx_ok': 0,
    }

    for line in counters.splitlines():
        match = re.match(
            r'\s*(Ethernet\S+)\s+\S+\s+([\d,]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+([\d,]+)',
            line
        )
        if match:
            iface = match.group(1)
            rx_ok = int(match.group(2).replace(',', ''))

            if rx_ok > 3000:
                result['ingress_interface'] = iface
                result['ingress_rx_ok'] = rx_ok
    return result

def get_tx(counters): #helper function to get forwarded packets and interface 
    result = {
        "forwarding_interfaces": []
    }
    for line in counters.splitlines():
        parts = line.split()
        if len(parts) < 10 or not parts[0].startswith("Ethernet"):
            continue

        iface = parts[0]
        try:
            tx_ok_str = parts[9].replace(',', '')
            tx_ok = int(tx_ok_str)
        except (ValueError, IndexError):
            continue

        if tx_ok > 500:
            result["forwarding_interfaces"].append({
                "interface": iface,
                "egress_tx_ok": tx_ok
            })

    return result

def get_weights(routes, target_ip):
    weights = {}
    lines = routes.strip().splitlines()
    collecting = False
    route_exists = False
    for line in lines:
        line = line.strip()
        # check for the start of a new route info for given ip
        if line and not line.startswith("nexthop"):
            if line.startswith(target_ip):
                collecting = True
                route_exists = True
            else:
                collecting = False
            continue

        # collect weight info for given ip 
        if collecting and line.startswith("nexthop"):
            parts = line.split()
            try:
                iface_index = parts.index("dev") + 1
                weight_index = parts.index("weight") + 1
                iface = parts[iface_index]
                weight = int(parts[weight_index])
                weights[iface] = weight
            except (ValueError, IndexError):
                continue
    if not route_exists:
        st.report_fail("test_case_failed", "No route information found for IP {target_ip}")

    total_weight = sum(weights.values())
    result = {}

    if total_weight > 0:
        for iface, weight in weights.items():
            percentage = (float(weight) / float(total_weight)) * 100.0
            result[iface] = percentage
    else:
        st.report_fail("test_case_failed", "Total weight is 0 - no valid weights found for IP {}".format(target_ip))

    return result

def get_cli_out():
    cmds = ["show ip bgp summ", "show int counters", "ip route show","show vxlan tunnel","show vxlan remotevtep","vtysh -c 'show bgp summ'","vtysh -c 'show bgp l2vpn evpn'"]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.config(dut, item)
                st.log(output)


