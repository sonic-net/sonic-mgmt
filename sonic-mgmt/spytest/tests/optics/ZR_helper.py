import pytest
import random
from spytest import st, tgapi, SpyTestDict
import re, time,json
import apis.system.logging as logapi
import apis.routing.ip as ipapi
import apis.system.logging as logapi

class variables:
    def __init__(self):
        self.ZR_frequency = "196100"
        self.tx_power = "2"
        self.ZR_negative_frequency = "191300"

var = variables()

def var_def():
    global vars, duts, local_links_D1, local_links_D2, tg1, tg2, tg_handle_1, tg_handle_2, SESSION_KEYS, INTERFACE_KEYS
    (tg1, tg2, tg_handle_1, tg_handle_2) = get_handles()
    SESSION_KEYS = SpyTestDict()
    INTERFACE_KEYS = SpyTestDict()
    vars = st.ensure_min_topology("D1T1:1","D1D2:1","D2T1:1")
    duts = [vars.D1, vars.D2]
    local_links_D1=st.get_dut_links_local(vars.D1)
    local_links_D2=st.get_dut_links_local(vars.D2)
    
def get_asic_from_port(port):
    port = int(re.search("\d+", str(port)).group(0))
    port = port/8
    if port in range(0,12):
        asic = 0
    elif port in range(12,24):
        asic = 1
    else:
        asic = 2  
    return asic

def frequency_dom(dut,asic,port,value):
    time.sleep(120)
    output =st.show(dut, 'sonic-db-cli -n asic{} STATE_DB hgetall "TRANSCEIVER_DOM_SENSOR|{}"'.format(asic,port),skip_tmpl=True, skip_error_check=False)
    output1 = re.search(r'(.*)', output)
    output1 = output1.group(1)
    output2 = output1.replace("'","\"")
    json_data = json.loads(output2)
    op= int(float((json_data[value])))
    op= str(op)
    return op

def verify_int_stat(dut,port):
     output = st.show(dut, 'show int status | grep ' + port)
     op= re.search(r'(.*routed\s+(up)\s+(up))',output)
     if op:
          return True
     else:
          return False
def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)


    
def run_traffic(request, wait_time=15):
    var_def()
    st.log('# Configure TG Interfaces #') 
    tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])
    tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1,tg_handle_2])
    res1=tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', intf_ip_addr="100.100.100.2", gateway="100.100.100.1", src_mac_addr='00:0a:01:00:11:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res1))
    tg1_interface = res1['handle']
    res2=tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', intf_ip_addr="200.200.200.2", gateway="200.200.200.1", src_mac_addr='00:0a:01:00:11:02', arp_send_req='1')
    st.log("INTFCONF: "+str(res2))
    tg2_interface = res2['handle']
    
    #Verify traffic between D1 and T1
    iteration=0 
    while iteration<5: 
        result = ipapi.ping(vars.D1, "100.100.100.2", distributed=True)
        if not result: 
            iteration+=1 
            st.wait(15)
        else:
            break 
    else:
        return False 

    #Ping verification between D2 and T1
    iteration=0
    while iteration<5:
        result = ipapi.ping(vars.D2, "200.200.200.2", distributed=True)
        if not result:
            iteration+=1
            st.wait(15)
        else:
            break
    else:
        return False

    #Ping Verification between D1 & D2 - to resolve the ARP between LCs as IXIA doesnt have automatic arp resolution for each traffic stream
    iteration=0
    while iteration<5:
        result = ipapi.ping(vars.D1, "10.10.{}.2".format(request.config.subnet), distributed=True)
        if not result:
            iteration+=1
            st.wait(15)
        else:
            break
    else:
        return False

    tg1.tg_traffic_control(action='clear_stats', port_handle=[tg_handle_1, tg_handle_2])
    receive = tg1.tg_traffic_config(port_handle=tg_handle_1, port_handle2=tg_handle_2, mode='create', transmit_mode='continuous', circuit_endpoint_type='ipv4', frame_size='64', rate_percent=16.5, emulation_src_handle=tg1_interface, emulation_dst_handle=tg2_interface)
    tg1_stream_id = receive["stream_id"]
    tg1.tg_traffic_control(action='run', stream_handle=[tg1_stream_id])
    st.wait(wait_time)
    tg1.tg_traffic_control(action='stop', port_handle=tg_handle_1)
    st.wait(2)
    tg_tx = tgapi.get_traffic_stats(tg1, port_handle=tg_handle_1)
    tg_rx = tgapi.get_traffic_stats(tg2, port_handle=tg_handle_2)
    st.log("Received traffic: {}".format(tg_rx['rx']['total_packets']))
    st.log("Sent traffic: {}".format(tg_tx['tx']['total_packets']))
    st.log(tg_rx['rx']['total_packets']/tg_tx['tx']['total_packets'])
    if tg_rx['rx']['total_packets'] > 0.80*tg_tx['tx']['total_packets']:
        return True
    else:
        return False
