import pytest
import random
from spytest import st, tgapi, SpyTestDict
import re, time
import apis.system.logging as logapi
import apis.routing.ip as ipapi
import apis.system.logging as logapi
#import tests.system.test_optics_v4.config_traffic_bgp as config_traffic_bgp

class variables:
    def __init__(self):
        self.MACSEC_PROFILE= {"aes_128": "GCM-AES-128", "aes_256": "GCM-AES-256", "aes_xpn_128":"GCM-AES-XPN-128", "aes_xpn_256":"GCM-AES-XPN-256"}
        self.MACSEC_REGEX = "ACL direction: .* Init macsec called for Ethernet{}\|MACSEC init config successful for .* port {}\|Config enable: idx: {} lane: .* mode:.*\|Configured default Policy on SecY for softPort: {}\|0x888E Egress rule add success for port {}\|\
0x888E Ingress rule add success for port {}\|0x876F Egress rule add success for port {}\|0x876F Ingress rule add success for port {}\|Macsec config enable is success and added rule to classify the packets to control for port: {}\|\TX SA.*install on port_oid.*, pd_port: {}\|RX SA.*install on port_oid.*, pd_port: {}"

var = variables()

def var_def():
    global vars, duts, local_links_D1, local_links_D2, tg1, tg2, tg_handle_1, tg_handle_2, SESSION_KEYS, INTERFACE_KEYS
    (tg1, tg2, tg_handle_1, tg_handle_2) = get_handles()
    SESSION_KEYS = SpyTestDict()
    INTERFACE_KEYS = SpyTestDict()
    vars = st.ensure_min_topology("D1T1:1","D1D2:2","D2T1:1")
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


def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)


def enable_macsec_feature(dut):
    st.config(dut, "config feature state macsec enabled")
    output = st.config(dut, "show feature status | grep macsec", skip_tmpl=True, skip_error_check=False)
    if re.search("enabled\s+enabled", output):
        st.banner("--------Macsec enabled on {}------".format(dut))
        return True
    else:
        st.error("Failed to enable macsec feature on {}".format(dut))
        return False



def apply_profile(duts, ports, profile, policy, replay_window="0", send_sci="1", is_lag= False, mismatch = False):
    try:
        for dut in duts:
            count = 0
            for port in ports[dut]:
                asic = get_asic_from_port(port) if is_lag is False else 0
                if count == 0:
                    if re.search("\d+", str(profile)).group(0) == '256':
                        primary_cak = "08711D1C5A4D5041455355250808000D156573415442565701010172762D273D30090905000600025C035F267A74203620540A59555B741A1951402435312F2922"
                    else:
                        primary_cak = "01435756085F5359761417283B2633372D5C557878707D65627A4A26342025737F"
                    st.config(dut, 'sudo config macsec -n asic{} profile add {} --priority 64 --cipher_suite "{}" --primary_cak {} --primary_ckn "6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435" --replay_window {} --rekey_period 30 --send_sci\
                '.format(asic, profile, var.MACSEC_PROFILE[profile], primary_cak, replay_window), skip_tmpl=True, skip_error_check=False)
                count+=1
                st.banner("--------Applying macsec profile on {} {}------".format(dut, port))
                st.config(dut, "sonic-db-cli -n asic{} CONFIG_DB HSET 'PORT|{}' 'macsec' '{}'".format(asic, port, profile), skip_tmpl=True, skip_error_check=False)
    except Exception as e:
        st.error("Error occured while applying the profile: {}".format(e))

def check_syslog(dut, port, syslog_regex):
    '''Get the port number from given interface name.
    For eg: Ethernet2 = 2*8 = 16 ; Ethernet16 = 16*8 = 128'''
    port_num = int(re.search("\d+", str(port)).group(0))
    port_8 = port_num/8 
    line = syslog_regex.format(port_8, port_8, port_num, port_num, port_num, port_num, port_num, port_num, port_num, port_8, port_8)
    if len(logapi.show_logging(dut, filter_list= [line]))<11:
        st.error("Failed to find syslogs on {} for {}".format(dut, port))
        return False
    return True

def is_container_running(dut, container_name, asic):
    """
    @summary: Decide whether the container is running or not
    @return:  Boolean value. True represents the container is running
    """
    result = st.show(dut, "docker ps | grep -w {}{}".format(container_name, asic))
    return len(result) == 1

    
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

def restart_container(dut, container_name, asic):
    cmd = "docker restart {}{}".format(container_name, asic)
    result = st.config(dut, cmd)
    st.log("result for docker restart {} is {}".format(cmd, result))
    st.wait(300)

def process_status(dut, container_name, asic, prs_name):
    cmd = "sudo docker exec {}{} supervisorctl status {}".format(container_name, asic,prs_name)
    output = st.config(dut, cmd)
    if re.search("\S+\s+RUNNING", output):
        st.log("the process {} is running in the container {}".format(prs_name, container_name))
        return True
    else:
        st.log("the process {} is not running in the container {}".format(prs_name, container_name))
        return False

def crash_process(dut, container_name, asic, prs_name):
    cmd = "sudo docker exec -i {}{} pkill -9 {}".format(container_name, asic, prs_name)
    result = st.config(dut, cmd)
    st.log("result for process restart {} is {}".format(cmd, result))
    st.wait(300)

def config_portchannel():
    var_def()
    for dut in duts: 
        st.config(dut, "sudo config portchannel -n asic0 add --min-links 2 PortChannel24")
        st.config(dut, "sudo config portchannel -n asic0 member add PortChannel24 {}".format(vars.D1D2P1))
        st.config(dut, "sudo config portchannel -n asic0 member add PortChannel24 {}".format(vars.D1D2P2))

def deconfig_portchannel():
    var_def()
    for dut in duts:
        st.config(dut, "sudo config portchannel -n asic0 member del PortChannel24 {}".format(vars.D1D2P1))
        st.config(dut, "sudo config portchannel -n asic0 member del PortChannel24 {}".format(vars.D1D2P2))
        st.config(dut, "sudo config portchannel -n asic0 del PortChannel24")
