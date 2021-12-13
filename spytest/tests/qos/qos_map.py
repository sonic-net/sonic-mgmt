import re
import json

from spytest import st, tgapi

import apis.qos.qos as qosapi
import apis.system.port as port
from apis.system import basic
import apis.common.asic as asicapi
import apis.system.interface as intf

from utilities.common import filter_and_select

obj_name = "AZURE"
port_qos_map = "PORT_QOS_MAP"
tc_queue_map = "TC_TO_QUEUE_MAP"
dscp_tc_map = "DSCP_TO_TC_MAP"

queue_list = ['2','5']
dscp_queue_list1 = ['UC1','UC5']
dscp_queue_list2 = ['UC2','UC4']
dscp_queue_list3 = ['UC2','UC5']
dscp_queue_list4 = ['UC5','UC2']
mqueue_list = ['MC12','MC15']
strict_pri_queue = ['UC6','UC7']
strict_dwrr_queue = ['UC4','UC5']
dwrr_queue = ['UC3','UC4']
dscp_list = ['20','46']
smac_list = ['00.00.00.00.00.01','00.00.00.00.00.03']
dmac_list = ['00.00.00.00.00.02','00.00.00.00.00.04']

rate_list = ['100','500']
exp_list1 = ['500','2500']
exp_list2 = ['2500','500']
pkts_sec = 100
rate_percent = 100
sp_ratio_1,sp_ratio_2 = 0.01, 1

vlan_id = 10
dut_ip_addr_1 = "10.10.10.1"
dut_ip_addr_2 = "20.20.20.1"
tg_ip_addr_1 = "10.10.10.2"
tg_ip_addr_2 = "20.20.20.2"
tg_ip_addr_3 = "10.10.10.3"
mask = 24

tc_to_queue_map_1 = {"0" : "0", "1" : "1", "2" : "2", "3" : "3",
                     "4" : "4", "5" : "5", "6" : "6", "7" : "7"}
tc_to_queue_map_2 = {"0" : "0", "1" : "1", "2" : "5", "3" : "3",
                     "4" : "4", "5" : "2", "6" : "6", "7" : "7"}
#tc1,qval1 = ["0","1","2","3","4","5","6","7"],["0","1","2","3","4","5","6","7"]
tc1,qval1 = ["2","5"],["2","5"]
tc2,qval2 = ["2","5"],["5","2"]


dscp_to_tc_map_1 = {"0-2,6,7,9-45,47,49-63":"1", "3":"3", "4":"4", "5":"2", "8":"0", "46":"5", "48":"6"}
dscp_to_tc_map_2 = {"0-2,6-7,9-19,21-45,47,49,51-63":"1", "3":"3", "4,46":"4", "5,20,50":"2", "8":"0", "48":"6"}
dscp_val_2,tc_val_2 = ["20","46"],["2","4"]
dscp_val_3,tc_val_3 = ["20","46"],["1","5"]

dscp_bind_port = {"dscp_to_tc_map"  : "AZURE"}

sched_0, sched_1, sched_2, sched_3 = "scheduler.0", "scheduler.1", "scheduler.2", "scheduler.3"
sched_strict = {"type"  : "STRICT", "weight": "25"}
sched_dwrr_1 = {"type"  : "DWRR", "weight": "50"}
sched_dwrr_2 = {"type"  : "DWRR", "weight": "20"}
sched_dwrr_3 = {"type"  : "DWRR", "weight": "10"}
sched_bind_0 = {"scheduler"   : "scheduler.0"}
sched_bind_1 = {"scheduler"   : "scheduler.1"}
sched_bind_2 = {"scheduler"   : "scheduler.2"}
sched_bind_3 = {"scheduler"   : "scheduler.3"}
pfc_bind = {"pfc_enable" : "2"}
wred_obj = "AZURE_LOSSLESS"
wred_profile = "WRED_PROFILE"
wred_input = {
            "wred_green_enable"      : "true",
            "wred_yellow_enable"     : "true",
            "wred_red_enable"        : "true",
            "ecn"                    : "ecn_all",
            "green_max_threshold"    : "200000",
            "green_min_threshold"    : "100000",
            "yellow_max_threshold"   : "2097152",
            "yellow_min_threshold"   : "1048576",
            "red_max_threshold"      : "2097152",
            "red_min_threshold"      : "1048576",
            "green_drop_probability" : "100",
            "yellow_drop_probability": "5",
            "red_drop_probability"   : "5"
            }
wred_bind = {"wred_profile": wred_obj}


def create_glob_vars():
    global vars, tg, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4
    global d1_p1, d1_p2, d2_p1, d2_p2, d1_d2_p1, d2_d1_p1
    vars = st.ensure_min_topology("D1T1:2","D2T1:2","D1D2:1")

    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    tg4, tg_ph_4 = tgapi.get_handle_byname("T1D2P2")
    tg = tg1; st.unused(tg2, tg3, tg4)
    d1_p1, d1_p2 = vars.D1T1P1, vars.D1T1P2
    d2_p1, d2_p2 = vars.D2T1P1, vars.D2T1P2
    d1_d2_p1, d2_d1_p1 = vars.D1D2P1, vars.D2D1P1

def create_stream(handle,type,vlan='10',pcp='1',rate='100',dscp='1',
                  src_mac='00.00.00.00.00.01',dst_mac='00.00.00.00.00.02',
                  src_ip=tg_ip_addr_1,dst_ip=tg_ip_addr_2):

    if type=='l2':
        tg.tg_traffic_config(mac_src = src_mac, mac_dst=dst_mac, rate_pps=rate, mode='create',
            port_handle=handle,l2_encap='ethernet_ii_vlan', vlan_id=vlan, vlan_user_priority= pcp,
            duration='5', transmit_mode='continuous')
    elif type=='l3':
        d1_tg_p1_mac = basic.get_ifconfig(vars.D1, d1_p1)[0]['mac']
        tg.tg_traffic_config(port_handle=handle, mac_src = src_mac, mac_dst=d1_tg_p1_mac,
            rate_pps=rate, mode='create', l2_encap='ethernet_ii', duration='5',ip_src_addr= src_ip,
            ip_dst_addr=dst_ip, l3_protocol= 'ipv4', ip_dscp=dscp,l3_length='512',
            mac_discovery_gw=dut_ip_addr_1, transmit_mode='continuous')
    elif type == 'copp_arp':
        tg.tg_traffic_config(port_handle=handle, mac_src=src_mac, mac_dst="ff:ff:ff:ff:ff:ff",
            rate_pps=rate,mode='create',l2_encap='ethernet_ii', transmit_mode='continuous',
            l3_protocol= 'arp',arp_src_hw_addr=src_mac,arp_dst_hw_addr="00:00:00:00:00:00",
            arp_operation='arpRequest',ip_src_addr=tg_ip_addr_1,ip_dst_addr=tg_ip_addr_2)
    elif type == 'wred':
        tg.tg_traffic_config(mac_src=src_mac, mac_dst=dst_mac, rate_percent=rate_percent,
            mode='create', port_handle=handle, l2_encap='ethernet_ii_vlan', vlan_id=vlan,
            vlan_user_priority=pcp, transmit_mode='continuous')
    else:
        tg.tg_traffic_config(mac_src = src_mac, mac_dst=dst_mac, rate_percent=rate_percent,
            mode='create', port_handle=handle,l2_encap='ethernet_ii_vlan', vlan_id=vlan,
            vlan_user_priority=pcp, transmit_mode='continuous',duration='5')


def verify_traffic(field,type='l2'):
    global sp_ratio_1, sp_ratio_2

    if type == 'l2' or type == 'l3':
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D1P1],
                'tx_obj': [tg],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P2],
                'rx_obj': [tg],
            },
        }
    else:
        if type == 'dwrr_scheduling':
            sp_ratio_1, sp_ratio_2 = 0.3, 0.7
        elif type == 'sp_dwrr_scheduling':
            sp_ratio_1, sp_ratio_2 = 0.008, 1
        else:
            sp_ratio_1, sp_ratio_2 = 0.015, 1
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D1P1],
                'tx_obj': [tg],
                'exp_ratio': [sp_ratio_1],
                'rx_ports': [vars.T1D2P1],
                'rx_obj': [tg],
                'tolerance_factor' : '3'
            },
            '2': {
                'tx_ports': [vars.T1D1P2],
                'tx_obj': [tg],
                'exp_ratio': [sp_ratio_2],
                'rx_ports': [vars.T1D2P2],
                'rx_obj': [tg],
                'tolerance_factor': '2'
            },
        }

    return tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type=field)


def verify_queue_traffic_and_counter(field, qname_list, rate_list, val_list, type='l2'):
    result1,result2 = True, True

    qosapi.clear_qos_queue_counters(vars.D1)
    if type == 'l2' or type == 'l3':
        tg.tg_traffic_control(action='run', port_handle=[tg_ph_1, tg_ph_2], duration='5')
    elif type == 'wred':
        tg.tg_traffic_control(action='run', port_handle=[tg_ph_1,tg_ph_2,tg_ph_3,tg_ph_4])
    else:
        tg.tg_traffic_control(action='run', port_handle=[tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4],
                              duration='5')
    st.wait(5)

    if not verify_traffic(field,type):
        st.log('traffic verification failed')
        result1 = False
    else:
        st.log('traffic verification passed')

    if type == 'l2' or type == 'l3':
        for queue,val,tol in zip(qname_list,val_list,rate_list):
            if not qosapi.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name=queue,
                    param_list=['pkts_count'], val_list=[val], tol_list=[tol]):
                st.log('qos queue counter verification failed')
                result2 = False
            else:
                st.log('qos queue counter verification passed')
    elif type == 'wred':
        result2 = verify_wred_drop(queue=qname_list, port=d1_d2_p1)
    else:
        result2 = verify_queue_drop(queue_list=qname_list, port=d1_d2_p1)

    return bool(result1 and result2)

def verify_wred_drop(port,queue):
    success = True
    asicapi.dump_counters(vars.D1)
    return success

def verify_queue_drop(queue_list,port):
    global pkts_sec, sp_ratio_1
    success = True

    cli_out = intf.show_queue_counters(vars.D1, port)
    fil_out1 = filter_and_select(cli_out, ['pkts_drop'], {"txq": queue_list[0]})
    fil_out2 = filter_and_select(cli_out, ['pkts_drop'], {"txq": queue_list[1]})
    if not fil_out1:
        st.error('queue name: {} not found in output: {}'.format(queue_list[0], cli_out))
        return False
    else:
        fil_out1 = fil_out1[0]

    if not fil_out2:
        st.error('queue name: {} not found in output: {}'.format(queue_list[1], cli_out))
        return False
    else:
        fil_out2 = fil_out2[0]

    try:
        fil_out1['pkts_drop'] = re.sub(",", "", fil_out1['pkts_drop'])
        fil_out2['pkts_drop'] = re.sub(",", "", fil_out2['pkts_drop'])
        q1_drop, q2_drop = int(fil_out1['pkts_drop']), int(fil_out2['pkts_drop'])
    except ValueError:
        st.error('cannot get integer value from obtained '
                 'string: {} or {}'.format(fil_out1['pkts_drop'],fil_out2['pkts_drop']))
        return False

    if q1_drop > q2_drop and q1_drop > (pkts_sec * sp_ratio_1):
        st.log('queue {} drop {} is more than queue {} drop {} as expected'.format(queue_list[0],
                    q1_drop, queue_list[1], q2_drop))
    else:
        st.error('queue {} drop {} is not more than queue {} drop {}'.format(queue_list[0],
                    q1_drop, queue_list[1], q2_drop))
        success = False
    return success


def clear_tgen_stats(flag,type='l2'):
    if flag=='start':
        create_glob_vars()
        action_list = ['reset']
    else:
        #send flag option as 'end'
        action_list = ['stop','reset']

    for action in action_list:
        if type == 'scheduling':
            tg.tg_traffic_control(action=action, port_handle=[tg_ph_1, tg_ph_2,
                tg_ph_3, tg_ph_4])
        else:
            tg.tg_traffic_control(action=action, port_handle=[tg_ph_1,tg_ph_2])

def check_port_speed(dut,in_port1,in_port2,out_port):
    global rate_percent, sp_ratio_1, sp_ratio_2, pkts_sec

    in_speed1 = port.get_status(dut, in_port1)[0]['speed']
    in_speed1 = get_speed(in_speed1)
    in_speed2 = port.get_status(dut, in_port2)[0]['speed']
    in_speed2 = get_speed(in_speed2)
    if in_speed1 != in_speed2:
        st.error('ingress port1 {} speed {} and port2 {} speed {} are not same,'
                 'skip the testcase'.format(in_port1,in_speed1,in_port2,in_speed2))
        return False

    eg_speed = port.get_status(dut, out_port)[0]['speed']
    eg_speed = get_speed(eg_speed)

    if in_speed1 >= eg_speed and in_speed1 / eg_speed == 1:
        rate_percent = 100
    elif in_speed1 >= eg_speed and in_speed1 / eg_speed == 2:
        rate_percent = 40
    elif in_speed1 >= eg_speed and in_speed1 / eg_speed ==4:
        rate_percent = 20
    elif in_speed1 >= eg_speed and in_speed1 / eg_speed == 10:
        rate_percent = 10


    pkts_sec = in_speed1 / 1024
    in_speed = in_speed1 + in_speed2
    if in_speed / eg_speed  > 1:
        st.log("egress speed: {} less than ingress speed: {}, congestion criteria met"
               .format(eg_speed, in_speed))
        return True
    else:
        st.log("egress speed: {} higher than ingress speed: {}, congestion criteria not met"
               .format(eg_speed, in_speed))
        return False

def get_speed(speed):
    if "G" in speed:
        return int(re.sub('G', '000000', speed))

def create_copp_json(dut, block_name, dict_input):

    temp_data = { block_name : dict_input, "OP" : "SET"}
    temp_data = [temp_data]
    final_data = json.dumps(temp_data)
    return st.apply_json(dut, final_data)


def verify_counter_cpu_asic_bcm(dut,queue,value,tol):
    queue_mc = queue
    nooftimes = 3
    queue = 'PERQ_PKT(' + queue + ').cpu0'
    queue_mc = 'MC_PERQ_PKT(' + queue_mc + ').cpu0'
    for itercountvar in range(nooftimes):
        if itercountvar != 0:
            st.wait(5)
        cli_out = asicapi.get_counters(dut)
        fil_out = filter_and_select(cli_out, ["time"], {"key": queue})
        if not fil_out:
            fil_out = filter_and_select(cli_out, ["time"], {"key": queue_mc})
        if not fil_out:
            st.error('queue: {} not found in output: {}'.format(queue, cli_out))
            if itercountvar < (nooftimes - 1):
                continue
            return False
        else:
            if not fil_out[0]['time']:
                st.error('queue: {} value is null in the output: {}'.format(queue, fil_out))
                if itercountvar < (nooftimes - 1):
                    asicapi.clear_counters(dut)
                    continue
                return False
            fil_out = fil_out[0]

        if not fil_out['time']:
            st.error('queue: {} value is null in the output: {}'.format(queue, cli_out))
            if itercountvar < (nooftimes - 1):
                continue
            return False

        fil_out['time'] = re.sub(r'|'.join((',', '/s')), "", fil_out['time'])
        ob_value = int(fil_out['time'])
        start_value = int(value) - int(tol)
        end_value = int(value) + int(tol)
        if ob_value >= start_value and ob_value <= end_value:
            st.log('obtained value {} for queue: {} is in the range b/w '
                   '{} and {}'.format(ob_value,queue,start_value,end_value))
            return True
        else:
            st.error('obtained value {} for queue: {} is NOT in the range b/w '
                     '{} and {}'.format(ob_value, queue, start_value, end_value))
            if itercountvar < (nooftimes - 1):
                asicapi.clear_counters(dut)
                continue
            return False


def verify_copp_arp_asic_bcm(dut,queue,value,tol,rate='100'):
    create_stream(type='copp_arp',handle=tg_ph_1,rate=rate)
    st.log("send ARP request and verify cpu counter")
    tg.tg_traffic_control(action='run', port_handle=[tg_ph_1])
    st.wait(5)
    return verify_counter_cpu_asic_bcm(dut,queue,value,tol)


def verify_pfc_counters(dut,port_mode,port,queue):
    st.log('verify pfc counters')
    return True


def get_counter_cpu(dut,queue,value='diff'):
    cli_out = asicapi.get_counters(dut)
    queue = 'PERQ_PKT(' + queue + ').cpu0'
    fil_out = filter_and_select(cli_out, [value], {"key": queue})
    if not fil_out:
        st.error('queue: {} not found in output: {}'.format(queue, cli_out))
        return False
    else:
        fil_out = fil_out[0]

    fil_out[value] = re.sub(r"\+", "", fil_out[value])
    return fil_out[value]

