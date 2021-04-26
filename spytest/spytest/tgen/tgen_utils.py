import re
import copy
from spytest import st, SpyTestDict
from spytest.tgen_api import get_chassis
from apis.system.basic import get_techsupport

def _log_call(fname, **kwargs):
    args_list=[]
    for key, value in kwargs.items():
        args_list.append("%s=%s" %(key, value))
    text = "{}({})\n".format(fname, ",".join(args_list))
    st.log('TGenUtil REQ: {}'.format(text.strip()))

def _validate_parameters(tr_details):

    mandatory_params = ['tx_ports','tx_obj','exp_ratio','rx_ports','rx_obj']
    for tr_pair in range(1,len(tr_details)+1):
        tr_pair = str(tr_pair)
        for param in mandatory_params:
            if tr_details[tr_pair].get(param) is None:
                st.error('{} parameter missing in traffic pair: {}'.format(param,tr_pair))
                return False
        if len(tr_details[tr_pair]['tx_ports']) != len(tr_details[tr_pair]['tx_obj']) != len(tr_details[tr_pair]['exp_ratio']):
            st.error('tx_ports, tx_obj and exp_ratio must be of same length, in traffic pair: {}'.format(tr_pair))
            return False
        if len(tr_details[tr_pair]['rx_ports']) != len(tr_details[tr_pair]['rx_obj']):
            st.error('rx_ports and rx_obj must be of length, in traffic pair: {}'.format(tr_pair))
            return False
        if tr_details[tr_pair].get('stream_list',None) != None:
            if len(tr_details[tr_pair]['tx_ports']) != len(tr_details[tr_pair]['stream_list']):
                st.error('tx_ports, stream_list must be of same length, in traffic pair: {}'.format(tr_pair))
                return False
        if tr_details[tr_pair].get('filter_param',None) != None and tr_details[tr_pair].get('stream_list',None) != None:
            if len(tr_details[tr_pair]['filter_param']) != len(tr_details[tr_pair]['stream_list']):
                st.error('stream_list and filter list must be of same length, in traffic pair: {}'.format(tr_pair))
                return False
        if tr_details[tr_pair].get('filter_val',None) != None and tr_details[tr_pair].get('filter_param',None) != None:
            if len(tr_details[tr_pair]['filter_val']) != len(tr_details[tr_pair]['filter_param']):
                st.error('filer value and filter list must be of same length, in traffic pair: {}'.format(tr_pair))
                return False
    st.debug('param validation successful')
    return True


def get_counter_name(mode,tg_type,comp_type,direction,logger=True):
    tg_type2 = "ixia" if tg_type == "scapy" else tg_type
    traffic_counters = {
        'aggregate': {
            'stc': {
                'tx': {
                    'packet_count': 'pkt_count',
                    'packet_rate': 'pkt_rate',
                    'oversize_count': 'pkt_count',
                    },
                'rx': {
                    'packet_count': 'pkt_count',
                    'packet_rate': 'pkt_rate',
                    'oversize_count': 'pkt_count',
                    },
                },
            'ixia': {
                'tx': {
                    'packet_count': 'raw_pkt_count',
                    'packet_rate': 'total_pkt_rate',
                    'oversize_count': 'raw_pkt_count',
                    },
                'rx': {
                    'packet_count': 'raw_pkt_count',
                    'packet_rate': 'raw_pkt_rate',
                    'oversize_count': 'oversize_count',
                    },
                },
            },
        'streamblock' : {
            'stc': {
                'tx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    'drop_count': 'total_pkts',
                    'drop_rate': 'total_pkt_rate',
                    },
                'rx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    'drop_count': 'dropped_pkts',
                    'drop_rate': 'dropped_pkts_percent',
                    },
                },
            'ixia': {
                'tx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    'drop_count': 'total_pkts',
                    'drop_rate': 'total_pkt_rate',
                    },
                'rx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    'drop_count': 'loss_pkts',
                    'drop_rate': 'loss_percent',
                    },
                },
            },
        'filter' : {
            'stc': {
                'tx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    },
                'rx': {
                    'packet_count': 'count',
                    'packet_rate': 'rate_pps',
                    },
                },
            'ixia': {
                'tx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    },
                'rx': {
                    'packet_count': 'total_pkts',
                    'packet_rate': 'total_pkt_rate',
                    },
                },
            }
        }

    counter_name = traffic_counters[mode][tg_type2][direction][comp_type]
    if logger:
        st.debug('TG type: {}, Comp_type: {}, Direction: {}, Counter_name: {}'.format(tg_type, comp_type, direction, counter_name))
    return counter_name


def _get_debug_dump(name='tg_stats_failed'):
    tg=get_chassis()
    get_techsupport(filename=name)
    tg.collect_diagnosic(fail_reason=name)


def _fetch_stats(obj, port, mode, comp_type, direction, stream_elem=None):
    """
    @author: Lakshminarayana D(lakshminarayana.d@broadcom.com)
    Fuction will fetch traffic stats based inputs and classify TgenFail based on stats available.
    :param obj: TG object
    :param port: Port handler
    :param mode: Mode of the stats to be fetched(Ex: streams, aggregate, traffic_items)
    :param comp_type: packet_count or packet_rate
    :param direction: Traffic direction ('tx' or 'rx')
    :param stream_elem: Stream handle need to provide when mode is streams or traffic_item
    :return: stats: A Dictionary object with tx/rx packets/bytes stats
    """

    stats_mode = 'streamblock' if mode in ['streams', 'traffic_item'] else mode
    counter_name = get_counter_name(stats_mode, obj.tg_type, comp_type, direction, logger=False)
    tx_counter = int()
    stats = dict()
    for loop in range(0, 4):
        if loop > 0:
            st.log('TG stats are not fully ready. Trying to fetch stats again.... iteration {}'.format(loop))
            st.wait(2, 'waiting before fetch stats again')
        stats = obj.tg_traffic_stats(port_handle=port, mode=mode)
        if obj.tg_type == 'stc':
            if mode == 'streams':
                tx_counter = float(stats[port]['stream'][stream_elem][direction][counter_name])
            else:
                tx_counter = int(stats[port][mode][direction][counter_name])
            if direction == 'rx' or tx_counter != 0: break
        elif obj.tg_type in ['ixia', 'scapy']:
            try:
                if mode == 'traffic_item':
                    tx_counter = float(stats[mode][stream_elem][direction][counter_name])
                else:
                    tx_counter = int(stats[port][mode][direction][counter_name])
            except Exception:
                st.error('Could not get traffic_stats from the TGEN, Please check if traffic was started')
                tx_counter = 0
            if stats.get('waiting_for_stats', '1') == '0' and (direction == 'rx' or tx_counter != 0):
                    break
    if direction == 'tx' and not tx_counter:
        (name, value) = ('stream handle', stream_elem) if stream_elem else ('port', port)
        msg = 'TX Counter {} is 0 (zero) for {}: {}'.format(counter_name, name, value)
        _get_debug_dump()
        st.warn(msg)
        st.report_tgen_fail('tgen_failed_api', msg)

    return stats

def _verify_aggregate_stats(tr_details,mode,comp_type,tolerance_factor,delay_factor,retry,return_all):

    return_value = True
    ret_all=[]
    delay = 5 * float(delay_factor)
    tolerance = 5 * float(tolerance_factor)

    st.tg_wait(delay, "aggregate_stats")

    port_stats = dict()
    for tr_pair in range(1,len(tr_details)+1):
        tr_pair = str(tr_pair)
        tx_ports = tr_details[tr_pair]['tx_ports']
        tx_obj = tr_details[tr_pair]['tx_obj']
        exp_ratio = tr_details[tr_pair]['exp_ratio']
        rx_ports = tr_details[tr_pair]['rx_ports']
        rx_obj = tr_details[tr_pair]['rx_obj']

        cmsg = 'Pair: {}, Transmit Ports: {}, Receive Ports: {}'.format(tr_pair, tx_ports, rx_ports)
        st.log('Validating Traffic, Pair: {}, Transmit Ports: {}, Receive Ports: {}'.format(tr_pair,tx_ports,rx_ports))
        retry_count = retry + 1 if not retry and comp_type == 'packet_rate' else retry
        tx_ph, rx_ph = None, None
        for loop in range(0, int(retry_count) + 1):
            if loop > 0:
                st.log('The difference is not in the given tolerance. So, retrying the stats fetch once again....{}'.format(loop))
                st.wait(2, 'waiting to before fetch stats again')
                for port in [tx_ph, rx_ph]: port_stats.pop(port, '')
            exp_val = 0
            for port,obj,ratio in zip(tx_ports,tx_obj,exp_ratio):
                tx_ph = obj.get_port_handle(port)
                # tx_stats = obj.tg_traffic_stats(port_handle=tx_ph, mode=mode)
                if tx_ph not in port_stats:
                    port_stats[tx_ph] = _fetch_stats(obj, tx_ph, mode, comp_type, 'tx')
                tx_stats = port_stats[tx_ph]
                #st.debug(tx_stats)
                counter_name = get_counter_name(mode,obj.tg_type,comp_type,'tx')
                cur_tx_val = int(tx_stats[tx_ph][mode]['tx'][counter_name])
                st.log('Transmit counter_name: {}, counter_val: {}'.format(counter_name,cur_tx_val))
                exp_val += cur_tx_val * ratio
            st.log('Total Tx from ports {}: {}'.format(tx_ports,exp_val))

            for port,obj in zip(rx_ports,rx_obj):
                rx_ph = obj.get_port_handle(port)
                # rx_stats = obj.tg_traffic_stats(port_handle=rx_ph, mode=mode)
                if rx_ph not in port_stats:
                    port_stats[rx_ph] = _fetch_stats(obj, rx_ph, mode, comp_type, 'rx')
                rx_stats = port_stats[rx_ph]
                #st.debug(rx_stats)
                counter_name = get_counter_name(mode,obj.tg_type,comp_type,'rx')
                real_rx_val = int(rx_stats[rx_ph][mode]['rx'][counter_name])
                st.log('Receive counter_name: {}, counter_val: {}'.format(counter_name,real_rx_val))

            st.log('Total Rx on ports {}: {}'.format(rx_ports, real_rx_val))

            diff = (abs(exp_val - real_rx_val) * 100.0) / exp_val if exp_val > 0 else abs(real_rx_val * 100.0 / cur_tx_val)
            if diff <= tolerance:
                st.log('Traffic Validation: {}, {}'.format('Success',cmsg))
                st.log('Got expected values; Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
                ret_all.append(True)
                break
            elif loop != retry_count:
                if not retry and comp_type == 'packet_rate' and diff > (tolerance + 5):
                    msg = 'The traffic difference is in not between {} and {}. Skipping the retry'.format(tolerance, tolerance + 5)
                    st.debug(msg)
                else:
                    st.log('Traffic Varification: {}, {}'.format('Failure', cmsg))
                    st.log('Expected: {}, Actual: {}, diff%: {}'.format(exp_val, real_rx_val, diff))
                    continue
            return_value = False
            ret_all.append(False)
            st.log('Traffic Validation: {}, {}'.format('Failure', cmsg))
            st.log('Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
            break
    return return_value if return_all==0 else (return_value, ret_all)


def _verify_streamlevel_stats(tr_details,mode,comp_type,tolerance_factor,delay_factor,retry,return_all):

    return_value = True
    ret_all=[]
    delay = 5 * float(delay_factor)
    tolerance = 5 * float(tolerance_factor)

    st.tg_wait(delay, "streamlevel_stats")

    stream_stats = dict()
    for tr_pair in range(1,len(tr_details)+1):
        tr_pair = str(tr_pair)
        tx_ports = tr_details[tr_pair]['tx_ports']
        tx_obj = tr_details[tr_pair]['tx_obj']
        exp_ratio = tr_details[tr_pair]['exp_ratio']
        rx_ports = tr_details[tr_pair]['rx_ports']
        rx_obj = tr_details[tr_pair]['rx_obj']
        stream_list = tr_details[tr_pair]['stream_list']

        cmsg = 'Pair: {}, TX Ports: {}, RX Ports: {}'.format(tr_pair,tx_ports,rx_ports)
        st.log('Validating Traffic, {}, stream_list: {}'.format(cmsg,stream_list))

        rx_obj = rx_obj[0]
        rx_port = rx_ports[0]
        rx_ph = rx_obj.get_port_handle(rx_port)
        for txPort,txObj,ratio,stream in zip(tx_ports,tx_obj,exp_ratio,stream_list):
            if type(ratio) is not list:
                ratio = [ratio]
            if len(stream) != len(ratio):
                ratio = ratio * len(stream)
            tx_ph = txObj.get_port_handle(txPort)
            for strelem,ratelem in zip(stream,ratio):
                retry_count = retry + 1 if not retry and comp_type == 'packet_rate' else retry
                for loop in range(0, int(retry_count)+1):
                    if loop > 0:
                        st.log('The difference is not in the given tolerance. So, retrying the stats fetch once again....{}'.format(loop))
                        st.wait(2, 'waiting to before fetch stats again')
                        if rx_obj.tg_type == 'stc': stream_stats.pop(tx_ph, '')
                        if rx_obj.tg_type in ['ixia', 'scapy']: stream_stats.pop(rx_ph, '')
                    exp_val = 0
                    tx_counter_name = get_counter_name(mode, rx_obj.tg_type, comp_type, 'tx')
                    rx_counter_name = get_counter_name(mode, rx_obj.tg_type, comp_type, 'rx')
                    if rx_obj.tg_type == 'stc':
                        #rx_stats = rx_obj.tg_traffic_stats(port_handle=rx_ph,mode='streams',streams=strelem)
                        if tx_ph not in stream_stats:
                            stream_stats[tx_ph] = _fetch_stats(txObj, tx_ph, 'streams', comp_type, 'tx', stream_elem=strelem)
                        rx_stats = stream_stats[tx_ph]
                        exp_val = int(rx_stats[tx_ph]['stream'][strelem]['tx'][tx_counter_name])
                        tx_val=exp_val
                        exp_val = int(exp_val * float(ratelem))
                        real_rx_val = int(rx_stats[tx_ph]['stream'][strelem]['rx'][rx_counter_name])
                    elif rx_obj.tg_type in ['ixia', 'scapy']:
                        #rx_stats = rx_obj.tg_traffic_stats(port_handle=rx_ph, mode='traffic_item')
                        if rx_ph not in stream_stats:
                            stream_stats[rx_ph] = _fetch_stats(rx_obj, rx_ph, 'traffic_item', comp_type, 'tx', stream_elem=strelem)
                        rx_stats = stream_stats[rx_ph]

                        #Following check is to avoid KeyError traffic_item. Reason is traffic was not started.
                        #Ixia team is looking into why traffic was not started - might be setup issue
                        if rx_stats['status'] != '1':
                            st.error('Could not get traffic_stats from the TGEN, Please check if traffic was started')
                            return False
                        try:
                            exp_val = float(rx_stats['traffic_item'][strelem]['tx'][tx_counter_name])
                        except Exception:
                            st.error('Could not get tx counter from the TGEN, Please check if traffic was started')
                            return False

                        tx_val=exp_val
                        exp_val = int(exp_val * float(ratelem))

                        try:
                            real_rx_val = float(rx_stats['traffic_item'][strelem]['rx'][rx_counter_name])
                        except Exception:
                            st.error('Could not get rx counter from the TGEN, Please check if traffic was started')
                            return False

                    st.log('RX counter {} = {}'.format(rx_counter_name, real_rx_val))
                    if tx_val > 0:
                        diff = (abs(exp_val - real_rx_val) * 100.0) / exp_val if exp_val > 0 else abs(real_rx_val * 100.0 / tx_val)
                        if diff <= tolerance:
                            st.log('Traffic Validation: {}, {} streamid: {}'.format('Success',cmsg, strelem))
                            st.log('Got expected values; Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
                            ret_all.append(True)
                            break
                        if loop != retry_count:
                            if not retry and comp_type == 'packet_rate' and diff > (tolerance + 5):
                                msg = 'The traffic difference is in not between {} and {}. Skipping the retry'.format(tolerance, tolerance + 5)
                                st.debug(msg)
                            else:
                                st.log('Traffic Varification: {}, {} streamid: {}'.format('Failure', cmsg, strelem))
                                st.log('Expected: {}, Actual: {}, diff%: {}'.format(exp_val, real_rx_val, diff))
                                continue
                    return_value = False
                    ret_all.append(False)
                    st.log('Traffic Validation: {}, {} streamid: {}'.format('Failure',cmsg, strelem))
                    st.log('Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
                    break
    return return_value if return_all==0 else (return_value, ret_all)

def _verify_analyzer_filter_stats(tr_details,mode,comp_type,tolerance_factor,delay_factor,retry,return_all):

    return_value = True
    ret_all=[]
    delay = 5 * float(delay_factor)
    tolerance = 5 * float(tolerance_factor)

    st.tg_wait(delay, "analyzer_filter_stats")

    for tr_pair in range(1,len(tr_details)+1):
        tr_pair = str(tr_pair)
        tx_ports = tr_details[tr_pair]['tx_ports']
        tx_obj = tr_details[tr_pair]['tx_obj']
        exp_ratio = tr_details[tr_pair]['exp_ratio']
        rx_ports = tr_details[tr_pair]['rx_ports']
        rx_obj = tr_details[tr_pair]['rx_obj']
        stream_list = tr_details[tr_pair]['stream_list']
        filter_param = tr_details[tr_pair]['filter_param']
        filter_val = tr_details[tr_pair]['filter_val']
        st.log('Validating Traffic, Pair: {}, Transmit Ports: {}, Receive Ports: {}, stream_list: {}, filter_param: {}, filter_val: {}'.format(tr_pair,tx_ports,rx_ports,stream_list,filter_param,filter_val))

        rx_obj = rx_obj[0]
        rx_port = rx_ports[0]
        rx_ph = rx_obj.get_port_handle(rx_port)
        for txPort,txObj,ratio,stream,fparam,fvalue in zip(tx_ports,tx_obj,exp_ratio,stream_list,filter_param,filter_val):
            tx_ph = txObj.get_port_handle(txPort)
            i = 1
            j = str(i)
            if type(stream) == str:
                st.log('only one stream is configured, form a list')
                stream = [stream]
                fparam = [fparam]
                fvalue = [fvalue]
            for strelem,fpelem,fvelem in zip(stream,fparam,fvalue):
                exp_val = 0
                if rx_obj.tg_type == 'stc':
                    tx_counter_name = get_counter_name(mode,rx_obj.tg_type,comp_type,'tx')
                    rx_counter_name = get_counter_name(mode,rx_obj.tg_type,comp_type,'rx')
                    tx_stats = txObj.tg_traffic_stats(mode='streams',port_handle=tx_ph)
                    exp_val = int(tx_stats[tx_ph]['stream'][strelem]['tx'][tx_counter_name])
                    tx_val=exp_val
                    if exp_val == 0:
                        msg = 'TX Counter {} is 0 (zero) for port: {}'.format(tx_counter_name, strelem)
                        st.warn(msg)
                        st.report_tgen_fail('tgen_failed_api', msg)
                    exp_val = exp_val * ratio
                    rx_stats = rx_obj.tg_traffic_stats(port_handle=rx_ph,mode='aggregate')
                    try:
                        real_rx_val = int(rx_stats[rx_ph]['aggregate']['rx'][fpelem][fvelem][rx_counter_name])
                    except KeyError:
                        st.log("traffic not found for the parameter: {} {}".format(fpelem,fvelem))
                        real_rx_val = 0
                elif rx_obj.tg_type in ['ixia', 'scapy']:
                    tx_counter_name = get_counter_name(mode,rx_obj.tg_type,comp_type,'tx')
                    rx_counter_name = get_counter_name(mode,rx_obj.tg_type,comp_type,'rx')
                    tx_stats = txObj.tg_traffic_stats(mode='streams',port_handle=tx_ph)
                    exp_val = int(float(tx_stats[tx_ph]['stream'][strelem]['tx'][tx_counter_name]))
                    tx_val=exp_val
                    if exp_val == 0:
                        msg = 'TX Counter {} is 0 (zero) for port: {}'.format(tx_counter_name, strelem)
                        st.warn(msg)
                        st.report_tgen_fail('tgen_failed_api', msg)
                    exp_val = exp_val * ratio
                    # need to get total flows and verify whether particular flow matching the filter value
                    # rx['flow'].keys() &  rx['flow']['1']['tracking']['2']['tracking_value'] prints '10' example vlan id 10
                    rx_stats = rx_obj.tg_traffic_stats(port_handle=rx_ph,mode='flow')
                    real_rx_val = int(float(rx_stats['flow'][j]['rx'][rx_counter_name]))
                    i += 1
                    j = str(i)
                st.log('Receive counter_name: {}, counter_val: {}'.format(rx_counter_name,real_rx_val))
                diff = (abs(exp_val - real_rx_val) * 100.0) / exp_val if exp_val > 0 else abs(real_rx_val * 100.0 / tx_val)
                if diff <= tolerance:
                    st.log('Traffic Validation: {}, Pair: {}, Transmit Ports: {}, Receive Ports: {}, streamid: {}, filter param: {}, filter value: {}'.format(
                            'Success', tr_pair, tx_ports, rx_ports, strelem, fpelem, fvelem))
                    st.log('Got expected values; Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
                    ret_all.append(True)
                else:
                    return_value = False
                    ret_all.append(False)
                    st.log('Traffic Validation: {}, Pair: {}, Transmit Ports: {}, Receive Ports: {}, streamid: {}, filter param: {}, filter value: {}'.format(
                            'Failure', tr_pair, tx_ports, rx_ports, strelem, fpelem, fvelem))
                    st.log('Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
    return return_value if return_all==0 else (return_value, ret_all)


def _verify_custom_filter_stats(tr_details,mode,comp_type,tolerance_factor,delay_factor,retry,return_all):

    return_value = True
    ret_all=[]
    delay = 5 * float(delay_factor)
    tolerance = 5 * float(tolerance_factor)

    st.tg_wait(delay, "custom_filter_stats")

    for tr_pair in range(1,len(tr_details)+1):
        tr_pair = str(tr_pair)
        tx_ports = tr_details[tr_pair]['tx_ports']
        tx_obj = tr_details[tr_pair]['tx_obj']
        exp_ratio = tr_details[tr_pair]['exp_ratio']
        rx_ports = tr_details[tr_pair]['rx_ports']
        rx_obj = tr_details[tr_pair]['rx_obj']

        st.log('Validating Traffic, Pair: {}, Transmit Ports: {}, Receive Ports: {}'.format(tr_pair,tx_ports,rx_ports))
        exp_val = 0
        for port,obj,ratio in zip(tx_ports,tx_obj,exp_ratio):
            tx_ph = obj.get_port_handle(port)
            mode = 'aggregate'
            tx_stats = obj.tg_traffic_stats(port_handle=tx_ph,mode=mode)
            counter_name = get_counter_name(mode,obj.tg_type,comp_type,'tx')
            cur_tx_val = int(tx_stats[tx_ph][mode]['tx'][counter_name])
            st.log('Transmit counter_name: {}, counter_val: {}'.format(counter_name,cur_tx_val))
            if cur_tx_val == 0:
                msg = 'TX Counter {} is 0 (zero) for port: {}'.format(counter_name, port)
                st.warn(msg)
                st.report_tgen_fail('tgen_failed_api', msg)
            exp_val += cur_tx_val * ratio
            # st.log(exp_val)
        st.log('Total Tx from ports {}: {}'.format(tx_ports,exp_val))

        for port,obj in zip(rx_ports,rx_obj):
            rx_ph = obj.get_port_handle(port)
            mode = 'custom_filter'
            rx_stats = obj.tg_custom_filter_config(mode='getStats',port_handle=rx_ph)
            st.log(rx_stats)
            counter_name = 'filtered_frame_count'
            real_rx_val = int(rx_stats[rx_ph][mode][counter_name])
            st.log('Receive counter_name: {}, counter_val: {}'.format(counter_name,real_rx_val))

        st.log('Total Rx on ports {}: {}'.format(rx_ports,real_rx_val))

        diff = (abs(exp_val - real_rx_val) * 100.0) / exp_val if exp_val > 0 else abs(real_rx_val * 100.0 / cur_tx_val)
        if diff <= tolerance:
            st.log('Traffic Validation: {}, Pair: {}, Transmit Ports: {}, Receive Ports: {}'.format('Success',tr_pair,tx_ports,rx_ports))
            st.log('Got expected values; Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
            ret_all.append(True)
        else:
            return_value = False
            ret_all.append(False)
            st.log('Traffic Validation: {}, Pair: {}, Transmit Ports: {}, Receive Ports: {}'.format('Failure',tr_pair,tx_ports,rx_ports))
            st.log('Expected: {}, Actual: {}, diff%: {}'.format(exp_val,real_rx_val,diff))
    return return_value if return_all==0 else (return_value, ret_all)


def validate_tgen_traffic(**kwargs):

    '''
    traffic_details = {
        '1' : {
            'tx_ports' : ['5/7', '5/8'],
            'tx_obj' : ['tg2','tg2'],
            'exp_ratio' : [1,1],
            'rx_ports' : ['5/9'],
            'rx_obj' : ['tg2'],
            },
        '2' : {
            'tx_ports' : ['5/7', '5/8'],
            'tx_obj' : ['tg2','tg2'],
            'exp_ratio' : [1,1],
            'rx_ports' : ['5/9'],
            'rx_obj' : ['tg2'],
            },
    }

    comp_type : <packet_count|packet_rate>'
    mode : <aggregate|streamblock|filter>
    tolernace_factor: <0...20>. Default is 1 and tolerance is 5%
    delay_factor: <0...24>. Default is 1 and delay is 5 sec
    retry: <1..3>. Default is 1 and retry is 1
    return_all: <0/1>. To get the result of all streams.
        Default is 0
        Return value will be tuple with (final_result, all_result)
    '''

    _log_call("validate_tgen_traffic", **kwargs)

    if kwargs.get('traffic_details') is None:
        st.log('Mandatory param traffic_details is missing')
        return False

    traffic_details = kwargs['traffic_details']
    #st.log(traffic_details)
    if not _validate_parameters(traffic_details):
        return False

    delay_factor = kwargs.get('delay_factor',1)
    delay_factor = delay_factor if float(delay_factor) >= 1 else 1
    tolerance_factor = kwargs.get('tolerance_factor',1)
    retry = kwargs.get('retry',0)
    comp_type = kwargs.get('comp_type','packet_count')
    return_all = kwargs.get('return_all',0)
    mode = kwargs.get('mode').lower()

    if mode == 'aggregate':
        return _verify_aggregate_stats(traffic_details, mode=mode, comp_type=comp_type, \
               tolerance_factor=tolerance_factor, delay_factor=delay_factor, retry=retry, return_all=return_all)
    elif mode == 'streamblock':
        return _verify_streamlevel_stats(traffic_details, mode=mode, comp_type=comp_type, \
               tolerance_factor=tolerance_factor, delay_factor=delay_factor, retry=retry, return_all=return_all)
    elif mode == 'filter':
        return _verify_analyzer_filter_stats(traffic_details, mode=mode, comp_type=comp_type, \
               tolerance_factor=tolerance_factor, delay_factor=delay_factor, retry=retry, return_all=return_all)
    elif mode == 'custom_filter':
        return _verify_custom_filter_stats(traffic_details, mode=mode, comp_type=comp_type, \
               tolerance_factor=tolerance_factor, delay_factor=delay_factor, retry=retry, return_all=return_all)


def _verify_packet_capture(pkt_dict, offset_list, value_list,port_handle, max_count=20, return_index=0):

    tot_pkts = int(pkt_dict[port_handle]['aggregate']['num_frames'])
    if max_count > 0 and tot_pkts > max_count:
        tot_pkts = max_count

    for pkt_num in range(tot_pkts):
        st.log('Parsing packet: {}, port_handle: {}'.format(pkt_num,port_handle))
        ret_val = len(value_list)
        for offset,value in zip(offset_list,value_list):
            if ":" in value:
                value = value.split(':')
            elif "." in value:
                value = [hex(int(i))[2:].zfill(2).upper() for i in value.split('.')]
            else:
                hex_string = value.upper()
                if len(hex_string) % 2 != 0:
                    hex_string = hex_string.zfill(len(hex_string)+1)
                value = [(hex_string[i:i+2]) for i in range(0, len(hex_string), 2)]

            if not isinstance(value,list):
                value = [value]

            start_range = offset
            end_range = offset + len(value)

            try:
                found_value = pkt_dict[port_handle]['frame'][str(pkt_num)]['frame_pylist'][start_range:end_range]
            except Exception:
                found_value = []

            if found_value == value:
                st.log('Match found in packet: {} for {} at offset: {}'.format(pkt_num,value,offset))
                ret_val -= 1
            else:
                st.log('Match not found in packet: {} at offset: {}, Expected: {}, Found: {}'.format(pkt_num,offset,value,found_value))

        if ret_val == 0 and return_index:
            return pkt_num, True
        elif ret_val == 0:
            return  True
    return (-1, False) if return_index else False

def _parse_ixia_packet(pkt_dict,header,field,value,offset='not_set'):

    for k,v in pkt_dict.items():
        if isinstance(v,dict):
            if "display_name" in v:
                if re.search(r'Generic Routing Encapsulation',header) and re.search(r'Data',field,re.I):
                    if header in k and v['display_name'] == field:
                        data_value = v['value']
                        start_index = int(offset)
                        end_index = int(offset) + len(value)
                        new_data_value = data_value[start_index:end_index]
                        if new_data_value.upper() == value.upper():
                            ixia_pckt_cap_ret_val.append(True)
                            return ixia_pckt_cap_ret_val
                elif v['display_name'] == field and v['value'].upper() == value.upper() and header in k:
                    ixia_pckt_cap_ret_val.append(True)
                    return ixia_pckt_cap_ret_val
            _parse_ixia_packet(v,header,field,value,offset)

    ixia_pckt_cap_ret_val.append(False)
    return ixia_pckt_cap_ret_val

def _verify_packet_capture_ixia(pkt_dict,header_list,value_list,port_handle,return_index=0):

        frame_format = {
            'ETH': {
                'h_name': 'Ethernet',
                'fname_list': ['Ethernet','Source','Destination','Type'],
                },
            'VLAN': {
                'h_name': '1Q Virtual LAN',
                'fname_list': ['1Q Virtual LAN','CFI','ID','Priority','Type'],
                },
            'IP': {
                'h_name': 'Internet Protocol',
                'fname_list':  ['Version','Total Length','Source','Destination','Protocol','Time to live','Header Length','Identification','Precedence', 'Differentiated Services Codepoint', 'Reliability','Explicit Congestion Notification', 'Fragment offset', 'More fragments'],
                },
            'IP6': {
                'h_name': 'Internet Protocol Version 6$',
                'fname_list':  ['Source','Destination','Protocol'],
                },
            'TCP': {
                'h_name': 'Transmission Control Protocol',
                'fname_list': ['Source Port','Destination Port'],
                },
            'UDP': {
                'h_name': 'User Datagram Protocol',
                'fname_list': ['Source Port','Destination Port'],
                },
            'GRE': {
                'h_name': 'Generic Routing Encapsulation',
                'fname_list': ['Data','Protocol Type'],
                }
            }

        global ixia_pckt_cap_ret_val
        last_pkt_count = int(pkt_dict[port_handle]['frame']['data']['frame_id_end'])+1
    #    last_pkt_count = 2
        for pkt_num in range(1,last_pkt_count):
            st.log('Parsing packet: {}, port_handle: {}'.format(pkt_num,port_handle))
            try:
                p_d = pkt_dict[port_handle]['frame']['data'][str(pkt_num)]
            except Exception:
                st.error('The given indexed packet not found in the capture buffer')
                st.report_tgen_fail('tgen_failed_capture_buffer')
            #p_d = pkt_dict
            ret_val = len(value_list)
            for header_field,value in zip(header_list,value_list):
                header = header_field.split(':')[0]
                field = header_field.split(':')[1]
                offset = 'not_set'
                ixia_pckt_cap_ret_val = []
                if header == 'GRE' and re.search(r'Data',field,re.I):
                    offset = header_field.split(':')[2]
                    if re.search(r':',value):
                        value = ''.join(value.split(':')).upper()
                    elif re.search(r'\.',value):
                        value = ''.join([hex(int(i))[2:].zfill(2).upper() for i in value.split('.')])

                elif not re.search(r':|\.',value):
                    if re.search(r'vlan',header,re.I):
#                        header = '802'
                        vid = value[1:4]
                        value = str(int(vid,16))
                    # special code for following, one elif  for each header
                    # vlan priority
                    # tos
                    # dscp
                    else:
                        value = str(int(value,16))
                st.log("{} {} {}".format(header, field, value))

                res = _parse_ixia_packet(p_d,frame_format[header]['h_name'],field,value,offset)
                if True in res:
                    st.log('Match found in packet: {} for {} in {}:{} header'.format(pkt_num,value,header,field))
                    ret_val -= 1
                else:
                    st.log('Match not found in packet: {} for {} in {}:{} header'.format(pkt_num,value,header,field))
                    st.log('Packet: {}'.format(p_d))

            if ret_val == 0 and return_index:
                return pkt_num, True
            elif ret_val == 0:
                return True


def validate_packet_capture(**kwargs):
    pkt_dict = kwargs['pkt_dict']
    header_list = kwargs.get('header_list','new_ixia_format')
    offset_list = kwargs['offset_list']
    value_list = kwargs['value_list']
    num_frames = kwargs.get('var_num_frames', 20)
    return_index =kwargs.get('return_index', 0)

    _log_call("validate_packet_capture", **kwargs)

    if len(pkt_dict.keys()) > 2:
        st.log('Packets have caputred on more than one port. Pass packet info for only one port')
        return False

    for key in pkt_dict:
        if key != 'status':
            port_handle = key

    if pkt_dict[port_handle]['aggregate']['num_frames'] in ['0', 'N/A']:
        st.log("No packets were captured")
        return False
    else:
        st.log('Number of packets captured: {}'.format(pkt_dict[port_handle]['aggregate']['num_frames']))

    if kwargs['tg_type'] in ['stc']:
        return _verify_packet_capture(pkt_dict,offset_list,value_list,port_handle,num_frames,return_index)

    if kwargs['tg_type'] in ['scapy']:
        return _verify_packet_capture(pkt_dict,offset_list,value_list,port_handle, 0, return_index)

    if kwargs['tg_type'] in ['ixia']:
        if header_list == 'new_ixia_format':
            ### _verify_packet_capture_ixia is obsolete from now on, it is there only for legacy script.
            return _verify_packet_capture(pkt_dict,offset_list,value_list,port_handle,num_frames,return_index)
        else:
            return _verify_packet_capture_ixia(pkt_dict,header_list,value_list,port_handle,return_index)

def verify_ping(src_obj,port_handle,dev_handle,dst_ip,ping_count=5,exp_count=5):
    ping_count,exp_count = int(ping_count),int(exp_count)
    if src_obj.tg_type == 'stc':
        result = src_obj.tg_emulation_ping(handle=dev_handle,host=dst_ip,count=ping_count)
        st.log("ping output: {}".format(result))
        return True if int(result['tx']) == ping_count and  int(result['rx']) == exp_count else False
    elif src_obj.tg_type in ['ixia', 'scapy']:
        count = 0
        for _ in range(ping_count):
            result = src_obj.tg_interface_config(protocol_handle=dev_handle,send_ping='1',ping_dst=dst_ip)
            st.log("ping output: {}".format(result))
            if port_handle not in result:
                st.warn("port_handle details not found in o/p")
            elif "ping_details" not in result[port_handle]:
                st.warn("ping_details details not found in o/p")
            else:
                try:
                    result = result[port_handle]['ping_details']
                    if src_obj.tg_type == 'scapy':
                        ping_out = re.search(r'([0-9]+)\s+packets transmitted,\s+([0-9]+)\s+received', result)
                    else:
                        ping_out = re.search(r'([0-9]+)\s+requests sent,\s+([0-9]+)\s+replies received', result)
                    tx_pkt,rx_pkt = ping_out.group(1),ping_out.group(2)
                    if int(tx_pkt) == int(rx_pkt):
                        count += 1
                except AttributeError:
                    st.warn("ping command o/p not matching regular expression")
        return True if count == exp_count else False
    else:
        st.error("Need to add code for this tg type: {}".format(src_obj.tg_type))
        return False

def tg_bgp_config(**kwargs):

    """
    Description:
    Configures the BGP parameters on the already created host.

    Returns:
    Returns the dict of statuses of different procedures used.
    Empty dict {} on error.

    Parameters:
    tg        = (Mandatory) Tgen object.
    handle    = (Mandatory) Host handle (returned by tg_create_host) if conf_var is sent.
                or bgp_handle if conf_var is not used.
    conf_var  = Dict variable for tg_emulation_bgp_config.
    route_var = Single or List of route variables (of type dict).
    ctrl_var  = Dict variable for tg_emulation_bgp_control.

    Usage:
    tg_bgp_conf1 = { 'mode'                  : 'enable',
                     'active_connect_enable' : '1',
                     'local_as'              : '100',
                     'remote_as'             : '100',
                     'remote_ip_addr'        : '21.1.1.1'
                   }
    tg_bgp_route1 = { 'mode'       : 'add',
                      'num_routes' : '10',
                      'prefix'     : '121.1.1.0'
                    }
    tg_bgp_ctrl1 = { 'mode' : 'start'}

    bgp_host1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = tg_bgp_conf1,
        route_var = tg_bgp_route1,
        ctrl_var  = tg_bgp_ctrl1)
    # Only BGP neighborship and not the routes.
    bgp_host1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = tg_bgp_conf1,
        ctrl_var  = tg_bgp_ctrl1)
    """

    ret = {}
    def_conf_var = { 'mode'                  : 'enable',
                     'active_connect_enable' : '1'
                   }
    def_route_var = { 'mode' : 'add',
    }
    def_ctrl_var = { 'mode' : 'start',
                   }

    _log_call("tg_bgp_config", **kwargs)

    for param in ['tg', 'handle']:
        if param not in kwargs:
            st.log("BGP_ERROR: Mandatory parameter {} is missing.".format(str(param)))
            return ret
    handle = kwargs['handle']
    tg = kwargs['tg']
    handle = handle['handle'] if 'handle' in handle else handle
    hand = handle

    conf_var = {}
    route_var = [{}]
    ctrl_var = {}
    if 'conf_var' in kwargs:
        conf_var = copy.deepcopy(kwargs['conf_var'])
    if 'route_var' in kwargs:
        route_var = copy.deepcopy(kwargs['route_var'])
        route_var = list(route_var) if type(route_var) is list else [route_var]
    if 'ctrl_var' in kwargs:
        ctrl_var = copy.deepcopy(kwargs['ctrl_var'])

    # Copying default values to var.
    for k in def_conf_var.keys():
        conf_var[k] = conf_var.get(k,def_conf_var[k])
    for i in range(len(route_var)):
        for k in def_route_var.keys():
            route_var[i][k] = route_var[i].get(k,def_route_var[k])
    for k in def_ctrl_var.keys():
        ctrl_var[k] = ctrl_var.get(k,def_ctrl_var[k])

    bgp_conf={}
    bgp_route = []
    bgp_ctrl={}
    if 'conf_var' in kwargs:
        bgp_conf = tg.tg_emulation_bgp_config(handle=handle, **conf_var)
        st.log(bgp_conf)
        hand = bgp_conf['handle']

    if 'route_var' in kwargs:
        for i,var in enumerate(route_var):
            bgp_route.append(tg.tg_emulation_bgp_route_config(handle=hand, **var))
        st.log(bgp_route)

    if 'ctrl_var' in kwargs:
        bgp_ctrl = tg.tg_emulation_bgp_control(handle=hand,**ctrl_var)
        st.log(bgp_ctrl)

    ret['conf'] = copy.deepcopy(bgp_conf)
    ret['route'] = copy.deepcopy(bgp_route)
    ret['ctrl'] = copy.deepcopy(bgp_ctrl)
    st.log('Return Status : '+str(ret))

    return ret

def tg_igmp_config(**kwargs):

    """
    Description:
    Configures the IGMP parameters on the already created host.

    Returns:
    Returns the dict of statuses of different procedures used.
    Empty dict {} on error.

    Parameters:
    tg        = (Mandatory) Tgen object.
    handle    = (Mandatory) Host handle (returned by tg_create_host) if conf_var is sent.
                or igmp_handle if conf_var is not used.
    session_var  = Dict variable for tg_emulation_igmp_config.
    group_var = Dict variable for tg_emulation_multicast_group_config.
    source_var = Dict variable for tg_emulation_multicast_source_config(Applicable only for V3).
    igmp_group_var = Dict variable for tg_emulation_igmp_group_config

    Usage:
    session_conf1 = { 'mode'        : 'create',
                     'count'        : '1',
                     'version'      : 'v3'
                   }
    group_conf1 = { 'mode'       : 'create',
                    'num_groups' : '10',
                    'ip_addr_start'     : '225.1.1.1'
                    'active' : '1'
                  }
    source_conf1 = { 'mode'       : 'create',
                     'num_sources' : '10',
                     'ip_addr_start'     : '11.1.1.1'
                     'active' : '1'
                    }
    igmp_group_conf1 = { 'mode'        : 'create',
                         'g_filter_mode'        : 'include'
                   }

    igmp_host1 = tg_igmp_config(tg = tg1,
        handle    = h1['handle'],
        session_var  = session_conf1,
        group_var = group_conf1,
        source_var = source_conf1,
        igmp_group_var = igmp_group_conf1,
    """

    ret = {}
    def_session_var = { 'mode' : 'create',
                        'igmp_version' : 'v2'
                    }
    def_group_var = { 'mode' : 'create',
                      'active' : '1'
                    }
    def_source_var = {'mode': 'create',
                      'active': '0',
                      'ip_addr_start': '21.1.1.100',
                      'num_sources': '5'
                      }
    def_igmp_group_var = { 'mode' : 'create' }

    _log_call("tg_igmp_config", **kwargs)

    for param in ['tg', 'handle']:
        if param not in kwargs:
            st.log("IGMP_ERROR: Mandatory parameter {} is missing.".format(str(param)))
            return ret
    handle = kwargs['handle']
    tg = kwargs['tg']
    handle = handle['handle'] if 'handle' in handle else handle
    handle = handle[0] if type(handle) is list else handle

    session_var = {}
    group_var = {}
    source_var = {}
    igmp_group_var = {}

    if 'session_var' in kwargs:
        session_var = copy.deepcopy(kwargs['session_var'])
    if 'group_var' in kwargs:
        group_var = copy.deepcopy(kwargs['group_var'])
    if 'source_var' in kwargs:
        source_var = copy.deepcopy(kwargs['source_var'])
    if 'igmp_group_var' in kwargs:
        igmp_group_var = copy.deepcopy(kwargs['igmp_group_var'])

    # Copying default values to var.
    for k in def_session_var.keys():
        session_var[k] = session_var.get(k,def_session_var[k])
    for k in def_group_var.keys():
        group_var[k] = group_var.get(k,def_group_var[k])
    for k in def_source_var.keys():
        source_var[k] = source_var.get(k,def_source_var[k])
    for k in def_igmp_group_var.keys():
        igmp_group_var[k] = igmp_group_var.get(k, def_igmp_group_var[k])

    igmp_session = {}
    igmp_group = {}
    igmp_source = {}
    igmp_config ={}

    if 'session_var' in kwargs:
        igmp_session = tg.tg_emulation_igmp_config(handle=handle, **session_var)
        st.log(igmp_session)
        igmp_group_var['session_handle'] = igmp_session['host_handle']

    if 'group_var' in kwargs:
        igmp_group = tg.tg_emulation_multicast_group_config(**group_var)
        st.log(igmp_group)
        igmp_group_var['group_pool_handle'] = igmp_group['mul_group_handle']

    if 'source_var' in kwargs:
        source_var['active'] = '1'
    igmp_source = tg.tg_emulation_multicast_source_config(**source_var)
    st.log(igmp_source)
    igmp_group_var['source_pool_handle'] = igmp_source['mul_source_handle']

    if 'igmp_group_var' in kwargs:
        igmp_config = tg.tg_emulation_igmp_group_config(**igmp_group_var)
        st.log(igmp_config)

    ret['session'] = copy.deepcopy(igmp_session)
    ret['group'] = copy.deepcopy(igmp_group)
    ret['source'] = copy.deepcopy(igmp_source)
    ret['config'] = copy.deepcopy(igmp_config)
    st.log('Return Status : '+str(ret))

    return ret


def get_traffic_stats(tg_obj, **kwargs):
    """
    @author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    Common function to get the traffic stats
    :param tg_obj: TG object
    :param mode: Mode of the stats to be fetched
    :param port_handle: Port handler
    :return: stats: A Dictionary object with tx/rx packets/bytes stats
    """
    stats = SpyTestDict()
    stats.tx = SpyTestDict()
    stats.rx = SpyTestDict()
    if "port_handle" not in kwargs:
        st.error("Please provide the port handler")
        return False
    port_handle = kwargs["port_handle"]
    mode = kwargs["mode"] if "mode" in kwargs else "aggregate"
    direction = kwargs.get('direction', 'rx')
    stats_tg = _fetch_stats(tg_obj, port_handle, mode, 'packet_count', direction)
    stats.tx.total_packets = int(stats_tg[port_handle][mode]['tx']['total_pkts'])
    stats.tx.total_bytes = int(stats_tg[port_handle][mode]['tx']['pkt_byte_count'])
    stats.rx.total_packets = int(stats_tg[port_handle][mode]['rx']['total_pkts'])
    stats.rx.total_bytes = int(stats_tg[port_handle][mode]['rx']['pkt_byte_count'])
    stats.rx.oversize_count = 0
    if "oversize_count" in stats_tg[port_handle][mode]['rx']:
        stats.rx.oversize_count = int(stats_tg[port_handle][mode]['rx']['oversize_count'])
    st.log("*****TG STATS******")
    st.log(stats)
    st.log("***********")
    return stats


# combine the calls when the tg is same
def port_traffic_control(action, *args, **kwargs):
    for arg in args:
        tg, tg_ph = arg
        if action == "reset_and_clear_stats":
            tg.tg_traffic_control(action="reset", port_handle=tg_ph, **kwargs)
            tg.tg_traffic_control(action="clear_stats", port_handle=tg_ph, **kwargs)
        else:
            tg.tg_traffic_control(action=action, port_handle=tg_ph, **kwargs)

