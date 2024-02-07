from datetime import datetime
from spytest import st
from apis.system.rest import get_rest
from utilities.common import make_list
from utilities.utils import get_interface_number_from_name

invalid_ports = ['vlan', 'eth0']


def process_intf_status_rest_output(data):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param data:
    :type dict:
    :type bool:
    :return:
    :rtype:
    """
    reason_map = {"OPER_UP": "oper-up", "PHY_LINK_DOWN": "phy-link-down", "ADMIN_DOWN": "admin-down", "ERR_DISABLED": "err-disabled"}
    ret_val = list()
    if isinstance(data, dict) and data.get('output') and data['output'].get('openconfig-interfaces:interface'):
        actual_data = data['output']['openconfig-interfaces:interface']
    elif isinstance(data, dict) and data.get('output') and data['output'].get('openconfig-interfaces:interfaces') and data['output']['openconfig-interfaces:interfaces'].get('interface'):
        actual_data = data['output']['openconfig-interfaces:interfaces']['interface']
    else:
        st.error('interface status GET data is not as per format')
        st.debug('Provided data: {}'.format(data))
        return ret_val
    if actual_data and isinstance(actual_data, list):
        for intf_entry in actual_data:
            temp = dict()
            if intf_entry.get('name') and any(port in intf_entry['name'].lower() for port in invalid_ports):
                continue
            temp['interface'] = intf_entry.get('name', '')
            temp['description'] = intf_entry['state']['description'] if intf_entry.get('state') and intf_entry['state'].get('description') else '-'
            temp['oper'] = intf_entry['state']['oper-status'].lower() if intf_entry.get('state') and intf_entry['state'].get('oper-status') else ''
            temp['admin'] = reason_map.get(intf_entry['openconfig-if-ethernet:ethernet']['state']['openconfig-interfaces-ext:reason']) if intf_entry.get('openconfig-if-ethernet:ethernet') and intf_entry['openconfig-if-ethernet:ethernet'].get('state') and intf_entry['openconfig-if-ethernet:ethernet']['state'].get('openconfig-interfaces-ext:reason') else ''
            temp['mtu'] = str(intf_entry['state']['mtu']) if intf_entry.get('state') and intf_entry['state'].get('mtu') else '9100'
            port_speed = intf_entry['openconfig-if-ethernet:ethernet']['state']['port-speed'] if intf_entry.get('openconfig-if-ethernet:ethernet') and intf_entry['openconfig-if-ethernet:ethernet'].get('state') and intf_entry['openconfig-if-ethernet:ethernet']['state'].get('port-speed') else ''
            temp['speed'] = port_speed.replace('GB', '000').split(":")[1].replace('SPEED_', '') if port_speed else port_speed
            ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    else:
        st.debug("Provided data: {}".format(data))
        st.debug(ret_val)
        return ret_val


def process_intf_counters_rest_output(data, type='interface'):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param data:
    :type dict:
    :type bool:
    :return:
    :rtype:
    """
    ret_val = list()
    if type == 'interface':
        if isinstance(data, dict) and data.get('output') and data['output'].get('openconfig-interfaces:interface'):
            actual_data = data['output']['openconfig-interfaces:interface']
        elif isinstance(data, dict) and data.get('output') and data['output'].get('openconfig-interfaces:interfaces') and data['output']['openconfig-interfaces:interfaces'].get('interface'):
            actual_data = data['output']['openconfig-interfaces:interfaces']['interface']
        else:
            st.error('interface counters GET data is not as per format')
            st.debug('Provided data: {}'.format(data))
            return ret_val
        if actual_data and isinstance(actual_data, list):
            for intf_entry in actual_data:
                temp = {}
                if intf_entry.get('name') and any(port in intf_entry['name'].lower() for port in invalid_ports):
                    continue
                temp['iface'] = intf_entry.get('name', '')
                temp['state'] = intf_entry['state']['oper-status'].upper()[0] if intf_entry.get('state') and intf_entry['state'].get('oper-status') and len(intf_entry['state']['oper-status']) >= 1 else ''
                if intf_entry.get('state') and intf_entry['state'].get('counters'):
                    counters_data = intf_entry['state']['counters']
                    temp['rx_ok'] = str(counters_data.get('in-pkts', '0'))
                    temp['rx_err'] = str(counters_data.get('in-errors', '0'))
                    temp['rx_drp'] = str(counters_data.get('in-discards', '0'))
                    temp['tx_ok'] = str(counters_data.get('out-pkts', '0'))
                    temp['tx_err'] = str(counters_data.get('out-errors', '0'))
                    temp['tx_drp'] = str(counters_data.get('out-discards', '0'))
                if intf_entry.get('openconfig-if-ethernet:ethernet') and intf_entry['openconfig-if-ethernet:ethernet'].get('state') and intf_entry['openconfig-if-ethernet:ethernet']['state'].get('counters'):
                    counters_data = intf_entry['openconfig-if-ethernet:ethernet']['state']['counters']
                    temp['rx_ovr'] = str(counters_data.get('in-oversize-frames', '0'))
                    temp['tx_ovr'] = str(counters_data.get('openconfig-interfaces-ext:out-oversize-frames', '0'))
                ret_val.append(temp)
            st.debug(ret_val)
            return ret_val
    elif type == 'rif_interface':
        if isinstance(data, dict) and data.get('output') and data['output'].get('openconfig-if-ip:counters'):
            actual_data = data['output']['openconfig-if-ip:counters']
        else:
            st.error('interface counters GET data is not as per format')
            st.debug('Provided data: {}'.format(data))
            return ret_val
        temp = {}
        temp['rx_ok'] = str(actual_data.get('in-pkts', '0'))
        temp['rx_pps'] = str(actual_data.get('openconfig-interfaces-ext:in-pkts-per-second', '0'))
        temp['rx_bps'] = str(actual_data.get('openconfig-interfaces-ext:in-octets-per-second', '0'))
        if actual_data.get('in-error-pkts') == '0' and actual_data.get('out-error-pkts') == '0':
            temp['tx_err'] = 'N/A'
            temp['rx_err'] = 'N/A'
        else:
            temp['tx_err'] = str(actual_data.get('out-error-pkts', '0'))
            temp['rx_err'] = str(actual_data.get('in-error-pkts', '0'))
        temp['tx_ok'] = str(actual_data.get('out-pkts', '0'))
        temp['tx_pps'] = str(actual_data.get('openconfig-interfaces-ext:out-pkts-per-second', '0'))
        temp['tx_bps'] = str(actual_data.get('openconfig-interfaces-ext:out-octets-per-second', '0'))
        ret_val.append(temp)
        return ret_val
    else:
        st.debug('Provided data: {}'.format(data))
        st.debug(ret_val)
        return ret_val


def rest_get_queue_counters(dut, port):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    ret_val = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    url = rest_urls['queue_counters_get'].format(port)
    get_info = get_rest(dut, rest_url=url, timeout=60)
    if isinstance(get_info, dict) and get_info.get('output') and isinstance(get_info['output'], dict) and get_info['output'].get('openconfig-qos:queues') and get_info['output']['openconfig-qos:queues'].get('queue'):
        actual_data = get_info['output']['openconfig-qos:queues']['queue']
    else:
        st.error('queue counters GET data is not as per format')
        st.debug('Provided data: {}'.format(get_info))
        return ret_val
    if actual_data and isinstance(actual_data, list):
        for entry in actual_data:
            temp = dict()
            if isinstance(entry, dict) and entry.get('state') and isinstance(entry['state'], dict):
                counters_info = entry['state']
                port, queue = counters_info['name'].split(':') if counters_info.get('name') and ':' in counters_info['name'] else ['', '']
                temp['port'] = port
                temp['txq'] = '{}{}'.format(counters_info['traffic-type'], queue) if counters_info.get('traffic-type') else '{}{}'.format('NA', queue)
                temp['pkts_drop'] = str(counters_info.get('dropped-pkts', '0'))
                temp['byte_drop'] = str(counters_info.get('dropped-octets', '0'))
                temp['pkts_count'] = str(counters_info.get('transmit-pkts', '0'))
                temp['byte_count'] = str(counters_info.get('transmit-octets', '0'))
                temp['bit_rate'] = str(counters_info.get('transmit-bits-per-second', '0'))
                temp['byte_rate'] = str(counters_info.get('transmit-octets-per-second', '0'))
                temp['pkts_rate'] = str(counters_info.get('transmit-pkts-per-second', '0'))
                ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    else:
        st.debug('Provided data: {}'.format(get_info))
        st.debug(ret_val)
        return ret_val


def rest_get_intf_down_reason(dut, intfs, **kwargs):
    """
    To get processed output from REST interface down reason.
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param intfs:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    intfs = make_list(intfs)
    reasons_map = {'ADMIN_DOWN': 'admin-down', 'ERR_DISABLED': 'err-disabled', 'PHY_LINK_DOWN': 'phy-link-down', 'OPER_UP': 'oper-up', 'ALL_LINKS_DOWN': 'all-links-down', 'MIN_LINKS': 'min-links', 'LACP_FAIL': 'lacp-fail'}
    for intf in intfs:
        url = rest_urls['phy_link_down_reason'] if intf.startswith('Eth') else rest_urls['lag_link_down_reason']
        out = get_rest(dut, rest_url=url.format(name=intf))
        if out and isinstance(out, dict) and out.get('output') and isinstance(out['output'], dict) and out['output'].get('openconfig-interfaces-ext:reason'):
            reason = out['output']['openconfig-interfaces-ext:reason']
        if 'reason' in locals():
            temp = dict()
            temp['interface'] = intf
            temp['admin'] = reasons_map[reason] if reasons_map.get(reason) else reason
            retval.append(temp)
    st.debug(retval)
    return retval


def rest_get_intf_down_event(dut, intfs, **kwargs):
    """
    To get processed output from REST interface down event.
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param intfs:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    intfs = make_list(intfs)
    events_map = {'ADMIN_DOWN': 'admin-down', 'ERR_DISABLED': 'err-disabled', 'PHY_LINK_DOWN': 'phy-link-down', 'OPER_UP': 'oper-up', 'ALL_LINKS_DOWN': 'all-links-down', 'MIN_LINKS': 'min-links', 'LACP_FAIL': 'lacp-fail'}
    timestamp = None
    for intf in intfs:
        url = rest_urls['phy_link_down_event'] if intf.startswith("Eth") else rest_urls['lag_link_down_event']
        out = get_rest(dut, rest_url=url.format(name=intf))
        if out and isinstance(out, dict) and out.get('output') and isinstance(out['output'], dict) and out['output'].get('openconfig-interfaces-ext:reason-event') and isinstance(out['output']['openconfig-interfaces-ext:reason-event'], list):
            events_data = out['output']['openconfig-interfaces-ext:reason-event']
        if 'events_data' in locals():
            for event_data in events_data:
                if isinstance(event_data, dict) and event_data.get('state') and isinstance(event_data['state'], dict):
                    event = event_data['state']
                    temp = dict()
                    temp['interface'] = intf
                    if intf.startswith("PortChannel"):
                        temp['channel_number'] = get_interface_number_from_name(intf)['number']
                    temp['reason'] = events_map[event['reason']] if event.get('reason') and events_map.get(event['reason']) else event.get('reason')
                    temp['event'] = event['event'] if event.get('event') else ''
                    temp['timestamp'] = event['timestamp'] if event.get('timestamp') else ''
                    if not timestamp:
                        timestamp = temp['timestamp']
                        final_reason = temp['reason']
                    else:
                        if datetime.strptime(temp['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ") > datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ"):
                            final_reason = temp['reason']
                            timestamp = temp['timestamp']
                    retval.append(temp)
    _ = [entry.update(reason=final_reason) for entry in retval]
    st.debug(retval)
    return retval


def process_intf_counters_gnmi_rest_output(data, type='interface', counter_type='basic', rif=None):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param data:
    :type dict:
    :type bool:
    :return:
    :rtype:
    """
    ret_val = list()
    flag_sub_intf = False
    if type == 'interface':
        valid_output = False
        if isinstance(data, dict) and data.get('openconfig-interfaces:interface') and isinstance(data['openconfig-interfaces:interface'], list):
            actual_data = data['openconfig-interfaces:interface'][0]
            if actual_data.get('state') and actual_data['state'].get('counters'):
                counters_data = actual_data['state']['counters']
            if actual_data['state']['name'].startswith('Eth'):
                if rif == "yes":
                    if actual_data['subinterfaces']['subinterface'][0]['openconfig-if-ip:ipv4']['state']['counters']:
                        counters_ext_data = actual_data['subinterfaces']['subinterface'][0]['openconfig-if-ip:ipv4']['state']['counters']
                        valid_output = True
                else:
                    if actual_data.get('openconfig-if-ethernet:ethernet') and actual_data['openconfig-if-ethernet:ethernet'].get('state') and actual_data['openconfig-if-ethernet:ethernet']['state'].get('counters'):
                        counters_ext_data = actual_data['openconfig-if-ethernet:ethernet']['state']['counters']
                        valid_output = True
            if actual_data['state']['name'].startswith('Vl'):
                if actual_data.get('openconfig-vlan:routed-vlan') and actual_data['openconfig-vlan:routed-vlan'].get('openconfig-if-ip:ipv4') and actual_data['openconfig-vlan:routed-vlan']['openconfig-if-ip:ipv4'].get('state') and actual_data['openconfig-vlan:routed-vlan']['openconfig-if-ip:ipv4']['state'].get('counters'):
                    counters_data = actual_data['openconfig-vlan:routed-vlan']['openconfig-if-ip:ipv4']['state']['counters']
                    valid_output = True
            else:
                valid_output = True

        # Adding support for sub-intf.
        elif isinstance(data, dict) and data.get('openconfig-interfaces:subinterface') and isinstance(data['openconfig-interfaces:subinterface'], list):
            flag_sub_intf = True
            actual_data = data['openconfig-interfaces:subinterface'][0]
            v4v6 = {}
            v4v6 = actual_data.get('openconfig-if-ip:ipv4', actual_data.get('openconfig-if-ip:ipv6', ''))
            if v4v6 != '':
                if v4v6.get('state') and v4v6['state'].get('counters'):
                    counters_data = v4v6['state']['counters']
                    valid_output = True
            if rif == "yes":
                if actual_data['openconfig-if-ip:ipv4']['state']['counters']:
                    counters_ext_data = actual_data['openconfig-if-ip:ipv4']['state']['counters']
                    valid_output = True

        if not valid_output:
            st.error('interface counters GET data is not as per format')
            st.debug('Provided data: {}'.format(data))
            return ret_val

        temp = {}
        if flag_sub_intf:
            temp['iface'] = ''
            temp['state'] = ''
        else:
            temp['iface'] = actual_data['state']['name']
            temp['state'] = actual_data['state']['oper-status'].upper()[0] if len(actual_data['state']['oper-status']) >= 1 else ''

        if counter_type == 'basic':
            st.log("counters_data:{}".format(counters_data))
            counters_data_map = {'rx_ok': 'in-pkts', 'rx_err': 'in-errors', 'rx_drp': 'in-discards',
                                 'tx_ok': 'out-pkts', 'tx_err': 'out-errors', 'tx_drp': 'out-discards'}
            temp['rx_bps'] = temp['rx_util'] = ''
            temp['tx_bps'] = temp['tx_util'] = ''
            if temp['iface'].startswith('Vl') or flag_sub_intf:
                counters_data_map = {'rx_ok': 'in-pkts', 'rx_err': 'in-error-pkts', 'rx_bps': 'openconfig-interfaces-ext:in-octets-per-second', 'rx_pps': 'openconfig-interfaces-ext:in-pkts-per-second',
                                     'tx_ok': 'out-pkts', 'tx_err': 'out-error-pkts', 'tx_bps': 'openconfig-interfaces-ext:out-octets-per-second', 'tx_pps': 'openconfig-interfaces-ext:out-pkts-per-second'}

            for tmpl_key, yang_attr in counters_data_map.items():
                temp[tmpl_key] = str(counters_data[yang_attr])

            temp['rx_ovr'] = '0'
            temp['tx_ovr'] = '0'
            if temp['iface'].startswith('Eth'):
                temp['rx_ovr'] = str(counters_ext_data['in-oversize-frames'])
                temp['tx_ovr'] = str(counters_ext_data['out-oversize-frames'])
            if temp['iface'].startswith('Vl'):
                temp['rx_drp'] = '0'
                temp['tx_drp'] = '0'

            ret_val.append(temp)

        if counter_type == "rif_counter":
            st.log("rif_counters_data:{}".format(counters_ext_data))
            if temp['iface'].startswith('Eth') or flag_sub_intf:
                counters_ext_data_map = {'rx_ok': 'in-pkts', 'rx_err': 'in-error-pkts',
                                         'tx_ok': 'out-pkts', 'tx_err': 'out-error-pkts',
                                         'rx_bps': 'openconfig-interfaces-ext:in-octets-per-second',
                                         'tx_bps': 'openconfig-interfaces-ext:out-octets-per-second',
                                         'rx_pps': 'openconfig-interfaces-ext:in-pkts-per-second',
                                         'tx_pps': 'openconfig-interfaces-ext:out-pkts-per-second'}

                temp['rx_util'] = ''
                temp['tx_util'] = ''
                for tmpl_key, yang_attr in counters_ext_data_map.items():
                    temp[tmpl_key] = str(counters_ext_data[yang_attr])
            ret_val.append(temp)

        if counter_type == 'rate':
            temp['rate_interval'] = str(actual_data['state']['rate-interval'])

            counters_data_map = {'rx_mbps': 'in-octets-per-second', 'rx_mbitsps': 'in-bits-per-second', 'rx_pps': 'in-pkts-per-second', 'rx_util': 'in-utilization',
                                 'tx_mbps': 'out-octets-per-second', 'tx_mbitsps': 'out-bits-per-second', 'tx_pps': 'out-pkts-per-second', 'tx_util': 'out-utilization'}

            for tmpl_key, yang_attr in counters_data_map.items():
                temp[tmpl_key] = str(counters_data[yang_attr])

            temp['rx_bps'] = temp['tx_bps'] = '0.0'
            ret_val.append(temp)

        if counter_type == 'detailed':
            counters_data_map = {'pkt_rx_unicast': 'in-unicast-pkts', 'pkt_rx_multicast': 'in-multicast-pkts', 'pkt_rx_broadcast': 'in-broadcast-pkts', 'pkt_rx_without_errors': 'in-pkts',
                                 'pkt_tx_unicast': 'out-unicast-pkts', 'pkt_tx_multicast': 'out-multicast-pkts', 'pkt_tx_broadcast': 'out-broadcast-pkts', 'pkt_tx_successfully': 'out-pkts',
                                 'time_since_counters_last_cleared': 'last-clear'}

            for tmpl_key, yang_attr in counters_data_map.items():
                temp[tmpl_key] = str(counters_data[yang_attr])

            rx_counters_ext_data_map = {
                'pkt_rx_64_octets': 'in-frames-64-octets', 'pkt_rx_65_127_octets': 'in-frames-65-127-octets', 'pkt_rx_128_255_octets': 'in-frames-128-255-octets',
                'pkt_rx_256_511_octets': 'in-frames-256-511-octets', 'pkt_rx_512_1023_octets': 'in-frames-512-1023-octets', 'pkt_rx_1024_1518_octets': 'in-frames-1024-1518-octets',
                'pkt_rx_1519_2047_octets': 'in-frames-1519-2047-octets', 'pkt_rx_2048_4095_octets': 'in-frames-2048-4095-octets',
                'pkt_rx_4096_9216_octets': 'in-frames-4096-9216-octets', 'pkt_rx_9217_16383_octets': 'in-frames-9217-16383-octets', 'pkt_rx_jabbers': 'in-jabber-frames',
                'pkt_rx_fragments': 'in-fragment-frames', 'pkt_rx_undersize': 'in-undersize-frames', 'pkt_rx_overruns': 'in-oversize-frames', 'pkt_rx_crc_errros': 'in-crc-errors',
            }

            for tmpl_key, yang_attr in rx_counters_ext_data_map.items():
                temp[tmpl_key] = '0'
                if temp['iface'].startswith('Eth'):
                    if tmpl_key in ['pkt_rx_jabbers', 'pkt_rx_fragments', 'pkt_rx_undersize', 'pkt_rx_overruns', 'pkt_rx_crc_errros']:
                        temp[tmpl_key] = str(counters_ext_data[yang_attr])
                        continue
                    temp[tmpl_key] = str(counters_ext_data['openconfig-if-ethernet-ext:in-distribution'][yang_attr])

            tx_counters_ext_data_map = {
                'pkt_tx_64_octets': 'out-frames-64-octets', 'pkt_tx_65_127_octets': 'out-frames-65-127-octets', 'pkt_tx_128_255_octets': 'out-frames-128-255-octets',
                'pkt_tx_256_511_octets': 'out-frames-256-511-octets', 'pkt_tx_512_1023_octets': 'out-frames-512-1023-octets', 'pkt_tx_1024_1518_octets': 'out-frames-1024-1518-octets',
                'pkt_tx_1519_2047_octets': 'out-frames-1519-2047-octets', 'pkt_tx_2048_4095_octets': 'out-frames-2048-4095-octets',
                'pkt_tx_4096_9216_octets': 'out-frames-4096-9216-octets', 'pkt_tx_9217_16383_octets': 'out-frames-9217-16383-octets', 'pkt_tx_overruns': 'out-oversize-frames',
            }

            for tmpl_key, yang_attr in tx_counters_ext_data_map.items():
                temp[tmpl_key] = '0'
                if temp['iface'].startswith('Eth'):
                    if tmpl_key in ['pkt_tx_overruns']:
                        temp[tmpl_key] = str(counters_ext_data[yang_attr])
                        continue
                    temp[tmpl_key] = str(counters_ext_data['openconfig-if-ethernet-ext:out-distribution'][yang_attr])

            ret_val.append(temp)

        st.debug(ret_val)
        return ret_val
