from spytest import st
from apis.system.rest import get_rest

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
            temp['admin'] = intf_entry['state']['admin-status'].lower() if intf_entry.get('state') and intf_entry['state'].get('admin-status') else ''
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


def process_intf_counters_rest_output(data):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param data:
    :type dict:
    :type bool:
    :return:
    :rtype:
    """
    ret_val = list()
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
            temp['state'] = intf_entry['state']['oper-status'].upper()[0] if intf_entry.get('state') and intf_entry['state'].get('oper-status') and len(intf_entry['state']['oper-status']) >=1 else ''
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
                temp['txq'] = '{}{}'.format(counters_info['openconfig-qos-ext:traffic-type'], queue) if counters_info.get('openconfig-qos-ext:traffic-type') else '{}{}'.format('NA', queue)
                temp['pkts_drop'] = str(counters_info.get('dropped-pkts', '0'))
                temp['byte_drop'] = str(counters_info.get('openconfig-qos-ext:dropped-octets', '0'))
                temp['pkts_count'] = str(counters_info.get('transmit-pkts', '0'))
                temp['byte_count'] = str(counters_info.get('transmit-octets', '0'))
                ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    else:
        st.debug('Provided data: {}'.format(get_info))
        st.debug(ret_val)
        return ret_val
