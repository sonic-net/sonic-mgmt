from spytest import st
from apis.system.rest import get_rest

invalid_ports = ['vlan', 'eth0']


def process_intf_status_rest_output(data, single_port=True):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param data:
    :type dict:
    :param single_port:
    :type bool:
    :return:
    :rtype:
    """
    ret_val = []
    try: 
        if single_port:
            actaul_data = data['output']['openconfig-interfaces:interface']
        else:
            actaul_data = data['output']['openconfig-interfaces:interfaces']['interface']
        for intf_entry in actaul_data:
            temp = {}
            if any(port in intf_entry['name'].lower() for port in invalid_ports):
                continue
            temp['interface'] =  intf_entry['name']
            if 'description' in intf_entry['state']:
                temp['description'] = intf_entry['state']['description']
            temp['oper'] = intf_entry['state']['oper-status'].lower()
            temp['admin'] = intf_entry['state']['admin-status'].lower()
            temp['mtu'] = str(intf_entry['state']['mtu'])
            port_speed = intf_entry.get('openconfig-if-ethernet:ethernet',{}).get('state',{}).get('port-speed',None)
            temp['speed'] = port_speed.replace('GB', '000').split(":")[1].replace('SPEED_', '') if port_speed else port_speed
            ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.error("{} exception occurred".format(e))
        st.debug("Given data is:{}".format(data))
        st.debug(ret_val)
        return ret_val


def process_intf_counters_rest_output(data, single_port=False):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param data:
    :type dict:
    :param single_port:
    :type bool:
    :return:
    :rtype:
    """
    ret_val = []
    try:
        if single_port:
            actaul_data = data['output']['openconfig-interfaces:interface']
        else:
            actaul_data = data['output']['openconfig-interfaces:interfaces']['interface']
        for intf_entry in actaul_data:
            temp = {}
            if any(port in intf_entry['name'].lower() for port in invalid_ports):
                continue
            temp['iface'] =  intf_entry['name']
            temp['state'] = intf_entry['state']['oper-status'].upper()[0]
            temp['rx_ok'] = intf_entry['state']['counters']['in-pkts']
            temp['rx_err'] = intf_entry['state']['counters']['in-errors']
            temp['rx_drp'] = intf_entry['state']['counters']['in-discards']
            temp['tx_ok'] = intf_entry['state']['counters']['out-pkts']
            temp['tx_err'] = intf_entry['state']['counters']['out-errors']
            temp['tx_drp'] = intf_entry['state']['counters']['out-discards']
            if 'PortChannel' not in intf_entry['name']: ##RX_OVERSIZE and TX_OVERSIZE counters are not available for LAG, reported SONIC-32454
                temp['rx_ovr'] = intf_entry['openconfig-if-ethernet:ethernet']['state']['counters']['in-oversize-frames']
                temp['tx_ovr'] = intf_entry['openconfig-if-ethernet:ethernet']['state']['counters']['openconfig-interfaces-ext:out-oversize-frames']
            ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.error("{} exception occurred".format(e))
        st.debug("Given data is:{}".format(data))
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
    try:
        get_info = get_rest(dut, rest_url=url, timeout=60)
        for entry in get_info['output']['openconfig-qos:queues']['queue']:
            temp = dict()
            counters_info = entry['state']
            port, queue = counters_info['name'].split(':')
            temp['port'] = port
            temp['txq'] = "{}{}".format(counters_info["openconfig-qos-ext:traffic-type"], queue)
            temp['pkts_drop'] = counters_info['dropped-pkts']
            temp['byte_drop'] = counters_info['openconfig-qos-ext:dropped-octets']
            temp['pkts_count'] = counters_info['transmit-pkts']
            temp['byte_count'] = counters_info['transmit-octets']
            ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.error("{} exception occurred".format(e))
        st.log("The output is:{}".format(get_info))
        st.debug(ret_val)
        return ret_val
