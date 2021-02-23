import re
from spytest import st
from apis.system.rest import get_rest


def rest_get_all_portchannel_info(dut):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ret_val = []
    try:
        data = get_rest(dut, rest_url = rest_urls['pc_interfaces_config'])
        portchannel_info = data["output"]["openconfig-lacp:interfaces"]["interface"]
        for entry in portchannel_info:
            temp = {}
            if 'state' not in entry:
                ret_val.extend(get_static_portchannel(dut, entry['name']))
                continue
            temp['name'] = entry['name']
            temp['protocol'] = 'LACP' if entry['state']['lacp-mode'].upper() == 'ACTIVE' else 'Static'
            temp['state'] = get_oper_status(dut, entry['name'])
            temp['group'] = re.search(r"(\d+)", entry['name']).group(0)
            temp['members'] = []
            if 'members' in entry:
                members_info = entry['members']['member']
                for member_info in members_info:
                    members = {}
                    members['port'] = member_info['interface']
                    members['port_state'] = 'U' if member_info['state']['openconfig-interfaces-ext:selected'] else 'D'
                    temp['members'].append(members)
            ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.log("{} exception occurred".format(e))
        st.debug(ret_val)
        return ret_val


def rest_get_per_portchannel_info(dut, portchannel):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param portchannel:
    :type str:
    :return:
    :rtype:
    """
    rest_urls = st.get_datastore(dut, 'rest_urls')
    url = rest_urls['get_pc_type'].format(portchannel)
    data = get_rest(dut, rest_url = url)
    if 'output' in data and "openconfig-if-aggregate:lag-type" in data['output'] and data['output']['openconfig-if-aggregate:lag-type'] == 'STATIC':
        return get_static_portchannel(dut, portchannel)
    url = rest_urls['pc_interface_config'].format(portchannel)
    ret_val = []
    try:
        data = get_rest(dut, rest_url = url)
        portchannel_info = data["output"]['openconfig-lacp:interface'][0]
        temp = {}
        temp['name'] = portchannel_info['name']
        temp['protocol'] = 'LACP' if portchannel_info['state']['lacp-mode'].upper() == 'ACTIVE' else 'Static'
        temp['state'] = get_oper_status(dut, portchannel)
        temp['group'] = re.search(r"(\d+)", portchannel_info['name']).group(0)
        temp['members'] = []
        if 'members' in portchannel_info:
            members_info = portchannel_info['members']['member']
            for member_info in members_info:
                members = {}
                members['port'] = member_info['interface']
                members['port_state'] = 'U' if member_info['state']['openconfig-interfaces-ext:selected'] else 'D'
                temp['members'].append(members)
        ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.log("{} exception occurred".format(e))
        st.debug(ret_val)
        return ret_val


def get_oper_status(dut, interface):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param interface:
    :type str:
    :return:
    :rtype:
    """
    rest_urls = st.get_datastore(dut, 'rest_urls')
    url = rest_urls['config_interface_oper_state'].format(interface)
    try:
        get_info = get_rest(dut, rest_url = url)
        oper_status = 'U' if get_info["output"]["openconfig-interfaces:oper-status"].upper()=='UP' else 'D'
        return oper_status
    except Exception as e:
        st.log("{} exception occurred".format(e))
        return None


def get_static_portchannel(dut, portchannel):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param portchannel:
    :type str:
    :return:
    :rtype:
    """
    rest_urls = st.get_datastore(dut, 'rest_urls')
    url = rest_urls['aggregate_state_get'].format(portchannel)
    ret_val = []
    try:
        lag_info = {}
        get_info = get_rest(dut, rest_url = url)
        get_info = get_info["output"]["openconfig-if-aggregate:state"]
        lag_info['name'] = portchannel
        lag_info['protocol'] = get_info['lag-type'].capitalize()
        lag_info['state'] = get_oper_status(dut, portchannel)
        lag_info['group'] = re.search(r"(\d+)", portchannel).group(0)
        lag_info['members'] = []
        for member in get_info['member']:
            if member:
                member_info = {}
                member_info['port'] = member
                member_info['port_state'] = get_oper_status(dut, member)
                lag_info['members'].append(member_info)
        ret_val.append(lag_info)
        return ret_val
    except Exception as e:
        st.log("{} exception occurred".format(e))
        return ret_val

def rest_get_fallback_status(dut, portchannel):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param portchannel:
    :type str:
    :return:
    :rtype:
    """
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ret_val = []
    try:
        fallback_info = dict()
        url = rest_urls['fallback_oper_status_get'].format(portchannel)
        oper_info = get_rest(dut, rest_url=url)
        url = rest_urls['fallback_enable_config'].format(portchannel)
        enable_info = get_rest(dut, rest_url=url)
        fallback_info['port_channel_name'] = portchannel
        fallback_info['fallback_config'] = 'Enabled' if enable_info['output']['openconfig-interfaces-ext:fallback'] else 'Disabled'
        fallback_info['fallback_oper_status'] = 'Enabled' if oper_info['output']['openconfig-interfaces-ext:fallback'] else 'Disabled'
        ret_val.append(fallback_info)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.error("{} exception occurred".format(e))
        st.debug(ret_val)
        return ret_val