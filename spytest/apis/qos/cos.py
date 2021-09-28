import json, re
from spytest import st
from utilities.utils import get_interface_number_from_name
from utilities.common import make_list, filter_and_select
from apis.system.rest import config_rest, delete_rest, get_rest, rest_status
errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']


def config_port_qos_map(dut, obj_name, interface, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        if not obj_name or not interface:
            st.log("Please provide obj_name like 'AZURE' and interface like 'Ethernet0,Ethernet1'")
            return False
        else:
            cos_specific_dict = {"tc_to_queue_map": obj_name, "dscp_to_tc_map": obj_name}
            temp_data[interface] = cos_specific_dict
        final_data['PORT_QOS_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        intf_data = get_interface_number_from_name(interface)
        commands.append('interface {} {}'.format(intf_data['type'], intf_data['number']))
        commands.append('qos-map tc-queue {}'.format(obj_name))
        commands.append('qos-map dscp-tc {}'.format(obj_name))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['port_qos_map_config'].format(interface)
        port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"dscp-to-forwarding-group": obj_name, "forwarding-group-to-queue": obj_name}}}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=port_qos_map_data):
            st.error("Failed configure PORT_QOS_MAP")
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_port_qos_map_all(dut, qos_maps, cli_type=''):
    """
    To configure port qos map for all types of mappings
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param qos_maps:
    :type qos_maps:
    :param cli_type:
    :type cli_type:
    """
    qos_maps=make_list(qos_maps)
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        for qos_map in qos_maps:
            if qos_map['port'] not in temp_data:
                temp_data[qos_map['port']] = {}
            if qos_map['map'] == 'dot1p_to_tc_map':
                temp_data[qos_map['port']].update(dot1p_to_tc_map="{}".format(qos_map['obj_name']))
            elif qos_map['map'] == 'dscp_to_tc_map':
                temp_data[qos_map['port']].update(dscp_to_tc_map="{}".format(qos_map['obj_name']))
            elif qos_map['map'] == 'pfc_to_queue_map':
                temp_data[qos_map['port']].update(pfc_to_queue_map="{}".format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_dot1p_map':
                temp_data[qos_map['port']].update(tc_to_dot1p_map="{}".format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_dscp_map':
                temp_data[qos_map['port']].update(tc_to_dscp_map="{}".format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_pg_map':
                temp_data[qos_map['port']].update(tc_to_pg_map="{}".format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_queue_map':
                temp_data[qos_map['port']].update(tc_to_queue_map="{}".format(qos_map['obj_name']))
            else:
                st.error('Invalid map: {}'.format(qos_map['map']))
                return False
        final_data['PORT_QOS_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        for qos_map in qos_maps:
            intf_data = get_interface_number_from_name(qos_map['port'])
            commands.append('interface {} {}'.format(intf_data['type'], intf_data['number']))
            if qos_map['map'] == 'dot1p_to_tc_map':
                commands.append('qos-map dot1p-tc {}'.format(qos_map['obj_name']))
            elif qos_map['map'] == 'dscp_to_tc_map':
                commands.append('qos-map dscp-tc {}'.format(qos_map['obj_name']))
            elif qos_map['map'] == 'pfc_to_queue_map':
                commands.append('qos-map pfc-priority-queue {}'.format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_dot1p_map':
                commands.append('qos-map tc-dot1p {}'.format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_dscp_map':
                commands.append('qos-map tc-dscp {}'.format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_pg_map':
                commands.append('qos-map tc-pg {}'.format(qos_map['obj_name']))
            elif qos_map['map'] == 'tc_to_queue_map':
                commands.append('qos-map tc-queue {}'.format(qos_map['obj_name']))
            else:
                st.error('Invalid map: {}'.format(qos_map['map']))
                return False
            commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for qos_map in qos_maps:
            url = rest_urls['port_qos_map_config'].format(qos_map['port'])
            if qos_map['map'] == 'dot1p_to_tc_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"dot1p-to-forwarding-group": qos_map['obj_name']}}}
            elif qos_map['map'] == 'dscp_to_tc_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"dscp-to-forwarding-group": qos_map['obj_name']}}}
            elif qos_map['map'] == 'pfc_to_queue_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"pfc-priority-to-queue": qos_map['obj_name']}}}
            elif qos_map['map'] == 'tc_to_dot1p_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"forwarding-group-to-dot1p": qos_map['obj_name']}}}
            elif qos_map['map'] == 'tc_to_dscp_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"forwarding-group-to-dscp": qos_map['obj_name']}}}
            elif qos_map['map'] == 'tc_to_pg_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"forwarding-group-to-priority-group": qos_map['obj_name']}}}
            elif qos_map['map'] == 'tc_to_queue_map':
                port_qos_map_data = {"openconfig-qos-maps-ext:interface-maps": {"config": {"forwarding-group-to-queue": qos_map['obj_name']}}}
            else:
                st.error('Invalid map: {}'.format(qos_map['map']))
                return False
        
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=port_qos_map_data):
                st.error("Failed configure PORT_QOS_MAP")
                return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_tc_to_queue_map(dut, obj_name, tc_to_queue_map_dict, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        tc_to_queue_map_dict = get_non_range_map_data_from_range_map_data(tc_to_queue_map_dict)
        if not tc_to_queue_map_dict or not obj_name:
            st.log("Please provide traffic class to queue map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = tc_to_queue_map_dict
        final_data['TC_TO_QUEUE_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map tc-queue {}'.format(obj_name))
        for tc, queue in tc_to_queue_map_dict.items():
            commands.append('traffic-class {} queue {}'.format(tc, queue))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['tc_queue_map_config']
        tc_to_queue_map_dict = get_non_range_map_data_from_range_map_data(tc_to_queue_map_dict)
        maps_data = [{'fwd-group': str(tc), 'config': {'fwd-group': str(tc), 'output-queue-index': int(queue)}} for tc, queue in tc_to_queue_map_dict.items()]
        tc_queue_map_data = {"openconfig-qos-maps-ext:forwarding-group-queue-map": [{"name": obj_name, "config": {"name": obj_name}, "forwarding-group-queue-map-entries": {"forwarding-group-queue-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=tc_queue_map_data):
            st.error("Failed to map TC to QUEUE with data: {}".format(tc_to_queue_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_dscp_to_tc_map(dut, obj_name, dscp_to_tc_map_dict, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        dscp_to_tc_map_dict = get_non_range_map_data_from_range_map_data(dscp_to_tc_map_dict)
        if not dscp_to_tc_map_dict or not obj_name:
            st.log("Please provide dscp value to traffic priority value map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = dscp_to_tc_map_dict
        final_data['DSCP_TO_TC_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map dscp-tc {}'.format(obj_name))
        for dscp, tc in dscp_to_tc_map_dict.items():
            commands.append('dscp {} traffic-class {}'.format(dscp, tc))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['dscp_tc_map_config']
        dscp_to_tc_map_dict = get_non_range_map_data_from_range_map_data(dscp_to_tc_map_dict)
        maps_data = [{"dscp": int(dscp), "config": {"dscp": int(dscp), "fwd-group": str(tc)}} for dscp, tc in dscp_to_tc_map_dict.items()]
        dscp_tc_map_data = {"openconfig-qos-maps-ext:dscp-map": [{"name": obj_name, "config": {"name": obj_name}, "dscp-map-entries": {"dscp-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=dscp_tc_map_data):
            st.error("Failed to map DSCP to TC with data: {}".format(dscp_to_tc_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_tc_to_pg_map(dut, obj_name, tc_to_pg_map_dict, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        tc_to_pg_map_dict = get_non_range_map_data_from_range_map_data(tc_to_pg_map_dict)
        if not tc_to_pg_map_dict or not obj_name:
            st.log("Please provide traffic class to priority group map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = tc_to_pg_map_dict
        final_data['TC_TO_PRIORITY_GROUP_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map tc-pg {}'.format(obj_name))
        for tc, pg in tc_to_pg_map_dict.items():
            commands.append('traffic-class {} priority-group {}'.format(tc, pg))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['tc_pg_map_config']
        tc_to_pg_map_dict = get_non_range_map_data_from_range_map_data(tc_to_pg_map_dict)
        maps_data = [{"fwd-group": str(tc), "config": {"fwd-group": str(tc), "priority-group-index": int(pg)}} for tc, pg in tc_to_pg_map_dict.items()]
        tc_pg_map_data = {"openconfig-qos-maps-ext:forwarding-group-priority-group-map": [{"name": obj_name, "config": {"name": obj_name}, "forwarding-group-priority-group-map-entries": {"forwarding-group-priority-group-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=tc_pg_map_data):
            st.error("Failed to map TC to PG with data: {}".format(tc_to_pg_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_dot1p_to_tc_map(dut, obj_name, dot1p_to_tc_map_dict, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To map the dot1p to tc
    :param dut:
    :type dut:
    :param obj_name:
    :type obj_name:
    :param dot1p_to_tc_map_dict:
    :type dict:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        dot1p_to_tc_map_dict = get_non_range_map_data_from_range_map_data(dot1p_to_tc_map_dict)
        if not dot1p_to_tc_map_dict or not obj_name:
            st.log("Please provide dot1p value to traffic class value map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = dot1p_to_tc_map_dict
        final_data['DOT1P_TO_TC_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map dot1p-tc {}'.format(obj_name))
        for dot1p, tc in dot1p_to_tc_map_dict.items():
            commands.append('dot1p {} traffic-class {}'.format(dot1p, tc))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['dot1p_tc_map_config'].format(obj_name)
        dot1p_to_tc_map_dict = get_non_range_map_data_from_range_map_data(dot1p_to_tc_map_dict)
        maps_data = [{"dot1p": int(dot1p), "config": {"dot1p": int(dot1p), "fwd-group": str(tc)}} for dot1p, tc in dot1p_to_tc_map_dict.items()]
        dot1p_tc_map_data = {"openconfig-qos-maps-ext:dot1p-map": [{"name": obj_name, "config": {"name": obj_name}, "dot1p-map-entries": {"dot1p-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=dot1p_tc_map_data):
            st.error("Failed to map DOT1P to TC with data: {}".format(dot1p_to_tc_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_pfc_priority_to_queue_map(dut, obj_name, pfc_priority_to_queue_map_dict, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To map the PFC priority to queue
    :param dut:
    :type dut:
    :param obj_name:
    :type obj_name:
    :param pfc_priority_to_queue_map_dict:
    :type dict:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        pfc_priority_to_queue_map_dict = get_non_range_map_data_from_range_map_data(pfc_priority_to_queue_map_dict)
        if not pfc_priority_to_queue_map_dict or not obj_name:
            st.log("Please provide pfc priority to queue map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = pfc_priority_to_queue_map_dict
        final_data['MAP_PFC_PRIORITY_TO_QUEUE'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map pfc-priority-queue {}'.format(obj_name))
        for pfc_priority, queue in pfc_priority_to_queue_map_dict.items():
            commands.append('pfc-priority {} queue {}'.format(pfc_priority, queue))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pfc_priority_queue_map_config']
        pfc_priority_to_queue_map_dict = get_non_range_map_data_from_range_map_data(pfc_priority_to_queue_map_dict)
        maps_data = [{"dot1p": int(dot1p), "config": {"dot1p": int(dot1p), "output-queue-index": int(queue)}} for dot1p, queue in pfc_priority_to_queue_map_dict.items()]
        pfc_priority_queue_map_data = {"openconfig-qos-maps-ext:pfc-priority-queue-map": [{"name": obj_name, "config": {"name": obj_name}, "pfc-priority-queue-map-entries": {"pfc-priority-queue-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=pfc_priority_queue_map_data):
            st.error("Failed to map PFC_PRIORITY to QUEUE with data: {}".format(pfc_priority_to_queue_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_tc_to_dot1p_map(dut, obj_name, tc_to_dot1p_map_dict, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To map the tc to dot1p
    :param dut:
    :type dut:
    :param obj_name:
    :type obj_name:
    :param tc_to_dot1p_map_dict:
    :type dict:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        tc_to_dot1p_map_dict = get_non_range_map_data_from_range_map_data(tc_to_dot1p_map_dict)
        if not tc_to_dot1p_map_dict or not obj_name:
            st.log("Please provide traffic class to dot1p map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = tc_to_dot1p_map_dict
        final_data['TC_TO_DOT1P_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map tc-dot1p {}'.format(obj_name))
        for tc, dot1p in tc_to_dot1p_map_dict.items():
            commands.append('traffic-class {} dot1p {}'.format(tc, dot1p))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['tc_dot1p_map_config']
        tc_to_dot1p_map_dict = get_non_range_map_data_from_range_map_data(tc_to_dot1p_map_dict)
        maps_data = [{"fwd-group": str(tc), "config": {"fwd-group": str(tc), "dot1p": int(dot1p)}} for tc, dot1p in tc_to_dot1p_map_dict.items()]
        tc_dot1p_map_data = {"openconfig-qos-maps-ext:forwarding-group-dot1p-map": [{"name": obj_name, "config": {"name": obj_name}, "forwarding-group-dot1p-map-entries": {"forwarding-group-dot1p-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=tc_dot1p_map_data):
            st.error("Failed to map TC to DOT1P with data: {}".format(tc_to_dot1p_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_tc_to_dscp_map(dut, obj_name, tc_to_dscp_map_dict, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To map the tc to dscp
    :param dut:
    :type dut:
    :param obj_name:
    :type obj_name:
    :param tc_to_dscp_map_dict:
    :type dict:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        final_data = dict()
        temp_data = dict()
        tc_to_dscp_map_dict = get_non_range_map_data_from_range_map_data(tc_to_dscp_map_dict)
        if not tc_to_dscp_map_dict or not obj_name:
            st.log("Please provide traffic class to dscp map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
            return False
        else:
            temp_data[obj_name] = tc_to_dscp_map_dict
        final_data['TC_TO_DSCP_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        commands.append('qos map tc-dscp {}'.format(obj_name))
        for tc, dscp in tc_to_dscp_map_dict.items():
            commands.append('traffic-class {} dscp {}'.format(tc, dscp))
        commands.append('exit')
        response = st.config(dut, commands, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'rest-patch'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['tc_dscp_map_config'].format(obj_name)
        tc_to_dscp_map_dict = get_non_range_map_data_from_range_map_data(tc_to_dscp_map_dict)
        maps_data = [{"fwd-group": str(tc), "config": {"fwd-group": str(tc), "dscp": int(dscp)}} for tc, dscp in tc_to_dscp_map_dict.items()]
        tc_dscp_map_data = {"openconfig-qos-maps-ext:forwarding-group-dscp-map": [{"name": obj_name, "config": {"name": obj_name}, "forwarding-group-dscp-map-entries": {"forwarding-group-dscp-map-entry": maps_data}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=tc_dscp_map_data):
            st.error("Failed to map TC to DSCP with data: {}".format(tc_to_dscp_map_dict))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def clear_qos_map_entries(dut, map_type, obj_name, maps_dict, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To clear qos map entries
    :param dut:
    :type dut:
    :param map_type:
    :type map_type:
    :param obj_name:
    :type obj_name:
    :param maps_dict:
    :type maps_dict:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    qos_clear = kwargs.get('qos_clear', False)
    if (not qos_clear) and cli_type=='click':
        cli_type = 'klish'
    if cli_type=='click':
        command = 'config qos clear'
        response = st.config(dut, command, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type == 'klish':
        commands = list()
        if map_type == 'dot1p_to_tc_map':
            commands.append('qos map dot1p-tc {}'.format(obj_name))
            commands.extend(['no dot1p {}'.format(map) for map in maps_dict.keys()])
        elif map_type == 'dscp_to_tc_map':
            commands.append('qos map dscp-tc {}'.format(obj_name))
            commands.extend(['no dscp {}'.format(map) for map in maps_dict.keys()])
        elif map_type == 'pfc_to_queue_map':
            commands.append('qos map pfc-priority-queue {}'.format(obj_name))
            commands.extend(['no pfc-priority {}'.format(map) for map in maps_dict.keys()])
        elif map_type == 'tc_to_dot1p_map':
            commands.append('qos map tc-dot1p {}'.format(obj_name))
            commands.extend(['no traffic-class {}'.format(map) for map in maps_dict.keys()])
        elif map_type== 'tc_to_dscp_map':
            commands.append('qos map tc-dscp {}'.format(obj_name))
            commands.extend(['no traffic-class {}'.format(map) for map in maps_dict.keys()])
        elif map_type == 'tc_to_pg_map':
            commands.append('qos map tc-pg {}'.format(obj_name))
            commands.extend(['no traffic-class {}'.format(map) for map in maps_dict.keys()])
        elif map_type == 'tc_to_queue_map':
            commands.append('qos map tc-queue {}'.format(obj_name))
            commands.extend(['no traffic-class {}'.format(map) for map in maps_dict.keys()])
        else:
            st.error('Invalid map type: {}'.format(map_type))
            return False
        if commands:
            commands.append('exit')
            response = st.config(dut, commands, type=cli_type)
            if any(error in response.lower() for error in errors_list):
                st.error("The response is: {}".format(response))
                return False
    elif cli_type in['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        urls_map = {'dot1p_to_tc_map': rest_urls['dot1p_tc_entry_config'],
                    'dscp_to_tc_map': rest_urls['dscp_tc_entry_config'],
                    'pfc_to_queue_map': rest_urls['pfc_priority_queue_entry_config'],
                    'tc_to_dot1p_map': rest_urls['tc_dot1p_entry_config'],
                    'tc_to_dscp_map': rest_urls['tc_dscp_entry_config'],
                    'tc_to_pg_map':  rest_urls['tc_pg_entry_config'],
                    'tc_to_queue_map': rest_urls['tc_queue_entry_config']}
        if map_type in urls_map:
            url = urls_map[map_type]
        else:
            st.error('Invalid map type: {}'.format(map_type))
            return False
        for map in maps_dict.keys():
            if not delete_rest(dut, rest_url = url.format(obj_name, map)):
                st.error("Failed to remove entry {} for {}".format(map, map_type))
                return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def clear_qos_map_table(dut, qos_maps, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To clear qos map table
    :param dut:
    :type dut:
    :param qos_maps:
    :type qos_maps:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    qos_maps = make_list(qos_maps)
    qos_clear = kwargs.get('qos_clear', False)
    skip_error = kwargs.get('skip_error', False)
    error_msg = kwargs.get('error_msg', False)
    errors = make_list(error_msg) if error_msg else errors_list
    if (not qos_clear) and cli_type=='click':
        cli_type = 'klish'
    if cli_type == 'click':
        command = 'config qos clear'
        response = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type == 'klish':
        commands = list()
        for qos_map in qos_maps:
            commands_map = {'dot1p_to_tc_map': "no qos map dot1p-tc {}",
                            'dscp_to_tc_map': "no qos map dscp-tc {}",
                            'pfc_to_queue_map': "no qos map pfc-priority-queue {}",
                            'tc_to_dot1p_map': "no qos map tc-dot1p {}",
                            'tc_to_dscp_map': "no qos map tc-dscp {}",
                            'tc_to_pg_map': "no qos map tc-pg {}",
                            'tc_to_queue_map': "no qos map tc-queue {}"}
            if qos_map['map'] in commands_map:
                commands.append(commands_map[qos_map['map']].format(qos_map['obj_name']))
            else:
                st.error('Invalid map type: {}'.format(qos_map['map']))
                return False
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for qos_map in qos_maps:
            urls_map = {'dot1p_to_tc_map': rest_urls['dot1p_tc_table_config'],
                        'dscp_to_tc_map': rest_urls['dscp_tc_table_config'],
                        'pfc_to_queue_map': rest_urls['pfc_priority_queue_table_config'],
                        'tc_to_dot1p_map': rest_urls['tc_dot1p_table_config'],
                        'tc_to_dscp_map': rest_urls['tc_dscp_table_config'],
                        'tc_to_pg_map': rest_urls['tc_pg_table_config'],
                        'tc_to_queue_map': rest_urls['tc_queue_table_config']}
            if qos_map['map'] in urls_map:
                url = urls_map[qos_map['map']].format(qos_map['obj_name'])
            else:
                st.error('Invalid map type: {}'.format(qos_map['map']))
                return False
            if skip_error:
                out = delete_rest(dut, rest_url=url, get_response=True)
                error_resp = str(out['output']).lower()
                if ((not rest_status(int(out['status']))) and any(error.lower() in error_resp for error in errors)):
                    st.error("Failed clear {} table: {}".format(qos_map['map'], qos_map['obj_name']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed clear {} table: {}".format(qos_map['map'], qos_map['obj_name']))
                    return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def clear_port_qos_map_all(dut, qos_maps, **kwargs):
    """
    To clear port qos map for all types of mappings
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param qos_maps:
    :type qos_maps:
    :param cli_type:
    :type cli_type:
    """
    qos_maps=make_list(qos_maps)
    cli_type = st.get_ui_type(dut, **kwargs)
    qos_clear = kwargs.get('qos_clear', False)
    if (not qos_clear) and cli_type=='click':
        cli_type = 'klish'
    if cli_type == 'click':
        command = 'config qos clear'
        response = st.config(dut, command, type=cli_type)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False

    elif cli_type == 'klish':
        commands = list()
        for qos_map in qos_maps:
            intf_data = get_interface_number_from_name(qos_map['port'])
            commands_map = {'dot1p_to_tc_map': "no qos-map dot1p-tc",
                            'dscp_to_tc_map': "no qos-map dscp-tc",
                            'pfc_to_queue_map': "no qos-map pfc-priority-queue",
                            'tc_to_dot1p_map': "no qos-map tc-dot1p",
                            'tc_to_dscp_map': "no qos-map tc-dscp",
                            'tc_to_pg_map': "no qos-map tc-pg",
                            'tc_to_queue_map': "no qos-map tc-queue"}
            if qos_map['map'] in commands_map:
                commands.append('interface {} {}'.format(intf_data['type'], intf_data['number']))
                commands.append(commands_map[qos_map['map']])
                commands.append('exit')
            else:
                st.error('Invalid map type: {}'.format(qos_map['map']))
                return False

        if commands:
            response = st.config(dut, commands, type=cli_type)
            if any(error in response.lower() for error in errors_list):
                st.error("The response is: {}".format(response))
                return False

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for qos_map in qos_maps:
            urls_map = {'dot1p_to_tc_map': rest_urls['port_qos_dot1p_tc_map_config'],
                        'dscp_to_tc_map': rest_urls['port_qos_dscp_tc_map_config'],
                        'pfc_to_queue_map': rest_urls['port_qos_pfc_queue_map_config'],
                        'tc_to_dot1p_map': rest_urls['port_qos_tc_dot1p_map_config'],
                        'tc_to_dscp_map': rest_urls['port_qos_tc_dscp_map_config'],
                        'tc_to_pg_map': rest_urls['port_qos_tc_pg_map_config'],
                        'tc_to_queue_map': rest_urls['port_qos_tc_queue_map_config']}
            if qos_map['map'] in urls_map:
                url = urls_map[qos_map['map']].format(qos_map['port'])
            else:
                st.error('Invalid map type: {}'.format(qos_map['map']))
                return False
            if not delete_rest(dut, rest_url=url):
                st.error("Failed clear {} table on port: {}".format(qos_map['map'], qos_map['port']))
                return False

    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def show_qos_map_table(dut, type, obj_name='', **kwargs):
    """
    To show qos map tables
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param type:
    :type type:
    :param obj_name:
    :type obj_name:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        if type == 'dot1p_to_tc_map':
            command = 'show qos map dot1p-tc {}'.format(obj_name) if obj_name else 'show qos map dot1p-tc'
        elif type == 'dscp_to_tc_map':
            command = 'show qos map dscp-tc {}'.format(obj_name) if obj_name else 'show qos map dscp-tc'
        elif type == 'pfc_to_queue_map':
            command = 'show qos map pfc-priority-queue {}'.format(obj_name) if obj_name else 'show qos map pfc-priority-queue'
        elif type == 'tc_to_dot1p_map':
            command = 'show qos map tc-dot1p {}'.format(obj_name) if obj_name else 'show qos map tc-dot1p'
        elif type == 'tc_to_dscp_map':
            command = 'show qos map tc-dscp {}'.format(obj_name) if obj_name else 'show qos map tc-dscp'
        elif type == 'tc_to_pg_map':
            command = 'show qos map tc-pg {}'.format(obj_name) if obj_name else 'show qos map tc-pg'
        elif type == 'tc_to_queue_map':
            command = 'show qos map tc-queue {}'.format(obj_name) if obj_name else 'show qos map tc-queue'
        else:
            st.error("Invalid type: {}".format(type))
            return False
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        key_maps = {"dot1p_to_tc_map": "openconfig-qos-maps-ext:dot1p-map", "dscp_to_tc_map": "openconfig-qos-maps-ext:dscp-map", "pfc_to_queue_map": "openconfig-qos-maps-ext:pfc-priority-queue-map", "tc_to_dot1p_map": "openconfig-qos-maps-ext:forwarding-group-dot1p-map", "tc_to_dscp_map": "openconfig-qos-maps-ext:forwarding-group-dscp-map", "tc_to_pg_map": "openconfig-qos-maps-ext:forwarding-group-priority-group-map", "tc_to_queue_map": "openconfig-qos-maps-ext:forwarding-group-queue-map"}
        if type == 'dot1p_to_tc_map':
            url = rest_urls['dot1p_tc_table_config'].format(obj_name) if obj_name else rest_urls['dot1p_tc_table_all_config']
        elif type == 'dscp_to_tc_map':
            url = rest_urls['dscp_tc_table_config'].format(obj_name) if obj_name else rest_urls['dscp_tc_table_all_config']
        elif type == 'pfc_to_queue_map':
            url = rest_urls['pfc_priority_queue_table_config'].format(obj_name) if obj_name else rest_urls['pfc_priority_queue_table_all_config']
        elif type == 'tc_to_dot1p_map':
            url = rest_urls['tc_dot1p_table_config'].format(obj_name) if obj_name else rest_urls['tc_dot1p_table_all_config']
        elif type == 'tc_to_dscp_map':
            url = rest_urls['tc_dscp_table_config'].format(obj_name) if obj_name else rest_urls['tc_dscp_table_all_config']
        elif type == 'tc_to_pg_map':
            url = rest_urls['tc_pg_table_config'].format(obj_name) if obj_name else rest_urls['tc_pg_table_all_config']
        elif type == 'tc_to_queue_map':
            url = rest_urls['tc_queue_table_config'].format(obj_name) if obj_name else rest_urls['tc_queue_table_all_config']
        else:
            st.error("Invalid type: {}".format(type))
            return False
        total_output = get_rest(dut, rest_url=url)
        if total_output['output']:
            output = _get_rest_qos_map_output(total_output['output'][key_maps[type]], type)
        else:
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return output


def _get_rest_qos_map_output(data, table):
    """
    To process and return the REST qos map output
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param data:
    :type data:
    :param table:
    :type table:
    """
    table_map = {'dot1p_to_tc_map': {'parent': 'dot1p-map-entries', 'child': 'dot1p-map-entry', 'attr': 'dot1p,tc,dot1p,fwd-group'},
                 'dscp_to_tc_map': {'parent': 'dscp-map-entries', 'child': 'dscp-map-entry', 'attr': 'dscp,tc,dscp,fwd-group'},
                 'pfc_to_queue_map': {'parent': 'pfc-priority-queue-map-entries', 'child': 'pfc-priority-queue-map-entry', 'attr': 'pfc_priority,queue,dot1p,output-queue-index'},
                 'tc_to_dot1p_map': {'parent': 'forwarding-group-dot1p-map-entries', 'child': 'forwarding-group-dot1p-map-entry', 'attr': 'tc,dot1p,fwd-group,dot1p'},
                 'tc_to_dscp_map': {'parent': 'forwarding-group-dscp-map-entries', 'child': 'forwarding-group-dscp-map-entry', 'attr': 'tc,dscp,fwd-group,dscp'},
                 'tc_to_pg_map': {'parent': 'forwarding-group-priority-group-map-entries', 'child': 'forwarding-group-priority-group-map-entry', 'attr':'tc,pg,fwd-group,priority-group-index'},
                 'tc_to_queue_map': {'parent': 'forwarding-group-queue-map-entries', 'child': 'forwarding-group-queue-map-entry', 'attr': 'tc,queue,fwd-group,output-queue-index'}}
    if table not in table_map:
        st.error("Invalid map: {}".format(table))
        return False
    fields = table_map[table]
    retval = list()
    try:
        for entry in data:
            if fields['parent'] in entry:
                mappings = entry[fields['parent']][fields['child']]
                for mapping in mappings:
                    attr = fields['attr'].split(',')
                    temp = dict()
                    temp['table'] = entry['name']
                    temp[attr[0]] = str(mapping['state'][attr[2]])
                    temp[attr[1]] = str(mapping['state'][attr[3]])
                    retval.append(temp)
        st.debug(retval)
        return retval
    except Exception as e:
        st.error("{} exception occurred".format(e))
        st.debug("Given data is:{}".format(data))
        st.debug("Given table is:{}".format(table))
        st.debug(retval)
        return retval


def verify_qos_map_table(dut, type, obj_name, mapping_dict, **kwargs):
    """
    To verify qos map tables
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param type:
    :type type: supported types: ['dot1p_to_tc_map', 'dscp_to_tc_map', 'pfc_to_queue_map', 'tc_to_dot1p_map', 'tc_to_dscp_map', 'tc_to_pg_map', 'tc_to_queue_map']
    :param obj_name:
    :type obj_name:
    :param mapping_dict:
    :type mapping_dict:
    Eg: verify_qos_map_table(vars.D1, 'pfc_to_queue_map', 'AZURE', {"1": "1", "2": "2"})
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_qos_map_table(dut, type, obj_name, cli_type=cli_type)
    mapping_dict = get_non_range_map_data_from_range_map_data(mapping_dict)
    if output:
        params_map = {'dot1p_to_tc_map': ['dot1p', 'tc'], 'dscp_to_tc_map': ['dscp', 'tc'], 'pfc_to_queue_map': ['pfc_priority', 'queue'], 'tc_to_dot1p_map': ['tc', 'dot1p'], 'tc_to_dscp_map': ['tc', 'dscp'], 'tc_to_pg_map': ['tc', 'pg'], 'tc_to_queue_map': ['tc', 'queue']}
        param1, param2 = params_map[type]
        for key, value in mapping_dict.items():
            match = {'table': obj_name, param1: str(key), param2: str(value)}
            ent = filter_and_select(output, None, match)
            if not ent:
                st.error("entry not found for {}: {}, {}: {} in {}: {}".format(param1, key, param2, value, type, obj_name))
                return False
    return True


def get_non_range_map_data_from_range_map_data(dict_data):
    """
    To get the non-range map data from range map data
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dict_data:
    :type dict_data:
    """
    retval = dict()
    for key,value in dict_data.items():
        temp=list()
        key, value = str(key).replace(" ", "").replace(",", " "), str(value)
        range_entries=re.findall(r'\d+\-\d+', key)
        if range_entries:
            for entry in range_entries:key=key.replace(entry, "")
            for entry in range_entries:
                ents=entry.split("-")
                temp.extend([str(i) for i in range(int(ents[0]), int(ents[1])+1)])
        temp.extend(re.findall(r"\d+", key))
        retval.update({i:value for i in temp})
    st.debug("The updated non-range map data is: {}".format(retval))
    return retval
