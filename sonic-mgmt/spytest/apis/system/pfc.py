import json

from spytest import st
from apis.system.interface import interface_status_show, clear_interface_counters
from spytest.utils import filter_and_select
from utilities.common import make_list
from utilities.utils import get_interface_number_from_name
from apis.system.rest import config_rest, delete_rest, get_rest

errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']


def config_pfc_asymmetric(dut, mode, interface = [], **kwargs):
    """
    To configure asymmetric mode on ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param type:
    :type on|off:
    :param interface:
    :type list():
    :param cli_type:
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    if mode not in ['on','off'] or not interface:
        st.error("Mode can take on|off values only, interface cannot be empty")
        return False
    interface = make_list(interface)
    commands = list()
    if cli_type == 'click':
        for intf in interface:
            intf = st.get_other_names(dut, [intf])[0] if '/' in intf else intf
            commands.append("sudo pfc config asymmetric {} {}".format(mode,intf))
    elif cli_type == 'klish':
        no_form = "" if mode == 'on' else "no"
        for intf in interface:
            intf_data = get_interface_number_from_name(intf)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("{} priority-flow-control asymmetric".format(no_form))
            commands.append("exit")
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        asym = True if mode == 'on' else False
        config_data = {"openconfig-qos-ext:config": {"asymmetric": asym}}
        for intf in interface:
            url = rest_urls['pfc_asymmetric_config'].format(intf)
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
                st.error("Failed to configure asymmetric mode: {} on port: {}".format(mode, intf))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def config_pfc_lossless_queues(dut, queues_list, ports_list, **kwargs):
    """
    To configure lossless priorities on port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param queues_list:
    :type list:
    :param cli_type:
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', True)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    cli_type = 'klish' if skip_error and cli_type == 'click' else cli_type
    ports = make_list(ports_list)
    queues = make_list(queues_list)
    if cli_type == 'click':
        queues = ",".join([str(queue) for queue in queues]) if config else ""
        final_data = dict()
        temp_data = dict()
        for port in ports:
            port = st.get_other_names(dut, [port])[0] if '/' in port else port
            temp_data[port] = {"pfc_enable": queues}
        final_data['PORT_QOS_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json2(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        no_form = "" if config else "no"
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            commands.append('interface {} {}'.format(intf_data['type'], intf_data['number']))
            commands.extend(['{} priority-flow-control priority {}'.format(no_form, queue) for queue in queues])
            commands.append('exit')
            response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
            if any(error.lower() in response.lower() for error in errors):
                st.error("The response is: {}".format(response))
                return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        message = "loss-less" if config else "lossy"
        for port in ports:
            for queue in queues:
                url = rest_urls['pfc_lossless_queue_config'].format(port)
                config_data = {"openconfig-qos-ext:pfc-priorities": {"pfc-priority": [{"dot1p": int(queue), "config": {"dot1p": int(queue), "enable": config}}]}}
                if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to configure the priority: {} as {} on port: {}".format(queue, message, port))
                    return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def verify_pfc_asymmetric(dut, ports, mode, cli_type=''):
    """
    To configure lossless priorities on port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param ports:
    :type list:
    :param mode:
    :type on/off:
    :param cli_type:
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    ports = make_list(ports)
    if mode not in ['on', 'off']:
        st.error("Mode can take on|off values only")
        return False
    if cli_type == 'click':
        command = "pfc show asymmetric"
        output = st.show(dut, command, type=cli_type)
        asym_mode = ['off', 'N/A'] if mode == 'off' else 'on'
        for port in ports:
            port = st.get_other_names(dut, [port])[0] if '/' in port else port
            entry = filter_and_select(output, ['pfc_asymmetric'], {'interface': port})
            if not (len(entry) and entry[0]['pfc_asymmetric'] in asym_mode):
                st.error('Provided asymmetric mode: {} not matching with the actual mode: {} on port: {}'.format(mode, asym_mode, port))
                return False
    elif cli_type == 'klish':
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            command = "show qos interface {} {}".format(intf_data['type'], intf_data['number'])
            output = st.show(dut, command, type=cli_type)
            entry = filter_and_select(output, None, {'pfc_asymmetric': mode})
            if not entry:
                st.error('Provided asymmetric mode: {} not matching with the actual mode on port: {}'.format(mode, port))
                return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        asym_mode = True if mode=='on' else False
        verify_payload = {"openconfig-qos-ext:asymmetric": asym_mode}
        for port in ports:
            url = rest_urls['pfc_asymmetric_get'].format(port)
            out = get_rest(dut, rest_url = url)
            if not out['output'] == verify_payload:
                st.error('Provided asymmetric mode: {} not matching with the actual mode on port: {}'.format(mode, port))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def start_pfc_wd(dut,action,detection_time,restoration_time,interface=[], **kwargs):
    """
    To configure PFC Watch-Dog parameters
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param action:
    :type action:
    :param detection_time:
    :type detection_time:
    :param restoration_time:
    :type restoration_time:
    :param interface:
    :type interface:
    """
    if not interface:
        st.error("Please provide atleast one interface")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    interfaces = make_list(interface)
    commands = list()
    if cli_type == 'click':
        for intf in interfaces:
            intf = st.get_other_names(dut, [intf])[0] if '/' in intf else intf
            commands.append("pfcwd start --action {} ports {} detection-time {} --restoration-time {}".format(action,intf,detection_time,restoration_time))
    elif cli_type == 'klish':
        for intf in interfaces:
            intf_data = get_interface_number_from_name(intf)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("priority-flow-control watchdog action {}".format(action))
            commands.append("priority-flow-control watchdog detect-time {}".format(detection_time))
            commands.append("priority-flow-control watchdog restore-time {}".format(restoration_time))
            commands.append("exit")
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        config_data = {"openconfig-qos-ext:config": {"action": action.upper(), "detection-time": int(detection_time), "restoration-time": int(restoration_time)}}
        for intf in interfaces:
            url= rest_urls['pfc_wd_interface_config'].format(intf)
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
                st.error("Failed to configure PFC watch dog parameters on port: {}".format(intf))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def stop_pfc_wd(dut,interface=[], **kwargs):
    """
    To configure PFC Watch-Dog as OFF
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param interface:
    :type interface:
    """
    if not interface:
        st.error("Please provide atleast one interface")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    interfaces = make_list(interface)
    commands = list()
    if cli_type == 'click':
        for intf in interfaces:
            intf = st.get_other_names(dut, [intf])[0] if '/' in intf else intf
            commands.append("pfcwd stop {}".format(intf))
    elif cli_type == 'klish':
        for intf in interfaces:
            intf_data = get_interface_number_from_name(intf)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("priority-flow-control watchdog off")
            commands.append("exit")
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for intf in interfaces:
            url = rest_urls['pfc_wd_interface_config'].format(intf)
            if not delete_rest(dut, rest_url= url):
                st.error("Failed to stop PFC watch dog on {}".format(intf))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def pfc_wd_counter_poll_interval(dut, interval, **kwargs):
    """
    To configure PFC Watch-Dog polling interval
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param interval:
    :type interval:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    command = ''
    if cli_type == 'click':
        command = "pfcwd interval {}".format(interval)
    elif cli_type == 'klish':
        command = "priority-flow-control watchdog polling-interval {}".format(interval)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pfc_wd_global_config']
        poll_config = {"openconfig-qos-ext:pfc-watchdog": {"poll": {"config": {"poll-interval": int(interval)}}}}
        if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=poll_config):
            st.error('Failed to configure PFC Watch-Dog polling interval as: {}'.format(interval))
            return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if command:
        response = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def pfc_wd_counter_poll_config(dut, enable, **kwargs):
    """
    To enable/disable PFC Watch-Dog counter poll
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param dut:
    :type True/False:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    command = ''
    if cli_type == 'click':
        mode = 'enable' if enable else 'disable'
        command = "pfcwd counter_poll {}".format(mode)
    elif cli_type == 'klish':
        command = 'priority-flow-control watchdog counter-poll' if enable else 'no priority-flow-control watchdog counter-poll'
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pfc_wd_global_config']
        mode = 'ENABLE' if enable else 'DISABLE'
        config_data = {"openconfig-qos-ext:pfc-watchdog": {"flex": {"config": {"counter-poll": mode}}}}
        if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
            st.error('Failed to {} PFC Watch-Dog counter poll'.format(mode))
            return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if command:
        response = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def show_pfc_wd_config(dut, ports=[], **kwargs):
    """
    To get PFC Watch-Dog configuration
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param dut:
    :type dut:
    :param ports:
    :type list:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = cli_type if ports else 'click'
    ports = make_list(ports)
    if cli_type == 'click':
        command = "pfcwd show config"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        output = list()
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            command = "show qos interface {} {}".format(intf_data['type'], intf_data['number'])
            out = st.show(dut, command, type=cli_type)
            _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
            output.extend(out)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        output = list()
        for port in ports:
            url = rest_urls['get_pfc_params'].format(port)
            out = get_rest(dut, rest_url = url)
            if (out and ('output' in out) and out.get('output')):
                out = _get_rest_pfc_params_config(out['output'])
                _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
                output.extend(out)
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return output


def show_pfc_wd_stats(dut, **kwargs):
    """
    To get PFC Watch-Dog statistics
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param dut:
    :type dut:
    :param ports:
    :type ports:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    ports = make_list(kwargs.get('ports', []))
    command = ''
    if cli_type == 'click':
        command = "pfcwd show stats"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        temp_vars = st.get_testbed_vars()
        if not ports:
            port = 'Eth all' if temp_vars.config.ifname_type == 'alias' else 'Ethernet all'
            command = "show qos interface {} priority-flow-control statistics queue".format(port)
            output = st.show(dut, command, type=cli_type)
        else:
            output = list()
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                command = "show qos interface {} {} priority-flow-control statistics queue".format(intf_data['type'], intf_data['number'])
                output.extend(st.show(dut, command, type=cli_type))
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if not ports:
            url = rest_urls['get_pfc_all_counters']
            out = get_rest(dut, rest_url=url, timeout=120)
            if not (out and ('output' in out) and out.get('output')):
                st.error("No data found in output: {}".format(out))
                return False
            output = _get_rest_pfc_wd_stats_all(out['output'])
        else:
            output = list()
            for port in ports:
                url = rest_urls['get_pfcwd_counters'].format(port)
                out = get_rest(dut, rest_url=url, timeout=20)
                if not (out and ('output' in out) and out.get('output')):
                    st.error("No data found in output: {}".format(out))
                    return False
                output.extend(_get_rest_pfc_wd_stats(out['output'], port))
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return output


def show_asymmetric_pfc(dut, ports=[], cli_type=''):
    """
    To show asymmetric PFC configuration on ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param ports:
    :type list:
    :param cli_type:
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = cli_type if ports else 'click'
    ports = make_list(ports)
    if cli_type == 'click':
        command = "pfc show asymmetric"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        output = list()
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            command = "show qos interface {} {}".format(intf_data['type'], intf_data['number'])
            out = st.show(dut, command, type=cli_type)
            _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
            output.extend(out)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        output = list()
        for port in ports:
            url = rest_urls['get_pfc_params'].format(port) 
            out = get_rest(dut, rest_url = url)
            if (out and ('output' in out) and out.get('output')):
                out = _get_rest_pfc_params_config(out['output'])
                _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
                output.extend(out)
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return output


def clear_pfc_counters(dut, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type #Clear commands use RPC calls for those OC-YANG URLs won't be available
    if cli_type == 'click':
        command = "sonic-clear pfccounters"
        st.show(dut, command, skip_tmpl=True)
    elif cli_type == 'klish':
        if not clear_interface_counters(dut, **kwargs):
            st.error("Failed to clear PFC counters")
            return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def show_pfc_counters(dut, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    ports = make_list(kwargs.get('ports', []))
    if cli_type == 'click':
        command = "show pfc counters"
        rv = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        temp_vars = st.get_testbed_vars()
        if not ports:
            port = 'Eth all' if temp_vars.config.ifname_type == 'alias' else 'Ethernet all'
            command = "show qos interface {} priority-flow-control statistics".format(port)
            rv = st.show(dut, command, type=cli_type)
        else:
            rv = list()
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                command = "show qos interface {} {} priority-flow-control statistics".format(intf_data['type'], intf_data['number'])
                rv.extend(st.show(dut, command, type=cli_type))
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if not ports:
            url = rest_urls['get_pfc_all_counters']
            out = get_rest(dut, rest_url=url, timeout=120)
            if not (('output' in out) and out.get('output')):
                st.error("No data found in output: {}".format(out))
                return False
            rv = _get_rest_pfc_counters_all(out['output'])
        else:
            rv = list()
            for port in ports:
                url = rest_urls['get_pfc_pause_counters'].format(port)
                out = get_rest(dut, rest_url=url, timeout=120)
                if not (('output' in out) and out.get('output')):
                    st.error("No data found in output: {}".format(out))
                    return False
                rv.extend(_get_rest_pfc_counters(out['output'], port))
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    output = [{k: v.replace('received', 'Port Rx').replace('transmitted', 'Port Tx').replace(',', '') for k, v in each.items()} for each in rv]
    return output


def get_pfc_counters(dut,interface,mode,*argv):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param mode:
    :param argv: 'pfc0','pfc1','pfc2','pfc3','pfc4','pfc5','pfc6','pfc7'
    :return:
    """
    output = show_pfc_counters(dut)
    port_mode = 'Port Tx'
    if mode.lower() == 'rx':
        port_mode = 'Port Rx'
    entries = filter_and_select(output,argv,{'port':interface,'port_mode':port_mode})
    return entries


def get_pfc_counters_all(dut, interface, mode='tx'):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param mode:
    :param kwargs:
    :return:
    """

    output = show_pfc_counters(dut)
    port_mode = 'Port Tx'
    if mode.lower() == 'rx':
        port_mode = 'Port Rx'
    match = {'port':interface,'port_mode':port_mode}
    entries = filter_and_select(output, None, match)
    if not entries:
        st.log("No queue couters found on {} for {} {}".format(dut, interface, mode))
        return (False,0)
    new_entry = {}
    for i in entries[0]:
        new_entry[i]=entries[0][i].replace(",","")
    return (True,new_entry)

def verify_pfc_counters(dut,interface,mode='tx',**kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param mode:
    :param kwargs:
    :return:
    """

    output = show_pfc_counters(dut)
    port_mode = 'Port Tx'
    if mode.lower() == 'rx':
        port_mode = 'Port Rx'

    for each in kwargs.keys():
        match = {'port':interface,'port_mode':port_mode,each:kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def config_pfc_buffer_prameters(dut, hwsku, ports_dict, **kwargs):
    """
    Autor: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To configure the platform specific buffer constants
    :param hwsku:
    :type hwsku:
    :param dut:
    :type dut:
    :param ports_dict:
    :type ports_dict:
    """
    constants = st.get_datastore(dut, "constants")
    ports_show = interface_status_show(dut, list(ports_dict.keys()))
    port_speed = dict()
    core_buffer_config = kwargs.get('core_buffer_config', False)
    apply_buffer_config = kwargs.get('apply_buffer_config', True)
    for port in ports_dict.keys():
        port_speed[port] = filter_and_select(ports_show, ['speed'], {'interface': port})[0]['speed'].replace('G', '000')
    native_ports_map_dict = {port:st.get_other_names(dut, [port])[0] if '/' in port else port for port in ports_dict.keys()}
    retval = dict()
    update_retval = lambda entries: {retval.update(entry) for entry in entries}
    if hwsku.lower() in constants['TH_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "12766208", "type": "egress"},
                                           "egress_lossy_pool": {"mode": "dynamic", "size": "7326924", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress", "xoff": "4625920"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "egress_lossless_pool", "size": "0", "static_th": "12766208"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "egress_lossless_pool", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3", "pool": "ingress_lossless_pool", "size": "0"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_25000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_100000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'100000' : 'pg_lossless_100000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '10000' : 'pg_lossless_10000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "{}".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TH2_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "12766208", "type": "egress"},
                                       "egress_lossy_pool": {"mode": "dynamic", "size": "7326924", "type": "egress"},
                                       "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress", "xoff": "4625920"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "egress_lossless_pool", "size": "0", "static_th": "12766208"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "egress_lossless_pool", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3","pool": "ingress_lossless_pool","size": "0"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_25000_300m_profile": {"dynamic_th": "-3","pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_100000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'10000' : 'pg_lossless_10000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '100000' : 'pg_lossless_100000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "{}".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TH3_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossy_pool": {"mode": "dynamic", "size": "67108864", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "59001152", "type": "ingress", "xoff": "7428992"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"dynamic_th": "3", "pool": "egress_lossy_pool", "size": "0"},
                                                 "egress_lossy_profile": {"dynamic_th": "3", "pool": "egress_lossy_pool", "size": "0"},
                                                 "ingress_lossy_profile": {"pool": "ingress_lossless_pool", "size": "0", "static_th": "67108864"},
                                                 "pg_lossless_10000_40m_profile": {"dynamic_th": "-2", "pool": "ingress_lossless_pool", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_50000_40m_profile": {"dynamic_th": "-2", "pool": "ingress_lossless_pool", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_100000_40m_profile": {"dynamic_th": "-2", "pool": "ingress_lossless_pool", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_200000_40m_profile": {"dynamic_th": "-2", "pool": "ingress_lossless_pool", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_400000_40m_profile": {"dynamic_th": "-2", "pool": "ingress_lossless_pool", "size": "1270","xoff": "190500", "xon": "0", "xon_offset": "2540"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "40m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'400000' : 'pg_lossless_400000_40m_profile', '200000' : 'pg_lossless_200000_40m_profile', '100000' : 'pg_lossless_100000_40m_profile', '50000': 'pg_lossless_50000_40m_profile', '10000' : 'pg_lossless_10000_40m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "{}".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TD2_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "12766208", "type": "egress"},
                                           "egress_lossy_pool": {"mode": "dynamic", "size": "7326924", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "egress_lossless_pool", "size": "0", "static_th": "12766208"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "egress_lossless_pool", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3", "pool": "ingress_lossless_pool", "size": "0"},
                                                 "pg_lossless_1000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-3", "pool": "ingress_lossless_pool", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'10000' : 'pg_lossless_10000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '1000' : 'pg_lossless_1000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "{}".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)
    
    elif hwsku.lower() in constants['TD3_PLATFORMS']+constants['MV2_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "33004032", "type": "egress"},
                                           "egress_lossy_pool": {"mode": "dynamic", "size": "12766208", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress", "xoff": "196608"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "egress_lossless_pool", "size": "0", "static_th": "33004032"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "egress_lossless_pool", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3", "pool": "ingress_lossless_pool", "size": "0"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "1", "pool": "ingress_lossless_pool", "size": "9427", "xoff": "50176", "xon": "0", "xon_offset": "3584"},
                                                 "pg_lossless_25000_300m_profile": {"dynamic_th": "1", "pool": "ingress_lossless_pool", "size": "9427", "xoff": "50176", "xon": "0", "xon_offset": "3584"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "1", "pool": "ingress_lossless_pool", "size": "9427", "xoff": "50176", "xon": "0", "xon_offset": "3584"},
                                                 "pg_lossless_100000_300m_profile": {"dynamic_th": "1", "pool": "ingress_lossless_pool", "size": "9427", "xoff": "50176", "xon": "0", "xon_offset": "3584"}}}
            if hwsku.lower() in ['quanta-ix8a-bwde-56x', 'accton-as4630-54pe']:
                buffer_profile['BUFFER_PROFILE'].update(pg_lossless_1000_300m_profile={"dynamic_th": "1", "pool": "ingress_lossless_pool", "size": "9427", "xoff": "50176", "xon": "0", "xon_offset": "3584"})
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'100000' : 'pg_lossless_100000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '10000' : 'pg_lossless_10000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            if hwsku.lower() in ['quanta-ix8a-bwde-56x', 'accton-as4630-54pe']:
                ingress_profile_mapping.update({'1000': 'pg_lossless_1000_300m_profile'})
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "{}".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    else:
        st.error("Invalid platform")
        return False
    if retval:
        final_data = json.dumps(retval)
        st.apply_json2(dut, final_data)
    return True


def _get_rest_pfc_wd_stats(data, port):
    """
    To get processed output from REST PFC watchdog statistics per port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    retval = list()
    if data.get("openconfig-qos-ext:pfc-queue") and data["openconfig-qos-ext:pfc-queue"].get("pfc-queue") and isinstance(data["openconfig-qos-ext:pfc-queue"]["pfc-queue"], list):
        entries = data["openconfig-qos-ext:pfc-queue"]["pfc-queue"]
        for entry in entries:
            temp = dict()
            if 'queue' in entry and entry.get('statistics'):
                stats = entry['statistics']
                temp['port'] = port
                temp['status'] = 'N/A'
                temp['queue'] = str(entry['queue'])
                if 'rx-drop' in stats:
                    temp['rx_drop'] = str(stats['rx-drop'])
                if 'rx-drop-last' in stats:
                    temp['rx_last_drop'] = str(stats['rx-drop-last'])
                if 'rx-ok' in stats:
                    temp['rx_ok'] = str(stats['rx-ok'])
                if 'rx-ok-last' in stats:
                    temp['rx_last_ok'] = str(stats['rx-ok-last'])
                if 'storm-detected' in stats:
                    temp['storm_detect'] = str(stats['storm-detected'])
                if 'storm-restored' in stats:
                    temp['storm_restore'] = str(stats['storm-restored'])
                if 'tx-drop' in stats:
                    temp['tx_drop'] = str(stats['tx-drop'])
                if 'tx-drop-last' in stats:
                    temp['tx_last_drop'] = str(stats['tx-drop-last'])
                if 'tx-ok' in stats:
                    temp['tx_ok'] = str(stats['tx-ok'])
                if 'tx-ok-last' in stats:
                    temp['tx_last_ok'] = str(stats['tx-ok-last'])
                retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_pfc_wd_stats_all(data):
    """
    To get processed output from REST PFC watchdog statistics for all ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    retval = list()
    if "openconfig-qos:interface" in data and data.get("openconfig-qos:interface") and isinstance(data["openconfig-qos:interface"], list):
        entries = data["openconfig-qos:interface"]
        for entry in entries:
            if "interface-id" in entry and entry.get("openconfig-qos-ext:pfc") and entry["openconfig-qos-ext:pfc"].get("pfc-queue") and entry["openconfig-qos-ext:pfc"]["pfc-queue"].get("pfc-queue") and isinstance(entry["openconfig-qos-ext:pfc"]["pfc-queue"]["pfc-queue"], list):
                pfcwd_stats = entry["openconfig-qos-ext:pfc"]["pfc-queue"]["pfc-queue"]
                for pfcwd_stat in pfcwd_stats:
                    temp = dict()
                    if 'queue' in pfcwd_stat and pfcwd_stat.get('statistics'):
                        stats = pfcwd_stat['statistics']
                        temp['port'] = entry['interface-id']
                        temp['status'] = 'N/A'
                        temp['queue'] = str(pfcwd_stat['queue'])
                        if 'rx-drop' in stats:
                            temp['rx_drop'] = str(stats['rx-drop'])
                        if 'rx-drop-last' in stats:
                            temp['rx_last_drop'] = str(stats['rx-drop-last'])
                        if 'rx-ok' in stats:
                            temp['rx_ok'] = str(stats['rx-ok'])
                        if 'rx-ok-last' in stats:
                            temp['rx_last_ok'] = str(stats['rx-ok-last'])
                        if 'storm-detected' in stats:
                            temp['storm_detect'] = str(stats['storm-detected'])
                        if 'storm-restored' in stats:
                            temp['storm_restore'] = str(stats['storm-restored'])
                        if 'tx-drop' in stats:
                            temp['tx_drop'] = str(stats['tx-drop'])
                        if 'tx-drop-last' in stats:
                            temp['tx_last_drop'] = str(stats['tx-drop-last'])
                        if 'tx-ok' in stats:
                            temp['tx_ok'] = str(stats['tx-ok'])
                        if 'tx-ok-last' in stats:
                            temp['tx_last_ok'] = str(stats['tx-ok-last'])
                        retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_pfc_counters(data, port):
    """
    To get processed output from REST PFC statistics per port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    rx_entry = {'port': port, 'port_mode': 'received'}
    tx_entry = {'port': port, 'port_mode': 'transmitted'}
    if "openconfig-qos-ext:pfc-priority" in data and data["openconfig-qos-ext:pfc-priority"] and isinstance(data["openconfig-qos-ext:pfc-priority"], list):
        entries = data["openconfig-qos-ext:pfc-priority"]
        for entry in entries:
            if entry.get('state') and entry['state'].get('statistics') and 'dot1p' in entry['state']:
                stats = entry['state']['statistics']
                if 'pause-frames-rx' in stats:
                    rx_entry['pfc{}'.format(entry['state']['dot1p'])] = str(stats['pause-frames-rx'])
                if 'pause-frames-tx' in stats:
                    tx_entry['pfc{}'.format(entry['state']['dot1p'])] = str(stats['pause-frames-tx'])
    st.debug([rx_entry, tx_entry])
    return [rx_entry, tx_entry]


def _get_rest_pfc_counters_all(data):
    """
    To get processed output from REST PFC statistics for all ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    retval = list()
    if "openconfig-qos:interface" in data and data.get("openconfig-qos:interface") and isinstance(data["openconfig-qos:interface"], list):
        entries = data["openconfig-qos:interface"]
        for entry in entries:
            if "interface-id" in entry and entry.get("openconfig-qos-ext:pfc") and entry["openconfig-qos-ext:pfc"].get("pfc-priorities") and entry["openconfig-qos-ext:pfc"]["pfc-priorities"].get("pfc-priority") and isinstance(entry["openconfig-qos-ext:pfc"]["pfc-priorities"]["pfc-priority"], list):
                pfc_stats = entry["openconfig-qos-ext:pfc"]["pfc-priorities"]["pfc-priority"]
                rx_entry = {'port': entry["interface-id"], 'port_mode': 'received'}
                tx_entry = {'port': entry["interface-id"], 'port_mode': 'transmitted'}
                for pfc_stat in pfc_stats:
                    if pfc_stat.get('state') and pfc_stat['state'].get('statistics') and 'dot1p' in pfc_stat['state']:
                        stats = pfc_stat['state']['statistics']
                        if 'pause-frames-rx' in stats:
                            rx_entry['pfc{}'.format(pfc_stat['state']['dot1p'])] = str(stats['pause-frames-rx'])
                        if 'pause-frames-tx' in stats:
                            tx_entry['pfc{}'.format(pfc_stat['state']['dot1p'])] = str(stats['pause-frames-tx'])
                retval.extend([rx_entry, tx_entry])
    st.debug(retval)
    return retval


def _get_rest_pfc_params_config(data):
    """
    To get PFC parameters configured on port from REST output
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param data:
    :type data:
    """
    retval = dict()
    if "openconfig-qos-ext:pfc" in data and "state" in data["openconfig-qos-ext:pfc"] and "asymmetric" in data["openconfig-qos-ext:pfc"]["state"] and data["openconfig-qos-ext:pfc"]["state"]["asymmetric"]:
        retval['pfc_asymmetric'] = "on"
    else:
        retval['pfc_asymmetric'] = "off"
    if "openconfig-qos-ext:pfc" in data and "pfc-priorities" in data["openconfig-qos-ext:pfc"] and "pfc-priority" in data["openconfig-qos-ext:pfc"]["pfc-priorities"]:
        priority_entries = data["openconfig-qos-ext:pfc"]["pfc-priorities"]["pfc-priority"]
        if isinstance(priority_entries, list):
            pfc_lossless_priorities = [str(priority_entry['state']['dot1p']) for priority_entry in priority_entries if 'state' in priority_entry and 'dot1p' in priority_entry['state'] and 'enable' in priority_entry['state'] and priority_entry['state']['enable']]
            retval['pfc_priority'] = ','.join(pfc_lossless_priorities) if pfc_lossless_priorities else ''
    else:
        retval['pfc_priority'] = ''
    if "openconfig-qos-ext:pfc" in data and "watchdog" in data["openconfig-qos-ext:pfc"] and "state" in data["openconfig-qos-ext:pfc"]["watchdog"]:
        wathdog_data = data["openconfig-qos-ext:pfc"]["watchdog"]["state"]
        retval['action'] = wathdog_data["action"].lower() if "action" in wathdog_data else "N/A"
        retval['detectiontime'] = str(wathdog_data["detection-time"]) if "detection-time" in wathdog_data else "0"
        retval['restorationtime'] = str(wathdog_data["restoration-time"]) if "restoration-time" in wathdog_data else "0"
    else:
        retval['action'], retval['detectiontime'], retval['restorationtime'] = "N/A", "0", "0"
    st.debug([retval])
    return [retval]
