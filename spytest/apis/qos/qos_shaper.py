# This file contains the list of API's which performs QOS Shaper operations.
# Author : Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)

import json
import re
from spytest import st
from utilities.utils import get_interface_number_from_name
from utilities.common import make_list, filter_and_select
from apis.system.rest import config_rest, delete_rest
from apis.system.port import get_interface_counters_all
from apis.qos.qos import clear_qos_config
errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']

get_klish_rate = lambda rate: int((int(rate)*8)/1000)
get_rest_rate = lambda rate: int(rate)*8


def apply_port_shaping_config(dut, shaper_data, **kwargs):
    """
    API to configure Port-Level shaper
    :param dut:
    :type dut:
    :param shaper_data:
    :type shaper_data:
    :param cli_type:
    :type cli_type:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    cli_type = 'klish' if skip_error and cli_type == 'click' else cli_type
    st.debug("Provided port-shaper configuration is: {}".format(shaper_data))
    if not shaper_data.get("policy_name"):
        st.error("policy_name is not provided")
        return False
    if cli_type == 'click':
        policy_name = "{}@255".format(shaper_data["policy_name"])
        json_data = {"PORT_QOS_MAP": {}, "SCHEDULER": {policy_name: {}}}
        if shaper_data.get("port"):
            ports = make_list(shaper_data["port"])
            json_data["PORT_QOS_MAP"] = {port: {"scheduler": "{}".format(policy_name)} for port in ports}
        else:
            json_data.pop("PORT_QOS_MAP")
        if ("pir" in shaper_data) or ("pbs" in shaper_data) or shaper_data.get("meter_type"):
            if shaper_data.get("meter_type"):
                json_data["SCHEDULER"][policy_name].update(meter_type = shaper_data['meter_type'])
            if "pir" in shaper_data:
                json_data["SCHEDULER"][policy_name].update(pir = str(shaper_data['pir']))
            if "pbs" in shaper_data:
                json_data["SCHEDULER"][policy_name].update(pbs = str(shaper_data['pbs']))
        else:
            json_data.pop("SCHEDULER")
        json_config = json.dumps(json_data)
        json.loads(json_config)
        st.apply_json2(dut, json_config)
    elif cli_type == 'klish':
        commands = list()
        if ("pir" in shaper_data) or ("pbs" in shaper_data):
            commands.append("qos scheduler-policy {}".format(shaper_data['policy_name']))
            commands.append("port")
            if "pir" in shaper_data:
                commands.append("pir {}".format(get_klish_rate(shaper_data['pir'])))
            if "pbs" in shaper_data:
                commands.append("pbs {}".format(shaper_data['pbs']))
            commands.extend(["exit", "exit"])
        if shaper_data.get("port"):
            ports = make_list(shaper_data["port"])
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
                commands.append("scheduler-policy {}".format(shaper_data['policy_name']))
                commands.append("exit")
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if ("pir" in shaper_data) or ("pbs" in shaper_data):
            url = rest_urls['shaper_create_config']
            params_config = dict()
            if "pir" in shaper_data:
                params_config.update(pir=str(get_rest_rate(shaper_data['pir'])))
            if "pbs" in shaper_data:
                params_config.update(be=int(shaper_data['pbs']))
            config_data = {"openconfig-qos:scheduler-policies": {"scheduler-policy": [{"name": shaper_data['policy_name'], "config": {"name": shaper_data['policy_name']}, "schedulers": {"scheduler": [{"sequence": 255, "config": {"sequence": 255}, "two-rate-three-color": {"config": params_config}}]}}]}}
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                st.error("Failed to create port-level shaper with shaper-data: {}".format(shaper_data))
                return False
        if shaper_data.get("port"):
            ports = make_list(shaper_data["port"])
            for port in ports:
                url = rest_urls['apply_shaper_config'].format(port)
                config_data = {"openconfig-qos:config": {"name": shaper_data['policy_name']}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to attach shaper configuration to port: {}".format(port))
                    return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def apply_queue_shaping_config(dut, shaper_data, **kwargs):
    """
    API to configure Queue-Level shaper
    :param dut:
    :type dut:
    :param shaper_data:
    :type shaper_data:
    :param cli_type:
    :type cli_type:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    cli_type = 'klish' if skip_error and cli_type == 'click' else cli_type
    st.debug("Provided queue-shaper configuration is: {}".format(shaper_data))
    ports = list()
    if shaper_data.get('port'):
        ports = make_list(shaper_data['port'])
    if not shaper_data.get("policy_name"):
        st.error("policy_name is not provided")
        return False
    if cli_type == 'click':
        config_data = {"QUEUE": {}, "SCHEDULER": {}}
        if shaper_data.get('shaper_data'):
            shaper_info = make_list(shaper_data['shaper_data'])
            for ent in shaper_info:
                policy = "{}@{}".format(shaper_data['policy_name'], ent['queue'])
                if ('cir' in ent) or ('cbs' in ent) or ('pir' in ent) or ('pbs' in ent):
                    temp = dict()
                    temp[policy] = {}
                    if 'meter_type' in ent:
                        temp[policy].update(meter_type=ent['meter_type'])
                    if 'cir' in ent:
                        temp[policy].update(cir=str(ent['cir']))
                    if 'cbs' in ent:
                        temp[policy].update(cbs=str(ent['cbs']))
                    if 'pir' in ent:
                        temp[policy].update(pir=str(ent['pir']))
                    if 'pbs' in ent:
                        temp[policy].update(pbs=str(ent['pbs']))
                    config_data["SCHEDULER"].update(temp)
                if ports:
                    queue_map = dict()
                    queue_map = {"{}|{}".format(port, ent['queue']): {"scheduler": "{}".format(policy)} for port in ports}
                    config_data["QUEUE"].update(queue_map)
        config_data2 = {key: value for key, value in config_data.items()}
        for key, value in config_data2.items():
            if not value:
                config_data.pop(key)
        json_config = json.dumps(config_data)
        json.loads(json_config)
        st.apply_json2(dut, json_config)
    elif cli_type == 'klish':
        shaper_info = make_list(shaper_data['shaper_data'])
        commands = list()
        commands.append("qos scheduler-policy {}".format(shaper_data['policy_name']))
        for ent in shaper_info:
            if ('cir' in ent) or ('cbs' in ent) or ('pir' in ent) or ('pbs' in ent):
                commands.append("queue {}".format(ent['queue']))
                if 'cir' in ent:
                    commands.append("cir {}".format(get_klish_rate(ent['cir'])))
                if 'cbs' in ent:
                    commands.append("cbs {}".format(ent['cbs']))
                if 'pir' in ent:
                    commands.append("pir {}".format(get_klish_rate(ent['pir'])))
                if 'pbs' in ent:
                    commands.append("pbs {}".format(ent['pbs']))
                commands.append("exit")
        commands.append("exit")
        if ports:
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
                commands.append("scheduler-policy {}".format(shaper_data['policy_name']))
                commands.append("exit")
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        shaper_info = make_list(shaper_data['shaper_data'])
        for ent in shaper_info:
            if ('cir' in ent) or ('cbs' in ent) or ('pir' in ent) or ('pbs' in ent):
                url = rest_urls['shaper_create_config']
                params_config = dict()
                if 'cir' in ent:
                    params_config.update(cir = str(get_rest_rate(ent['cir'])))
                if 'cbs' in ent:
                    params_config.update(bc=int(ent['cbs']))
                if 'pir' in ent:
                    params_config.update(pir = str(get_rest_rate(ent['pir'])))
                if 'pbs' in ent:
                    params_config.update(be=int(ent['pbs']))
                config_data = {"openconfig-qos:scheduler-policies": {"scheduler-policy": [{"name": shaper_data['policy_name'], "config": {"name": shaper_data['policy_name']}, "schedulers": {"scheduler": [{"sequence": int(ent['queue']), "config": {"sequence": int(ent['queue'])}, "two-rate-three-color": {"config": params_config}}]}}]}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to create queue-level shaper with shaper-data: {}".format(ent))
                    return False
        if ports:
            for port in ports:
                url = rest_urls['apply_shaper_config'].format(port)
                config_data = {"openconfig-qos:config": {"name": shaper_data['policy_name']}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to attach queue-shaper configuration to port: {}".format(port))
                    return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def clear_port_shaper(dut, port='', shaper_data='', **kwargs):
    """
    API to clear shaper and detach shaper from port
    :param dut:
    :type dut:
    :param port:
    :type port:
    :param shaper_data:
    :type shaper_data:
    :param cli_type:
    :type cli_type:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    cli_type = 'klish' if skip_error and cli_type == 'click' else cli_type
    qos_clear = kwargs.get('qos_clear', False)
    remove_shaper = kwargs.get('remove_shaper', True)
    if (not qos_clear) and cli_type=='click':
        cli_type = 'klish'
    if cli_type == 'click':
        clear_qos_config(dut)
    elif cli_type == 'klish':
        commands = list()
        if port:
            intf_data = get_interface_number_from_name(port)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("no scheduler-policy")
            commands.append("exit")
        if shaper_data and remove_shaper:
            commands.append("no qos scheduler-policy {}".format(shaper_data))
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if port:
            url = rest_urls['policy_apply_config'].format(port)
            if not delete_rest(dut, rest_url=url):
                st.error("Failed to remove scheduler-policy on port: {}".format(port))
                return False
        if shaper_data and remove_shaper:
            url = rest_urls['scheduler_policy_config'].format(shaper_data)
            if not delete_rest(dut, rest_url=url):
                st.error("Failed to remove QOS scheduler-policy: {}".format(shaper_data))
                return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def apply_queue_shcheduling_config(dut, scheduler_data, **kwargs):
    """
    API to configure scheduler parameters
    :param dut:
    :type dut:
    :param scheduler_data:
    :type scheduler_data:
    :param cli_type:
    :type cli_type:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    cli_type = 'klish' if skip_error and cli_type == 'click' else cli_type
    st.debug("Provided scheduler configuration is: {}".format(scheduler_data))
    ports = list()
    if scheduler_data.get('port'):
        ports = make_list(scheduler_data['port'])
    if not scheduler_data.get("policy_name"):
        st.error("policy_name is not provided")
        return False
    if cli_type == 'click':
        config_data = {"QUEUE": {}, "SCHEDULER": {}}
        scheduler_info = make_list(scheduler_data['scheduler_data'])
        for ent in scheduler_info:
            temp = dict()
            queue_map = dict()
            policy = "{}@{}".format(scheduler_data['policy_name'], ent['queue'])
            temp[policy] = dict()
            if 'weight' in ent:
                temp[policy].update(weight = str(ent['weight']))
            if ent.get('type'):
                temp[policy].update(type = ent['type'].upper())
            if ports:
                queue_map = {"{}|{}".format(port, ent['queue']) : {"scheduler": "{}".format(policy)} for port in ports}
            if temp[policy]:
                config_data['SCHEDULER'].update(temp)
            if queue_map:
                config_data['QUEUE'].update(queue_map)
        if not config_data['QUEUE']:
            config_data.pop('QUEUE')
        if not config_data['SCHEDULER']:
            config_data.pop('SCHEDULER')
        json_config = json.dumps(config_data)
        json.loads(json_config)
        st.apply_json2(dut, json_config)
    elif cli_type == 'klish':
        commands = list()
        commands.append("qos scheduler-policy {}".format(scheduler_data['policy_name']))
        scheduler_info = make_list(scheduler_data['scheduler_data'])
        for ent in scheduler_info:
            commands.append("queue {}".format(ent['queue']))
            if ent.get('type'):
                commands.append("type {}".format(ent['type'].lower()))
            if 'weight' in ent:
                commands.append("weight {}".format(ent['weight']))
            commands.append("exit")
        commands.append("exit")
        if ports:
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
                commands.append("scheduler-policy {}".format(scheduler_data['policy_name']))
                commands.append("exit")
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        scheduler_info = make_list(scheduler_data['scheduler_data'])
        for ent in scheduler_info:
            if ent.get('type') or 'weight' in ent:
                url = rest_urls['shaper_create_config']
                params_config = {"sequence": int(ent['queue'])}
                if ent.get('type'):
                    params_config.update(priority=ent['type'].upper())
                if 'weight' in ent:
                    params_config.update({"openconfig-qos-ext:weight": int(ent['weight'])})
                config_data = {"openconfig-qos:scheduler-policies": {"scheduler-policy": [{"name": scheduler_data['policy_name'], "config": {"name": scheduler_data['policy_name']}, "schedulers": {"scheduler": [{"sequence": int(ent['queue']), "config": params_config}]}}]}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error('Failed to create scheduler with data: {}'.format(ent))
                    return False
        if ports:
            for port in ports:
                url = rest_urls['apply_shaper_config'].format(port)
                config_data = {"openconfig-qos:config": {"name": scheduler_data['policy_name']}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to attach queue-shaper configuration to port: {}".format(port))
                    return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def reset_port_shaper_params(dut, policy_name, params_list, **kwargs):
    """
    API to reset Port-Level shaper parameters
    :param dut:
    :type dut:
    :param policy_name:
    :type policy_name:
    :param params_list:
    :type params_list:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error = kwargs.get('skip_error', False)
    params_list = [param.lower() for param in make_list(params_list)]
    if cli_type == 'klish':
        commands = list()
        commands.append("qos scheduler-policy {}".format(policy_name))
        commands.append("port")
        commands.extend(["no {}".format(param) for param in params_list])
        commands.extend(["exit", "exit"])
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for param in params_list:
            if param.lower() not in ['pir', 'pbs']:
                st.error('Invalid port shaper parameter: {}'.format(param))
                return False
            if param == 'pir':
                url = rest_urls['shaper_pir_config'].format(policy_name, 255)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to reset {} for port shaper profile: {}".format(param, policy_name))
                    return False
            if param == 'pbs':
                url = rest_urls['shaper_pbs_config'].format(policy_name, 255)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to reset {} for port shaper profile: {}".format(param, policy_name))
                    return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def reset_queue_shaper_params(dut, policy_name, params_dict, **kwargs):
    """
    API to reset Queue-Level shaper parameters
    :param dut:
    :type dut:
    :param policy_name:
    :type policy_name:
    :param params_dict:
    :type params_dict:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error = kwargs.get('skip_error', False)
    if cli_type == 'klish':
        commands = list()
        commands.append("qos scheduler-policy {}".format(policy_name))
        for queue, params in params_dict.items():
            parameters = make_list(params)
            commands.append("queue {}".format(queue))
            commands.extend(["no {}".format(param.lower()) for param in parameters])
            commands.append("exit")
        commands.append("exit")
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for queue, params in params_dict.items():
            parameters = make_list(params)
            for param in parameters:
                if param.lower() not in ['pir', 'pbs', 'cir', 'cbs', 'type', 'weight']:
                    st.error('Invalid queue shaper/scheduler parameter: {}'.format(param))
                    return False
                if param.lower() == 'pir':
                    url = rest_urls['shaper_pir_config'].format(policy_name, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to reset {} on Queue: {} for shaper profile: {}".format(param, queue, policy_name))
                        return False
                if param.lower() == 'pbs':
                    url = rest_urls['shaper_pbs_config'].format(policy_name, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to reset {} on Queue: {} for shaper profile: {}".format(param, queue, policy_name))
                        return False
                if param.lower() == 'cir':
                    url = rest_urls['shaper_cir_config'].format(policy_name, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to reset {} on Queue: {} for shaper profile: {}".format(param, queue, policy_name))
                        return False
                if param.lower() == 'cbs':
                    url = rest_urls['shaper_cbs_config'].format(policy_name, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to reset {} on Queue: {} for shaper profile: {}".format(param, queue, policy_name))
                        return False
                if param.lower() == 'type':
                    url = rest_urls['scheduler_type_config'].format(policy_name, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to reset {} on Queue: {} for shaper profile: {}".format(param, queue, policy_name))
                        return False
                if param.lower() == 'weight':
                    url = rest_urls['scheduler_weight_config'].format(policy_name, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to reset {} on Queue: {} for shaper profile: {}".format(param, queue, policy_name))
                        return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def config_invalid_shaper(dut, policy_name, **kwargs):
    """
    API to configure invalid shaper
    :param dut:
    :type dut:
    :param policy_name:
    :type policy_name:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error = kwargs.get('skip_error', False)
    if cli_type == 'klish':
        command = "qos scheduler-policy {}".format(policy_name)
        response = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['policy_config']
        config_data = {"openconfig-qos:scheduler-policy": [{"name": policy_name, "config": {"name": policy_name}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
            st.error("Failed to configure Policy: {}".format(policy_name))
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def get_port_tx_rate_in_bps(dut, port, **kwargs):
    """
    This API is used to return the TX_BPS of a port
    :param dut:
    :type dut:
    :param port:
    :type port:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    CMD = 'show interfaces counters | grep "{}"'
    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] else cli_type
    output = st.show(dut, CMD.format(port), cli_type=cli_type) if cli_type == 'click' else get_interface_counters_all(dut, port, cli_type=cli_type)
    entry = filter_and_select(output, ['tx_bps'], {'iface': port})
    rv = re.search(r"\d+\.\d+", entry[0]['tx_bps']) if entry and 'tx_bps' in entry[0] else 0
    if cli_type == 'click':
        if rv:
           if 'GB/s' in entry[0]['tx_bps']:
               multiplier = 1000 * 1000 * 1000
           elif 'MB/s' in entry[0]['tx_bps']:
               multiplier = 1000 * 1000
           elif 'KB/s' in entry[0]['tx_bps']:
               multiplier = 1000
           else:
               multiplier = 1
        return round(float(rv.group()) * multiplier) if rv else 0
    elif cli_type == 'klish':
        return round(float(rv.group()) * 1000 * 1000) if rv else 0
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
