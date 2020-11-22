# This file contains the list of API's which performs Threshold Feature operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
from spytest import st
import utilities.common as utils
from utilities.utils import get_interface_number_from_name
from apis.common import redis
import apis.system.interface as intapi
import apis.system.logging as logapi
import apis.common.asic as asicapi
from apis.system.rest import config_rest, delete_rest, get_rest


def config_threshold(dut, **kwargs):
    """
    Config Threshold.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :param :threshold_type: priority-group|queue
    :param :port_alias:
    :param :buffer_type: if threshold_type:priority-group {shared|headroom} |
                                                        else threshold_type:queue {unicast|multicast}
    :param :index: if threshold_type:priority-group - PGindex value | else threshold_type:queue - queueindex value
    :param :errtype: threshold value | pg index
    :return:
    """
    if 'threshold_type' not in kwargs and 'port_alias' not in kwargs and 'buffer_type' not in kwargs and \
        'value' not in kwargs and 'index' not in kwargs:
        st.error("Mandatory parameter threshold_type/port_alias/index/buffer_type/value not found")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    if kwargs['threshold_type'] in ["priority-group", "queue"]:
        if cli_type == 'click':
            commands = "config {} threshold {} {} {} {}".format(kwargs['threshold_type'], kwargs['port_alias'],
                                                               kwargs['index'], kwargs['buffer_type'], kwargs['value'])
        elif cli_type == "klish":
            commands = list()
            commands.append("interface {}".format(kwargs.get('port_alias')))
            commands.append("threshold {} {} {} {}".format(kwargs['threshold_type'],
                                                     kwargs['index'], kwargs['buffer_type'], kwargs['value']))
            commands.append("exit")
        elif cli_type in ["rest-patch", "rest-put"]:
            config_data = {"openconfig-qos-ext:thresholds":{"threshold":[{"buffer": kwargs['threshold_type'],
                                                                        "type": kwargs['buffer_type'],
                                                                        "port": kwargs['port_alias'],
                                                                        "index": kwargs['index'],
                                                                        "config": {"buffer": kwargs['threshold_type'],
                                                                                   "type": kwargs['buffer_type'],
                                                                                   "port": kwargs['port_alias'],
                                                                                   "index": kwargs['index'],
                                                                                "threshold-value": kwargs['value']}}]}}
            url = st.get_datastore(dut, "rest_urls")["thresholds"]
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
                return False
            return True
        else:
            st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
    else:
        st.error("Invalid threshold_type provided '{}'".format(kwargs['threshold_type']))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if kwargs.get('errtype') == 'threshold':
            errstr = 'Error: threshold value must be in range 1-100'
        elif kwargs.get('errtype') == 'pgindex':
            errstr = 'Error: priority-group must be in range 0-7'
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        st.config(dut, commands, type=cli_type)
        if cli_type == 'klish':
            st.config(dut, "exit", type=cli_type)
    return True


def clear_threshold(dut, **kwargs):
    """
    Clear threshold configuration.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :threshold_type:  priority-group|queue
    :param :port_alias:
    :param :buffer_type: if threshold_type:priority-group {shared|headroom} |
                                                            else threshold_type:queue {unicast|multicast} | all
    :param :index: if threshold_type:priority-group - PGindex value | else threshold_type:queue - queueindex value
    :param :breach: all | event-id
    :param :cli_type:  click|klish
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "click":
        if kwargs.get('port_alias') == 'CPU':
            kwargs['buffer_type'] = 'all'
        if kwargs.get("breach"):
            if kwargs.get('breach') == "all":
                commands = "sonic-clear threshold breach"
            else:
                commands = "sonic-clear threshold breach {}".format(kwargs.get("breach"))
        elif kwargs.get("threshold_type") and kwargs.get('buffer_type') == "all":
            commands = "sonic-clear {} threshold".format(kwargs['threshold_type'])
        else:
            if 'threshold_type' not in kwargs and 'port_alias' not in kwargs and 'buffer_type' not in kwargs and \
                    'index' not in kwargs:
                st.error("Mandatory parameter threshold_type/port_alias/index/type not found")
                return False
            if kwargs['threshold_type'] in ["priority-group", "queue"]:
                commands = "sonic-clear {} threshold {} {} {}".format(kwargs['threshold_type'], kwargs['port_alias'],
                                                                      kwargs['index'], kwargs['buffer_type'])
            else:
                st.error("Invalid threshold_type provided '{}'".format(kwargs['threshold_type']))
                return False
    elif cli_type == "klish":
        if kwargs.get("breach"):
            if kwargs.get('breach') == "all":
                commands = "clear threshold breach all"
            else:
                commands = "clear threshold breach {}".format(kwargs['breach'])
        else:
            if 'threshold_type' not in kwargs or 'port_alias' not in kwargs or 'buffer_type' not in kwargs:
                st.error("Mandatory parameter threshold_type/port_alias not found")
                return False
            ports_list = utils.make_list(kwargs['port_alias'])
            if kwargs['threshold_type'] in ["priority-group", "queue"]:
                commands = list()
                buffers = ['unicast', 'multicast'] if kwargs['threshold_type'] == 'queue' else ['shared', 'headroom']
                for port in ports_list:
                    if port.upper() == 'CPU':
                        commands.append("interface {}".format(port.upper()))
                    else:
                        interface_details = get_interface_number_from_name(port)
                        commands.append("interface {} {}".format(interface_details['type'], interface_details['number']))
                    if kwargs['buffer_type'] == 'all':
                        for buffer in buffers:
                            commands.extend(["no threshold {} {} {}".format(kwargs['threshold_type'], i, buffer) for i in range(8)])
                    else:
                        commands.append("no threshold {} {} {}".format(kwargs['threshold_type'], kwargs['index'], kwargs['buffer_type']))
                    commands.append("exit")
            else:
                st.error("Invalid threshold_type provided '{}'".format(kwargs['threshold_type']))
                return False
    elif cli_type in ["rest-patch","rest-put"]:
        if kwargs.get("breach"):
            if kwargs.get('breach') == "all":
                data = {"openconfig-qos-ext:input": {"breach-event-id": "ALL"}}
            else:
                data = {"openconfig-qos-ext:input": {"breach-event-id": str(kwargs.get('breach'))}}
            url = st.get_datastore(dut, "rest_urls")["clear_threshold_breaches"]
            if not config_rest(dut, http_method="post", rest_url= url, json_data=data):
                st.debug("Failed to clear threshold breaches")
                return False
        else:
            if 'threshold_type' not in kwargs or 'port_alias' not in kwargs or 'buffer_type' not in kwargs:
                st.error("Mandatory parameter threshold_type/port_alias not found")
                return False
            ports_list = utils.make_list(kwargs['port_alias'])
            if kwargs['threshold_type'] in ["priority-group", "queue"]:
                buffers = ['unicast', 'multicast'] if kwargs['threshold_type'] == 'queue' else ['shared', 'headroom']
                for port in ports_list:
                    if kwargs['buffer_type'] == 'all':
                        for buffer in buffers:
                            for i in range(8):
                                url = st.get_datastore(dut,"rest_urls")["delete_int_threshold"].\
                                format(kwargs['threshold_type'], buffer,port, i)
                                if not delete_rest(dut, rest_url=url):
                                    st.debug("Failed to clear threshold buffers")
                                    return False
                    else:
                        url = st.get_datastore(dut,"rest_urls")["delete_int_threshold"].format(kwargs['threshold_type'],
                                            kwargs['buffer_type'], port, kwargs['index'])
                        if not delete_rest(dut, rest_url=url):
                            st.debug("Failed to clear threshold buffers")
                            return False
            else:
                st.error("Invalid threshold_type provided '{}'".format(kwargs['threshold_type']))
                return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, commands, type=cli_type)
    return True


def show_threshold(dut, **kwargs):
    """
    Show threshold
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param :threshold_type:  priority-group|queue
    :param :buffer_type: if threshold_type:priority-group {shared|headroom} |
                                                            else threshold_type:queue {unicast|multicast}
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if 'threshold_type' not in kwargs and 'buffer_type' not in kwargs:
        st.error("Mandatory parameter threshold_type and buffer_type not found")
        return False
    if cli_type == "click":
        command = "show {} threshold {}".format(kwargs['threshold_type'], kwargs['buffer_type'])
        if 'port_alias' in kwargs:
            command += " | grep -w {}".format(kwargs['port_alias'])
    elif cli_type == "klish":
        command = "show threshold {} {}".format(kwargs['threshold_type'], kwargs['buffer_type'])
        if 'port_alias' in kwargs:
            command += " | grep {}".format(kwargs['port_alias'])
            if kwargs['port_alias'].upper() == 'CPU' and kwargs['threshold_type'] == 'queue' and kwargs['buffer_type'] == 'multicast':
                command = "show threshold queue CPU"
                entries = st.show(dut, command, type=cli_type)
                output = {'port': 'CPU'}
                for entry in entries:
                    queue = entry['cpu'].split(":")[-1]
                    output['mc{}'.format(queue)] = entry['threshold']
                st.debug([output])
                return [output]
    elif cli_type in ["rest-patch","rest-put"]:
        output = list()
        url = st.get_datastore(dut, "rest_urls")["thresholds"]
        try:
            get_resp = get_rest(dut, rest_url=url)["output"]["openconfig-qos-ext:thresholds"]["threshold"]
            temp_output = {}
            for each in get_resp:
                buffer_mapping = {"priority-group": "pg", "unicast": "uc", "multicast": "mc"}
                each["buffer"] = each["type"] if each["buffer"] == "queue" else each["buffer"]
                if each["type"] == kwargs["buffer_type"]:
                    if each["port"] not in temp_output:
                        port = each["port"]
                        temp_output[port] = {}
                        temp_output[port]["port"] = port
                        temp_output[port]["{}{}".format(buffer_mapping[each["buffer"]], each["index"])] = each["state"]\
                        ["threshold-value"]
                    else:
                        temp_output[port]["{}{}".format(buffer_mapping[each["buffer"]], each["index"])] = each["state"]\
                        ["threshold-value"]
            if 'port_alias' in kwargs:
                output.append(temp_output[kwargs['port_alias']])
            else:
                output = list(temp_output.values())
        except Exception as e:
            st.debug("Error in getting interface thresholds")
            st.debug(e)
            return []
        return output
    output = st.show(dut, command, type=cli_type)
    return output


def verify_threshold(dut, **kwargs):
    """
    Verify Threshold
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :threshold_type: priority-group|queue
    :param :buffer_type: if threshold_type:priority-group {shared|headroom} |
                                                            else threshold_type: queue {unicast|multicast}
    :param :cli_type: click|klish
    :return:
    """
    output = show_threshold(dut, **kwargs)
    non_verify = ['threshold_type', 'buffer_type', 'port_alias', 'cli_type']
    temp_kwargs = {k: v for k, v in kwargs.items() if k not in non_verify}
    for each in temp_kwargs.keys():
        match = {each: temp_kwargs[each]}
        entries = utils.filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, temp_kwargs[each]))
            return False
    return True


def show_threshold_breaches(dut, cli_type=""):
    """
    Show Threshold Breaches
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :cli_type
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ["click", "klish"]:
        command = "show threshold breaches"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        output = list()
        url = st.get_datastore(dut, "rest_urls")["threshold_breaches"]
        try:
            get_resp = get_rest(dut, rest_url=url)["output"]["openconfig-qos-ext:threshold-breaches"]["breach"]
            for each in get_resp:
                breach = dict()
                if "state" in each:
                    breach["eventid"] = str(each["id"])
                    breach["index"] = str(each["state"]["index"])
                    breach["buffer"] = each["state"]["buffer"]
                    breach["threshold_type"] = each["state"]["type"]
                    breach["counter"] = each["state"]["counter"]
                    breach["value"] = str(each["state"]["breach-value"])
                    breach["port"] = each["state"]["port"]
                    output.append(breach)
        except Exception as e:
            st.debug("Error in getting threshold breaches")
            st.debug(e)
            return []
    return output


def verify_threshold_breaches(dut, **kwargs):
    """
    Verify Threshold Breaches
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :buffer: (Mandatory)
    :param :port:
    :param :index:
    :param :threshold_type:
    :param :value:
    :param :year:
    :param :month:
    :param :day:
    :param :hours:
    :param :minutes:
    :param :seconds:
    :param :eventid:
    :param :cli_type:
    :return:
    """
    if 'buffer' not in kwargs:
        st.error("Mandatory parameter 'buffer' not found")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_threshold_breaches(dut, cli_type)
    kwargs.pop("cli_type", "click")
    entries = utils.filter_and_select(output, None, {'buffer': kwargs['buffer']})
    if not entries:
        st.log("Provided buffer '{}' is not present in table ".format(kwargs['buffer']))
        return False
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries_temp = utils.filter_and_select(entries, None, match)
        if not entries_temp:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_hardware_map_status(dut, queues, itter_count=30, delay=1):
    """
    To verify the Queue init in hardware
    :param dut:
    :param queues:
    :param itter_count:
    :param delay:
    :return:
    """
    command = redis.build(dut, redis.COUNTERS_DB, "keys *MAP*")
    queues_li = utils.make_list(queues)
    i = 1
    while True:
        output = st.show(dut, command)
        output_list = utils.filter_and_select(output, ["name"], None)
        output_list = utils.dicts_list_values(output_list, "name")
        result = True
        for each_q in queues_li:
            if each_q not in output_list:
                st.log("{} not yet init.".format(each_q))
                result = False
        if result:
            return True
        if i > itter_count:
            st.log("Max {} tries Exceeded.Exiting..".format(i))
            return False
        i += 1
        st.wait(delay)


def verify_port_table_port_config(dut, itter_count=30, delay=1):
    """
    To verify the Port Table Port config status
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param itter_count:
    :param delay:
    :return:
    """
    command = redis.build(dut, redis.APPL_DB, "HGETALL PORT_TABLE:PortConfigDone")
    i = 1
    while True:
        output = st.show(dut, command)
        output_list = utils.filter_and_select(output, ["name"], None)
        output_list = utils.dicts_list_values(output_list, "name")
        if 'count' in output_list:
            st.log("{}".format(output))
            return True
        if i > itter_count:
            st.log("Max {} tries Exceeded.Exiting..".format(i))
            return False
        i += 1
        st.wait(delay)


def set_threshold_rest_data(**kwargs):
    """
    To Construct Threshold feature SET REST data
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :threshold_type: priority-group|queue
    :param :port_alias:
    :param :buffer_type: if threshold_type:priority-group {shared|headroom}
                                                        | else threshold_type:queue {unicast|multicast}
    :param :index: if threshold_type:priority-group - PGindex value | else threshold_type:queue - queueindex value
    :return:
    """
    if 'threshold_type' not in kwargs and 'port_alias' not in kwargs and 'buffer_type' not in kwargs and \
            'value' not in kwargs and 'index' not in kwargs:
        st.error("Mandatory parameter threshold_type/port_alias/index/buffer_type/value not found")
        return False

    if kwargs['threshold_type'] == 'priority-group' and kwargs['buffer_type'] == 'shared':
        rv = {
            "realm": "ingress-port-priority-group",
            "port": kwargs['port_alias'],
            "priority-group": kwargs['index'],
            "um-share-threshold": kwargs['value']
            }
        return rv

    if kwargs['threshold_type'] == 'priority-group' and kwargs['buffer_type'] == 'headroom':
        rv = {
            "realm": "ingress-port-priority-group",
            "port": kwargs['port_alias'],
            "priority-group": kwargs['index'],
            "um-headroom-threshold": kwargs['value']
            }
        return rv

    if kwargs['threshold_type'] == 'queue' and kwargs['buffer_type'] == 'unicast':
        rv = {
            "realm": "egress-uc-queue",
            "port": kwargs['port_alias'],
            "user-queue": kwargs['index'],
            "uc-threshold": kwargs['value']
            }
        return rv

    if kwargs['threshold_type'] == 'queue' and kwargs['buffer_type'] == 'multicast':
        rv = {"realm": "egress-mc-queue",
              "port": kwargs['port_alias'],
              "user-queue": kwargs['index'],
              "mc-threshold": kwargs['value']
              }
        return rv

    st.error('No Match for threshold_type and buffer_type found')
    return False


def get_threshold_rest_data(**kwargs):
    """
    To Construct Threshold feature GET REST data
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :threshold_type:
    :param :buffer_type:
    :return:
    """

    if 'threshold_type' not in kwargs and 'buffer_type' not in kwargs:
        st.error("Mandatory parameter threshold_type and buffer_type  not found")
        return False

    rv = {
        "include-ingress-port-priority-group": 0,
        "include-ingress-port-service-pool": 0,
        "include-ingress-service-pool": 0,
        "include-egress-port-service-pool": 0,
        "include-egress-service-pool": 0,
        "include-egress-uc-queue": 0,
        "include-egress-uc-queue-group": 0,
        "include-egress-mc-queue": 0,
        "include-egress-cpu-queue": 0,
        "include-egress-rqe-queue": 0,
        "include-device": 0
        }

    if kwargs['threshold_type'] == 'priority-group' and kwargs['buffer_type'] in ['shared', 'headroom']:
        rv['include-ingress-port-priority-group'] = 1
    if kwargs['threshold_type'] == 'queue' and kwargs['buffer_type'] == 'unicast':
        rv['include-egress-uc-queue'] = 1
    if kwargs['threshold_type'] == 'queue' and kwargs['buffer_type'] == 'multicast'  and kwargs['port'] != 'CPU':
        rv['include-egress-mc-queue'] = 1
    if kwargs['threshold_type'] == 'queue' and kwargs['buffer_type'] == 'multicast'  and kwargs['port'] == 'CPU':
        rv['include-egress-cpu-queue'] = 1

    return rv


def threshold_feature_debug(dut, mode, platform=None, test=''):
    """
    Debug calls for Threshold feature.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :param platform:
    :param test:
    :return:
    """
    mode_li = list(mode) if isinstance(mode, list) else [mode]
    for each_mode in mode_li:
        if each_mode == 'clear_counters':
            intapi.clear_interface_counters(dut)
            # intapi.clear_watermark_counters(dut,'all')

        if each_mode == 'show_counters':
            intapi.show_interface_counters_all(dut)
            # intapi.show_watermark_counters(dut,'all')
            asicapi.clear_counters(dut)
            st.wait(1)
            asicapi.dump_counters(dut)

        if each_mode == 'asic_info':
            asicapi.dump_threshold_info(dut, test, platform, 'asic_info')

        if each_mode == 'debug_log_enable':
            st.config(dut, 'swssloglevel -l DEBUG -c thresholdmgr', skip_error_check=True)
            st.config(dut, 'swssloglevel -l SAI_LOG_LEVEL_DEBUG -s -c TAM', skip_error_check=True)

        if each_mode == 'debug_log_disable':
            st.config(dut, 'swssloglevel -l INFO -c thresholdmgr', skip_error_check=True)
            st.config(dut, 'swssloglevel -l SAI_LOG_LEVEL_INFO -s -c TAM', skip_error_check=True)

        if each_mode == 'show_logging':
            logapi.show_logging(dut, lines=100)

        if each_mode == 'port_map':
            asicapi.dump_threshold_info(dut, test, platform, 'asic_portmap')

def config_buffer_pool_threshold(dut, **kwargs):
    """
    Config API for buffer pool threshold
    Author: Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

    :param dut:
    :param :pool:ingress_lossless_pool|egress_lossy_pool|egress_lossless_pool
    :param :threshold_value:
    :param :cli_type:click|klish
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    if 'pool' not in kwargs and 'threshold' not in kwargs:
        st.error("Mandatory parameters buffer pool name, threshold not found")
        return False

    if cli_type == 'klish':
        command = "threshold buffer-pool {} {}".format(kwargs['pool'], kwargs['threshold'])
    else:
        command = "config buffer-pool threshold {} {}".format(kwargs['pool'], kwargs['threshold'])
    st.config(dut, command, type=cli_type)
    return True

def verify_buffer_pool_threshold(dut, **kwargs):
    """
    Verify Buffer pool threshold
    Author: Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

    :param :dut:
    :param :pool:ingress_lossless_pool|egress_lossy_pool|egress_lossless_pool
    :param :threshold:
    :param :cli_type:click|klish

    :return:
    """
    output = show_buffer_pool_threshold(dut, **kwargs)
    non_verify = ['cli_type']
    temp_kwargs = {k: v for k, v in kwargs.items() if k not in non_verify}
    for each in temp_kwargs.keys():
        match = {each: temp_kwargs[each]}
        entries = utils.filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, temp_kwargs[each]))
            return False
    return True

def show_buffer_pool_threshold(dut, **kwargs):
    """
    Show buffer pool threshold
    Author: Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

    :param dut:
    :param :pool:ingress_lossless_pool|egress_lossy_pool|egress_lossless_pool
    :param :threshold:
    :param :cli_type:click|klish
    :return:
    """
    if 'pool' not in kwargs and 'threshold' not in kwargs:
        st.error("Mandatory parameters buffer pool name, threshold not found")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    if cli_type == "klish":
        command = "show threshold buffer-pool"
    else:
        command = "show buffer_pool threshold buffer_pool_all"
    output = st.show(dut, command, type=cli_type)
    return output

def clear_buffer_pool_threshold(dut, **kwargs):
    """
    Clear buffer pool configuration.
    Author: Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

    :param dut:
    :param :cli_type:click|klish
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type

    if cli_type == 'klish':
        command = "no threshold buffer-pool"
    else:
        command = "sonic-clear buffer-pool threshold"
    st.config(dut, command, type=cli_type)
    return True
