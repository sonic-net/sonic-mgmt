# This file contains the list of API's which performs snapshot configurations.
#Author: prudviraj k (prudviraj.kristipati.@broadcom.com)

from spytest import st
from utilities.common import filter_and_select, dicts_list_values,integer_parse, iterable
from utilities.utils import get_dict_from_redis_cli, get_interface_number_from_name
from apis.common import redis
from apis.system.rest import config_rest, delete_rest, get_rest

def config_snapshot_interval(dut,**kwargs):
    """
    configuring the water mark intervals
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to update the  watermark configuration
    :return:
    """
    snapshot_arg = kwargs
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ["rest-patch", "rest-put"] and  snapshot_arg['snap'] in ["clear_buffer-pool watermark", "sonic-clear buffer-pool watermark"]:
        cli_type = 'klish'
    if not snapshot_arg:
        st.error("Mandatory arguments are not given")
    if cli_type == "click":
        if snapshot_arg['snap'] == "interval":
            command = "config watermark interval {}".format(snapshot_arg['interval_val'])
        elif snapshot_arg['snap'] == "telemetry":
            command = "config watermark telemetry interval {}".format(snapshot_arg['interval_val'])
        elif snapshot_arg['snap'] == "clear_snaphot_interval":
            command = "sonic-clear watermark interval"
        elif snapshot_arg['snap'] == "clear_snapshot_counters":
            command = "sonic-clear {} {} {}".format(snapshot_arg['group'],snapshot_arg['table'],snapshot_arg['counter_type'])
        elif snapshot_arg['snap'] == "clear_buffer-pool watermark":
            command = "sonic-clear buffer-pool watermark"
        elif snapshot_arg['snap'] == "clear_buffer-pool persistent-watermark":
            command = "sonic-clear buffer-pool persistent-watermark"
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        if snapshot_arg['snap'] == "interval":
            command = "watermark interval {}".format(snapshot_arg['interval_val'])
        elif snapshot_arg['snap'] == "telemetry":
            command = "watermark telemetry interval {}".format(snapshot_arg['interval_val'])
        elif snapshot_arg['snap'] == "clear_snaphot_interval":
            command = "no watermark interval"
        elif snapshot_arg['snap'] == "clear_snapshot_counters":
            command = "clear {} {} {}".format(snapshot_arg['group'],snapshot_arg['table'],snapshot_arg['counter_type'])
        elif snapshot_arg['snap'] == "clear_buffer-pool watermark":
            command = "clear buffer_pool watermark"
        elif snapshot_arg['snap'] == "clear_buffer-pool persistent-watermark":
            command = "clear buffer_pool persistent-watermark"
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if snapshot_arg['snap'] == "interval":
            url = rest_urls['config_watermark_interval']
            data = {"openconfig-qos-ext:refresh-interval": snapshot_arg['interval_val']}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        elif snapshot_arg['snap'] == "telemetry":
            url = rest_urls['config_telemetry_interval']
            data = {"openconfig-qos-ext:refresh-interval": snapshot_arg['interval_val']}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        elif snapshot_arg['snap'] == "clear_snaphot_interval":
            url = rest_urls['config_watermark_interval']
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        elif snapshot_arg['snap'] == "clear_snapshot_counters":
            url = rest_urls['clear_watermark_counters']
            data = {"openconfig-qos-ext:input": { "buffer": snapshot_arg['group'], "buffer-type": snapshot_arg['counter_type'], "watermark-type": snapshot_arg['table']}}
            if not config_rest(dut, http_method='post', rest_url=url, json_data=data):
                return False
        return True
    else:
        st.error("Unsupported UI Type: {} provided".format(cli_type))
        return False

def show(dut,*argv,**kwargs):
    """
    show commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param argv:
    :param interval:
    :param clear_interval:
    :param persistent_head:
    :param persistent_shared:
    :param threshold_head:
    :param threshold__shared:
    :param watermark_head:
    :param watermark_shared:
    :param port_alias:
    :param column_name:
    :param queue_value:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ["rest-patch", "rest-put"] and 'column_name' in kwargs:
        cli_type = 'klish'
    if cli_type in ["rest-patch", "rest-put"]:
        for queue_type in argv:
            if queue_type in ["buffer_pool_watermark", "buffer_pool_persistent-watermark", "buffer_pool_counters_DB"]:
                cli_type = 'klish'
    persistent="show priority-group persistent-watermark"
    user_watermark="show priority-group watermark"
    queue_user_watermark= "show queue watermark"
    queue_persistent_watermark = "show queue persistent-watermark"
    if cli_type == 'click' or cli_type == 'klish':
        if "snapshot_interval" in argv:
            command = "show watermark interval"
        elif 'telemetry_interval' in argv:
            command = "show watermark telemetry interval"
        elif 'persistent_PG_headroom' in argv:
            command = persistent + " " + "{}".format("headroom")
        elif 'persistent_PG_shared' in argv:
            command = persistent + " " + "{}".format("shared")
        elif 'user_watermark_PG_headroom' in argv:
            command = user_watermark + " " + "{}".format("headroom")
        elif 'user_watermark_PG_shared' in argv:
            command = user_watermark + " " + "{}".format("shared")
        elif 'queue_user_watermark_unicast' in argv:
            command = queue_user_watermark + " " + "{}".format("unicast")
        elif 'queue_user_watermark_multicast' in argv:
            command = queue_user_watermark + " " + "{}".format("multicast")
        elif 'queue_user_watermark_cpu' in argv:
            command = queue_user_watermark + " " + "{}".format("CPU")
        elif 'queue_persistent_watermark_unicast' in argv:
            command = queue_persistent_watermark + " " + "{}".format("unicast")
        elif 'queue_persistent_watermark_multicast' in argv:
            command = queue_persistent_watermark + " " + "{}".format("multicast")
        elif 'buffer_pool_watermark' in argv or 'percent' in kwargs :
            if cli_type == 'klish' and 'percent' in kwargs:
                perc = 'percentage'
            else:
                perc = kwargs.get('percent', '')
            command = "show buffer_pool watermark {}".format(perc)
        elif 'buffer_pool_persistent-watermark' in argv or 'percent' in kwargs :
            if cli_type == 'klish' and 'percent' in kwargs:
                perc = 'percentage'
            else:
                perc = kwargs.get('percent', '')
            command = "show buffer_pool persistent-watermark {}".format(perc)
        elif 'column_name' and 'queue_value' in kwargs:
            intf_name = st.get_other_names(dut, [kwargs['interface_name']])[0] if '/' in kwargs['interface_name'] else kwargs['interface_name']
            command = redis.build(dut, redis.COUNTERS_DB, "hget {} {}:{}".format(kwargs['column_name'], intf_name, kwargs['queue_value']))
            output = st.show(dut, command)
            oid = output[0]['oid'].strip('"')
            command = redis.build(dut, redis.COUNTERS_DB, "hgetall {}:{}".format(kwargs['table_name'], oid))
            output = st.show(dut, command)
            output = output[:-1]
            dut_output = get_dict_from_redis_cli(output)
            st.log(dut_output)
            return [dut_output]
        elif 'buffer_pool_counters_DB' in argv:
            command = redis.build(dut, redis.COUNTERS_DB, "Hgetall COUNTERS_BUFFER_POOL_NAME_MAP")
            output = st.show(dut, command)
            output = output[:-1]
            dut_output = get_dict_from_redis_cli(output)
            st.log(dut_output)
            command = redis.build(dut, redis.COUNTERS_DB, "hgetall COUNTERS:{}".format(dut_output[kwargs['oid_type']].strip('"')))
            output = st.show(dut, command)
            output = output[:-1]
            dut_output = get_dict_from_redis_cli(output)
            st.log(dut_output)
            return [dut_output]
        if 'port_alias' in kwargs or 'percentage' in kwargs:
            if cli_type == 'click':
                command += " {} | grep -w {}".format(kwargs.get('percentage', ''), kwargs['port_alias'])
                return st.show(dut, command, type=cli_type)
            elif cli_type == 'klish':
                if kwargs['port_alias'] == 'CPU':
                    command += " | grep {}".format(kwargs['port_alias'])
                else:
                    interface_details = get_interface_number_from_name(kwargs['port_alias'])
                    if 'percentage' in kwargs:
                        using_perc = command.split(" ")
                        using_perc.insert(-1, "percentage")
                        command = " ".join(using_perc)
                        command += " interface {} {}".format(interface_details.get("type"),
                                                             interface_details.get("number"))
                    else:
                        command += " interface {} {}".format(interface_details.get("type"),
                                                             interface_details.get("number"))
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        ret_val = list()
        rest_urls = st.get_datastore(dut, "rest_urls")
        if "snapshot_interval" in argv:
            url = rest_urls['get_watermark_interval']
            get_info = get_rest(dut, rest_url=url, timeout=60)
            temp = dict()
            temp['snapshotinterval'] = get_info['output']['openconfig-qos-ext:watermark']['state']['refresh-interval']
            ret_val.append(temp)
            st.debug(ret_val)
            return ret_val
        elif 'telemetry_interval' in argv:
            url = rest_urls['get_telemetry_interval']
            get_info = get_rest(dut, rest_url=url, timeout=60)
            temp = dict()
            temp['telemetryinterval'] = get_info['output']['openconfig-qos-ext:telemetry-watermark']['state']['refresh-interval']
            ret_val.append(temp)
            st.debug(ret_val)
            return ret_val
        for queue_type in argv:
            if 'port_alias' in kwargs or 'percentage' in kwargs:
                ret_val = list()
                rest_urls = st.get_datastore(dut, "rest_urls")
                if queue_type in ['queue_user_watermark_unicast', 'queue_user_watermark_multicast', 'queue_persistent_watermark_unicast', 'queue_persistent_watermark_multicast', 'queue_user_watermark_cpu']:
                    url = rest_urls['get_queue_counter_values'].format(kwargs['port_alias'])
                    get_info = get_rest(dut, rest_url=url, timeout=60)
                    for entry in get_info['output']['openconfig-qos:queues']['queue']:
                        temp = dict()
                        counters_info = entry['state']
                        port, queue = counters_info['name'].split(':')
                        type = counters_info["openconfig-qos-ext:traffic-type"]
                        counter = type.lower() + queue
                        if kwargs['port_alias'] == 'CPU':
                            cpu_counter = port + queue
                            temp['queue'] = cpu_counter
                            temp['bytes'] = counters_info["openconfig-qos-ext:watermark"]
                        if 'percentage' in kwargs:
                            if queue_type in ['queue_user_watermark_unicast', 'queue_user_watermark_multicast']:
                                temp[counter] = counters_info["openconfig-qos-ext:watermark-percent"]
                            elif queue_type in ['queue_persistent_watermark_unicast', 'queue_persistent_watermark_multicast']:
                                temp[counter] = counters_info["openconfig-qos-ext:persistent-watermark-percent"]
                        else:
                            if queue_type in ['queue_user_watermark_unicast', 'queue_user_watermark_multicast']:
                                temp[counter] = counters_info["openconfig-qos-ext:watermark"]
                            elif queue_type in ['queue_persistent_watermark_unicast', 'queue_persistent_watermark_multicast']:
                                temp[counter] = counters_info["openconfig-qos-ext:persistent-watermark"]
                        ret_val.append(temp)
                    st.debug(ret_val)
                    return ret_val
                if queue_type in ['persistent_PG_shared', 'user_watermark_PG_shared', 'persistent_PG_headroom', 'user_watermark_PG_headroom']:
                    url = rest_urls['get_pg_counter_values'].format(kwargs['port_alias'])
                    get_info = get_rest(dut, rest_url=url, timeout=60)
                    for entry in get_info['output']['openconfig-qos-ext:priority-groups']['priority-group']:
                        temp = dict()
                        counters_info = entry['state']
                        port, queue = counters_info['name'].split(':')
                        for i in range(0, 8):
                            if queue == str(i):
                                counter = 'pg' + str(i)
                                if 'percentage' in kwargs:
                                    if queue_type == 'user_watermark_PG_shared':
                                        temp[counter] = counters_info['shared-watermark-percent']
                                    elif queue_type == 'user_watermark_PG_headroom':
                                        temp[counter] = counters_info['headroom-watermark-percent']
                                    elif queue_type == 'persistent_PG_shared':
                                        temp[counter] = counters_info['shared-persistent-watermark-percent']
                                    elif queue_type == 'persistent_PG_headroom':
                                        temp[counter] = counters_info['headroom-persistent-watermark-percent']
                                else:
                                    if queue_type == 'user_watermark_PG_shared':
                                        temp[counter] = counters_info['shared-watermark']
                                    elif queue_type == 'user_watermark_PG_headroom':
                                        temp[counter] = counters_info['headroom-watermark']
                                    elif queue_type == 'persistent_PG_shared':
                                        temp[counter] = counters_info['shared-persistent-watermark']
                                    elif queue_type == 'persistent_PG_headroom':
                                        temp[counter] = counters_info['headroom-persistent-watermark']
                                ret_val.append(temp)
                    st.debug(ret_val)
                    return ret_val
    else:
        st.error("Unsupported UI Type: {} provided".format(cli_type))
        return False



def verify(dut, *argv, **kwargs):
    """
    verify commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :param :verify_list:
    :return:
    """
    result = True

    if not kwargs.get('verify_list'):
        st.error("Mandatory arguments 'verify_list' is not given")
    output = show(dut, *argv, **kwargs)
    if not output:
        return False
    for each in kwargs['verify_list']:
        if not filter_and_select(output, None, each):
            st.log("{} is not matching in the output {} ".format(each, output))
            result = False

    return result

def verify_buffer_pool(dut, *argv, **kwargs):
    """
    verify commands summary
    Author: phani ravula (phanikumar.ravula@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :param :verify_list:
    :return:
    """
    result = True

    if not kwargs.get('verify_list'):
        st.error("Mandatory arguments 'verify_list' is not given")
    output = show(dut, *argv, **kwargs)
    if not output:
        return False
    if kwargs['verify_list']:
        entries = filter_and_select(output, None, kwargs['verify_list'])
        if kwargs['key'] and not filter_and_select(entries, None, kwargs['key']):
            return False
        return True
    return result


def get(dut, *argv, **kwargs):
    """
    verify commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param argv:
    :param :get_value:
    :return:
    """
    if not (kwargs.get('get_value') and kwargs.get('match')):
        st.error("Mandatory arguments 'get_value', 'match' is not given")
    output = show(dut, *argv, **kwargs)
    if not output:
        return None
    entries = filter_and_select(output, None, kwargs['match'])
    out = dicts_list_values(entries, kwargs['get_value'])
    return integer_parse(out[0])


def load_json_config(dut, convert_json, config_file):
    """
    To load buffer configuration
    Author: Jagadish Ch (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param convert_json:
    :param :config_file:
    :return:
    """
    st.config(dut, convert_json)
    load_json = "config load {} -y".format(config_file)
    st.config(dut, load_json)
    return True

def multicast_queue_start_value(dut, *argv, **kwargs):
    result = True
    output = show(dut, *argv, **kwargs)
    for queue in iterable(output):
        if queue.get('mc8'):
            result = True
            break
        else:
            result = False
    return result
