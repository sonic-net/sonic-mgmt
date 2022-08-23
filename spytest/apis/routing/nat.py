# Author(Rest Porting): Prudvi Mangadu.
from spytest import st
from spytest.utils import filter_and_select
from utilities.utils import get_interface_number_from_name
from apis.common import redis
from apis.system.rest import config_rest, get_rest, delete_rest


def config_nat_feature(dut, oper='enable', cli_type="", skip_error_check=True):
    """
    Config NAT Feature
    Author:kesava-swamy.karedla@broadcom.com

    :param dut:
    :param oper: enable/disable
    :param cli_type:
    :param skip_error_check:
    :return:
    """
    instance = 0
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "config nat feature {}".format(oper)
    elif cli_type == "klish":
        command = list()
        operation = "enable" if oper == "enable" else "no enable"
        command.append("nat")
        command.append("{}".format(operation))
        command.append("exit")
    elif cli_type in ["rest-patch", "rest-put"]:
        operation = True if oper == "enable" else False
        url = st.get_datastore(dut, "rest_urls")['config_nat_feature'].format(instance)
        data = {"openconfig-nat:config": {"enable": operation}}
        config_rest(dut, http_method=cli_type, rest_url=url, json_data=data)
        return True
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def config_nat_static(dut, **kwargs):
    """
    Config NAT Static
    Author:kesava-swamy.karedla@broadcom.com

    :param :dut:
    :param :config: add/del
    :param :local_ip: local ipv4 address
    :param :global_ip: global ipv4 address
    :param :nat_type: snat/dnat
    :param :twice_nat_id: twice_nat_id for group
    :param :protocol: basic/tcp/udp
    :param :local_port_id: L4 port number:
    :param :global_port_id: L4 port number

    usage:
    config_nat_static(dut1, protocol="basic, global_ip="65,89.12.11", local_ip="10.0.0.1", nat_type="dnat",
    config="add")
    config_nat_static(dut1, protocol="basic, global_ip="65,89.12.11", local_ip="10.0.0.1", nat_type="snat",
    config="add")
    config_nat_static(dut1, protocol="basic, global_ip="65,89.12.11",local_ip="10.0.0.1", nat_type="dnat",
    twice_nat_id ="100", config="yes")
    config_nat_static(dut1, protocol="basic, global_ip="65,89.12.11",local_ip="10.0.0.1", nat_type="snat",
    twice_nat_id ="100", config="yes")
    config_nat_static(dut1, protocol="basic, global_ip="65,89.12.11", local_ip="10.0.0.1", config="del")
    """
    instance = 0
    result = False
    command = ""
    if "local_ip" not in kwargs and "global_ip" not in kwargs and "config" not in kwargs and "protocol" not in kwargs:
        st.error("Mandatory params local_ip,global_ip,config,protocol not provided ")
        return result
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)
    if cli_type == "click":
        if kwargs["config"] == "add":
            if kwargs['protocol'] == 'all':
                command = "config nat add static basic {} {} ".format(kwargs["global_ip"], kwargs["local_ip"])

            if kwargs['protocol'] in ['tcp', 'udp']:
                command = "config nat add static {} {} {} {} {}".format(kwargs['protocol'],
                                                                        kwargs["global_ip"],
                                                                        kwargs["global_port_id"],
                                                                        kwargs["local_ip"],
                                                                        kwargs["local_port_id"])
            if "nat_type" in kwargs:
                command += ' -nat_type {}'.format(kwargs["nat_type"])

            if "twice_nat_id" in kwargs:
                command += ' -twice_nat_id {}'.format(kwargs["twice_nat_id"])

        if kwargs["config"] == "del":
            if kwargs['protocol'] == 'all':
                command = "config nat remove static basic {} {} ".format(kwargs["global_ip"],
                                                                         kwargs["local_ip"])
            if kwargs['protocol'] in ['tcp', 'udp']:
                command = "config nat remove static {} {} {} {} {} ".format(kwargs['protocol'], kwargs["global_ip"],
                                                                            kwargs["global_port_id"],
                                                                            kwargs["local_ip"],
                                                                            kwargs["local_port_id"])
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == "klish":
        commands = list()
        cmd = ''
        commands.append("nat")
        if kwargs.get("config") == "add":
            if kwargs['protocol'] == 'all':
                cmd = "static basic {} {}".format(kwargs["global_ip"], kwargs["local_ip"])
            elif kwargs['protocol'] in ['tcp', 'udp']:
                cmd = "static {} {} {} {} {}".format(kwargs['protocol'], kwargs["global_ip"], kwargs["global_port_id"],
                                                     kwargs["local_ip"], kwargs["local_port_id"])
            if "nat_type" in kwargs:
                cmd += " {}".format(kwargs["nat_type"])
            if "twice_nat_id" in kwargs:
                cmd += " twice-nat-id {}".format(kwargs["twice_nat_id"])
            commands.append(cmd)
        else:
            if kwargs['protocol'] == 'all':
                commands.append("no static basic {}".format(kwargs["global_ip"]))
            elif kwargs['protocol'] in ['tcp', 'udp']:
                commands.append(
                    "no static {} {} {}".format(kwargs['protocol'], kwargs["global_ip"], kwargs["global_port_id"]))
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)

    elif cli_type in ["rest-patch", "rest-put"]:
        data = {}
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = ''
        if kwargs.get("config") == "add":
            if kwargs['protocol'] == 'all':
                url = rest_urls['config_nat_static'].format(instance, kwargs["global_ip"])
                data = {"openconfig-nat:config": {"internal-address": kwargs["local_ip"]}}

            elif kwargs['protocol'] in ['tcp', 'udp']:
                protocol_no = 6 if kwargs['protocol'] == 'tcp' else 17
                url = rest_urls['config_napt_static'].format(instance, kwargs["global_ip"], protocol_no,
                                                             kwargs["global_port_id"])
                data = {"openconfig-nat:config": {"internal-address": kwargs["local_ip"],
                                                  "internal-port": int(kwargs["local_port_id"])}}
            if "nat_type" in kwargs:
                data['openconfig-nat:config']['type'] = kwargs["nat_type"].upper()
            if "twice_nat_id" in kwargs:
                data['openconfig-nat:config']['twice-nat-id'] = int(kwargs["twice_nat_id"])

            config_rest(dut, http_method=cli_type, rest_url=url, json_data=data)
            return True
        else:
            if kwargs['protocol'] == 'all':
                url = rest_urls['del_nat_static'].format(instance, kwargs["global_ip"])
            elif kwargs['protocol'] in ['tcp', 'udp']:
                protocol_no = 6 if kwargs['protocol'] == 'tcp' else 17
                url = rest_urls['del_napt_static'].format(instance, kwargs["global_ip"], protocol_no,
                                                          kwargs["global_port_id"])
            delete_rest(dut, rest_url=url)
            return True
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def config_nat_pool(dut, **kwargs):
    """
    Config NAT pool
    Author:kesava-swamy.karedla@broadcom.com

    :param :dut:
    :param :config: add | del
    :param :ool_name:
    :param :global_ip:
    :param :global_ip_range:
    :param :lobal_port_range:

    usage:
    config_nat_pool(dut1, pool_name="pool1", global_ip_range="65.89.12.11-65.89.12.20", config="add")
    config_nat_static_basic(dut1, pool_name="pool1", global_ip_range="65.89.12.11-65.89.12.20", config="add")
    config_nat_static_basic(dut1, local_ip="10.0.0.1", global_ip="65.89.12.11", nat_type="dnat", twice_nat_id ="100",
    config="yes")
    """
    instance = 0
    result = False
    command = ''
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)
    if "pool_name" not in kwargs and "config" not in kwargs:
        st.error("Mandatory params pool_name, config are not provided")
        return result
    if kwargs["config"] == "add":
        if not (kwargs["global_ip_range"] or kwargs["global_port_range"]):
            st.error("Mandatory params pool_name, config, global_ip_range, global_port_range not provided")
            return result
    if kwargs["config"] == "add":
        if cli_type == "click":
            command = "config nat add pool {} ".format(kwargs["pool_name"])
            if "global_ip_range" in kwargs:
                command += " {}".format(kwargs['global_ip_range'])
            if "global_port_range" in kwargs:
                command += " {}".format(kwargs['global_port_range'])
        elif cli_type == "klish":
            commands = list()
            commands.append("nat")
            cmd = "pool {}".format(kwargs["pool_name"])
            if "global_ip_range" in kwargs:
                cmd += " {}".format(kwargs['global_ip_range'])
            if "global_port_range" in kwargs:
                cmd += " {}".format(kwargs['global_port_range'])
            commands.append(cmd)
            commands.append("exit")
            st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
            return True
        elif cli_type in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['config_nat_pool'].format(instance, kwargs["pool_name"])
            data = {"openconfig-nat:config": {}}
            if "global_ip_range" in kwargs:
                data['openconfig-nat:config']["nat-ip"] = kwargs['global_ip_range']
            if "global_port_range" in kwargs:
                data['openconfig-nat:config']["nat-port"] = kwargs['global_port_range']
            config_rest(dut, http_method=cli_type, rest_url=url, json_data=data)
            return True
        else:
            st.log("UNSUPPORTE CLI TYPE")
            return False
    if kwargs["config"] == "del":
        if cli_type == "click":
            command = "config nat remove pool {}".format(kwargs["pool_name"])
        elif cli_type == "klish":
            commands = list()
            commands.append("nat")
            commands.append("no pool {}".format(kwargs["pool_name"]))
            commands.append("exit")
            st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
            return True
        elif cli_type in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['del_nat_pool'].format(instance)
            delete_rest(dut, rest_url=url)
            return True
        else:
            st.log("UNSUPPORTE CLI TYPE")
            return False
    # Here handling the error while adding or deleting the pool
    if "skip_error" in kwargs and kwargs["skip_error"]:
        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
            st.log("Error handled by API")
            return False
    else:
        st.config(dut, command)
    return True


def config_nat_pool_binding(dut, **kwargs):
    """
    Config NAT pool bindings
    Author:kesava-swamy.karedla@broadcom.com

    :param :dut:
    :param :config: add/del:
    :param :binding_name:
    :param :pool_name:
    :param :nat_type:
    :param :twice_nat_id:
    :param :acl_name:

    usage:
    config_nat_pool_binding(dut1, binding_name="name", pool_name="pool1", acl_name="acl1", nat_type="dnat",
    config="add")
    """
    #  config nat add binding bind1 test1 acl1
    instance = 0
    result = False
    command = ''
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)
    if cli_type not in ["click", "klish", "rest-patch", "rest-put"]:
        st.log("UNSUPPORTE CLI TYPE")
        return False
    if "binding_name" not in kwargs and "config" not in kwargs:
        st.error("Mandatory params binding_name, config not provided ")
        return result

    if kwargs["config"] == "add":
        if "pool_name" not in kwargs:
            st.error("Mandatory params pool_name is not provided ")
            return result
        if cli_type == "click":
            command = "config nat add binding {} {}".format(kwargs["binding_name"], kwargs["pool_name"])
            if "acl_name" in kwargs:
                command += " {}".format(kwargs["acl_name"])
            if "nat_type" in kwargs:
                command += " -nat_type {}".format(kwargs["nat_type"])
            if "twice_nat_id" in kwargs:
                command += ' -twice_nat_id {}'.format(kwargs["twice_nat_id"])
        elif cli_type == "klish":
            command = list()
            command.append("nat")
            cmd = "binding {} {}".format(kwargs["binding_name"], kwargs["pool_name"])
            if "acl_name" in kwargs:
                cmd += " {}".format(kwargs["acl_name"])
            if "nat_type" in kwargs:
                cmd += " {}".format(kwargs["nat_type"])
            if "twice_nat_id" in kwargs:
                cmd += " twice-nat-id {}".format(kwargs["twice_nat_id"])
            command.append(cmd)
            command.append("exit")
        elif cli_type in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['config_nat_pool_binding'].format(instance, kwargs["binding_name"])
            data = {"openconfig-nat:config": {"nat-pool": kwargs["pool_name"]}}
            if "acl_name" in kwargs:
                data['openconfig-nat:config']['access-list'] = kwargs["acl_name"]
            if "nat_type" in kwargs:
                data['openconfig-nat:config']['type'] = kwargs["nat_type"].upper()
            if "twice_nat_id" in kwargs:
                data['openconfig-nat:config']['twice-nat-id'] = int(kwargs["twice_nat_id"])
            config_rest(dut, http_method=cli_type, rest_url=url, json_data=data)
            return True

    if kwargs["config"] == "del":
        if cli_type == "click":
            command = "config nat remove binding {} ".format(kwargs['binding_name'])
        elif cli_type == "klish":
            command = list()
            command.append("nat")
            command.append("no binding {}".format(kwargs["binding_name"]))
            command.append("exit")
        elif cli_type in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['del_nat_pool_binding'].format(instance, kwargs["binding_name"])
            delete_rest(dut, rest_url=url)
            return True
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def config_nat_interface(dut, **kwargs):
    """
    Config NAT interface
    Author:kesava-swamy.karedla@broadcom.com
    :param :dut:
    :param :config: add-del:
    :param :interface_name:
    :param :zone_value:

    usage:
    config_nat_interface(dut1, interface_name, zone_value, config="add")
    config_nat_interface(dut1, interface_name, config="del")
    """
    result = False
    command = ''
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)
    if cli_type not in ["klish", "click", "rest-patch", "rest-put"]:
        st.log("UNSUPPORTE CLI TYPE")
        return False
    if "interface_name" not in kwargs and "config" not in kwargs:
        st.error("Mandatory params interface_name or config not provided")
        return result
    if kwargs["config"] == "add":
        if "zone_value" not in kwargs:
            st.error("Mandatory params zone_vlaue not provided")
            return result
        if cli_type == "click":
            command = "config nat add interface {} -nat_zone {}".format(kwargs["interface_name"], kwargs["zone_value"])
        elif cli_type == "klish":
            command = list()
            intf_data = get_interface_number_from_name(kwargs["interface_name"])
            command.append("interface {} {}".format(intf_data["type"], intf_data["number"]))
            command.append("nat-zone {}".format(kwargs["zone_value"]))
            command.append("exit")
        elif cli_type in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['config_nat_interface'].format(kwargs["interface_name"])
            data = {"openconfig-interfaces-ext:nat-zone": int(kwargs["zone_value"])}
            config_rest(dut, http_method=cli_type, rest_url=url, json_data=data)
            return True

    if kwargs["config"] == "del":
        if cli_type == "click":
            command = "config nat remove interface {}".format(kwargs["interface_name"])
        elif cli_type == "klish":
            command = list()
            intf_data = get_interface_number_from_name(kwargs["interface_name"])
            command.append("interface {} {}".format(intf_data["type"], intf_data["number"]))
            command.append("no nat-zone")
            command.append("exit")
        elif cli_type in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['del_nat_interface'].format(kwargs["interface_name"])
            delete_rest(dut, rest_url=url)
            return True

    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def config_nat_timeout(dut, **kwargs):
    """
    Conifg NAT Timeout
    Author:kesava-swamy.karedla@broadcom.com

    :param :dut:
    :param :config: add/del
    :param :udp_timeout:
    :param :tcp_timeout:

    usage:
    config_nat_timeout(dut1, udp_timeout)
    config_nat_timeout(dut1, tcp_timeout)
    """
    instance = 0
    command = ''
    data = {"openconfig-nat:config": {}}
    if not kwargs:
        st.error("Alteast pass any of config, timeout, udp_timeout and/or tcp_timeout")
        return False
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    skip_error_check = kwargs.get("skip_error_check", True)
    if cli_type not in ["click", "klish", "rest-patch", "rest-put"]:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    if cli_type == "klish":
        command = list()
        command.append("nat")
    if "timeout" in kwargs:
        if cli_type == "click":
            if kwargs["config"] == "set":
                command = "config nat set timeout {}".format(kwargs["timeout"])
            else:
                command = "config nat reset timeout"
        elif cli_type == "klish":
            if kwargs["config"] == "set":
                command.append("timeout {}".format(kwargs["timeout"]))
            else:
                command.append("no timeout")
        elif cli_type in ["rest-patch", "rest-put"]:
            if kwargs["config"] == "set":
                data["openconfig-nat:config"]['timeout'] = int(kwargs["timeout"])
            else:
                data["openconfig-nat:config"]['timeout'] = 600
    if "udp_timeout" in kwargs:
        if cli_type == "click":
            if kwargs["config"] == "set":
                command = "config nat set udp-timeout {}".format(kwargs["udp_timeout"])
            else:
                command = "config nat reset udp-timeout"
        elif cli_type == "klish":
            if kwargs["config"] == "set":
                command.append("udp-timeout {}".format(kwargs["udp_timeout"]))
            else:
                command.append("no udp-timeout")
        elif cli_type in ["rest-patch", "rest-put"]:
            if kwargs["config"] == "set":
                data["openconfig-nat:config"]['udp-timeout'] = int(kwargs["udp_timeout"])
            else:
                data["openconfig-nat:config"]['udp-timeout'] = 300
    if "tcp_timeout" in kwargs:
        if cli_type == "click":
            if kwargs["config"] == "set":
                command = "config nat set tcp-timeout {}".format(kwargs["tcp_timeout"])
            else:
                command = "config nat reset tcp-timeout"
        elif cli_type == "klish":
            if kwargs["config"] == "set":
                command.append("tcp-timeout {}".format(kwargs["tcp_timeout"]))
            else:
                command.append("no tcp-timeout")
        elif cli_type in ["rest-patch", "rest-put"]:
            if kwargs["config"] == "set":
                data["openconfig-nat:config"]['tcp-timeout'] = int(kwargs["tcp_timeout"])
            else:
                data["openconfig-nat:config"]['tcp-timeout'] = 86400
    if cli_type == "klish":
        command.append("exit")
    if cli_type in ["rest-patch", "rest-put"]:
        url = st.get_datastore(dut, "rest_urls")['config_nat_feature'].format(instance)
        config_rest(dut, http_method=cli_type, rest_url=url, json_data=data)
        return True
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def verify_nat_config(dut, mode, **kwargs):
    """
    Verify NAT Config
    :param dut:
    :param mode:
    :param kwargs:
    :return:
    """
    nat_config_modes = ['globalvalues', 'static', 'pool', 'bindings']
    if mode not in nat_config_modes:
        st.error("Invalid mode {}".format(mode))
        return False
    command = "show nat config {}".format(mode)
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def clear_nat(dut, **kwargs):
    """
    Clear NAT
    Author:kesava-swamy.karedla@broadcom.com

    :param dut:
    :param :translations: Ture/False
    :param :statistics: True/False

    usage:
    clear_nat(dut1, translations=True)
    clear_nat(dut1, statistics=True)
    """
    command = ''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "click":
        if "translations" in kwargs:
            command = "sonic-clear nat translations"
        if "statistics" in kwargs:
            command = "sonic-clear nat statistics"
    elif cli_type == "klish":
        if "translations" in kwargs:
            command = "clear nat translations"
        if "statistics" in kwargs:
            command = "clear nat statistics"
    elif cli_type in ["rest-patch", "rest-put"]:
        url = st.get_datastore(dut, "rest_urls")['clear_nat']
        data = {}
        if "translations" in kwargs:
            data = {"sonic-nat:input": {"nat-param": "ENTRIES"}}
        if "statistics" in kwargs:
            data = {"sonic-nat:input": {"nat-param": "STATISTICS"}}
        config_rest(dut, http_method='post', rest_url=url, json_data=data)
        return True
    else:
        st.log("UNSUPPORTE CLI TYPE")
        return False
    st.config(dut, command, type=cli_type)
    return True


def show_nat_translations(dut, cli_type=""):
    """
    Show NAT Translations
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param cli_type:
    :return:
    """
    instance = 0
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if 'rest' in cli_type:
        return _get_nat_oc_yang_output(dut, call='translations', instance=instance)
    else:
        command = "show nat translations"
    return st.show(dut, command, type=cli_type)


def show_nat_statistics(dut, cli_type=""):
    """
    Show NAT Statistics
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param cli_type:
    :return:
    """
    instance = 0
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if 'rest' in cli_type:
        return _get_nat_oc_yang_output(dut, call='statistics', instance=instance)
    else:
        result = list()
        command = "show nat statistics"
        output = st.show(dut, command, type=cli_type)
        for data in output:
            res = dict()
            for key, value in data.items():
                if key == "protocol":
                    res.update({key: value.lower()})
                else:
                    res.update({key: value})
            result.append(res)
        return result


def get_nat_statistics(dut, **kwargs):
    """
    Get NAT Statistics
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    stats = ['packets', 'bytes']
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_nat_statistics(dut, cli_type=cli_type)
    match = {}
    if 'protocol' in kwargs:
        match['protocol'] = kwargs['protocol']
    if 'src_ip' in kwargs:
        match['src_ip'] = kwargs['src_ip']
    if 'src_ip_port' in kwargs:
        match['src_ip_port'] = kwargs['src_ip_port']
    if 'dst_ip' in kwargs:
        match['dst_ip'] = kwargs['dst_ip']
    if 'dst_ip_port' in kwargs:
        match['dst_ip_port'] = kwargs['dst_ip_port']
    st.log(match)
    entries = filter_and_select(output, stats, match)
    return entries


def poll_for_nat_statistics(dut, itr=15, delay=2, **kwargs):
    """
    Author:kiran-kumar.vedula@broadcom.com
    :param :dut:
    :param :acl_table:
    :param :acl_rule:
    :param :itr:
    :param :delay:
    :return:
    """
    i = 1
    while True:
        result = verify_nat_statistics(dut, **kwargs)
        if result:
            return get_nat_statistics(dut, **kwargs)
        if i >= itr:
            return None
        st.wait(delay)
        i += 1

def poll_for_twice_nat_statistics(dut, itr=15, delay=2, **kwargs):
    """
    :param :dut:
    :param :acl_table:
    :param :acl_rule:
    :param :itr:
    :param :delay:
    :return:
    """
    i = 1
    while True:
        result = verify_twice_nat_statistics(dut, **kwargs)
        if result is None:
            if i >= itr:
                return None
            st.wait(delay)
            i += 1
        else:
            return result

def verify_nat_statistics(dut, **kwargs):
    """
    Verify NAT Statistics
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    stats = ['packets', 'bytes']
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_nat_statistics(dut, cli_type=cli_type)
    match = {}
    match1 = {}

    if 'protocol' in kwargs:
        match['protocol'] = kwargs['protocol']
        match1['protocol'] = kwargs['protocol']
    if 'src_ip' in kwargs:
        match['src_ip'] = kwargs['src_ip']
    if 'src_ip_port' in kwargs:
        match['src_ip_port'] = kwargs['src_ip_port']

    if 'dst_ip' in kwargs:
        match1['dst_ip'] = kwargs['dst_ip']
    if 'dst_ip_port' in kwargs:
        match1['dst_ip_port'] = kwargs['dst_ip_port']

    st.debug(match)
    st.debug(match1)
    entries = filter_and_select(output, stats, match)
    entries1 = filter_and_select(output, stats, match1)

    if entries and (int(entries[0]['packets']) > 0):
        return True
    elif entries1 and (int(entries1[0]['packets']) > 0):
        return True
    else:
        return False


def verify_twice_nat_statistics(dut, **kwargs):
    """
    Verify Twice NAT Statistics

    :param dut:
    :return:
    """
    stats = ['packets', 'bytes']
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_nat_statistics(dut, cli_type=cli_type)
    match = {}

    if 'protocol' in kwargs:
        match['protocol'] = kwargs['protocol']
    if 'src_ip' in kwargs:
        match['src_ip'] = kwargs['src_ip']
    if 'src_ip_port' in kwargs:
        match['src_ip_port'] = kwargs['src_ip_port']
    if 'dst_ip' in kwargs:
        match['dst_ip'] = kwargs['dst_ip']
    if 'dst_ip_port' in kwargs:
        match['dst_ip_port'] = kwargs['dst_ip_port']

    st.debug(match)
    entries = filter_and_select(output, stats, match)

    if entries and (int(entries[0]['packets']) > 0):
        return entries
    else:
        return None

def get_nat_translations(dut, **kwargs):
    """
    Get NAT Translations
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    get_list = ["trn_src_ip", "trn_src_ip_port", "trn_dst_ip", "trn_dst_ip_port"]
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_nat_translations(dut, cli_type=cli_type)
    st.log(output)
    match = {}
    if 'protocol' in kwargs:
        match['protocol'] = kwargs['protocol']
    if 'src_ip' in kwargs:
        match['src_ip'] = kwargs['src_ip']
    if 'src_ip_port' in kwargs:
        match['src_ip_port'] = kwargs['src_ip_port']
    if 'dst_ip' in kwargs:
        match['dst_ip'] = kwargs['dst_ip']
    if 'dst_ip_port' in kwargs:
        match['dst_ip_port'] = kwargs['dst_ip_port']
    st.debug(match)
    entries = filter_and_select(output, get_list, match)
    return entries


def poll_for_nat_translations(dut, itr=2, delay=2, **kwargs):
    """
    :param :dut:
    :param :protocol
    :param :src_ip
    :param :src_ip_port
    :param :dst_ip
    :param :dst_ip_port
    :param :trn_src_ip
    :param :trn_src_ip_port
    :param :trn_dst_ip
    :param :trn_dst_ip_port
    :return:
    """
    i = 1
    while True:
        result = verify_nat_translations(dut, **kwargs)
        if result:
            return get_nat_translations(dut, **kwargs)
        if i >= itr:
            return None
        st.wait(delay)
        i += 1


def verify_nat_translations(dut, **kwargs):
    """
    Verify NAT Translations
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :protocol
    :param :src_ip
    :param :src_ip_port
    :param :dst_ip
    :param :dst_ip_port
    :param :trn_src_ip
    :param :trn_src_ip_port
    :param :trn_dst_ip
    :param :trn_dst_ip_port
    :return:
    """
    entries = None
    cli_type = st.get_ui_type(dut, **kwargs)
    output = show_nat_translations(dut, cli_type=cli_type)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        get_list = ["trn_src_ip", "trn_src_ip_port", "trn_dst_ip", "trn_dst_ip_port"]
        entries = filter_and_select(output, get_list, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return entries


def verify_nat_entry_db(dut, table, prot, ip, port, **kwargs):
    """
    Author : Priyanka
    :param dut:
    :param table:
    :param prot:
    :param ip:
    :param port:
    :param kwargs:
    :return:
    """
    string = ''
    if table == "NAT_TABLE":
        string = "NAT_TABLE:{}".format(ip)
    elif table == "NAPT_TABLE":
        string = "NAPT_TABLE:{}:{}:{}".format(prot, ip, port)
    command = redis.build(dut, redis.APPL_DB, "hgetall {}".format(string))
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def set_nat_timeout_db(dut, prot, seconds):
    """
    Author : Akhilesh
    :param dut:
    :param prot:
    :param seconds:
    :return:
    """
    if prot == "tcp":
        timeout = "nat_tcp_timeout"
    elif prot == "udp":
        timeout = "nat_udp_timeout"
    elif prot == "all":
        timeout = "nat_timeout"

    string = "\"NAT_GLOBAL|Values\" \"{}\" {}".format(timeout, seconds)
    command = redis.build(dut, redis.CONFIG_DB, "hset {}".format(string))
    st.config(dut, command)
    return True


def verify_static_nat_entry(dut, port=None, prot=None, global_ip=None, global_port=None, local_ip=None, local_port=None,
                            nat_type=None):
    """
    Author : Priyanka
    :param dut:
    :param port:
    :param prot:
    :param global_ip:
    :param global_port:
    :param local_ip:
    :param local_port:
    :param nat_type:
    :return:
    """
    cmd = "sudo iptables -t nat -v -n -L"
    output = st.show(dut, cmd)
    st.debug(output)
    print(output)
    if nat_type == "snat":
        match = {"target": "DNAT", "prot": prot, "destination": local_ip, "trans_ip": global_ip}
        match1 = {"target": "SNAT", "prot": prot, "source": global_ip, "trans_ip": local_ip}
    else:
        match = {"target": "DNAT", "prot": prot, "destination": global_ip, "trans_ip": local_ip}
        match1 = {"target": "SNAT", "prot": prot, "source": local_ip, "trans_ip": global_ip}
    print (match)
    print (match1)

    entries = filter_and_select(output, None, match)
    print(entries)
    entries1 = filter_and_select(output, None, match1)
    print(entries1)
    if entries:
        if entries1:
            return True
        else:
            return False
    return False


def verify_dynamic_nat_entry(dut, **kwargs):
    """
    Author : Priyanka
    :param :dut
    :param :global_port_range:
    :param :global_ip_range:
    :return:
    """
    cmd = "sudo iptables -t nat -v -n -L"
    output = st.show(dut, cmd)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
        elif len(entries) < 3:
            return False
    return True


def verify_show_nat_config_static(dut, mode=None, **kwargs):
    """
    Author : Priyanka
    :param :dut:
    :param :mode:
    :param :local_ip:
    :param :global_ip:
    :param :nat_type:
    :param :twice_nat_id:
    :param :prot:
    :param :local_port:
    :param :global_port:
    """
    nat_config_modes = ['globalvalues', 'static', 'pool', 'bindings']
    if mode not in nat_config_modes:
        st.error("Invalid mode {}, should be in {}".format(mode, ','.join(nat_config_modes)))
        return False
    command = "show nat config {}".format(mode)
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def config_nat_global(dut, **kwargs):
    """
    Author : Priyanka
    :param :dut:
    :param :prot:
    :param :time:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)
    if cli_type not in ["click", "klish"]:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    if kwargs["admin_mode"]:
        if cli_type == "click":
            command = "config nat feature {}".format(kwargs["admin_mode"])
        else:
            command = list()
            command.append("nat")
            admin_mode = "enable" if kwargs["admin_mode"] == "enable" else "no enable"
            command.append("{}".format(admin_mode))
            command.append("exit")
    elif kwargs["prot"]:
        command = "config nat {}-timeout {}".format(kwargs["prot"], kwargs["time"])
    else:
        command = "config nat timeout {}".format(kwargs["time"])
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def verify_conntrack_table(dut, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    command = "sudo conntrack -j -L"
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_bcmcmd_static_nat_entry_ingress_entry(dut, **kwargs):
    """
    Author:anuja.dhopeshwarkar@broadcom.com
    :param dut:
    """
    if "destIp" not in kwargs and "srcIp" not in kwargs:
        st.error("Mandatory params are not provided destIp, srcIp not given")
        return False
    cmd = "bcmcmd 'l3 nat_ingress show'"
    output = st.show(dut, cmd)
    st.debug(kwargs["destIp"])
    st.debug(kwargs["srcIp"])
    st.debug(output)
    if kwargs["destPort"]:
        match = {"type": "DNAT", "ip": kwargs["destIp"], "l4port": kwargs["destPort"]}
    else:
        match = {"type": "DNAT", "ip": kwargs["destIp"]}
    entries = filter_and_select(output, None, match)
    if kwargs["srcPort"]:
        match = {"type": "SNAT", "ip": kwargs["srcIp"], "l4port": kwargs["srcPort"]}
    else:
        match = {"type": "SNAT", "ip": kwargs["srcIp"]}
    entries1 = filter_and_select(output, None, match)
    if entries and entries1:
        return True
    else:
        return False


def verify_bcmcmd_static_nat_entry_egress_entry(dut, **kwargs):
    """
    Author:anuja.dhopeshwarkar@broadcom.com
    :param dut:
    :type dut:
    """
    if "destIp" not in kwargs and "srcIp" not in kwargs:
        st.error("Mandatory params are not provided destIp, srcIp not given")
        return False
    cmd = "bcmcmd 'l3 nat_egress show'"
    output = st.show(dut, cmd)
    st.debug(kwargs["destIp"])
    st.debug(kwargs["srcIp"])
    st.debug(output)
    if kwargs["srcPort"]:
        match = {"type": "DNAT", "ip": kwargs["srcIp"], "l4port": kwargs["srcPort"]}
    else:
        match = {"type": "DNAT", "ip": kwargs["srcIp"]}
    entries = filter_and_select(output, None, match)
    if kwargs["destPort"]:
        match = {"type": "SNAT", "ip": kwargs["destIp"], "l4port": kwargs["destPort"]}
    else:
        match = {"type": "SNAT", "ip": kwargs["destIp"]}
    entries1 = filter_and_select(output, None, match)
    if entries and entries1:
        return True
    else:
        return False


def clear_nat_config(dut, *argv, **kwargs):
    """
    Clear all NAT config
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :all: To clear all NAT config
    :param :static_all:
    :param :bindings:
    :param :interfaces:
    :param :pools:
    :return:
    """
    instance = 0
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)
    if cli_type not in ["klish", "click", "rest-patch", "rest-put"]:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    if not argv:
        argv = ['all']
    if cli_type == "klish":
        command = list()
        command.append("nat")
    else:
        command = ""
    if "static_all" in argv or 'all' in argv:
        if cli_type == "click":
            command += "sudo config nat remove static all;"
        elif cli_type == "klish":
            command.append("no static all")
        elif cli_type not in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['clear_nat_static_all'].format(instance)
            delete_rest(dut, rest_url=url)
    if "bindings" in argv or 'all' in argv:
        if cli_type == "click":
            command += "sudo config nat remove bindings;"
        elif cli_type == "klish":
            command.append("no bindings")
        elif cli_type not in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['clear_nat_bindings'].format(instance)
            delete_rest(dut, rest_url=url)
    if "interfaces" in argv or 'all' in argv:
        if cli_type == "click":
            command += "sudo config nat remove interfaces;"
        elif cli_type == "klish":
            command.append("no nat interfaces")
        elif cli_type not in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['clear_nat_interfaces'].format(instance)
            delete_rest(dut, rest_url=url)
    if "pools" in argv or 'all' in argv:
        if cli_type == "click":
            command += "sudo config nat remove pools;"
        elif cli_type == "klish":
            command.append("no pools")
        elif cli_type not in ["rest-patch", "rest-put"]:
            url = st.get_datastore(dut, "rest_urls")['clear_nat_pools'].format(instance)
            delete_rest(dut, rest_url=url)
    if cli_type == "klish":
        command.append("exit")
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def get_nat_translations_count(dut, counter_name=None, cli_type=""):
    """
    Get NAT Translations Count
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param counter_name:
    :param cli_type:
    :return:
    """
    instance = 0
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if 'rest' in cli_type:
        output = _get_nat_oc_yang_output(dut, call='translations_count', instance=instance)
        if counter_name:
            if counter_name in output[0]:
                return int(output[0][counter_name])
            else:
                return 0
        return output
    else:
        command = 'show nat translations count'
        output = st.show(dut, command, type=cli_type)
        if counter_name:
            return int(output[0][counter_name])
        return output


def verify_nat_translations_count(dut, **kwargs):
    """
    Verify NAT Translations Count
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :counter_name:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    output = get_nat_translations_count(dut, cli_type=cli_type)
    result = True
    for each in kwargs:
        match = {each: str(kwargs[each])}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            result = False
    return result


def _get_nat_oc_yang_output(dut, call='translations', instance=0):
    final = []
    protocol_map = {17: 'udp', 6: 'tcp', 'all': 'all'}
    dummy = ''
    tr_head = ['protocol', 'src_ip', 'src_ip_port', 'trn_src_ip', 'trn_src_ip_port', 'dst_ip', 'dst_ip_port',
               'trn_dst_ip', 'trn_dst_ip_port']
    st_head = ['protocol', 'src_ip', 'src_ip_port', 'dst_ip', 'dst_ip_port', 'bytes', 'packets']
    ct_head = ['static_napt_entries', 'dynamic_napt_entries', 'total_entries', 'static_nat_entries',
               'dynamic_nat_entries', 'total_snat_snapt_entries', 'total_dnat_dnapt_entries',
               'static_twice_nat_entries', 'static_twice_napt_entries', 'dynamic_twice_nat_entries',
               'dynamic_twice_napt_entries']

    url = st.get_datastore(dut, "rest_urls")['get_nat'].format(instance)
    rest_out = get_rest(dut, rest_url=url, timeout=30)

    nat_out = []
    napt_out = []
    twice_out = []
    twice_napt_out = []
    counter = {e: 0 for e in ct_head}

    if 'nat-mapping-table' in rest_out['output']['openconfig-nat:instance'][0].keys():
        nat_out = rest_out['output']['openconfig-nat:instance'][0]['nat-mapping-table']['nat-mapping-entry']
    if 'napt-mapping-table' in rest_out['output']['openconfig-nat:instance'][0].keys():
        napt_out = rest_out['output']['openconfig-nat:instance'][0]['napt-mapping-table']['napt-mapping-entry']
    if 'nat-twice-mapping-table' in rest_out['output']['openconfig-nat:instance'][0].keys():
        twice_out = rest_out['output']['openconfig-nat:instance'][0]['nat-twice-mapping-table']['nat-twice-entry']
    if 'napt-twice-mapping-table' in rest_out['output']['openconfig-nat:instance'][0].keys():
        twice_napt_out = rest_out['output']['openconfig-nat:instance'][0]['napt-twice-mapping-table']['napt-twice-entry']

    if call == 'translations' or call == 'translations_count':
        for each in napt_out + nat_out:
            if each.get('state'):
                out = {e: dummy for e in tr_head}
                out['protocol'] = protocol_map.get(each.get('protocol', 'all'))
                state = each.get('state')
                if 'SNAT' in state['type']:
                    out['src_ip'] = state.get('external-address', dummy)
                    out['src_ip_port'] = str(state.get('external-port', dummy))
                    out['trn_src_ip'] = state.get('translated-ip', dummy)
                    out['trn_src_ip_port'] = str(state.get('translated-port', dummy))
                    counter['total_snat_snapt_entries'] += 1
                    if "STATIC" in state.get('entry-type', ''):
                        if out['protocol'] == 'all':
                            counter['static_nat_entries'] += 1
                        else:
                            counter['static_napt_entries'] += 1
                    else:
                        if out['protocol'] == 'all':
                            counter['dynamic_nat_entries'] += 1
                        else:
                            counter['dynamic_napt_entries'] += 1
                else:
                    out['dst_ip'] = state.get('external-address', dummy)
                    out['dst_ip_port'] = str(state.get('external-port', dummy))
                    out['trn_dst_ip'] = state.get('translated-ip', dummy)
                    out['trn_dst_ip_port'] = str(state.get('translated-port', dummy))
                    counter['total_dnat_dnapt_entries'] += 1
                    if "STATIC" in state.get('entry-type', ''):
                        if out['protocol'] == 'all':
                            counter['static_twice_nat_entries'] += 1
                        else:
                            counter['static_twice_napt_entries'] += 1
                    else:
                        if out['protocol'] == 'all':
                            counter['dynamic_twice_nat_entries'] += 1
                        else:
                            counter['dynamic_twice_napt_entries'] += 1
                counter['total_entries'] += 1
                final.append(out)

        for each in twice_out:
            out = {e: dummy for e in tr_head}
            out['protocol'] = protocol_map.get('all')
            if each.get('state'):
                state = each.get('state')
                out['trn_src_ip'] = state.get('translated-src-ip', dummy)
                out['trn_dst_ip'] = state.get('translated-dst-ip', dummy)
                out['src_ip_port'] = str(state.get('external-port', dummy))
                out['dst_ip_port'] = str(state.get('external-port', dummy))
                out['trn_src_ip_port'] = str(state.get('translated-port', dummy))
                out['trn_dst_ip_port'] = str(state.get('translated-port', dummy))
                if "STATIC" in state.get('entry-type', ''):
                    if out['protocol'] == 'all':
                        counter['static_nat_entries'] += 1
                    else:
                        counter['static_napt_entries'] += 1
                else:
                    if out['protocol'] == 'all':
                        counter['dynamic_nat_entries'] += 1
                    else:
                        counter['dynamic_napt_entries'] += 1
            out['src_ip'] = each.get('src-ip', dummy)
            out['dst_ip'] = each.get('dst-ip', dummy)
            counter['total_entries'] += 1
            final.append(out)

        for each in twice_napt_out:
            out = {e: dummy for e in tr_head}
            out['protocol'] = protocol_map.get(each.get("protocol"),"all")
            if each.get('state'):
                state = each.get('state')
                out['trn_src_ip'] = state.get('translated-src-ip', dummy)
                out['trn_dst_ip'] = state.get('translated-dst-ip', dummy)
                out['src_ip_port'] = str(each.get('src-port', dummy))
                out['dst_ip_port'] = str(each.get('dst-port', dummy))
                out['trn_src_ip_port'] = str(state.get('translated-src-port', dummy))
                out['trn_dst_ip_port'] = str(state.get('translated-dst-port', dummy))
                if "STATIC" in state.get('entry-type', ''):
                    if out['protocol'] == 'all':
                        counter['static_nat_entries'] += 1
                    else:
                        counter['static_napt_entries'] += 1
                else:
                    if out['protocol'] == 'all':
                        counter['dynamic_nat_entries'] += 1
                    else:
                        counter['dynamic_napt_entries'] += 1
            out['src_ip'] = each.get('src-ip', dummy)
            out['dst_ip'] = each.get('dst-ip', dummy)
            counter['total_entries'] += 1
            final.append(out)

        if call == 'translations_count':
            return [{k: str(v) for k, v in counter.items()}]

    elif call == 'statistics':
        for each in napt_out + nat_out:
            if each.get('state'):
                state = each.get('state')
                if state.get('counters'):
                    out = {e: dummy for e in st_head}
                    out['protocol'] = protocol_map.get(each.get('protocol', 'all'))
                    if 'SNAT' in state['type']:
                        out['src_ip'] = state.get('external-address', dummy)
                        out['src_ip_port'] = state.get('external-port', dummy)
                    else:
                        out['dst_ip'] = state.get('external-address', dummy)
                        out['dst_ip_port'] = state.get('external-port', dummy)
                    out['packets'] = state['counters'].get('nat-translations-pkts', '0')
                    out['bytes'] = state['counters'].get('nat-translations-bytes', '0')
                    final.append(out)
        for each in twice_out:
            if each.get('state'):
                state = each.get('state')
                if state.get('counters'):
                    if state.get('counters'):
                        out = {e: dummy for e in st_head}
                        out['protocol'] = protocol_map.get('all')
                        out['packets'] = state['counters'].get('nat-translations-pkts', '0')
                        out['bytes'] = state['counters'].get('nat-translations-bytes', '0')
                        out['src_ip'] = each.get('src-ip', dummy)
                        out['dst_ip'] = each.get('dst-ip', dummy)
                        final.append(out)
        for each in twice_napt_out:
            if each.get('state'):
                state = each.get('state')
                if state.get('counters'):
                    out = {e: dummy for e in tr_head}
                    out['protocol'] = protocol_map.get(each.get("protocol"), "all")
                    out['packets'] = state['counters'].get('nat-translations-pkts', '0')
                    out['bytes'] = state['counters'].get('nat-translations-bytes', '0')
                    out['src_ip'] = each.get('src-ip', dummy)
                    out['dst_ip'] = each.get('dst-ip', dummy)
                    out['src_ip_port'] = str(each.get('src-port', dummy))
                    out['dst_ip_port'] = str(each.get('dst-port', dummy))
                    final.append(out)

    st.debug(final)
    return final


def show_nat_config(dut, mode, **kwargs):
    """
    Verify NAT Config
    :param dut:
    :param mode:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
    nat_config_modes = ['globalvalues', 'static', 'pool', 'bindings']
    if mode not in nat_config_modes:
        st.error("Invalid mode {}".format(mode))
        return False
    command = "show nat config {}".format(mode)
    output = st.show(dut, command, type=cli_type)
    response = list()
    match = dict()
    for each in kwargs.keys():
        match.update({each: kwargs[each]})
    if match:
        entries = filter_and_select(output, None, match)
        if not entries:
            for each in kwargs.keys():
                st.log("{} and {} is not match ".format(each, kwargs[each]))
            return []
        st.debug(entries)
        if isinstance(entries, dict):
            response.append(entries)
            return response
        else:
            return entries
    return output
