# This file contains the list of API's which performs RADIUS operations.
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

import re
from spytest import st
import apis.system.basic as basic_obj
from apis.system.rest import config_rest, get_rest, delete_rest
from utilities import utils
import utilities.common as common_utils
import apis.system.system_server as sys_server_api
import apis.system.connection as con_obj
import apis.routing.ip as ip_api
from utilities.utils import get_supported_ui_type_list, ensure_service_params
from utilities.services import create_radius_docker_container, remove_radius_docker_container

try:
    import apis.yang.codegen.messages.das as umf_das
    from apis.yang.utils.common import Operation
except ImportError:
    pass

debug = False

# timeout set to 125 sec due defect sonic-24329.once fixed will change to lower limit.
time_out = 125


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in utils.get_supported_ui_type_list() else cli_type
    return cli_type


def config_server(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig radius server using provided parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param family:
    :param no_form:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring RADIUS SERVER Parameters ...")
    if "ip_address" not in kwargs:
        st.error("IP Address not provided")
        return False
    ipaddress_li = common_utils.make_list(kwargs["ip_address"])
    for each_ip in ipaddress_li:
        if cli_type in utils.get_supported_ui_type_list():
            kwargs['config'] = 'no' if no_form else 'yes'
            if 'use_mgmt_vrf' in kwargs:
                kwargs['vrf'] = kwargs.pop('use_mgmt_vrf')
            if 'source_intf' in kwargs:
                kwargs['src_intf'] = kwargs.pop('source_intf')
            if 'key' in kwargs and 'encrypted' in kwargs["key"]:
                kwargs['key'] = kwargs['key'].replace(' encrypted', '')
                kwargs['encrypted'] = True
            result = sys_server_api.config_aaa_server(dut, server_name='RADIUS', server_address=each_ip, **kwargs)
            if not result:
                return result
        elif cli_type == "klish":
            cmd = "radius-server host {}".format(each_ip)
            if "auth_type" in kwargs:
                cmd += " auth-type {}".format(kwargs["auth_type"])
            if "auth_port" in kwargs:
                cmd += " auth-port {}".format(kwargs["auth_port"])
            if "key" in kwargs:
                cmd += " key {}".format(kwargs["key"])
            if "priority" in kwargs:
                cmd += " priority {}".format(kwargs["priority"])
            if "timeout" in kwargs:
                cmd += " timeout {}".format(kwargs["timeout"])
            if "use_mgmt_vrf" in kwargs:
                cmd += " vrf {}".format(kwargs.get("use_mgmt_vrf"))
            if "retransmit" in kwargs:
                cmd += " re-transmit {}".format(kwargs["retransmit"])
            if "source_intf" in kwargs:
                cmd += " source-interface {}".format(kwargs["source_intf"])
            command = "no {}".format(cmd) if no_form else cmd
            st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        elif cli_type == "click":
            action = kwargs["action"] if "action" in kwargs else "add"
            command = "config radius {} {}".format(action, each_ip)
            if "retransmit" in kwargs:
                command += " -r {}".format(kwargs["retransmit"])
            if "auth_type" in kwargs:
                command += " -a {}".format(kwargs["auth_type"])
            if "timeout" in kwargs:
                command += " -t {}".format(kwargs["timeout"])
            if "key" in kwargs:
                command += " -k {}".format(kwargs["key"])
            if "auth_port" in kwargs:
                command += " -o {}".format(kwargs["auth_port"])
            if "priority" in kwargs:
                command += " -p {}".format(kwargs["priority"])
            if "use_mgmt_vrf" in kwargs:
                command += " -m"
            if "source_intf" in kwargs:
                if kwargs["source_intf"] == "Management0":
                    kwargs["source_intf"] = "eth0"
                command += " -s {}".format(kwargs["source_intf"])
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_urls = st.get_datastore(dut, "rest_urls")
            config_url = rest_urls['aaa_server_config']
            global_params = {"name": "RADIUS"}
            server_params = {"name": "RADIUS", "address": each_ip}
            radius_params = dict()
            radius_ext_params = dict()
            if "retransmit" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_retransmit_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove retransmit config for {} server".format(each_ip))
                        return False
                else:
                    radius_params.update({"retransmit-attempts": int(kwargs["retransmit"])})
            if "auth_type" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_authtype_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove auth_type config for {} server".format(each_ip))
                        return False
                else:
                    server_params.update({"openconfig-system-ext:auth-type": kwargs["auth_type"]})
            if "timeout" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_timeout_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove timeout config for {} server".format(each_ip))
                        return False
                else:
                    server_params.update({"timeout": int(kwargs["timeout"])})
            if "key" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_secretkey_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove key config for {} server".format(each_ip))
                        return False
                else:
                    if "encrypted" in kwargs["key"]:
                        kwargs["key"] = kwargs["key"].replace(" encrypted", "")
                        radius_params.update({"secret-key": kwargs["key"], "encrypted": True})
                    else:
                        radius_params.update({"secret-key": kwargs["key"]})
            if "auth_port" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_authport_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove auth-port config for {} server".format(each_ip))
                        return False
                else:
                    radius_params.update({"auth-port": int(kwargs["auth_port"])})
            if "priority" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_priority_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove priority config for {} server".format(each_ip))
                        return False
                else:
                    server_params.update({"openconfig-system-ext:priority": int(kwargs["priority"])})
            if "use_mgmt_vrf" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_vrf_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove VRF config for {} server".format(each_ip))
                        return False
                else:
                    server_params.update({"openconfig-system-ext:vrf": kwargs["use_mgmt_vrf"]})
            if "source_intf" in kwargs:
                if kwargs["source_intf"] == "Management0":
                    kwargs["source_intf"] = "eth0"
                if no_form:
                    del_url = rest_urls['radius_vrf_config'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove ipaddress config for {} server".format(each_ip))
                        return False
                else:
                    radius_params.update({"openconfig-aaa-radius-ext:source-interface": kwargs["source_intf"]})
            if "ip_address" in kwargs:
                if no_form:
                    del_url = rest_urls['radius_delete_server'].format('RADIUS', each_ip)
                    if not delete_rest(dut, rest_url=del_url, timeout=time_out):
                        st.error("Failed to remove ipaddress config for {} server".format(each_ip))
                        return False
            if not no_form:
                config_data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": global_params, "servers": {"server": [{"address": each_ip, "config": server_params, "radius": {"config": radius_params}}]}, "openconfig-aaa-radius-ext:radius": {"config": radius_ext_params}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=config_url, json_data=config_data, timeout=time_out):
                    return False
        else:
            st.error("UNSUPPORTED CLI TYPE: {}".format(cli_type))
            return False
        return True


def config_global_server_params(dut, skip_error_check=False, params=dict(), cli_type=""):
    """
    Config / Unconfig global server params using provided parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param params: {"source_ip":{"value":"10.20.3.1", "no_form": False}, "key":{"value":"ABCD", "no_form": True},
                "auth_port":{"value":"56", "no_form": False}, "timeout":{"value":"30", "no_form": True}}
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Configuring GLOBAL SERVER Parameters ...")
    if not params:
        st.log("Invalid parameters provided ..")
        return False
    count = 0
    # #Added fallback to restpatch due to timeout value was not woring in rest and Defect id is SONIC-75718
    # chap_type = params['auth_type']['value'] if 'auth_type' in params else ''
    # if cli_type in utils.get_supported_ui_type_list():
    #     cli_type = 'rest-patch' if chap_type == 'chap' else cli_type
    if cli_type in utils.get_supported_ui_type_list():
        fields = {"source_ip": "source-ip", "key": "key", "auth_type": "auth-type", "timeout": "timeout",
                  "retransmit": "retransmit", "nasip": "nas-ip", "statistics": "statistics"}
        kwargs = dict()
        for key, value in params.items():
            kwargs['config'] = 'no' if value.get('no_form') else 'yes'
            kwargs[fields[key].replace('-', '_')] = value['value']
        return sys_server_api.config_aaa_server_properties(dut, server_name='RADIUS', **kwargs)
    elif cli_type == "klish":
        cmd = "radius-server"
        fields = {"source_ip": "source-ip", "key": "key", "auth_type": "auth-type", "timeout": "timeout",
                  "retransmit": "retransmit", "nasip": "nas-ip", "statistics": "statistics"}
        for key, value in params.items():
            if value.get("no_form"):
                command = "no {} {}".format(cmd, fields[key])
            else:
                command = "{} {} {}".format(cmd, fields[key], value["value"])
            output = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
            if "% Error" in utils.remove_last_line_from_string(output):
                st.log(utils.remove_last_line_from_string(output))
                return False
            count += 1
    elif cli_type == "click":
        cmd = "config radius"
        fields = {"source_ip": "sourceip", "key": "passkey", "auth_type": "authtype", "timeout": "timeout", "retransmit": "retransmit", "nasip": "nasip", "statistics": "statistics"}
        for key, value in params.items():
            if value.get("no_form"):
                if key == "source_ip":
                    command = "{} default {} {}".format(cmd, fields[key], value["value"])
                else:
                    command = "{} default {}".format(cmd, fields[key])
            else:
                command = "{} {} {}".format(cmd, fields[key], value["value"])
            output = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
            if "Valid chars are" in utils.remove_last_line_from_string(output):
                st.log(utils.remove_last_line_from_string(output))
                return False
            count += 1
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url_mapping = {"source_ip": "radius_sourceip", "key": "radius_key", "auth_type": "radius_authtype", "timeout": "radius_timeout",
                       "retransmit": "radius_retransmit", "nasip": "radius_nasip", "statistics": "radius_statistics"}
        for key, value in params.items():
            if value.get("no_form"):
                url = rest_urls[url_mapping[key]].format("RADIUS")
                if not delete_rest(dut, rest_url=url, timeout=time_out):
                    return False
            else:
                url = rest_urls['aaa_server_config']
                if key == "statistics":
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS"}, "openconfig-aaa-radius-ext:radius": {"config": {"statistics": True}}}]}
                elif key == 'nasip':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS"}, "openconfig-aaa-radius-ext:radius": {"config": {"nas-ip-address": value["value"]}}}]}
                elif key == 'retransmit':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "openconfig-aaa-radius-ext:radius": {"config": {"retransmit-attempts": int(value["value"])}}}]}
                elif key == 'timeout':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS", "openconfig-system-ext:timeout": int(value["value"])}}]}
                elif key == 'auth_type':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS", "openconfig-system-ext:auth-type": value["value"]}}]}
                elif key == 'key':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS", "openconfig-system-ext:secret-key": value["value"]}}]}
                elif key == 'source_ip':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS", "openconfig-system-ext:source-address": value["value"]}}]}
                else:
                    continue
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                    return False
                count += 1
    else:
        st.error("UNSUPPORTED CLI_TYPE: {}".format(cli_type))
        return False
    if count > 0:
        return True
    st.log("Returning False as the command execution is not happened with the provided parameters .. ")
    return False


def show_config(dut, search_string="", cli_type="", verify=True):
    '''
    API to show the configured radius parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    {'globals': [{global_auth_type': 'pap (default)','global_source_ip': '10.25.36.25','global_passkey': 'abcd (default)',
     'global_timeout': '5 (default)'}],
     'servers': [{'auth_type': '', 'passkey': '', 'auth_port': '1815', 'priority': '1', 'timeout': '', 'address': '1.1.1.5'},
      {'auth_type': '', 'passkey': '', 'auth_port': '1812', 'priority': '1', 'timeout': '', 'address': '1.1.1.1'}]}
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    st.log("Showing radius configuration ...")
    if cli_type == "klish":
        command = "show radius-server"
        return format_show_output(dut, command, cli_type)
    elif cli_type == "click":
        command = "show radius | grep -w {}".format(search_string) if search_string else "show radius"
        return format_show_output(dut, command, cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['radius_server_show'].format("RADIUS")
        url1 = rest_urls['radius_server_config'].format("RADIUS")
        url2 = rest_urls['radius_nasip_retransmit_stasitics_config'].format("RADIUS")
        server_output = get_rest(dut, rest_url=url)
        global_config = get_rest(dut, rest_url=url1)
        global_ext_data = get_rest(dut, rest_url=url2)
        result = process_radius_output(server_output['output'], global_config['output'], global_ext_data['output'],
                                       verify=verify)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return result


def format_show_output(dut, command, cli_type):
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    output = st.show(dut, command, type=cli_type)
    result = {"globals": [], "servers": []}
    server_out = dict()
    for d in output:
        global_out = dict()
        for k, v in d.items():
            if "global" in k:
                global_out[k] = v
        if d["address"] or d["stats_server_ip"]:
            addr_val = d["address"] if d["address"] else d["stats_server_ip"]
            if not server_out.get(addr_val):
                server_out[addr_val] = dict()
                server_out[addr_val] = d
            else:
                stats_keys = ["stats_server_ip", "access_requests", "access_accepts", "access_rejects",
                              "timeout_access_reqs", "access_challenges", "bad_authenticators", "invalid_packets"]
                if d["stats_server_ip"] == addr_val:
                    for stat_key in stats_keys:
                        server_out[addr_val][stat_key] = d[stat_key]
        if global_out and not utils.check_empty_values_in_dict(global_out):
            result["globals"].append(global_out)
    for _, value in server_out.items():
        if server_out and not utils.check_empty_values_in_dict(value):
            for detail in list(value):
                if "global" in detail:
                    value.pop(detail)
            value.pop("stats_server_ip")
            result["servers"].append(value)
    st.debug(result)
    return result


def verify_config(dut, params, cli_type=""):
    """
    API to verify the Radius Parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param params: {"globals":{"global_auth_type":"pap", "global_source_ip":'10.25.36.25'},
    "servers":[{'auth_port': '1815', 'priority': '1', 'address': '1.1.1.5'},
      {'auth_port': '1812', 'priority': '1', 'address': '1.1.1.1'}]}
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if not isinstance(params, dict):
        st.log("Unsupported data format provided...")
        return False

    if cli_type in get_supported_ui_type_list():
        if "globals" in params and params["globals"]:
            params["globals"]['config'] = 'verify'
            if 'global_retransmit' in params["globals"]:
                params["globals"]['retransmit'] = params["globals"].pop('global_retransmit')
            if 'global_timeout' in params["globals"]:
                params["globals"]['timeout'] = params["globals"].pop('global_timeout')
            if 'global_passkey' in params["globals"]:
                params["globals"]['key'] = params["globals"].pop('global_passkey')
            res1 = sys_server_api.config_aaa_server_properties(dut, server_name='RADIUS', **params["globals"])
            if res1 is False:
                st.log("Verification of radius global parameters values failed")
                return False
        if "servers" in params and params["servers"]:
            for each_server in params["servers"]:
                each_server['config'] = 'verify'
                ip_address = each_server.pop('address')
                if 'passkey' in each_server:
                    each_server['key'] = each_server.pop('passkey')
                res1 = sys_server_api.config_aaa_server(dut, server_name='RADIUS', server_address=ip_address, **each_server)
                if res1 is False:
                    st.log("Verification of radius server {} parameters values failed".format(ip_address))
                    return False
    else:
        output = show_config(dut, cli_type=cli_type)
        if not output:
            st.log("Identified empty radius output ..")
            return False
        if "globals" in params and params["globals"]:
            for key, value in params["globals"].items():
                if str(value) != str(output["globals"][0][key]):
                    st.log("Verification of radius global parameters {} with {} values is failed".format(key, value))
                    return False
        if "servers" in params and params["servers"]:
            for details in params["servers"]:
                is_found = 0
                for data in output["servers"]:
                    for key, value in details.items():
                        if str(value) != str(data[key]):
                            st.log("Verifications of {} with {} values is failed".format(key, value))
                            is_found = 0
                        else:
                            st.log("Radius server key: {}, value: {} verification success".format(key, value))
                            is_found += 1
                    if is_found == len(details):
                        st.log("Already found, hence breaking the iteration ..")
                        break
                if is_found != len(details):
                    st.log("Verification of radius server parameter verification failed..")
                    return False
    if "globals" in params and params["globals"] or "servers" in params and params["servers"]:
        st.log("Verification of radius server parameters SUCCESS ..")
        return True


def aaa_authentication_debug_trace(dut, skip_error_check=False, **kwargs):
    cli_type = st.get_ui_type(dut, cli_type='click')
    if kwargs["option"] == "debug":
        command = "config aaa authentication debug {}".format(kwargs["action"])
    if kwargs["option"] == "trace":
        command = "config aaa authentication trace {}".format(kwargs["action"])
    st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
    return True


def clear_radius_statistics(dut, skip_error_check=False, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'click':
        command = "sonic-clear radius"
        st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        command = "clear radius-server statistics"
        st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def process_radius_output(server_output, global_config, global_ext_data, verify=True):
    radius_output = dict()
    radius_output["servers"] = list()
    radius_output["globals"] = list()
    if server_output and server_output.get("openconfig-system:servers"):
        if isinstance(server_output.get("openconfig-system:servers")["server"], list):
            for server_data in server_output.get("openconfig-system:servers")["server"]:
                servers = dict()
                servers["address"] = server_data.get("address", "")
                if server_data.get("config"):
                    serve_config = server_data.get("config")
                    servers["auth_type"] = serve_config.get("auth-type", "")
                    servers["priority"] = serve_config.get("priority", "")
                    servers["vrf_mgmt"] = serve_config.get("vrf", "")
                    servers["timeout"] = serve_config.get("timeout", "")
                else:
                    servers["auth_type"] = servers["priority"] = servers["vrf_mgmt"] = servers["timeout"] = ""

                if server_data.get("radius") and "config" in server_data.get("radius"):
                    radius_data = server_data.get("radius")["config"]
                    servers["auth_port"] = radius_data.get("auth-port", "")
                    servers["retransmit"] = radius_data.get("retransmit-attempts", "")
                    servers["passkey"] = radius_data.get("secret-key", "")
                    if verify:
                        servers["passkey"] = "Yes" if servers["passkey"] else "No"
                    servers["si"] = radius_data.get("openconfig-aaa-radius-ext:source-interface", "")

                else:
                    servers["auth_port"] = servers["retransmit"] = servers["passkey"] = servers["si"] = ""

                if server_data.get("radius") and "state" in server_data.get("radius"):
                    counters_data = server_data.get("radius").get("state").get("counters")
                    if counters_data:
                        servers["access_accepts"] = counters_data.get("access-accepts", "")
                        servers["access_rejects"] = counters_data.get("access-rejects", "")
                        servers["access_requests"] = counters_data.get("openconfig-aaa-radius-ext:access-requests", "")
                        servers["invalid_packets"] = counters_data.get("openconfig-aaa-radius-ext:invalid-packets", "")
                        servers["access_challenges"] = counters_data.get("openconfig-aaa-radius-ext:access-challenges", "")
                        servers["timeout_access_reqs"] = counters_data.get("retried-access-requests", "")
                        servers["bad_authenticators"] = counters_data.get("openconfig-aaa-radius-ext:bad-authenticators", "")
                    else:
                        servers["bad_authenticators"] = servers["timeout_access_reqs"] = servers["access_accepts"] = servers["access_rejects"] = servers["access_challenges"] = servers["access_requests"] = servers["invalid_packets"] = "0"
                else:
                    servers["bad_authenticators"] = servers["timeout_access_reqs"] = servers["access_accepts"] = \
                        servers["access_rejects"] = servers["access_challenges"] = servers["access_requests"] = servers[
                        "invalid_packets"] = "0"
                radius_output["servers"].append(servers)
    global_data = dict()
    if global_config and global_config.get("openconfig-system:config"):
        global_config_data = global_config.get("openconfig-system:config")
        global_data["global_auth_type"] = global_config_data.get("auth-type", "")
        global_data["global_passkey"] = global_config_data.get("secret-key", "")
        if verify:
            global_data["global_passkey"] = "Yes" if global_data["global_passkey"] else "No"
        global_data["global_source_ip"] = global_config_data.get("openconfig-system-ext:source-address", "")
        global_data["global_timeout"] = global_config_data.get("timeout", "")
    else:
        global_data["global_auth_type"] = ""
        global_data["global_passkey"] = "No"
        global_data["global_source_ip"] = ""
        global_data["global_timeout"] = ""

    if global_ext_data and global_ext_data.get("openconfig-aaa-radius-ext:config"):
        global_ext_config = global_ext_data.get("openconfig-aaa-radius-ext:config")
        global_data["global_nas_ip"] = global_ext_config.get("nas-ip-address", "")
        global_data["global_retransmit"] = global_ext_config.get("retransmit-attempts", "")
        global_data["global_statistics"] = global_ext_config.get("statistics", False)
    else:
        global_data["global_nas_ip"] = ""
        global_data["global_retransmit"] = ""
        global_data["global_statistics"] = ""
    if global_data:
        radius_output["globals"].append(global_data)
    return radius_output


def get_enyc_key(dut, ip_address="", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in "click":
        command = "show runningconfiguration all"
        data = basic_obj.get_show_command_data(dut, command, type="json")
        if not data:
            st.error("Content not found ..")
            return ""
        if "RADIUS_SERVER" in data:
            result = data["RADIUS_SERVER"][ip_address]["passkey"]
    elif cli_type in "klish":
        command = 'show running-configuration | grep "radius.*{}"'.format(ip_address)
        output = st.show(dut, command, type=cli_type, skip_tmpl=True)
        result = re.findall(r'key(.*?)encrypted', output)[0].replace(" ", "")
    elif cli_type in ["rest-patch", "rest-put"]:
        output = show_config(dut, cli_type=cli_type, verify=False)
        result = common_utils.filter_and_select(output["servers"], match={"address": ip_address})[0]["passkey"]
    return result


def verify_key_config(dut, ip_address="", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    result = get_enyc_key(dut, ip_address=ip_address, cli_type=cli_type)
    if result:
        if "U2F" in result and "=" in result:
            st.log("Key encrypted")
            return True
        else:
            st.error("key not encrypted")
            return False
    else:
        st.error("key not found")
        return False


def config_global_das_params(dut, cmd_type_list, **kwargs):
    """
    Config / Unconfig global DAS server params using provided parameters
    Author: Naveen Kumar Aketi (naveen.kumaraketi@broadcom.com)
    :param dut:
    :param cmd_type_list:
    :param kwargs:
    :return:

    config_global_das_params(dut='dut1', cmd_type_list=[], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['port'], port=6000)
    config_global_das_params(dut='dut1', cmd_type_list=['port'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['auth_type'], auth_type='all')
    config_global_das_params(dut='dut1', cmd_type_list=['auth_type'], auth_type='any')
    config_global_das_params(dut='dut1', cmd_type_list=['auth_type'], auth_type='session-key')
    config_global_das_params(dut='dut1', cmd_type_list=['auth_type'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['server_key'], server_key='ABCD')
    config_global_das_params(dut='dut1', cmd_type_list=['server_key'], server_key='34e$5%^8(-~1!@', encrypted='encrypted')
    config_global_das_params(dut='dut1', cmd_type_list=['server_key'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_server_key'])
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_server_key'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_session_key'])
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_session_key'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['port', 'ignore_server_key'], port=6000)
    config_global_das_params(dut='dut1', cmd_type_list=['port', 'ignore_server_key'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_bounce_port'])
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_bounce_port'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_disable_port'])
    config_global_das_params(dut='dut1', cmd_type_list=['ignore_disable_port'], config='no')
    config_global_das_params(dut='dut1', cmd_type_list=['req_timeout'], req_timeout='5')
    config_global_das_params(dut='dut1', cmd_type_list=['req_timeout'], config='no')
    """
    config = kwargs.pop('config', 'yes')
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']:
        cli_type = 'klish'
    if type(cmd_type_list) is not list:
        cmd_type_list = [cmd_type_list]

    port = kwargs.pop('port', None)
    req_timeout = kwargs.pop('req_timeout', None)
    auth_type = kwargs.pop('auth_type', None)
    server_key = kwargs.pop('server_key', None)
    encrypted = kwargs.pop('encrypted', '')
    vrf_name = kwargs.pop('vrf_name', '')
    cmd = list()
    cmd_sub_list = list()

    st.log("Configuring GLOBAL DAS SERVER Parameters ...")
    if cli_type in utils.get_supported_ui_type_list():
        das_glb_obj = umf_das.Das()
        mode_dict = {'yes': 'true', 'no': 'false'}
        if len(cmd_type_list):
            setattr(das_glb_obj, 'DasAdminMode', 'true')
            for cmd_type in cmd_type_list:
                st.log("cmd_type {}".format(cmd_type))
                if cmd_type == 'ignore_bounce_port':
                    setattr(das_glb_obj, 'IgnoreBouncePort', mode_dict[config])
                if cmd_type == 'ignore_disable_port':
                    setattr(das_glb_obj, 'IgnoreDisablePort', mode_dict[config])
                if cmd_type == 'port':
                    if config == 'yes':
                        setattr(das_glb_obj, 'DasPort', int(port))
                    else:
                        setattr(das_glb_obj, 'DasPort', 0)
                if cmd_type == 'auth_type':
                    if config == 'yes':
                        dict = {'any': "ANY", 'all': "ALL", 'session-key': "SESSION_KEY"}
                        setattr(das_glb_obj, 'DasAuthType', dict[auth_type])
                    else:
                        setattr(das_glb_obj, 'DasAuthType', 'ALL')
                if cmd_type == 'req_timeout':
                    if config == 'yes':
                        setattr(das_glb_obj, 'DasRequestTimeout', int(req_timeout))
                    else:
                        setattr(das_glb_obj, 'DasRequestTimeout', 3)
                if cmd_type == 'server_key':
                    if config == 'yes':
                        setattr(das_glb_obj, 'GlobalServerKey', server_key)
                        setattr(das_glb_obj, 'Encrypted', 'false')
                    else:
                        das_glb_obj1 = umf_das.Das()
                        result1 = das_glb_obj1.unConfigure(dut, target_attr=das_glb_obj1.GlobalServerKey, cli_type=cli_type)
                        if not result1.ok():
                            st.log('test_step_failed: Config Global server key {}'.format(result1.data))
                            return False
                if cmd_type == 'ignore_server_key':
                    setattr(das_glb_obj, 'IgnoreServerKey', mode_dict[config])
                if cmd_type == 'ignore_session_key':
                    setattr(das_glb_obj, 'IgnoreSessionKey', mode_dict[config])
                if cmd_type == 'vrf_name':
                    if config == 'yes':
                        setattr(das_glb_obj, 'DasVrfName', vrf_name)
                    else:
                        das_glb_obj1 = umf_das.Das()
                        result1 = das_glb_obj1.unConfigure(dut, target_attr=das_glb_obj1.DasVrfName, cli_type=cli_type)
                        if not result1.ok():
                            st.log('test_step_failed: Unconfig VRF name {}'.format(result1.data))
                            return False
            result = das_glb_obj.configure(dut, cli_type=cli_type)
        else:
            result = das_glb_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config Global DAS parameters {}'.format(result.data))
            return False
        else:
            return True
    elif cli_type == "klish":
        if len(cmd_type_list):
            cmd.append("aaa server radius dynamic-author")
            for cmd_type in cmd_type_list:
                st.log("cmd_type {}".format(cmd_type))
                if cmd_type == 'ignore_bounce_port' or cmd_type == 'ignore_disable_port':
                    cmd_sub_list.append('bounce-port' if 'bounce' in cmd_type else 'disable-port')
                if cmd_type == 'port':
                    if config == 'yes':
                        cmd.append('port {}'.format(port))
                    else:
                        cmd.append('no port')
                if cmd_type == 'auth_type':
                    if config == 'yes':
                        cmd.append('auth-type {}'.format(auth_type))
                    else:
                        cmd.append('no auth-type')
                if cmd_type == 'server_key':
                    if config == 'yes':
                        cmd.append('server-key {} {}'.format(server_key, encrypted))
                    else:
                        cmd.append('no server-key')
                if cmd_type == 'ignore_server_key':
                    if config == 'yes':
                        cmd.append('ignore server-key')
                    else:
                        cmd.append('no ignore server-key')
                if cmd_type == 'ignore_session_key':
                    if config == 'yes':
                        cmd.append('ignore session-key')
                    else:
                        cmd.append('no ignore session-key')
                if cmd_type == 'vrf_name':
                    if config == 'yes':
                        cmd.append('vrf {}'.format(vrf_name))
                    else:
                        cmd.append('no vrf')
                if cmd_type == 'req_timeout':
                    if config == 'yes':
                        cmd.append('request-timeout {}'.format(req_timeout))
                    else:
                        cmd.append('no request-timeout')
            cmd.append('exit')
            for config_cmd in cmd_sub_list:
                if config == 'yes':
                    command = 'authentication command {} ignore'.format(config_cmd)
                else:
                    command = 'no authentication command {} ignore'.format(config_cmd)
                cmd.append(command)
        else:
            cmd.append("no aaa server radius dynamic-author")
        out = st.config(dut, cmd, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True


def config_client_das_params(dut, cmd_type_list, **kwargs):
    """
    Config / Unconfig client DAS server params using provided parameters
    Author: Naveen Kumar Aketi (naveen.kumaraketi@broadcom.com)
    :param dut:
    :param client_config:
    :param cmd_type_list:
    :param kwargs:
    :return:

    config_client_das_params(dut='dut1', cmd_type_list=[], config='no')
    config_client_das_params(dut='dut1', cmd_type_list=['client_addr'], client_addr='1.1.1.1')
    config_client_das_params(dut='dut1', cmd_type_list=['client_addr'], client_addr='2201::1', config='no')
    config_client_das_params(dut='dut1', cmd_type_list=['client_addr'], client_addr='broadcom.com')
    config_client_das_params(dut='dut1', cmd_type_list=['client_addr_secret_key'], client_addr='1.1.1.1', server_key='xxyyzz')
    config_client_das_params(dut='dut1', cmd_type_list=['client_addr_secret_key'], client_addr='1.1.1.1', server_key='6a$2#e~1!@#', encrypted='encrypted')
    config_client_das_params(dut='dut1', cmd_type_list=['client_addr'], config='no')
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.pop('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    if cli_type in ['click', 'rest-patch', 'rest-put']:
        cli_type = 'klish'
    if type(cmd_type_list) is not list:
        cmd_type_list = [cmd_type_list]

    client_addr = kwargs.pop('client_addr', None)
    server_key = kwargs.pop('server_key', None)
    encrypted = kwargs.pop('encrypted', '')
    cmd = list()

    st.log("Configuring CLIENT DAS SERVER Parameters ...")
    if cli_type in utils.get_supported_ui_type_list():
        das_glb_obj = umf_das.Das()
        das_client_obj = umf_das.DasClientConfigTableEntry(Clientaddress=client_addr, Das=das_glb_obj)
        if len(cmd_type_list):
            for cmd_type in cmd_type_list:
                st.log("cmd_type {}".format(cmd_type))
                if cmd_type == 'client_addr':
                    if config == 'yes':
                        result = das_client_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
                    else:
                        result = das_client_obj.unConfigure(dut, cli_type=cli_type)
                if cmd_type == 'client_addr_secret_key':
                    if config == 'yes':
                        setattr(das_client_obj, 'ServerKey', server_key)
                        setattr(das_client_obj, 'Encrypted', 'false')
                        result = das_client_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
                    else:
                        result = das_client_obj.unConfigure(dut, cli_type=cli_type)
        else:
            result = das_client_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config Client DAS parameters {}'.format(result.data))
            return False
        return True
    elif cli_type == "klish":
        if len(cmd_type_list):
            cmd.append("aaa server radius dynamic-author")

            for cmd_type in cmd_type_list:
                st.log("cmd_type {}".format(cmd_type))
                if cmd_type == 'client_addr':
                    if config == 'yes':
                        cmd.append('client {}'.format(client_addr))
                    else:
                        cmd.append('no client {}'.format(client_addr))
                if cmd_type == 'client_addr_secret_key':
                    if config == 'yes':
                        cmd.append('client {} server-key {} {}'.format(client_addr, server_key, encrypted))
                    else:
                        cmd.append('no client {}'.format(client_addr))
            cmd.append('exit')
        else:
            cmd.append("no aaa server radius dynamic-author")

        out = st.config(dut, cmd, type='klish', skip_error_check=skip_error)
        if 'Error' in out:
            return False
        return True


def show_radius_das(dut, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in utils.get_supported_ui_type_list():
        filter_type = kwargs.get("filter_type", "ALL")
        query_params_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        das_glb_obj = umf_das.Das()
        rv = das_glb_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        output = []
        if rv.ok():
            das_glb_data = rv.payload
            temp_dict = {}
            temp_dict['admin_mode'] = 'Enabled' if das_glb_data['openconfig-das:das']['das-global-config-table']['state']['das-admin-mode'] is True else 'Disabled'
            temp_dict['auth_type'] = das_glb_data['openconfig-das:das']['das-global-config-table']['state']['das-auth-type'].lower()
            temp_dict['port'] = das_glb_data['openconfig-das:das']['das-global-config-table']['state']['das-port']
            temp_dict['global_secret_key'] = 'Yes' if das_glb_data['openconfig-das:das']['das-global-config-table']['state']['encrypted'] is True else 'No'
            temp_dict['ignore_server_key'] = 'Enabled' if das_glb_data['openconfig-das:das']['das-global-config-table']['state']['ignore-server-key'] is True else 'Disabled'
            temp_dict['ignore_session_key'] = 'Enabled' if das_glb_data['openconfig-das:das']['das-global-config-table']['state']['ignore-session-key'] is True else 'Disabled'
            temp_dict['coa_bounce_host_port'] = 'Reject' if das_glb_data['openconfig-das:das']['das-global-config-table']['state']['ignore-bounce-port'] is True else 'Accept'
            temp_dict['coa_disable_host_port'] = 'Reject' if das_glb_data['openconfig-das:das']['das-global-config-table']['state']['ignore-disable-port'] is True else 'Accept'
            temp_dict['vrf_name'] = das_glb_data['openconfig-das:das']['das-global-config-table']['state'].get('das-vrf-name', 'Not Configured')
            temp_dict['req_timeout'] = das_glb_data['openconfig-das:das']['das-global-config-table']['state']['das-request-timeout']
            if 'das-client-config-table' in das_glb_data['openconfig-das:das']:
                for entry in das_glb_data['openconfig-das:das']['das-client-config-table']['das-client-config-table-entry']:
                    temp_dict1 = {}
                    temp_dict1['client_address'] = entry['state']['clientaddress']
                    temp_dict1['secret_key'] = 'Yes' if 'server-key' in entry['state'] else 'No'
                    temp_dict1.update(temp_dict)
                    output.append(temp_dict1)
            else:
                output.append(temp_dict)
            st.log("REST OUTPUT: {}".format(output))
    elif cli_type in "klish":
        command = "show radius-server dynamic-author"
        output = st.show(dut, command, type=cli_type)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output


def verify_radius_das(dut, **kwargs):
    """
    Author:naveen.kumaraketi@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=kwargs.pop('cli_type', ''))
    parsed_output = show_radius_das(dut, cli_type=cli_type, **kwargs)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = common_utils.filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}: Expected - {} Actual - {} ".format(each, kwargs[each],
                                                                                 parsed_output[0][each]))
            return False
    return True


def show_radius_das_statistics(dut, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    client = kwargs.pop('client', None)
    cli_type = force_cli_type_to_klish(cli_type=cli_type) if client == 'all' else cli_type

    if cli_type in utils.get_supported_ui_type_list():
        filter_type = kwargs.get("filter_type", "ALL")
        query_params_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        das_glb_obj = umf_das.Das()
        output = []
        temp_dict = {}
        if client is not None:
            das_client_obj = umf_das.DasClientCounterStatsTableEntry(Clientaddr=client, Das=das_glb_obj)
            rv = das_client_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
            das_data = rv.payload
            if rv.ok():
                temp_dict['coa_requests_received'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-requests-received'])
                temp_dict['coa_ack_responses_sent'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-ack-responses-sent'])
                temp_dict['coa_nack_responses_sent'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-nak-responses-sent'])
                temp_dict['coa_requests_ignored'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-requests-ignored'])
                temp_dict['coa_miss_unsupp_attr_requests'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-missing-unsupported-attributes-requests'])
                temp_dict['coa_sesn_ctxt_not_found_requests'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-session-context-not-found-requests'])
                temp_dict['coa_invalid_attr_requests'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-invalid-attribute-value-requests'])
                temp_dict['admin_prohibited_requests'] = str(das_data['openconfig-das:das-client-counter-stats-table-entry'][0]['state']['num-coa-administratively-prohibited-requests'])
        else:
            rv = das_glb_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
            das_data = rv.payload
            if rv.ok():
                temp_dict['coa_requests_received'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-requests-received'])
                temp_dict['coa_ack_responses_sent'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-ack-responses-sent'])
                temp_dict['coa_nack_responses_sent'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-nak-responses-sent'])
                temp_dict['coa_requests_ignored'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-requests-ignored'])
                temp_dict['coa_miss_unsupp_attr_requests'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-missing-unsupported-attributes-requests'])
                temp_dict['coa_sesn_ctxt_not_found_requests'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-session-context-not-found-requests'])
                temp_dict['coa_invalid_attr_requests'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-invalid-attribute-value-requests'])
                temp_dict['admin_prohibited_requests'] = str(das_data['openconfig-das:das']['das-global-counter-stats-table']['state']['num-coa-administratively-prohibited-requests'])
        output.append(temp_dict)
    else:
        command = "show radius-server dynamic-author statistics "
        if client is not None:
            command = command + "client " + client
        output = st.show(dut, command, type=cli_type)
    st.log(output)
    return output


def _convert_kwargs_to_list(**kwargs):
    # Converting all kwargs to list
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    return kwargs


def verify_radius_das_statistics(dut, cli_type="", **kwargs):
    """
    Author:naveen.kumaraketi@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    output = show_radius_das_statistics(dut, **kwargs)
    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    client = kwargs.pop('client', None)
    if client is None:
        kwargs.pop('dac_addr', None)

    kwargs = _convert_kwargs_to_list(**kwargs)

    # convert kwargs into list of dictionary
    input_dict_list = []
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = common_utils.filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False
    return ret_val


def clear_radius_das_statistics(dut, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    client = kwargs.pop('client', None)
    skip_error = kwargs.pop('skip_error_check', False)

    if cli_type in "klish":
        command = "clear radius-server dynamic-author statistics"
        if client is not None:
            command = command + ' client ' + client
        st.config(dut, command, skip_error_check=skip_error, type=cli_type)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def send_das_request(das_request_type, **kwargs):
    '''
    This function will create, execute and delete the dac request file on Radius server, provides the results
    :param das_request_type:
    :param kwargs:
    :param exp_result: True - Received-ACK, False - Received-NAK, None - No Response from server
    :return: True or False
    '''
    user_name = kwargs.pop('user_name', None)
    exp_result = kwargs.pop('exp_result', None)
    message_type_list = common_utils.make_list(kwargs.pop('message_type_list', []))
    rad_data = kwargs.pop('radius_data', {})
    exp_err_code = kwargs.pop('exp_err_code', None)
    das_ip = kwargs.pop('das_ip', None)
    das_key = kwargs.pop('das_key', None)
    das_port = kwargs.pop('das_port', 3799)
    ssh_obj = rad_data.get('ssh_obj', kwargs.get('ssh_obj'))
    das_fname = rad_data.get('das_fname', kwargs.get('das_fname'))
    radius_user_dir = rad_data.get('radius_server_users_dir', kwargs.get('radius_server_users_dir'))
    num_retries = rad_data.get('num_retries', kwargs.get('num_retries', '3'))
    num_requests_in_parallel = rad_data.get('num_requests_in_parallel', kwargs.get('num_requests_in_parallel'))
    delay_factor = kwargs.get('delay_factor', 1)
    exp_err_code_name = ''
    das_ip = das_ip if common_utils.is_valid_ipv4(das_ip) else '[{}]'.format(das_ip)
    mand_params = {'das_ip': das_ip, 'das_key': das_key, 'ssh_obj': ssh_obj, 'das_fname': das_fname,
                   'radius_user_dir': radius_user_dir}
    for param in mand_params:
        if mand_params[param] is None:
            st.log("Mandatory Parameter '{}' is missing".format(param))
            return False

    cmd = ''
    result2 = True
    result = True

    if ssh_obj:
        prompt = ssh_obj.find_prompt()
    else:
        return False

    st.log('prompt {}'.format(prompt))

    if das_request_type == 'DM':
        message_result = 'Disconnect'
        request_type = 'disconnect'
    elif das_request_type == 'COA':
        message_result = 'CoA'
        request_type = 'coa'
    elif das_request_type == 'ACCT':
        message_result = 'Acct'
        request_type = 'acct'
    else:
        st.log('Invalid DAS request type {}'.format(das_request_type))
        return False

    if exp_result is True:
        message_result = message_result + '-ACK'
    else:
        message_result = message_result + '-NAK'

    message_result = 'Received ' + message_result

    st.log('message_type_list - {}'.format(message_type_list))

    if exp_err_code is not None:
        if exp_err_code == '401':
            exp_err_code_name = 'Error-Cause = Unsupported-Attribute'
        if exp_err_code == '402':
            exp_err_code_name = 'Error-Cause = Missing-Attribute'
        if exp_err_code == '403':
            exp_err_code_name = 'Error-Cause = NAS-Identification-Mismatch'
        if exp_err_code == '404':
            exp_err_code_name = 'Error-Cause = Invalid-Request'
        if exp_err_code == '405':
            exp_err_code_name = 'Error-Cause = Unsupported-Service'
        if exp_err_code == '407':
            exp_err_code_name = 'Error-Cause = Invalid-Attribute-Value'
        if exp_err_code == '501':
            exp_err_code_name = 'Error-Cause = Administratively-Prohibited'
        if exp_err_code == '503':
            exp_err_code_name = 'Error-Cause = Session-Context-Not-Found'
        if exp_err_code == '504':
            exp_err_code_name = 'Error-Cause = Session-Context-Not-Removable'
        if exp_err_code == '508':
            exp_err_code_name = 'Error-Cause = Multiple-Session-Selection-Unsupported'

    msg_type_map = {'session_timeout': 'Session-Timeout', 'das_nas_ip_addr': 'NAS-IP-Address',
                    'das_nas_port_id': 'NAS-Port-Id', 'das_nas_port': 'NAS-Port',
                    'das_calling_station_id': 'Calling-Station-Id', 'das_acct_session_id': 'Acct-Session-Id',
                    'das_filter_id': 'filter-id', 'das_nas_id': 'NAS-identifier'}
    sub_cmd_map = {'reauthenticate': 'reauthenticate', 'bounce_host_port': 'bounce-host-port',
                   'disable_host_port': 'disable-host-port'}

    if user_name is not None:
        if type(user_name) is not list:
            user_name = common_utils.make_list(user_name)
    else:
        user_name = ['']
    for user in user_name:
        if user:
            user_info = 'user-name=' + '\\"' + user + '\\"'
            cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_user_dir + das_fname + '\n'
        for message_type in message_type_list:
            if message_type in list(sub_cmd_map.keys()):
                sub_command = 'cisco-AVPair=' + '\\"' + 'subscriber:command={}'.format(sub_cmd_map[message_type]) + '\\"'
                cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
            if message_type in list(msg_type_map.keys()):
                value = kwargs.get(message_type, None)
                if value is not None:
                    sub_command = '{} = '.format(msg_type_map[message_type]) + '\\"' + str(value) + '\\"'
                    cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
            if message_type == 'unknown_attribute':
                sub_command = 'tunnel-password=' + '\\"' + 'abcdef' + '\\"'
                cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
            if message_type == 'vlan':
                das_vlan_id = kwargs.get('das_vlan_id', None)
                das_tunnel_type = kwargs.get('das_tunnel_type', '13')
                das_tunnel_medium_type = kwargs.get('das_tunnel_medium_type', '6')
                if das_vlan_id is not None:
                    sub_command = 'Tunnel-type={},'.format(str(das_tunnel_type))
                    cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
                    sub_command = 'Tunnel-Medium-Type={},'.format(str(das_tunnel_medium_type))
                    cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
                    sub_command = 'Tunnel-Private-Group-ID=' + '\\"' + str(das_vlan_id) + '\\"'
                    cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
            if message_type == 'acl':
                das_acl = kwargs.get('das_acl', None)
                if das_acl is not None:
                    sub_command = 'cisco-AVPair=' + '\\"' + str(das_acl) + '\\"'
                    cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
            if message_type == 'redirect':
                das_url = kwargs.get('das_url', None)
                if das_url is not None:
                    sub_command = 'cisco-AVPair=' + '\\"' + 'url-redirect=' + das_url + '\\"'
                    cmd = cmd + 'echo -e ' + sub_command + ' >> ' + radius_user_dir + das_fname + '\n'
        if exp_err_code != '508':
            cmd = cmd + 'echo -e ""' + ' >> ' + radius_user_dir + das_fname + '\n'

    st.log('start executing command...')
    output = ssh_obj.send_command(cmd, expect_string=prompt)
    st.log('cmd -- {}'.format(cmd))
    st.log('Output -- {}'.format(output))

    cmd = 'cat ' + radius_user_dir + das_fname
    st.log('start executing command...')
    output = ssh_obj.send_command(cmd, expect_string=prompt)
    st.log('cmd -- {}'.format(cmd))
    st.log('Output -- {}'.format(output))

    cmd = 'cat ' + radius_user_dir + das_fname + ' | ' + 'radclient -x ' + das_ip + ':' + str(das_port) + ' ' + request_type + '  ' + das_key + ' -r ' + str(num_retries)
    if num_requests_in_parallel:
        cmd = cmd + ' -p ' + str(num_requests_in_parallel)
    st.log('start executing command...')
    output = ssh_obj.send_command(cmd, expect_string=prompt, delay_factor=delay_factor)
    st.log('###############################################################')
    st.log('cmd -- {}'.format(cmd))
    st.log('###############################################################')
    st.log('Output -- {}'.format(output))
    st.log('###############################################################')
    st.log('exp_result -- {}, exp_err_code -- {}, exp_err_code_name -- {}'.format(exp_result, exp_err_code, exp_err_code_name))

    if message_result in output:
        result1 = True
    else:
        if exp_result is None and 'No reply from server' in output:
            result1 = True
        else:
            result1 = False

    if exp_err_code is not None:
        if exp_err_code_name in output:
            result2 = True
        else:
            result2 = False

    if result1 is False or result2 is False:
        result = False

    cmd = 'rm -rf ' + radius_user_dir + das_fname
    output = ssh_obj.send_command(cmd, expect_string=prompt)
    st.log('cmd -- {}'.format(cmd))
    st.log('Output -- {}'.format(output))

    st.log('Expected message_result -- {}, exp_result -- {}, exp_err_code_name - {}, result1 -- {}, result2 -- {}, returning -- {}'.format(
        message_result, exp_result, exp_err_code_name, result1, result2, result))
    return result


def config_radius_clients(**kwargs):
    ##################################
    st.banner("Configure Radius Clients on Server")
    ###################################
    rad_data = kwargs.pop('radius_data', {})
    ssh_obj = rad_data.get('ssh_obj', kwargs.get('ssh_obj'))
    ip_addr = rad_data.get('client_ip', kwargs.get('client_ip'))
    netmask = rad_data.get('subnet', kwargs.get('subnet'))
    shared_secret_key = rad_data.get('shared_secret_key', kwargs.get('shared_key'))
    radius_dir = rad_data.get('radius_server_path', kwargs.get('radius_server_path'))
    clients_file_name = rad_data.get('clients_file_name', kwargs.get('clients_file_name', 'clients.conf'))

    if ip_addr is None:
        msg = st.error("Invalid Client IP")
        st.report_fail('test_case_failed_msg', msg)

    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        # client_info = 'client ' + ip_addr + '/' + netmask + '\{'
        # cmd = 'echo -e ' + client_info + ' > ' + radius_dir + '/' + clients_file_name + '\n'
        client_info = r'client host' + r'\{'
        cmd = 'echo -e ' + client_info + ' > ' + radius_dir + '/' + clients_file_name + '\n'
        client_info = r'\            ipaddr\         = ' + ip_addr + '/' + netmask + ''
        cmd = cmd + 'echo -e ' + client_info + ' >> ' + radius_dir + '/' + clients_file_name + '\n'
        client_info = r'\            secret\         = ' + shared_secret_key
        cmd = cmd + 'echo -e ' + client_info + ' >> ' + radius_dir + '/' + clients_file_name + '\n'
        client_info = r'\}'
        cmd = cmd + 'echo -e ' + client_info + ' >> ' + radius_dir + '/' + clients_file_name + '\n'
        st.log(cmd)
        output = ssh_obj.send_command(cmd, expect_string="{}|#|$".format(prompt))
        st.log(output)


def config_radius_users(**kwargs):
    rad_data = kwargs.pop('radius_data', {})
    user_dict = rad_data.get('user_dict', kwargs.get('user_dict'))
    radius_dir = rad_data.get('radius_server_path', kwargs.get('radius_server_path'))
    ssh_obj = rad_data.get('ssh_obj', kwargs.get('ssh_obj'))
    user_info = ''
    if kwargs.get('rewrite'):
        prompt = ssh_obj.find_prompt()
        cmd = 'echo -e ' + '>' + radius_dir + '/users' + '\n'
        st.log(cmd)
        output = ssh_obj.send_command(cmd, expect_string="{}|#|$".format(prompt))
        st.log(output)
    redirect_char = ' > '
    if kwargs.get('append_user'):
        redirect_char = ' >> '

    if kwargs.get('username'):
        user_info = user_info + kwargs['username'] + ' Cleartext-Password := \\"' + kwargs['password'] + '\\"'

    if kwargs.get('auth_type'):
        user_info += ' Auth-Type := \\"' + kwargs.pop('auth_type', 'EAP') + '\\"'
    cmd = 'echo -e ' + user_info + redirect_char + radius_dir + '/users' + '\n'

    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        if user_dict:
            for key, value in user_dict.items():
                cmd = ''
                user_info = ''
                if value.get('auth_type'):
                    user_info = user_info + key + ' Auth-Type := \\"' + str(value['auth_type']) + '\\"' + ',' + ' Cleartext-Password := \\"' + value['password'] + '\\"'
                else:
                    user_info = user_info + key + ' Cleartext-Password := \\"' + value['password'] + '\\"'
                cmd = cmd + 'echo -e ' + user_info + redirect_char + radius_dir + '/users' + '\n'
                if value.get('tunnel_type'):
                    user_info = r'\         Tunnel-Type = ' + str(value['tunnel_type']) + ','
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('tunnel_medium_type'):
                    user_info = r'\        Tunnel-Medium-Type = ' + str(value['tunnel_medium_type']) + ','
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('tunnel_private_group_id'):
                    user_info = r'\        Tunnel-Private-Group-Id = ' + str(value['tunnel_private_group_id']) + ','
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('session_timeout'):
                    user_info = r'\        Session-Timeout = \"' + str(value['session_timeout']) + '\\",'
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('termination_action'):
                    user_info = r'\        Termination-Action = \"' + str(value['termination_action']) + '\\",'
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('arista_avpair'):
                    user_info = r'\        Arista-AVPair = \"' + str(value['arista_avpair']) + '\\",'
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('redirect_acl'):
                    user_info = r'\        Cisco-AVPair += \"url-redirect-acl=' + str(value['redirect_acl']) + '\\",'
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('redirect_url'):
                    user_info = r'\        Cisco-AVPair += \"url-redirect=' + str(value['redirect_url']) + '\\",'
                    cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('cisco_avpair'):
                    for val in common_utils.make_list(value['cisco_avpair']):
                        user_info = r'\        Cisco-AVPair += \"' + str(val) + '\\",'
                        cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('filter_id'):
                    for val in common_utils.make_list(value['filter_id']):
                        user_info = r'\        Filter-Id += \"' + str(val) + '\\",'
                        cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                if value.get('mgmt_priv_level'):
                    for val in common_utils.make_list(value['mgmt_priv_level']):
                        user_info = r'\        Management-Privilege-Level := \"' + str(val) + '\\",'
                        cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                str_1 = "Hello %u"
                last_line = r'\        Reply-Message = \"' + str_1 + '\\"'
                cmd = cmd + 'echo -e ' + last_line + ' >> ' + radius_dir + '/users' + '\n'
                st.log(cmd)
                output = ssh_obj.send_command(cmd, expect_string="{}|#|$".format(prompt))
                st.log(output)
        else:
            if kwargs.get('tunnel_type'):
                user_info = r'\         Tunnel-Type = ' + str(kwargs['tunnel_type']) + ','
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
            if kwargs.get('tunnel_medium_type'):
                user_info = r'\        Tunnel-Medium-Type = ' + str(kwargs['tunnel_medium_type']) + ','
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
            if kwargs.get('vlan_id'):
                user_info = r'\         Tunnel-Type = ' + '13' + ','
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                user_info = r'\        Tunnel-Medium-Type = ' + '6' + ','
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
                user_info = r'\        Tunnel-Private-Group-Id = ' + str(kwargs['vlan_id']) + ','
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
            if kwargs.get('filter_id'):
                user_info = r'\        Filter-Id = \"' + str(kwargs['filter_id']) + '\\",'
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
            if kwargs.get('session_timeout'):
                user_info = r'\        Session-Timeout = \"' + str(kwargs['session_timeout']) + '\\",'
                cmd = cmd + 'echo -e ' + user_info + ' >> ' + radius_dir + '/users' + '\n'
            str_1 = "Hello %u"
            last_line = r'\        Reply-Message = \"' + str_1 + '\\"'
            cmd = cmd + 'echo -e ' + last_line + ' >> ' + radius_dir + '/users' + '\n'
            st.log(cmd)
            output = ssh_obj.send_command(cmd, expect_string="{}|#|$".format(prompt))
            st.log(output)


def unconfig_radius_users(**kwargs):
    rad_data = kwargs.pop('radius_data', {})
    radius_dir = rad_data.get('radius_server_path', kwargs.get('radius_server_path'))
    ssh_obj = rad_data.get('ssh_obj', kwargs.get('ssh_obj'))
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        cmd = 'echo ' + '>' + radius_dir + '/users'
        output = ssh_obj.send_command(cmd, expect_string="{}|#|$".format(prompt))
        st.log(output)


def run_radius_server(action='restart', **kwargs):
    #########################################
    st.banner("{} Radius server".format(action))
    #########################################
    rad_data = kwargs.pop('radius_data', {})
    radius_dir = rad_data.get('radius_server_path', kwargs.get('radius_server_path'))
    ssh_obj = rad_data.get('ssh_obj', kwargs.get('ssh_obj'))
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = 'cat {}/clients.conf'.format(radius_dir)
        ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        command = 'cat {}/users'.format(radius_dir)
        ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        command = 'service freeradius {}'.format(action)
        st.log(command)
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        st.log(output)


def set_radius_server_params(dut):
    rad_server = dict()
    rad_server['server_ip'] = ensure_service_params(dut, "pac_radius", "ip")
    rad_server['username'] = ensure_service_params(dut, "pac_radius", "username")
    rad_server['password'] = ensure_service_params(dut, "pac_radius", "password")
    rad_server['radius_server_path'] = ensure_service_params(dut, "pac_radius", "radius_server_path")
    rad_server['radius_server_home_path'] = ensure_service_params(dut, "pac_radius", "radius_server_home_path")
    rad_server['radius_server_mask'] = ensure_service_params(dut, "pac_radius", "radius_server_mask")
    rad_server['radius_server_log'] = ensure_service_params(dut, "pac_radius", "radius_server_log")
    rad_server['ssh_port'] = 22
    rad_server['auth_port'] = 1812
    # To provide env argument SPYTEST_OVERRIDE_RADIUS_INFO, follow format ip:ssh_port:radius_server_port (10.190.1.1:22:1812)
    server_info = "{}:{}:{}".format(rad_server['server_ip'], rad_server['ssh_port'], 1812)
    server_info = st.getenv("SPYTEST_OVERRIDE_RADIUS_INFO", server_info)
    match = re.search(r'([^:]*):(\d+):(\d+)', server_info)
    if match:
        rad_server['server_ip'] = match.group(1)
        rad_server['ssh_port'] = match.group(2)
        rad_server['auth_port'] = match.group(3)
    # Update valid server/VM IP (tcp://10.193.81.56:2375) in 'docker:spytest_docker_host' in sonic_services.yaml, if not leave it empty.
    DOCKER_HOST = ensure_service_params(dut, "docker", "spytest_docker_host")
    # To provide env argument SPYTEST_DOCKER_HOST, follow format --env SPYTEST_DOCKER_HOST tcp://10.193.81.56:2375
    DOCKER_HOST = st.getenv("SPYTEST_DOCKER_HOST", DOCKER_HOST)
    if DOCKER_HOST:
        url_info = common_utils.parse_url(DOCKER_HOST)
        if url_info["ip"]:
            st.log("Creating radius docker")
            rad_server['server_ip'] = url_info["ip"]
            radius_container_data = create_radius_docker_container(DOCKER_HOST)
            rad_server['ssh_port'] = radius_container_data['ssh_port']
            rad_server['auth_port'] = radius_container_data['radius_port']
            rad_server['username'] = radius_container_data['username']
            rad_server['password'] = radius_container_data['password']
            rad_server['radius_server_home_path'] = '/home/{}'.format(rad_server['username'])
            st.register_cleanup(remove_radius_docker_container, radius_container_data['cont_id'], DOCKER_HOST)
    st.banner("Radius server details used in this run: server ip-{}, ssh_port-{}, auth_port-{}".format(rad_server['server_ip'], rad_server['ssh_port'], rad_server['auth_port']))
    if not ip_api.ping(dut, rad_server['server_ip'], family='ipv4', external=True):
        st.error("Ping reachability is failed between radius server and Device.")
    rad_server['ssh_obj'] = con_obj.connect_to_device(rad_server['server_ip'], rad_server['username'], rad_server['password'], 'ssh', retry=5, port=rad_server['ssh_port'])
    if not rad_server['ssh_obj']:
        st.error("Failed to connect to radius server")
        st.report_fail('test_case_failed')
    return rad_server
