# This file contains the list of API's which performs RADIUS operations.
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

import re
from spytest import st
import apis.system.basic as basic_obj
from apis.system.rest import config_rest, get_rest, delete_rest
from utilities import utils
import utilities.common as common_utils
import apis.system.system_server as sys_server_api
from utilities.utils import get_supported_ui_type_list

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
