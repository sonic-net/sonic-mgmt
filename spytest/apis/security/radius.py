# This file contains the list of API's which performs RADIUS operations.
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
import utilities.utils as utils
import utilities.common as common_utils
from apis.system.rest import config_rest, get_rest, delete_rest

debug = False

##timeout set to 125 sec due defect sonic-24329.once fixed will change to lower limit.
time_out=125

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
        if cli_type == "klish":
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
    if cli_type == "klish":
        cmd = "radius-server"
        fields = {"source_ip": "source-ip", "key": "key", "auth_type": "auth-type", "timeout": "timeout",
                  "retransmit": "retransmit", "nasip": "nas-ip", "statistics":"statistics"}
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
        fields = {"source_ip":"sourceip","key":"passkey","auth_type":"authtype","timeout":"timeout","retransmit":"retransmit","nasip":"nasip","statistics":"statistics"}
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
        url_mapping = {"source_ip":"radius_sourceip", "key":"radius_key", "auth_type": "radius_authtype", "timeout": "radius_timeout",
                  "retransmit": "radius_retransmit", "nasip": "radius_nasip", "statistics":"radius_statistics"}
        for key, value in params.items():
            if value.get("no_form"):
                url = rest_urls[url_mapping[key]].format("RADIUS")
                if not delete_rest(dut,  rest_url=url, timeout=time_out):
                    return False
            else:
                url = rest_urls['aaa_server_config']
                if key == "statistics":
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS"}, "openconfig-aaa-radius-ext:radius": {"config": {"statistics": True}}}]}
                elif key == 'nasip':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS", "config": {"name": "RADIUS"}, "openconfig-aaa-radius-ext:radius": {"config": {"nas-ip-address": value["value"]}}}]}
                elif key == 'retransmit':
                    data = {"openconfig-system:server-group": [{"name": "RADIUS","openconfig-aaa-radius-ext:radius": {"config": {"retransmit-attempts": int(value["value"])}}}]}
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


def show_config(dut, search_string="", cli_type=""):
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
    st.log("Showing radius configuration ...")
    result = {"globals": [], "servers": []}
    if cli_type == "klish":
        command = "show radius-server"
        output = st.show(dut, command, type=cli_type)
        global_out = dict()
        if not output:
            return result
        for k, v in output[0].items():
            if "global" in k:
                global_out[k] = v
        if global_out:
            result["globals"].append(global_out)
        for d in output[0:]:
            server_out = dict()
            for k, v in d.items():
                if not "global" in k:
                    server_out[k] = v
            if server_out:
                result["servers"].append(server_out)
    elif cli_type == "click":
        command = "show radius | grep -w {}".format(search_string) if search_string else "show radius"
        output = st.show(dut, command, type=cli_type)
        for d in output:
            global_out = dict()
            server_out = dict()
            for k, v in d.items():
                if "global" in k:
                    global_out[k] = v
                else:
                    server_out[k] = v
            if global_out and not utils.check_empty_values_in_dict(global_out):
                result["globals"].append(global_out)
            if server_out and not utils.check_empty_values_in_dict(server_out):
                result["servers"].append(server_out)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['radius_server_show'].format("RADIUS")
        url1 = rest_urls['radius_server_config'].format("RADIUS")
        url2 = rest_urls['radius_nasip_retransmit_stasitics_config'].format("RADIUS")
        server_output = get_rest(dut, rest_url=url)
        global_config = get_rest(dut, rest_url=url1)
        global_ext_data = get_rest(dut, rest_url=url2)
        result =  process_radius_output(server_output['output'], global_config['output'], global_ext_data['output'])
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
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
    if not isinstance(params, dict):
        st.log("Unsupported data format provided...")
        return False

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
                        st.log("Radius server Key Value verification success")
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
    if cli_type in ['click','klish']:
        command = "sonic-clear radius"
        st.config(dut, command, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['radius_statistics'].format("RADIUS")
        delete_rest(dut, rest_url=url, get_response=True)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True

def process_radius_output(server_output, global_config, global_ext_data):

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
                    servers["auth_type"] = serve_config.get("openconfig-system-ext:auth-type", "")
                    servers["priority"] = serve_config.get("openconfig-system-ext:priority", "")
                    servers["vrf_mgmt"] = serve_config.get("openconfig-system-ext:vrf", "")
                    servers["timeout"] = serve_config.get("timeout", "")
                else:
                    servers["auth_type"] = servers["priority"] = servers["vrf_mgmt"] = servers["timeout"] = ""

                if server_data.get("radius") and "config" in server_data.get("radius"):
                    radius_data = server_data.get("radius")["config"]
                    servers["auth_port"] = radius_data.get("auth-port","")
                    servers["retransmit"] = radius_data.get("retransmit-attempts","")
                    servers["passkey"] = radius_data.get("secret-key","")

                else:
                    servers["auth_port"] = servers["retransmit"] = servers["passkey"] = ""

                if server_data.get("state") and "counters" in server_data.get("state"):
                    counters_data = server_data.get("state")["counters"]
                    servers["access_accepts"] = counters_data.get("access-accepts", "0")
                    servers["access_rejects"] = counters_data.get("access-rejects", "0")
                    servers["access_requests"] = counters_data.get("openconfig-aaa-radius-ext:access-requests", "0")
                else:
                    servers["access_accepts"] = servers["access_rejects"] = servers["access_requests"] = "0"
                radius_output["servers"].append(servers)
    global_data = dict()
    if global_config and global_config.get("openconfig-system:config"):
        global_config_data = global_config.get("openconfig-system:config")
        global_data["global_auth_type"] = global_config_data.get("openconfig-system-ext:auth-type", "")
        global_data["global_passkey"] = global_config_data.get("openconfig-system-ext:secret-key", "")
        global_data["global_source_ip"] = global_config_data.get("openconfig-system-ext:source-address", "")
        global_data["global_timeout"] = global_config_data.get("openconfig-system-ext:timeout", "")
    else:
        global_data["global_auth_type"] = ""
        global_data["global_passkey"] = ""
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
