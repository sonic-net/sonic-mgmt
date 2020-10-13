# This file contains the list of API's which performs RADIUS operations.
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
import utilities.utils as utils
import utilities.common as common_utils

debug = False


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
    st.log("Configuring RADIUS SERVER Parameters ...")
    cli_type = kwargs["cli_type"] if kwargs.get("cli_type") else "klish"
    if "ip_address" not in kwargs:
        st.log("IP Address not provided")
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
            command = "no {}".format(cmd) if no_form else cmd
            st.cli_config(dut, command, "mgmt-config", skip_error_check)
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
            st.config(dut, command, skip_error_check=skip_error_check)


def config_global_server_params(dut, skip_error_check=False, params=dict(), cli_type="klish"):
    """
    Config / Unconfig global server params using provided parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param params: {"source_ip":{"value":"10.20.3.1", "no_form": False}, "key":{"value":"ABCD", "no_form": True},
                "auth_port":{"value":"56", "no_form": False}, "timeout":{"value":"30", "no_form": True}}
    :return:
    """
    st.log("Configuring GLOBAL SERVER Parameters ...")
    if not params:
        st.log("Invalid parameters provided ..")
        return False
    count = 0
    if cli_type == "klish":
        cmd = "radius-server"
        fields = {"source_ip": "source-ip", "key": "key", "auth_type": "auth-type", "timeout": "timeout",
                  "retransmit": "retransmit"}
        for key, value in params.items():
            if value.get("no_form"):
                command = "no {} {}".format(cmd, fields[key])
            else:
                command = "{} {} {}".format(cmd, fields[key], value["value"])
            output = st.cli_config(dut, command, "mgmt-config", skip_error_check)
            if "Syntax error: Illegal parameter" in utils.remove_last_line_from_string(output):
                st.log(utils.remove_last_line_from_string(output))
                return False
            count += 1
    elif cli_type == "click":
        cmd = "config radius"
        fields = {"source_ip":"sourceip","key":"passkey","auth_type":"authtype","timeout":"timeout","retransmit":"retransmit"}
        for key, value in params.items():
            if value.get("no_form"):
                if key == "source_ip":
                    command = "{} default {} {}".format(cmd, fields[key], value["value"])
                else:
                    command = "{} default {}".format(cmd, fields[key])
            else:
                command = "{} {} {}".format(cmd, fields[key], value["value"])
            output = st.config(dut, command, skip_error_check=skip_error_check)
            if "Valid chars are" in utils.remove_last_line_from_string(output):
                st.log(utils.remove_last_line_from_string(output))
                return False
            count += 1
    if count > 0:
        return True
    st.log("Returning False as the command execution is not happened with the provided parameters .. ")
    return False

def show_config(dut, search_string="", cli_type="klish"):
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
    st.log("Showing radius configuration ...")
    result = {"globals": [], "servers": []}
    if cli_type == "klish":
        command = "show radius-server"
        output = st.cli_show(dut, command, "mgmt-user")
        global_out = dict()
        for k, v in output[0].items():
            if "global" in k:
                global_out[k] = v
        if global_out and utils.check_empty_values_in_dict(global_out):
            result["globals"].append(global_out)
        for d in output[1:]:
            server_out = dict()
            for k, v in d.items():
                if not "global" in k:
                    server_out[k] = v
            if server_out and utils.check_empty_values_in_dict(server_out):
                result["servers"].append(server_out)
    elif cli_type == "click":
        command = "show radius | grep -w {}".format(search_string) if search_string else "show radius"
        output = st.show(dut, command)
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
    return result

def verify_config(dut, params, cli_type="klish"):
    """
    API to verify the Radius Parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param params: {"globals":{"global_auth_type":"pap", "global_source_ip":'10.25.36.25'},
    "servers":[{'auth_port': '1815', 'priority': '1', 'address': '1.1.1.5'},
      {'auth_port': '1812', 'priority': '1', 'address': '1.1.1.1'}]}
    :return:
    """
    if not isinstance(params, dict):
        st.log("Unsupported data format provided...")
        return False

    output = show_config(dut, cli_type=cli_type)
    if not output:
        st.log("Identified empty radius output ..")
        return False
    if "globals" in params and params["globals"]:
        for key, value in params["globals"].items():
            if str(value) != output["globals"][0][key]:
                st.log("Verification of radius global parameters {} with {} values is failed".format(key, value))
                return False
    if "servers" in params and params["servers"]:
        for details in params["servers"]:
            is_found = 0
            for data in output["servers"]:
                for key, value in details.items():
                    if str(value) != data[key]:
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
