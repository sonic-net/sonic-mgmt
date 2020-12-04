import re
import string
import copy
import random
import json
from spytest.logger import Logger
from spytest.st_time import get_timenow
import spytest.env as env

class UIGnmi(object):
    def __init__(self, logger=None, testbed_vars=None):
        self.logger = logger or Logger()
        self.tb_vars = testbed_vars
        self.no_need_to_add = False

    def uignmi_log(self, msg, width=120, delimiter="#", header=True, footer=True):
        msg_list = []
        if header:
            msg_list.append(delimiter * width)
        if msg != None:
            if isinstance(msg, list):
                for eachline in msg:
                    if isinstance(eachline, list):
                        msg_list.append("{0} {1} {0}".format(delimiter, " : ".join(str(e) for e in eachline).center(width - 4)))
                    else:
                        msg_list.append("{0} {1} {0}".format(delimiter, str(eachline).center(width - 4)))
            else:
                msg_list.append("{0} {1} {0}".format(delimiter, msg.center(width - 4)))
        if footer:
            msg_list.append(delimiter * width)
        for each_line in msg_list:
            self.logger.info(each_line)

    def _uignmi_get_config_mode_path_values(self, all_path_args, all_params, stepentry, replaced_mode_values):
        try:
            if "configs" in stepentry.keys():
                for config_step in stepentry["configs"]:
                    path = config_step.get("path", None)
                    op = config_step.get("operation", None)

                    if path and op:
                        path_plus_op = "{};{}".format(path, op)
                        if path_plus_op in all_path_args:
                            for key, value in all_path_args[path_plus_op].items():
                                if key not in replaced_mode_values:
                                    changed_value = self._uignmi_get_valueset_for_param(all_params, path_plus_op, key, value, "path")
                                    replaced_mode_values[key] = changed_value
        except Exception:
            pass
        return

    def _uignmi_get_config_mode_data_values(self, all_data_args, all_params, stepentry, replaced_mode_values, replaced_cmd_params):
        try:
            if "configs" in stepentry.keys():
                for config_step in stepentry["configs"]:
                    path = config_step.get("path", None)
                    op = config_step.get("operation", None)

                    if path and op:
                        path_plus_op = "{};{}".format(path, op)
                        if path_plus_op in all_data_args:
                            for key, value in all_data_args[path_plus_op].items():
                                if key not in replaced_cmd_params:
                                    trimmed_value = re.sub(r"\{\{", "", re.sub(r"\}\}", "", value)).split(" ")[0]
                                    val_list = trimmed_value.split(";")
                                    if len(val_list) > 2:
                                        type_or_upd_value = val_list[-1].split("|")
                                    else:
                                        type_or_upd_value = val_list[1]
                                    if val_list[0] in replaced_mode_values:
                                        changed_value = replaced_mode_values[val_list[0]]
                                    else:
                                        changed_value = self._uignmi_get_valueset_for_param(all_params, path_plus_op, key, type_or_upd_value, "parameter")
                                    replaced_cmd_params[key] = changed_value
        except Exception:
            pass
        return

    def _uignmi_get_action_mode_arg_values(self, all_path_args, all_params, stepentry, replaced_mode_values):
        try:
            if "actions" in stepentry.keys():
                for action_step in stepentry["actions"]:
                    path = action_step.get("path", None)
                    op = action_step.get("operation", None)

                    if path and op:
                        path_plus_op = "{};{}".format(path, op)
                        if path_plus_op in all_path_args:
                            for key, value in all_path_args[path_plus_op].items():
                                if key not in replaced_mode_values:
                                    changed_value = self._uignmi_get_valueset_for_param(all_params, path_plus_op, key, value, "path")
                                    replaced_mode_values[key] = changed_value
        except Exception:
            pass
        return

    def _uignmi_get_action_cmd_param_values(self, all_data_args, all_params, stepentry, replaced_mode_values, replaced_cmd_params):
        try:
            if "actions" in stepentry.keys():
                for action_step in stepentry["actions"]:
                    path = action_step.get("path", None)
                    op = action_step.get("operation", None)

                    if path and op:
                        path_plus_op = "{};{}".format(path, op)
                        if path_plus_op in all_data_args:
                            for key, value in all_data_args[path_plus_op].items():
                                if key not in replaced_cmd_params:
                                    trimmed_value = re.sub(r"\{\{", "", re.sub(r"\}\}", "", value)).split(" ")[0]
                                    val_list = trimmed_value.split(";")
                                    if len(val_list) > 2:
                                        type_or_upd_value = val_list[-1].split("|")
                                    else:
                                        type_or_upd_value = val_list[1]
                                    if val_list[0] in replaced_mode_values:
                                        changed_value = replaced_mode_values[val_list[0]]
                                    else:
                                        changed_value = self._uignmi_get_valueset_for_param(all_params, path_plus_op, key, type_or_upd_value, "parameter")
                                    replaced_cmd_params[key] = changed_value
        except Exception:
            pass
        return

    def _uignmi_get_preconfig_mode_path_values(self, all_path_args, all_params, stepentry, replaced_mode_values):
        try:
            if "pre-configs" in stepentry.keys():
                for config_step in stepentry["pre-configs"]:
                    path = config_step.get("path", None)
                    op = config_step.get("operation", None)

                    if path and op:
                        path_plus_op = "{};{}".format(path, op)
                        if path_plus_op in all_path_args:
                            for key, value in all_path_args[path_plus_op].items():
                                if key not in replaced_mode_values:
                                    changed_value = self._uignmi_get_valueset_for_param(all_params, path_plus_op, key, value, "path")
                                    replaced_mode_values[key] = changed_value
        except Exception:
            pass
        return

    def _uignmi_get_preconfig_mode_data_values(self, all_data_args, all_params, stepentry, replaced_mode_values, replaced_cmd_params):
        try:
            if "pre-configs" in stepentry.keys():
                for config_step in stepentry["pre-configs"]:
                    path = config_step.get("path", None)
                    op = config_step.get("operation", None)

                    if path and op:
                        path_plus_op = "{};{}".format(path, op)
                        if path_plus_op in all_data_args:
                            for key, value in all_data_args[path_plus_op].items():
                                if key not in replaced_cmd_params:
                                    trimmed_value = re.sub(r"\{\{", "", re.sub(r"\}\}", "", value)).split(" ")[0]
                                    val_list = trimmed_value.split(";")
                                    if len(val_list) > 2:
                                        type_or_upd_value = val_list[-1].split("|")
                                    else:
                                        type_or_upd_value = val_list[1]
                                    if val_list[0] in replaced_mode_values:
                                        changed_value = replaced_mode_values[val_list[0]]
                                    else:
                                        changed_value = self._uignmi_get_valueset_for_param(all_params, path_plus_op, key, type_or_upd_value, "parameter")
                                    replaced_cmd_params[key] = changed_value
        except Exception:
            pass
        return

    def _uignmi_substitute_path_data_params(self, stepentry, all_data_args, all_params, replaced_mode_values, replaced_cmd_params):
        changed_steps = []

        minIndex = 0
        maxIndex = 1
        if env.get("SPYTEST_UI_POSITIVE_CASES_ONLY", "0") != "0":
            maxIndex = 1

        for index in range(minIndex, maxIndex):
            copied_step = copy.deepcopy(stepentry)

            try:
                if "pre-configs" in copied_step.keys():
                    for preconfig_step in copied_step["pre-configs"]:
                        path = preconfig_step.get("path", None)
                        op = preconfig_step.get("operation", None)
                        data = preconfig_step.get("data", None)
                        path_plus_op = "{};{}".format(path, op)

                        cfg_valid = preconfig_step.get("valid", 1)
                        if index > 2:
                            cfg_valid = int(not cfg_valid)

                        # Replace the arg values in path string
                        if path:
                            pattern_match = re.findall(r"{(\w+(-*\w+)+)}", path)
                            if pattern_match:
                                for key, value in replaced_mode_values.items():
                                    for attr in pattern_match:
                                        # keyword = re.findall("\w+", attr)
                                        if key == attr[0]:
                                            path = path.replace("={" + key + "}", "[{}={}]".format(key, value))
                                            path = path.replace(",{" + key + "}", "[{}={}]".format(key, value))
                        path = path.replace("/restconf/data", "")
                        if data:
                            datastr = json.dumps(data)
                            for key, value in replaced_cmd_params.items():
                                if key in datastr:
                                    arg_datatype_str = all_data_args[path_plus_op][key]
                                    if "integer" in arg_datatype_str or "boolean" in arg_datatype_str or isinstance(value,int):
                                        datastr = datastr.replace("\"{{" + key + "}}\"", str(value))
                                    else:
                                        datastr = datastr.replace("{{" + key + "}}", str(value))
                            data = json.loads(datastr)

                        # Update the step values with replaced data
                        preconfig_step.update({"path": path})
                        preconfig_step.update({"data": data})
                        preconfig_step.update({"valid": cfg_valid})

                if "configs" in copied_step.keys():
                    for config_step in copied_step["configs"]:
                        path = config_step.get("path", None)
                        op = config_step.get("operation", None)
                        data = config_step.get("data", None)
                        path_plus_op = "{};{}".format(path, op)

                        cfg_valid = config_step.get("valid", 1)
                        if index > 2:
                            cfg_valid = int(not cfg_valid)

                        # Replace the arg values in path string
                        if path:
                            pattern_match = re.findall(r"{(\w+(-*\w+)+)}", path)
                            if pattern_match:
                                for key, value in replaced_mode_values.items():
                                    for attr in pattern_match:
                                        # keyword = re.findall("\w+", attr)
                                        if key == attr[0]:
                                            path = path.replace("={" + key + "}", "[{}={}]".format(key, value))
                                            path = path.replace(",{" + key + "}", "[{}={}]".format(key, value))
                        path = path.replace("/restconf/data", "")

                        if data:
                            datastr = json.dumps(data)
                            for key, value in replaced_cmd_params.items():
                                if key in datastr:
                                    arg_datatype_str = all_data_args[path_plus_op][key]
                                    if "integer" in arg_datatype_str or "boolean" in arg_datatype_str or isinstance(value, int):
                                        datastr = datastr.replace("\"{{" + key + "}}\"", str(value))
                                    else:
                                        datastr = datastr.replace("{{" + key + "}}", str(value))
                            data = json.loads(datastr)

                        # Update the step values with replaced data
                        config_step.update({"path": path})
                        config_step.update({"data": data})
                        config_step.update({"valid": cfg_valid})

                if self.no_need_to_add:
                    continue

                if "actions" in copied_step.keys():
                    for action_step in copied_step["actions"]:
                        path = action_step.get("path", None)
                        matches = action_step.get("match", None)

                        action_valid = action_step.get("valid", 1)
                        if index > 2:
                            action_valid = int(not action_valid)

                        # Replace the arg values in path string
                        if path:
                            pattern_match = re.findall(r"{(\w+(-*\w+)+)}", path)
                            if pattern_match:
                                for key, value in replaced_mode_values.items():
                                    for attr in pattern_match:
                                        # keyword = re.findall("\w+", attr)
                                        if key == attr[0]:
                                            path = path.replace("={" + key + "}", "[{}={}]".format(key, value))
                                            path = path.replace(",{" + key + "}", "[{}={}]".format(key, value))
                        path = path.replace("/restconf/data", "")

                        if matches:
                            matches_str = json.dumps(matches)
                            for key, value in replaced_cmd_params.items():
                                if key in matches_str:
                                    arg_datatype_str = all_data_args[path_plus_op][key]
                                    if "integer" in arg_datatype_str or "boolean" in arg_datatype_str or isinstance(value, int):
                                        matches_str = matches_str.replace("\"{{" + key + "}}\"", str(value))
                                    else:
                                        matches_str = matches_str.replace("{{" + key + "}}", str(value))
                            matches = json.loads(matches_str)

                        # Update the step values with replaced data
                        action_step.update({"path": path})
                        if matches:
                            action_step.update({"match": matches})
                        action_step.update({"valid": action_valid})

                if not self.no_need_to_add:
                    changed_steps.append(copied_step)
            except Exception:
                pass

        if not changed_steps:
            changed_steps.append(copy.deepcopy(stepentry))

        return changed_steps

    def _uignmi_get_valueset_for_param(self, all_params, path_plus_op, param_name, param_type, datatype):
        retval = "TODO"

        # print("_uignmi_get_valueset_for_param:", param_name, param_type)
        if isinstance(param_type, list):
            # Later need to differentiate this for path, parameter, match
            retval = random.choice(param_type)
        elif param_type in ["integer", "number", "double", "string", "boolean"]:
            if param_type in ["integer", "number", "double"]:
                int_vals = range(0,65536)
                # Later need to differentiate this for path, parameter, match
                retval = random.choice(int_vals)
            elif param_type in ["string"]:
                is_interface_in_path = "interface={"+param_name+"}"
                is_ipaddress_in_path = "address={"+param_name+"}"

                mac_address_names = ["mac-address", "source-mac", "destination-mac"]

                if is_interface_in_path in path_plus_op:
                    # Later need to differentiate this for path, parameter, match
                    retval = random.choice(self.tb_vars.free_ports)
                elif param_name in mac_address_names:
                    retval = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(2)) for _ in range(6))
                elif is_ipaddress_in_path in path_plus_op:
                    if "v6" in path_plus_op or "V6" in path_plus_op:
                        retval = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(4)) for _ in range(8))
                    else:
                        retval = '.'.join(str(random.randint(0, 255)) for _ in range(4))
                elif "hostname" in param_name:
                    # Later need to differentiate this for path, parameter, match
                    retval = "sonic"
                else:
                    letters = string.ascii_letters + string.digits + '_-'
                    minLen = 1
                    maxLen = 64
                    stringLength = random.randint(minLen, maxLen)
                    # Later need to differentiate this for path, parameter, match
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
            elif param_type in ["boolean"]:
                bool_vals = [0,1]
                # Later need to differentiate this for path, parameter, match
                retval = random.choice(bool_vals)
        elif param_type in all_params:
            #param_dict = all_params[param_type]
            retval = self._uignmi_get_valueset_for_param_from_clilist(param_name, param_type, all_params, datatype)

        #print("Random_value:", retval)
        return retval

    def _uignmi_get_valueset_for_param_from_clilist(self, param_name, param_type, all_params, datatype):
        retval = "TODO"

        param_dict = all_params[param_type]
        method = param_dict.get("method", None)
        pattern = param_dict.get("pattern", None)
        ip_address_patterns = ["INT_OR_IP_ADDR", "IP_ADDR", "IP_ADDR_ANY",
                               "IP_ADDR_DHCP_SUBNET", "IP_ADDR_DHCP_SUBNET_IPV4IPV6",
                               "IP_ADDR_MASK", "IPADDR_NN", "IPV4_ADDR_ABC",
                               "IPV4_IPV6_NETWORK", "IPV4_OR_IPV6_ADDR", "INT32_OR_IP_ADDR",
                               "IPV4V6_ADDR", "IPV6_ADDR", "IPV6_ADDR_MASK", "DOTTED_QUAD", "AA_NN_IPADDR_NN",
                               "HOSTNAME_OR_IPADDR", "HOSTNAME_OR_IPV4_ADDR", "RD", "RT", "OSPF_INT_OR_IP_ADDR", "AREA_NUM_DOT"]

        if param_type.startswith("SPYTEST_"):
            if param_name == "bgp_instance":
                retval = 1
                return retval

            if param_name in ["bgp_vrf_name", "ospf_vrf_name"]:
                retval = "Vrf_test"
                return retval

            if param_name == "domain_id":
                retval = 1
                return retval

            if method in ["integer", "unsignedInteger"]:
                (minv, maxv) = re.match(r'(\d+)\.\.(\d+)', pattern).groups()
                retval = random.randint(int(minv), int(maxv))
            if method == "UINT" and "INTERFACE" in param_type:
                retval = random.choice(self.tb_vars.free_ports)
            if method in ["select"]:
                choices = re.findall(r"(\S+)\(\S+\)", pattern)
                retval = random.choice(choices)
            if method == "string":
                while True:
                    letters = string.ascii_letters + string.digits + '_-'
                    minLen = 1
                    maxLen = 63
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    if re.match(pattern, retval):
                        break
            if method == "ipaddress":
                while True:
                    retval = '.'.join(str(random.randint(0, 255)) for _ in range(4))
                    if re.match(pattern, retval):
                        break
        elif method:
            if method in ["integer", "unsignedInteger"]:
                if param_name in ["as-num-dot", "asnum", "as-number"]:
                    retval = 1
                    return retval

                (minv, maxv) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', pattern).groups()
                retval = random.randint(int(minv), int(maxv))
            elif method in ["select"]:
                if param_type == "INTF_TYPE":
                    tmp_choices = re.findall(r"(\S+)", pattern)
                    choices = []
                    for tmp in tmp_choices:
                        choices.append(re.sub(r"\(\S+\)", "", tmp))
                elif "(" in pattern:
                    choices = re.findall(r"(\S+)\(\S+\)", pattern)
                else:
                    choices = re.findall(r"(\S+)", pattern)
                retval = random.choice(choices)
            elif method in ["regexp_select"]:
                if param_type == "PHY_INTERFACE":
                    retval = random.choice(self.tb_vars.free_ports)
                elif param_type == "VLAN_INTERFACE":
                    vid_pattern = all_params["VLAN_ID"].get("pattern", None)
                    (minv, maxv) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', vid_pattern).groups()
                    retval = "Vlan {}".format(random.randint(int(minv), int(maxv)))
                elif param_type == "PO_INTERFACE":
                    po_pattern = all_params["PO_INTERFACE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'PortChannel\(([-+]?\d+)\-([-+]?\d+)\)', po_pattern).groups()
                    retval = "PortChannel{}".format(random.randint(int(minv), int(maxv)))
                elif param_type == "LOOPBACK_INTERFACE":
                    lb_pattern = all_params["LOOPBACK_INTERFACE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'Loopback\(([-+]?\d+)\-([-+]?\d+)\)', lb_pattern).groups()
                    retval = "Loopback{}".format(random.randint(int(minv), int(maxv)))
                elif param_type == "MGMT_INTERFACE":
                    mg_pattern = all_params["MGMT_INTERFACE"].get("ext_pattern", None)
                    retval = re.sub(r"Management\(|\)", "", mg_pattern)
                    retval = "Management{}".format(retval)
                else:
                    retval = "TODO";  # TODO
            else:
                retval = "TODO"; # TODO
        else:
            if param_type == "UINT":
                if param_name.startswith("phy-if-") or param_name in ["if-id", "PLK", "ifnum", "ptp_port_number"]:
                    retval = random.choice(self.tb_vars.free_ports)
                elif param_name == "zone":
                    minv = 0
                    maxv = 3
                    retval = str(random.randint(minv, maxv))
                elif param_name == "pid-no":
                    minv = 1
                    maxv = 255
                    retval = str(random.randint(minv, maxv))
                elif param_name == "sampling-rate-val":
                    minv = 1
                    maxv = 65535
                    retval = str(random.randint(minv, maxv))
                else:
                    minv = 0
                    maxv = pow(2, 32) - 1
                    retval = str(random.randint(minv, maxv))
            elif param_type.startswith("STRING") or param_type.startswith("HOSTNAME_STR"):
                if param_name.startswith("ifId"):
                    retval = random.choice(self.tb_vars.free_ports)
                    retval = re.sub("Ethernet", "", retval)
                    return retval

                intf_names = ["phy-if-id", "interface", "interfacename", "interface-name", "intf-name", "mrouter-if-name"]
                intf_names.extend(["grp-if-name", "donor-interface", "ifname", "ifName", "ifName1", "src-phy-if-id"])
                if param_name in intf_names:
                    retval = random.choice(self.tb_vars.free_ports)
                    return retval

                if "WITH_PIPE" in param_type and param_name == "cmd":
                    retval = random.choice(["ls", "whoami", "hostname"])
                    return retval

                if param_name == "rl":
                    choices = ["admin", "operator"]
                    retval = random.choice(choices)
                    return retval

                if param_name == "date":
                    retval = get_timenow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    return retval

                if param_name in ["vrf-name"] and param_type in ["STRING", "STRING_15"]:
                    retval = "Vrf_test"
                    return retval

                vrf_string_types = ["STRING", "STRING_15", "STRING_63"]
                if param_name in ["vrfname", "vrf-name"] and param_type in vrf_string_types:
                    minLen = 1
                    maxLen = 11
                    if param_type.startswith("STRING_"):
                        maxLen = int(re.sub("STRING_", "", param_type))
                        maxLen = maxLen - 4
                    letters = string.ascii_letters + string.digits
                    stringLength = random.randint(minLen, maxLen)
                    retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    return retval

                if param_name in ["route-map-name"] and param_type in ["STRING"]:
                    param_type = "STRING_63"

                if param_name in ["session-name"] and param_type in ["STRING"]:
                    param_type = "STRING_72"

                if param_type.startswith("STRING"):
                    search_pattern = "{}_".format("STRING")
                elif param_type.startswith("HOSTNAME_STR"):
                    search_pattern = "{}_".format("HOSTNAME_STR")
                else:
                    search_pattern = "{}_".format("TODO")

                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    letters = string.ascii_letters + string.digits + '_-'
                    minLen = 1
                    maxLen = 1
                    if param_type.startswith(search_pattern):
                        lengths_part = re.sub(search_pattern, "", param_type)
                        if "_" in lengths_part:
                            min_part = lengths_part.split("_")[0]
                            max_part = lengths_part.split("_")[-1]
                        else:
                            min_part = "1"
                            max_part = lengths_part
                        try:
                            minLen = int(min_part)
                            maxLen = int(max_part)
                        except Exception:
                            pass
                    else:
                        maxLen = 64
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type.startswith("PASSWORD_STR"):
                minLen = 1
                maxLen = 64
                letters = string.ascii_letters + string.digits + '_-'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ip_address_patterns:
                min_ipv4_mask = "1"
                min_ipv6_mask = "1"
                max_ipv4_mask = "32"
                max_ipv6_mask = "128"

                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    rand_ipv4_mask = str(random.randint(int(min_ipv4_mask), int(max_ipv4_mask)))
                    rand_ipv6_mask = str(random.randint(int(min_ipv6_mask), int(max_ipv6_mask)))
                    rand_ipv4_address = '.'.join(str(random.randint(0,255)) for _ in range(4))
                    rand_ipv6_address = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(4)) for _ in range(8))

                    if "MASK" in param_type or "SUBNET" in param_type or "NETWORK" in param_type:
                        rand_ipv4_address = "{}/{}".format(rand_ipv4_address, rand_ipv4_mask)
                        rand_ipv6_address = "{}/{}".format(rand_ipv6_address, rand_ipv6_mask)

                    if "IPADDR_NN" in param_type or param_type in ["RD", "RT"]:
                        aa_nn_val = str(random.randint(0, 65535))
                        rand_ipv4_address = "{}:{}".format(rand_ipv4_address, aa_nn_val)
                        rand_ipv6_address = "{}:{}".format(rand_ipv6_address, aa_nn_val)

                    if "V6" in param_type:
                        retval = rand_ipv6_address
                    else:
                        retval = rand_ipv4_address
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["MAC_ADDR", "FBS_MAC_ADDR", "ACL_MAC_ADDR"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(2)) for _ in range(6))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["HEX_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = '0x' + ''.join(random.choice(string.hexdigits).lower() for _ in range(6))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["PTP_V6SCOPE_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = '0x' + random.choice(string.hexdigits).lower()
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["TACACS_KEY", "RADIUS_KEY"]:
                minLen = 1
                maxLen = 32
                letters = string.ascii_letters + string.digits
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["RADIUS_VRF"]:
                minLen = 1
                maxLen = 28
                letters = string.ascii_letters + string.digits
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["FILE_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    letters = string.ascii_letters
                    retval = "file://" + ''.join(random.choice(letters) for i in range(10))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["AA_NN"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = "{}:{}".format(str(random.randint(0, 65535)), str(random.randint(0, 65535)))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["KDUMP_MEMORY"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = "0M-2G:256M,2G-4G:320M,4G-8G:384M,8G-:448M"
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["AUTH_KEY_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = ''.join(random.choice(string.hexdigits).lower() for _ in range(32))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["SHA_AUTH_KEY_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = ''.join(random.choice(string.hexdigits).lower() for _ in range(40))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["ENGINE_ID_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = ''.join(random.choice(string.hexdigits).lower() for _ in range(random.randint(10, 64)))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["OID_IDENTIFIER"]:
                minLen = 1
                maxLen = 255
                letters = string.digits + '.'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["SNMP_IDENTIFIER"]:
                minLen = 1
                maxLen = 32
                letters = string.ascii_letters + string.digits + '_-'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["LINE"]:
                minLen = 1
                maxLen = 63
                letters = string.ascii_letters + string.digits + '_-'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["VLAN_RANGE"]:
                minv = 1
                maxv = 4094
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    randNum = random.randint(minv, maxv)
                    retval = randNum
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, str(each_val)):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["STR_ASN_LST"]:
                req_pattern = all_params["RANGE_1_4294967295"].get("pattern", None)
                (minv, maxv) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', req_pattern).groups()
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = random.randint(minv, maxv)
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, str(each_val)):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["VRF_NAME"]:
                minLen = 1
                maxLen = 11
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
            elif param_type in ["SFLOW_AGENT"]:
                retval = random.choice(self.tb_vars.free_ports)
            elif param_type in ["PCP_VALUE_MASK"]:
                randNum1 = random.choice(range(0,8))
                randNum2 = random.choice([i for i in range(0,8) if i not in [randNum1]])
                retval = "{}/{}".format(randNum1, randNum2)
            elif param_type in ["ETHERTYPE_VALUE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    retval = '0x1' + ''.join(random.choice(string.hexdigits).lower() for _ in range(3))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval[:-2]:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["DESCRIPTION"]:
                minLen = 1
                maxLen = 256
                letters = string.ascii_letters + string.digits + '_-'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                    try:
                        if isinstance(retval, list):
                            all_correct_values = True
                            for each_val in retval:
                                if each_val:
                                    if not re.match(pattern, each_val):
                                        all_correct_values = False
                                        break
                            if all_correct_values:
                                break
                        else:
                            if re.match(pattern, retval):
                                break
                    except Exception:
                        break
            elif param_type in ["VTEP_NAME"]:
                minLen = 1
                maxLen = 58
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                retval = 'Vtep_' + ''.join(random.choice(letters) for i in range(stringLength))
            elif param_type in ["ACL_REMARK"]:
                minLen = 1
                maxLen = 256
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                retval = ''.join(random.choice(letters) for i in range(stringLength))
            elif param_type in ["AUTH_TYPES"]:
                choices = ['password', 'cert', 'jwt', 'none']
                retval = random.choice(choices)

            # TODO: Need to do for other types such as IP, HOSTNAME , etc.

        #print("Random_value_from_clilist:", param_name, param_type, retval)
        return retval

