import re
import string
import copy
import random
import json
from spytest.logger import Logger

class UIRest(object):
    def __init__(self, logger=None, testbed_vars=None):
        self.logger = logger or Logger()
        self.tb_vars = testbed_vars

    def uirest_log(self, msg, width=120, delimiter="#", header=True, footer=True):
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

    def _uirest_get_config_mode_path_values(self, all_path_args, all_params, stepentry, replaced_mode_values):
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
                                    changed_value = self._uirest_get_valueset_for_param(all_params, path_plus_op, key, value, "path")
                                    replaced_mode_values[key] = changed_value
        except:
            pass

        #print("Updated modes - configs", replaced_mode_values)
        #import pdb; pdb.set_trace()
        return

    def _uirest_get_config_mode_data_values(self, all_data_args, all_params, stepentry, replaced_mode_values, replaced_cmd_params):
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
                                        changed_value = self._uirest_get_valueset_for_param(all_params, path_plus_op, key, type_or_upd_value, "parameter")
                                    if isinstance(changed_value, list):
                                        replaced_cmd_params[key] = changed_value
                                    else:
                                        replaced_cmd_params[key] = changed_value
        except:
            pass

        #print("Updated cmd params - configs", replaced_cmd_params)
        #import pdb; pdb.set_trace()
        return

    def _uirest_get_action_mode_arg_values(self, all_path_args, all_params, stepentry, replaced_mode_values):
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
                                    changed_value = self._uirest_get_valueset_for_param(all_params, path_plus_op, key, value, "path")
                                    replaced_mode_values[key] = changed_value
        except:
            pass

        #print("Updated modes - actions", replaced_mode_values)
        #import pdb; pdb.set_trace()
        return

    def _uirest_get_action_cmd_param_values(self, all_data_args, all_params, stepentry, replaced_mode_values, replaced_cmd_params):
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
                                        changed_value = self._uirest_get_valueset_for_param(all_params, path_plus_op, key, type_or_upd_value, "parameter")
                                    if isinstance(changed_value, list):
                                        replaced_cmd_params[key] = changed_value
                                    else:
                                        replaced_cmd_params[key] = changed_value
        except:
            pass

        #print("Updated cmd params - actions", replaced_cmd_params)
        #import pdb; pdb.set_trace()
        return

    def _uirest_get_preconfig_mode_path_values(self, all_path_args, all_params, stepentry, replaced_mode_values):
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
                                    changed_value = self._uirest_get_valueset_for_param(all_params, path_plus_op, key, value, "path")
                                    replaced_mode_values[key] = changed_value
        except:
            pass

        #print("Updated modes - pre-configs", replaced_mode_values)
        #import pdb; pdb.set_trace()
        return

    def _uirest_get_preconfig_mode_data_values(self, all_data_args, all_params, stepentry, replaced_mode_values, replaced_cmd_params):
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
                                        changed_value = self._uirest_get_valueset_for_param(all_params, path_plus_op, key, type_or_upd_value, "parameter")
                                    if isinstance(changed_value, list):
                                        replaced_cmd_params[key] = changed_value
                                    else:
                                        replaced_cmd_params[key] = changed_value
        except:
            pass

        #print("Updated cmd params - pre-configs", replaced_cmd_params)
        #import pdb; pdb.set_trace()
        return

    def _uirest_substitute_path_data_params(self, stepentry, all_data_args, all_params, replaced_mode_values, replaced_cmd_params):

        changed_steps = []

        minIndex = 0
        maxIndex = 1

        for index in range(minIndex, maxIndex):
            copied_step = copy.deepcopy(stepentry)
            no_need_to_add = False

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
                            for key, value in replaced_mode_values.items():
                                path = path.replace("{" + key + "}", str(value))

                        if data:
                            datastr = json.dumps(data)
                            for key, value in replaced_cmd_params.items():
                                if key in datastr:
                                    arg_datatype_str = all_data_args[path_plus_op][key]
                                    if "boolean" in arg_datatype_str:
                                        datastr = datastr.replace("\"{{" + key + "}}\"", value)
                                    elif "integer" in arg_datatype_str or "number" in arg_datatype_str or isinstance(value, int):
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
                            for key, value in replaced_mode_values.items():
                                path = path.replace("{" + key + "}", str(value))

                        if data:
                            datastr = json.dumps(data)
                            for key, value in replaced_cmd_params.items():
                                if key in datastr:
                                    arg_datatype_str = all_data_args[path_plus_op][key]
                                    if "boolean" in arg_datatype_str:
                                        datastr = datastr.replace("\"{{" + key + "}}\"", value)
                                    elif "integer" in arg_datatype_str or "number" in arg_datatype_str or isinstance(value, int):
                                        datastr = datastr.replace("\"{{" + key + "}}\"", str(value))
                                    else:
                                        datastr = datastr.replace("{{" + key + "}}", str(value))
                            data = json.loads(datastr)

                        # Update the step values with replaced data
                        config_step.update({"path": path})
                        config_step.update({"data": data})
                        config_step.update({"valid": cfg_valid})

                if no_need_to_add:
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
                            for key, value in replaced_mode_values.items():
                                path = path.replace("{" + key + "}", value)

                        if matches:
                            matches_str = json.dumps(matches)
                            for key, value in replaced_cmd_params.items():
                                if key in matches_str:
                                    arg_datatype_str = all_data_args[path_plus_op][key]
                                    if "boolean" in arg_datatype_str:
                                        datastr = datastr.replace("\"{{" + key + "}}\"", value)
                                    elif "integer" in arg_datatype_str or "number" in arg_datatype_str or isinstance(value, int):
                                        matches_str = matches_str.replace("\"{{" + key + "}}\"", str(value))
                                    else:
                                        matches_str = matches_str.replace("{{" + key + "}}", str(value))
                            matches = json.loads(matches_str)
                            
                        # Update the step values with replaced data
                        action_step.update({"path": path})
                        if matches:
                            action_step.update({"match": matches})
                        action_step.update({"valid": action_valid})

                if not no_need_to_add:
                    changed_steps.append(copied_step)
            except:
                pass

        #print("Changed Steps", changed_steps)
        if not changed_steps:
            changed_steps.append(copy.deepcopy(stepentry))

        #import pdb; pdb.set_trace()
        return changed_steps

    def _uirest_get_valueset_for_param(self, all_params, path_plus_op, param_name, param_type, datatype):
        retval = "TODO"

        #print("_uirest_get_valueset_for_param:", param_name, param_type)
        if isinstance(param_type, list):
            if datatype in ["path", "match"]:
                retval = random.choice(param_type)
            else:
                retval = random.choice(param_type)
        elif param_type in ["integer", "number", "double", "string", "boolean"]:
            if param_type in ["integer", "number", "double"]:
                int_vals = range(0,65536)
                if datatype in ["path", "match"]:
                    retval = random.choice(int_vals)
                else:
                    retval = random.choice(int_vals)
            elif param_type in ["string"]:
                is_interface_in_path = "interface={"+param_name+"}"
                is_ipaddress_in_path = "address={"+param_name+"}"

                mac_address_names = ["mac-address", "source-mac", "destination-mac"]

                if is_interface_in_path in path_plus_op:
                    if datatype in ["path", "match"]:
                        if self.tb_vars.connected_ports:
                            retval = self.tb_vars.connected_ports[0]
                        else:
                            retval = self.tb_vars.free_ports[0]
                    else:
                        if self.tb_vars.connected_ports:
                            retval = self.tb_vars.connected_ports[0]
                        else:
                            retval = self.tb_vars.free_ports[0]
                elif param_name in mac_address_names:
                    retval = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(2)) for _ in range(6))
                elif is_ipaddress_in_path in path_plus_op:
                    if "v6" in path_plus_op or "V6" in path_plus_op:
                        retval = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(4)) for _ in range(8))
                    else:
                        retval = '.'.join(str(random.randint(0, 255)) for _ in range(4))
                else:
                    letters = string.ascii_letters + string.digits + '_-'
                    minLen = 1
                    maxLen = 64
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
            elif param_type in ["boolean"]:
                bool_vals = ["false", "true"]
                if datatype in ["path", "match"]:
                    retval = random.choice(bool_vals)
                else:
                    retval = random.choice(bool_vals)
        elif param_type in all_params:
            #param_dict = all_params[param_type]
            retval = self._uirest_get_valueset_for_param_from_clilist(param_name, param_type, all_params, datatype)

        #print("Random_value:", retval)
        return retval

    def _uirest_get_valueset_for_param_from_clilist(self, param_name, param_type, all_params, datatype):
        retval = "TODO"

        param_dict = all_params[param_type]
        method = param_dict.get("method", None)
        pattern = param_dict.get("pattern", None)
        ip_address_patterns = ["INT_OR_IP_ADDR", "IP_ADDR", "IP_ADDR_ANY",
                               "IP_ADDR_DHCP_SUBNET", "IP_ADDR_DHCP_SUBNET_IPV4IPV6",
                               "IP_ADDR_MASK", "IPADDR_NN", "IPV4_ADDR_ABC",
                               "IPV4_IPV6_NETWORK", "IPV4_OR_IPV6_ADDR", "INT32_OR_IP_ADDR",
                               "IPV4V6_ADDR", "IPV6_ADDR", "IPV6_ADDR_MASK", "DOTTED_QUAD", "AA_NN_IPADDR_NN",
                               "HOSTNAME_OR_IPADDR", "HOSTNAME_OR_IPV4_ADDR", "RD", "RT"]

        if param_type.startswith("SPYTEST_"):
            if method in ["integer", "unsignedInteger"]:
                (min, max) = re.match(r'(\d+)\.\.(\d+)', pattern).groups()
                retval = random.randint(int(min), int(max))
            if method == "UINT" and "INTERFACE" in param_type:
                if self.tb_vars.connected_ports:
                    retval = self.tb_vars.connected_ports[0]
                else:
                    retval = self.tb_vars.free_ports[0]
                if datatype not in ["path", "match"]:
                    retval = re.sub("Ethernet", "", retval)
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
                (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', pattern).groups()
                if datatype in ["path", "match"]:
                    retval = random.randint(int(min), int(max))
                else:
                    #if min == max:
                    #    retval = [int(min), None, None, int(min)-1, int(max)+1]
                    #else:
                    #    randNum = random.randint(int(min), int(max))
                    #    retval = [int(min), int(max), randNum, int(min)-1, int(max)+1]
                    retval = random.randint(int(min), int(max))
            elif method in ["select"]:
                if "(" in pattern:
                    choices = re.findall(r"(\S+)\(\S+\)", pattern)
                else:
                    choices = re.findall(r"(\S+)", pattern)
                if datatype in ["path", "match"]:
                    retval = random.choice(choices)
                else:
                    #retval = [choices[0], choices[-1], random.choice(choices), None, None]
                    retval = random.choice(choices)
            elif method in ["regexp_select"]:
                if param_type == "PHY_INTERFACE":
                    if self.tb_vars.connected_ports:
                        retval = self.tb_vars.connected_ports[0]
                    else:
                        retval = self.tb_vars.free_ports[0]
                elif param_type == "VLAN_INTERFACE":
                    vid_pattern = all_params["VLAN_ID"].get("pattern", None)
                    (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', vid_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "Vlan {}".format(random.randint(int(min), int(max)))
                    else:
                        retval = "Vlan {}".format(random.randint(int(min), int(max)))
                elif param_type == "PO_INTERFACE":
                    po_pattern = all_params["LAG_ID"].get("pattern", None)
                    (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', po_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "PortChannel{}".format(random.randint(int(min), int(max)))
                    else:
                        retval = "PortChannel{}".format(random.randint(int(min), int(max)))
                elif param_type == "LOOPBACK_INTERFACE":
                    lb_pattern = all_params["LOOPBACK_NUM"].get("pattern", None)
                    (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', lb_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "Loopback{}".format(random.randint(int(min), int(max)))
                    else:
                        retval = "Loopback{}".format(random.randint(int(min), int(max)))
                else:
                    retval = "TODO";  # TODO
            else:
                retval = "TODO"; # TODO
        else:
            if param_type == "UINT":
                if param_name.startswith("phy-if-"):
                    if self.tb_vars.connected_ports:
                        retval = self.tb_vars.connected_ports[0]
                    else:
                        retval = self.tb_vars.free_ports[0]
                    if datatype not in ["path", "match"]:
                        retval = re.sub("Ethernet", "", retval)
                        #retval = [retval, None, None, None, None]
                elif param_name == "zone":
                    min = 0
                    max = 3
                    if datatype in ["path", "match"]:
                        retval = str(random.randint(min, max))
                    else:
                        #retval = [min, max, random.randint(min, max), min-1, max+1]
                        retval = str(random.randint(min, max))
                else:
                    min = 0
                    max = 65535
                    if datatype in ["path", "match"]:
                        retval = random.randint(min, max)
                    else:
                        #retval = [min, max, random.randint(min, max), min-1, max+1]
                        retval = random.randint(min, max)
            elif param_type.startswith("STRING") or param_type.startswith("HOSTNAME_STR"):
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
                        except:
                            pass
                    else:
                        maxLen = 64
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        #minStr = ''.join(random.choice(letters) for i in range(minLen))
                        #maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        #randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        #retval = [minStr, maxStr, randStr, None, None]
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
                    except:
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
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        #minStr = ''.join(random.choice(letters) for i in range(minLen))
                        #maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        #randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        #retval = [minStr, maxStr, randStr, None, None]
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
                    except:
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

                    if datatype in ["path", "match"]:
                        if "V6" in param_type:
                            retval = rand_ipv6_address
                        else:
                            retval = rand_ipv4_address
                    else:
                        if "V6" in param_type:
                            #retval = [None, None, rand_ipv6_address, None, None]
                            retval = rand_ipv6_address
                        else:
                            #retval = [None, None, rand_ipv4_address, None, None]
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
                    except:
                        break
            elif param_type in ["MAC_ADDR"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    rand_mac_address = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(2)) for _ in range(6))
                    if datatype in ["path", "match"]:
                        retval = rand_mac_address
                    else:
                        #retval = [None, None, rand_mac_address, None, None]
                        retval = rand_mac_address
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
                    except:
                        break
            elif param_type in ["HEX_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    min_hex_str = "0x0"
                    rand_hex_str = '0x' + ''.join(random.choice(string.hexdigits).lower() for _ in range(6))
                    max_hex_str = "0xFFFFFF"
                    invalid_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(6))
                    if datatype in ["path", "match"]:
                        retval = rand_hex_str
                    else:
                        #retval = [min_hex_str, max_hex_str, rand_hex_str, None, invalid_hex_str]
                        retval = rand_hex_str
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
                    except:
                        break
            elif param_type in ["PTP_V6SCOPE_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    min_hex_str = "0x0"
                    rand_hex_str = '0x' + random.choice(string.hexdigits).lower()
                    max_hex_str = "0xF"
                    invalid_hex_str = random.choice(string.hexdigits).lower()
                    if datatype in ["path", "match"]:
                        retval = rand_hex_str
                    else:
                        #retval = [min_hex_str, max_hex_str, rand_hex_str, None, invalid_hex_str]
                        retval = rand_hex_str
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
                    except:
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
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        #minStr = ''.join(random.choice(letters) for i in range(minLen))
                        #maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        #randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        #invalidMaxStr = ''.join(random.choice(letters) for i in range(maxLen+1))
                        #retval = [minStr, maxStr, randStr, None, invalidMaxStr]
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
                    except:
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
                    if datatype in ["path", "match"]:
                        #retval = ''.join(random.choice(letters) for i in range(stringLength))
                        retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        #minStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(minLen))
                        #maxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen))
                        #randStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                        #invalidMaxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                        #invalidMinStr = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        #retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
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
                    except:
                        break
            elif param_type == "FILE_TYPE":
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    letters = string.ascii_letters
                    randStr = "file://" + ''.join(random.choice(letters) for i in range(10))
                    if datatype in ["path", "match"]:
                        retval = randStr
                    else:
                        #retval = [None, None, randStr, None, None]
                        retval = randStr
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
                    except:
                        break
            elif param_type == "AA_NN":
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    rand_aa_nn_val = "{}:{}".format(str(random.randint(0, 65535)), str(random.randint(0, 65535)))
                    if datatype in ["path", "match"]:
                        retval = rand_aa_nn_val
                    else:
                        #retval = [None, None, rand_aa_nn_val, None, None]
                        retval = rand_aa_nn_val
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
                    except:
                        break
            elif param_type == "KDUMP_MEMORY":
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    rand_kdump_val = "0M-2G:256M,2G-4G:320M,4G-8G:384M,8G-:448M"
                    if datatype in ["path", "match"]:
                        retval = rand_kdump_val
                    else:
                        #retval = [None, None, rand_kdump_val, None, None]
                        retval = rand_kdump_val
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
                    except:
                        break
            elif param_type in ["AUTH_KEY_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    min_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(32))
                    max_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(32))
                    rand_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(32))
                    invalid_hex_str1 = ''.join(random.choice(string.hexdigits).lower() for _ in range(30))
                    invalid_hex_str2 = ''.join(random.choice(string.hexdigits).lower() for _ in range(34))
                    if datatype in ["path", "match"]:
                        retval = rand_hex_str
                    else:
                        #retval = [min_hex_str, max_hex_str, rand_hex_str, invalid_hex_str1, invalid_hex_str2]
                        retval = rand_hex_str
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
                    except:
                        break
            elif param_type in ["SHA_AUTH_KEY_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    min_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(40))
                    max_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(40))
                    rand_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(40))
                    invalid_hex_str1 = ''.join(random.choice(string.hexdigits).lower() for _ in range(38))
                    invalid_hex_str2 = ''.join(random.choice(string.hexdigits).lower() for _ in range(42))
                    if datatype in ["path", "match"]:
                        retval = rand_hex_str
                    else:
                        #retval = [min_hex_str, max_hex_str, rand_hex_str, invalid_hex_str1, invalid_hex_str2]
                        retval = rand_hex_str
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
                    except:
                        break
            elif param_type in ["ENGINE_ID_TYPE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    min_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(10))
                    max_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(64))
                    rand_hex_str = ''.join(random.choice(string.hexdigits).lower() for _ in range(random.randint(10, 64)))
                    invalid_hex_str1 = ''.join(random.choice(string.hexdigits).lower() for _ in range(9))
                    invalid_hex_str2 = ''.join(random.choice(string.hexdigits).lower() for _ in range(65))
                    if datatype in ["path", "match"]:
                        retval = rand_hex_str
                    else:
                        #retval = [min_hex_str, max_hex_str, rand_hex_str, invalid_hex_str1, invalid_hex_str2]
                        retval = rand_hex_str
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
                    except:
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
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidStr1 = ''.join(random.choice(letters) for i in range(minLen - 1))
                        invalidStr2 = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        #retval = [minStr, maxStr, randStr, invalidStr1, invalidStr2]
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
                    except:
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
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidStr1 = ''.join(random.choice(letters) for i in range(minLen - 1))
                        invalidStr2 = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        #retval = [minStr, maxStr, randStr, invalidStr1, invalidStr2]
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
                    except:
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
                    if datatype in ["path", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidStr1 = ''.join(random.choice(letters) for i in range(minLen - 1))
                        invalidStr2 = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        #retval = [minStr, maxStr, randStr, invalidStr1, invalidStr2]
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
                    except:
                        break
            elif param_type in ["VLAN_RANGE"]:
                min = 1
                max = 4094
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    randNum = random.randint(min, max)
                    if datatype in ["path", "match"]:
                        retval = randNum
                    else:
                        #retval = [min, max, randNum, min-1, max+1]
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
                    except:
                        break

            # TODO: Need to do for other types such as IP, HOSTNAME , etc.

        #print("Random_value_from_clilist:", param_name, param_type, retval)
        return retval

