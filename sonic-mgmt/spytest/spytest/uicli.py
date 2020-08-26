import re
import string
import copy
import random
import time
from spytest.logger import Logger
from spytest.st_time import get_timenow

class UICLI(object):
    def __init__(self, logger=None, testbed_vars=None, scriptname=None):
        self.logger = logger or Logger()
        self.tb_vars = testbed_vars
        self.script = scriptname

    def uicli_log(self, msg, width=120, delimiter="#", header=True, footer=True):
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

    def _uicli_get_config_mode_arg_values_dict(self, all_params, stepentry, replaced_mode_values):
        try:
            if "configs" in stepentry.keys():
                for config_step in stepentry["configs"]:
                    mode = config_step.get("mode", None)

                    if len(mode) > 1:
                        (mode_name, mode_args) = mode
                        for key, value in mode_args.items():
                            matched = re.match(r'\$(\S+)\$(\S+)\$', str(value).strip())
                            if not matched:
                                replaced_mode_values[value] = value
                                continue

                            param_data = matched.group(0)
                            param_name = matched.group(1)
                            param_type = matched.group(2)

                            if param_data not in replaced_mode_values and param_type in all_params.keys():
                                #param_dict = all_params[param_type]
                                #changed_value = self._uicli_get_random_value_for_param(param_name, param_type, param_dict, "argument")
                                changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "argument")
                                replaced_mode_values[param_data] = changed_value
        except:
            pass

        #print("Updated modes - configs", replaced_mode_values)
        #import pdb; pdb.set_trace()
        return

    def _uicli_get_config_cmd_param_values_list(self, all_params, stepentry, replaced_cmd_params):
        try:
            if "configs" in stepentry.keys():
                for config_step in stepentry["configs"]:
                    cfg_section = config_step.get("config", None)
                    if cfg_section:
                        cfg_command = cfg_section.get("command", None)

                    if cfg_section and cfg_command:
                        matched_list = re.findall(r'\$\S+\$\S+\$', str(cfg_command).strip())
                        for matched in matched_list:
                            matched_values = re.match(r'\$(\S+)\$(\S+)\$', str(matched).strip())
                            param_data = matched_values.group(0)
                            param_name = matched_values.group(1)
                            param_type = matched_values.group(2)
                            #param_data_esc = re.escape(param_data)
                            # print(param_data, param_name, param_type)

                            #import pdb; pdb.set_trace()
                            if param_data not in replaced_cmd_params and param_type in all_params.keys():
                                #param_dict = all_params[param_type]
                                #changed_value = self._uicli_get_random_value_for_param(param_name, param_type, param_dict, "parameter")
                                changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "parameter")
                                if isinstance(changed_value, list):
                                    replaced_cmd_params[param_data] = changed_value
                                else:
                                    replaced_cmd_params[param_data] = str(changed_value)
        except:
            pass

        #print("Updated cmd params - configs", replaced_cmd_params)
        #import pdb; pdb.set_trace()
        return

    def _uicli_get_action_mode_arg_values_dict(self, all_params, stepentry, replaced_mode_values):
        try:
            if "actions" in stepentry.keys():
                for action_step in stepentry["actions"]:
                    mode = action_step.get("mode", None)

                    if len(mode) > 1:
                        (mode_name, mode_args) = mode
                        for key, value in mode_args.items():
                            matched = re.match(r'\$(\S+)\$(\S+)\$', str(value).strip())
                            if not matched:
                                replaced_mode_values[value] = value
                                continue

                            param_data = matched.group(0)
                            param_name = matched.group(1)
                            param_type = matched.group(2)

                            if param_data not in replaced_mode_values and param_type in all_params.keys():
                                #param_dict = all_params[param_type]
                                #changed_value = self._uicli_get_random_value_for_param(param_name, param_type, param_dict, "argument")
                                changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "argument")
                                replaced_mode_values[param_data] = changed_value
        except:
            pass

        #print("Updated modes - actions", replaced_mode_values)
        #import pdb; pdb.set_trace()
        return

    def _uicli_get_action_cmd_param_values_list(self, all_params, stepentry, replaced_cmd_params):
        try:
            if "actions" in stepentry.keys():
                for action_step in stepentry["actions"]:
                    action_section = action_step.get("action", None)
                    if action_section:
                        action_command = action_section.get("command", None)

                    if action_section and action_command:
                        matched_list = re.findall(r'\$\S+\$\S+\$', str(action_command).strip())
                        for matched in matched_list:
                            matched_values = re.match(r'\$(\S+)\$(\S+)\$', str(matched).strip())
                            param_data = matched_values.group(0)
                            param_name = matched_values.group(1)
                            param_type = matched_values.group(2)
                            #param_data_esc = re.escape(param_data)
                            # print(param_data, param_name, param_type)

                            # import pdb; pdb.set_trace()
                            if param_data not in replaced_cmd_params and param_type in all_params.keys():
                                #param_dict = all_params[param_type]
                                #changed_value = self._uicli_get_random_value_for_param(param_name, param_type, param_dict, "parameter")
                                changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "parameter")
                                if isinstance(changed_value, list):
                                    replaced_cmd_params[param_data] = changed_value
                                else:
                                    replaced_cmd_params[param_data] = str(changed_value)
        except:
            pass

        #print("Updated cmd params - actions", replaced_cmd_params)
        #import pdb; pdb.set_trace()
        return

    def _uicli_get_preconfig_mode_arg_values_dict(self, all_params, stepentry, replaced_mode_values):
        try:
            if "pre-configs" in stepentry.keys():
                for config_step in stepentry["pre-configs"]:
                    mode = config_step.get("mode", None)

                    if len(mode) > 1:
                        (mode_name, mode_args) = mode
                        for key, value in mode_args.items():
                            matched = re.match(r'\$(\S+)\$(\S+)\$', str(value).strip())
                            if not matched:
                                replaced_mode_values[value] = value
                                continue

                            param_data = matched.group(0)
                            param_name = matched.group(1)
                            param_type = matched.group(2)

                            if param_data not in replaced_mode_values and param_type in all_params.keys():
                                #param_dict = all_params[param_type]
                                #changed_value = self._uicli_get_random_value_for_param(param_name, param_type, param_dict, "argument")
                                changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "argument")
                                replaced_mode_values[param_data] = changed_value
        except:
            pass

        #print("Updated modes - pre-configs", replaced_mode_values)
        #import pdb; pdb.set_trace()
        return

    def _uicli_get_preconfig_cmd_param_values_list(self, all_params, stepentry, replaced_cmd_params):
        try:
            if "pre-configs" in stepentry.keys():
                for config_step in stepentry["pre-configs"]:
                    cfg_section = config_step.get("pre-config", None)
                    if cfg_section:
                        cfg_command = cfg_section.get("command", None)

                    if cfg_section and cfg_command:
                        matched_list = re.findall(r'\$\S+\$\S+\$', str(cfg_command).strip())
                        for matched in matched_list:
                            matched_values = re.match(r'\$(\S+)\$(\S+)\$', str(matched).strip())
                            param_data = matched_values.group(0)
                            param_name = matched_values.group(1)
                            param_type = matched_values.group(2)
                            #param_data_esc = re.escape(param_data)
                            # print(param_data, param_name, param_type)

                            #import pdb; pdb.set_trace()
                            if param_data not in replaced_cmd_params and param_type in all_params.keys():
                                #param_dict = all_params[param_type]
                                #changed_value = self._uicli_get_random_value_for_param(param_name, param_type, param_dict, "parameter")
                                changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "parameter")
                                if isinstance(changed_value, list):
                                    replaced_cmd_params[param_data] = changed_value
                                else:
                                    replaced_cmd_params[param_data] = str(changed_value)
        except:
            pass

        #print("Updated cmd params - pre-configs", replaced_cmd_params)
        #import pdb; pdb.set_trace()
        return

    def _uicli_substitute_args_params(self, all_params, stepentry, replaced_mode_values, replaced_cmd_params):

        changed_steps = []
        curr_cfg_cmds_list = []
        curr_precfg_cmds_list = []

        minIndex = 0
        maxIndex = 5

        for index in range(minIndex, maxIndex):
            copied_step = copy.deepcopy(stepentry)
            no_need_to_add = False

            try:
                if "pre-configs" in copied_step.keys():
                    for preconfig_step in copied_step["pre-configs"]:
                        cfg_mode = preconfig_step.get("mode", None)
                        cfg_section = preconfig_step.get("pre-config", None)
                        cfg_valid = preconfig_step.get("valid", 1)
                        if index > 2:
                            cfg_valid = int(not cfg_valid)

                        if cfg_section:
                            cfg_command = cfg_section.get("command", None)

                        # Replace the mode values in arg strings
                        if len(cfg_mode) > 1:
                            (mode_name, mode_args) = cfg_mode
                            for key, value in mode_args.items():
                                if replaced_mode_values.get(value, None) is not None:
                                    mode_args.update({key: replaced_mode_values.get(value)})

                        if cfg_section and cfg_command:
                            if not replaced_cmd_params:
                                if cfg_command not in curr_precfg_cmds_list:
                                    curr_precfg_cmds_list.append(cfg_command)
                            for param_data in replaced_cmd_params.keys():
                                param_data_esc = re.escape(param_data)
                                replace_with = replaced_cmd_params.get(param_data)[index]
                                if replace_with is not None:
                                    replace_with = str(replace_with)
                                    cfg_command = re.sub(param_data_esc, replace_with, cfg_command)
                                    if cfg_command not in curr_precfg_cmds_list:
                                        curr_precfg_cmds_list.append(cfg_command)

                        # Update the step values with replaced data
                        preconfig_step.update({"mode": cfg_mode})
                        cfg_section.update({"command": cfg_command})
                        cfg_section.update({"valid": cfg_valid})

                if "configs" in copied_step.keys():
                    for config_step in copied_step["configs"]:
                        cfg_mode = config_step.get("mode", None)
                        cfg_section = config_step.get("config", None)
                        cfg_valid = config_step.get("valid", 1)
                        if index > 2:
                            cfg_valid = int(not cfg_valid)

                        if cfg_section:
                            cfg_command = cfg_section.get("command", None)

                        # Replace the mode values in arg strings
                        if len(cfg_mode) > 1:
                            (mode_name, mode_args) = cfg_mode
                            for key, value in mode_args.items():
                                if replaced_mode_values.get(value, None) is not None:
                                    mode_args.update({key: replaced_mode_values.get(value)})

                        if cfg_section and cfg_command:
                            for param_data in replaced_cmd_params.keys():
                                param_data_esc = re.escape(param_data)
                                replace_with = replaced_cmd_params.get(param_data)[index]
                                if replace_with is not None:
                                    replace_with = str(replace_with)
                                    cfg_command = re.sub(param_data_esc, replace_with, cfg_command)
                                else:
                                    no_need_to_add = True
                            if not replaced_cmd_params:
                                if cfg_command not in curr_cfg_cmds_list:
                                    curr_cfg_cmds_list.append(cfg_command)
                                else:
                                    no_need_to_add = True
                            elif not no_need_to_add:
                                if cfg_command not in curr_cfg_cmds_list:
                                    curr_cfg_cmds_list.append(cfg_command)
                                else:
                                    no_need_to_add = True

                        # Update the step values with replaced data
                        config_step.update({"mode": cfg_mode})
                        cfg_section.update({"command": cfg_command})
                        cfg_section.update({"valid": cfg_valid})

                if no_need_to_add:
                    continue

                if "actions" in copied_step.keys():
                    for action_step in copied_step["actions"]:
                        action_mode = action_step.get("mode", None)
                        action_section = action_step.get("action", None)
                        action_valid = action_step.get("valid", 1)
                        if index > 2:
                            action_valid = int(not action_valid)

                        if action_section:
                            action_command = action_section.get("command", None)
                            action_matches = action_section.get("match", None)

                        # Replace the mode values in arg strings
                        if len(action_mode) > 1:
                            (mode_name, mode_args) = action_mode
                            for key, value in mode_args.items():
                                if replaced_mode_values.get(value, None) is not None:
                                    mode_args.update({key: replaced_mode_values.get(value)})

                        if action_section and action_command:
                            for param_data in replaced_cmd_params.keys():
                                param_data_esc = re.escape(param_data)
                                replace_with = replaced_cmd_params.get(param_data)[index]
                                if replace_with is not None:
                                    replace_with = str(replace_with)
                                    action_command = re.sub(param_data_esc, replace_with, action_command)
                                else:
                                    no_need_to_add = True

                        # Substitute the param values in match values.
                        for match_dict in action_matches:
                            for key, value in match_dict.items():
                                if value in replaced_mode_values:
                                    changed_value = replaced_mode_values[value]
                                elif value in replaced_cmd_params:
                                    changed_value = replaced_cmd_params[value][index]
                                else:
                                    matched = re.match(r'\$(\S+)\$(\S+)\$', str(value).strip())
                                    if matched:
                                        param_data = matched.group(0)
                                        param_name = matched.group(1)
                                        param_type = matched.group(2)
                                        #param_dict = all_params[param_type]
                                        changed_value = self._uicli_get_valueset_for_param(param_name, param_type, all_params, "match")
                                    else:
                                        changed_value = value
                                match_dict.update({key: str(changed_value)})

                        action_step.update({"mode": action_mode})
                        action_section.update({"command": action_command})
                        if action_matches:
                            action_section.update({"match": action_matches})
                        action_section.update({"valid": action_valid})

                if not no_need_to_add:
                    changed_steps.append(copied_step)
            except:
                pass

        #print("Changed Steps", changed_steps)
        if not changed_steps:
            changed_steps.append(copy.deepcopy(stepentry))

        #import pdb; pdb.set_trace()
        return changed_steps

    def _uicli_get_valueset_for_param(self, param_name, param_type, all_params, datatype):
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
            if param_name == "bgp_instance":
                retval = 1
                return retval

            if param_name == "bgp_vrf_name":
                retval = "Vrf_test"
                #minLen = 1
                #maxLen = 28
                #letters = string.ascii_letters + string.digits
                #stringLength = random.randint(minLen, maxLen)
                #retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                return retval

            if method in ["integer", "unsignedInteger"]:
                (min, max) = re.match(r'(\d+)\.\.(\d+)', pattern).groups()
                retval = random.randint(int(min), int(max))
            if method == "UINT" and "INTERFACE" in param_type:
                if self.tb_vars.connected_ports:
                    retval = self.tb_vars.connected_ports[0]
                else:
                    retval = self.tb_vars.free_ports[0]
                if datatype not in ["argument", "match"]:
                    retval = re.sub("Ethernet", "", retval)
            if method in ["select"]:
                choices = re.findall(r"(\S+)\(\S+\)", pattern)
                retval = random.choice(choices)
            if method == "string":
                while True:
                    letters = string.ascii_letters + string.digits + '_-'
                    minLen = 1
                    maxLen = 512
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
                    if datatype in ["argument", "match"]:
                        retval = 1
                    else:
                        retval = [1, 1, 1, None, None]
                    return retval

                (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', pattern).groups()
                if datatype in ["argument", "match"]:
                    retval = random.randint(int(min), int(max))
                else:
                    if min == max:
                        retval = [int(min), None, None, int(min)-1, int(max)+1]
                    else:
                        #retval = random.randint(int(min), int(max))
                        randNum = random.randint(int(min), int(max))
                        retval = [int(min), int(max), randNum, int(min)-1, int(max)+1]
                        #retval = [int(min), int(max), random.randint(int(min), int(max))]
            elif method in ["select"]:
                if "(" in pattern:
                    choices = re.findall(r"(\S+)\(\S+\)", pattern)
                else:
                    choices = re.findall(r"(\S+)", pattern)
                if datatype in ["argument", "match"]:
                    retval = random.choice(choices)
                else:
                    #retval = random.choice(choices)
                    retval = [choices[0], choices[-1], random.choice(choices), None, None]
                    #retval = [choices[0], choices[-1], random.choice(choices)]
            elif method in ["regexp_select"]:
                if param_type == "PHY_INTERFACE":
                    if self.tb_vars.connected_ports:
                        retval = self.tb_vars.connected_ports[0]
                    else:
                        retval = self.tb_vars.free_ports[0]
                    if datatype not in ["argument", "match"]:
                        retval = re.sub("Ethernet", "Ethernet ", retval)
                        retval = [retval, retval, retval, None, None]
                elif param_type == "VLAN_INTERFACE":
                    vid_pattern = all_params["VLAN_ID"].get("pattern", None)
                    (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', vid_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "Vlan {}".format(random.randint(int(min), int(max)))
                    else:
                        randNum = random.randint(int(min), int(max))
                        retval = [int(min), int(max), randNum, int(min) - 1, int(max) + 1]
                        retval = ["Vlan " + str(ele) for ele in retval]
                else:
                    retval = "TODO";  # TODO
            else:
                retval = "TODO"; # TODO
        else:
            if param_type == "UINT":
                if param_name.startswith("phy-if-") or param_name in ["if-id", "PLK", "ifnum", "ptp_port_number"]:
                    if self.tb_vars.connected_ports:
                        retval = self.tb_vars.connected_ports[0]
                    else:
                        retval = self.tb_vars.free_ports[0]
                    if datatype not in ["argument", "match"]:
                        retval = re.sub("Ethernet", "", retval)
                        retval = [retval, retval, retval, None, None]
                elif param_name == "zone":
                    #retval = str(random.randint(0, 255))
                    min = 0
                    max = 3
                    if datatype in ["argument", "match"]:
                        retval = str(random.randint(min, max))
                    else:
                        #retval = str(random.randint(min, max))
                        retval = [min, max, random.randint(min, max), min-1, max+1]
                        #retval = [min, max, random.randint(min, max)]
                else:
                    #retval = str(random.randint(0, 65535))
                    min = 0
                    max = pow(2, 32) - 1
                    if datatype in ["argument", "match"]:
                        retval = str(random.randint(min, max))
                    else:
                        #retval = str(random.randint(min, max))
                        retval = [min, max, random.randint(min, max), min-1, max+1]
                        #retval = [min, max, random.randint(min, max)]
            elif param_type.startswith("STRING") or param_type.startswith("HOSTNAME_STR"):
                if param_name.startswith("ifId"):
                    if self.tb_vars.connected_ports:
                        retval = self.tb_vars.connected_ports[0]
                    else:
                        retval = self.tb_vars.free_ports[0]
                    retval = re.sub("Ethernet", "", retval)
                    if datatype not in ["argument", "match"]:
                        retval = [retval, retval, retval, None, None]
                    return retval

                intf_names = ["phy-if-id", "interface", "interfacename", "interface-name", "intf-name", "mrouter-if-name", "grp-if-name", "donor-interface", "ifname", "ifName", "ifName1"]
                if param_name in intf_names:
                    if self.tb_vars.connected_ports:
                        retval = self.tb_vars.connected_ports[0]
                    else:
                        retval = self.tb_vars.free_ports[0]
                    if datatype not in ["argument", "match"]:
                        retval = [retval, retval, retval, None, None]
                    return retval

                if "WITH_PIPE" in param_type and param_name == "cmd":
                    retval = random.choice(["ls", "whoami", "hostname"])
                    if datatype not in ["argument", "match"]:
                        retval = [retval, None, None, None, None]
                    return retval

                if param_name == "rl":
                    choices = ["admin", "operator"]
                    if datatype in ["argument", "match"]:
                        retval = random.choice(choices)
                    else:
                        retval = [choices[0], choices[-1], random.choice(choices), None, None]
                    return retval

                if param_name == "date":
                    valid_val = get_timenow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    invalid_val = get_timenow().strftime("%Y-%m-%dT%H:%M:%S")
                    time.sleep(1)
                    retval = valid_val
                    if datatype not in ["argument", "match"]:
                        retval = [valid_val, None, None, None, invalid_val]
                    return retval

                if param_name in ["vrf-name"] and param_type in ["STRING", "STRING_15"] and self.script in ["bgp"]:
                    if datatype in ["argument", "match"]:
                        retval = "Vrf_test"
                    else:
                        retval = ["Vrf_test", "Vrf_test", "Vrf_test", None, None]
                    return retval

                vrf_string_types = ["STRING", "STRING_15", "STRING_63"]
                if param_name in ["vrfname"] and param_type in vrf_string_types:
                    minLen = 1
                    maxLen = 28
                    if param_type.startswith("STRING_"):
                        maxLen = int(re.sub("STRING_", "", param_type))
                    letters = string.ascii_letters + string.digits
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        #retval = ''.join(random.choice(letters) for i in range(stringLength))
                        retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                        invalidMaxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                        invalidMinStr = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
                    return retval

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
                        maxLen = 512
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        #retval = ''.join(random.choice(letters) for i in range(stringLength))
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        retval = [minStr, maxStr, randStr, None, None]
                        #retval = [minStr, maxStr, randStr]
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
                maxLen = 512
                letters = string.ascii_letters + string.digits + '_-'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        retval = [minStr, maxStr, randStr, None, None]
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
                #min_ipv4_address = "0.0.0.0"
                #min_ipv6_address = "0:0:0:0:0:0:0:0"; #"::"
                #max_ipv4_address = "255.255.255.255"
                #max_ipv6_address = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"

                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    rand_ipv4_mask = str(random.randint(int(min_ipv4_mask), int(max_ipv4_mask)))
                    rand_ipv6_mask = str(random.randint(int(min_ipv6_mask), int(max_ipv6_mask)))
                    rand_ipv4_address = '.'.join(str(random.randint(0,255)) for _ in range(4))
                    rand_ipv6_address = ':'.join(''.join(random.choice(string.hexdigits).lower() for _ in range(4)) for _ in range(8))

                    if "MASK" in param_type or "SUBNET" in param_type or "NETWORK" in param_type:
                        # min_ipv4_address = "{}/{}".format(min_ipv4_address, min_ipv4_mask)
                        # max_ipv4_address = "{}/{}".format(max_ipv4_address, max_ipv4_mask)
                        # min_ipv6_address = "{}/{}".format(min_ipv6_address, min_ipv6_mask)
                        # max_ipv6_address = "{}/{}".format(max_ipv6_address, max_ipv6_mask)
                        rand_ipv4_address = "{}/{}".format(rand_ipv4_address, rand_ipv4_mask)
                        rand_ipv6_address = "{}/{}".format(rand_ipv6_address, rand_ipv6_mask)

                    if "IPADDR_NN" in param_type or param_type in ["RD", "RT"]:
                        aa_nn_val = str(random.randint(0, 65535))
                        rand_ipv4_address = "{}:{}".format(rand_ipv4_address, aa_nn_val)
                        rand_ipv6_address = "{}:{}".format(rand_ipv6_address, aa_nn_val)

                    if datatype in ["argument", "match"]:
                        if "V6" in param_type:
                            retval = rand_ipv6_address
                        else:
                            retval = rand_ipv4_address
                    else:
                        if "V6" in param_type:
                            #retval = [min_ipv6_address, max_ipv6_address, rand_ipv6_address, None, None]
                            retval = [None, None, rand_ipv6_address, None, None]
                        else:
                            #retval = [min_ipv4_address, max_ipv4_address, rand_ipv4_address, None, None]
                            retval = [None, None, rand_ipv4_address, None, None]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_mac_address
                    else:
                        retval = [None, None, rand_mac_address, None, None]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_hex_str
                    else:
                        retval = [min_hex_str, max_hex_str, rand_hex_str, None, invalid_hex_str]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_hex_str
                    else:
                        retval = [min_hex_str, max_hex_str, rand_hex_str, None, invalid_hex_str]
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
                maxLen = 65
                letters = string.ascii_letters + string.digits
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidMaxStr = ''.join(random.choice(letters) for i in range(maxLen+1))
                        retval = [minStr, maxStr, randStr, None, invalidMaxStr]
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
                    if datatype in ["argument", "match"]:
                        #retval = ''.join(random.choice(letters) for i in range(stringLength))
                        retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                        invalidMaxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                        invalidMinStr = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
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
                    if datatype in ["argument", "match"]:
                        retval = randStr
                    else:
                        retval = [None, None, randStr, None, None]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_aa_nn_val
                    else:
                        retval = [None, None, rand_aa_nn_val, None, None]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_kdump_val
                    else:
                        retval = [None, None, rand_kdump_val, None, None]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_hex_str
                    else:
                        retval = [min_hex_str, max_hex_str, rand_hex_str, invalid_hex_str1, invalid_hex_str2]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_hex_str
                    else:
                        retval = [min_hex_str, max_hex_str, rand_hex_str, invalid_hex_str1, invalid_hex_str2]
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
                    if datatype in ["argument", "match"]:
                        retval = rand_hex_str
                    else:
                        retval = [min_hex_str, max_hex_str, rand_hex_str, invalid_hex_str1, invalid_hex_str2]
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
                    if datatype in ["argument", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidStr1 = ''.join(random.choice(letters) for i in range(minLen - 1))
                        invalidStr2 = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        retval = [minStr, maxStr, randStr, invalidStr1, invalidStr2]
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
                    if datatype in ["argument", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidStr1 = ''.join(random.choice(letters) for i in range(minLen - 1))
                        invalidStr2 = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        retval = [minStr, maxStr, randStr, invalidStr1, invalidStr2]
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
                maxLen = 512
                letters = string.ascii_letters + string.digits + '_-'
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        retval = ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = ''.join(random.choice(letters) for i in range(stringLength))
                        invalidStr1 = ''.join(random.choice(letters) for i in range(minLen - 1))
                        invalidStr2 = ''.join(random.choice(letters) for i in range(maxLen + 1))
                        retval = [minStr, maxStr, randStr, invalidStr1, invalidStr2]
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
                    if datatype in ["argument", "match"]:
                        retval = randNum
                    else:
                        retval = [min, max, randNum, min-1, max+1]
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
            elif param_type in ["STR_ASN_LST"]:
                req_pattern = all_params["RANGE_1_4294967295"].get("pattern", None)
                (min, max) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', req_pattern).groups()
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    randNum = random.randint(min, max)
                    if datatype in ["argument", "match"]:
                        retval = randNum
                    else:
                        retval = [min, max, randNum, min-1, max+1]
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

        #print("Random_value:", retval)
        return retval

