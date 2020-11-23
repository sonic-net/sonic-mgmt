import re
import string
import copy
import random
import time
from spytest.logger import Logger
from spytest.st_time import get_timenow
import spytest.env as env

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
                        (_, mode_args) = mode
                        for _, value in mode_args.items():
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
        except Exception:
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
        except Exception:
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
                        (_, mode_args) = mode
                        for _, value in mode_args.items():
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
        except Exception:
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
        except Exception:
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
                        (_, mode_args) = mode
                        for _, value in mode_args.items():
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
        except Exception:
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
        except Exception:
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
        if env.get("SPYTEST_UI_POSITIVE_CASES_ONLY", "0") != "0":
            maxIndex = 3

        for index in range(minIndex, maxIndex):
            copied_step = copy.deepcopy(stepentry)
            no_need_to_add = False

            try:
                if "pre-configs" in copied_step.keys():
                    for preconfig_step in copied_step["pre-configs"]:
                        cfg_mode = preconfig_step.get("mode", None)
                        cfg_section = preconfig_step.get("pre-config", None)
                        cfg_valid = cfg_section.get("valid", 1)
                        if index > 2:
                            cfg_valid = int(not cfg_valid)

                        if cfg_section:
                            cfg_command = cfg_section.get("command", None)

                        # Replace the mode values in arg strings
                        if len(cfg_mode) > 1:
                            (_, mode_args) = cfg_mode
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
                        cfg_valid = cfg_section.get("valid", 1)
                        if index > 2:
                            cfg_valid = int(not cfg_valid)

                        if cfg_section:
                            cfg_command = cfg_section.get("command", None)

                        # Replace the mode values in arg strings
                        if len(cfg_mode) > 1:
                            (_, mode_args) = cfg_mode
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
                        action_valid = action_section.get("valid", 1)
                        if index > 2:
                            action_valid = int(not action_valid)

                        if action_section:
                            action_command = action_section.get("command", None)
                            action_matches = action_section.get("match", None)

                        # Replace the mode values in arg strings
                        if len(action_mode) > 1:
                            (_, mode_args) = action_mode
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
                        if action_matches:
                            for match_dict in action_matches:
                                for key, value in match_dict.items():
                                    if value in replaced_mode_values:
                                        changed_value = replaced_mode_values[value]
                                    elif value in replaced_cmd_params:
                                        changed_value = replaced_cmd_params[value][index]
                                    else:
                                        matched = re.match(r'\$(\S+)\$(\S+)\$', str(value).strip())
                                        if matched:
                                            #param_data = matched.group(0)
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
            except Exception:
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
        ip_address_patterns = ["INT_OR_IP_ADDR", "IP_ADDR", "IP_ADDR_ANY", "IP_ADDR_DHCP_SUBNET", "IP_ADDR_MASK",
                               "IP_ADDR_DHCP_SUBNET_IPV4IPV6", "IPADDR_NN", "IPV4_ADDR_ABC", "IPV4_IPV6_NETWORK",
                               "IPV4_OR_IPV6_ADDR", "INT32_OR_IP_ADDR", "IPV4V6_ADDR", "IPV6_ADDR", "IPV6_ADDR_MASK",
                               "DOTTED_QUAD", "AA_NN_IPADDR_NN", "HOSTNAME_OR_IPADDR", "HOSTNAME_OR_IPV4_ADDR",
                               "RD", "RT", "OSPF_INT_OR_IP_ADDR", "AREA_NUM_DOT", "LDAP_HOSTNAME_OR_IPADDR", "DOMAIN_NAME_OR_IPADDR"]

        dot_start_patterns = ["BASE_DN", "BIND_DN", "BIND_PW", "PAM_FILTER", "PAM_LOGIN_ATTR", "PAM_GRP_DN",
                              "PAM_MEM_ATTR", "SUDOERS_BASE", "NSS_BASE_PWD", "NSS_BASE_GRP", "NSS_BASE_SHADOW",
                              "NSS_BASE_NETGRP", "NSS_BASE_SUDOERS", "NSS_INITGRP", "ATTR_FROM", "ATTR_TO",
                              "OBJ_FROM", "OBJ_TO", "DEFAULT_FROM", "DEFAULT_TO", "OVERRIDE_FROM", "OVERRIDE_TO"]

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
                if ".." in pattern:
                    (minv, maxv) = re.match(r'(\d+)\.\.(\d+)', pattern).groups()
                if "|" in pattern:
                    (minv, maxv) = re.match(r'\(\s*\[(\d)\]\s*\|\s*\[(\d)\]\s*\)', pattern).groups()
                retval = random.randint(int(minv), int(maxv))
            if method == "UINT" and "INTERFACE" in param_type:
                retval = random.choice(self.tb_vars.free_ports)
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

                #(minv, maxv) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', pattern).groups()
                if ".." in pattern:
                    (minv, maxv) = re.match(r'([-+]?\d+)\.\.([-+]?\d+)', pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = random.randint(int(minv), int(maxv))
                    else:
                        if minv == maxv:
                            retval = [int(minv), None, None, int(minv)-1, int(maxv)+1]
                        else:
                            randNum = random.randint(int(minv), int(maxv))
                            retval = [int(minv), int(maxv), randNum, int(minv)-1, int(maxv)+1]
                if "|" in pattern:
                    (minv, maxv) = re.match(r'\(\s*\[(\d)\]\s*\|\s*\[(\d)\]\s*\)', pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = random.choice([int(minv), int(maxv)])
                    else:
                        if minv == maxv:
                            retval = [int(minv), None, None, int(minv)-1, int(maxv)+1]
                        else:
                            randNum = random.choice([int(minv), int(maxv)])
                            retval = [int(minv), int(maxv), randNum, int(minv)-1, int(maxv)+1]
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
                if datatype in ["argument", "match"]:
                    retval = random.choice(choices)
                else:
                    retval = [choices[0], choices[-1], random.choice(choices), None, None]
            elif method in ["regexp_select"]:
                if param_type in ["PHY_VL_PO_INTERFACE"]:
                    param_type = random.choice(["PHY_INTERFACE", "VLAN_INTERFACE", "PO_INTERFACE"])
                if param_type in ["PHY_VL_PO_LB_INTERFACE", "PHY_LB_PO_VL_INTERFACE"]:
                    param_type = random.choice(["PHY_INTERFACE", "VLAN_INTERFACE", "PO_INTERFACE", "LOOPBACK_INTERFACE"])

                if param_type in ["PHY_INTERFACE", "PHY_INTERFACE_ALL"]:
                    retval = random.choice(self.tb_vars.free_ports)
                    if datatype not in ["argument", "match"]:
                        retval = re.sub("Ethernet", "Ethernet ", retval)
                        retval = [retval, retval, retval, None, None]
                elif param_type in ["VLAN_INTERFACE"]:
                    vid_pattern = all_params["VLAN_INTERFACE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'Vlan\(([-+]?\d+)\.\.([-+]?\d+)\)', vid_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "Vlan {}".format(random.randint(int(minv), int(maxv)))
                    else:
                        randNum = random.randint(int(minv), int(maxv))
                        retval = [int(minv), int(maxv), randNum, int(minv) - 1, int(maxv) + 1]
                        retval = ["Vlan " + str(ele) for ele in retval]
                elif param_type in ["PO_INTERFACE"]:
                    po_pattern = all_params["PO_INTERFACE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'PortChannel\(([-+]?\d+)\.\.([-+]?\d+)\)', po_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "PortChannel {}".format(random.randint(int(minv), int(maxv)))
                    else:
                        randNum = random.randint(int(minv), int(maxv))
                        retval = [int(minv), int(maxv), randNum, int(minv) - 1, int(maxv) + 1]
                        retval = ["PortChannel " + str(ele) for ele in retval]
                elif param_type in ["LOOPBACK_INTERFACE"]:
                    lb_pattern = all_params["LOOPBACK_INTERFACE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'Loopback\(([-+]?\d+)\.\.([-+]?\d+)\)', lb_pattern).groups()
                    if datatype in ["argument", "match"]:
                        retval = "Loopback {}".format(random.randint(int(minv), int(maxv)))
                    else:
                        randNum = random.randint(int(minv), int(maxv))
                        retval = [int(minv), int(maxv), randNum, int(minv) - 1, int(maxv) + 1]
                        retval = ["Loopback " + str(ele) for ele in retval]
                elif param_type in ["MGMT_INTERFACE"]:
                    mg_pattern = all_params["MGMT_INTERFACE"].get("ext_pattern", None)
                    retval = re.sub(r"Management\(|\)", "", mg_pattern)
                    if datatype in ["argument", "match"]:
                        retval = "Management {}".format(retval)
                    else:
                        retval = [int(retval), int(retval), int(retval), int(retval) - 1, int(retval) + 1]
                        retval = ["Management " + str(ele) for ele in retval]
                elif param_type in ["ETHER_INTERFACE_RANGE"]:
                    randMinPortVal = re.sub("Ethernet", "", random.choice(self.tb_vars.free_ports))
                    randMaxPortVal = re.sub("Ethernet", "", random.choice(self.tb_vars.free_ports))
                    rangevals = [randMinPortVal, randMaxPortVal]
                    rangevals.sort()
                    minPortNum = rangevals[0]
                    maxPortNum = rangevals[-1]
                    if datatype in ["argument", "match"]:
                        retval = "Ethernet {}".format("-".join(map(str, rangevals)))
                    else:
                        rangevals = [randMinPortVal, randMaxPortVal]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [minPortNum, minPortNum]))
                        maxVal = "-".join(map(str, [minPortNum, maxPortNum]))
                        retval = [minVal, maxVal, randNum, None, None]
                        retval = ["Ethernet " + str(ele) for ele in retval]
                elif param_type in ["VLAN_INTERFACE_RANGE"]:
                    vid_pattern = all_params["VLAN_INTERFACE_RANGE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'Vlan\(([-+]?\d+)\.\.([-+]?\d+)\)', vid_pattern).groups()
                    if datatype in ["argument", "match"]:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        retval = "Vlan {}".format("-".join(map(str, rangevals)))
                    else:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [int(minv), int(minv)]))
                        maxVal = "-".join(map(str, [int(minv), int(maxv)]))
                        inValidMinVal = "-".join(map(str, [int(minv) - 1, int(minv)]))
                        inValidMaxVal = "-".join(map(str, [int(minv), int(maxv) + 1]))
                        retval = [minVal, maxVal, randNum, inValidMinVal, inValidMaxVal]
                        retval = ["Vlan " + str(ele) for ele in retval]
                elif param_type in ["PO_INTERFACE_RANGE"]:
                    po_pattern = all_params["PO_INTERFACE_RANGE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'PortChannel\(([-+]?\d+)\.\.([-+]?\d+)\)', po_pattern).groups()
                    if datatype in ["argument", "match"]:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        retval = "PortChannel {}".format("-".join(map(str, rangevals)))
                    else:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [int(minv), int(minv)]))
                        maxVal = "-".join(map(str, [int(minv), int(maxv)]))
                        inValidMinVal = "-".join(map(str, [int(minv) - 1, int(minv)]))
                        inValidMaxVal = "-".join(map(str, [int(minv), int(maxv) + 1]))
                        retval = [minVal, maxVal, randNum, inValidMinVal, inValidMaxVal]
                        retval = ["PortChannel " + str(ele) for ele in retval]
                elif param_type in ["ETHER_RANGE"]:
                    randMinPortVal = re.sub("Ethernet", "", random.choice(self.tb_vars.free_ports))
                    randMaxPortVal = re.sub("Ethernet", "", random.choice(self.tb_vars.free_ports))
                    rangevals = [randMinPortVal, randMaxPortVal]
                    rangevals.sort()
                    minPortNum = rangevals[0]
                    maxPortNum = rangevals[-1]
                    if datatype in ["argument", "match"]:
                        retval = "-".join(map(str, rangevals))
                    else:
                        rangevals = [randMinPortVal, randMaxPortVal]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [minPortNum, minPortNum]))
                        maxVal = "-".join(map(str, [minPortNum, maxPortNum]))
                        retval = [minVal, maxVal, randNum, None, None]
                elif param_type in ["PO_RANGE"]:
                    po_pattern = all_params["PO_RANGE"].get("ext_pattern", None)
                    (minv, maxv) = re.match(r'\(([-+]?\d+)\.\.([-+]?\d+)\)', po_pattern).groups()
                    if datatype in ["argument", "match"]:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        retval = "-".join(map(str, rangevals))
                    else:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [int(minv), int(minv)]))
                        maxVal = "-".join(map(str, [int(minv), int(maxv)]))
                        inValidMinVal = "-".join(map(str, [int(minv) - 1, int(minv)]))
                        inValidMaxVal = "-".join(map(str, [int(minv), int(maxv) + 1]))
                        retval = [minVal, maxVal, randNum, inValidMinVal, inValidMaxVal]
                elif param_type in ["ETH_PHY_SLOT_PORT_SUBPORT"]:
                    retval = random.choice(self.tb_vars.free_port_alias)
                    if datatype not in ["argument", "match"]:
                        retval = re.sub("Eth", "", retval)
                        retval = [retval, retval, retval, None, None]
                elif param_type in ["ETH_RANGE_PHY_SLOT_PORT_SUBPORT"]:
                    randMinPortVal = re.sub("Eth", "", random.choice(self.tb_vars.free_port_alias))
                    randMaxPortVal = re.sub("Eth", "", random.choice(self.tb_vars.free_port_alias))
                    rangevals = [randMinPortVal, randMaxPortVal]
                    rangevals.sort()
                    minPortNum = rangevals[0]
                    maxPortNum = rangevals[-1]
                    if datatype in ["argument", "match"]:
                        retval = "-".join(map(str, rangevals))
                    else:
                        rangevals = [randMinPortVal, randMaxPortVal]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [minPortNum, minPortNum]))
                        maxVal = "-".join(map(str, [minPortNum, maxPortNum]))
                        retval = [minVal, maxVal, randNum, None, None]
                else:
                    if datatype in ["argument", "match"]:
                        retval = "$TODO$"
                    else:
                        retval = ["$TODO$", "$TODO$", "$TODO$", None, None]
            else:
                if datatype in ["argument", "match"]:
                    retval = "$TODO$"
                else:
                    retval = ["$TODO$", "$TODO$", "$TODO$", None, None]
        else:
            if param_type == "UINT":
                if param_name.startswith("phy-if-") or param_name in ["ifId", "if-id", "PLK", "ifnum", "ptp_port_number"]:
                    retval = random.choice(self.tb_vars.free_ports)
                    if datatype not in ["argument", "match"]:
                        retval = re.sub("Ethernet", "", retval)
                        retval = [retval, retval, retval, None, None]
                elif param_name == "zone":
                    minv = 0
                    maxv = 3
                    if datatype in ["argument", "match"]:
                        retval = str(random.randint(minv, maxv))
                    else:
                        retval = [minv, maxv, random.randint(minv, maxv), minv-1, maxv+1]
                elif param_name == "pid-no":
                    minv = 1
                    maxv = 255
                    if datatype in ["argument", "match"]:
                        retval = str(random.randint(minv, maxv))
                    else:
                        retval = [minv, maxv, random.randint(minv, maxv), minv-1, None]
                elif param_name == "sampling-rate-val":
                    minv = 1
                    maxv = 65535
                    if datatype in ["argument", "match"]:
                        retval = str(random.randint(minv, maxv))
                    else:
                        retval = [minv, maxv, random.randint(minv, maxv), minv-1, maxv+1]
                else:
                    minv = 0
                    maxv = pow(2, 32) - 1
                    if datatype in ["argument", "match"]:
                        retval = str(random.randint(minv, maxv))
                    else:
                        retval = [minv, maxv, random.randint(minv, maxv), minv-1, maxv+1]
            elif param_type.startswith("STRING") or param_type.startswith("HOSTNAME_STR"):
                if param_name == "create" and self.script in ["interface"]:
                    if datatype in ["argument", "match"]:
                        retval = "create"
                    else:
                        retval = ["create", "create", "create", "create", "create"]
                    return retval

                if param_name.startswith("ifId"):
                    retval = random.choice(self.tb_vars.free_ports)
                    retval = re.sub("Ethernet", "", retval)
                    if datatype not in ["argument", "match"]:
                        retval = [retval, retval, retval, None, None]
                    return retval

                intf_names = ["phy-if-id", "interface", "interfacename", "interface-name", "intf-name", "mrouter-if-name"]
                intf_names.extend(["grp-if-name", "donor-interface", "ifname", "ifName", "ifName1", "src-phy-if-id"])
                if param_name in intf_names:
                    retval = random.choice(self.tb_vars.free_ports)
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
                if param_name in ["vrfname", "vrf-name"] and param_type in vrf_string_types:
                    minLen = 1
                    maxLen = 11
                    if param_type.startswith("STRING_"):
                        maxLen = int(re.sub("STRING_", "", param_type))
                        maxLen = maxLen - 4
                    letters = string.ascii_letters + string.digits
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                        invalidMaxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                        invalidMinStr = ''.join(random.choice(letters) for i in range(stringLength))
                        retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
                    return retval

                if param_name in ["route-map-name"] and param_type in ["STRING"]:
                    param_type = "STRING_63"

                if param_name in ["session-name"] and param_type in ["STRING"]:
                    param_type = "STRING_72"

                if param_type in ["STRING_32_TAM"]:
                    param_type = "STRING_32"

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
                        maxLen = 512
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
                    except Exception:
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

                    if datatype in ["argument", "match"]:
                        if "V6" in param_type:
                            retval = rand_ipv6_address
                        else:
                            retval = rand_ipv4_address
                    else:
                        if "V6" in param_type:
                            retval = [None, None, rand_ipv6_address, None, None]
                        else:
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
                    except Exception:
                        break
            elif param_type in ["MAC_ADDR", "FBS_MAC_ADDR", "ACL_MAC_ADDR"]:
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
                    except Exception:
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
                    except Exception:
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
                    except Exception:
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
                    except Exception:
                        break
            elif param_type in ["RADIUS_VRF"]:
                minLen = 1
                maxLen = 11
                letters = string.ascii_letters + string.digits
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    stringLength = random.randint(minLen, maxLen)
                    if datatype in ["argument", "match"]:
                        retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    else:
                        minStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(minLen))
                        maxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen))
                        randStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                        invalidMaxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                        invalidMinStr = ''.join(random.choice(letters) for i in range(stringLength))
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
                    except Exception:
                        break
            elif param_type in ["FILE_TYPE"]:
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
                    except Exception:
                        break
            elif param_type in ["AA_NN"]:
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
                    except Exception:
                        break
            elif param_type in ["KDUMP_MEMORY"]:
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
                    except Exception:
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
                    except Exception:
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
                    except Exception:
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
                    except Exception:
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
                    if datatype in ["argument", "match"]:
                        retval = randNum
                    else:
                        retval = [minv, maxv, randNum, minv-1, maxv+1]
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
            elif param_type in ["NAT_PORT_RANGE"]:
                minv = 1
                maxv = 65535
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    #randNum = random.randint(minv, maxv)
                    if datatype in ["argument", "match"]:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        retval = "-".join(map(str, rangevals))
                    else:
                        rangevals = [random.randint(int(minv), int(maxv)), random.randint(int(minv), int(maxv))]
                        rangevals.sort()
                        randNum = "-".join(map(str, rangevals))
                        minVal = "-".join(map(str, [int(minv), int(minv)]))
                        maxVal = "-".join(map(str, [int(minv), int(maxv)]))
                        inValidMinVal = "-".join(map(str, [int(minv) - 1, int(minv)]))
                        inValidMaxVal = "-".join(map(str, [int(minv), int(maxv) + 1]))
                        retval = [minVal, maxVal, randNum, inValidMinVal, inValidMaxVal]
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
                    randNum = random.randint(minv, maxv)
                    if datatype in ["argument", "match"]:
                        retval = randNum
                    else:
                        retval = [minv, maxv, randNum, minv-1, maxv+1]
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
            elif param_type in ["VRF", "VRF_NAME", "VRF_OR_DEFAULT", "VRF_OR_MGMT"]:
                minLen = 1
                maxLen = 11
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                if datatype in ["argument", "match"]:
                    retval = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                else:
                    minStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(minLen))
                    maxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen))
                    randStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(stringLength))
                    invalidMaxStr = 'Vrf_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                    invalidMinStr = ''.join(random.choice(letters) for i in range(stringLength))
                    retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
            elif param_type in ["SFLOW_AGENT"]:
                retval = random.choice(self.tb_vars.free_ports)
                if datatype not in ["argument", "match"]:
                    retval = re.sub("Ethernet", "Ethernet ", retval)
                    retval = [retval, retval, retval, None, None]
            elif param_type in ["PCP_VALUE_MASK"]:
                min_arg = 0
                max_arg = 7
                minVal = "{0}/{0}".format(min_arg)
                maxVal = "{0}/{0}".format(max_arg)
                randNum1 = random.choice(range(0,8))
                randNum2 = random.choice([i for i in range(0,8) if i not in [randNum1]])
                randNum = "{}/{}".format(randNum1, randNum2)
                invalidMin = "{}/{}".format(min_arg-1, min_arg-1)
                invalidMax = "{}/{}".format(max_arg + 1, max_arg + 1)
                if datatype in ["argument", "match"]:
                    retval = randNum
                else:
                    retval = [minVal, maxVal, randNum, invalidMin, invalidMax]
            elif param_type in ["ETHERTYPE_VALUE"]:
                iter_count = 0
                while True:
                    iter_count += 1
                    if iter_count > 5: break
                    min_hex_str = "0x1000"
                    rand_hex_str = '0x1' + ''.join(random.choice(string.hexdigits).lower() for _ in range(3))
                    max_hex_str = "0xFAA"
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
                    except Exception:
                        break
            elif param_type in ["VTEP_NAME"]:
                minLen = 1
                maxLen = 58
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                if datatype in ["argument", "match"]:
                    retval = 'Vtep_' + ''.join(random.choice(letters) for i in range(stringLength))
                else:
                    minStr = 'Vtep_' + ''.join(random.choice(letters) for i in range(minLen))
                    maxStr = 'Vtep_' + ''.join(random.choice(letters) for i in range(maxLen))
                    randStr = 'Vtep_' + ''.join(random.choice(letters) for i in range(stringLength))
                    invalidMaxStr = 'Vtep_' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                    invalidMinStr = ''.join(random.choice(letters) for i in range(stringLength))
                    retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
            elif param_type in ["ACL_REMARK"]:
                minLen = 1
                maxLen = 256
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                if datatype in ["argument", "match"]:
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                else:
                    minStr = ''.join(random.choice(letters) for i in range(minLen))
                    maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                    randStr = ''.join(random.choice(letters) for i in range(stringLength))
                    retval = [minStr, maxStr, randStr, None, None]
            elif param_type in ["AUTH_TYPES"]:
                choices = ['password', 'cert', 'jwt', 'none']
                if datatype in ["argument", "match"]:
                    retval = random.choice(choices)
                else:
                    retval = [choices[0], choices[-1], random.choice(choices), None, None]
            elif param_type in dot_start_patterns:
                minLen = 1
                maxLen = 63
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
                    except Exception:
                        break
            elif param_type in ["BOOT_OPTIONS"]:
                if datatype in ["argument", "match"]:
                    retval = "-h"
                else:
                    retval = ["-h", None, None, None, None]
            elif param_type in ["LDAP_VRF"]:
                minLen = 1
                maxLen = 28
                letters = string.ascii_letters + string.digits
                stringLength = random.randint(minLen, maxLen)
                if datatype in ["argument", "match"]:
                    retval = 'Vrf' + ''.join(random.choice(letters) for i in range(stringLength))
                else:
                    minStr = 'Vrf' + ''.join(random.choice(letters) for i in range(minLen))
                    maxStr = 'Vrf' + ''.join(random.choice(letters) for i in range(maxLen))
                    randStr = 'Vrf' + ''.join(random.choice(letters) for i in range(stringLength))
                    invalidMaxStr = 'Vrf' + ''.join(random.choice(letters) for i in range(maxLen + 1))
                    invalidMinStr = ''.join(random.choice(letters) for i in range(stringLength))
                    retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
            elif param_type in ["LST_GROUP_NAME"]:
                minLen = 1
                maxLen = 62
                letters = string.ascii_letters + string.digits + '_-'
                single_letter = random.choice(string.ascii_letters + string.digits)
                stringLength = random.randint(minLen, maxLen)
                if datatype in ["argument", "match"]:
                    retval = single_letter + ''.join(random.choice(letters) for i in range(stringLength))
                else:
                    minStr = single_letter + ''.join(random.choice(letters) for i in range(minLen))
                    maxStr = single_letter + ''.join(random.choice(letters) for i in range(maxLen))
                    randStr = single_letter + ''.join(random.choice(letters) for i in range(stringLength))
                    invalidMaxStr = single_letter + ''.join(random.choice(letters) for i in range(maxLen + 1))
                    invalidMinStr = "-" + ''.join(random.choice(letters) for i in range(stringLength))
                    retval = [minStr, maxStr, randStr, invalidMinStr, invalidMaxStr]
            elif param_type in ["CONTAINER_NAME"]:
                minLen = 1
                maxLen = 64
                letters = string.ascii_letters + string.digits + '_-'
                stringLength = random.randint(minLen, maxLen)
                if datatype in ["argument", "match"]:
                    retval = ''.join(random.choice(letters) for i in range(stringLength))
                else:
                    minStr = ''.join(random.choice(letters) for i in range(minLen))
                    maxStr = ''.join(random.choice(letters) for i in range(maxLen))
                    randStr = ''.join(random.choice(letters) for i in range(stringLength))
                    invalidMaxStr = ''.join(random.choice(letters) for i in range(maxLen + 1))
                    #invalidMinStr = ''.join(random.choice(letters) for i in range(stringLength))
                    retval = [minStr, maxStr, randStr, None, invalidMaxStr]
            elif param_type in ["NUM32_WITH_SIGN"]:
                maxv = pow(2, 32) - 1
                minv = -1 * maxv
                if datatype in ["argument", "match"]:
                    retval = str(random.randint(minv, maxv))
                else:
                    retval = [minv, maxv, random.randint(minv, maxv), minv - 1, maxv + 1]
            elif param_type in ["FRONT_PANEL_PORT"]:
                minv = 1
                maxv = 299
                if datatype in ["argument", "match"]:
                    retval = str(random.randint(minv, maxv))
                else:
                    retval = ["1/"+str(minv), "1/"+str(maxv), "1/"+str(random.randint(minv, maxv)), "1/"+str(minv-1), "1/"+str(maxv+1)]
            elif param_type in ["PORT_GROUP_ID"]:
                minv = 1
                maxv = 99
                if datatype in ["argument", "match"]:
                    retval = str(random.randint(minv, maxv))
                else:
                    retval = [minv, maxv, random.randint(minv, maxv), minv - 1, maxv + 1]


            # TODO: Need to do for other types such as IP, HOSTNAME , etc.

        #print("Random_value:", retval)
        return retval

