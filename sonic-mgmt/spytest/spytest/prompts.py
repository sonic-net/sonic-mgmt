import os
import re
import logging
from spytest.dicts import SpyTestDict
from spytest.ordyaml import OrderedYaml

prompts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "prompts")

class Prompts(object):
    """
    todo: Update Documentation
    """

    def __init__(self, model=None, logger=None):
        """
        Construction of Prompts object
        :param logger:
        :type logger:
        """
        self.logger = logger or logging.getLogger()
        self.oyaml = None
        model = "sonic" if not model else re.sub("_(ssh|terminal)$", "", model)
        filename = "{}_prompts.yaml".format(model)
        filename = os.path.join(os.path.abspath(prompts_root), filename)

        self.oyaml = OrderedYaml(filename,[])
        prompts_file_data = self.oyaml.get_data() or dict()

        self.patterns = prompts_file_data.patterns if "patterns" in prompts_file_data else SpyTestDict()
        self.modes = prompts_file_data.modes if "modes" in prompts_file_data else SpyTestDict()
        self.required_args = prompts_file_data.required_args if "required_args" in prompts_file_data else SpyTestDict()
        self.sudo_include_prompts = prompts_file_data.sudo_include_prompts if "sudo_include_prompts" in prompts_file_data else []
        self.do_exclude_prompts = prompts_file_data.do_exclude_prompts if "do_exclude_prompts" in prompts_file_data else []

        self.stored_values = SpyTestDict()

    def __del__(self):
        pass

    def update_with_hostname(self, hostname):
        for pattern in self.patterns:
            if re.search(r"{}", self.patterns[pattern]):
                #print("Matched Pattern: '{}' : '{}' : '{}'".format(pattern, self.patterns[pattern], self.patterns[pattern].format(hostname)))
                self.patterns[pattern] = re.sub(r"{}", hostname, self.patterns[pattern])

    def get_mode_for_prompt(self, prompt):
        prompt2 = prompt.replace("\\", "")
        for mode in self.patterns:
            lpattern = self.patterns[mode]
            if re.search(lpattern, prompt2):
                return mode
        return "unknown-prompt"

    def get_prompt_for_mode(self, mode):
        if mode in self.patterns:
            return self.patterns[mode]
        return "unknown-mode"

    def check_args_for_req_mode(self, mode, **kwargs):
        missing_args_flag = 0
        args_str = ""
        if mode in self.required_args:
            if mode == "vtysh-router-config":
                if "router" not in kwargs.keys():
                    missing_args_flag = 1
                    args_str = ", ".join(self.required_args[mode])
                elif kwargs["router"] in ["bgp", "eigrp", "isis", "openfabric", "ospf"]:
                    if "instance" not in kwargs.keys():
                        missing_args_flag = 1
                        args_str = ", ".join(self.required_args[mode])
            elif mode == "vtysh-router-af-config" and "addr_family" not in kwargs.keys():
                missing_args_flag = 1
                args_str = ", ".join(self.required_args[mode])
            else:
                for arg in self.required_args[mode]:
                    if arg not in kwargs.keys():
                        missing_args_flag = 1
                        args_str = ", ".join(self.required_args[mode])
                        break

            if missing_args_flag:
                msg = "{} option(s) must be provided for {}.".format(args_str, mode)
                raise ValueError(msg)
        return

    def check_move_for_parent_of_frommode(self, prompt, mode, **kwargs):
        if mode == "vtysh-intf-config":
            return True

        if mode == "vtysh-router-config":
            if "router" not in self.stored_values:
                self.stored_values["router"] = kwargs["router"]
                return False
            else:
                if self.stored_values["router"] != kwargs["router"]:
                    self.stored_values["router"] = kwargs["router"]
                    return True

        if mode == "mgmt-ipv4-acl-config":
            if "aclname" not in self.stored_values:
                self.stored_values["aclname"] = kwargs["aclname"]
                return False
            else:
                if self.stored_values["aclname"] != kwargs["aclname"]:
                    self.stored_values["aclname"] = kwargs["aclname"]
                    return True

        if mode == "mgmt-evpn-view":
            if "evpnname" not in self.stored_values:
                self.stored_values["evpnname"] = kwargs["evpnname"]
                return False
            else:
                if self.stored_values["evpnname"] != kwargs["evpnname"]:
                    self.stored_values["evpnname"] = kwargs["evpnname"]
                    return True

        if mode == "mgmt-bfd-peer-view":
            if "peer_ip" not in self.stored_values:
                self.stored_values["peer_ip"] = kwargs["peer_ip"]
                return False
            else:
                if self.stored_values["peer_ip"] != kwargs["peer_ip"]:
                    self.stored_values["peer_ip"] = kwargs["peer_ip"]
                    return True

        if mode == "mgmt-route-map-view":
            if "map_name" not in self.stored_values:
                self.stored_values["map_name"] = kwargs["map_name"]
                self.stored_values["action"] = kwargs["action"]
                self.stored_values["seq_num"] = kwargs["seq_num"]
                return False
            else:
                if self.stored_values["map_name"] != kwargs["map_name"] or \
                        self.stored_values["action"] != kwargs["action"] or \
                        self.stored_values["seq_num"] != kwargs["seq_num"]:
                    self.stored_values["map_name"] = kwargs["map_name"]
                    self.stored_values["action"] = kwargs["action"]
                    self.stored_values["seq_num"] = kwargs["seq_num"]
                    return True

        if mode == "mgmt-link-state-track-view":
            if "track_name" not in self.stored_values:
                self.stored_values["track_name"] = kwargs["track_name"]
                return False
            else:
                if self.stored_values["track_name"] != kwargs["track_name"]:
                    self.stored_values["track_name"] = kwargs["track_name"]
                    return True

        if mode == "mgmt-router-bgp-view":
            if "bgp_instance" not in self.stored_values:
                self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
                self.stored_values["bgp_vrf_name"] = kwargs["bgp_vrf_name"]
                return False
            else:
                if self.stored_values["bgp_instance"] != kwargs["bgp_instance"] or \
                        self.stored_values["bgp_vrf_name"] != kwargs["bgp_vrf_name"]:
                    self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
                    self.stored_values["bgp_vrf_name"] = kwargs["bgp_vrf_name"]
                    return True

        if mode == "mgmt-router-bgp-af-view":
            if "af_type" not in self.stored_values:
                self.stored_values["af_type"] = kwargs["af_type"]
                self.stored_values["af_family"] = kwargs["af_family"]
                return False
            else:
                if self.stored_values["af_type"] != kwargs["af_type"] or \
                        self.stored_values["af_family"] != kwargs["af_family"]:
                    self.stored_values["af_type"] = kwargs["af_type"]
                    self.stored_values["af_family"] = kwargs["af_family"]
                    return True

        if mode == "mgmt-router-bgp-nbr-view":
            if "ip_address" not in self.stored_values:
                self.stored_values["ip_address"] = kwargs["ip_address"]
                return False
            else:
                if self.stored_values["ip_address"] != kwargs["ip_address"]:
                    self.stored_values["ip_address"] = kwargs["ip_address"]
                    return True

        if mode == "mgmt-router-bgp-nbr-af-view":
            if "nbr_af_type" not in self.stored_values:
                self.stored_values["nbr_af_type"] = kwargs["nbr_af_type"]
                self.stored_values["nbr_af_family"] = kwargs["nbr_af_family"]
                return False
            else:
                if self.stored_values["nbr_af_type"] != kwargs["nbr_af_type"] or \
                        self.stored_values["nbr_af_family"] != kwargs["nbr_af_family"]:
                    self.stored_values["nbr_af_type"] = kwargs["nbr_af_type"]
                    self.stored_values["nbr_af_family"] = kwargs["nbr_af_family"]
                    return True

        if mode == "mgmt-router-bgp-template-view":
            if "group_name" not in self.stored_values:
                self.stored_values["group_name"] = kwargs["group_name"]
                return False
            else:
                if self.stored_values["group_name"] != kwargs["group_name"]:
                    self.stored_values["group_name"] = kwargs["group_name"]
                    return True

        if mode == "mgmt-router-bgp-template-af-view":
            if "tpl_af_type" not in self.stored_values:
                self.stored_values["tpl_af_type"] = kwargs["tpl_af_type"]
                self.stored_values["tpl_af_family"] = kwargs["tpl_af_family"]
                return False
            else:
                if self.stored_values["tpl_af_type"] != kwargs["tpl_af_type"] or \
                        self.stored_values["tpl_af_family"] != kwargs["tpl_af_family"]:
                    self.stored_values["tpl_af_type"] = kwargs["tpl_af_type"]
                    self.stored_values["tpl_af_family"] = kwargs["tpl_af_family"]
                    return True

        if mode == "mgmt-router-bgp-l2vpn-vni-view":
            if "vxlan_id" not in self.stored_values:
                self.stored_values["vxlan_id"] = kwargs["vxlan_id"]
                return False
            else:
                if self.stored_values["vxlan_id"] != kwargs["vxlan_id"]:
                    self.stored_values["vxlan_id"] = kwargs["vxlan_id"]
                    return True

        if mode == "mgmt-intf-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-{})".format(kwargs["interface"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-vlan-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-Vlan{})".format(kwargs["vlan"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-lag-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-po{})".format(kwargs["portchannel"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-management-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-eth{})".format(kwargs["management"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-vxlan-view":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-Vxlan-{})".format(kwargs["vxlan"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-mirror-session-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-mirror-{})".format(kwargs["session_name"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-mclag-view":
            prompt2 = prompt.replace("\\", "")
            intfNum = "mclag-domain-{})".format(kwargs["domain_id"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-lo-view":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-lo{})".format(kwargs["loopback_id"])
            if intfNum in prompt2:
                return False
            else:
                return True

        return False

    def check_move_for_parent_of_tomode(self, prompt, mode, **kwargs):
        check_for_parents = False
        if mode == "vtysh-router-config":
            if "router" not in self.stored_values:
                self.stored_values["router"] = kwargs["router"]
                return False
            else:
                if self.stored_values["router"] != kwargs["router"]:
                    self.stored_values["router"] = kwargs["router"]
                    check_for_parents = True

        if mode == "vtysh-router-af-config":
            if "router" in kwargs:
                if "router" not in self.stored_values:
                    self.stored_values["router"] = kwargs["router"]
                    return False
                else:
                    if self.stored_values["router"] != kwargs["router"]:
                        self.stored_values["router"] = kwargs["router"]
                        check_for_parents = True

        if mode == "mgmt-ipv4-acl-config":
            if "aclname" not in self.stored_values:
                self.stored_values["aclname"] = kwargs["aclname"]
                return False
            else:
                if self.stored_values["aclname"] != kwargs["aclname"]:
                    self.stored_values["aclname"] = kwargs["aclname"]

        if mode == "mgmt-evpn-view":
            if "evpnname" not in self.stored_values:
                self.stored_values["evpnname"] = kwargs["evpnname"]
                return False
            else:
                if self.stored_values["evpnname"] != kwargs["evpnname"]:
                    self.stored_values["evpnname"] = kwargs["evpnname"]
                    return True

        if mode == "mgmt-bfd-peer-view":
            if "peer_ip" not in self.stored_values:
                self.stored_values["peer_ip"] = kwargs["peer_ip"]
                return False
            else:
                if self.stored_values["peer_ip"] != kwargs["peer_ip"]:
                    self.stored_values["peer_ip"] = kwargs["peer_ip"]
                    return True

        if mode == "mgmt-route-map-view":
            if "map_name" not in self.stored_values:
                self.stored_values["map_name"] = kwargs["map_name"]
                self.stored_values["action"] = kwargs["action"]
                self.stored_values["seq_num"] = kwargs["seq_num"]
                return False
            else:
                if self.stored_values["map_name"] != kwargs["map_name"] or \
                        self.stored_values["action"] != kwargs["action"] or \
                        self.stored_values["seq_num"] != kwargs["seq_num"]:
                    self.stored_values["map_name"] = kwargs["map_name"]
                    self.stored_values["action"] = kwargs["action"]
                    self.stored_values["seq_num"] = kwargs["seq_num"]
                    return True

        if mode == "mgmt-link-state-track-view":
            if "track_name" not in self.stored_values:
                self.stored_values["track_name"] = kwargs["track_name"]
                return False
            else:
                if self.stored_values["track_name"] != kwargs["track_name"]:
                    self.stored_values["track_name"] = kwargs["track_name"]
                    return True

        if mode == "mgmt-router-bgp-view":
            if "bgp_instance" not in self.stored_values:
                self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
                self.stored_values["bgp_vrf_name"] = kwargs["bgp_vrf_name"]
                return False
            else:
                if self.stored_values["bgp_instance"] != kwargs["bgp_instance"] or \
                        self.stored_values["bgp_vrf_name"] != kwargs["bgp_vrf_name"]:
                    self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
                    self.stored_values["bgp_vrf_name"] = kwargs["bgp_vrf_name"]
                    return True

        if mode == "mgmt-router-bgp-af-view":
            if "af_type" not in self.stored_values:
                self.stored_values["af_type"] = kwargs["af_type"]
                self.stored_values["af_family"] = kwargs["af_family"]
                return False
            else:
                if self.stored_values["af_type"] != kwargs["af_type"] or \
                        self.stored_values["af_family"] != kwargs["af_family"]:
                    self.stored_values["af_type"] = kwargs["af_type"]
                    self.stored_values["af_family"] = kwargs["af_family"]
                    return True

        if mode == "mgmt-router-bgp-nbr-view":
            if "ip_address" not in self.stored_values:
                self.stored_values["ip_address"] = kwargs["ip_address"]
                return False
            else:
                if self.stored_values["ip_address"] != kwargs["ip_address"]:
                    self.stored_values["ip_address"] = kwargs["ip_address"]
                    return True

        if mode == "mgmt-router-bgp-nbr-af-view":
            if "nbr_af_type" not in self.stored_values:
                self.stored_values["nbr_af_type"] = kwargs["nbr_af_type"]
                self.stored_values["nbr_af_family"] = kwargs["nbr_af_family"]
                return False
            else:
                if self.stored_values["nbr_af_type"] != kwargs["nbr_af_type"] or \
                        self.stored_values["nbr_af_family"] != kwargs["nbr_af_family"]:
                    self.stored_values["nbr_af_type"] = kwargs["nbr_af_type"]
                    self.stored_values["nbr_af_family"] = kwargs["nbr_af_family"]
                    return True

        if mode == "mgmt-router-bgp-template-view":
            if "group_name" not in self.stored_values:
                self.stored_values["group_name"] = kwargs["group_name"]
                return False
            else:
                if self.stored_values["group_name"] != kwargs["group_name"]:
                    self.stored_values["group_name"] = kwargs["group_name"]
                    return True

        if mode == "mgmt-router-bgp-template-af-view":
            if "tpl_af_type" not in self.stored_values:
                self.stored_values["tpl_af_type"] = kwargs["tpl_af_type"]
                self.stored_values["tpl_af_family"] = kwargs["tpl_af_family"]
                return False
            else:
                if self.stored_values["tpl_af_type"] != kwargs["tpl_af_type"] or \
                        self.stored_values["tpl_af_family"] != kwargs["tpl_af_family"]:
                    self.stored_values["tpl_af_type"] = kwargs["tpl_af_type"]
                    self.stored_values["tpl_af_family"] = kwargs["tpl_af_family"]
                    return True

        if mode == "mgmt-router-bgp-l2vpn-vni-view":
            if "vxlan_id" not in self.stored_values:
                self.stored_values["vxlan_id"] = kwargs["vxlan_id"]
                return False
            else:
                if self.stored_values["vxlan_id"] != kwargs["vxlan_id"]:
                    self.stored_values["vxlan_id"] = kwargs["vxlan_id"]
                    return True

        if check_for_parents:
            parent_modes_list = []
            curr_mode = self.get_mode_for_prompt(prompt)
            while True:
                parent_modes_list.append(self.modes[curr_mode][0])
                curr_mode = self.modes[curr_mode][0]
                if curr_mode == "":
                    break
            if mode in parent_modes_list:
                return True

        return False

    def get_backward_command_and_prompt(self, mode):
        if mode not in self.modes:
            return ["", ""]
        cmd = self.modes[mode][2]
        expected_prompt = self.get_prompt_for_mode(self.modes[mode][0])
        return [cmd, expected_prompt]

    def get_forward_command_and_prompt_with_values(self, mode, **kwargs):
        if mode not in self.modes:
            return ["", ""]
        cmd = self.modes[mode][1]
        expected_prompt = self.get_prompt_for_mode(mode)
        if mode in self.required_args:
            values = []
            for arg in self.required_args[mode]:
                if arg in kwargs.keys():
                    if mode == "mgmt-intf-config" and arg == "interface":
                        intf_value = re.sub("Ethernet", "Ethernet ", kwargs[arg])
                        values.append(intf_value)
                    else:
                        values.append(kwargs[arg])
                else:
                    values.append("")
            cmd = cmd.format(*values)
        return [cmd, expected_prompt]

