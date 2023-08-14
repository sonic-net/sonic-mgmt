import os
import re
import logging
from spytest.dicts import SpyTestDict
from spytest.ordyaml import OrderedYaml
from spytest import env

prompts_root = os.path.join(os.path.dirname(__file__), '..', '..', "datastore", "prompts")


class Prompts(object):

    def __init__(self, model=None, logger=None, normal_user_mode=None):
        """
        Construction of Prompts object
        :param logger:
        :type logger:
        """
        self.normal_user_mode = normal_user_mode or "normal-user"
        self.logger = logger or logging.getLogger()
        self.oyaml = None
        model = "sonic" if not model else re.sub("_(ssh|terminal)$", "", model)
        filename = "{}_prompts.yaml".format(model)
        filename = env.get("SPYTEST_PROMPTS_FILENAME", filename)
        filename = os.path.join(os.path.abspath(prompts_root), filename)

        self.oyaml = OrderedYaml(filename, [])
        prompts_file_data = self.oyaml.get_data() or dict()

        self.normal_user_prompts = []
        self.patterns = prompts_file_data.patterns if "patterns" in prompts_file_data else SpyTestDict()
        self.normal_user_prompt_tmpl = self.patterns.get(self.normal_user_mode)
        self.modes = prompts_file_data.modes if "modes" in prompts_file_data else SpyTestDict()
        self.required_args = prompts_file_data.required_args if "required_args" in prompts_file_data else SpyTestDict()
        self.sudo_include_prompts = prompts_file_data.sudo_include_prompts if "sudo_include_prompts" in prompts_file_data else []
        self.do_exclude_prompts = prompts_file_data.do_exclude_prompts if "do_exclude_prompts" in prompts_file_data else []
        self.do_exclude_prompts.append(self.normal_user_mode)

        self.stored_values = SpyTestDict()
        self.hostname = None

    def __del__(self):
        pass

    def add_user_hostname(self, value, username=None):
        if not self.normal_user_prompt_tmpl:
            self.normal_user_prompts = []
        elif not value and not username:
            self.normal_user_prompts = []
        else:
            value = value or self.hostname or ""
            value = value.split(".")[0]
            prompt = re.sub(r"{}", value, self.normal_user_prompt_tmpl)
            prompt = re.sub(r"{username}", username or "", prompt)
            if prompt not in self.normal_user_prompts:
                self.normal_user_prompts.append(prompt)
        return self.normal_user_prompts

    def get_normal_user_prompts(self, index):
        prompt = self._get_prompt_for_mode(self.normal_user_mode, index=index)
        prompts = [prompt] if prompt else []
        prompts.extend(self.normal_user_prompts)
        return prompts

    def set_normal_user_prompt(self, value, index):
        self.patterns[self.normal_user_mode] = value
        self.patterns["{}--{}".format(self.normal_user_mode, index)] = value

    def update_with_hostname(self, username, hostname, index=None):
        self.hostname = hostname
        for pattern in self.patterns:
            if isinstance(self.patterns[pattern], dict):
                self.update_with_hostname(username, hostname, self.patterns[pattern])
                continue
            prompt = self.patterns[pattern]
            prompt = re.sub(r"{}", hostname or "", prompt)
            prompt = re.sub(r"{username}", username or "", prompt)
            self.patterns[pattern] = prompt
            if index is not None:
                self.patterns["{}--{}".format(pattern, index)] = prompt
        return "|".join(self.get_normal_user_prompts(index))

    def _check_ifname_type(self, ifname_type):
        return ifname_type or 'native'

    def get_mode(self, mode, ifname_type=None):
        ifname_type = self._check_ifname_type(ifname_type)
        lmode = self.modes[mode]
        if isinstance(lmode, dict):
            lmode = lmode.get(ifname_type, lmode[sorted(list(lmode.keys()))[0]])
        return lmode

    def normalize_mode(self, mode, role=None):
        if role in ["admin", None]:
            return mode
        return mode.replace("vtysh", "mgmt")

    def normalize_prompt(self, prompt, role=None):
        if role in ["admin", None]:
            return prompt
        return prompt.replace("--sonic-mgmt--", "sonic")

    def get_mode_for_prompt(self, prompt, index=0, role=None):
        prompt2 = prompt.replace("\\", "")
        for mode in self.patterns:
            lpattern = self.patterns[mode]
            lpatterns = list(lpattern.values() if isinstance(lpattern, dict) else [lpattern])
            for ptrn in lpatterns:
                if re.search(ptrn, prompt2):
                    return self.normalize_mode(mode, role)
        for ptrn in self.get_normal_user_prompts(index):
            if ptrn and re.search(ptrn, prompt2):
                return self.normal_user_mode
        return "unknown-prompt"

    def _get_prompt_for_mode(self, mode, ifname_type=None, index=0, role=None):
        mode = self.normalize_mode(mode, role)
        ifname_type = self._check_ifname_type(ifname_type)
        if mode in self.patterns:
            mode2 = "{}--{}".format(mode, index)
            if mode2 in self.patterns:
                lpattern = self.patterns[mode2]
            else:
                lpattern = self.patterns[mode]
            if isinstance(lpattern, dict):
                lpattern = lpattern.get(ifname_type, lpattern[sorted(list(lpattern.keys()))[0]])
            return self.normalize_prompt(lpattern, role)
        return "unknown-mode"

    def get_prompt_for_mode(self, mode, ifname_type=None, index=0, role=None):
        if mode == self.normal_user_mode:
            return "|".join(self.get_normal_user_prompts(index))
        return self._get_prompt_for_mode(mode, ifname_type, index, role)

    def check_args_for_req_mode(self, abort, mode, **kwargs):
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
                    argName = arg.replace('?', '')
                    if argName not in kwargs.keys() and not arg.startswith('?'):
                        missing_args_flag = 1
                        args_str = ", ".join(self.required_args[mode])
                        break

            if missing_args_flag:
                msg = "{} option(s) must be provided for {}.".format(args_str, mode)
                if not abort:
                    return msg
                raise ValueError(msg)
        return None

    def check_move_for_parent_of_from_mode(self, prompt, mode, **kwargs):
        if mode == "vtysh-intf-config":
            return True

        if mode == "mgmt-config":
            if "conf_session" in kwargs:
                return True

            if "conf_terminal" in kwargs:
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

        if mode == "mgmt-ipv6-acl-config":
            if "ipv6_aclname" not in self.stored_values:
                self.stored_values["ipv6_aclname"] = kwargs["aclname"]
                return False
            else:
                if self.stored_values["ipv6_aclname"] != kwargs["aclname"]:
                    self.stored_values["ipv6_aclname"] = kwargs["aclname"]
                    return True

        if mode == "mgmt-mac-acl-config":
            if "mac_aclname" not in self.stored_values:
                self.stored_values["mac_aclname"] = kwargs["aclname"]
                return False
            else:
                if self.stored_values["mac_aclname"] != kwargs["aclname"]:
                    self.stored_values["mac_aclname"] = kwargs["aclname"]
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
            if "bgp_vrf_name" in kwargs:
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
            else:
                if "bgp_instance" not in self.stored_values:
                    self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
                    return False
                else:
                    if self.stored_values["bgp_instance"] != kwargs["bgp_instance"]:
                        self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
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

        if mode == "mgmt-router-ospf-view":
            if "ospf_vrf_name" not in self.stored_values:
                self.stored_values["ospf_vrf_name"] = kwargs["ospf_vrf_name"]
                return False
            else:
                if self.stored_values["ospf_vrf_name"] != kwargs["ospf_vrf_name"]:
                    return True

        if mode == "mgmt-intf-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-{})".format(kwargs["interface"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-subintf-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-{})".format(kwargs["interface"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-intf-vlan-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-Vlan{})".format(kwargs["vlan"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-intf-po-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-po{})".format(kwargs["portchannel"])
            if intfNum in prompt2:
                return False
            else:
                return True

        if mode == "mgmt-intf-management-config":
            prompt2 = prompt.replace("\\", "")
            intfNum = "-eth{})".format(kwargs["number"])
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

        if mode == "mgmt-wred-view":
            if "wred_name" not in self.stored_values:
                self.stored_values["wred_name"] = kwargs["wred_name"]
                return False
            else:
                if self.stored_values["wred_name"] != kwargs["wred_name"]:
                    self.stored_values["wred_name"] = kwargs["wred_name"]
                    return True

        if mode == "mgmt-qos-sched-policy-view":
            if "sched_policy_name" not in self.stored_values:
                self.stored_values["sched_policy_name"] = kwargs["sched_policy_name"]
                return False
            else:
                if self.stored_values["sched_policy_name"] != kwargs["sched_policy_name"]:
                    self.stored_values["sched_policy_name"] = kwargs["sched_policy_name"]
                    return True

        if mode == "mgmt-qos-sched-policy-queue-view":
            if "sched_policy_name" not in self.stored_values:
                self.stored_values["queue_id"] = kwargs["queue_id"]
                return False
            else:
                if self.stored_values["queue_id"] != kwargs["queue_id"]:
                    self.stored_values["queue_id"] = kwargs["queue_id"]
                    return True

        if mode == "mgmt-qos-intf-view":
            if "qos_interface" not in self.stored_values:
                self.stored_values["qos_interface"] = kwargs["qos_interface"]
                return False
            else:
                if self.stored_values["qos_interface"] != kwargs["qos_interface"]:
                    self.stored_values["qos_interface"] = kwargs["qos_interface"]
                    return True

        return False

    def check_move_for_parent_of_to_mode(self, prompt, mode, ifname_type, **kwargs):
        check_for_parents = False

        if mode == "mgmt-config":
            if "conf_session" in kwargs:
                check_for_parents = True

            if "conf_terminal" in kwargs:
                check_for_parents = True

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

        if mode == "mgmt-ipv6-acl-config":
            if "ipv6_aclname" not in self.stored_values:
                self.stored_values["ipv6_aclname"] = kwargs["aclname"]
                return False
            else:
                if self.stored_values["ipv6_aclname"] != kwargs["aclname"]:
                    self.stored_values["ipv6_aclname"] = kwargs["aclname"]
                    return True

        if mode == "mgmt-mac-acl-config":
            if "mac_aclname" not in self.stored_values:
                self.stored_values["mac_aclname"] = kwargs["aclname"]
                return False
            else:
                if self.stored_values["mac_aclname"] != kwargs["aclname"]:
                    self.stored_values["mac_aclname"] = kwargs["aclname"]
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
            if "bgp_vrf_name" in kwargs:
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
            else:
                if "bgp_instance" not in self.stored_values:
                    self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
                    return False
                else:
                    if self.stored_values["bgp_instance"] != kwargs["bgp_instance"]:
                        self.stored_values["bgp_instance"] = kwargs["bgp_instance"]
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

        if mode == "mgmt-router-ospf-view":
            if "ospf_vrf_name" not in self.stored_values:
                self.stored_values["ospf_vrf_name"] = kwargs["ospf_vrf_name"]
                return False
            else:
                if self.stored_values["ospf_vrf_name"] != kwargs["ospf_vrf_name"]:
                    return True

        if mode == "mgmt-wred-view":
            if "wred_name" not in self.stored_values:
                self.stored_values["wred_name"] = kwargs["wred_name"]
                return False
            else:
                if self.stored_values["wred_name"] != kwargs["wred_name"]:
                    self.stored_values["wred_name"] = kwargs["wred_name"]
                    return True

        if mode == "mgmt-qos-sched-policy-view":
            if "sched_policy_name" not in self.stored_values:
                self.stored_values["sched_policy_name"] = kwargs["sched_policy_name"]
                return False
            else:
                if self.stored_values["sched_policy_name"] != kwargs["sched_policy_name"]:
                    self.stored_values["sched_policy_name"] = kwargs["sched_policy_name"]
                    return True

        if mode == "mgmt-qos-sched-policy-queue-view":
            if "sched_policy_name" not in self.stored_values:
                self.stored_values["queue_id"] = kwargs["queue_id"]
                return False
            else:
                if self.stored_values["queue_id"] != kwargs["queue_id"]:
                    self.stored_values["queue_id"] = kwargs["queue_id"]
                    return True

        if mode == "mgmt-qos-intf-view":
            if "qos_interface" not in self.stored_values:
                self.stored_values["qos_interface"] = kwargs["qos_interface"]
                return False
            else:
                if self.stored_values["qos_interface"] != kwargs["qos_interface"]:
                    self.stored_values["qos_interface"] = kwargs["qos_interface"]
                    return True

        if check_for_parents:
            parent_modes_list = []
            curr_mode = self.get_mode_for_prompt(prompt)
            while True:
                parent_modes_list.append(self.get_mode(curr_mode, ifname_type)[0])
                curr_mode = self.get_mode(curr_mode, ifname_type)[0]
                if curr_mode == "":
                    break
            if mode in parent_modes_list:
                return True

        return False

    def get_backward_command_and_prompt(self, mode, ifname_type=None):
        ifname_type = self._check_ifname_type(ifname_type)
        if mode not in self.modes:
            return ["", ""]
        cmd = self.get_mode(mode, ifname_type)[2]
        expected_prompt = self.get_prompt_for_mode(self.get_mode(mode, ifname_type)[0], ifname_type)
        return [cmd, expected_prompt]

    def get_forward_command_and_prompt_with_values(self, mode, ifname_type=None, **kwargs):
        ifname_type = self._check_ifname_type(ifname_type)
        if mode not in self.modes:
            return ["", ""]
        cmd = self.get_mode(mode, ifname_type)[1]
        expected_prompt = self.get_prompt_for_mode(mode, ifname_type)
        if mode in self.required_args:
            values = []

            # Handle specific node with interface range
            if mode == "mgmt-intf-range-eth-config" and 'alt_port_names' in kwargs:
                native_ports = [re.sub(r'.*?(\d+)', r'\1', x) for x in kwargs.get('alt_port_names', {}).keys()]
                alias_ports = [re.sub(r'.*?(\d+/\d+)', r'\1', x) for x in kwargs.get('alt_port_names', {}).values()]
                comp = re.split(r'([,-])', kwargs.get('range', '').replace(" ", ""))
                # print('native_ports = {}\nalias_port = {}\ncomp = {}'.format(native_ports, alias_ports, comp))
                for i, port in enumerate(comp):
                    if ifname_type == 'native':
                        if port in alias_ports:
                            comp[i] = native_ports[alias_ports.index(port)]
                    elif ifname_type == 'alias':
                        if port in native_ports:
                            comp[i] = alias_ports[native_ports.index(port)]
                kwargs['range'] = "".join(comp)

            for arg in self.required_args[mode]:
                argName = arg.replace('?', '')
                if argName in kwargs.keys():
                    if (mode == "mgmt-intf-config" or mode == "mgmt-subintf-config") and argName == "interface":
                        intf_value = re.sub(r"(Ethernet)", r"\1 ", kwargs[argName])
                        values.append(intf_value)
                    elif mode.startswith("mgmt-router-bgp-") and argName == "bgp_vrf_name":
                        vrf_part = "vrf {}".format(kwargs[argName])
                        values.append(vrf_part)
                    else:
                        values.append(kwargs[argName])
                else:
                    values.append("")
            cmd = cmd.format(*values)
        return [cmd, expected_prompt]
