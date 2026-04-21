# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The iosxr_l3_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function

import copy


__metaclass__ = type


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.facts.facts import Facts
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    add_command_to_config_list,
    dict_to_set,
    filter_dict_having_none_value,
    normalize_interface,
    remove_command_from_config_list,
    remove_duplicate_interface,
    validate_ipv6,
    validate_n_expand_ipv4,
)


class L3_Interfaces(ConfigBase):
    """
    The iosxr_l3_interfaces class
    """

    gather_subset = ["!all", "!min"]

    gather_network_resources = ["l3_interfaces"]

    def get_l3_interfaces_facts(self, data=None):
        """Get the 'facts' (the current configuration)
        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(
            self.gather_subset,
            self.gather_network_resources,
            data=data,
        )
        l3_interfaces_facts = facts["ansible_network_resources"].get(
            "l3_interfaces",
        )
        if not l3_interfaces_facts:
            return []
        return l3_interfaces_facts

    def execute_module(self):
        """Execute the module
        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {"changed": False}
        warnings = list()
        commands = list()

        if self.state in self.ACTION_STATES:
            existing_l3_interfaces_facts = self.get_l3_interfaces_facts()
        else:
            existing_l3_interfaces_facts = []

        if self.state in self.ACTION_STATES or self.state == "rendered":
            commands.extend(self.set_config(existing_l3_interfaces_facts))

        if commands and self.state in self.ACTION_STATES:
            if not self._module.check_mode:
                self._connection.edit_config(commands)
            result["changed"] = True

        if self.state in self.ACTION_STATES:
            result["commands"] = commands

        if self.state in self.ACTION_STATES or self.state == "gathered":
            changed_l3_interfaces_facts = self.get_l3_interfaces_facts()

        elif self.state == "rendered":
            result["rendered"] = commands

        elif self.state == "parsed":
            running_config = self._module.params["running_config"]
            if not running_config:
                self._module.fail_json(
                    msg="value of running_config parameter must not be empty for state parsed",
                )
            result["parsed"] = self.get_l3_interfaces_facts(
                data=running_config,
            )

        if self.state in self.ACTION_STATES:
            result["before"] = existing_l3_interfaces_facts
            if result["changed"]:
                result["after"] = changed_l3_interfaces_facts

        elif self.state == "gathered":
            result["gathered"] = changed_l3_interfaces_facts

        result["warnings"] = warnings
        return result

    def set_config(self, existing_l3_interfaces_facts):
        """Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params["config"]
        have = copy.deepcopy(existing_l3_interfaces_facts)
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """Select the appropriate function based on the state provided
        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []

        if self.state in ("overridden", "merged", "replaced", "rendered") and not want:
            self._module.fail_json(
                msg="value of config parameter must not be empty for state {0}".format(
                    self.state,
                ),
            )

        if self.state == "overridden":
            commands = self._state_overridden(want, have, self._module)
        elif self.state == "deleted":
            commands = self._state_deleted(want, have)
        elif self.state in ("merged", "rendered"):
            commands = self._state_merged(want, have, self._module)
        elif self.state == "replaced":
            commands = self._state_replaced(want, have, self._module)

        return commands

    def _state_replaced(self, want, have, module):
        """The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []

        for interface in want:
            interface["name"] = normalize_interface(interface["name"])
            for each in have:
                if each["name"] == interface["name"]:
                    break
            else:
                commands.extend(self._set_config(interface, dict(), module))
                continue
            have_dict = filter_dict_having_none_value(interface, each)
            commands.extend(self._clear_config(dict(), have_dict))
            commands.extend(self._set_config(interface, each, module))
        # Remove the duplicate interface call
        commands = remove_duplicate_interface(commands)

        return commands

    def _state_overridden(self, want, have, module):
        """The command generator when state is overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        not_in_have = set()
        in_have = set()

        for each in have:
            for interface in want:
                interface["name"] = normalize_interface(interface["name"])
                if each["name"] == interface["name"]:
                    in_have.add(interface["name"])
                    break
                if interface["name"] != each["name"]:
                    not_in_have.add(interface["name"])
            else:
                # We didn't find a matching desired state, which means we can
                # pretend we received an empty desired state.
                interface = dict(name=each["name"])
                kwargs = {"want": interface, "have": each}
                commands.extend(self._clear_config(**kwargs))
                continue
            have_dict = filter_dict_having_none_value(interface, each)
            commands.extend(self._clear_config(dict(), have_dict))
            commands.extend(self._set_config(interface, each, module))
        # Add the want interface that's not already configured in have interface
        for each in not_in_have - in_have:
            for every in want:
                interface = "interface {0}".format(every["name"])
                if each and interface not in commands:
                    commands.extend(self._set_config(every, {}, module))
        # Remove the duplicate interface call
        commands = remove_duplicate_interface(commands)

        return commands

    def _state_merged(self, want, have, module):
        """The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []

        for interface in want:
            interface["name"] = normalize_interface(interface["name"])
            if self.state == "rendered":
                commands.extend(self._set_config(interface, dict(), module))
            else:
                for each in have:
                    if each["name"] == interface["name"]:
                        break
                else:
                    commands.extend(
                        self._set_config(interface, dict(), module),
                    )
                    continue
                commands.extend(self._set_config(interface, each, module))

        return commands

    def _state_deleted(self, want, have):
        """The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []

        if want:
            for interface in want:
                interface["name"] = normalize_interface(interface["name"])
                for each in have:
                    if each["name"] == interface["name"] or interface["name"] in each["name"]:
                        break
                else:
                    continue
                interface = dict(name=interface["name"])
                commands.extend(self._clear_config(interface, each))
        else:
            for each in have:
                want = dict()
                commands.extend(self._clear_config(want, each))

        return commands

    def verify_diff_again(self, want, have):
        """
        Verify the IPV4 difference again as sometimes due to
        change in order of set, set difference may result into change,
        when there's actually no difference between want and have
        :param want: want_dict IPV4
        :param have: have_dict IPV4
        :return: diff
        """
        diff = False
        for each in want:
            each_want = dict(each)
            for every in have:
                every_have = dict(every)

                if each_want.get("address") == every_have.get("address"):
                    if len(each_want.keys()) == len(every_have.keys()) and (
                        each_want.get("secondary") == every_have.get("secondary")
                    ):
                        diff = False
                        break
                    if not each_want.get("secondary") and not every_have.get(
                        "secondary",
                    ):
                        diff = False
                        break

                    diff = True
                else:
                    diff = True
            if diff:
                break

        return diff

    def _set_config(self, want, have, module):
        # Set the interface config based on the want and have config
        commands = []
        interface = "interface " + want["name"]

        # To handle L3 IPV4 configuration
        if want.get("ipv4"):
            for each in want.get("ipv4"):
                if each.get("address") != "dhcp":
                    each["address"] = validate_n_expand_ipv4(module, each)

        if have.get("ipv4"):
            for each in have.get("ipv4"):
                if each.get("address") != "dhcp":
                    each["address"] = validate_n_expand_ipv4(module, each)

        # Temporarily remove 'flow' before comparison
        want_flow = want.pop("flow", None)
        have_flow = have.pop("flow", None)

        # Get the diff b/w want and have
        want_dict = dict_to_set(want)
        have_dict = dict_to_set(have)

        # To handle L3 IPV4 configuration
        want_ipv4 = dict(want_dict).get("ipv4")
        have_ipv4 = dict(have_dict).get("ipv4")
        if want_ipv4:
            if have_ipv4:
                diff_ipv4 = set(want_ipv4) - set(dict(have_dict).get("ipv4"))
                if diff_ipv4:
                    diff_ipv4 = diff_ipv4 if self.verify_diff_again(want_ipv4, have_ipv4) else ()
            else:
                diff_ipv4 = set(want_ipv4)
            for each in diff_ipv4:
                ipv4_dict = dict(each)
                if ipv4_dict.get("address") != "dhcp":
                    cmd = "ipv4 address {0}".format(ipv4_dict["address"])
                    if ipv4_dict.get("secondary"):
                        cmd += " secondary"
                    add_command_to_config_list(interface, cmd, commands)

        # To handle L3 IPV6 configuration
        want_ipv6 = dict(want_dict).get("ipv6")
        have_ipv6 = dict(have_dict).get("ipv6")
        if want_ipv6:
            if have_ipv6:
                diff_ipv6 = set(want_ipv6) - set(have_ipv6)
            else:
                diff_ipv6 = set(want_ipv6)
            for each in diff_ipv6:
                ipv6_dict = dict(each)
                validate_ipv6(ipv6_dict.get("address"), module)
                cmd = "ipv6 address {0}".format(ipv6_dict.get("address"))
                add_command_to_config_list(interface, cmd, commands)

        if want.get("load_interval"):
            if want["load_interval"] != have.get("load_interval"):
                cmd = "load-interval {0}".format(want["load_interval"])
                add_command_to_config_list(interface, cmd, commands)

        if want.get("flow_control"):
            if want["flow_control"] != have.get("flow_control"):
                cmd = "flow-control {0}".format(want["flow_control"])
                add_command_to_config_list(interface, cmd, commands)

        want_cd = want.get("carrier_delay")
        have_cd = have.get("carrier_delay")

        if want_cd and want_cd != have_cd:
            cmd_parts = ["carrier-delay"]
            want_up = want_cd.get("up")
            want_down = want_cd.get("down")
            have_up = have_cd.get("up") if have_cd else None
            have_down = have_cd.get("down") if have_cd else None

            if want_up is not None and want_up != have_up:
                cmd_parts.append("up {}".format(want_up))
            if want_down is not None and want_down != have_down:
                cmd_parts.append("down {}".format(want_down))

            if len(cmd_parts) > 1:
                cmd = " ".join(cmd_parts)
                add_command_to_config_list(interface, cmd, commands)

        dampening_want = want.get("dampening")
        dampening_have = have.get("dampening")

        if dampening_want and dampening_want != dampening_have:
            if dampening_want.get("enabled"):
                if dampening_want.get("half_life") is None:
                    cmd = "dampening"
                else:
                    cmd_parts = ["dampening"]
                    params_order = [
                        "half_life",
                        "reuse_threshold",
                        "suppress_threshold",
                        "max_suppress_time",
                        "restart_penalty",
                    ]
                    for param in params_order:
                        value = dampening_want.get(param)
                        if value is not None:
                            cmd_parts.append(str(value))
                        else:
                            break
                    cmd = " ".join(cmd_parts)
                add_command_to_config_list(interface, cmd, commands)

        if want_flow is not None or have_flow is not None:
            have_flow = have_flow or {}
            want_flow = want_flow or {}

            if self.state == "replaced" and have_flow:
                for proto in ["ipv4", "ipv6"]:
                    if proto in have_flow and proto not in want_flow:
                        have_cfg = have_flow[proto]
                        cmd = "no flow {0} monitor {1} sampler {2} {3}".format(
                            proto,
                            have_cfg["monitor"],
                            have_cfg["sampler"],
                            have_cfg["direction"],
                        )
                        add_command_to_config_list(interface, cmd, commands)

            for proto, want_cfg in want_flow.items():
                if want_cfg is None:
                    continue

                have_cfg = have_flow.get(proto, {})
                if want_cfg != have_cfg:
                    if have_cfg:
                        cmd = "no flow {0} monitor {1} sampler {2} {3}".format(
                            proto,
                            have_cfg["monitor"],
                            have_cfg["sampler"],
                            have_cfg["direction"],
                        )
                        add_command_to_config_list(interface, cmd, commands)
                    cmd = "flow {0} monitor {1} sampler {2} {3}".format(
                        proto,
                        want_cfg["monitor"],
                        want_cfg["sampler"],
                        want_cfg["direction"],
                    )
                    add_command_to_config_list(interface, cmd, commands)

        if want_flow is not None:
            want["flow"] = want_flow
        if have_flow is not None:
            have["flow"] = have_flow

        return commands

    def _clear_config(self, want, have):
        # Delete the interface config based on the want and have config
        count = 0
        commands = []
        if want.get("name"):
            interface = "interface " + want["name"]
        else:
            interface = "interface " + have["name"]

        if have.get("ipv4") and want.get("ipv4"):
            for each in have.get("ipv4"):
                if each.get("secondary") and not (want.get("ipv4")[count].get("secondary")):
                    cmd = "ipv4 address {0} secondary".format(
                        each.get("address"),
                    )
                    remove_command_from_config_list(interface, cmd, commands)
                count += 1
        if have.get("ipv4") and not (want.get("ipv4")):
            remove_command_from_config_list(
                interface,
                "ipv4 address",
                commands,
            )
        if have.get("ipv6") and not (want.get("ipv6")):
            remove_command_from_config_list(
                interface,
                "ipv6 address",
                commands,
            )

        if have.get("carrier_delay") and not (want.get("carrier_delay")):
            remove_command_from_config_list(interface, "carrier-delay", commands)

        if have.get("dampening") and not (want.get("dampening")):
            remove_command_from_config_list(interface, "dampening", commands)

        if have.get("load_interval") and not want.get("load_interval"):
            remove_command_from_config_list(interface, "load-interval", commands)

        if have.get("flow_control") and not want.get("flow_control"):
            remove_command_from_config_list(interface, "flow-control", commands)

        if have.get("flow") and not want.get("flow"):
            for proto in ["ipv4", "ipv6"]:
                if have["flow"].get(proto):
                    have_proto_flow = have["flow"][proto]
                    cmd = "no flow {0} monitor {1} sampler {2} {3}".format(
                        proto,
                        have_proto_flow["monitor"],
                        have_proto_flow["sampler"],
                        have_proto_flow["direction"],
                    )
                    add_command_to_config_list(interface, cmd, commands)

        return commands
