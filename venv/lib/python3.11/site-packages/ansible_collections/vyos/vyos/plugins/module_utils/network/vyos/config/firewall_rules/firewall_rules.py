#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The vyos_firewall_rules class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
    to_list,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.facts.facts import Facts
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.utils import (
    list_diff_want_only,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import (
    LooseVersion,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import (
    get_os_version,
    load_config,
)


class Firewall_rules(ConfigBase):
    """
    The vyos_firewall_rules class
    """

    gather_subset = [
        "!all",
        "!min",
    ]

    gather_network_resources = [
        "firewall_rules",
    ]

    def __init__(self, module):
        super(Firewall_rules, self).__init__(module)

    def get_firewall_rules_facts(self, data=None):
        """Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(
            self.gather_subset,
            self.gather_network_resources,
            data=data,
        )
        firewall_rules_facts = facts["ansible_network_resources"].get("firewall_rules")
        if not firewall_rules_facts:
            return []
        return firewall_rules_facts

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {"changed": False}
        warnings = list()
        commands = list()
        diff = None

        try:
            self._module.params["comment"]
        except KeyError:
            comment = []
        else:
            comment = self._module.params["comment"]

        if self.state in self.ACTION_STATES:
            existing_firewall_rules_facts = self.get_firewall_rules_facts()
        else:
            existing_firewall_rules_facts = []

        if self.state in self.ACTION_STATES or self.state == "rendered":
            commands.extend(self.set_config(deepcopy(existing_firewall_rules_facts)))

        if commands and self._module._diff:
            commit = not self._module.check_mode
            diff = load_config(self._module, commands, commit=commit, comment=comment)
            if diff:
                result["diff"] = {"prepared": str(diff)}

        if commands and self.state in self.ACTION_STATES:
            if not self._module.check_mode:
                self._connection.edit_config(commands)
            result["changed"] = True

        if self.state in self.ACTION_STATES:
            result["commands"] = commands

        if self.state in self.ACTION_STATES or self.state == "gathered":
            changed_firewall_rules_facts = self.get_firewall_rules_facts()
        elif self.state == "rendered":
            result["rendered"] = commands
        elif self.state == "parsed":
            running_config = self._module.params["running_config"]
            if not running_config:
                self._module.fail_json(
                    msg="value of running_config parameter must not be empty for state parsed",
                )
            result["parsed"] = self.get_firewall_rules_facts(data=running_config)
        else:
            changed_firewall_rules_facts = []

        if self.state in self.ACTION_STATES:
            result["before"] = existing_firewall_rules_facts
            if result["changed"]:
                result["after"] = changed_firewall_rules_facts
        elif self.state == "gathered":
            result["gathered"] = changed_firewall_rules_facts

        result["warnings"] = warnings
        return result

    def set_config(self, existing_firewall_rules_facts):
        """Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params["config"]
        self._prune_stubs(want)
        have = existing_firewall_rules_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, w, h):
        """Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        if self.state in ("merged", "replaced", "overridden", "rendered") and not w:
            self._module.fail_json(
                msg="value of config parameter must not be empty for state {0}".format(self.state),
            )
        if self.state == "overridden":
            commands.extend(self._state_overridden(w, h))
        elif self.state == "deleted":
            commands.extend(self._state_deleted(w, h))
        elif w:
            if self.state == "merged" or self.state == "rendered":
                commands.extend(self._state_merged(w, h))
            elif self.state == "replaced":
                commands.extend(self._state_replaced(w, h))
        return commands

    def _state_replaced(self, want, have):
        """The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        if have:
            # Iterate over the afi rule sets we already have.
            for h in have:
                r_sets = self._get_r_sets(h)
                # Iterate over each rule set we already have.
                for rs in r_sets:
                    # In the desired configuration, search for the rule set we
                    # already have (to be replaced by our desired
                    # configuration's rule set).
                    rs_id = self._rs_id(rs, h["afi"])
                    wanted_rule_set = self.search_r_sets_in_have(want, rs_id, "r_list")
                    if self._is_same_rs(remove_empties(wanted_rule_set), remove_empties(rs)):
                        continue
                    if wanted_rule_set is not None:
                        # Remove the rules that we already have if the wanted
                        # rules exist under the same name.
                        commands.extend(
                            self._add_r_sets(
                                h["afi"],
                                want=rs,
                                have=wanted_rule_set,
                                opr=False,
                            ),
                        )
        # Merge the desired configuration into what we already have.
        commands.extend(self._state_merged(want, have))
        return commands

    def _state_overridden(self, want, have):
        """The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        if have:
            for h in have:
                have_r_sets = self._get_r_sets(h)
                for rs in have_r_sets:
                    rs_id = self._rs_id(rs, h["afi"])
                    w = self.search_r_sets_in_have(want, rs_id, "r_list")
                    if self._is_same_rs(remove_empties(w), remove_empties(rs)):
                        continue
                    else:
                        commands.append(self._compute_command(rs_id, remove=True))
                        # Blank out the only rule set that it is removed.
                        for entry in have:
                            if entry["afi"] == rs_id["afi"] and rs_id["name"]:
                                entry["rule_sets"] = [
                                    rule_set
                                    for rule_set in entry["rule_sets"]
                                    if rule_set.get("name") != rs_id["name"]
                                ]
                            elif entry["afi"] == rs_id["afi"] and rs_id["filter"]:
                                entry["rule_sets"] = [
                                    rule_set
                                    for rule_set in entry["rule_sets"]
                                    if rule_set.get("filter") != rs_id["filter"]
                                ]
            commands.extend(self._state_merged(want, have))
        return commands

    def _state_merged(self, want, have):
        """The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        for w in want:
            r_sets = self._get_r_sets(w)
            for rs in r_sets:
                rs_id = self._rs_id(rs, w["afi"])
                h = self.search_r_sets_in_have(have, rs_id, "r_list")
                if self._is_same_rs(remove_empties(h), remove_empties(rs)):
                    continue
                else:
                    commands.extend(self._add_r_sets(w["afi"], rs, h))
        return commands

    def _state_deleted(self, want, have):
        """The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        if want:
            for w in want:
                r_sets = self._get_r_sets(w)
                if r_sets:
                    for rs in r_sets:
                        rs_id = self._rs_id(rs, w["afi"])
                        h = self.search_r_sets_in_have(have, rs_id, "r_list")
                        if h:
                            commands.append(self._compute_command(rs_id, remove=True))
                elif have:
                    for h in have:
                        if h["afi"] == w["afi"]:
                            commands.append(
                                self._compute_command(self._rs_id(None, w["afi"]), remove=True),
                            )
        elif have:
            for h in have:
                r_sets = self._get_r_sets(h)
                if r_sets:
                    commands.append(self._compute_command(self._rs_id(None, h["afi"]), remove=True))
        return commands

    def _add_r_sets(self, afi, want, have, opr=True):
        """
        This function forms the set/delete commands based on the 'opr' type
        for rule-sets attributes.
        :param afi: address type.
        :param want: desired config.
        :param have: target config.
        :param opr: True/False.
        :return: generated commands list.
        """
        commands = []
        l_set = ("description", "default_action", "default_jump_target", "enable_default_log")
        h_rs = {}
        h_rules = {}
        w_rs = deepcopy(remove_empties(want))
        w_rules = w_rs.pop("rules", None)
        rs_id = self._rs_id(want, afi=afi)
        if have:
            h_rs = deepcopy(remove_empties(have))
            h_rules = h_rs.pop("rules", None)
        if w_rs:
            for key, val in iteritems(w_rs):
                if opr and key in l_set and not (h_rs and self._is_w_same(w_rs, h_rs, key)):
                    if key == "enable_default_log":
                        if val and (not h_rs or key not in h_rs or not h_rs[key]):
                            commands.append(self._add_rs_base_attrib(rs_id, key, w_rs))
                    else:
                        commands.append(self._add_rs_base_attrib(rs_id, key, w_rs))
                elif not opr and key in l_set:
                    if (
                        key == "enable_default_log"
                        and val
                        and h_rs
                        and (key not in h_rs or not h_rs[key])
                    ):
                        commands.append(self._add_rs_base_attrib(rs_id, key, w_rs, opr))
                    elif not (h_rs and self._in_target(h_rs, key)):
                        commands.append(self._add_rs_base_attrib(rs_id, key, w_rs, opr))
            commands.extend(self._add_rules(rs_id, w_rules, h_rules, opr))
        if h_rules:
            have["rules"] = h_rules
        if w_rules:
            want["rules"] = w_rules
        return commands

    def _add_rules(self, rs_id, w_rules, h_rules, opr=True):
        """
        This function forms the set/delete commands based on the 'opr' type
        for rules attributes.
        :param rs_id: rule-set identifier.
        :param w_rules: desired config.
        :param h_rules: target config.
        :param opr: True/False.
        :return: generated commands list.
        """
        commands = []
        l_set = (
            "ipsec",
            "action",
            "number",
            "protocol",
            "fragment",
            "disable",
            "description",
            "jump_target",
        )
        if w_rules:
            for w in w_rules:
                cmd = self._compute_command(rs_id, w["number"], opr=opr)
                h = self.search_rules_in_have_rs(h_rules, w["number"])
                if w != h and self.state == "replaced":
                    h = {}
                for key, val in iteritems(w):
                    if val:
                        if opr and key in l_set and not (h and self._is_w_same(w, h, key)):
                            if key == "disable":
                                if not (not val and (not h or key not in h or not h[key])):
                                    commands.append(self._add_r_base_attrib(rs_id, key, w))
                            else:
                                commands.append(self._add_r_base_attrib(rs_id, key, w))
                        elif not opr:
                            # Note: if you are experiencing sticky configuration on replace
                            # you may need to add an explicit check for the key here. Anything that
                            # doesn't have a custom operation is taken care of by the `l_set` check
                            # below, but I'm not sure how any of the others work.
                            # It's possible that historically the delete was forced (but now it's
                            # checked).
                            if key == "number" and self._is_del(l_set, h):
                                commands.append(self._add_r_base_attrib(rs_id, key, w, opr=opr))
                                continue
                            if (
                                key == "tcp"
                                and val
                                and h
                                and (key not in h or not h[key] or h[key] != w[key])
                            ):
                                commands.extend(self._add_tcp(key, w, h, cmd, opr))
                            if (
                                key == "state"
                                and val
                                and h
                                and (key not in h or not h[key] or h[key] != w[key])
                            ):
                                commands.extend(self._add_state(key, w, h, cmd, opr))
                            if (
                                key == "icmp"
                                and val
                                and h
                                and (key not in h or not h[key] or h[key] != w[key])
                            ):
                                commands.extend(self._add_icmp(key, w, h, cmd, opr))
                            if (
                                key in ("packet_length", "packet_length_exclude")
                                and val
                                and h
                                and (key not in h or not h[key] or h[key] != w[key])
                            ):
                                commands.extend(self._add_packet_length(key, w, h, cmd, opr))
                            elif key == "disable" and val and h and (key not in h or not h[key]):
                                commands.append(self._add_r_base_attrib(rs_id, key, w, opr=opr))
                            if (
                                key in ("inbound_interface", "outbound_interface")
                                and val
                                and h
                                and (key not in h or not h[key] or h[key] != w[key])
                            ):
                                commands.extend(self._add_interface(key, w, h, cmd, opr))
                            elif (
                                key in l_set
                                and not (h and self._in_target(h, key))
                                and not self._is_del(l_set, h)
                            ):
                                commands.append(self._add_r_base_attrib(rs_id, key, w, opr=opr))
                        elif key == "tcp":
                            commands.extend(self._add_tcp(key, w, h, cmd, opr))
                        elif key == "time":
                            commands.extend(self._add_time(key, w, h, cmd, opr))
                        elif key == "icmp":
                            commands.extend(self._add_icmp(key, w, h, cmd, opr))
                        elif key == "state":
                            commands.extend(self._add_state(key, w, h, cmd, opr))
                        elif key == "log":
                            commands.extend(self._add_log(key, w, h, cmd, opr))
                        elif key == "limit":
                            commands.extend(self._add_limit(key, w, h, cmd, opr))
                        elif key == "recent":
                            commands.extend(self._add_recent(key, w, h, cmd, opr))
                        elif key == "destination" or key == "source":
                            commands.extend(self._add_src_or_dest(key, w, h, cmd, opr))
                        elif key in ("packet_length", "packet_length_exclude"):
                            commands.extend(self._add_packet_length(key, w, h, cmd, opr))
                        elif key in ("inbound_interface", "outbound_interface"):
                            commands.extend(self._add_interface(key, w, h, cmd, opr))
        return commands

    def _add_state(self, attr, w, h, cmd, opr):
        """
        This function forms the command for 'state' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        h_state = {}
        commands = []
        l_set = ("new", "invalid", "related", "established")
        if w[attr]:
            if h and attr in h.keys():
                h_state = h.get(attr) or {}
            for item, val in iteritems(w[attr]):
                if (
                    opr
                    and item in l_set
                    and not (h_state and self._is_w_same(w[attr], h_state, item))
                ):
                    if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
                        commands.append(cmd + (" " + attr + " " + item))
                    else:
                        commands.append(
                            cmd + (" " + attr + " " + item + " " + self._bool_to_str(val)),
                        )
                elif not opr and item in l_set and not self._in_target(h_state, item):
                    commands.append(cmd + (" " + attr + " " + item))
        return commands

    def _add_log(self, attr, w, h, cmd, opr):
        """
        This function forms the command for 'log' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        h_state = {}
        commands = []
        if w[attr]:
            if h and attr in h.keys():
                h_state = h.get(attr) or {}

            if (
                LooseVersion(get_os_version(self._module)) < LooseVersion("1.4")
                and opr
                and not (h and self._is_w_same(w, h, attr))
            ):
                commands.append(cmd + " " + attr + " '" + w[attr] + "'")
            elif (
                LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4")
                and opr
                and not (h and self._is_w_same(w, h, attr))
            ):
                commands.append(cmd + " " + attr)
            elif not opr and not self._in_target(h_state, w[attr]):
                commands.append(cmd + (" " + attr + " '" + w[attr] + "'"))

        return commands

    def _add_recent(self, attr, w, h, cmd, opr):
        """
        This function forms the command for 'recent' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        h_recent = {}
        l_set = ("count", "time")
        if w[attr]:
            if h and attr in h.keys():
                h_recent = h.get(attr) or {}
            for item, val in iteritems(w[attr]):
                if (
                    opr
                    and item in l_set
                    and not (h_recent and self._is_w_same(w[attr], h_recent, item))
                ):
                    commands.append(cmd + (" " + attr + " " + item + " " + str(val)))
                elif (
                    not opr and item in l_set and not (h_recent and self._in_target(h_recent, item))
                ):
                    commands.append(cmd + (" " + attr + " " + item))
        return commands

    def _add_icmp(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'icmp' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        h_icmp = {}
        l_set = ("code", "type", "type_name")
        if w[attr]:
            if h and attr in h.keys():
                h_icmp = h.get(attr) or {}
            for item, val in iteritems(w[attr]):
                if (
                    opr
                    and item in l_set
                    and not (h_icmp and self._is_w_same(w[attr], h_icmp, item))
                ):
                    if item == "type_name":
                        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
                            param_name = "type-name"
                        else:
                            param_name = "type"
                        if "ipv6" in cmd:  # ipv6-name or ipv6
                            commands.append(cmd + (" " + "icmpv6" + " " + param_name + " " + val))
                        else:
                            commands.append(
                                cmd + (" " + attr + " " + item.replace("_", "-") + " " + val),
                            )
                    else:
                        if "ipv6" in cmd:  # ipv6-name or ipv6
                            commands.append(cmd + (" " + "icmpv6" + " " + item + " " + str(val)))
                        else:
                            commands.append(cmd + (" " + attr + " " + item + " " + str(val)))
                elif not opr and item in l_set and not self._in_target(h_icmp, item):
                    commands.append(
                        cmd + (" " + attr + " " + item.replace("_", "-") + " " + str(val)),
                    )
        return commands

    def _add_interface(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'interface' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        h_if = {}
        l_set = ("name", "group")
        if w[attr]:
            if h and attr in h.keys():
                h_if = h.get(attr) or {}
            for item, val in iteritems(w[attr]):
                if opr and item in l_set and not (h_if and self._is_w_same(w[attr], h_if, item)):
                    commands.append(
                        cmd
                        + (" " + attr.replace("_", "-") + " " + item.replace("_", "-") + " " + val),
                    )
                elif not opr and item in l_set and not (h_if and self._in_target(h_if, item)):
                    commands.append(
                        cmd + (" " + attr.replace("_", "-") + " " + item.replace("_", "-")),
                    )
        return commands

    def _add_time(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'time' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        h_time = {}
        l_set = (
            "utc",
            "stopdate",
            "stoptime",
            "weekdays",
            "monthdays",
            "startdate",
            "starttime",
        )
        if w[attr]:
            if h and attr in h.keys():
                h_time = h.get(attr) or {}
            for item, val in iteritems(w[attr]):
                if (
                    opr
                    and item in l_set
                    and not (h_time and self._is_w_same(w[attr], h_time, item))
                ):
                    if item == "utc":
                        if not (not val and (not h_time or item not in h_time)):
                            commands.append(cmd + (" " + attr + " " + item))
                    else:
                        commands.append(cmd + (" " + attr + " " + item + " " + val))
                elif (
                    not opr
                    and item in l_set
                    and not (h_time and self._is_w_same(w[attr], h_time, item))
                ):
                    commands.append(cmd + (" " + attr + " " + item))
        return commands

    def _add_tcp_1_4(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'tcp' attributes based on the 'opr'.
        Version 1.4+
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        have = []
        key = "flags"
        want = []

        if w:
            if w.get(attr):
                want = w.get(attr).get(key) or []
        if h:
            if h.get(attr):
                have = h.get(attr).get(key) or []
        if want:
            if opr:
                flags = list_diff_want_only(want, have)
                for flag in flags:
                    invert = flag.get("invert", False)
                    commands.append(
                        cmd + (" " + attr + " flags " + ("not " if invert else "") + flag["flag"]),
                    )
            elif not opr:
                flags = list_diff_want_only(want, have)
                for flag in flags:
                    invert = flag.get("invert", False)
                    commands.append(
                        cmd + (" " + attr + " flags " + ("not " if invert else "") + flag["flag"]),
                    )
        return commands

    def _add_packet_length(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'packet_length[_exclude]' attributes based on the 'opr'.
        If < 1.4, handle tcp attributes.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        have = []
        want = []

        if w:
            if w.get(attr):
                want = w.get(attr) or []
        if h:
            if h.get(attr):
                have = h.get(attr) or []
        attr = attr.replace("_", "-")
        if want:
            if opr:
                lengths = list_diff_want_only(want, have)
                for l_rec in lengths:
                    commands.append(cmd + " " + attr + " " + str(l_rec["length"]))
            elif not opr:
                lengths = list_diff_want_only(want, have)
                for l_rec in lengths:
                    commands.append(cmd + " " + attr + " " + str(l_rec["length"]))
        return commands

    def _tcp_flags_string(self, flags):
        """
        This function forms the tcp flags string.
        :param flags: flags list.
        :return: flags string or None.
        """
        if not flags:
            return ""
        flag_str = ""
        for flag in flags:
            this_flag = flag["flag"].upper()
            if flag.get("invert", False):
                this_flag = "!" + this_flag
            if len(flag_str) > 0:
                flag_str = ",".join([flag_str, this_flag])
            else:
                flag_str = this_flag
        return flag_str

    def _add_tcp(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'tcp' attributes based on the 'opr'.
        If < 1.4, handle tcp attributes.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            return self._add_tcp_1_4(attr, w, h, cmd, opr)
        h_tcp = {}
        commands = []
        if w[attr]:
            key = "flags"
            flags = w[attr].get(key) or {}
            if flags:
                if h and key in h[attr].keys():
                    h_tcp = h[attr].get(key) or {}
                if flags:
                    flag_str = self._tcp_flags_string(flags)
                    if opr and not (h_tcp and flags == h_tcp):
                        commands.append(cmd + (" " + attr + " " + "flags" + " " + flag_str))
                    if not opr and not (h_tcp and flags == h_tcp):
                        commands.append(cmd + (" " + attr + " " + "flags" + " " + flag_str))
        return commands

    def _add_limit(self, attr, w, h, cmd, opr):
        """
        This function forms the commands for 'limit' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        h_limit = {}
        commands = []
        if w[attr]:
            key = "burst"
            if (
                opr
                and key in w[attr].keys()
                and not (h and attr in h.keys() and self._is_w_same(w[attr], h[attr], key))
            ):
                commands.append(cmd + (" " + attr + " " + key + " " + str(w[attr].get(key))))
            elif (
                not opr
                and key in w[attr].keys()
                and not (h and attr in h.keys() and self._in_target(h[attr], key))
            ):
                commands.append(cmd + (" " + attr + " " + key + " " + str(w[attr].get(key))))
            key = "rate"
            rate = w[attr].get(key) or {}
            if rate:
                if h and key in h[attr].keys():
                    h_limit = h[attr].get(key) or {}
                if "unit" in rate and "number" in rate:
                    if opr and not (
                        h_limit
                        and self._is_w_same(rate, h_limit, "unit")
                        and self._is_w_same(rate, h_limit, "number")
                    ):
                        commands.append(
                            cmd
                            + (
                                " "
                                + attr
                                + " "
                                + key
                                + " "
                                + str(rate["number"])
                                + "/"
                                + rate["unit"]
                            ),
                        )
                    if not opr and not (
                        h_limit
                        and self._is_w_same(rate, h_limit, "unit")
                        and self._is_w_same(rate, h_limit, "number")
                    ):
                        commands.append(cmd + (" " + attr + " " + key))
        return commands

    def _add_src_or_dest(self, attr, w, h, cmd, opr=True):
        """
        This function forms the commands for 'src/dest' attributes based on the 'opr'.
        :param attr: attribute name.
        :param w: base config.
        :param h: target config.
        :param cmd: commands to be prepend.
        :return: generated list of commands.
        """
        commands = []
        h_group = {}
        g_set = ("port_group", "address_group", "network_group")
        if w[attr]:
            keys = ("address", "mac_address", "port")
            for key in keys:
                if (
                    opr
                    and key in w[attr].keys()
                    and not (h and attr in h.keys() and self._is_w_same(w[attr], h[attr], key))
                ):
                    commands.append(
                        cmd + (" " + attr + " " + key.replace("_", "-") + " " + w[attr].get(key)),
                    )
                elif (
                    not opr
                    and key in w[attr].keys()
                    and not (h and attr in h.keys() and self._in_target(h[attr], key))
                ):
                    commands.append(cmd + (" " + attr + " " + key))

            key = "group"
            group = w[attr].get(key) or {}
            if group:
                h_group = {}
                if h and h.get(attr) and key in h[attr].keys():
                    h_group = h[attr].get(key)
                for item, val in iteritems(group):
                    if val:
                        if (
                            opr
                            and item in g_set
                            and not (h_group and self._is_w_same(group, h_group, item))
                        ):
                            commands.append(
                                cmd
                                + (
                                    " "
                                    + attr
                                    + " "
                                    + key
                                    + " "
                                    + item.replace("_", "-")
                                    + " "
                                    + val
                                ),
                            )
                        elif (
                            not opr
                            and item in g_set
                            and not (h_group and self._in_target(h_group, item))
                        ):
                            commands.append(
                                cmd + (" " + attr + " " + key + " " + item.replace("_", "-")),
                            )
        return commands

    def search_rules_in_have_rs(self, have_rules, r_number):
        """
        This function returns the rule if it is present in target config.
        :param have: target config.
        :param rs_id: rule-set identifier.
        :param r_number: rule-number.
        :return: rule.
        """
        if have_rules:
            key = "number"
            for r in have_rules:
                if key in r and r[key] == r_number:
                    return r
        return None

    def search_r_sets_in_have(self, have, rs_id, type="rule_sets"):
        """
        This function  returns the rule-set/rule if it is present in target config.
        :param have: target config.
        :param rs_id: rule-identifier.
        :param type: rule_sets if searching a rule_set and r_list if searching from a rule_list.
        :return: rule-set/rule.
        """
        if "afi" in rs_id:
            afi = rs_id["afi"]
        else:
            afi = None
        if rs_id["filter"]:
            key = "filter"
            w_value = rs_id["filter"]
        elif rs_id["name"]:
            key = "name"
            w_value = rs_id["name"]
        else:
            raise ValueError("id must be specific to name or filter")

        if type not in ("r_list", "rule_sets"):
            raise ValueError("type must be rule_sets or r_list")
        if have:
            if type == "r_list":
                for h in have:
                    if h["afi"] == afi:
                        r_sets = self._get_r_sets(h)
                        for rs in r_sets:
                            if key in rs and rs[key] == w_value:
                                return rs
            else:
                # searching a ruleset
                for rs in have:
                    if key in rs and rs[key] == w_value:
                        return rs
        return None

    def _get_r_sets(self, item):
        """
        This function returns the list of rule-sets.
        :param item: config dictionary.
        :return: list of rule-sets/rules.
        """
        rs_list = []
        type = "rule_sets"
        r_sets = item[type]
        if r_sets:
            for rs in r_sets:
                rs_list.append(rs)
        return rs_list

    def _compute_command(
        self,
        rs_id,
        number=None,
        attrib=None,
        value=None,
        remove=False,
        opr=True,
    ):
        """
        This function construct the add/delete command based on passed attributes.
        :param rs_id: rule-set identifier.
        :param number: rule-number.
        :param attrib: attribute name.
        :param value: value.
        :param remove: True if delete command needed to be construct.
        :param opr: operation flag.
        :return: generated command.
        """
        if rs_id["name"] and rs_id["filter"]:
            raise ValueError("name and filter cannot be used together")
        if remove or not opr:
            cmd = "delete firewall " + self._get_fw_type(rs_id["afi"])
        else:
            cmd = "set firewall " + self._get_fw_type(rs_id["afi"])
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            if rs_id["name"]:
                cmd += " name " + rs_id["name"]
            elif rs_id["filter"]:
                cmd += " " + rs_id["filter"] + " filter"
        elif rs_id["name"]:
            cmd += " " + rs_id["name"]
        if number:
            cmd += " rule " + str(number)
        if attrib:
            if (
                LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4")
                and attrib == "enable_default_log"
            ):
                cmd += " " + "default-log"
            else:
                cmd += " " + attrib.replace("_", "-")
        if value and opr and attrib != "enable_default_log" and attrib != "disable":
            cmd += " '" + str(value) + "'"
        return cmd

    def _add_r_base_attrib(self, rs_id, attr, rule, opr=True):
        """
        This function forms the command for 'rules' attributes which doesn't
        have further sub attributes.
        :param rs_id: rule-set identifier.
        :param attrib: attribute name
        :param rule: rule config dictionary.
        :param opr: True/False.
        :return: generated command.
        """
        if attr == "number":
            command = self._compute_command(rs_id, number=rule["number"], opr=opr)
        else:
            command = self._compute_command(
                rs_id=rs_id,
                number=rule["number"],
                attrib=attr,
                value=rule[attr],
                opr=opr,
            )
        return command

    def _rs_id(self, have, afi, name=None, filter=None):
        """
        This function returns the rule-set identifier based on
        the example rule, overriding the components as specified.

        :param have: example rule.
        :param afi: address type.
        :param name: rule-set name.
        :param filter: filter name.
        :return: rule-set identifier.
        """
        identifier = {"name": None, "filter": None}
        if afi:
            identifier["afi"] = afi
        else:
            raise ValueError("afi must be provided")

        if name:
            identifier["name"] = name
            return identifier
        elif filter:
            identifier["filter"] = filter
            return identifier
        if have:
            if "name" in have and have["name"]:
                identifier["name"] = have["name"]
                return identifier
            if "filter" in have and have["filter"]:
                identifier["filter"] = have["filter"]
                return identifier
        # raise ValueError("name or filter must be provided or present in have")
        # unless we want a wildcard
        return identifier

    def _add_rs_base_attrib(self, rs_id, attrib, rule, opr=True):
        """

        This function forms the command for 'rule-sets' attributes which don't
        have further sub attributes.

        :param rs_id: rule-set identifier.
        :param attrib: attribute name
        :param rule: rule config dictionary.
        :param opr: True/False.
        :return: generated command.
        """
        command = self._compute_command(
            rs_id=rs_id,
            attrib=attrib,
            value=rule[attrib],
            opr=opr,
        )
        return command

    def _bool_to_str(self, val):
        """
        This function converts the bool value into string.
        :param val: bool value.
        :return: enable/disable.
        """
        return "enable" if val else "disable"

    def _get_fw_type(self, afi):
        """
        This function returns the firewall rule-set type based on IP address.
        :param afi: address type
        :return: rule-set type.
        """
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            return "ipv6" if afi == "ipv6" else "ipv4"
        return "ipv6-name" if afi == "ipv6" else "name"

    def _is_del(self, l_set, h, key="number"):
        """
        This function checks whether rule needs to be deleted based on
        the rule number.
        :param l_set: attribute set.
        :param h: target config.
        :param key: number.
        :return: True/False.
        """
        return key in l_set and not (h and self._in_target(h, key))

    def _is_w_same(self, w, h, key):
        """
        This function checks whether the key value is same in base and
        target config dictionary.
        :param w: base config.
        :param h: target config.
        :param key:attribute name.
        :return: True/False.
        """
        return True if h and key in h and h[key] == w[key] else False

    def _in_target(self, h, key):
        """
        This function checks whether the target exists and key present in target config.
        :param h: target config.
        :param key: attribute name.
        :return: True/False.
        """
        return True if h and key in h else False

    def _prune_stubs(self, rs):
        if isinstance(rs, list):
            for item in rs:
                self._prune_stubs(item)
        elif isinstance(rs, dict):
            keys_to_remove = [
                key
                for key, value in rs.items()
                if (
                    (key == "disable" and value is False)
                    or (
                        key == "log"
                        and value == "disable"
                        and LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4")
                    )
                    or (
                        key in ["new", "invalid", "related", "established"]
                        and value is False
                        and LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4")
                    )
                )
            ]
            for key in keys_to_remove:
                del rs[key]
            for key in rs:
                self._prune_stubs(rs[key])

    def _is_same_rs(self, w, rs):
        if isinstance(w, dict) and isinstance(rs, dict):
            if w.keys() != rs.keys():
                return False
            for key in w:
                if not self._is_same_rs(w[key], rs[key]):
                    return False
            return True
        elif isinstance(w, list) and isinstance(rs, list):
            try:
                def comparison(x):
                    if 'name' in x:
                        return x['name']
                    if 'number' in x:
                        return x['number']
                    return str(x)

                sorted_list1 = sorted(w, key=comparison)
                sorted_list2 = sorted(rs, key=comparison)
            except TypeError:
                return False
            if len(sorted_list1) != len(sorted_list2):
                return False
            return all(self._is_same_rs(x, y) for x, y in zip(sorted_list1, sorted_list2))
        else:
            return w == rs
