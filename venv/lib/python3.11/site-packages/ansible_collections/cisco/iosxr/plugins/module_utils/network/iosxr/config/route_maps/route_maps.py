#
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_route_maps config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.facts.facts import Facts
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.route_maps import (
    Route_mapsTemplate,
)


class Route_maps(ResourceModule):
    """
    The iosxr_route_maps config class
    """

    def __init__(self, module):
        super(Route_maps, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="route_maps",
            tmplt=Route_mapsTemplate(),
        )
        self.parsers = [
            "add.eigrp_metric",
            "add.rip_metric",
            "drop",
            "pass",
            "prepend",
            "suppress_route",
            "unsuppress_route",
            "remove",
            "set.administrative_distance",
            "set.local_preference",
            "set.aigp_metric",
            "set.attribute_set",
            "set.c_multicast_routing",
            "set.community",
            "set.core_tree",
            "set.dampening",
            "set.downstream_core_tree",
            "set.eigrp_metric",
            "set.fallback_vrf_lookup",
            "set.flow_tag",
            "set.forward_class",
            "set.ip_precedence",
            "set.isis_metric",
            "set.label",
            "set.label_index",
            "set.label_mode",
            "set.large_community",
            "set.level",
            "set.load_balance",
            "set.lsm_root",
            "set.metric_type",
            "set.mpls",
            "set.med",
            "set.extcommunity",
            "set.next_hop",
            "set.origin",
            "set.ospf_metric",
            "set.path_selection.all",
            "set.path_selection.backup",
            "set.path_selection.best_path",
            "set.path_selection.group_best",
            "set.path_selection.multiplath",
            "set.path_color",
            "set.qos_group",
            "set.rib_metric",
            "set.rip_metric",
            "set.rip_tag",
            "set.rt_set",
            "set.s_pmsi",
            "set.spf_priority",
            "set.static_p2mp_te",
            "set.tag",
            "set.traffic_index",
            "set.upstream_core_tree",
            "set.vpn_distinguisher",
            "set.weight",
        ]

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        if self.state not in ["parsed", "gathered"]:
            self.generate_commands()
            self.run_commands()
        return self.result

    def generate_commands(self):
        """Generate configuration commands to send based on
        want, have and desired state.
        """
        wantd = self._route_maps_list_to_dict(self.want)
        haved = self._route_maps_list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)
        for k, want in wantd.items():
            if self.state == "purged":  # for purged state
                if haved.pop(k, {}):
                    self._handle_purged(k)
            else:  # for all other states
                self._compare(want=want, have=haved.pop(k, {}), policy_name=k)

        # clean anything that is surplus, if state purged clean all have if want is empty
        if self.state == "overridden" or (self.state == "purged" and not wantd):
            for h, haved in haved.items():
                self._handle_purged(h)

    def _handle_purged(self, policy_name):
        self.commands.append(f"no route-policy {policy_name}")

    def _compare(self, want, have, policy_name):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Route_maps network resource.
        """
        append_endif = False
        append_nested_endif = False
        append_else_once = True
        order_list = [
            "global",
            "if_section_",
            "elseif_section_",
            "elseHas_global_",
            "elseHas_if_section_",
            "elseHas_elseif_section_",
            "elseHas_else_section_",
        ]  # to maintain the sanity of how commands are generated
        begin = len(self.commands)

        for check_cond in order_list:  # iterate on the list to preserve sequence
            w_res = {key: val for key, val in want.items() if key.startswith(check_cond)}

            for w_condition, w_policy_config in w_res.items():  # loop over want's condition section
                h_policy_config = have.pop(w_condition, {})

                # if want clauses and have clauses are not same
                if w_policy_config != h_policy_config:
                    if self.state in ["replaced", "overridden"]:
                        # cannot add commands on a adhoc manner it replaces the whole config
                        h_policy_config = {}

                    render_condition = {
                        "condition": w_policy_config.pop("condition", ""),
                        "condition_type": w_policy_config.pop("conf_type").split("_section")[0],
                    }  # required to generate conditional statements

                    begin_endif = len(self.commands)  # handle elseif conditions

                    if check_cond.startswith("elseHas_"):
                        # adds else only once if there is else block
                        if append_else_once:
                            self.commands.append("else")
                            append_else_once = False

                    if render_condition.get("condition_type") != "global":
                        self.addcmd(
                            render_condition,
                            "condition",
                            negate=False,
                        )  # condition commands added here
                    if w_policy_config.get("apply"):  # as apply is a list
                        w_apply_config = w_policy_config.pop("apply", {})
                        h_apply_config = h_policy_config.pop("apply", {})
                        for w_name, w_apply in w_apply_config.items():
                            h_apply = h_apply_config.pop(w_name, {})
                            # apply config added here
                            self.compare(
                                parsers=[
                                    "apply",
                                ],
                                want={"apply": w_apply},
                                have={"apply": h_apply},
                            )
                    # route-policy configs added here
                    self.compare(parsers=self.parsers, want=w_policy_config, have=h_policy_config)
                    if len(self.commands) != begin_endif and w_condition.startswith("if_section_"):
                        # if we want to add any condition we have to start with if
                        append_endif = True
                    if len(self.commands) != begin_endif and w_condition.startswith(
                        "elseHas_if_section_",
                    ):
                        append_nested_endif = True  # same as above

        if len(self.commands) != begin:
            if append_nested_endif:  # add endif if there was a nested else
                self.commands.append("endif")
            if append_endif:  # add endif if there was a condition in the top level config
                self.commands.append("endif")
            self.commands.append("end-policy")  # if route-policy then end-policy
            self.commands.insert(
                begin,
                f"route-policy {policy_name}",
            )  # the name of the route-policy

    def _route_maps_list_to_dict(self, data):
        temp_rmap_list = dict()

        def process_apply(apply_conf):
            rm_apply = {}
            for apply_config in apply_conf:
                rm_apply[apply_config.get("route_policy")] = apply_config
            return rm_apply

        for rmap in data:
            temp_rmap = dict()
            rmap_name = ""
            for cond, rm_conf in rmap.items():
                if cond == "name":
                    rmap_name = rm_conf
                    temp_rmap["name"] = rmap_name
                elif cond in ["if_section", "global"]:
                    if rm_conf.get("apply"):
                        rm_conf["apply"] = process_apply(rm_conf.get("apply"))
                    rm_conf["conf_type"] = cond
                    if cond == "global":
                        temp_rmap[cond] = rm_conf
                    else:
                        temp_rmap[cond + "_" + (rm_conf.get("condition").replace(" ", "_"))] = (
                            rm_conf
                        )
                elif cond == "elseif_section":
                    for elif_config in rm_conf:
                        if elif_config.get("apply"):
                            elif_config["apply"] = process_apply(elif_config.get("apply"))
                        elif_config["conf_type"] = cond
                        temp_rmap[cond + "_" + (elif_config.get("condition").replace(" ", "_"))] = (
                            elif_config
                        )
                elif (
                    cond == "else_section"
                ):  # wanted to do recursion but the overall performance is better this way
                    for else_cond, else_rm_conf in rm_conf.items():
                        if else_cond in ["if_section", "global", "else_section"]:
                            if else_rm_conf.get("apply"):
                                else_rm_conf["apply"] = process_apply(else_rm_conf.get("apply"))
                            else_rm_conf["conf_type"] = else_cond
                            if else_cond in ["global", "else_section"]:
                                temp_rmap["elseHas_" + else_cond + "_"] = else_rm_conf
                            else:
                                temp_rmap[
                                    "elseHas_"
                                    + else_cond
                                    + "_"
                                    + (else_rm_conf.get("condition").replace(" ", "_"))
                                ] = else_rm_conf
                        elif else_cond == "elseif_section":
                            for elif_config in else_rm_conf:
                                if elif_config.get("apply"):
                                    elif_config["apply"] = process_apply(elif_config.get("apply"))
                                elif_config["conf_type"] = "elseif_section"
                                temp_rmap[
                                    "elseHas_"
                                    + else_cond
                                    + "_"
                                    + (elif_config.get("condition").replace(" ", "_"))
                                ] = elif_config
            if temp_rmap:
                temp_rmap_list[rmap_name] = temp_rmap
        return temp_rmap_list
