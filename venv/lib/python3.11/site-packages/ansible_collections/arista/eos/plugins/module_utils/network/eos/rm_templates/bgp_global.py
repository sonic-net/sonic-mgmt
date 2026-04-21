# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Bgp_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""
import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_router_bgp_cmd(config_data):
    command = "router bgp {as_number}".format(**config_data)
    return command


def _tmplt_bgp_vrf(config_data):
    command = "vrf {vrf}".format(**config_data)
    return command


def _tmplt_bgp_aggregate_address(config_data):
    command = "aggregate-address {address}".format(**config_data)
    if config_data.get("as_set"):
        command += " as-set"
    if config_data.get("summary_only"):
        command += " summary-only"
    if config_data.get("attribute_map"):
        command += " attribute-map {attribute_map}".format(**config_data)
    if config_data.get("match_map"):
        command += " match-map {match_map}".format(**config_data)
    if config_data.get("advertise_only"):
        command += " advertise-only"
    return command


def _tmplt_bgp_params(config_data):
    command = "bgp"
    if config_data["bgp_params"].get("additional_paths"):
        command += " additional-paths " + config_data["bgp_params"]["additional_paths"]
        if config_data["bgp_params"]["additional_paths"] == "send":
            command += " any"
    elif config_data["bgp_params"].get("advertise_inactive"):
        command += " advertise-inactive"
    elif config_data["bgp_params"].get("allowas_in"):
        command += " allowas-in"
        if config_data["bgp_params"]["allowas_in"].get("count"):
            command += " {count}".format(**config_data["bgp_params"]["allowas_in"])
    elif config_data["bgp_params"].get("always_compare_med"):
        command += " always-compare-med"
    elif config_data["bgp_params"].get("asn"):
        command += " asn notaion {asn}".format(**config_data["bgp_params"])
    elif config_data["bgp_params"].get("auto_local_addr"):
        command += " auto-local-addr"
    elif config_data["bgp_params"].get("bestpath"):
        if config_data["bgp_params"]["bestpath"].get("as_path"):
            command += " bestpath as-path {as_path}".format(**config_data["bgp_params"]["bestpath"])
        elif config_data["bgp_params"]["bestpath"].get("ecmp_fast"):
            command += " bestpath ecmp-fast"
        elif config_data["bgp_params"]["bestpath"].get("med"):
            command += " bestpath med"
            if config_data["bgp_params"]["bestpath"]["med"].get("confed"):
                command += " confed"
            else:
                command += " missing-as-worst"
        elif config_data["bgp_params"]["bestpath"].get("skip"):
            command += " bestpath skip next-hop igp-cost"
        elif config_data["bgp_params"]["bestpath"].get("tie_break"):
            tie = re.sub(
                r"_",
                r"-",
                config_data["bgp_params"]["bestpath"]["tie_break"],
            )
            command += " tie-break " + tie
    elif config_data["bgp_params"].get("client_to_client"):
        command += " client-to-client reflection"
    elif config_data["bgp_params"].get("cluster_id"):
        command += " cluster-id {cluster_id}".format(**config_data["bgp_params"])
    elif config_data["bgp_params"].get("confederation"):
        command += " confederation"
        if config_data["bgp_params"]["confederation"].get("identifier"):
            command += " identifier " + config_data["bgp_params"]["confederation"]["identifier"]
        else:
            command += " peers {peers}".format(**config_data["bgp_params"]["confederation"])
    elif config_data["bgp_params"].get("control_plane_filter"):
        command += " control-plane-filter default-allow"
    elif config_data["bgp_params"].get("convergence"):
        command += " convergence"
        if config_data["bgp_params"]["convergence"].get("slow_peer"):
            command += " slow-peer"
        command += " time {time}".format(**config_data["bgp_params"]["convergence"])
    elif config_data["bgp_params"].get("default"):
        command += " default {default}".format(**config_data["bgp_params"])
    elif config_data["bgp_params"].get("enforce_first_as"):
        command += " enforce-first-as"
    elif config_data["bgp_params"].get("host_routes"):
        command += " host-routes fib direct-install"
    elif config_data["bgp_params"].get("labeled_unicast"):
        command += " labeled-unicast rib {labeled_unicast}".format(**config_data["bgp_params"])
    elif config_data["bgp_params"].get("listen"):
        # from eos 4.23 , 'bgp listen limit ' is replaced by 'dynamic peer max'.
        command = "dynamic peer max "
        if config_data["bgp_params"]["listen"].get("limit"):
            command += "{limit}".format(**config_data["bgp_params"]["listen"])
        else:
            command += " range {address} peer group".format(
                **config_data["bgp_params"]["listen"]["range"],
            )
            if config_data["bgp_params"]["listen"]["range"]["peer_group"].get(
                "peer_filter",
            ):
                command += " {name} peer-filter {peer_filter}".format(
                    **config_data["bgp_params"]["listen"]["range"]["peer_group"],
                )
            else:
                command += " {name} remote-as {remote_as}".format(
                    **config_data["bgp_params"]["listen"]["range"]["peer_group"],
                )
    elif config_data["bgp_params"].get("log_neighbor_changes"):
        command += " log-neighbor-changes"
    elif config_data["bgp_params"].get("missing_policy"):
        command += " missing-policy direction {direction} action {action}".format(
            **config_data["bgp_params"]["missing_policy"],
        )
    elif config_data["bgp_params"].get("monitoring"):
        command += " monitoring"
    elif config_data["bgp_params"].get("next_hop_unchanged"):
        command += " next-hop-unchanged"
    elif config_data["bgp_params"].get("redistribute_internal"):
        command += " redistribute-internal"
    elif config_data["bgp_params"].get("route"):
        command += " route install-map {route}".format(**config_data["bgp_params"])
    elif config_data["bgp_params"].get("route_reflector"):
        command += " route-reflector preserve-attributes"
        if config_data["bgp_params"]["route_reflector"].get("preserve"):
            command += " always"
    elif config_data["bgp_params"].get("transport"):
        command += " transport listen-port {transport}".format(**config_data["bgp_params"])
    return command


def _tmplt_bgp_redistribute(config_data):
    command = "redistribute {protocol}".format(**config_data)
    if config_data.get("isis_level"):
        command += " {isis_level}".format(**config_data)
    if config_data.get("ospf_route"):
        if config_data["ospf_route"] == "nssa_external_2":
            route = "nssa-external 2"
        elif config_data["ospf_route"] == "nssa_external_1":
            route = "nssa-external 1"
        else:
            route = config_data["ospf_route"]
        command += " match " + route
    if config_data.get("route_map"):
        command += " route-map {route_map}".format(**config_data)
    return command


def _tmplt_bgp_default_metric(config_data):
    command = "default-metric {default_metric}".format(**config_data)
    return command


def _tmplt_bgp_distance(config_data):
    command = "distance bgp"
    if config_data["distance"].get("external"):
        command += " {external}".format(**config_data["distance"])
    if config_data["distance"].get("internal"):
        command += " {internal}".format(**config_data["distance"])
    if config_data["distance"].get("local"):
        command += " {local}".format(**config_data["distance"])
    return command


def _tmplt_bgp_graceful_restart(config_data):
    command = "graceful-restart"
    if config_data.get("restart_time"):
        command += " restart-time {restart_time}".format(**config_data)
    if config_data.get("stalepath_time"):
        command += " stalepath-time {stalepath_time}".format(**config_data)
    return command


def _tmplt_bgp_graceful_restart_helper(config_data):
    command = "graceful-restart-helper"
    return command


def _tmplt_bgp_access_group(config_data):
    if config_data.get("afi") == "ipv4":
        afi = "ip"
    else:
        afi = "ipv6"
    command = afi + " access-group {acl_name}".format(**config_data)
    if config_data.get("direction"):
        command += " {direction}".format(**config_data)
    return command


def _tmplt_bgp_maximum_paths(config_data):
    command = "maximum-paths {max_equal_cost_paths}".format(**config_data["maximum_paths"])
    if config_data["maximum_paths"].get("max_installed_ecmp_paths"):
        command += " ecmp {max_installed_ecmp_paths}".format(**config_data["maximum_paths"])
    return command


def _tmplt_bgp_monitoring(config_data):
    cmd = "monitoring"
    command = ""
    if config_data.get("timestamp"):
        command = cmd + " timestamp {timestamp}".format(**config_data)
    if config_data.get("port"):
        command = cmd + " port {port}".format(**config_data)
    if config_data.get("received"):
        command = cmd + " received routes {received}".format(**config_data)
    if config_data.get("station"):
        command = cmd + " station {station}".format(**config_data)
    return command


def _tmplt_bgp_neighbor(config_data):
    command = "neighbor {neighbor_address}".format(**config_data["neighbor"])
    if config_data["neighbor"].get("additional_paths"):
        command += " additional-paths {additional_paths}".format(**config_data["neighbor"])
        if config_data["neighbor"]["additional_paths"] == "send":
            command += "any"
    elif config_data["neighbor"].get("peer_group"):
        command += " peer group"
        if config_data["neighbor"]["peer_group"] != config_data["neighbor"]["peer_group"]:
            command += config_data["neighbor"]["peer_group"]
    elif config_data["neighbor"].get("allowas_in"):
        command += " allowas-in"
        if config_data["neighbor"]["allowas_in"].get("count"):
            command += " {count}".format(**config_data["neighbor"]["allowas_in"])
    elif config_data["neighbor"].get("auto_local_addr"):
        command += " auto-local-addr"
    elif config_data["neighbor"].get("bfd"):
        command += " bfd"
        if config_data["neighbor"]["bfd"] == "c_bit":
            command += " c-bit"
    elif config_data["neighbor"].get("default_originate"):
        command += " default-originate"
        if config_data["neighbor"]["default_originate"].get("route_map"):
            command += " route-map {route_map}".format(
                **config_data["neighbor"]["default_originate"],
            )
        if config_data["neighbor"]["default_originate"].get("always"):
            command += " always"
    elif config_data["neighbor"].get("description"):
        command += " description {description}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("dont_capability_negotiate"):
        command += " dont-capability-negotiate"
    elif config_data["neighbor"].get("ebgp_multihop"):
        command += " ebgp-multihop"
        if config_data["neighbor"]["ebgp_multihop"].get("ttl"):
            command += " {ttl}".format(**config_data["neighbor"]["ebgp_multihop"])
    elif config_data["neighbor"].get("encryption_password"):
        command += " password {type} {password}".format(
            **config_data["neighbor"]["encryption_password"],
        )
    elif config_data["neighbor"].get("enforce_first_as"):
        command += " enforce-first-as"
    elif config_data["neighbor"].get("export_localpref"):
        command += " export-localpref {export_localpref}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("fall_over"):
        command += " fall-over bfd"
    elif config_data["neighbor"].get("graceful_restart"):
        command += " graceful-restart"
    elif config_data["neighbor"].get("graceful_restart_helper"):
        command += " graceful-restart-helper"
    elif config_data["neighbor"].get("idle_restart_timer"):
        command += " idle-restart-timer {idle_restart_timer}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("import_localpref"):
        command += " import-localpref {import_localpref}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("link_bandwidth"):
        command += " link-bandwidth"
        if config_data["neighbor"]["link_bandwidth"].get("auto"):
            command += " auto"
        if config_data["neighbor"]["link_bandwidth"].get("default"):
            command += " default {default}".format(**config_data["neighbor"]["link_bandwidth"])
        if config_data["neighbor"]["link_bandwidth"].get("update_delay"):
            command += " update-delay {update_delay}".format(
                **config_data["neighbor"]["link_bandwidth"],
            )
    elif config_data["neighbor"].get("local_as"):
        command += " local-as {as_number} no-prepend replace-as".format(
            **config_data["neighbor"]["local_as"],
        )
        if config_data["neighbor"]["local_as"].get("fallback"):
            command += " fallback"
    elif config_data["neighbor"].get("local_v6_addr"):
        command += " local-v6-addr {local_v6_addr}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("maximum_accepted_routes"):
        command += " maximum-accepted-routes {count}".format(
            **config_data["neighbor"]["maximum_accepted_routes"],
        )
        if config_data["neighbor"]["maximum_accepted_routes"].get(
            "warning_limit",
        ):
            command += " warning-limit {warning_limit}".format(
                **config_data["neighbor"]["maximum_accepted_routes"],
            )
    elif config_data["neighbor"].get("maximum_received_routes"):
        command += " maximum-routes {count}".format(
            **config_data["neighbor"]["maximum_received_routes"],
        )
        if config_data["neighbor"]["maximum_received_routes"].get(
            "warning_limit",
        ):
            if config_data["neighbor"]["maximum_received_routes"]["warning_limit"].get(
                "limit_count",
            ):
                command += " warning-limit {limit_count}".format(
                    **config_data["neighbor"]["maximum_received_routes"]["warning_limit"],
                )
            if config_data["neighbor"]["maximum_received_routes"]["warning_limit"].get(
                "limit_percent",
            ):
                command += (
                    " warning-limit "
                    + str(
                        config_data["neighbor"]["maximum_received_routes"]["warning_limit"][
                            "limit_percent"
                        ],
                    )
                    + " percent"
                )
        if config_data["neighbor"]["maximum_received_routes"].get(
            "warning_only",
        ):
            command += " warning-only"
    elif config_data["neighbor"].get("metric_out"):
        command += " metric-out {metric_out}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("monitoring"):
        command += " monitoring"
    elif config_data["neighbor"].get("next_hop_self"):
        command += " next-hop-self"
    elif config_data["neighbor"].get("next_hop_unchanged"):
        command += " next-hop-unchanged"
    elif config_data["neighbor"].get("next_hop_v6_address"):
        command += " next-hop-v6-addr {next_hop_v6_address} in".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("out_delay"):
        command += " out-delay {out_delay}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("remote_as"):
        command += " remote-as {remote_as}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("remove_private_as"):
        command += " remove-private-as"
        if config_data["neighbor"]["remove_private_as"].get("all"):
            command += " all"
        if config_data["neighbor"]["remove_private_as"].get("replace_as"):
            command += " replace-as"
    elif config_data["neighbor"].get("peer_as"):
        command += " peer-as {peer_as}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("prefix_list"):
        command += " prefix-list {name} {direction}".format(
            **config_data["neighbor"]["prefix_list"],
        )
    elif config_data["neighbor"].get("route_map"):
        command += " route-map {name} {direction}".format(**config_data["neighbor"]["route_map"])
    elif config_data["neighbor"].get("route_reflector_client"):
        command += " route-reflector-client"
    elif config_data["neighbor"].get("route_to_peer"):
        command += " route-to-peer"
    elif config_data["neighbor"].get("send_community"):
        command += " send-community"
        if config_data["neighbor"]["send_community"].get(
            "community_attribute",
        ):
            command += " " + config_data["neighbor"]["send_community"]["community_attribute"]
        if config_data["neighbor"]["send_community"].get("sub_attribute"):
            command += " " + config_data["neighbor"]["send_community"]["sub_attribute"]
        if config_data["neighbor"]["send_community"].get(
            "link_bandwidth_attribute",
        ):
            command += " " + config_data["neighbor"]["send_community"]["link_bandwidth_attribute"]
        if config_data["neighbor"]["send_community"].get("speed"):
            command += " " + config_data["neighbor"]["send_community"]["speed"]
        if config_data["neighbor"]["send_community"].get("divide"):
            command += " " + config_data["neighbor"]["send_community"]["divide"]
    elif config_data["neighbor"].get("shutdown"):
        command += " shutdown"
    elif config_data["neighbor"].get("soft_reconfiguration"):
        command += " soft-reconfiguration inbound"
        if config_data["neighbor"]["soft_reconfiguration"] == "all":
            command += " all"
    elif config_data["neighbor"].get("transport"):
        command += " transport"
        if config_data["neighbor"]["transport"].get("connection_mode"):
            command += " connection-mode passive"
        else:
            command += " remote-port {remote_port}".format(**config_data["neighbor"]["transport"])
    elif config_data["neighbor"].get("timers"):
        command += " timers {keepalive} {holdtime}".format(**config_data["neighbor"]["timers"])
    elif config_data["neighbor"].get("ttl"):
        command += " ttl maximum-hops {ttl}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("update_source"):
        command += " update-source {update_source}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("weight"):
        command += " weight {weight}".format(**config_data["neighbor"])
    return command


def _tmplt_bgp_network(config_data):
    command = "network {address}".format(**config_data)
    if config_data.get("route_map"):
        command += " route-map {route_map}".format(**config_data)
    return command


def _tmplt_bgp_route_target(config_data):
    command = "route-target {action}".format(**config_data["route_target"])
    if config_data["route_target"].get("type"):
        command += " {type}".format(**config_data["route_target"])
    if config_data["route_target"].get("route_map"):
        command += " {route_map}".format(**config_data["route_target"])
    if config_data["route_target"].get("imported_route"):
        command += " imported-route"
    if config_data["route_target"].get("target"):
        command += " {target}".format(**config_data["route_target"])

    return command


def _tmplt_bgp_router_id(config_data):
    command = "router-id {router_id}".format(**config_data)
    return command


def _tmplt_bgp_shutdown(config_data):
    return "shutdown"


def _tmplt_bgp_timers(config_data):
    command = "timers bgp {keepalive} {holdtime}".format(**config_data["timers"])
    return command


def _tmplt_bgp_ucmp(config_data):
    command = "ucmp"
    if "fec" in config_data["ucmp"]:
        command += " fec threshold trigger"
        command += " {trigger} clear {clear} warning-only".format(**config_data["ucmp"]["fec"])
    if "link_bandwidth" in config_data["ucmp"]:
        command += " link-bandwidth {mode}".format(**config_data["ucmp"]["link_bandwidth"])
        if config_data["ucmp"]["link_bandwidth"].get("mode") == "update_delay":
            command += " {update_delay}".format(**config_data["ucmp"]["link_bandwidth"])
    if "mode" in config_data["ucmp"]:
        command += " mode 1"
        if config_data["ucmp"]["mode"].get("nexthops"):
            command += " {nexthops}".format(**config_data["ucmp"]["mode"])
    return command


def _tmplt_bgp_update(config_data):
    command = "update {wait_for}".format(**config_data["update"])
    if config_data["update"].get("batch_size"):
        command += " {batch_size}".format(**config_data["update"])
    return command


def _tmplt_bgp_vlan(config_data):
    command = "vlan {vlan}".format(**config_data)
    return command


def _tmplt_bgp_vlan_aware_bundle(config_data):
    command = "vlan-aware-bundle " + config_data["vlan_aware_bundle"]
    return command


class Bgp_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Bgp_globalTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "router",
            "getval": re.compile(
                r"""
                ^router\s
                bgp
                \s(?P<as_num>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_router_bgp_cmd,
            "compval": "as_number",
            "result": {"as_number": "{{ as_num }}"},
        },
        {
            "name": "vrf",
            "getval": re.compile(
                r"""
                \s*vrf
                \s(?P<vrf>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_vrf,
            "compval": "vrfs.vrf",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "vrf": "{{ vrf }}",
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "aggregate_address",
            "getval": re.compile(
                r"""
                \s*aggregate-address
                \s+(?P<address>\S+)
                \s*(?P<as_set>as-set)*
                \s*(?P<summary_only>summary-only)*
                \s*(?P<attribute_map>attribute-map\s\S+)*
                \s*(?P<match_map>match-map\s\S+)*
                \s*(?P<advertise_only>advertise-only)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_aggregate_address,
            "compval": "aggregate_address",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "aggregate_address": [
                            {
                                "address": "{{ address }}",
                                "advertise_only": "{{ True if advertise_only is defined }}",
                                "as_set": "{{ True if as_set is defined }}",
                                "summary_only": "{{ True if summary_only is defined }}",
                                "attribute_map": "{{ attribute_map.split(" ")[1] }}",
                                "match_map": "{{ match_map.split(" ")[1] }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "bgp_params_additional_paths",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+additional-paths
                \s+(?P<action>\S+)
                \s*(any)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.additional_paths",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "additional_paths": "{{ action }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_advertise_inactive",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+advertise-inactive
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.advertise_inactive",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "advertise_inactive": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_allowas_in",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+allowas-in
                \s*(?P<count>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.allowas_in",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "allowas_in": {
                                "set": "{{ True if count is undefined }}",
                                "count": "{{ count }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_always_compare_med",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+always-compare-med
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.always_compare_med",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "always_compare_med": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_asn",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+asn
                \s+notation
                \s+(?P<notation>asdot|asplain)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.asn",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "asn": "{{ notation }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_auto_local_addr",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+auto-local-addr
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.auto_local_addr",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "auto_local_addr": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_bestpath_as_path",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+bestpath
                \s*(?P<as_path>as-path\s\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.bestpath.as_path",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "bestpath": {
                                "as_path": "{{ as_path.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_bestpath_ecmp_fast",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+bestpath
                \s+ecmp-fast
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.bestpath.ecmp_fast",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "bestpath": {
                                "ecmp_fast": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_bestpath_med",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+bestpath
                \s+med
                \s*(?P<confed>confed)*
                \s*(?P<missing>missing-as-worst)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.bestpath.med",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "med": {
                                "confed": "{{ True if confed is defined }}",
                                "missing_as_worst": "{{ True if missing is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_bestpath_skip",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+bestpath
                \s+(?P<skip>skip)
                \s+next-hop
                \s+igp-cost
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.bestpath.skip",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "bestpath": {
                                "skip": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_tie_break",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+tie-break
                \s+(?P<tie>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.bestpath.tie_break",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "tie_break": "{{ tie }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_client_to_client",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+client-to-client
                \s+reflection
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.client_to_client",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "client_to_client": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_cluster_id",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+cluster-id
                \s+(?P<address>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.cluster_id",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "cluster_id": "{{ address }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_confederation",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+confederation
                \s*(?P<identifier>identifier\s.+)*
                \s*(?P<peers>peers\s.+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.confederation",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "confederation": {
                                "identifier": "{{ identifier.split(" ")[1] }}",
                                "peers": "{{ peers.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_control_plane_filter",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+control-plane-filter
                \s+default-allow
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.control_plane_filter",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "control_plane_filter": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_convergence",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+convergence
                \s*(?P<slow>slow-peer)*
                \s+(?P<time>time\s\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.convergence",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "convergence": {
                                "slow_peer": "{{ True if slow is defined else False}}",
                                "time": "{{ time.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params_default",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+default
                \s(?P<param>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.default",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "default": "{{ param }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.enforce_first_as",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+enforce-first-as
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.enforce_first_as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "enforce_first_as": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.host_routes",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+host-routes
                \s+fib
                \s+direct-install
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.host_routes",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "host_routes": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.labelled_unicast",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+labeled-unicast
                \s+rib
                \s+(?P<rib>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.labelled_unicast",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "labeled_unicast": "{{ rib }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.listen_limit",
            "getval": re.compile(
                r"""
                \s*dynamic\speer\smax
                \s+(?P<limit>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.listen.limit",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "listen": {
                                "limit": "{{ limit }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.listen_range",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+listen
                \s+range
                \s+(?P<address>\S+)
                \s+peer\sgroup
                \s+(?P<group>\S+)
                \s*(?P<filter>peer-filter \S+)*
                \s*(?P<remote_as>remote-as \S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.listen.range",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "listen": {
                                "range": {
                                    "address": "{{ address }}",
                                    "peer_group": {
                                        "name": "{{ group }}",
                                        "peer_filter": "{{ filter }}",
                                        "remote_as": "{{ remote_as }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.log_neighbor_changes",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+log-neighbor-changes
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.log_neighbor_changes",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "log_neighbor_changes": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.missing_policy",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+missing-policy
                \s+direction
                \s+(?P<dir>in|out)
                \s+action
                \s+(?P<action>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.missing_policy",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "missing_policy": {
                                "direction": "{{ dir }}",
                                "action": "{{ action }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.monitoring",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+monitoring
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.monitoring",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "monitoring": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.nexthop_unchanged",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+next-hop-unchanged
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.next_hop_unchanged",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "next_hop_unchanged": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.redistribute_internal",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+redistribute-internal
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.redistribute_internal",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "redistribute_internal": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.route",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+route
                \s+install-map
                \s+(?P<route>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.route",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "route": "{{ route }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.route_reflector",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+route-reflector
                \s+preserve-attributes
                \s*(?P<preserve>always)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.route_reflector",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "route_reflector": {
                                "set": "{{ True if presever is undefined }}",
                                "preserve": "{{ True if preserve is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.transport",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+transport
                \s+listen-port
                \s+(?P<port>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.transport",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp_params": {
                            "transport": "{{ port }}",
                        },
                    },
                },
            },
        },
        {
            "name": "default_metric",
            "getval": re.compile(
                r"""
                \s*default-metric
                \s(?P<metric>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_default_metric,
            "compval": "default_metric",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "default_metric": "{{ metric }}",
                    },
                },
            },
        },
        {
            "name": "redistribute",
            "getval": re.compile(
                r"""
                \s*redistribute
                \s+(?P<route>\S+)
                \s*(?P<level>level-1|level-2|level-1-2)*
                \s*(?P<match>match\s.+)*
                \s*(?P<route_map>route-map\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_redistribute,
            "compval": "redistribute",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "redistribute": [
                            {
                                "protocol": "{{ route }}",
                                "route_map": "{{ route_map.split(" ")[1] }}",
                                "isis_level": "{{ level }}",
                                "ospf_route": "{{ 'nssa_external_' + match.split(" ")[2] if match.split(" ")[1] == 'nssa-external' else  match.split(" ")[1]}}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "distance",
            "getval": re.compile(
                r"""
                \s*distance
                \s+bgp
                \s(?P<external>\d+)
                \s*(?P<internal>\d+)*
                \s*(?P<local>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_distance,
            "compval": "distance",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "distance": {
                            "external": "{{ external }}",
                            "internal": "{{ internal }}",
                            "local": "{{ local }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_restart",
            "getval": re.compile(
                r"""
                \s*graceful-restart
                \s*(?P<restart_time>restart-time\s\d+)*
                \s*(?P<stalepath_time>stalepath-time\s\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_graceful_restart,
            "remval": "graceful-restart",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "graceful_restart": {
                            "set": "{{ True if restart_time and stalepath_time is not defined }}",
                            "restart_time": "{{ restart_time.split(" ")[1]|int }}",
                            "stalepath_time": "{{ stalepath_time.split(" ")[1]|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_restart_helper",
            "getval": re.compile(
                r"""
                \s*graceful-restart-helper
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_graceful_restart_helper,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "graceful_restart": {
                            "set": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "access_group",
            "getval": re.compile(
                r"""
                \s*(?P<afi>ip|ipv6)
                \s+access-group
                \s+(?P<acl_name>\S+)
                \s*(?P<direction>in)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_access_group,
            "compval": "access_group",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "access_group": [
                            {
                                "afi": "{{ ipv4 if afi == 'ip'  else afi }}",
                                "acl_name": "{{ acl_name }}",
                                "direction": "{{ direction }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "maximum_paths",
            "getval": re.compile(
                r"""
                \s*maximum-paths
                \s+(?P<max_equal_cost_paths>\d+)
                \s*(ecmp)*
                \s*(?P<max_installed_ecmp_paths>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_maximum_paths,
            "compval": "maximum_paths",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "maximum_paths": {
                            "max_equal_cost_paths": "{{ max_equal_cost_paths }}",
                            "max_installed_ecmp_paths": "{{ max_installed_ecmp_paths }}",
                        },
                    },
                },
            },
        },
        {
            "name": "monitoring",
            "getval": re.compile(
                r"""
                \s*monitoring
                \s+(?P<port>\d+)
                \s*(?P<received>received\sroutes\s\S+)*
                \s*(?P<time>timestamp\s\S+)*
                \s*(?P<station>station\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_monitoring,
            "compval": "monitoring",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "monitoring": {
                            "port": "{{ port }}",
                            "received": "{{ received.split(" ")[2] }}",
                            "timestamp": "{{ timestamp.split(" ")[1] }}",
                            "station": "{{ station.split(" ")[1] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.additional_paths",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+additional-paths
                \s+(?P<action>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.additional_paths",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "additional_paths": "{{ action }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.allowas_in",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+allowas-in
                \s*(?P<count>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.allowas_in",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "allowas_in": {
                                    "set": "{{ True if count is undefined }}",
                                    "count": "{{ count }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.auto_local_addr",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+auto-local-addr
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.auto_local_addr",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "auto_local_addr": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.bfd",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+bfd
                \s*(?P<cbit>c-bit)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.bfd",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "bfd": "{{ 'c_bit' if cbit is defined else 'enable' }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.default_originate",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+default-originate
                \s*(?P<route_map>route-map\s\S+)*
                \s*(?P<always>always)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.default_originate",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "default_originate": {
                                    "route_map": "{{ route_map.split(" ")[1] }}",
                                    "always": "{{ True if always is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.description",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+description
                \s+(?P<desc>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.description",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "description": "{{ desc }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.dont_capability_negotiate",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+dont-capability-negotiate
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.dont_capability_negotiate",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "dont_capability_negotiate": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.ebgp_multihop",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+ebgp-multihop
                \s+(?P<ttl>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.ebgp_multihop",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "ebgp_multihop": {
                                    "set": "{{ True if ttl is not defined }}",
                                    "ttl": "{{ ttl }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.encryption_password",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+password
                \s*(?P<type>\d+)
                \s*(?P<password>\S+)
                """,
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.encryption_password",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "encryption_password": {
                                    "type": "{{ type }}",
                                    "password": "{{ password }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.enforce_first_as",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+enforce-first-as
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.enforce_first_as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "enforce_first_as": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.export_localpref",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+export-localpref
                \s+(?P<pref>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.export_localpref",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "export_localpref": "{{ pref }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.fall_over",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+fall-over
                \s+bfd
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.fall_over",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "fall_over": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.graceful_restart",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+graceful-restart
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "remval": "neighbor {{ peer }} graceful-restart",
            "compval": "neighbor.graceful_restart",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "graceful_restart": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.graceful_restart_helper",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+graceful-restart-helper
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.graceful_restart_helper",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "graceful_restart_helper": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.idle_restart_timer",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+idle-restart-timer
                \s+(?P<time>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.idle_restart_timer",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "idle_restart_timer": "{{ time }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.import_localpref",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+import-localpref
                \s+(?P<pref>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.import_localpref",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "import_localpref": "{{ pref }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.link_bandwidth",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+link-bandwidth
                \s*(?P<auto>auto)*
                \s*(?P<default>default\s\S+)*
                \s*(?P<update>update-delay\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.link_bandwidth",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "link_bandwidth": {
                                    "set": "{{ True }}",
                                    "auto": "{{ True if auto is defined }}",
                                    "default": "{{ default.split(" ")[1] if default is defined }}",
                                    "update_delay": "{{ update.split(" ")[1] if update is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.local_as",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+local-as
                \s+(?P<num>\S+)
                \s+no-prepend
                \s+replace-as
                \s*(?P<fallback>fallback)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.local_as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "local_as": {
                                    "as_number": "{{ num }}",
                                    "fallback": "{{ True if fallback is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.local_v6_addr",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+local-v6-addr
                \s+(?P<addr>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.local_v6_addr",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "local_v6_addr": "{{ addr }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.maximum_accepted_routes",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+maximum-accepted-routes
                \s+(?P<count>\d+)
                \s*warning-limit*
                \s*(?P<limit>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.maximum_accepted_routes",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "maximum_accepted_routes": {
                                    "count": "{{ count }}",
                                    "warning_limit": "{{ limit }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.maximum_received_routes",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+maximum-routes
                \s+(?P<count>\d+)*
                \s*(warning-limit)*
                \s*(?P<limit>\d+)*
                \s*(?P<percent>percent)*
                \s*(?P<warning_only>warning-only)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.maximum_received_routes",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "maximum_received_routes": {
                                    "count": "{{ count }}",
                                    "warning_limit": {
                                        "limit_count": "{{ limit if percent is undefined }}",
                                        "limit_percent": "{{ limit if percent is defined }}",
                                    },
                                    "warning_only": "{{ True if warning_only is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.metric_out",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+metric-out
                \s+(?P<metric>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.metric_out",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "metric_out": "{{ metric }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.monitoring",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+monitoring
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.monitoring",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "monitoring": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.next_hop_self",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+next-hop-self
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.next_hop_self",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "next_hop_self": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.next_hop_unchanged",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+next-hop-unchanged
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.next_hop_unchanged",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "next_hop_unchanged": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.next_hop_v6_addr",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+next-hop-v6-addr
                \s+(?P<addr>\S+)
                \s+in
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.next_hop_v6_address",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "next_hop_v6_address": "{{ addr }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.out_delay",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+out-delay
                \s+(?P<delay>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.out_delay",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "out_delay": "{{ delay }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.remote_as",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+remote-as
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.remote_as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "remote_as": "{{ num }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.remove_private_as",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+remove-private-as
                \s*(?P<all>all)*
                \s*(?P<replace>replace-as)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.remove_private_as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "remove_private_as": {
                                    "set": "{{ True if all is undefined and replace is undefined }}",
                                    "all": "{{ True if all is defined }}",
                                    "replace_as": "{{ True if replace is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.peer_group",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+peer\sgroup
                \s*(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.peer_group",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "peer_group": "{{ name if name is defined else peer}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.prefix_list",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+prefix-list
                \s+(?P<name>\S+)
                \s+(?P<dir>in|out)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.prefix_list",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "prefix_list": {
                                    "name": "{{ name }}",
                                    "direction": "{{ dir }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.route_map",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+route-map
                \s+(?P<name>\S+)
                \s+(?P<dir>in|out)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.route_map",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "route_map": {
                                    "name": "{{ name }}",
                                    "direction": "{{ dir }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.route_reflector_client",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+route-reflector-client
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.route_reflector_client",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "route_reflector_client": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.route_to_peer",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+route-to-peer
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.route_to_peer",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "route_to_peer": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.send_community",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+send-community
                \s*(?P<comm>add|extended|link-bandwidth|remove|standard)*
                \s*(?P<attr>extended|link-bandwidth|standard)*
                \s*(?P<link>aggregate|divide)*
                \s*(?P<div>equal|ratio)*
                \s*(?P<speed>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.send_community",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "send_community": {
                                    "set": "{{ True if comm is not defined }}",
                                    "community_attribute": "{{ comm }}",
                                    "sub_attribute": "{{ attr }}",
                                    "link_bandwidth_attribute": "{{ link }}",
                                    "speed": "{{ speed }}",
                                    "divide": "{{ div }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.shutdown",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+shutdown
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.shutdown",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "shutdown": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.soft_reconfiguration",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+soft-reconfiguration
                \s+inbound
                \s*(?P<all>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.soft_reconfiguration",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "soft_reconfiguration": "{{ 'all' if all is defined else 'None' }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.transport",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+transport
                \s+(?P<mode>\S+)
                \s*(passive)*
                \s*(?P<port>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.transport",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "transport": {
                                    "connection_mode": "{{ mode }}",
                                    "remote_port": "{{ port if port is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.timers",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+timers
                \s+(?P<keepalive>\d+)
                \s+(?P<hold>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.timers",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "timers": {
                                    "keepalive": "{{ keepalive }}",
                                    "holdtime": "{{ holdtime }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.ttl",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+ttl
                \s+maximum-hops
                \s+(?P<hop>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.ttl",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "ttl": "{{ hop }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.update_source",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+update-source
                \s+(?P<src>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.update_source",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "update_source": "{{ src }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.weight",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+weight
                \s+(?P<val>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.weight",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "neighbor_address": "{{ peer }}",
                                "weight": "{{ val }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "network",
            "getval": re.compile(
                r"""
                \s*network
                \s+(?P<address>\S+)
                \s*(route-map)*
                \s*(?P<route_map>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_network,
            "compval": "network",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "network": {
                            "{{ address }}": {
                                "address": "{{ address }}",
                                "route_map": "{{ route_map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "route_target",
            "getval": re.compile(
                r"""
                \s*route-target
                \s+(?P<action>\S+)
                \s*(?P<type>evpn|vpn-ipv4|vpn-ipv6)*
                \s*(?P<map>route-map\s\S+)*
                \s*(?P<imp>imported-route)*
                \s*(?P<target>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_route_target,
            "compval": "route_target",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "route_target": {
                            "action": "{{ action }}",
                            "type": "{{ type }}",
                            "route_map": "{{ map.split(" ")[1] }}",
                            "imported_route": "{{ True if imp is defined }}",
                            "target": "{{ target }}",
                        },
                    },
                },
            },
        },
        {
            "name": "router_id",
            "getval": re.compile(
                r"""
                \s*router-id
                \s+(?P<id>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_router_id,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "router_id": "{{ id }}",
                    },
                },
            },
        },
        {
            "name": "shutdown",
            "getval": re.compile(
                r"""
                \s*shutdown
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_shutdown,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "shutdown": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "timers",
            "getval": re.compile(
                r"""
                \s*timers
                \s+bgp
                \s+(?P<keepalive>\d+)
                \s+(?P<holdtime>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_timers,
            "compval": "timers",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "timers": {
                            "keepalive": "{{ keepalive }}",
                            "holdtime": "{{ holdtime }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ucmp_fec",
            "getval": re.compile(
                r"""
                \s*ucmp
                \s+fec
                \s+threshold
                \s+(?P<trigger>trigger \d+)
                \s+(?P<clear>clear \d+)
                \s+warning-only
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_ucmp,
            "compval": "ucmp.fec",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "ucmp": {
                            "fec": {
                                "trigger": "{{ trigger }}",
                                "clear": "{{ clear }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ucmp_link_bandwidth",
            "getval": re.compile(
                r"""
                \s*ucmp
                \s+link-bandwidth
                \s*(?P<ucmp_mode>recursive|encoding-weighted|update-delay)
                \s*(?P<update_delay>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_ucmp,
            "compval": "ucmp.link_bandwidth",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "ucmp": {
                            "link_bandwidth": {
                                "mode": "{{ ucmp_mode }}",
                                "update_delay": "{{ update_delay }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ucmp_mode",
            "getval": re.compile(
                r"""
                \s*ucmp
                \s+mode
                \s+(?P<ucmp_set>\d+)
                \s*(?P<nexthop>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_ucmp,
            "compval": "ucmp.mode",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "ucmp": {
                            "mode": {
                                "set": "{{ True if ucmp_set == '1'}}",
                                "nexthops": "{{ nexthop }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "update",
            "getval": re.compile(
                r"""
                \s*update
                \s+(?P<wait>\S+)
                \s*(?P<size>batch-size\s\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_update,
            "compval": "update",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "update": {
                            "wait_for": "{{ wait }}",
                            "batch_size": "{{ size.split(" ")[1] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "vlan",
            "getval": re.compile(
                r"""
                \s*vlan
                \s+(?P<id>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_vlan,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "vlan": "{{ id }}",
                    },
                },
            },
        },
        {
            "name": "vlan_aware_bundle",
            "getval": re.compile(
                r"""
                \s*vlan-aware-bundle
                \s+(?P<bundle>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_vlan_aware_bundle,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "vlan_aware_bundle": "{{ bundle }}",
                    },
                },
            },
        },
    ]
    # fmt: on
