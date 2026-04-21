from __future__ import absolute_import, division, print_function


__metaclass__ = type
import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_ospf_default_information(config_data):
    if "default_information_originate" in config_data:
        command = "default-information originate"
        if "always" in config_data["default_information_originate"]:
            command += " always"
        if "metric" in config_data["default_information_originate"]:
            command += " metric {metric}".format(**config_data["default_information_originate"])
        if "metric_type" in config_data["default_information_originate"]:
            command += " metric-type {metric_type}".format(
                **config_data["default_information_originate"],
            )
        if "route_policy" in config_data["default_information_originate"]:
            command += " route-policy {route_policy}".format(
                **config_data["default_information_originate"],
            )
        return command


def _tmplt_ospf_auto_cost(config_data):
    if "auto_cost" in config_data:
        command = "auto-cost"
        if "disable" in config_data["auto_cost"]:
            command += " disable"
        if "reference_bandwidth" in config_data["auto_cost"]:
            command += " reference-bandwidth {reference_bandwidth}".format(
                **config_data["auto_cost"],
            )
        return command


def _tmplt_ospf_bfd(config_data):
    if "bfd" in config_data:
        command = "bfd"
        if "minimum_interval" in config_data["bfd"]:
            command += " minimum-interval {minimum_interval}".format(**config_data["bfd"])

        if "multiplier" in config_data["bfd"]:
            command += " multiplier {multiplier}".format(**config_data["bfd"])

        return command


def _tmplt_ospf_security(config_data):
    if "security_ttl" in config_data:
        command = "security_ttl"
        if "set" in config_data["security_ttl"]:
            command += " ttl"
        elif config_data["security_ttl"].get("hops"):
            command += " ttl hops {0}".format(
                config_data["security_ttl"].get("hops"),
            )
        return command


def _tmplt_ospf_log_adjacency(config_data):
    if "log_adjacency_changes" in config_data:
        command = "log adjacency"
        if "set" in config_data["log_adjacency_changes"]:
            command += " changes"
        elif config_data["log_adjacency_changes"].get("disable"):
            command += " disable"
        elif config_data["log_adjacency_changes"].get("details"):
            command += " details"
        return command


def _tmplt_ospf_log_max_lsa(config_data):
    if "max_lsa" in config_data:
        command = "max-lsa"
        if "threshold" in config_data["max_lsa"]:
            command += " {0}".format(config_data["max_lsa"].get("threshold"))
        if "warning_only" in config_data["max_lsa"]:
            command += " warning-only {0}".format(
                config_data["max_lsa"].get("warning_only"),
            )
        if "ignore_time" in config_data["max_lsa"]:
            command += " ignore-time {0}".format(
                config_data["max_lsa"].get("ignore_time"),
            )
        if "ignore_count" in config_data["max_lsa"]:
            command += " ignore-count {0}".format(
                config_data["max_lsa"].get("ignore_count"),
            )
        if "reset_time" in config_data["max_lsa"]:
            command += " reset-time {0}".format(
                config_data["max_lsa"].get("reset_time"),
            )
        return command


def _tmplt_ospf_max_metric(config_data):
    if "max_metric" in config_data:
        command = "max-metric"
        if "router_lsa" in config_data["max_metric"]:
            command += " router-lsa"
        if "external_lsa" in config_data["max_metric"]:
            command += " external-lsa {external_lsa}".format(**config_data["max_metric"])
        if "include_stub" in config_data["max_metric"]:
            command += " include-stub"
        if "on_startup" in config_data["max_metric"]:
            if "time" in config_data["max_metric"]["on_startup"]:
                command += " on-startup {time}".format(**config_data["max_metric"]["on_startup"])
            elif "wait_for_bgp" in config_data["max_metric"]["on_startup"]:
                command += " on-startup wait-for-bgp"
        if "summary_lsa" in config_data["max_metric"]:
            command += " summary-lsa {summary_lsa}".format(**config_data["max_metric"])
        return command


def _tmplt_ospf_distance_admin(config_data):
    if "admin_distance" in config_data:
        command = "distance"
        if config_data["admin_distance"].get("value"):
            command += " {0}".format(
                config_data["admin_distance"].get("value"),
            )
        if config_data["admin_distance"].get("source"):
            command += " {0}".format(
                config_data["admin_distance"].get("source"),
            )
        if config_data["admin_distance"].get("wildcard"):
            command += " {0}".format(
                config_data["admin_distance"].get("wildcard"),
            )
        if config_data["admin_distance"].get("access_list"):
            command += " {0}".format(
                config_data["admin_distance"].get("access_list"),
            )
        return command


def _tmplt_ospf_distance_ospf(config_data):
    if "ospf_distance" in config_data:
        command = "distance ospf"
        if config_data["ospf_distance"].get("external"):
            command += " external {0}".format(
                config_data["ospf_distance"].get("external"),
            )
        if config_data["ospf_distance"].get("inter_area"):
            command += " inter-area {0}".format(
                config_data["ospf_distance"].get("inter_area"),
            )
        if config_data["ospf_distance"].get("intra_area"):
            command += " intra-area {0}".format(
                config_data["ospf_distance"].get("intra_area"),
            )
        return command


def _tmplt_ospf_nsr(config_data):
    if "nsr" in config_data:
        command = "nsr"
        if "set" in config_data["nsr"]:
            command += " nsr"
        elif config_data["nsr"].get("disable"):
            command += " nsr {0}".format("disable")
        return command


def _tmplt_ospf_protocol(config_data):
    if "protocol_shutdown" in config_data:
        command = "protocol"
        if "set" in config_data["protocol_shutdown"]:
            command += " shutdown"
        elif config_data["shutdown"].get("host_mode"):
            command += " shutdown host-mode"
        elif config_data["shutdown"].get("on_reload"):
            command += " shutdown on-reload"
        return command


def _tmplt_microloop_avoidance(config_data):
    if "microloop_avoidance" in config_data:
        command = "microloop avoidance"
        if "protected" in config_data["microloop_avoidance"]:
            command += " protected"
        if "segment_routing" in config_data["microloop_avoidance"]:
            command += " segment_routing"
        if "rib_update_delay" in config_data["microloop_avoidance"]:
            command += " rin-update-delay {0}".config_data["microloop_avoidance"].get(
                "rib_update_delay",
            )
        return command


def _tmplt_ospf_bfd_fast_detect(config_data):
    if "bfd" in config_data:
        command = "bfd"
        if "fast_detect" in config_data["bfd"]:
            fast_detect = config_data["bfd"].get("fast_detect")
            command += " fast-detect"
            if "strict_mode" in fast_detect:
                command += " strict-mode"
        return command


def _tmplt_ospf_mpls_traffic_eng(config_data):
    if "traffic_eng" in config_data:
        command = "mpls traffic-eng"
        if "igp_intact" in config_data["traffic_eng"]:
            command += " igp-intact"
        if "ldp_sync_update" in config_data["traffic_eng"]:
            command += " ldp_sync_update"
        if "multicast_intact" in config_data["traffic_eng"]:
            command += " multicast_intact"
        if "auto_route_exclude" in config_data["traffic_eng"]:
            policy = config_data["traffic_eng"].get("autoroute_exclude")
            command += " autoroute-exlude route-policy {0}".format(
                policy.get("route_policy"),
            )
        return command


def _tmplt_ospf_authentication_md(config_data):
    command = []
    if "authentication" in config_data:
        if config_data["authentication"].get("message_digest"):
            command = "authentication message-digest"
            md = config_data["authentication"].get("message_digest")
            if md.get("keychain"):
                command += " keychain " + md.get("keychain")
        return command


def _tmplt_ospf_authentication(config_data):
    command = []
    if "authentication" in config_data:
        if config_data["authentication"].get("keychain"):
            command = "authentication keychain " + config_data["authentication"].get("keychain")
        elif config_data["authentication"].get("no_auth"):
            command = "authentication null"
        return command


def _tmplt_ospf_adjacency_stagger(config_data):
    if "adjacency_stagger" in config_data:
        command = "adjacency stagger".format(**config_data)
        if config_data["adjacency_stagger"].get("min_adjacency") and config_data[
            "adjacency_stagger"
        ].get("min_adjacency"):
            command += " {0} {1}".format(
                config_data["adjacency_stagger"].get("min_adjacency"),
                config_data["adjacency_stagger"].get("max_adjacency"),
            )
        elif config_data["adjacency_stagger"].get("disable"):
            command += " disable"
        return command


def _tmplt_ospf_adjacency_distribute_bgp_state(config_data):
    if "distribute_link_list" in config_data:
        command = "distribute link-state"
        if config_data["distribute_link_list"].get("instance_id"):
            command += "  instance-id {0}".format(
                config_data["distribute_link_list"].get("instance_id"),
            )
        elif config_data["distribute_link_list"].get("throttle"):
            command += "  throttle {0}".format(
                config_data["distribute_link_list"].get("throttle"),
            )
        return command
    elif "distribute_bgp_ls" in config_data:
        command = "distribute bgp-ls"
        if config_data["distribute_bgp_ls"].get("instance_id"):
            command += "  instance-id {0}".format(
                config_data["distribute_bgp_ls"].get("instance_id"),
            )
        elif config_data["distribute_bgp_ls"].get("throttle"):
            command += "  throttle {0}".format(
                config_data["distribute_bgp_ls"].get("throttle"),
            )
        return command


def _tmplt_ospf_capability_opaque(config_data):
    if "capability" in config_data:
        if "opaque" in config_data["capability"]:
            command = "capability opaque"
            opaque = config_data["capability"].get("opaque")
            if "disable" in opaque:
                command += "capability opaque disable"
        return command


def _tmplt_ospf_authentication_key(config_data):
    if "authentication_key" in config_data:
        command = "authentication-key".format(**config_data)
        if config_data["authentication_key"].get("password"):
            command += " {0}".format(
                config_data["authentication_key"].get("password"),
            )
        return command


def _tmplt_ospf_area_authentication(config_data):
    if "authentication" in config_data:
        command = "area {area_id} authentication".format(**config_data)
        if config_data["authentication"].get("keychain"):
            command += " keychain " + config_data["authentication"].get(
                "keychain",
            )
        elif config_data["authentication"].get("no_auth"):
            command += " null"
        return command


def _tmplt_ospf_area_authentication_md(config_data):
    if "authentication" in config_data:
        command = "area {area_id} authentication".format(**config_data)
        if "message_digest" in config_data["authentication"]:
            command = "authentication message-digest"
            md = config_data["authentication"].get("message_digest")
            if md.get("keychain"):
                command += " keychain " + md.get("keychain")
        return command


def _tmplt_ospf_area_authentication_key(config_data):
    if "authentication_key" in config_data:
        command = "area {area_id} authentication-key".format(**config_data)
        if config_data["authentication_key"].get("password"):
            command += " {0}".format(
                config_data["authentication_key"].get("password"),
            )
        return command


def _tmplt_ospf_area_mpls_ldp(config_data):
    commands = []
    if "mpls" in config_data:
        command = "area {area_id} mpls".format(**config_data)
        if config_data["mpls"].get("ldp"):
            ldp = config_data["mpls"].get("ldp")
            if "auto_config" in ldp:
                command += " auto-config"
                commands.append(command)
            if "sync" in ldp:
                command += " sync"
                commands.append(command)
            if "sync_igp_shortcuts" in ldp:
                command += " sync-igp-shortcuts"
                commands.append(command)
        return commands


def _tmplt_ospf_area_bfd(config_data):
    if "bfd" in config_data:
        command = "area {area_id} bfd".format(**config_data)
        if "minimum_interval" in config_data["bfd"]:
            command += " minimum-interval {minimum_interval}".format(**config_data["bfd"])

        if "multiplier" in config_data["bfd"]:
            command += " multiplier {multiplier}".format(**config_data["bfd"])

        return command


def _tmplt_ospf_area_bfd_fast_detect(config_data):
    if "bfd" in config_data:
        command = "area {area_id} bfd".format(**config_data)
        if "fast_detect" in config_data["bfd"]:
            fast_detect = config_data["bfd"].get("fast_detect")
            command += " fast-detect"
            if "strict_mode" in fast_detect:
                command += " strict-mode"
        return command


def _tmplt_ospf_mpls_ldp(config_data):
    commands = []
    if "mpls" in config_data:
        command = "mpls".format(**config_data)
        if config_data["mpls"].get("ldp"):
            ldp = config_data["mpls"].get("ldp")
            if "auto_config" in ldp:
                command += " auto-config"
                commands.append(command)
            if "sync" in ldp:
                command += " sync"
                commands.append(command)
            if "sync_igp_shortcuts" in ldp:
                command += " sync-igp-shortcuts"
                commands.append(command)
        return commands


def _tmplt_ospf_area_nssa(config_data):
    if "nssa" in config_data:
        command = "area {area_id} nssa".format(**config_data)
        if config_data["nssa"].get("no_redistribution"):
            command += " no-redistribution"
        if config_data["nssa"].get("no_summary"):
            command += " no-summary"
        return command


def _tmplt_ospf_area_nssa_def_info_origin(config_data):
    if "nssa" in config_data:
        command = "area {area_id} nssa".format(**config_data)
        if "default_information_originate" in config_data["nssa"]:
            command += " default-information-originate"
            def_info_origin = config_data["nssa"].get(
                "default_information_originate",
            )
            if "metric" in def_info_origin:
                command += " metric {metric}".format(
                    **config_data["nssa"]["default_information_originate"],
                )
            if "metric_type" in def_info_origin:
                command += " metric-type {metric_type}".format(
                    **config_data["nssa"]["default_information_originate"],
                )
        return command


def _tmplt_ospf_area_nssa_translate(config_data):
    if "nssa" in config_data:
        command = "area {area_id} nssa".format(**config_data)
        if config_data["nssa"].get("translate"):
            command += " translate"
            translate = config_data["nssa"].get("translate")
            if "type7" in translate:
                command += " type7"
            if translate["type7"].get("always"):
                command += " always"
        return command


def _tmplt_ospf_area_vlink_authentication(config_data):
    if "authentication" in config_data:
        command = "area {area_id} virtual-link {id} authentication".format(**config_data)
        if config_data["authentication"].get("keychain"):
            command += " keychain " + config_data["authentication"].get(
                "keychain",
            )
        elif config_data["authentication"].get("no_auth"):
            command += " null"
        return command


def _tmplt_ospf_area_vlink_authentication_md(config_data):
    if "authentication" in config_data:
        command = "area {area_id} virtual-link {id} authentication".format(**config_data)
        if config_data["authentication"].get("message_digest"):
            command = "authentication message-digest"
            md = config_data["authentication"].get("message_digest")
            if md.get("keychain"):
                command += " keychain " + md.get("keychain")
        return command


def _tmplt_ospf_area_vlink_authentication_key(config_data):
    if "authentication_key" in config_data:
        command = "area {area_id} virtual-link {id} authentication-key".format(**config_data)
        if config_data["authentication_key"].get("password"):
            command += " {0}".format(
                config_data["authentication_key"].get("password"),
            )
        return command


def _tmplt_ospf_area_stub(config_data):
    if "stub" in config_data:
        command = "area {area_id} stub".format(**config_data)
        if config_data["stub"].get("no_summary"):
            command += " no-summary"
        return command


def _tmplt_ospf_area_ranges(config_data):
    if "ranges" in config_data:
        commands = []
        for k, v in config_data["ranges"].items():
            cmd = "area {area_id} range".format(**config_data)
            temp_cmd = " {address}".format(**v)
            if "advertise" in v:
                temp_cmd += " advertise"
            elif "not_advertise" in v:
                temp_cmd += " not-advertise"
            cmd += temp_cmd
            commands.append(cmd)
        return commands


def _tmplt_prefix_suppression(config_data):
    if "prefix_suppression" in config_data:
        if "set" in config_data["prefix_suppression"]:
            command = "prefix-suppression"
        if "secondary_address" in config_data["prefix_suppression"]:
            command = "prefix-suppression secondary-address"
        return command


def _tmplt_protocol_shutdown(config_data):
    if "protocol_shutdown" in config_data:
        if "set" in config_data["protocol_shutdown"]:
            command = "protocol-shutdown"
        if "host_mode" in config_data["protocol_shutdown"]:
            command = "protocol-shutdown host-mode"
        if "on_reload" in config_data["protocol_shutdown"]:
            command = "protocol-shutdown on-reload"
        return command


def _tmplt_timers_lsa(config_data):
    if "timers" in config_data:
        command = "timers lsa"
        if "group_pacing" in config_data["timers"]["lsa"]:
            command += " group-pacing {group_pacing}".format(**config_data["timers"]["lsa"])
        if "min_arrival" in config_data["timers"]["lsa"]:
            command += " min-arrival {min_arrival}".format(**config_data["timers"]["lsa"])
        if "refresh" in config_data["timers"]["lsa"]:
            command += " refresh {refresh}".format(**config_data["timers"]["lsa"])
        return command


def _tmplt_timers_graceful_shutdown(config_data):
    if "timers" in config_data:
        command = "timers graceful-shutdown"
        if "initial_delay" in config_data["timers"]["graceful-shutdown"]:
            command += " initial delay {initial_delay}".format(
                **config_data["timers"]["graceful-shutdown"],
            )
        if "retain_routes" in config_data["timers"]["graceful-shutdown"]:
            command += " retain routes {retain_routes}".format(
                **config_data["timers"]["graceful-shutdown"],
            )
        return command


class Ospfv2Template(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Ospfv2Template, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "pid",
            "getval": re.compile(
                r"""
                        ^router
                        \sospf\s(?P<pid>\S+)
                        $""",
                re.VERBOSE,
            ),
            "setval": "router ospf {{ process_id }}",
            "result": {
                "processes": {"{{ pid }}": {"process_id": "{{ pid }}"}},
            },
            "shared": True,
        },
        {
            "name": "cost",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \scost(?P<cost>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "cost {{ cost }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "cost": "{{ cost|int }}",
                    },
                },
            },
        },
        {
            "name": "default_metric",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sdefault-metric(?P<default_metric>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "default-metric {{ default_metric }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "default_metric": "{{ default_metric|int }}",
                    },
                },
            },
        },
        {
            "name": "packet_size",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \spacket-size(?P<packet_size>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "packet-size {{ packet_size }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "packet_size": "{{ packet_size|int }}",
                    },
                },
            },
        },
        {
            "name": "dead_interval",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sdead-interval(?P<dead_interval>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "dead-interval {{ dead_interval }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "dead_interval": "{{ dead_interval|int }}",
                    },
                },
            },
        },
        {
            "name": "hello_interval",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \shello-interval(?P<hello_interval>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "hello-interval {{ hello_interval }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "hello_interval": "{{ hello_interval|int }}",
                    },
                },
            },
        },
        {
            "name": "priority",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \spriority(?P<priority>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "priority {{ priority }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "priority": "{{ priority|int }}",
                    },
                },
            },
        },
        {
            "name": "weight",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sweight(?P<weight>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "weight {{ weight }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "weight": "{{ weight|int }}",
                    },
                },
            },
        },
        {
            "name": "retransmit_interval",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sretransmit-interval(?P<retransmit_interval>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "retransmit-interval {{ retransmit_interval }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "retransmit_interval": "{{ retransmit_interval|int }}",
                    },
                },
            },
        },
        {
            "name": "transmit_delay",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \stransmit-delay(?P<transmit_delay>\s\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "transmit-delay {{ transmit_delay }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "transmit_delay": "{{ transmit_delay|int }}",
                    },
                },
            },
        },
        {
            "name": "passive",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \spassive\s(?P<passive>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "passive {{ passive }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "passive": "{{ passive }}",
                    },
                },
            },
        },
        {
            "name": "process.database_filter",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sdatabase-filter
                \sall
                \sout\s(?P<database_filter>\s\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "process.database_filter",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "database_filter": "{{ database_filter }}",
                    },
                },
            },
        },
        {
            "name": "demand_circuit",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sdemand-circuit\s(?P<demand_circuit>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "demand-circuit {{ demand_circuit }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "demand_circuit": "{{ demand_circuit }}",
                    },
                },
            },
        },
        {
            "name": "external_out",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sexternal-out\s(?P<external_out>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "external-out {{ external_out }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "external_out": "{{ external_out }}",
                    },
                },
            },
        },
        {
            "name": "router_id",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \srouter-id\s(?P<router_id>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "router-id {{ router_id }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "router_id": "{{ router_id }}",
                    },
                },
            },
        },
        {
            "name": "summary_in",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \ssummary-in\s(?P<summary_in>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "summary-in {{ summary_in }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "summary_in": "{{ summary_in }}",
                    },
                },
            },
        },

        {
            "name": "mtu_ignore",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \smtu-ignore\s(?P<mtu_ignore>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "mtu-ignore {{ mtu_ignore }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "mtu_ignore": "{{ mtu_ignore }}",
                    },
                },
            },
        },
        {
            "name": "flood_reduction",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sflood-reduction\s(?P<flood_reduction>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "flood-reduction {{ flood_reduction }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "flood_reduction": "{{ flood_reduction }}",
                    },
                },
            },
        },
        {
            "name": "loopback_stub_network",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sloopback(?P<loopback>)
                \sstub-network\s(?P<stub_network>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "loopback stub-network {{ stub_network }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "loopback_stub_network": "{{ loopback_stub_network }}",
                    },
                },
            },
        },
        {
            "name": "address_family_unicast",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \saddress-family(?P<address_family>)
                \sipv4(?P<ipv4>)
                \sunicast(?P<unicast>)
                $""",
                re.VERBOSE,
            ),

            "setval": "address_family_unicast",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "address_family_unicast": "{{ True if unicast is defined }}",
                    },
                },
            },
        },
        {
            "name": "default_weight",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sapply-weight(?P<apply_weight>)
                    \sdefault-weight(?P<default_weight>\s\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": "apply-weight default-weight {{ default_weight }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "apply_weight": {
                            "default_weight": "{{ default_weight|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bandwidth",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sapply-weight(?P<apply_weight>)
                    \sbandwidth(?P<bandwidth>\s\d+)?
                    $""",
                re.VERBOSE,
            ),
            "setval": "apply-weight bandwidth {{ bandwidth }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "apply_weight": {
                            "bandwidth": "{{ bandwidth|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "adjacency_stagger",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sadjacency(?P<adjacency>)
                    \sstagger(?P<stagger>)
                    (\s(?P<min_adjacency>\d+))?
                    (\s(?P<max_adjacency>\d+))?
                    (\sdisable(?P<disable>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_adjacency_stagger,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "adjacency_stagger": {
                            "min_adjacency": "{{ min_adjacency|int }}",
                            "max_adjacency": "{{ max_adjacency }}",
                            "disable": "{{ True if disable is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "authentication",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sauthentication(?P<auth>)
                    (\skeychain\s(?P<keychain>\S+)*)?
                    (\snull(?P<no_auth>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "authentication": {
                            "no_auth": "{{ True if no_auth is defined }}",
                            "keychain": "{{ keychain }}",
                        },
                    },
                },
            },
        },
        {
            "name": "authentication.message_digest",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sauthentication(?P<auth>)
                    \smessage-digest(?P<md>)
                    \skeychain\s(?P<md_key>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication_md,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "authentication": {
                            "message_digest": {
                                "keychain": "{{ md_key }}",
                                "set": "{{ True if md is defined and md_key is undefined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "default_information_originate",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sdefault-information(?P<default_information>)
                    (\soriginate(?P<originate>))?
                    (\salways(?P<always>))?
                    (\smetric\s(?P<metric>\d+))?
                    (\smetric-type\s(?P<metric_type>\d+))?
                    (\sroute_policy\s(?P<route_policy>)\S+)?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_default_information,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "default_information_originate": {
                            "always": "{{ True if always is defined }}",
                            "metric": "{{ metric|int }}",
                            "metric_type": "{{ metric_type|int }}",
                            "route_policy": "{{ route_policy }}",
                            "set": "{{ True if default_information is defined and always is undefined and metric "
                                   "is undefined and metric_type is undefined and route_policy is undefined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "auto_cost",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sauto-cost(?P<auto_cost>)
                    (\sreference-bandwidth\s(?P<reference_bandwidth>\d+))?
                    (\sdisable(?P<disable>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_auto_cost,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "auto_cost": {
                            "disable": "{{ True if disable is defined }}",
                            "reference_bandwidth": "{{ reference_bandwidth|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bfd",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sbfd(?P<bfd>)
                    (\sminimum-interval\s(?P<minimum_interval>\d+))?
                    (\smultiplier\s(?P<multiplier>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_bfd,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "bfd": {
                            "minimum_interval": "{{ minimum_interval|int }}",
                            "multiplier": "{{ multiplier|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.fast_detect",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sbfd(?P<bfd>)
                    \sfast-detect(?P<fast_detect>)
                    (\s(?P<disable>disable))?
                    (\s(?P<strict_mode>strict-mode))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_bfd_fast_detect,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "bfd": {
                            "fast_detect": {
                                "set": "{{ True if disable is undefined and strict_mode is undefined }}",
                                "strict_mode": "{{ True if strict_mode is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "security",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \ssecurity(?P<security>)
                    \sttl(?P<ttl>)?
                    (\shops\s(?P<hops>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_security,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "security_ttl": {
                            "set": "{{ True if ttl is defined and hops is undefined }}",
                            "hops": "{{ hops }}",
                        },
                    },
                },
            },
        },
        {
            "name": "nsr",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \snsr(?P<nsr>)
                    \sdisable(?P<disable>)?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_nsr,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "nsr": {
                            "set": "{{ True if nsr is defined and disable is undefined }}",
                            "disable": "{{ True if disable is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "protocol",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sprotocol(?P<protocol>)
                    \s(shutdown(?P<shutdown>))
                    (\shost-mode(?P<host_mode>))?
                    (\son-reload\s(?P<on_reload>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_protocol,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "protocol_shutdown": {
                            "set": "{{ True if shutdown is defined and host-mode is undefined and on_reload is undefined  }}",
                            "host_mode": "{{ True if host_mode is defined }}",
                            "on_reload": "{{ True if on_reload is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "capability",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \scapability(?P<capability>)
                    (\stype7\s(?P<type7>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": "capability type7 {{ type7 }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "capability": {
                            "type7": "{{ type7 }}",
                        },
                    },
                },
            },
        },
        {
            "name": "capability.opaque",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \scapability(?P<capability>)?
                    \sopaque(?P<opaque>)
                    (\sdisable(?P<disable>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_capability_opaque,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "capability": {
                            "opaque": {
                                "disable": "{{ True if disable is defined }}",
                                "set": "{{ True if opaque is defined and disable is undefined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "admin_distance",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sdistance\s(?P<value>d+)
                    \s(?P<source>\S+)
                    \s(?P<wildcard>\S+)
                    (\s(?P<access_list>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_distance_admin,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "distance": {
                            "admin_distance": {
                                "value": "{{ value|int }}",
                                "source": "{{ source }}",
                                "wildcard": "{{ wildcard }}",
                                "access_list": "{{ access_list }}",
                            },
                        },
                    },
                },
            },
        },

        {
            "name": "ospf_distance",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sdistance(?P<value>)
                    \sospf(?P<ospf>)
                    (\sexternal\s(?P<external>\d+))?
                    (\sinter-area\s(?P<inter_area>\d+))?
                    (\sintra-area\s(?P<intra_area>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_distance_ospf,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "distance": {
                            "ospf_distance": {
                                "external": "{{ external|int }}",
                                "inter_area": "{{ inter_area|int }}",
                                "intra_area": "{{ intra_area|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "authentication_key",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sauthentication-key(?P<auth_key>)
                    (\s(?P<password>\S+))?
                    (\sclear\s(?P<clear>)\S+)?
                    (\sencrypted(?P<encrypted>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication_key,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "authentication_key": {
                            "clear": "{{ clear }}",
                            "encrypted": "{{ encrypted}}",
                            "password": "{{ password if clear is undefined and encrypted is undefined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "area.default_cost",
            "getval": re.compile(
                r"""
                   ^router
                   \sospf\s(?P<pid>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \sdefault-cost\s(?P<default_cost>\d+)
                   $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} default-cost {{ default_cost }}",
            "compval": "default_cost",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "default_cost": "{{ default_cost|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.dead_interval",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \sdead-interval\s(?P<dead_interval>\d+)
                $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} dead-interval {{ dead_interval }}",
            "compval": "dead_interval",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "dead_interval": "{{ dead_interval|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.hello_interval",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \shello-interval\s(?P<hello_interval>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} hello-interval {{ hello_interval }}",
            "compval": "hello_interval",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "hello_interval": "{{ hello_interval|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.transmit_delay",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \stransmit-delay\s(?P<transmit_delay>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} transmit-delay {{ transmit_delay }}",
            "compval": "transmit_delay",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "transmit_delay": "{{ transmit_delay|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.cost",
            "getval": re.compile(
                r"""
                   ^router
                   \sospf\s(?P<pid>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \scost\s(?P<cost>\d+)
                   $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} cost {{ cost }}",
            "compval": "cost",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "cost": "{{ cost|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.priority",
            "getval": re.compile(
                r"""
                   ^router
                   \sospf\s(?P<pid>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \spriority\s(?P<priority>\d+)
                   $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} priority {{ priority }}",
            "compval": "priority",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "priority": "{{ priority|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.weight",
            "getval": re.compile(
                r"""
                   ^router
                   \sospf\s(?P<pid>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \sweight\s(?P<weight>\d+)
                   $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} weight {{ weight }}",
            "compval": "weight",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "weight": "{{ weight|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.packet_size",
            "getval": re.compile(
                r"""
                   ^router
                   \sospf\s(?P<pid>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \spacket-size\s(?P<packet_size>\d+)
                   $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} packet-size {{ packet_size }}",
            "compval": "packet_size",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "packet_size": "{{ packet_size|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.summary_in",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \ssummary-in\s(?P<summary_in>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} summary-in {{ summary_in }}",
            "compval": "summary_in",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "summary_in": "{{ summary_in }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.demand_circuit",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \sdemand-circuit\s(?P<demand_circuit>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} demand-circuit {{ demand_circuit }}",
            "compval": "demand_circuit",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "demand_circuit": "{{ demand_circuit }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.passive",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \spassive\s(?P<passive>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} passive {{ passive }}",
            "compval": "passive",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "passive": "{{ passive }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.external_out",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \sexternal-out\s(?P<external_out>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} external-out {{ external_out }}",
            "compval": "passive",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "external_out": "{{ external_out }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.mtu_ignore",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \smtu-ignore\s(?P<mtu_ignore>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "area {{ area_id }} mtu-ignore {{ mtu_ignore }}",
            "compval": "mtu_ignore",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "mtu_ignore": "{{ mtu_ignore }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.authentication",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sauthentication(?P<auth>)
                    (\skeychain\s(?P<keychain>\S+))?
                    (\snull(?P<no_auth>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_authentication,
            "compval": "authentication",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "authentication": {
                                    "no_auth": "{{ True if no_auth is defined }}",
                                    "keychain": "{{ keychain }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.authentication_key",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sauthentication-key(?P<auth_key>)
                    (\s(?P<password>\S+))?
                    (\sclear\s(?P<clear>)\S+)?
                    (\sencrypted(?P<encrypted>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_authentication_key,
            "compval": "authentication_key",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "authentication_key": {
                                    "clear": "{{ clear }}",
                                    "encrypted": "{{ encrypted}}",
                                    "password": "{{ password if clear is undefined and encrypted is undefined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.authentication.message_digest",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sauthentication(?P<auth>)
                    \smessage-digest(?P<md>)
                    \skeychain(?P<md_key>\s\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_authentication_md,
            "compval": "authentication.message_digest",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "authentication": {
                                    "message_digest": {
                                        "keychain": "{{ md_key }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.mpls_traffic_eng",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \smpls(?P<mpls>)
                    \straffic-end(?P<traffic_eng>)
                    $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} mpls traffic-eng",
            "compval": "mpls_traffic_eng",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "mpls": {
                                    "traffic_eng": "{{ True if traffic_eng is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.mpls_ldp",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \smpls(?P<mpls>)
                    (\sauto-config(?P<auto_config>))?
                    (\ssync(?P<sync>))?
                    (\ssync-igp-shortcuts(?P<syn_igp_shortcuts>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_mpls_ldp,
            "compval": "mpls_ldp",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "mpls": {
                                    "ldp": {
                                        "auto_config": "{{ True if auto_config is defined }}",
                                        "sync": "{{ True if sync is defined }}",
                                        "sync_igp_shortcuts": "{{ True if sync_igp_shortcuts is defined }}",

                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.bfd",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sbfd(?P<bfd>)
                    (\sminimum-interval\s(?P<minimum_interval>\d+))?
                    (\smultiplier\s(?P<multiplier>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_bfd,
            "compval": "bfd",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "bfd": {
                                    "minimum_interval": "{{ minimum_interval|int }}",
                                    "multiplier": "{{ multiplier|int }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.bfd.fast_detect",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sbfd(?P<bfd>)
                    \sarea(?P<area_id>)
                    \sfast-detect(?P<fast_detect>)
                    (\s(?P<disable>disable))?
                    (\s(?P<strict_mode>strict-mode))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_bfd_fast_detect,
            "compval": "bfd.fast_detect",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "bfd": {
                                    "fast_detect": {
                                        "set": "{{ True if disable is undefined and strict_mode is undefined }}",
                                        "strict_mode": "{{ True if strict_mode is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.stub",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \sstub(?P<nssa>)
                (\sno-summary(?P<no_sum>))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_stub,
            "compval": "stub",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "area_id": "{{ area_id }}",
                            "stub": {
                                "set": "{{ True if stub is defined and no_summary is undefined }}",
                                "no_summary": "{{ True if no_summary is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.nssa",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \snssa(?P<nssa>)
                (\sno-redistribution(?P<no_redis>))?
                (\sno-summary(?P<no_sum>))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_nssa,
            "compval": "nssa",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "area_id": "{{ area_id }}",
                            "nssa": {
                                "set": "{{ True if nssa is defined and no_summary is undefined and no_redis is undefined }}",
                                "no_summary": "{{ True if no_summary is defined }}",
                                "no_redistribution": "{{ True if no_redis is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.nssa.default_information_originate",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \snssa(?P<nssa>)
                (\sno-redistribution(?P<no_redis>))?
                (\sdefault-information-originate(?P<def_info_origin>))?
                (\smetric\s(?P<metric>\d+))?
                (\smetric-type\s(?P<metric_type>\d+))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_nssa_def_info_origin,
            "compval": "nssa.default_information_originate",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "nssa": {
                                    "default_information_originate": {
                                        "metric": "{{ metric|int }}",
                                        "metric_type": "{{ metric_type|int }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.ranges",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \srange(?P<range>)
                    \s(?P<address>\S+)
                    (\sadvertise(?P<advertise>))
                    (\snot-advertise(?P<not_advertise>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_ranges,
            "compval": "ranges",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "ranges": [
                                    {
                                        "address": "{{ address }}",
                                        "advertise": "{{ True if advertise is defined }}",
                                        "not_advertise": "{{ True if not_advertise is defined }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "area.nssa.translate",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sarea\s(?P<area_id>\S+)
                \snssa(?P<nssa>)
                \stranslate(?P<translate>)
                \stype7(?P<type7>)
                \salways\s(?P<always>)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_nssa_translate,
            "compval": "nssa.translate",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "area_id": "{{ area_id }}",
                            "nssa": {
                                "translate": {
                                    "type7": {
                                        "always": "{{ True if always is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "virtual_link.hello_interval",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \svirtual-link\s(?P<id>\S+)
                    \shello-interval\s(?P<hello_interval>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} virtual-link {{ id }} hello-interval {{ hello_interval }}",
            "compval": "hello_interval",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "virtual_link": {
                                    "{{ id }}":
                                        {
                                            "id": "{{ id }}",
                                            "hello_interval": "{{ hello_interval|int }}",
                                        },

                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "virtual_link.dead_interval",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \svirtual-link\s(?P<id>\S+)
                    \sdead-interval\s(?P<dead_interval>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} virtual-link {{ id }} dead-interval {{ dead_interval }}",
            "compval": "dead_interval",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "virtual_link": {
                                    "{{ id }}": {
                                        "id": "{{ id }}",
                                        "dead_interval": "{{ dead_interval|int }}",
                                    },

                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "virtual_link.retransmit_interval",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \svirtual-link\s(?P<id>\S+)
                    \sretransmit-interval\s(?P<retransmit_interval>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": "area {{ area_id }} virtual-link {{ id }} retransmit-interval {{ retransmit_interval }}",
            "compval": "retransmit_interval",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "virtual_link": {
                                    "{{ id }}": {
                                        "id": "{{ id }}",
                                        "retransmit_interval": "{{ retransmit_interval|int }}",
                                    },
                                },

                            },
                        },
                    },
                },
            },
        },
        {
            "name": "virtual_link.authentication",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \savirtual-link\s(?P<id>\S+)
                    \sauthentication(?P<auth>)
                    (\skeychain\s(?P<keychain>\S+))?
                    (\snull(?P<no_auth>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_vlink_authentication,
            "compval": "authentication",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "authentication": {
                                    "no_auth": "{{ True if no_auth is defined }}",
                                    "keychain": "{{ keychain }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "virtual_link.authentication_key",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \svirtual-link\s(?P<id>\S+)
                    \sauthentication-key(?P<auth_key>)
                    (\s(?P<password>\S+))?
                    (\sclear\s(?P<clear>)\S+)?
                    (\sencrypted(?P<encrypted>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_vlink_authentication_key,
            "compval": "authentication_key",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "virtual_link": {
                                    "{{ id }}": {
                                        "authentication_key": {
                                            "clear": "{{ clear }}",
                                            "encrypted": "{{ encrypted}}",
                                            "password": "{{ password if clear is undefined and encrypted is undefined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "virtual_link.authentication.message_digest",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \svirtual-link\s(?P<id>\S+)
                    \sauthentication(?P<auth>)
                    \smessage-digest(?P<md>)
                    \skeychain(?P<md_key>\s\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_area_vlink_authentication_md,
            "compval": "authentication.message_digest",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "areas": {
                            "{{ area_id }}": {
                                "area_id": "{{ area_id }}",
                                "virtual_link": {
                                    "{{ id }}": {
                                        "authentication": {
                                            "message_digest": {
                                                "keychain": "{{ md_key }}",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "link_down_fast_detect",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \slink-down
                    \sfast-detect(?P<fast_detect>)
                    $""",
                re.VERBOSE,
            ),
            "setval": "link-down fast-detect",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "link_down_fast_detect": "{{ True if fast_detect is defined }}",
                    },
                },
            },
        },
        {
            "name": "nsr",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \snsr
                    \sdisable(?P<disable>)
                    $""",
                re.VERBOSE,
            ),
            "setval": "nsr disable",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "disable": "{{ True if disable is defined }}",
                    },
                },
            },
        },
        {
            "name": "database_filter",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \sdatabase-filter
                \sall
                \sout\s(?P<outing>\S+)
                $""",
                re.VERBOSE,
            ),

            "setval": "database-filter all out {{ outing }}",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "outing": "{{ outing }}",
                    },
                },
            },
        },
        {
            "name": "distribute_link_state",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sdistribute(?P<distribute>)
                    \slink-state(?P<link_state>)
                    (\sinstance-id(?P<inst_id>\d+))?
                    (\sthrottle(?P<throttle>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_adjacency_distribute_bgp_state,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "distribute_link_list": {
                            "instance_id": "{{ inst_id|int }}",
                            "throttle": "{{ throttle }}",
                        },
                    },
                },
            },
        },
        {
            "name": "distribute_bgp_ls",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sdistribute(?P<distribute>)
                    \sbgp-ls(?P<bgp_ls>)
                    (\sinstance-id(?P<inst_id>\d+))?
                    (\sthrottle(?P<throttle>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_adjacency_distribute_bgp_state,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "distribute_bgp_ls": {
                            "instance_id": "{{ inst_id|int }}",
                            "throttle": "{{ throttle }}",
                        },
                    },
                },
            },
        },
        {
            "name": "log_adjacency_changes",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \slog(?P<security>)
                    \sadjacency(?P<adjacency>)?
                    (\schanges(?P<changes>))?
                    (\sdisable(?P<disable>))?
                    (\sdetails(?P<details>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_log_adjacency,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "log_adjacency_changes": {
                            "set": "{{ True if changes is defined }}",
                            "disable": "{{ True if disable is defined }}",
                            "details": "{{ True if details is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "max_lsa",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    (\smax-lsa\s(?P<threshold>\d+))?
                    (\swarning-only\s(?P<warning_only>\d+)?
                    (\signore-time\s(?P<ignore_time>\d+))?
                    (\signore-count\s(?P<ignore_count>\d+))?
                    (\sreset-time\s(?P<reset_time>)\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_log_max_lsa,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "max_lsa": {
                            "threshold": "{{ threshold|int }}",
                            "warning_only": "{{ warning_only|int }}",
                            "ignore_time": "{{ ignore_time|int }}",
                            "ignore_count": "{{ ignore_count|int }}",
                            "reset_time": "{{ reset_time|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "max_metric",
            "getval": re.compile(
                r"""
                ^router
                \sospf\s(?P<pid>\S+)
                \smax-metric
                \s*(?P<router_lsa>)
                (\s*external-lsa(?P<external_lsa>))?
                (\s(?P<max_metric_value>\d+))?
                \s*(?P<include_stub>include-stub)*
                \s*(?P<on_startup>on-startup)*
                \s*(?P<wait_period>\d+)*
                \s*(wait-for\sbgp)*
                \s*(?P<bgp_asn>\d+)*
                \s*(?P<summary_lsa>summary-lsa)*
                \s*(?P<sum_lsa_max_metric_value>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_max_metric,
            "remval": "max-metric router-lsa",
            "result": {
                "processes": {
                    '{{ "pid"  }}': {
                        "max_metric": {
                            "router_lsa": {
                                "set": "{{ True if router_lsa is defined and external_lsa is undefined else None }}",
                                "external_lsa": {
                                    "set": "{{ True if external_lsa is defined and max_metric_value is undefined else None }}",
                                    "max_metric_value": "{{ max_metric_value }}",
                                },
                                "include_stub": "{{ not not include_stub }}",
                                "on_startup": {
                                    "set": "{{ True if on_startup is defined and (wait_period and bgp_asn) is undefined else None }}",
                                    "wait_period": "{{ wait_period }}",
                                    "wait_for_bgp_asn": "{{ bgp_asn }}",
                                },
                                "summary_lsa": {
                                    "set": "{{ True if summary_lsa is defined and sum_lsa_max_metric_value is undefined else None }}",
                                    "max_metric_value": "{{ sum_lsa_max_metric_value }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "mpls_ldp",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \smpls(?P<mpls>)
                    (\sauto-config(?P<auto_config>))?
                    (\ssync(?P<sync>))?
                    (\ssync-igp-shortcuts(?P<syn_igp_shortcuts>))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_mpls_ldp,
            "compval": "mpls_ldp",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "mpls": {
                            "ldp": {
                                "auto_config": "{{ True if auto_config is defined }}",
                                "sync": "{{ True if sync is defined }}",
                                "sync_igp_shortcuts": "{{ True if sync_igp_shortcuts is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "microloop_avoidance",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \smicroloop(?P<microloop>)
                    \savoidance(?P<avoidance>)
                    (\s(?P<protected>protected))?
                    (\s(?P<segment_routing>segment-routing))?
                    (\srib-update-delay\s(?P<rib_update_delay>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_microloop_avoidance,
            "compval": "microloop_avoidance",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "microloop_avoidance": {
                            "protected": "{{ True if protected is defined }}",
                            "segment_routing": "{{ True if segment_routing is defined }}",
                            "rib_update_delay": "{{ rib_update_delay }}",
                        },
                    },
                },
            },
        },
        {
            "name": "mpls_traffic_eng",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \smpls(?P<mpls>)
                    \straffic-end(?P<traffic_eng>)
                    (\sautoroute-exclude(?P<autoroute>))?
                    (\sroute-policy(?P<route_policy>\S+))?
                    (\s(?P<igp_intact>igp_intact))?
                    (\s(?P<ldp_sync_update>ldp-sync-update))?
                    (\s(?P<multicast_intact>multicast-intact))?
                    (\srouter-id\s(?P<router_id>\S+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_mpls_traffic_eng,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "mpls": {
                            "autoroute_exclude": {
                                "route_policy": "{{ route_policy }}",
                            },
                            "igp_intact": "{{ True if igp_intact is defined }}",
                            "ldp_sync_update": "{{ True if ldp_sync_update is defined }}",
                            "multicast_intact": "{{ True if multicast_intact is defined }}",
                            "router_id": "{{ router_id }}",
                        },
                    },
                },
            },
        },
        {
            "name": "prefix_suppression",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sprefix-suppression(?P<prefix_suppression>)
                    (\s(?P<secondary_address>secondary-address))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_prefix_suppression,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "prefix_suppression": {
                            "set": "{{ True if prefix_suppression is defined and secondary_address is undefined }}",
                            "secondary_address": "{{ True if secondary_address is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "protocol_shutdown",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \sprotocol-shutdown(?P<protocol_shutdown>)
                    (\s(?P<host_mode>host-mode))?
                    (\s(?P<on_reload>on-reload))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_protocol_shutdown,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "protocol_shutdown": {
                            "set": "{{ True if protocol_shutdown is defined and host_mode is undefined and on_reload is undefined }}",
                            "host_mode": "{{ True if host_mode is defined }}",
                            "on_reload": "{{ True if on_reload is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "timers.lsa",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \stimers
                    \slsa
                    (\sgroup-pacing\s(?P<group_pacing>\d+))?
                    (\smin-arrival\s(?P<min_arrival>\d+))?
                    (\srefresh\s(?P<refresh>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_timers_lsa,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "timers": {
                            "lsa": {
                                "group_pacing": "{{ group_pacing|int }}",
                                "min_arrival": "{{ min_arrival|int }}",
                                "refresh": "{{ refresh|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "timers.graceful_shutdown",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \stimers
                    \sgraceful_shutdown
                    (\sinitial delay\s(?P<initial_delay>\d+))?
                    (\sretain routes\s(?P<retain_routes>\d+))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_timers_graceful_shutdown,
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "timers": {
                            "graceful_shutdown": {
                                "initial_delay": "{{ initial_delay|int }}",
                                "retain_routes": "{{ retain_routes|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "throttle.spf",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \stimers
                    \sthrottle
                    \sspf
                    (\s(?P<change_delay>\d+))
                    (\s(?P<second_delay>\d+))
                    (\s(?P<max_wait>\d+))
                    $""",
                re.VERBOSE,
            ),
            "setval": "timers throttle spf {{ throttle.spf.change_delay }}  {{ throttle.spf.second_delay }} {{ throttle.spf.max_wait }}",
            "compval": "throttle.lsa_all",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "timers": {
                            "throttle": {
                                "lsa_all": {
                                    "initial_delay": "{{ initial_delay }}",
                                    "min_delay": "{{ min_delay }}",
                                    "max_delay": "{{ max_delay }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "throttle.lsa_all",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \stimers
                    \sthrottle
                    \slsa
                    \sall
                    (\s(?P<initial_delay>\d+))
                    (\s(?P<min_delay>\d+))
                    (\s(?P<max_delay>\d+))
                    $""",
                re.VERBOSE,
            ),
            "setval": "timers throttle lsa all {{ throttle.lsa_all.initial_delay }} {{ throttle.lsa_all.min_delay }} {{ throttle.lsa_all.max_delay }}",
            "compval": "throttle.lsa_all",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "timers": {
                            "throttle": {
                                "lsa_all": {
                                    "initial_delay": "{{ initial_delay }}",
                                    "min_delay": "{{ min_delay }}",
                                    "max_delay": "{{ max_delay }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "throttle.fast_reroute",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \stimers
                    \sthrottle
                    \sfast-reroute\s(?P<fast_reroute>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": "timers throttle fast-reroute {{ fast_reroute }}",
            "compval": "throttle.fast_reroute",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "timers": {
                            "throttle": {
                                "fast_reroute": "{{ fast_reroute }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "timers.pacing_flood",
            "getval": re.compile(
                r"""
                    ^router
                    \sospf\s(?P<pid>\S+)
                    \stimers
                    \spacing
                    \sflood\s(?P<pacing_flood>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": "timers pacing flood {{ pacing_flood }}",
            "compval": "timers.pacing_flood",
            "result": {
                "processes": {
                    "{{ pid }}": {
                        "timers": {
                            "pacing_flood": "{{ pacing_flood }}",

                        },
                    },
                },
            },
        },
    ]
    # fmt: on
