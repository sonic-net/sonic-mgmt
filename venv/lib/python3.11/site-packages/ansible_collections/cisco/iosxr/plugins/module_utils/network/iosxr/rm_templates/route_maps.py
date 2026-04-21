# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Route_maps parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class Route_mapsTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Route_mapsTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "condition",
            "getval": re.compile(
                r"""^dummy-regex
                $""", re.VERBOSE,
            ),
            "setval": "{{ condition_type }}{{ ' ' + condition if condition_type!='else' }}{{ ' then' if condition_type!='else' }}",
            "result": {},
        },
        {
            "name": "add.eigrp_metric",
            "getval": re.compile(
                r"""
                \s*add\seigrp-metric
                (\s(?P<bandwidth>\d+))?
                (\s(?P<delay>\d+))?
                (\s(?P<reliability>\d+))?
                (\s(?P<effective_bandwith>\d+))?
                (\s(?P<max_transmission>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "add eigrp-metric {{ add.eigrp_metric.bandwidth|string }}"
            " {{ add.eigrp_metric.delay|string }} {{ add.eigrp_metric.reliability|string }}"
            " {{ add.eigrp_metric.effective_bandwith|string }} {{ add.eigrp_metric.max_transmission|string }}",
            "result": {
                "policies": {
                    "add": {
                        "eigrp_metric": {
                            "bandwidth": "{{ bandwidth }}",
                            "delay": "{{ delay }}",
                            "reliability": "{{ reliability }}",
                            "effective_bandwith": "{{ effective_bandwith }}",
                            "max_transmission": "{{ max_transmission }}",
                        },
                    },
                },
            },
        },
        {
            "name": "add.rip_metric",
            "getval": re.compile(
                r"""
                \s*add\srip_metric
                (\s(?P<rip_metric>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "add rip-metric {{ add.rip_metric|string }}",
            "result": {
                "policies": {
                    "add": {
                        "rip_metric": "{{ bandwidth }}",
                    },
                },
            },
        },
        {
            "name": "apply",
            "getval": re.compile(
                r"""
                \s*apply
                (\s(?P<route_policy>\S+))
                (\s(?P<route_policy_input>.+))?
                $""", re.VERBOSE,
            ),
            "setval": "apply"
            "{{ (' ' + apply.route_policy) if apply.route_policy is defined else '' }}"
            "{{ (' ' + apply.route_policy_input) if apply.route_policy_input is defined else '' }}",
            "result": {
                "policies": {
                    "apply": [
                        {
                            "route_policy": "{{ route_policy }}",
                            "route_policy_input": "{{ route_policy_input }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "drop",
            "getval": re.compile(
                r"""
                \s*drop
                $""", re.VERBOSE,
            ),
            "setval": "drop",
            "result": {
                "policies": {
                    "drop": True,
                },
            },
        },
        {
            "name": "pass",
            "getval": re.compile(
                r"""
                \s*pass
                $""", re.VERBOSE,
            ),
            "setval": "pass",
            "result": {
                "policies": {
                    "pass": True,
                },
            },
        },
        {
            "name": "prepend",
            "getval": re.compile(
                r"""
                \s*prepend
                (\sas-path\s(?P<as_path>\d+))?
                (\s(?P<most_recent>most-recent))?
                (\s(?P<own_as>own-as))?
                (\s(?P<number_of_times>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "prepend"
            "{{ (' as-path ' + prepend.as_path|string) if prepend.as_path is defined else '' }}"
            "{{ (' most-recent') if prepend.most_recent is defined else '' }}"
            "{{ (' own-as') if prepend.own_as|d(False) else '' }}"
            "{{ (' ' + prepend.number_of_times|string) if prepend.number_of_times is defined else '' }}",
            "result": {
                "policies": {
                    "prepend": {
                        "as_path": "{{ as_path }}",
                        "most_recent": "{{ not not most_recent }}",
                        "own_as": "{{ not not own_as }}",
                        "number_of_times": "{{ number_of_times }}",
                    },
                },
            },
        },
        {
            "name": "suppress_route",
            "getval": re.compile(
                r"""
                \s*suppress-route
                $""", re.VERBOSE,
            ),
            "setval": "suppress-route",
            "result": {
                "policies": {
                    "suppress_route": True,
                },
            },
        },
        {
            "name": "unsuppress_route",
            "getval": re.compile(
                r"""
                \s*unsuppress-route
                $""", re.VERBOSE,
            ),
            "setval": "unsuppress-route",
            "result": {
                "policies": {
                    "unsuppress_route": True,
                },
            },
        },
        {
            "name": "remove",
            "getval": re.compile(
                r"""
                \s*remove\sas-path
                (\s(?P<set>private-as))
                (\s(?P<entire_aspath>entire-aspath))?
                $""", re.VERBOSE,
            ),
            "setval": "remove as-path"
            "{{ (' private-as' ) if remove.set|d(False) else '' }}"
            "{{ (' entire-aspath' ) if remove.entire_aspath|d(False) else '' }}",
            "result": {
                "policies": {
                    "remove": {
                        "set": True,
                        "entire_aspath": "{{ not not entire_aspath }}",
                    },
                },
            },
        },
        {
            "name": "set.administrative_distance",
            "getval": re.compile(
                r"""
                \s*set\sadministrative-distance
                (\s(?P<administrative_distance>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "set administrative-distance {{ set.administrative_distance|string }}",
            "result": {
                "policies": {
                    "set": {
                        "administrative_distance": "{{ administrative_distance }}",
                    },
                },
            },
        },
        {
            "name": "set.local_preference",
            "getval": re.compile(
                r"""
                \s*set\slocal-preference\s(?P<increment>\+)?
                        (?P<decrement>\-)?
                        (?P<multiply>\*)?
                        (?P<metric_number>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "{% for pref in set.local_preference %}"
            "set local-preference"
            "{{ ' *' if pref.multiply|d(False) else '' }}"
            "{{ ' +' if pref.increment|d(False) else '' }}"
            "{{ ' -' if pref.decrement|d(False) else '' }}"
            "{{ ' ' ~ pref.metric_number|string }}\n"
            "{% endfor %}",
            "result": {
                "policies": {
                    "set": {
                        "local_preference": [
                            {
                                "increment": "{{ not not increment }}",
                                "metric_number": "{{ metric_number}}",
                                "decrement": "{{ not not decrement }}",
                                "multiply": "{{ not not multiply }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "set.aigp_metric",
            "getval": re.compile(
                r"""
                \s*set\saigp-metric
                (\s(?P<icrement>\+))?
                (\s(?P<decrement>\-))?
                (\s(?P<metric_number>\d+))?
                (\s(?P<igp_cost>igp-cost))?
                $""", re.VERBOSE,
            ),
            "setval": "set aigp-metric"
            "{{ (' +' ) if set.aigp_metric.icrement is defined else '' }}"
            "{{ (' -' ) if set.aigp_metric.decrement is defined else '' }}"
            "{{ (' ' +  set.aigp_metric.metric_number|string) if set.aigp_metric.metric_number is defined else '' }}"
            "{{ (' igp-cost' ) if set.aigp_metric.igp_cost is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "aigp_metric": {
                            "icrement": "{{ not not icrement }}",
                            "decrement": "{{ not not decrement }}",
                            "metric_number": "{{ metric_number }}",
                            "igp_cost": "{{ not not igp_cost }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.attribute_set",
            "getval": re.compile(
                r"""
                \s*set\sattribute-set\sname-string
                (\s(?P<attribute_set>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "set attribute-set name-string {{ set.attribute_set|string }}",
            "result": {
                "policies": {
                    "set": {
                        "attribute_set": "{{ attribute_set }}",
                    },
                },
            },
        },
        {
            "name": "set.c_multicast_routing",
            "getval": re.compile(
                r"""
                \s*set\sc-multicast-routing
                (\s(?P<bgp>bgp))?
                (\s(?P<pim>pim))?
                $""", re.VERBOSE,
            ),
            "setval": "set c-multicast-routing"
            "{{ (' bgp' ) if set.c_multicast_routing.bgp is defined else '' }}"
            "{{ (' pim' ) if set.c_multicast_routing.pim is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "c_multicast_routing": {
                            "bgp": "{{ not not bgp }}",
                            "pim": "{{ not not pim }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.community",
            "getval": re.compile(
                r"""
                \s*set\scommunity
                (\s(?P<community_name>(.*?)))?
                (\s(?P<additive>additive))?
                $""", re.VERBOSE,
            ),
            "setval": "set community"
            "{{ (' ' + set.community.community_name ) if set.community.community_name is defined else '' }}"
            "{{ (' additive') if set.community.additive|d(False) else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "community": {
                            "community_name": "{{ community_name }}",
                            "additive": "{{ not not additive }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.core_tree",
            "getval": re.compile(
                r"""
                \s*set\score-tree
                (\s(?P<ingress_replication>ingress-replication))?
                (\s(?P<ingress_replication_default>ingress-replication-default))?
                (\s(?P<ingress_replication_partitioned>ingress-replication-partitioned))?
                (\s(?P<mldp>mldp))?
                (\s(?P<mldp_default>mldp-default))?
                (\s(?P<mldp_inband>mldp-inband))?
                (\s(?P<mldp_partitioned_mp2mp>mldp-partitioned-mp2mp))?
                (\s(?P<mldp_partitioned_p2mp>mldp-partitioned-p2mp))?
                (\s(?P<p2mp_te>p2mp-te))?
                (\s(?P<p2mp_te_default>p2mp-te-default))?
                (\s(?P<p2mp_te_partitioned>p2mp-te-partitioned))?
                (\s(?P<pim_default>pim-default))?
                (\s(?P<sr_p2mp>sr-p2mp))?
                $""", re.VERBOSE,
            ),
            "setval": "set core-tree"
            "{{ (' ingress-replication' ) if set.core_tree.ingress_replication|d(False) is defined else '' }}"
            "{{ (' ingress-replication-default' ) if set.core_tree.ingress_replication_default|d(False) is defined else '' }}"
            "{{ (' ingress-replication-partitioned' ) if set.core_tree.ingress_replication_partitioned|d(False) is defined else '' }}"
            "{{ (' mldp' ) if set.core_tree.mldp|d(False) is defined else '' }}"
            "{{ (' mldp-default' ) if set.core_tree.mldp_default|d(False) is defined else '' }}"
            "{{ (' mldp-inband' ) if set.core_tree.mldp_inband|d(False) is defined else '' }}"
            "{{ (' mldp-partitioned-mp2mp' ) if set.core_tree.mldp_partitioned_mp2mp|d(False) is defined else '' }}"
            "{{ (' mldp-partitioned-p2mp' ) if set.core_tree.mldp_partitioned_p2mp|d(False) is defined else '' }}"
            "{{ (' p2mp-te' ) if set.core_tree.p2mp_te|d(False) is defined else '' }}"
            "{{ (' p2mp-te-default' ) if set.core_tree.p2mp_te_default|d(False) is defined else '' }}"
            "{{ (' p2mp-te-partitioned' ) if set.core_tree.p2mp_te_partitioned|d(False) is defined else '' }}"
            "{{ (' pim-default' ) if set.core_tree.pim_default|d(False) is defined else '' }}"
            "{{ (' sr-p2mp' ) if set.core_tree.sr_p2mp|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "core_tree": {
                            "ingress_replication": "{{ not not ingress_replication }}",
                            "ingress_replication_default": "{{ not not ingress_replication_default }}",
                            "ingress_replication_partitioned": "{{ not not ingress_replication_partitioned }}",
                            "mldp": "{{ not not mldp }}",
                            "mldp_default": "{{ not not mldp_default }}",
                            "mldp_inband": "{{ not not mldp_inband }}",
                            "mldp_partitioned_mp2mp": "{{ not not mldp_partitioned_mp2mp }}",
                            "mldp_partitioned_p2mp": "{{ not not mldp_partitioned_p2mp }}",
                            "p2mp_te": "{{ not not p2mp_te }}",
                            "p2mp_te_default": "{{ not not p2mp_te_default }}",
                            "p2mp_te_partitioned": "{{ not not p2mp_te_partitioned }}",
                            "pim_default": "{{ not not pim_default }}",
                            "sr_p2mp": "{{ not not sr_p2mp }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.dampening",
            "getval": re.compile(
                r"""
                \s*set\sdampening
                (\s(?P<halflife>\d+))?
                (\s(?P<suppress>\d+))?
                (\s(?P<reuse>\d+))?
                (\s(?P<max_suppress>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "set dampening"
            "{{ (' ' + set.dampening.halflife|string) if set.dampening.halflife is defined else '' }}"
            "{{ (' ' + set.dampening.max_suppress|string) if set.dampening.max_suppress is defined else '' }}"
            "{{ (' ' + set.dampening.reuse|string) if set.dampening.reuse is defined else '' }}"
            "{{ (' ' + set.dampening.suppress|string) if set.dampening.suppress is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "dampening": {
                            "halflife": "{{ halflife }}",
                            "max_suppress": "{{ max_suppress }}",
                            "reuse": "{{ reuse }}",
                            "suppress": "{{ suppress }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.downstream_core_tree",
            "getval": re.compile(
                r"""
                \s*set\sdownstream-core-tree
                (\s(?P<ingress_replication>ingress-replication))?
                (\s(?P<mldp>mldp))?
                (\s(?P<p2mp_te>p2mp-te))?
                (\s(?P<sr_p2mp>sr-p2mp))?
                $""", re.VERBOSE,
            ),
            "setval": "set downstream-core-tree"
            "{{ (' ingress-replication' ) if set.downstream_core_tree.ingress_replication|d(False) is defined else '' }}"
            "{{ (' mldp' ) if set.downstream_core_tree.mldp|d(False) is defined else '' }}"
            "{{ (' p2mp-te' ) if set.downstream_core_tree.p2mp_te|d(False) is defined else '' }}"
            "{{ (' sr-p2mp' ) if set.downstream_core_tree.sr_p2mp|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "downstream_core_tree": {
                            "ingress_replication": "{{ not not ingress_replication }}",
                            "mldp": "{{ not not mldp }}",
                            "p2mp_te": "{{ not not p2mp_te }}",
                            "sr_p2mp": "{{ not not sr_p2mp }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.eigrp_metric",
            "getval": re.compile(
                r"""
                \s*set\seigrp-metric
                (\s(?P<bandwidth>\d+))?
                (\s(?P<delay>\d+))?
                (\s(?P<reliability>\d+))?
                (\s(?P<effective_bandwith>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "set eigrp-metric"
            "{{ (' ' + set.eigrp_metric.bandwidth|string) if set.eigrp_metric.bandwidth is defined else '' }}"
            "{{ (' ' + set.eigrp_metric.delay|string) if set.eigrp_metric.delay is defined else '' }}"
            "{{ (' ' + set.eigrp_metric.reliability|string) if set.eigrp_metric.reliability is defined else '' }}"
            "{{ (' ' + set.eigrp_metric.effective_bandwith|string) if set.eigrp_metric.effective_bandwith is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "eigrp_metric": {
                            "bandwidth": "{{ bandwidth }}",
                            "delay": "{{ delay }}",
                            "reliability": "{{ reliability }}",
                            "effective_bandwith": "{{ effective_bandwith }}",
                            "max_transmission": "{{ max_transmission }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.extcommunity",
            "getval": re.compile(
                r"""
                \s*set\sextcommunity
                (\ssoo\s(?P<soo>\S+))?
                (\srt\s(?P<rt>\S+))?
                (\sbandwidth\s(?P<bandwidth>\S+))?
                (\scolor\s(?P<color>\S+))?
                (\scost\s(?P<cost>\S+))?
                (\sredirect-to-rt\s(?P<redirect_to_rt>\([^\)]+\)))?
                (\sseg-nh\s(?P<seg_nh>\S+))?
                (\s(?P<additive>additive))?
                $""", re.VERBOSE,
            ),
            "setval": "set extcommunity"
            "{{ (' soo ' + set.extcommunity.soo ) if set.extcommunity.soo is defined else '' }}"
            "{{ (' rt ' + set.extcommunity.rt ) if set.extcommunity.rt is defined else '' }}"
            "{{ (' bandwidth ' + set.extcommunity.bandwidth ) if set.extcommunity.bandwidth is defined else '' }}"
            "{{ (' color ' + set.extcommunity.color ) if set.extcommunity.color is defined else '' }}"
            "{{ (' cost ' + set.extcommunity.cost ) if set.extcommunity.cost is defined else '' }}"
            "{{ (' redirect-to-rt ' + set.extcommunity.redirect_to_rt ) if set.extcommunity.redirect_to_rt is defined else '' }}"
            "{{ (' seg-nh ' + set.extcommunity.seg_nh ) if set.extcommunity.seg_nh is defined else '' }}"
            "{{ (' additive') if set.extcommunity.additive|d(False) else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "extcommunity": {
                            "soo": "{{ soo }}",
                            "rt": "{{ rt }}",
                            "bandwidth": "{{ bandwidth }}",
                            "color": "{{ color }}",
                            "cost": "{{ cost }}",
                            "redirect_to_rt": "{{ redirect_to_rt }}",
                            "seg_nh": "{{ seg_nh }}",
                            "additive": "{{ not not additive }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.fallback_vrf_lookup",
            "getval": re.compile(
                r"""
                \s*set\sfallback-vrf-lookup
                $""", re.VERBOSE,
            ),
            "setval": "set fallback-vrf-lookup",
            "result": {
                "policies": {
                    "set": {
                        "fallback_vrf_lookup": True,
                    },
                },
            },
        },
        {
            "name": "set.flow_tag",
            "getval": re.compile(
                r"""
                \s*set\sflow-tag
                (\s(?P<flow_tag>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set flow-tag"
            "{{ (' ' + set.flow_tag|string) if set.flow_tag is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "flow_tag": "{{ flow_tag }}",
                    },
                },
            },
        },
        {
            "name": "set.forward_class",
            "getval": re.compile(
                r"""
                \s*set\sforward-class
                (\s(?P<flow_tag>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set forward-class"
            "{{ (' ' + set.forward_class|string) if set.forward_class is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "forward_class": "{{ forward_class }}",
                    },
                },
            },
        },
        {
            "name": "set.ip_precedence",
            "getval": re.compile(
                r"""
                \s*set\sip-precedence
                (\s(?P<ip_precedence>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set ip-precedence"
            "{{ (' ' + set.ip_precedence|string) if set.ip_precedence is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "ip_precedence": "{{ ip_precedence }}",
                    },
                },
            },
        },
        {
            "name": "set.isis_metric",
            "getval": re.compile(
                r"""
                \s*set\sisis-metric
                (\s(?P<isis_metric>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set isis-metric"
            "{{ (' ' + set.isis_metric|string) if set.isis_metric is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "isis_metric": "{{ isis_metric }}",
                    },
                },
            },
        },
        {
            "name": "set.label",
            "getval": re.compile(
                r"""
                \s*set\slabel
                (\s(?P<label>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set label"
            "{{ (' ' + set.label|string) if set.label is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "label": "{{ label }}",
                    },
                },
            },
        },
        {
            "name": "set.label_index",
            "getval": re.compile(
                r"""
                \s*set\slabel-index
                (\s(?P<label_index>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set label-index"
            "{{ (' ' + set.label_index|string) if set.label_index is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "label_index": "{{ label_index }}",
                    },
                },
            },
        },
        {
            "name": "set.label_mode",
            "getval": re.compile(
                r"""
                \s*set\slabel-mode
                (\s(?P<per_ce>per-ce))?
                (\s(?P<per_prefix>per-prefix))?
                (\s(?P<per_vrf>per-vrf))?
                $""", re.VERBOSE,
            ),
            "setval": "set label-mode"
            "{{ (' per-ce' ) if set.label_mode.per_ce|d(False) is defined else '' }}"
            "{{ (' per-prefix' ) if set.label_mode.per_prefix|d(False) is defined else '' }}"
            "{{ (' per-vrf' ) if set.label_mode.per_vrf|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "label_mode": {
                            "per_ce": "{{ not not per_ce }}",
                            "per_prefix": "{{ not not per_prefix }}",
                            "per_vrf": "{{ not not per_vrf }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.large_community",
            "getval": re.compile(
                r"""
                \s*set\slarge-community
                (\s(?P<large_community>.+))
                $""", re.VERBOSE,
            ),
            "setval": "set large-community {{ set.large_community }}",
            "result": {
                "policies": {
                    "set": {
                        "large_community": "{{ large_community }}",
                    },
                },
            },
        },
        {
            "name": "set.level",
            "getval": re.compile(
                r"""
                \s*set\slevel
                (\s(?P<level_1>level-1))?
                (\s(?P<level_1_2>level-1-2))?
                (\s(?P<level_2>level-2))?
                $""", re.VERBOSE,
            ),
            "setval": "set level"
            "{{ (' level-1' ) if set.level.level_1|d(False) is defined else '' }}"
            "{{ (' level-1-2' ) if set.level.level_1_2|d(False) is defined else '' }}"
            "{{ (' level-2' ) if set.level.level_2|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "level": {
                            "level_1": "{{ not not level_1 }}",
                            "level_1_2": "{{ not not level_1_2 }}",
                            "level_2": "{{ not not level_2 }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.load_balance",
            "getval": re.compile(
                r"""
                \s*set\sload-balance\secmp-consistent
                $""", re.VERBOSE,
            ),
            "setval": "set load-balance ecmp-consistent",
            "result": {
                "policies": {
                    "set": {
                        "load_balance": True,
                    },
                },
            },
        },
        {
            "name": "set.lsm_root",
            "getval": re.compile(
                r"""
                \s*set\slsm-root
                (\s(?P<lsm_root>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "set lsm-root {{ set.lsm_root }}",
            "result": {
                "policies": {
                    "set": {
                        "lsm_root": "{{ lsm_root }}",
                    },
                },
            },
        },
        {
            "name": "set.metric_type",
            "getval": re.compile(
                r"""
                \s*set\smetric-type
                (\s(?P<external>external))?
                (\s(?P<internal>internal))?
                (\s(?P<rib_metric_as_external>rib-metric-as-external))?
                (\s(?P<rib_metric_as_internal>rib-metric-as-internal))?
                (\s(?P<type_1>type-1))?
                (\s(?P<type_2>type-2))?
                $""", re.VERBOSE,
            ),
            "setval": "set metric-type"
            "{{ (' external' ) if set.metric_type.external|d(False) is defined else '' }}"
            "{{ (' internal' ) if set.metric_type.internal|d(False) is defined else '' }}"
            "{{ (' rib-metric-as-external' ) if set.metric_type.rib_metric_as_external|d(False) is defined else '' }}"
            "{{ (' rib-metric-as-internal' ) if set.metric_type.rib_metric_as_internal|d(False) is defined else '' }}"
            "{{ (' type-1' ) if set.metric_type.type_1|d(False) is defined else '' }}"
            "{{ (' type-2' ) if set.metric_type.type_2|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "metric_type": {
                            "external": "{{ not not external }}",
                            "internal": "{{ not not internal }}",
                            "rib_metric_as_external": "{{ not not rib_metric_as_external }}",
                            "rib_metric_as_internal": "{{ not not rib_metric_as_internal }}",
                            "type_1": "{{ not not type_1 }}",
                            "type_2": "{{ not not type_2 }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.mpls",
            "getval": re.compile(
                r"""
                \s*set\smpls\straffic-eng\sattributeset
                (\s(?P<mpls>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "set mpls traffic-eng attributeset {{ set.mpls }}",
            "result": {
                "policies": {
                    "set": {
                        "mpls": "{{ mpls }}",
                    },
                },
            },
        },
        {
            "name": "set.med",
            "getval": re.compile(
                r"""
                \s*set\smed
                (\s(?P<increment>\+))?
                (\s(?P<decrement>\-))?
                (\s(?P<value>\d+))?
                (\s(?P<igp_cost>igp-cost))?
                (\s(?P<max_reachable>max-reachable))?
                (\s(?P<parameter>\$\w+))?
                $""", re.VERBOSE,
            ),
            "setval": "set med"
            "{{ (' +' ) if set.med.increment is defined else '' }}"
            "{{ (' -' ) if set.med.decrement is defined else '' }}"
            "{{ (' ' + set.med.value|string ) if set.med.value is defined else '' }}"
            "{{ (' igp-cost') if set.med.igp_cost|d(False) else '' }}"
            "{{ (' max-reachable') if set.med.max_reachable|d(False) else '' }}"
            "{{ (' ' + set.med.parameter ) if set.med.parameter is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "med": {
                            "increment": "{{ not not increment }}",
                            "decrement": "{{ not not decrement }}",
                            "value": "{{ value }}",
                            "igp_cost": "{{ not not igp_cost }}",
                            "max_reachable": "{{ not not max_reachable }}",
                            "parameter": "{{ parameter }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.next_hop",
            "getval": re.compile(
                r"""
                \s*set\snext-hop
                (\s(?P<next_hop>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "set next-hop {{ set.next_hop.address }}",
            "result": {
                "policies": {
                    "set": {
                        "next_hop": {
                            "address": "{{ next_hop }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.origin",
            "getval": re.compile(
                r"""
                \s*set\sorigin
                (\s(?P<egp>egp))?
                (\s(?P<igp>igp))?
                (\s(?P<rincomplete>incomplete))?
                $""", re.VERBOSE,
            ),
            "setval": "set origin"
            "{{ (' egp' ) if set.origin.egp|d(False) is defined else '' }}"
            "{{ (' igp' ) if set.origin.igp|d(False) is defined else '' }}"
            "{{ (' incomplete' ) if set.origin.incomplete|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "origin": {
                            "egp": "{{ not not egp }}",
                            "igp": "{{ not not igp }}",
                            "rincomplete": "{{ not not rincomplete }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.ospf_metric",
            "getval": re.compile(
                r"""
                \s*set\sospf-metric
                (\s(?P<ospf_metric>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set ospf-metric {{ ospf_metric|string }}",
            "result": {
                "policies": {
                    "set": {
                        "ospf_metric": "{{ ospf_metric }}",
                    },
                },
            },
        },
        {
            "name": "set.path_selection.all",
            "getval": re.compile(
                r"""
                \s*set\spath-selection\sall\sadvertise
                $""", re.VERBOSE,
            ),
            "setval": "set path-selection all advertise",
            "result": {
                "policies": {
                    "set": {
                        "path_selection": {
                            "all": True,
                        },
                    },
                },
            },
        },
        {
            "name": "set.path_selection.backup",
            "getval": re.compile(
                r"""
                \s*set\spath-selection\sbackup
                (\s(?P<backup_decimal>\d+))?
                (\s(?P<advertise>advertise))?
                (\s(?P<install>install))?
                $""", re.VERBOSE,
            ),
            "setval": "set path-selection backup"
            "{{ (' ' + set.path_selection.backup.backup_decimal|string ) if set.path_selection.backup.backup_decimal is defined else '' }}"
            "{{ (' advertise') if set.path_selection.backup.advertise|d(False) else '' }}"
            "{{ (' install') if set.path_selection.backup.install|d(False) else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "path_selection": {
                            "backup": {
                                "backup_decimal": "{{ backup_decimal }}",
                                "advertise": "{{ not not advertise }}",
                                "install": "{{ not not install }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.path_selection.best_path",
            "getval": re.compile(
                r"""
                \s*set\spath-selection\sbest-path
                $""", re.VERBOSE,
            ),
            "setval": "set path-selection best_path",
            "result": {
                "policies": {
                    "set": {
                        "path_selection": {
                            "best_path": True,
                        },
                    },
                },
            },
        },
        {
            "name": "set.path_selection.group_best",
            "getval": re.compile(
                r"""
                \s*set\spath-selection\sbest-path\sadvertise
                $""", re.VERBOSE,
            ),
            "setval": "set path-selection group-best advertise",
            "result": {
                "policies": {
                    "set": {
                        "path_selection": {
                            "group_best": True,
                        },
                    },
                },
            },
        },
        {
            "name": "set.path_selection.multiplath",
            "getval": re.compile(
                r"""
                \s*set\spath-selection\smultiplath\sadvertise
                $""", re.VERBOSE,
            ),
            "setval": "set path-selection multiplath advertise",
            "result": {
                "policies": {
                    "set": {
                        "path_selection": {
                            "multiplath": True,
                        },
                    },
                },
            },
        },
        {
            "name": "set.path_color",
            "getval": re.compile(
                r"""
                \s*set\spath-color\sexternal-reach
                $""", re.VERBOSE,
            ),
            "setval": "set path-color external-reach",
            "result": {
                "policies": {
                    "set": {
                        "path_color": True,
                    },
                },
            },
        },
        {
            "name": "set.qos_group",
            "getval": re.compile(
                r"""
                \s*set\sqos-group
                (\s(?P<qos_group>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set qos-group {{ qos_group|string }}",
            "result": {
                "policies": {
                    "set": {
                        "qos_group": "{{ qos_group }}",
                    },
                },
            },
        },
        {
            "name": "set.rib_metric",
            "getval": re.compile(
                r"""
                \s*set\srib-metric
                (\s(?P<rib_metric>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set rib-metric {{ rib_metric|string }}",
            "result": {
                "policies": {
                    "set": {
                        "rib_metric": "{{ rib_metric }}",
                    },
                },
            },
        },
        {
            "name": "set.rip_metric",
            "getval": re.compile(
                r"""
                \s*set\srip-metric
                (\s(?P<rip_metric>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set rip-metric {{ rip_metric|string }}",
            "result": {
                "policies": {
                    "set": {
                        "rip_metric": "{{ rip_metric }}",
                    },
                },
            },
        },
        {
            "name": "set.rip_tag",
            "getval": re.compile(
                r"""
                \s*set\srip-tag
                (\s(?P<rip_tag>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set rip-tag {{ rip_tag|string }}",
            "result": {
                "policies": {
                    "set": {
                        "rip_tag": "{{ rip_tag }}",
                    },
                },
            },
        },
        {
            "name": "set.rt_set",
            "getval": re.compile(
                r"""
                \s*set\srt-set\sroute-limit
                (\s(?P<rt_set>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set rt-set route-limit {{ rt_set|string }}",
            "result": {
                "policies": {
                    "set": {
                        "rt_set": "{{ rt_set }}",
                    },
                },
            },
        },
        {
            "name": "set.s_pmsi",
            "getval": re.compile(
                r"""
                \s*set\ss-pmsi\sstar-g
                $""", re.VERBOSE,
            ),
            "setval": "set s-pmsi star-g",
            "result": {
                "policies": {
                    "set": {
                        "s_pmsi": True,
                    },
                },
            },
        },
        {
            "name": "set.spf_priority",
            "getval": re.compile(
                r"""
                \s*set\sspf-priority
                (\s(?P<critical>critical))?
                (\s(?P<high>high))?
                (\s(?P<medium>medium))?
                $""", re.VERBOSE,
            ),
            "setval": "set spf-priority"
            "{{ (' critical' ) if set.spf_priority.critical|d(False) is defined else '' }}"
            "{{ (' high' ) if set.spf_priority.high|d(False) is defined else '' }}"
            "{{ (' medium' ) if set.spf_priority.medium|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "spf_priority": {
                            "critical": "{{ not not critical }}",
                            "high": "{{ not not high }}",
                            "medium": "{{ not not medium }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.static_p2mp_te",
            "getval": re.compile(
                r"""
                \s*set\sstatic-p2mp-te
                (\s(?P<static_p2mp_te>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "set static-p2mp-te {{ set.static_p2mp_te }}",
            "result": {
                "policies": {
                    "set": {
                        "static_p2mp_te": "{{ static_p2mp_te }}",
                    },
                },
            },
        },
        {
            "name": "set.tag",
            "getval": re.compile(
                r"""
                \s*set\stag
                (\s(?P<tag>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set tag {{ set.tag|string }}",
            "result": {
                "policies": {
                    "set": {
                        "tag": "{{ tag }}",
                    },
                },
            },
        },
        {
            "name": "set.traffic_index",
            "getval": re.compile(
                r"""
                \s*set\straffic-index
                (\s(?P<index_number>\d+))?
                (\s(?P<ignore>ignore))?
                $""", re.VERBOSE,
            ),
            "setval": "set traffic-index"
            "{{ (' ' + set.traffic_index.index_number|string) if set.traffic_index.index_number is defined else '' }}"
            "{{ (' ignore') if set.traffic_index.ignore is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "traffic_index": {
                            "index_number": "{{ index_number }}",
                            "ignore": "{{ not not ignore }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.upstream_core_tree",
            "getval": re.compile(
                r"""
                \s*set\supstream-core-tree
                (\s(?P<ingress_replication>ingress-replication))?
                (\s(?P<mldp>mldp))?
                (\s(?P<p2mp_te>p2mp-te))?
                (\s(?P<sr_p2mp>sr-p2mp))?
                $""", re.VERBOSE,
            ),
            "setval": "set upstream-core-tree"
            "{{ (' ingress-replication' ) if set.upstream_core_tree.ingress_replication|d(False) is defined else '' }}"
            "{{ (' mldp' ) if set.upstream_core_tree.mldp|d(False) is defined else '' }}"
            "{{ (' p2mp-te' ) if set.upstream_core_tree.p2mp_te|d(False) is defined else '' }}"
            "{{ (' sr-p2mp' ) if set.upstream_core_tree.sr_p2mp|d(False) is defined else '' }}",
            "result": {
                "policies": {
                    "set": {
                        "upstream_core_tree": {
                            "ingress_replication": "{{ not not ingress_replication }}",
                            "mldp": "{{ not not mldp }}",
                            "p2mp_te": "{{ not not p2mp_te }}",
                            "sr_p2mp": "{{ not not sr_p2mp }}",
                        },
                    },
                },
            },
        },
        {
            "name": "set.vpn_distinguisher",
            "getval": re.compile(
                r"""
                \s*set\svpn-distinguisher
                (\s(?P<vpn_distinguisher>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set vpn-distinguisher {{ set.vpn_distinguisher|string }}",
            "result": {
                "policies": {
                    "set": {
                        "vpn_distinguisher": "{{ vpn_distinguisher }}",
                    },
                },
            },
        },
        {
            "name": "set.weight",
            "getval": re.compile(
                r"""
                \s*set\sweight
                (\s(?P<weight>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "set weight {{ set.weight|string }}",
            "result": {
                "policies": {
                    "set": {
                        "weight": "{{ weight }}",
                    },
                },
            },
        },
    ]
    # fmt: on
