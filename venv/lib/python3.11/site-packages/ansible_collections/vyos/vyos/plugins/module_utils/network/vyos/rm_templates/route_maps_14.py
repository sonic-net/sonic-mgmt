# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
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


class Route_mapsTemplate14(NetworkTemplate):
    def __init__(self, lines=None):
        prefix = {"set": "set", "remove": "delete"}
        super(Route_mapsTemplate14, self).__init__(lines=lines, tmplt=self, prefix=prefix)

    # fmt: off
    PARSERS = [
        {
            "name": "route_map",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "route_map",
            "setval": "policy route-map {{route_map}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                    },
                },
            },
        },
        {
            "name": "sequence",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "sequence",
            "setval": "policy route-map {{route_map}} rule {{sequence}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "call",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\scall\s(?P<call>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "policy route-map {{route_map}} rule {{sequence}} call {{call}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "call": "{{call}}",
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sdescription\s(?P<description>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "policy route-map {{route_map}} rule {{sequence}} description {{description}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "description": "{{description}}",
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "action",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\saction\s(?P<action>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "policy route-map {{route_map}} rule {{sequence}} action {{action}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "action": "{{action}}",
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "continue_sequence",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\scontinue\s(?P<continue>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "policy route-map {{route_map}} rule {{sequence}} continue {{continue_sequence}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "continue_sequence": "{{continue}}",
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "on_match_next",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\son-match\s(?P<next>next)
                *$""",
                re.VERBOSE,
            ),
            "compval": "on_match.next",
            "setval": "policy route-map {{route_map}} rule {{sequence}} on-match next",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "on_match": {
                                        "next": "{{True if next is defined}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "on_match_goto",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\son-match\sgoto\s(?P<goto>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "on_match.goto",
            "setval": "policy route-map {{route_map}} rule {{sequence}} on-match goto {{on_match.goto}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "on_match": {
                                        "goto": "{{goto}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_aggregator_ip",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\saggregator\sip\s(?P<ip>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.aggregator.ip",
            "setval": "policy route-map {{route_map}} rule {{sequence}} set aggregator ip {{set.aggregator.ip}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "aggregator": {
                                            "ip": "{{ip}}",
                                        },
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_aggregator_as",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\saggregator\sas\s(?P<as>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.aggregator.as",
            "setval": "policy route-map {{route_map}} rule {{sequence}} set aggregator as {{set.aggregator.as}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "aggregator": {
                                            "as": "{{as}}",
                                        },
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_as_path_exclude",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sas-path\sexclude\s(?P<as>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.as_path_exclude",
            "setval": "policy route-map {{route_map}} rule {{sequence}} set as-path exclude {{set.as_path_exclude}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "as_path_exclude": "{{as}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_as_path_prepend",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sas-path\sprepend\s(?P<as>.*)
                $""",
                re.VERBOSE,
            ),
            "compval": "set.as_path_prepend",
            "setval": "policy route-map {{route_map}} rule {{sequence}} set as-path prepend '{{set.as_path_prepend}}'",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "as_path_prepend": "{{as}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_atomic_aggregate",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\s(?P<as>atomic-aggregate)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.atomic_aggregate",
            "setval": "policy route-map {{route_map}} rule {{sequence}} set atomic-aggregate",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "atomic_aggregate": "{{True if as is defined}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_bgp_extcommunity_rt",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sbgp-extcommunity-rt\s(?P<bgp>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.bgp_extcommunity_rt",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set bgp-extcommunity-rt {{set.bgp_extcommunity_rt}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "bgp_extcommunity_rt": "{{bgp}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_comm_list",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\scommunity\scommunity-list\s(?P<comm_list>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.community.community_list",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match community community-list {{set.comm_list.comm_list}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "community": {"community_list": "{{comm_list}}"},
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_comm_list_delete",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\scomm-list\sdelete(?P<delete>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.comm_list.comm_list",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set comm-list delete",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "comm_list": {"delete": "{{True if delete is defined}}"},
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_extcommunity_rt",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sextcommunity\srt\s(?P<extcommunity_rt>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.extcommunity_rt",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set extcommunity rt {{set.extcommunity_rt}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "extcommunity_rt": "{{extcommunity_rt}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_extcommunity_soo",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sextcommunity\ssoo\s(?P<extcommunity_soo>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.extcommunity_soo",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set extcommunity soo {{set.extcommunity_soo}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "extcommunity_soo": "{{extcommunity_soo}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_extcommunity_bandwidth",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sextcommunity\sbandwidth\s(?P<extcommunity_bw>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.extcommunity_bandwidth",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set extcommunity bandwidth {{set.extcommunity_bandwidth}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "extcommunity_bandwidth": "{{extcommunity_bw}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_extcommunity_bandwidth_non_transitive",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sextcommunity\s(?P<extcommunity_bw_nt>bandwidth-non-transitive)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.extcommunity_bandwidth_non_transitive",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set extcommunity bandwidth-non-transitive",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "extcommunity_bandwidth_non_transitive": "{{True if extcommunity_bw_nt is defined}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_ip_next_hop",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sip-next-hop\s(?P<ip_next_hop>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.ip_next_hop",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set ip-next-hop {{set.ip_next_hop}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "ip_next_hop": "{{ip_next_hop}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_ipv6_next_hop",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sipv6-next-hop
                \s(?P<type>global|local)
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.ipv6_next_hop",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set ipv6-next-hop {{set.ipv6_next_hop.ip_type}} {{set.ipv6_next_hop.value}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "ipv6_next_hop": {
                                            "ip_type": "{{type}}",
                                            "value": "{{value}}",
                                        },
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_large_community",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\slarge-community\s(?P<op>none|replace\s(?P<large_community>\S+))
                $""",
                re.VERBOSE,
            ),
            "compval": "set.large_community",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set large-community {{set.large_community if set.large_community == 'none' else 'replace ' + set.large_community}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "large_community": "{{op if op == 'none' else large_community}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_local_preference",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\slocal-preference\s(?P<local_preference>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.local_preference",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set local-preference {{set.local_preference}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "local_preference": "{{local_preference}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_metric",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\smetric\s(?P<metric>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.metric",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set metric {{set.metric}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "metric": "{{metric}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_metric_type",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\smetric-type\s(?P<metric_type>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.metric_type",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set metric-type {{set.metric_type}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "metric_type": "{{metric_type}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_origin",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sorigin\s(?P<origin>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.origin",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set origin {{set.origin}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "origin": "{{origin}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_originator_id",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\soriginator-id\s(?P<originator_id>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.originator_id",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set originator-id {{set.originator_id}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "originator_id": "{{originator_id}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_src",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\ssrc\s(?P<src>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.src",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set src {{set.src}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "src": "{{src}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_tag",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\stag\s(?P<tag>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.tag",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set tag {{set.tag}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "tag": "{{tag}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_weight",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\sweight\s(?P<weight>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.weight",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set weight {{set.weight}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "weight": "{{weight}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_table",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\stable\s(?P<table>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "set.weight",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set table {{set.table}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "table": "{{table}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "set_community",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\sset\scommunity\s(?P<op>none|replace\s(?P<value>\S+))
                $""",
                re.VERBOSE,
            ),
            "compval": "set.community.value",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "set community {{set.community.value if set.community.value == 'none' else 'replace ' + set.community.value}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "set": {
                                        "community": {
                                            "value": "{{op if op == 'none' else value}}",
                                        },
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_as_path",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sas-path\s(?P<as_path>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.as_path",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match as-path {{match.as_path}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "as_path": "{{as_path}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_community_community_list",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\scommunity\scommunity-list\s(?P<community_list>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.community.community_list",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match community community-list {{match.community.community_list}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "community": {"community_list": "{{community_list}}"},
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_community_exact_match",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\scommunity\sexact-match(?P<exact_match>)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.community.exact_match",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match community exact-match",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "community": {"exact_match": "{{True if exact_match is defined}}"},
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_extcommunity",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sextcommunity\s(?P<extcommunity>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.extcommunity",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match extcommunity {{match.extcommunity}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "extcommunity": "{{extcommunity}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_interface",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sinterface\s(?P<interface>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.interface",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match interface {{match.interface}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "interface": "{{interface}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_large_community_large_community_list",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\slarge-community\slarge-community-list\s(?P<lc>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.large_community_large_community_list",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match large-community large-community-list {{match.large_community_large_community_list}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "large_community_large_community_list": "{{lc}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_metric",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\smetric\s(?P<metric>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.metric",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match metric {{match.metric}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "metric": "{{metric}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_origin",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sorigin\s(?P<origin>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.origin",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match origin {{match.origin}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "origin": "{{origin}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_peer",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\speer\s(?P<peer>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.peer",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match peer {{match.peer}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}":
                                {
                                    "sequence": "{{sequence}}",
                                    "match": {
                                        "peer": "{{peer}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "match_ip_address",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sip\saddress
                \s(?P<list_type>access-list|prefix-list)
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.ip.address",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match ip address {{match.ip.address.list_type}} {{match.ip.address.value}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "ip": {
                                        "address": {
                                            "list_type": "{{list_type}}",
                                            "value": "{{value}}",
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
            "name": "match_ip_next_hop",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sip\snexthop
                \s(?P<list_type>access-list|prefix-list)
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.ip.next_hop",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match ip nexthop {{match.ip.next_hop.list_type}} {{match.ip.next_hop.value}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "ip": {
                                        "next_hop": {
                                            "list_type": "{{list_type}}",
                                            "value": "{{value}}",
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
            "name": "match_ip_route_source",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sip\sroute-source
                \s(?P<list_type>access-list|prefix-list)
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.ip.route_source",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match ip route-source {{match.ip.route_source.list_type}} {{match.ip.route_source.value}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "ip": {
                                        "route_source": {
                                            "list_type": "{{list_type}}",
                                            "value": "{{value}}",
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
            "name": "match_ipv6_address",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sipv6\saddress
                \s(?P<list_type>access-list|prefix-list)
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.ipv6.address",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match ipv6 address {{match.ipv6.address.list_type}} {{match.ipv6.address.value}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "ipv6": {
                                        "address": {
                                            "list_type": "{{list_type}}",
                                            "value": "{{value}}",
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
            "name": "match_ipv6_nexthop",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sipv6\snexthop
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.ipv6.next_hop",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match ipv6 nexthop {{match.ipv6.next_hop}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "ipv6": {
                                        "next_hop": "{{value}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match_protocol",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\sprotocol\s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.protocol",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match protocol {{match.protocol}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "protocol": "{{value}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match_rpki",
            "getval": re.compile(
                r"""
                ^set\spolicy\sroute-map\s(?P<route_map>\S+)\srule\s(?P<sequence>\d+)\smatch\srpki
                \s(?P<value>\S+)
                *$""",
                re.VERBOSE,
            ),
            "compval": "match.rpki",
            "setval": "policy route-map {{route_map}} rule {{sequence}} "
                      "match rpki {{match.rpki}}",
            "result": {
                "route_maps": {
                    "{{ route_map }}": {
                        "route_map": '{{ route_map }}',
                        "entries": {
                            "{{sequence}}": {
                                "sequence": "{{sequence}}",
                                "match": {
                                    "rpki": "{{value}}",
                                },
                            },
                        },
                    },
                },
            },
        },

    ]
    # fmt: on
