# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
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

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_bgp_params_confederation(config_data):
    command = []
    for list_el in config_data["bgp_params"]["confederation"]:
        for k, v in iteritems(list_el):
            command.append(
                "protocols bgp {as_number} parameters confederation ".format(**config_data)
                + k
                + " "
                + str(v),
            )

    return command


def _tmplt_bgp_maximum_paths(config_data):
    command = []
    for list_el in config_data["maximum_paths"]:
        command.append(
            "protocols bgp {as_number} maximum-paths ".format(**config_data)
            + list_el["path"]
            + " "
            + str(list_el["count"]),
        )
    return command


def _tmplt_delete_bgp_maximum_paths(config_data):
    command = "protocols bgp {as_number} maximum-paths".format(**config_data)
    return command


def _tmplt_bgp_params_default(config_data):
    command = "protocols bgp {as_number} parameters default".format(**config_data)
    if config_data["bgp_params"]["default"].get("no_ipv4_unicast"):
        command += " no-ipv4-unicast"
    if config_data["bgp_params"]["default"].get("local_pref"):
        command += " local-pref {local_pref}".format(**config_data["bgp_params"]["default"])
    return command


def _tmplt_bgp_neighbor_timers(config_data):
    command = []
    for k, v in iteritems(config_data["neighbor"]["timers"]):
        command.append(
            "protocols bgp {as_number} neighbor ".format(**config_data)
            + config_data["neighbor"]["address"]
            + " timers "
            + k
            + " "
            + str(v),
        )

    return command


def _tmplt_bgp_timers(config_data):
    command = []
    for k, v in iteritems(config_data["timers"]):
        command.append(
            "protocols bgp {as_number} ".format(**config_data) + "timers " + k + " " + str(v),
        )

    return command


def _tmplt_bgp_neighbor_attribute_unchanged_as_path(config_data):
    command = "protocols bgp {as_number} ".format(
        **config_data,
    ) + "neighbor {address} attribute-unchanged as-path".format(**config_data["neighbor"])
    return command


def _tmplt_bgp_neighbor_attribute_unchanged_med(config_data):
    command = "protocols bgp {as_number} ".format(
        **config_data,
    ) + "neighbor {address} attribute-unchanged med".format(**config_data["neighbor"])
    return command


def _tmplt_bgp_neighbor_attribute_unchanged_next_hop(config_data):
    command = "protocols bgp {as_number} ".format(
        **config_data,
    ) + "neighbor {address} attribute-unchanged next-hop".format(**config_data["neighbor"])
    return command


def _tmplt_bgp_neighbor_distribute_list(config_data):
    command = []
    for list_el in config_data["neighbor"]["distribute_list"]:
        command.append(
            "protocols bgp {as_number} ".format(**config_data)
            + "neighbor {address} distribute-list ".format(**config_data["neighbor"])
            + list_el["action"]
            + " "
            + str(list_el["acl"]),
        )
    return command


def _tmplt_bgp_neighbor_route_map(config_data):
    command = []
    for list_el in config_data["neighbor"]["route_map"]:
        command.append(
            "protocols bgp {as_number} ".format(**config_data)
            + "neighbor {address} route-map ".format(**config_data["neighbor"])
            + list_el["action"]
            + " "
            + str(list_el["route_map"]),
        )
    return command


def _tmplt_bgp_neighbor_prefix_list(config_data):
    command = []
    for list_el in config_data["neighbor"]["prefix_list"]:
        command.append(
            "protocols bgp {as_number} ".format(**config_data)
            + "neighbor {address} prefix-list ".format(**config_data["neighbor"])
            + list_el["action"]
            + " "
            + str(list_el["prefix_list"]),
        )
    return command


def _tmplt_bgp_neighbor_filter_list(config_data):
    command = []
    for list_el in config_data["neighbor"]["filter_list"]:
        command.append(
            "protocols bgp {as_number} ".format(**config_data)
            + "neighbor {address} filter-list ".format(**config_data["neighbor"])
            + list_el["action"]
            + " "
            + str(list_el["path_list"]),
        )
    return command


def _tmplt_bgp_params_distance(config_data):
    command = (
        "protocols bgp {as_number} parameters distance global ".format(**config_data)
        + config_data["bgp_params"]["distance"]["type"]
        + " "
        + str(config_data["bgp_params"]["distance"]["value"])
    )
    return command


class Bgp_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        prefix = {"set": "set", "remove": "delete"}
        super(Bgp_globalTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            prefix=prefix,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "router",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }}",
            "compval": "as_number",
            "result": {
                "as_number": "{{ as_num }}",
            },
        },
        {
            "name": "maximum_paths",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+maximum-paths
                \s+(?P<path>ebgp|ibgp)
                \s+(?P<count>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_maximum_paths,
            "remval": _tmplt_delete_bgp_maximum_paths,
            "compval": "maximum_paths",
            "result": {
                "as_number": "{{ as_num }}",
                "maximum_paths": [
                    {
                        "path": "{{ path }}",
                        "count": "{{ count }}",
                    },
                ],
            },
        },
        {
            "name": "neighbor.advertisement_interval",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+advertisement-interval
                \s+(?P<interval>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} advertisement-interval {{ neighbor.advertisement_interval }}",
            "remval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} advertisement-interval",
            "compval": "neighbor.advertisement_interval",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "advertisement_interval": "{{ interval }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.allowas_in",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+allowas-in
                \s+number
                \s+(?P<num>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} allowas-in number {{ neighbor.allowas_in }}",
            "compval": "neighbor.allowas_in",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "allowas_in": "{{ count }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.as_override",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+as-override
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} as-override",
            "compval": "neighbor.as_override",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "as_override": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.attribute_unchanged.as_path",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+attribute-unchanged
                \s+(?P<val>as-path)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_attribute_unchanged_as_path,
            "compval": "neighbor.attribute_unchanged",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "attribute_unchanged": {
                            "{{ 'as_path' }}": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.attribute_unchanged.med",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+attribute-unchanged
                \s+(?P<val>med)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_attribute_unchanged_med,
            "compval": "neighbor.attribute_unchanged",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "attribute_unchanged": {
                            "{{ 'med' }}": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.attribute_unchanged.next_hop",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+attribute-unchanged
                \s+(?P<val>next-hop)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_attribute_unchanged_next_hop,
            "compval": "neighbor.attribute_unchanged",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "attribute_unchanged": {
                            "{{ 'next_hop' }}": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.capability_dynamic",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+capability
                \s+(?P<dynamic>dynamic)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} capability dynamic",
            "compval": "neighbor.capability.dynamic",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "capability": {
                            "dynamic": "{{ True if dynamic is defined}}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.capability_orf",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+capability
                \s+orf
                \s+prefix-list
                \s+(?P<orf>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} capability orf prefix-list {{ neighbor.capability.orf }}",
            "compval": "neighbor.capability.orf",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "capability": {
                            "orf": "{{ orf }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.default_originate",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+default-originate
                \s+route-map
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} default-originate route-map {{ neighbor.default_originate }}",
            "compval": "neighbor.advertisement_interval",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "default_originate": "{{ map }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.description",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+description
                \s+(?P<desc>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} description {{ neighbor.description }}",
            "compval": "neighbor.description",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "description": "{{ desc }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.disable_capability_negotiation",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+disable-capability-negotiation
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} disable-capability-negotiation",
            "compval": "neighbor.disable_capability_negotiation",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "disable_capability_negotiation": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.disable_connected_check",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+disable-connected-check
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} disable-connected-check",
            "compval": "neighbor.disable_connected_check",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "disable_connected_check": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.disable_send_community",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+disable-send-community
                \s+(?P<comm>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} disable-send-community {{ neighbor.disable_send_community }}",
            "compval": "neighbor.disable_send_community",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "disable_send_community": "{{ comm }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.distribute_list",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+distribute-list
                \s+(?P<action>export|import)
                \s+(?P<list>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_distribute_list,
            "compval": "neighbor.distribute_list",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "distribute_list": [
                            {
                                "action": "{{ action }}",
                                "acl": "{{ list }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "neighbor.ebgp_multihop",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+ebgp-multihop
                \s+(?P<hop>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} ebgp-multihop {{ neighbor.ebgp_multihop }}",
            "compval": "neighbor.ebgp_multihop",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "ebgp_multihop": "{{ hop|int }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.filter_list",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+filter-list
                \s+(?P<action>export|import)
                \s+(?P<list>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_filter_list,
            "compval": "neighbor.filter_list",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "filter_list": [
                            {
                                "action": "{{ action }}",
                                "path_list": "{{ list }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "neighbor.local_as",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+local-as
                \s+(?P<as>\S+)
                \s+no-prepend
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} local-as {{ neighbor.local_as }} no-prepend",
            "compval": "neighbor.local_as",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "local_as": "{{ as }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.maximum_prefix",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+maximum-prefix
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} maximum-prefix {{ neighbor.maximum_prefix }}",
            "compval": "neighbor.maximum_prefix",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "maximum_prefix": "{{ num }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.nexthop_self",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+nexthop-self
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} nexthop-self",
            "compval": "neighbor.nexthop_self",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "nexthop_self": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.override_capability",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+override-capability
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} override-capability",
            "compval": "neighbor.override_capability",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "override_capability": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.passive",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+passive
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} passive",
            "compval": "neighbor.passive",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "passive": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.password",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+password
                \s+(?P<pwd>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} password {{ neighbor.password }}",
            "compval": "neighbor.password",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "password": "{{ pwd }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.peer_group_name",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+peer-group
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} peer-group {{ neighbor.peer_group_name }}",
            "compval": "neighbor.peer_group_name",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "peer_group_name": "{{ name }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.port",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+port
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} port {{ neighbor.port }}",
            "compval": "neighbor.port",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "port": "{{ num|int }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.prefix_list",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+prefix-list
                \s+(?P<action>export|import)
                \s+(?P<list>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_prefix_list,
            "compval": "neighbor.prefix_list",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "prefix_list": [
                            {
                                "action": "{{ action }}",
                                "prefix_list": "{{ list }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "neighbor.remote_as",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+remote-as
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} remote-as {{ neighbor.remote_as }}",
            "compval": "neighbor.remote_as",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "remote_as": "{{ num|int }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.remove_private_as",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+remote-private-as
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} remote-private-as",
            "compval": "neighbor.remove_private_as",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "remove_private_as": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.route_map",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+route-map
                \s+(?P<action>export|import)
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_route_map,
            "compval": "neighbor.route_map",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "route_map": [
                            {
                                "action": "{{ action }}",
                                "route_map": "{{ map }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "neighbor.route_reflector_client",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+route-reflector-client
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} router-reflector-client",
            "compval": "neighbor.route_reflector_client",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "route_reflector_client": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.route_server_client",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+route-server-client
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} route-server-client",
            "compval": "neighbor.route_server_client",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "route_server_client": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.shutdown",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+shutdown
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} shutdown",
            "compval": "neighbor.shutdown",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "shutdown": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.soft_reconfiguration",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+soft-reconfiguration
                \s+inbound
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} soft-reconfiguration",
            "compval": "neighbor.soft_reconfiguration",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "soft_reconfiguration": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.strict_capability_match",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+strict-capability-match
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} strict-capability-match",
            "compval": "neighbor.strict_capability_match",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "strict_capability_match": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.unsuppress_map",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+unsuppress-map
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} unsuppress-map {{ neighbor.unsuppress_map }}",
            "compval": "neighbor.unsuppress_map",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "unsuppress_map": "{{ map }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.update_source",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+update-source
                \s+(?P<src>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} update-source {{ neighbor.update_source }}",
            "compval": "neighbor.update_source",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "update_source": "{{ src }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.weight",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+weight
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} weight {{ neighbor.weight }}",
            "compval": "neighbor.weight",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "weight": "{{ num }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.ttl_security",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+ttl-security
                \s+(?P<ttl>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} ttl-security {{ neighbor.ttl_security }}",
            "compval": "neighbor.ttl_security",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "ttl_security": "{{ ttl|int }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.timers",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+timers
                \s+(?P<type>connect|holdtime|keepalive)
                \s+(?P<sec>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor_timers,
            "remval": "protocols bgp {{ as_number }} neighbor {{ neighbor.address }} timers",
            "compval": "neighbor.timers",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbor": {
                    "{{ address }}": {
                        "address": "{{ address }}",
                        "timers": {
                            "{{ type }}": "{{ sec }}",
                        },
                    },
                },
            },
        },
        {
            "name": "timers",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+timers
                \s+(?P<type>\S+)
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_timers,
            "remval": "protocols bgp {{ as_number }} timers",
            "compval": "timers",
            "result": {
                "as_number": "{{ as_num }}",
                "timers": {
                    "{{ type }}": "{{ val }}",
                },
            },
        },
        {
            "name": "bgp_params.always_compare_med",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+always-compare-med
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters always-compare-med",
            "compval": "bgp_params.always_compare_med",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "always_compare_med": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.bestpath.as_path",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+bestpath
                \s+as-path
                \s+(?P<path>confed|ignore)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters bestpath as-path {{ bgp_params.bestpath.as_path }}",
            "compval": "bgp_params.bestpath.as_path",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "bestpath": {
                        "as_path": "{{ path }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.bestpath.compare_routerid",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+bestpath
                \s+compare-routerid
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters bestpath compare-routerid",
            "compval": "bgp_params.bestpath.compare_routerid",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "bestpath": {
                        "compare_routerid": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.bestpath.med",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+bestpath
                \s+med
                \s+(?P<path>confed|missing-as-worst)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters bestpath med {{ bestpath.med }}",
            "compval": "bgp_params.bestpath.med",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "bestpath": {
                        "med": "{{ path }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.cluster_id",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+cluster-id
                \s+(?P<id>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters cluster-id {{ bgp_params.cluster_id }}",
            "compval": "bgp_params.cluster_id",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "cluster_id": "{{ id }}",
                },
            },
        },
        {
            "name": "bgp_params.confederation",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+confederation
                \s+(?P<type>identifier|peers)
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params_confederation,
            "compval": "bgp_params.always_compare_med",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "confederation": [
                        {
                            "peers": "{{ val if type == 'peers' }}",
                            "identifier": "{{ val if type == 'identifier' }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "bgp_params.dampening_half_life",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+dampening
                \s+half-life
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters dampening half-life {{ bgp_params.dampening.half_life}}",
            "compval": "bgp_params.dampening.half_life",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "dampening": {
                        "half_life": "{{ val }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.dampening_max_suppress_time",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+dampening
                \s+max-suppress-time
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters dampening max-suppress-time {{ bgp_params.dampening.max_suppress_time}}",
            "compval": "bgp_params.dampening.max_suppress_time",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "dampening": {
                        "max_suppress_time": "{{ val }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.dampening_re_use",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+dampening
                \s+re-use
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters dampening re-use {{ bgp_params.dampening.re_use}}",
            "compval": "bgp_params.dampening.re_use",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "dampening": {
                        "re_use": "{{ val }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.dampening_start_suppress_time",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+dampening
                \s+start-suppress-time
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters dampening start-suppress-time {{ bgp_params.dampening.start_suppress_time}}",
            "compval": "bgp_params.dampening.start_suppress_time",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "dampening": {
                        "start_suppress_time": "{{ val }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.default",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+default
                \s*(?P<no_ipv4_unicast>no-ipv4-unicast)*
                \s*(?P<local_pref>local-pref\s\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params_default,
            "remval": "protocols bgp {{ as_number }} parameters default",
            "compval": "bgp_params.default",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "default": {
                        "no_ipv4_unicast": "{{ True if no_ipv4_unicast is defined }}",
                        "local_pref": "{{ local_pref.split(" " )[1] if local_pref is defined }}",
                    },
                },
            },
        },
        {
            "name": "bgp_params.deterministic_med",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+deterministic-med
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters deterministic-med",
            "compval": "bgp_params.deterministic_med",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "deterministic_med": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.disbale_network_import_check",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+disable-network-import-check
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters disable-network-import-check",
            "compval": "bgp_params.disable_network_import_check",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "disable_network_import_check": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.distance.prefix",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+distance\sprefix
                \s+(?P<prefix>\S+)
                \s+distance
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters distance prefix {{ bgp_params.distance.prefix }} distance {{ bgp_params.distance.value }}",
            "compval": "bgp_params.distance.prefix",
            "remval": "protocols bgp {{ as_number }} parameters distance prefix",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "distance": [
                        {
                            "prefix": "{{ prefix }}",
                            "value": "{{ val }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "bgp_params.distance.global",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+distance\sglobal
                \s+(?P<type>\S+)
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params_distance,
            "remval": "protocols bgp {{ as_number }} parameters distance global",
            "compval": "bgp_params.distance",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "distance": [
                        {
                            "type": "{{ type }}",
                            "value": "{{ val }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "bgp_params.enforce_first_as",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+enforce-first-as
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters enforce-first-as",
            "compval": "bgp_params.enforce_first_as",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "enforce_first_as": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.graceful_restart",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+graceful-restart\s+stalepath-time
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters graceful-restart stalepath-time {{ bgp_params.graceful_restart }}",
            "compval": "bgp_params.graceful_restart",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "graceful_restart": "{{ val }}",
                },
            },
        },
        {
            "name": "bgp_params.log_neighbor_changes",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+log-neighbor-changes
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters log-neighbor-changes",
            "compval": "bgp_params.log_neighbor_changes",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "log_neighbor_changes": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.no_client_to_client_reflection",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+no-client-to-client-reflection
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters no-client-to-client-reflection",
            "compval": "bgp_params.log_neighbor_changes",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "no_client_to_client_reflection": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.no_fast_external_failover",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+no-fast-external-failover
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters no-fast-external-failover",
            "compval": "bgp_params.no_fast_external_failover",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "no_fast_external_failover": "{{ True }}",
                },
            },
        },
        {
            "name": "bgp_params.routerid",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+router-id
                \s+(?P<id>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters router-id {{ bgp_params.router_id }}",
            "compval": "bgp_params.router_id",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "router_id": "{{ id }}",
                },
            },
        },
        {
            "name": "bgp_params.scan_time",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+parameters
                \s+scan-time
                \s+(?P<sec>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} parameters scan-time {{ bgp_params.scan_time }}",
            "compval": "bgp_params.scan_time",
            "result": {
                "as_number": "{{ as_num }}",
                "bgp_params": {
                    "scan_time": "{{ val }}",
                },
            },
        },

    ]
    # fmt: on
