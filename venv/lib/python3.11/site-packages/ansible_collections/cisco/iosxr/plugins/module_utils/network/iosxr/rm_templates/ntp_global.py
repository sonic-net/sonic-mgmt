# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Ntp_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def tmplt_interfaces(config_data):
    commands = []
    name = config_data.get("name")
    vrf = config_data.get("vrf", "")
    if vrf:
        base_command = "ntp interface {name} vrf {vrf}".format(
            name=name,
            vrf=vrf,
        )
    else:
        base_command = "ntp interface {name}".format(name=name)
    if config_data.get("broadcast_client"):
        commands.append(
            "{base_command} broadcast client".format(
                base_command=base_command,
            ),
        )
    if config_data.get("broadcast_key"):
        commands.append(
            "{base_command} broadcast key {broadcast_key}".format(
                broadcast_key=config_data.get("broadcast_key"),
                base_command=base_command,
            ),
        )
    if config_data.get("broadcast_destination"):
        commands.append(
            "{base_command} broadcast destination {broadcast_destination}".format(
                broadcast_destination=config_data.get("broadcast_destination"),
                base_command=base_command,
            ),
        )
    if config_data.get("broadcast_version"):
        commands.append(
            "{base_command} broadcast version {broadcast_version}".format(
                broadcast_version=config_data.get("broadcast_version"),
                base_command=base_command,
            ),
        )
    if config_data.get("multicast_destination"):
        commands.append(
            "{base_command} multicast destination {multicast_destination}".format(
                multicast_destination=config_data.get("multicast_destination"),
                base_command=base_command,
            ),
        )
    if config_data.get("multicast_client"):
        commands.append(
            "{base_command} multicast client {multicast_client}".format(
                multicast_client=config_data.get("multicast_client"),
                base_command=base_command,
            ),
        )
    if config_data.get("multicast_key"):
        commands.append(
            "{base_command} multicast key {multicast_key}".format(
                multicast_key=config_data.get("multicast_key"),
                base_command=base_command,
            ),
        )
    elif config_data.get("multicast_version"):
        commands.append(
            "{base_command} multicast version {multicast_version}".format(
                multicast_version=config_data.get("multicast_version"),
                base_command=base_command,
            ),
        )
    elif config_data.get("multicast_ttl"):
        commands.append(
            "{base_command} multicast ttl {multicast_ttl}".format(
                multicast_ttl=config_data.get("multicast_ttl"),
                base_command=base_command,
            ),
        )
    return commands


def tmplt_access_group_vrfs(config_data):
    commands = []
    vrf_name = config_data.get("name")
    base_command = "ntp access-group vrf {name}".format(name=vrf_name)
    for ip in ["ipv4", "ipv6"]:
        if config_data.get(ip, {}).get("serve"):
            commands.append(
                "{base_command} {ip} serve {serve}".format(
                    base_command=base_command,
                    serve=config_data.get(ip, {}).get("serve"),
                    ip=ip,
                ),
            )
        if config_data.get(ip, {}).get("serve_only"):
            commands.append(
                "{base_command} {ip} serve-only {serve_only}".format(
                    base_command=base_command,
                    serve_only=config_data.get(ip, {}).get("serve_only"),
                    ip=ip,
                ),
            )
        if config_data.get(ip, {}).get("query_only"):
            commands.append(
                "{base_command} {ip} query-only {query_only}".format(
                    base_command=base_command,
                    query_only=config_data.get(ip, {}).get("query_only"),
                    ip=ip,
                ),
            )
        if config_data.get(ip, {}).get("peer"):
            commands.append(
                "{base_command} {ip} peer {peer}".format(
                    base_command=base_command,
                    peer=config_data.get(ip, {}).get("peer"),
                    ip=ip,
                ),
            )

    return commands


class Ntp_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Ntp_globalTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "access_group.ipv4.peer",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv4\speer\s(?P<peer>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv4 peer {{access_group.ipv4.peer}}",
            "result": {
                "access_group": {
                    "ipv4": {
                        "peer": "{{ peer }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv4.serve",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv4\sserve\s(?P<serve>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv4 serve {{access_group.ipv4.serve}}",
            "result": {
                "access_group": {
                    "ipv4": {
                        "serve": "{{ serve }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv4.serve_only",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv4\sserve-only\s(?P<serve>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv4 serve-only {{access_group.ipv4.serve_only}}",
            "result": {
                "access_group": {
                    "ipv4": {
                        "serve_only": "{{ serve }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv4.query_only",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv4\squery-only\s(?P<query_only>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv4 query-only {{access_group.ipv4.query_only}}",
            "result": {
                "access_group": {
                    "ipv4": {
                        "query_only": "{{ query_only }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv6.peer",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv6\speer\s(?P<peer>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv6 peer {{access_group.ipv6.peer}}",
            "result": {
                "access_group": {
                    "ipv6": {
                        "peer": "{{ peer }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv6.serve",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv6\sserve\s(?P<serve>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv6 serve {{access_group.ipv6.serve}}",
            "result": {
                "access_group": {
                    "ipv6": {
                        "serve": "{{ serve }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv6.serve_only",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv6\sserve-only\s(?P<serve>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv6 serve-only {{access_group.ipv6.serve_only}}",
            "result": {
                "access_group": {
                    "ipv6": {
                        "serve_only": "{{ serve }}",
                    },
                },
            },
        },
        {
            "name": "access_group.ipv6.query_only",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sipv6\squery-only\s(?P<query_only>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group ipv6 query-only {{access_group.ipv6.query_only}}",
            "result": {
                "access_group": {
                    "ipv6": {
                        "query_only": "{{ query_only }}",
                    },
                },
            },
        },
        {
            "name": "vrfs",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group
                (\svrf\s(?P<vrf>\S+))
                (\s(?P<ipv6>ipv6))?
                (\s(?P<ipv4>ipv4))?
                (\speer\s(?P<peer>\S+))?
                (\sserve\s(?P<serve>\S+))?
                (\sserve-only\s(?P<serve_only>\S+))?
                (\squery-only\s(?P<query_only>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_access_group_vrfs,
            "result": {
                "access_group": {
                    "vrfs": {
                        "{{vrf}}": {
                            "name": "{{vrf}}",
                            "ipv6": {
                                "query_only": "{{ query_only if ipv6 is defined else ''}}",
                                "serve_only": "{{ serve_only if ipv6 is defined else ''}}",
                                "serve": "{{ serve if ipv6 is defined else ''}}",
                                "peer": "{{ peer if ipv6 is defined else ''}}",
                            },
                            "ipv4": {
                                "query_only": "{{ query_only if ipv4 is defined else ''}}",
                                "serve_only": "{{ serve_only if ipv4 is defined else ''}}",
                                "serve": "{{ serve if ipv4 is defined else ''}}",
                                "peer": "{{ peer if ipv4 is defined else '' }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "authenticate",
            "getval": re.compile(
                r"""
                ^ntp\s(?P<authenticate>authenticate)
                $""", re.VERBOSE,
            ),
            "setval": "ntp authenticate",
            "result": {
                "authenticate": "{{ not not authenticate }}",
            },
        },
        {
            "name": "authentication_keys",
            "getval": re.compile(
                r"""
                ^ntp\sauthentication-key\s(?P<id>\d+)\smd5\s(?P<encryption>encrypted)\s(?P<key>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp authentication-key {{ id }} md5 "
                      "{{ ('encrypted ') if encryption else 'clear ' }}"
                      "{{ key }}",
            "result": {
                "authentication_keys": [
                    {
                        "id": "{{ id }}",
                        "key": "{{ key }}",
                        "encryption": "{{ not not encryption }}",
                    },
                ],
            },
        },
        {
            "name": "log_internal_sync",
            "getval": re.compile(
                r"""
                ^ntp\s(?P<log_internal_sync>log-internal-sync)
                $""", re.VERBOSE,
            ),
            "setval": "ntp log-internal-sync",
            "result": {
                "log_internal_sync": "{{ not not log_internal_sync }}",
            },
        },
        {
            "name": "broadcastdelay",
            "getval": re.compile(
                r"""
                ^ntp\sbroadcastdelay\s(?P<broadcastdelay>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp broadcastdelay {{  broadcastdelay }}",
            "result": {
                "broadcastdelay": "{{ broadcastdelay }}",
            },
        },
        {
            "name": "drift.aging_time",
            "getval": re.compile(
                r"""
                ^ntp\sdrift\saging\stime\s(?P<aging_time>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp drift aging time {{ drift.aging_time  }}",
            "result": {
                "drift": {
                    "aging_time": "{{ aging_time }}",
                },
            },
        },
        {
            "name": "drift.file",
            "getval": re.compile(
                r"""
                ^ntp\sdrift\sfile\s(?P<file>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp drift file {{ drift.file  }}",
            "result": {
                "drift": {
                    "file": "{{ file }}",
                },
            },
        },
        {
            "name": "ipv4.dscp",
            "getval": re.compile(
                r"""
                ^ntp
                \sipv4\sdscp\s(?P<dscp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp ipv4 dscp {{ipv4.dscp}}",
            "result": {
                "ipv4": {
                    "dscp": "{{dscp}}",
                },
            },
        },
        {
            "name": "ipv4.precedence",
            "getval": re.compile(
                r"""
                ^ntp
                (\sipv4\sprecedence\s(?P<precedence>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "ntp ipv4 precedence {{ipv4.precedence}}",
            "result": {
                "ipv4": {"precedence": "{{precedence}}"},
            },
        },
        {
            "name": "ipv6.dscp",
            "getval": re.compile(
                r"""
                ^ntp
                \sipv6\sdscp\s(?P<dscp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp ipv6 dscp {{ipv6.dscp}}",
            "result": {
                "ipv6": {
                    "dscp": "{{dscp}}",
                },
            },
        },
        {
            "name": "ipv6.precedence",
            "getval": re.compile(
                r"""
                ^ntp
                (\sipv6\sprecedence\s(?P<precedence>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "ntp ipv6 precedence {{ipv6.precedence}}",
            "result": {
                "ipv6": {"precedence": "{{precedence}}"},
            },
        },
        {
            "name": "max_associations",
            "getval": re.compile(
                r"""
                ^ntp\smax-associations\s(?P<max_associations>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp max-associations {{ max_associations }}",
            "result": {
                "max_associations": "{{ max_associations }}",
            },
        },
        {
            "name": "master.stratum",
            "getval": re.compile(
                r"""
                ^ntp\smaster\s(?P<master>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp master {{ master.stratum }}",
            "result": {
                "master": {
                    "stratum": "{{ master }}",
                },
            },
        },
        {
            "name": "passive",
            "getval": re.compile(
                r"""
                ^ntp\s(?P<passive>passive)
                $""", re.VERBOSE,
            ),
            "setval": "ntp passive",
            "result": {
                "passive": "{{ not not passive }}",
            },
        },
        {
            "name": "update_calendar",
            "getval": re.compile(
                r"""
                ^ntp\s(?P<update_calendar>update-calendar)
                $""", re.VERBOSE,
            ),
            "setval": "ntp update-calendar",
            "result": {
                "update_calendar": "{{ not not update_calendar }}",
            },
        },
        {
            "name": "source_interface",
            "getval": re.compile(
                r"""
                ^ntp\ssource\s(?P<source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp source {{ source_interface }}",
            "result": {
                "source_interface": "{{ source }}",
            },
        },
        {
            "name": "source_vrfs",
            "getval": re.compile(
                r"""
                ^ntp\ssource\svrf\s(?P<vrf>\S+)\s(?P<source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp vrf {{vrf}} source {{name}}",
            "result": {
                "source_vrfs": {
                    "{{vrf}}": {
                        "name": "{{ source }}",
                        "vrf": "{{vrf}}",
                    },
                },
            },
        },
        {
            "name": "trusted_keys",
            "getval": re.compile(
                r"""
                ^ntp\strusted-key\s(?P<key>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp trusted-key {{ key_id }}",
            "result": {
                "trusted_keys": [
                    {
                        "key_id": "{{ key }}",
                    },
                ],
            },
        },
        {
            "name": "peers",
            "getval": re.compile(
                r"""
                ^ntp\speer
                (\svrf\s(?P<vrf>\S+))?
                \s(?P<peer>\S+)
                (\sversion\s(?P<version>\d+))?
                (\skey\s(?P<key>\d+))?
                (\sminpoll\s(?P<minpoll>\d+))?
                (\smaxpoll\s(?P<maxpoll>\d+))?
                (\s(?P<prefer>prefer))?
                (\s(?P<burst>burst))?
                (\s(?P<iburst>iburst))?
                (\ssource\s(?P<source>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "ntp peer"
                      "{{ (' vrf ' + vrf) if vrf is defined else '' }}"
                      "{{ ( ' '  + peer ) if peer is defined else '' }}"
                      "{{ ' burst' if burst is defined else ''}}"
                      "{{ ' iburst' if iburst is defined else ''}}"
                      "{{ (' key ' + key_id|string) if key_id is defined else '' }}"
                      "{{ (' minpoll ' + minpoll|string) if minpoll is defined else '' }}"
                      "{{ (' maxpoll ' + maxpoll|string) if maxpoll is defined else '' }}"
                      "{{ ' prefer' if prefer is defined else ''}}"
                      "{{ (' version ' + version|string) if version is defined else '' }}"
                      "{{ (' source ' + source|string) if source is defined else '' }}",
            "result": {
                "peers": {
                    "{{peer}}_{{vrf|d()}}": {
                        "peer": "{{ peer }}",
                        "vrf": "{{ vrf }}",
                        "burst": "{{ not not burst }}",
                        "iburst": "{{ not not iburst }}",
                        "key_id": "{{ key }}",
                        "minpoll": "{{ minpoll }}",
                        "maxpoll": "{{ maxpoll }}",
                        "prefer": "{{ not not prefer }}",
                        "version": "{{ version }}",
                        "source": "{{source}}",
                    },
                },
            },
        },
        {
            "name": "servers",
            "getval": re.compile(
                r"""
                ^ntp\sserver
                (\svrf\s(?P<vrf>\S+))?
                \s(?P<server>\S+)
                (\sversion\s(?P<version>\d+))?
                (\skey\s(?P<key>\d+))?
                (\sminpoll\s(?P<minpoll>\d+))?
                (\smaxpoll\s(?P<maxpoll>\d+))?
                (\s(?P<prefer>prefer))?
                (\s(?P<burst>burst))?
                (\s(?P<iburst>iburst))?
                (\ssource\s(?P<source>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "ntp server"
                      "{{ (' vrf ' + vrf) if vrf is defined else '' }}"
                      "{{ ( ' '  + server ) if server is defined else '' }}"
                      "{{ ' burst' if burst is defined else ''}}"
                      "{{ ' iburst' if iburst is defined else ''}}"
                      "{{ (' key ' + key_id|string) if key_id is defined else '' }}"
                      "{{ (' minpoll ' + minpoll|string) if minpoll is defined else '' }}"
                      "{{ (' maxpoll ' + maxpoll|string) if maxpoll is defined else '' }}"
                      "{{ ' prefer' if prefer is defined else ''}}"
                      "{{ (' version ' + version|string) if version is defined else '' }}"
                      "{{ (' source ' + source|string) if source is defined else '' }}",
            "result": {
                "servers": {
                    "{{server}}_{{vrf|d()}}": {
                        "server": "{{ server }}",
                        "vrf": "{{ vrf }}",
                        "burst": "{{ not not burst }}",
                        "iburst": "{{ not not iburst }}",
                        "key_id": "{{ key }}",
                        "minpoll": "{{ minpoll }}",
                        "maxpoll": "{{ maxpoll }}",
                        "prefer": "{{ not not prefer }}",
                        "version": "{{ version }}",
                        "source": "{{source}}",
                    },
                },
            },
        },
        {
            "name": "interfaces",
            "getval": re.compile(
                r"""
                ^ntp\sinterface\s(?P<name>\S+)
                (\svrf\s(?P<vrf>\S+))?
                (\smulticast\sclient\s(?P<m_client>\S+))?
                (\smulticast\skey\s(?P<m_key>\S+))?
                (\smulticast\sdestination\s(?P<m_dest>\S+))?
                (\smulticast\sversion\s(?P<m_version>\S+))?
                (\smulticast\sttl\s(?P<m_ttl>\S+))?
                (\sbroadcast\sclient(?P<b_client>))?
                (\sbroadcast\skey\s(?P<b_key>\S+))?
                (\sbroadcast\sdestination\s(?P<b_dest>\S+))?
                (\sbroadcast\sversion\s(?P<ntp_version>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_interfaces,
            "result": {
                "interfaces": {
                    "{{name}}_{{vrf|d()}}": {
                        "vrf": "{{vrf}}",
                        "name": "{{name}}",
                        "broadcast_client": "{{True if b_client is defined}}",
                        "multicast_key": "{{m_key}}",
                        "multicast_destination": "{{m_dest}}",
                        "multicast_client": "{{m_client}}",
                        "multicast_version": "{{m_version}}",
                        "multicast_ttl": "{{m_ttl}}",
                        "broadcast_key": "{{b_key}}",
                        "broadcast_destination": "{{b_dest}}",
                        "broadcast_version": "{{ntp_version}}",
                    },
                },
            },
        },

    ]
    # fmt: on
