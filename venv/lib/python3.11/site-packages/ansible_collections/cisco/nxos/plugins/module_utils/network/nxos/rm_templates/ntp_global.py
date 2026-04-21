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


class Ntp_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Ntp_globalTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "access_group.match_all",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\s(?P<match_all>match-all)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group match-all",
            "result": {
                "access_group": {
                    "match_all": "{{ True if match_all is defined else None }}",
                },
            },
        },
        {
            "name": "peer",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\speer\s(?P<acl>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group peer {{ access_list }}",
            "result": {
                "access_group": {
                    "peer": [
                        {
                            "access_list": "{{ acl }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "query_only",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\squery-only\s(?P<acl>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group query-only {{ access_list }}",
            "result": {
                "access_group": {
                    "query_only": [
                        {
                            "access_list": "{{ acl }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "serve",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sserve\s(?P<acl>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group serve {{ access_list }}",
            "result": {
                "access_group": {
                    "serve": [
                        {
                            "access_list": "{{ acl }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "serve_only",
            "getval": re.compile(
                r"""
                ^ntp\saccess-group\sserve-only\s(?P<acl>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp access-group serve-only {{ access_list }}",
            "result": {
                "access_group": {
                    "serve_only": [
                        {
                            "access_list": "{{ acl }}",
                        },
                    ],
                },
            },
        },
        {
            "name": "allow.control.rate_limit",
            "getval": re.compile(
                r"""
                ^ntp\sallow\scontrol\srate-limit\s(?P<rate_limit>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp allow control rate-limit {{ allow.control.rate_limit }}",
            "result": {
                "allow": {
                    "control": {
                        "rate_limit": "{{ rate_limit }}",
                    },
                },
            },
        },
        {
            "name": "allow.private",
            "getval": re.compile(
                r"""
                ^ntp\sallow\s(?P<private>private)
                $""", re.VERBOSE,
            ),
            "setval": "ntp allow private",
            "result": {
                "allow": {
                    "private": "{{ not not private }}",
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
                ^ntp\sauthentication-key\s(?P<id>\d+)\smd5\s(?P<key>\S+)\s(?P<encryption>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp authentication-key {{ id }} md5 {{ key }} {{ encryption }}",
            "result": {
                "authentication_keys": [
                    {
                        "id": "{{ id }}",
                        "key": "{{ key }}",
                        "encryption": "{{ encryption }}",
                    },
                ],
            },
        },
        {
            "name": "logging",
            "getval": re.compile(
                r"""
                ^ntp\s(?P<logging>logging)
                $""", re.VERBOSE,
            ),
            "setval": "ntp logging",
            "result": {
                "logging": "{{ not not logging }}",
            },
        },
        {
            "name": "master.stratum",
            "getval": re.compile(
                r"""
                ^ntp\smaster\s(?P<stratum>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp master {{ master.stratum }}",
            "result": {
                "master": {
                    "stratum": "{{ stratum }}",
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
            "name": "peers",
            "getval": re.compile(
                r"""
                ^ntp\speer
                \s(?P<peer>\S+)
                (\s(?P<prefer>prefer))?
                (\suse-vrf\s(?P<use_vrf>\S+))?
                (\skey\s(?P<key>\d+))?
                (\sminpoll\s(?P<minpoll>\d+))?
                (\smaxpoll\s(?P<maxpoll>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "ntp peer {{ peer }}"
                      "{{ ' prefer' if prefer|d(False) else ''}}"
                      "{{ (' use-vrf ' + vrf) if vrf is defined else '' }}"
                      "{{ (' key ' + key_id|string) if key_id is defined else '' }}"
                      "{{ (' minpoll ' + minpoll|string) if minpoll is defined else '' }}"
                      "{{ (' maxpoll ' + maxpoll|string) if maxpoll is defined else '' }}",
            "result": {
                "peers": [
                    {
                        "peer": "{{ peer }}",
                        "prefer": "{{ not not prefer }}",
                        "vrf": "{{ use_vrf }}",
                        "key_id": "{{ key }}",
                        "minpoll": "{{ minpoll }}",
                        "maxpoll": "{{ maxpoll }}",
                    },
                ],
            },
        },
        {
            "name": "servers",
            "getval": re.compile(
                r"""
                ^ntp\sserver
                \s(?P<server>\S+)
                (\s(?P<prefer>prefer))?
                (\suse-vrf\s(?P<use_vrf>\S+))?
                (\skey\s(?P<key>\d+))?
                (\sminpoll\s(?P<minpoll>\d+))?
                (\smaxpoll\s(?P<maxpoll>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "ntp server {{ server }}"
                      "{{ ' prefer' if prefer|d(False) else ''}}"
                      "{{ (' use-vrf ' + vrf) if vrf is defined else '' }}"
                      "{{ (' key ' + key_id|string) if key_id is defined else '' }}"
                      "{{ (' minpoll ' + minpoll|string) if minpoll is defined else '' }}"
                      "{{ (' maxpoll ' + maxpoll|string) if maxpoll is defined else '' }}",
            "result": {
                "servers": [
                    {
                        "server": "{{ server }}",
                        "prefer": "{{ not not prefer }}",
                        "vrf": "{{ use_vrf }}",
                        "key_id": "{{ key }}",
                        "minpoll": "{{ minpoll }}",
                        "maxpoll": "{{ maxpoll }}",
                    },
                ],
            },
        },
        {
            "name": "source",
            "getval": re.compile(
                r"""
                ^ntp\ssource\s(?P<source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp source {{ source }}",
            "result": {
                "source": "{{ source }}",
            },
        },
        {
            "name": "source_interface",
            "getval": re.compile(
                r"""
                ^ntp\ssource-interface(\s)+(?P<source_interface>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp source-interface {{ source_interface }}",
            "result": {
                "source_interface": "{{ source_interface }}",
            },
        },
        {
            "name": "trusted_keys",
            "getval": re.compile(
                r"""
                ^ntp\strusted-key\s(?P<key>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ntp trusted-key {{ key_id|string }}",
            "result": {
                "trusted_keys": [
                    {
                        "key_id": "{{ key }}",
                    },
                ],
            },
        },
    ]
    # fmt: on
