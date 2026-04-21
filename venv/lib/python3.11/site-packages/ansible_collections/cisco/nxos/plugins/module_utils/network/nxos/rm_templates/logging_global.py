# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Logging_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_hosts(data):
    cmd = "logging server {host}"
    data["client_identity"] = data.get("secure", {}).get("trustpoint", {}).get("client_identity")

    if "severity" in data:
        cmd += " {severity}"
    if "port" in data:
        cmd += " port {port}"
    if data["client_identity"]:
        cmd += " secure trustpoint client-identity {client_identity}"
    if "facility" in data:
        cmd += " facility {facility}"
    if "use_vrf" in data:
        cmd += " use-vrf {use_vrf}"

    cmd = cmd.format(**data)

    return cmd


class Logging_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Logging_globalTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "console",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\sconsole
                (\s(?P<severity>\d))?
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'no ' if console.state|d('') == 'disabled' else '' }}"
                      "logging console"
                      "{{ (' ' + console.severity|string) if console.severity is defined else '' }}",
            "result": {
                "console": {
                    "state": "{{ 'disabled' if negated is defined else None }}",
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "event.link_status.enable",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\sevent\slink-status\senable
                $""", re.VERBOSE,
            ),
            "setval": "logging event link-status enable",
            "result": {
                "event": {
                    "link_status": {
                        "enable": "{{ False if negated is defined else True }}",
                    },
                },
            },
        },
        {
            "name": "event.link_status.default",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\sevent\slink-status\sdefault
                $""", re.VERBOSE,
            ),
            "setval": "logging event link-status default",
            "result": {
                "event": {
                    "link_status": {
                        "default": "{{ False if negated is defined else True }}",
                    },
                },
            },
        },
        {
            "name": "event.trunk_status.enable",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\sevent\strunk-status\senable
                $""", re.VERBOSE,
            ),
            "setval": "logging event trunk-status enable",
            "result": {
                "event": {
                    "trunk_status": {
                        "enable": "{{ False if negated is defined else True }}",
                    },
                },
            },
        },
        {
            "name": "event.trunk_status.default",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\sevent\strunk-status\sdefault
                $""", re.VERBOSE,
            ),
            "setval": "logging event trunk-status default",
            "result": {
                "event": {
                    "trunk_status": {
                        "default": "{{ False if negated is defined else True }}",
                    },
                },
            },
        },
        {
            "name": "history.severity",
            "getval": re.compile(
                r"""
                ^logging\shistory
                \s(?P<severity>\d)
                $""", re.VERBOSE,
            ),
            "setval": "logging history {{ history.severity }}",
            "result": {
                "history": {
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "history.size",
            "getval": re.compile(
                r"""
                ^logging\shistory\ssize
                \s(?P<size>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "logging history size {{ history.size }}",
            "result": {
                "history": {
                    "size": "{{ size }}",
                },
            },
        },
        {
            "name": "ip.access_list.cache.entries",
            "getval": re.compile(
                r"""
                ^logging\sip\saccess-list\scache
                \sentries\s(?P<entries>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "logging ip access-list cache entries {{ ip.access_list.cache.entries }}",
            "result": {
                "ip": {
                    "access_list": {
                        "cache": {
                            "entries": "{{ entries }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ip.access_list.cache.interval",
            "getval": re.compile(
                r"""
                ^logging\sip\saccess-list\scache
                \sinterval\s(?P<interval>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "logging ip access-list cache interval {{ ip.access_list.cache.interval }}",
            "result": {
                "ip": {
                    "access_list": {
                        "cache": {
                            "interval": "{{ interval }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ip.access_list.cache.threshold",
            "getval": re.compile(
                r"""
                ^logging\sip\saccess-list\scache
                \sthreshold\s(?P<threshold>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "logging ip access-list cache threshold {{ ip.access_list.cache.threshold }}",
            "result": {
                "ip": {
                    "access_list": {
                        "cache": {
                            "threshold": "{{ threshold }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ip.access_list.detailed",
            "getval": re.compile(
                r"""
                ^logging\sip\saccess-list
                \s(?P<detailed>detailed)
                $""", re.VERBOSE,
            ),
            "setval": "logging ip access-list detailed",
            "result": {
                "ip": {
                    "access_list": {
                        "detailed": "{{ not not detailed }}",
                    },
                },
            },
        },
        {
            "name": "ip.access_list.include.sgt",
            "getval": re.compile(
                r"""
                ^logging\sip\saccess-list\sinclude
                \s(?P<sgt>sgt)
                $""", re.VERBOSE,
            ),
            "setval": "logging ip access-list include sgt",
            "result": {
                "ip": {
                    "access_list": {
                        "include": {
                            "sgt": "{{ not not sgt }}",
                        },
                    },
                },
            },
        },
        {
            # in some cases, the `logging level` command
            # has an extra space at the end
            "name": "facilities",
            "getval": re.compile(
                r"""
                ^logging\slevel
                \s(?P<facility>\S+)
                \s(?P<severity>\d+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "logging level {{ facility }} {{ severity }}",
            "result": {
                "facilities": [
                    {
                        "facility": "{{ facility }}",
                        "severity": "{{ severity }}",
                    },
                ],
            },
        },
        {
            "name": "logfile",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\slogfile
                (\s(?P<name>\S+))?
                (\s(?P<severity>\d+))?
                (\ssize\s(?P<size>\d+))?
                (\spersistent\sthreshold\s(?P<persistent_threshold>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'no ' if logfile.state|d('') == 'disabled' else '' }}"
                      "logging logfile"
                      "{{ ' ' + logfile.name if logfile.name|d('') else '' }}"
                      "{{ (' ' + logfile.severity|string) if logfile.severity is defined else '' }}"
                      "{{ (' size ' + logfile.size|string) if logfile.size is defined else '' }}"
                      "{{ (' persistent threshold ' + logfile.persistent_threshold|string) if logfile.persistent_threshold is defined else '' }}",
            "result": {
                "logfile": {
                    "state": "{{ 'disabled' if negated is defined else None }}",
                    "name": "{{ name }}",
                    "severity": "{{ severity }}",
                    "persistent_threshold": "{{ persistent_threshold }}",
                    "size": "{{ size }}",
                },
            },
        },
        {
            "name": "module",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\smodule
                (\s(?P<severity>\d))?
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'no ' if module.state|d('') == 'disabled' else '' }}"
                      "logging module"
                      "{{ (' ' + module.severity|string) if module.severity is defined else '' }}",
            "result": {
                "module": {
                    "state": "{{ 'disabled' if negated is defined else None }}",
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "monitor",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging\smonitor
                (\s(?P<severity>\d))?
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'no ' if monitor.state|d('') == 'disabled' else '' }}"
                      "logging monitor"
                      "{{ (' ' + monitor.severity|string) if monitor.severity is defined else '' }}",
            "result": {
                "monitor": {
                    "state": "{{ 'disabled' if negated is defined else None }}",
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "origin_id.hostname",
            "getval": re.compile(
                r"""
                ^logging\sorigin-id
                \s(?P<hostname>hostname)
                $""", re.VERBOSE,
            ),
            "setval": "logging origin-id hostname",
            "result": {
                "origin_id": {
                    "hostname": "{{ not not hostname }}",
                },
            },
        },
        {
            "name": "origin_id.ip",
            "getval": re.compile(
                r"""
                ^logging\sorigin-id
                \sip\s(?P<ip>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging origin-id ip {{ origin_id.ip }}",
            "result": {
                "origin_id": {
                    "ip": "{{ ip }}",
                },
            },
        },
        {
            "name": "origin_id.string",
            "getval": re.compile(
                r"""
                ^logging\sorigin-id
                \sstring\s(?P<string>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging origin-id string {{ origin_id.string }}",
            "result": {
                "origin_id": {
                    "string": "{{ string }}",
                },
            },
        },
        {
            "name": "rate_limit",
            "getval": re.compile(
                r"""
                ^(?P<negated>no\s)?
                logging
                \s(?P<rate_limit>rate-limit)
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'no ' if rate_limit|d('') == 'disabled' else '' }}"
                      "logging rate-limit",
            "result": {
                "rate_limit": "{{ 'disabled' if negated is defined else None }}",
            },
        },
        {
            "name": "rfc_strict",
            "getval": re.compile(
                r"""
                logging\srfc-strict
                \s(?P<rfc_strict>5424)
                $""", re.VERBOSE,
            ),
            "setval": "logging rfc-strict 5424",
            "result": {
                "rfc_strict": "{{ not not rfc_strict }}",
            },
        },
        {
            "name": "hosts",
            "getval": re.compile(
                r"""
                ^logging\sserver
                \s(?P<host>\S+)
                (\s(?P<severity>\d))?
                (\sport\s(?P<port>\d+))?
                (\ssecure\strustpoint\sclient-identity\s(?P<client_identity>\S+))?
                (\suse-vrf\s(?P<use_vrf>\S+))?
                (\sfacility\s(?P<facility>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_hosts,
            "result": {
                "hosts": [
                    {
                        "host": "{{ host }}",
                        "severity": "{{ severity }}",
                        "secure": {
                            "trustpoint": {
                                "client_identity": "{{ client_identity }}",
                            },
                        },
                        "port": "{{ port }}",
                        "facility": "{{ facility }}",
                        "use_vrf": "{{ use_vrf }}",
                    },
                ],
            },
        },
        {
            "name": "source_interface",
            "getval": re.compile(
                r"""
                ^logging\ssource-interface
                \s(?P<source_interface>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging source-interface {{ source_interface }}",
            "result": {
                "source_interface": "{{ source_interface }}",
            },
        },
        {
            "name": "timestamp",
            "getval": re.compile(
                r"""
                ^logging\stimestamp
                \s(?P<timestamp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging timestamp {{ timestamp }}",
            "result": {
                "timestamp": "{{ timestamp }}",
            },
        },
    ]
    # fmt: on
