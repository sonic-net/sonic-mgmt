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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.utils.utils import (
    normalize_interface,
)


def _tmplt_ntp_global_serve(config_data):
    el = config_data["serve"]
    command = "ntp serve"
    if el.get("access_lists"):
        command += " {afi} access-group".format(**el["access_lists"])
        if "acls" in el["access_lists"]:
            command += " {acl_name} ".format(**el["access_lists"]["acls"])
            if el["access_lists"]["acls"].get("vrf"):
                command += " vrf {vrf} ".format(**el["access_lists"]["acls"])
            command += el["access_lists"]["acls"]["direction"]
    return command


def _tmplt_ntp_global_authenticate(config_data):
    el = config_data["authenticate"]
    if el.get("enable"):
        command = "ntp authenticate"
        if el.get("servers"):
            command += " servers"
        return command


def _tmplt_ntp_global_authentication_keys(config_data):
    el = config_data["authentication_keys"]
    command = "ntp authentication-key "
    command += str(el["id"])
    command += " " + el["algorithm"]
    if "encryption" in el:
        command += " " + str(el["encryption"])
    if "key" in el:
        command += " " + el["key"]
    return command


def _tmplt_ntp_global_servers(config_data):
    el = config_data["servers"]
    command = "ntp server"
    if el.get("vrf"):
        command += " vrf {vrf}".format(**el)
    if el.get("server"):
        command += " {server}".format(**el)
    if el.get("burst"):
        command += " burst"
    if el.get("iburst"):
        command += " iburst"
    if el.get("key_id"):
        command += " key {key_id}".format(**el)
    if el.get("local_interface"):
        linterface = el.get("local_interface").replace(" ", "")
        command += " local-interface " + linterface
    if el.get("maxpoll"):
        command += " maxpoll {maxpoll}".format(**el)
    if el.get("minpoll"):
        command += " minpoll {minpoll}".format(**el)
    if el.get("prefer"):
        command += " prefer"
    if el.get("source"):
        interface_name = normalize_interface(el["source"])
        command += " source " + interface_name
    if el.get("version"):
        command += " version {version}".format(**el)
    return command


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
            "name": "authenticate",
            "getval": re.compile(
                r"""
                \s*ntp\sauthenticate
                \s*(?P<servers>servers)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ntp_global_authenticate,
            "result": {
                "authenticate": {
                    "enable": "{{ True if servers is undefined }}",
                    "servers": "{{ True if servers is defined }}",
                },
            },
        },
        {
            "name": "authentication_keys",
            "getval": re.compile(
                r"""
                \s*ntp\sauthentication-key
                \s+(?P<id>\d+)
                \s+(?P<algo>md5|sha1)
                \s*(?P<enc>0|7)*
                \s+(?P<line>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ntp_global_authentication_keys,
            "result": {
                "authentication_keys": {
                    "{{ id }}": {
                        "id": "{{ id }}",
                        "algorithm": "{{ algo }}",
                        "encryption": "{{ enc }}",
                        "key": "{{ line }}",
                    },
                },
            },
        },
        {
            "name": "local_interface",
            "getval": re.compile(
                r"""
                \s*ntp\slocal-interface
                \s+(?P<int>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'ntp local-interface {{ local_interface }}',
            "result": {
                "local_interface": "{{ int }}",
            },
        },
        {
            "name": "qos_dscp",
            "getval": re.compile(
                r"""
                \s*ntp\sqos\sdscp
                \s+(?P<val>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'ntp qos dscp {{ qos_dscp }}',
            "result": {
                "qos_dscp": "{{ val }}",
            },
        },
        {
            "name": "serve_all",
            "getval": re.compile(
                r"""
                \s*ntp\sserve
                \s+(?P<all>all)*
                $""",
                re.VERBOSE,
            ),
            "setval": "ntp serve all",
            "compval": "serve",
            "result": {
                "serve": {
                    "all": "{{ True if all is defined }}",
                },
            },
        },
        {
            "name": "serve",
            "getval": re.compile(
                r"""
                \s*ntp\sserve
                \s*(?P<afi>ip|ipv6)*
                \s*(access-group)*
                \s*(?P<name>\S+)*
                \s*(?P<vrf>vrf\s\S+)*
                \s*(?P<dir>in|out)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ntp_global_serve,
            "shared": True,
            "result": {
                "serve": {
                    "access_lists": {
                        "{{ afi }}": {
                            "afi": "{{ afi }}",
                            "acls": [
                                {
                                    "acl_name": "{{ name }}",
                                    "direction": "{{ dir }}",
                                    "vrf": "{{ vrf.split(" ")[1] }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "servers",
            "getval": re.compile(
                r"""
                \s*ntp\sserver
                \s*(?P<vrf>vrf\s\S+)*
                \s*(?P<host>\S+)*
                \s*(?P<prefer>prefer)*
                \s*(?P<burst>burst)*
                \s*(?P<iburst>iburst)*
                \s*(?P<maxpoll>maxpoll\s\d+)*
                \s*(?P<minpoll>minpoll\s\d+)*
                \s*(?P<source>source\s.+?)*
                \s*(?P<version>version\s[1-4])*
                \s*(?P<key>key\s.+)*
                (\s*local-interface\s(?P<local_int>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ntp_global_servers,
            "result": {
                "servers": {
                    "{{ host }}": {
                        "vrf": "{{ vrf.split(" ")[1] if vrf is defined }}",
                        "server": "{{ host }}",
                        "burst": "{{ True if burst is defined }}",
                        "iburst": "{{ True if iburst is defined }}",
                        "key_id": "{{ key.split(" ")[1] if key is defined }}",
                        "local_interface": "{{ local_int.replace(' ', '') if local_int is defined }}",
                        "maxpoll": "{{ maxpoll.split(" ")[1] if maxpoll is defined }}",
                        "minpoll": "{{ minpoll.split(" ")[1] if minpoll is defined }}",
                        "source": "{{ source.split(" ")[1] if source is defined }}",
                        "version": "{{ version.split(" ")[1] if version is defined }}",
                        "prefer": "{{ True if prefer is defined }}",
                    },
                },
            },
        },
        {
            "name": "trusted_key",
            "getval": re.compile(
                r"""
                \s*ntp\strusted-key
                \s*(?P<key>.+)*
                $""",
                re.VERBOSE,
            ),
            "setval": 'ntp trusted-key {{ trusted_key }}',
            "result": {
                "trusted_key": "{{ key }}",
            },
        },
    ]
    # fmt: on
