# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Ntp parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class NtpTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        prefix = {"set": "set", "remove": "delete"}
        self._overrides = {  # 1.4+ by default
            "_path": "service",  # 1.4 or greater, "system" for 1.3 or less
            "_ac": "allow-client",  # 1.4 or greater, "allow-clients" for 1.3 or less
        }
        super(NtpTemplate, self).__init__(lines=lines, tmplt=self, prefix=prefix, module=module)

    def set_ntp_path(self, path: str):
        """set_ntp_path"""
        self._overrides["_path"] = path

    def set_ntp_ac(self, ac: str):
        """set_ntp_ac"""
        self._overrides["_ac"] = ac

    def render(self, data, parser_name, negate=False):
        """render"""
        # add path to the data before rendering
        data = data.copy()
        data.update(self._overrides)
        # call the original method
        return super(NtpTemplate, self).render(data, parser_name, negate)

    # fmt: off
    PARSERS = [

        # set system ntp allow_clients address <address>
        {
            "name": "allow_clients",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp\s(?P<ac>allow-clients|allow-client)\saddress (\s(?P<ipaddress>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp {{_ac}} address {{allow_clients}}",
            "result": {
                "allow_clients": ["{{ipaddress}}"],
            },
        },

        # set system ntp allow_clients
        {
            "name": "allow_clients_delete",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp\s(?P<ac>allow-clients|allow-client)
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp {{_ac}}",
            "result": {

            },

        },

        # set system ntp listen_address <address>
        {
            "name": "listen_addresses",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp\slisten-address (\s(?P<ip_address>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp listen-address {{listen_addresses}}",
            "result": {
                "listen_addresses": ["{{ip_address}}"],
            },
        },

        # set system ntp listen_address
        {
            "name": "listen_addresses_delete",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp\slisten-address
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp listen-address",
            "result": {
            },
        },

        # set {{path}} ntp - for deleting the ntp configuration
        {
            "name": "service_delete",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp$
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp",
            "result": {
            },
        },

        # set system ntp server <name>
        {
            "name": "server",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp\sserver (\s(?P<name>\S+))
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp server {{server}}",
            "result": {
                "servers": {
                    "{{name}}": {
                        "server": "{{name}}",
                    },
                },

            },
        },

        # set system ntp server <name> <options>
        {
            "name": "options",
            "getval": re.compile(
                r"""
                ^set\s(?P<path>system|service)\sntp\sserver
                \s(?P<name>\S+)
                \s(?P<options>dynamic|preempt|pool|noselect|prefer|nts|interleave|ptp)
                $""",
                re.VERBOSE,
            ),
            "setval": "{{_path}} ntp server {{server}} {{options}}",
            "result": {
                "servers": {
                    "{{name}}": {
                        "server": "{{name}}",
                        "options": ["{{options}}"],
                    },
                },
            },
        },
    ]
    # fmt: on
