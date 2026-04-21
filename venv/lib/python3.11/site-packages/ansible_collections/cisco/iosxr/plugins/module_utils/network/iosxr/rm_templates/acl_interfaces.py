from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class Acl_interfacesTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Acl_interfacesTemplate, self).__init__(lines=lines, tmplt=self)

    # fmt: off
    PARSERS = [
        {
            'name': 'interface',
            'getval': re.compile(
                r'''
              ^interface
              \s(preconfigure)*\s*
              (?P<name>\S+)$''', re.VERBOSE,
            ),
            'setval': 'interface {{ name }}',
            'result': {
                '{{ name }}': {
                    'name': '{{ name }}',
                    'access_groups': {},
                },
            },
            'shared': True,
        },
        {
            "name": "access_groups",
            "getval": re.compile(
                r"""
                \s+(?P<afi>ipv4|ipv6)
                \saccess-group\s(?P<acl_name>\S+)
                \s(?P<direction>\S+)$
                """,
                re.VERBOSE,
            ),
            "setval": "{{ afi }} access-group {{ name }} {{ 'egress' if direction == 'out' else 'ingress' }}",
            "result": {
                "{{ name }}": {
                    "access_groups": {
                        "{{ afi }}": {
                            "afi": "{{ afi }}",
                            "acls": [
                                {
                                    "name": "{{ acl_name }}",
                                    "direction": "{{ 'in' if direction == 'ingress' else 'out' }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
