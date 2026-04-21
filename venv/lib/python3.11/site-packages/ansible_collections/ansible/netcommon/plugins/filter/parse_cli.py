#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The parse_cli filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
name: parse_cli
author: Peter Sprygada (@privateip)
version_added: "1.0.0"
short_description: parse_cli filter plugin.
description:
  - The filter plugins converts the output of a network device
    CLI command into structured JSON output.
  - Using the parameters below - C(xml_data | ansible.netcommon.parse_cli(template.yml))
  - This plugin is deprecated and will be removed in a future release after 2027-02-01, please Use ansible.utils.cli_parse instead.
notes:
  - The parse_cli filter will load the spec file and pass the command output through it,
    returning JSON output. The YAML spec file defines how to parse the CLI output
options:
  output:
    description:
    - This source data on which parse_cli invokes.
    type: raw
    required: True
  tmpl:
    description:
    - The spec file should be valid formatted YAML.
      It defines how to parse the CLI output and return JSON data.
    - For example C(cli_data | ansible.netcommon.parse_cli(template.yml)),
      in this case C(cli_data) represents cli output.
    type: str
"""

EXAMPLES = r"""
# Using parse_cli

# outputConfig

# ip dhcp pool Data
#   import all
#   network 192.168.1.0 255.255.255.0
#   update dns
#   default-router 192.168.1.1
#   dns-server 192.168.1.1 8.8.8.8
#   option 42 ip 192.168.1.1
#   domain-name test.local
#   lease 8

# pconnection.yml

# ---
# vars:
#   dhcp_pool:
#     name: "{{ item.name }}"
#     network: "{{ item.network_ip }}"
#     subnet: "{{ item.network_subnet }}"
#     dns_servers: "{{ item.dns_servers_1 }}{{ item.dns_servers_2 }}"
#     domain_name: "{{ item.domain_name_0 }}{{ item.domain_name_1 }}{{ item.domain_name_2 }}{{ item.domain_name_3 }}"
#     options: "{{ item.options_1 }}{{ item.options_2 }}"
#     lease_days: "{{ item.lease_days }}"
#     lease_hours: "{{ item.lease_hours }}"
#     lease_minutes: "{{ item.lease_minutes }}"

# keys:
#   dhcp_pools:
#     value: "{{ dhcp_pool }}"
#     items: "^ip dhcp pool (
#           ?P<name>[^\\n]+)\\s+(?:import (?P<import_all>all)\\s*)?(?:network (?P<network_ip>[\\d.]+)
#           (?P<network_subnet>[\\d.]+)?\\s*)?(?:update dns\\s*)?(?:host (?P<host_ip>[\\d.]+)
#           (?P<host_subnet>[\\d.]+)\\s*)?(?:domain-name (?P<domain_name_0>[\\w._-]+)\\s+)?
#           (?:default-router (?P<default_router>[\\d.]+)\\s*)?(?:dns-server
#           (?P<dns_servers_1>(?:[\\d.]+ ?)+ ?)+\\s*)?(?:domain-name (?P<domain_name_1>[\\w._-]+)\\s+)?
#           (?P<options_1>(?:option [^\\n]+\\n*\\s*)*)?(?:domain-name (?P<domain_name_2>[\\w._-]+)\\s+)?(?P<options_2>(?:option [^\\n]+\\n*\\s*)*)?
#           (?:dns-server (?P<dns_servers_2>(?:[\\d.]+ ?)+ ?)+\\s*)?(?:domain-name
#           (?P<domain_name_3>[\\w._-]+)\\s*)?(lease (?P<lease_days>\\d+)(?: (?P<lease_hours>\\d+))?(?: (?P<lease_minutes>\\d+))?\\s*)?(?:update arp)?"

# playbook

- name: Add config data
  ansible.builtin.set_fact:
    opconfig: "{{lookup('ansible.builtin.file', 'outputConfig') }}"

- name: Parse Data
  ansible.builtin.set_fact:
    output: "{{ opconfig | parse_cli('pconnection.yml') }}"


# Task Output
# -----------
#
# TASK [Add config data]
# ok: [host] => changed=false
#   ansible_facts:
#     xml: |-
#       ip dhcp pool Data
#         import all
#         network 192.168.1.0 255.255.255.0
#         update dns
#         default-router 192.168.1.1
#         dns-server 192.168.1.1 8.8.8.8
#         option 42 ip 192.168.1.1
#         domain-name test.local
#         lease 8

# TASK [Parse Data]
# ok: [host] => changed=false
#   ansible_facts:
#     output:
#       dhcp_pools:
#       - dns_servers: 192.168.1.1 8.8.8.8
#         domain_name: test.local
#         lease_days: 8
#         lease_hours: null
#         lease_minutes: null
#         name: Data
#         network: 192.168.1.0
#         options: |-
#           option 42 ip 192.168.1.1
#         subnet: 255.255.255.0
"""

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ansible.netcommon.plugins.plugin_utils.parse_cli import parse_cli


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment

from ansible.utils.display import Display


@pass_environment
def _parse_cli(*args, **kwargs):
    """parse cli"""
    display = Display()
    display.warning(
        "The 'parse_cli' filter is deprecated and will be removed in a future release "
        "after 2027-02-01. Use 'ansible.utils.cli_parse' instead."
    )
    keys = ["output", "tmpl"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="parse_cli")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return parse_cli(**updated_data)


class FilterModule(object):
    """parse_cli"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"parse_cli": _parse_cli}
