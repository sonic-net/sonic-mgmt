#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The parse_cli_textfsm filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
name: parse_cli_textfsm
author: Peter Sprygada (@privateip)
version_added: "1.0.0"
short_description: parse_cli_textfsm filter plugin.
description:
  - The network filters also support parsing the output of a CLI command using the TextFSM library.
    To parse the CLI output with TextFSM use this filter.
  - Using the parameters below - C(data | ansible.netcommon.parse_cli_textfsm(template.yml))
  - This plugin is deprecated and will be removed in a future release after 2027-02-01, please Use ansible.utils.cli_parse instead.
notes:
  - Use of the TextFSM filter requires the TextFSM library to be installed.
options:
  value:
    description:
    - This source data on which parse_cli_textfsm invokes.
    type: raw
    required: True
  template:
    description:
    - The template to compare it with.
    - For example C(data | ansible.netcommon.parse_cli_textfsm(template.yml)),
      in this case C(data) represents this option.
    type: str
"""

EXAMPLES = r"""
# Using parse_cli_textfsm

- name: "Fetch command output"
  cisco.ios.ios_command:
    commands:
      - show lldp neighbors
  register: lldp_output

- name: "Invoke parse_cli_textfsm"
  ansible.builtin.set_fact:
    device_neighbors: "{{ lldp_output.stdout[0] | parse_cli_textfsm('~/ntc-templates/templates/cisco_ios_show_lldp_neighbors.textfsm') }}"

- name: "Debug"
  ansible.builtin.debug:
    msg: "{{ device_neighbors }}"

# Task Output
# -----------
#
# TASK [Fetch command output]
# ok: [rtr-1]

# TASK [Invoke parse_cli_textfsm]
# ok: [rtr-1]

# TASK [Debug]
# ok: [rtr-1] => {
#     "msg": [
#         {
#             "CAPABILITIES": "R",
#             "LOCAL_INTERFACE": "Gi0/0",
#             "NEIGHBOR": "rtr-3",
#             "NEIGHBOR_INTERFACE": "Gi0/0"
#         },
#         {
#             "CAPABILITIES": "R",
#             "LOCAL_INTERFACE": "Gi0/1",
#             "NEIGHBOR": "rtr-1",
#             "NEIGHBOR_INTERFACE": "Gi0/1"
#         }
#     ]
# }
"""

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ansible.netcommon.plugins.plugin_utils.parse_cli_textfsm import (
    parse_cli_textfsm,
)


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment

from ansible.utils.display import Display


@pass_environment
def _parse_cli_textfsm(*args, **kwargs):
    """parse textfsm"""
    display = Display()
    display.warning(
        "The 'parse_cli_textfsm' filter is deprecated and will be removed in a future release "
        "after 2027-02-01. Use 'ansible.utils.cli_parse' instead."
    )
    keys = ["value", "template"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="parse_cli_textfsm")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return parse_cli_textfsm(**updated_data)


class FilterModule(object):
    """parse_cli_textfsm"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"parse_cli_textfsm": _parse_cli_textfsm}
