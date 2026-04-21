#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = """
    name: interface_range
    short_description: query interfaces from a range or comma separated list of ranges
    description:
      - this lookup returns interfaces from a range or comma separated list of ranges given to it
    notes:
      - duplicate interfaces from overlapping ranges will only be returned once
    options:
      _terms:
        description: comma separated strings of interface ranges
        required: True
"""

EXAMPLES = """
- name: "loop through range of interfaces"
  ansible.builtin.debug:
    msg: "{{ item }}"
  with_items: "{{ query('cisco.aci.interface_range', '1/1-4,1/20-25', '1/5', '1/2/3/8-10', '5/0-2') }}"
"""

RETURN = """
  _list:
    description: list of interfaces
    type: list
    elements: str
"""

import re

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


class LookupModule(LookupBase):
    def run(self, terms, **kwargs):
        interfaces = []
        errors = []

        for interface_range in ",".join(terms).replace(" ", "").split(","):
            if re.fullmatch(r"((\d+/)+\d+-\d+$)", interface_range):
                slots = interface_range.rsplit("/", 1)[0]
                range_start, range_stop = interface_range.rsplit("/", 1)[1].split("-")
                if int(range_stop) > int(range_start):
                    for x in range(int(range_start), int(range_stop) + 1):
                        interfaces.append("{0}/{1}".format(slots, x))
                else:
                    errors.append(interface_range)
            elif re.fullmatch(r"((\d+/)+\d+$)", interface_range):
                interfaces.append(interface_range)
            else:
                errors.append(interface_range)
        if errors:
            raise AnsibleError("Invalid range inputs, {0}".format(errors))

        # Sorted functionality for visual aid only, will result in 1/25, 1/3, 1/31
        # If full sort is needed leverage natsort package (https://github.com/SethMMorton/natsort)
        return sorted(set(interfaces))
