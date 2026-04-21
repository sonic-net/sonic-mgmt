#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The vlan_parser plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.errors import AnsibleFilterError


def _raise_error(msg):
    raise AnsibleFilterError(msg)


def vlan_parser(data, first_line_len=48, other_line_len=44):
    """
    Input: Unsorted list of vlan integers
    Output: Sorted string list of integers according to IOS-like vlan list rules

    1. Vlans are listed in ascending order
    2. Runs of 3 or more consecutive vlans are listed with a dash
    3. The first line of the list can be first_line_len characters long
    4. Subsequent list lines can be other_line_len characters
    """
    if not isinstance(data, (list)):
        _raise_error("Input is not valid for vlan_parser")
    # Sort and remove duplicates
    sorted_list = sorted(set(data))

    if sorted_list[0] < 1 or sorted_list[-1] > 4094:
        _raise_error("Valid VLAN range is 1-4094")

    parse_list = []
    idx = 0
    while idx < len(sorted_list):
        start = idx
        end = start
        while end < len(sorted_list) - 1:
            if sorted_list[end + 1] - sorted_list[end] == 1:
                end += 1
            else:
                break

        if start == end:
            # Single VLAN
            parse_list.append(str(sorted_list[idx]))
        elif start + 1 == end:
            # Run of 2 VLANs
            parse_list.append(str(sorted_list[start]))
            parse_list.append(str(sorted_list[end]))
        else:
            # Run of 3 or more VLANs
            parse_list.append(str(sorted_list[start]) + "-" + str(sorted_list[end]))
        idx = end + 1

    line_count = 0
    result = [""]
    for vlans in parse_list:
        # First line (" switchport trunk allowed vlan ")
        if line_count == 0:
            if len(result[line_count] + vlans) > first_line_len:
                result.append("")
                line_count += 1
                result[line_count] += vlans + ","
            else:
                result[line_count] += vlans + ","

        # Subsequent lines (" switchport trunk allowed vlan add ")
        else:
            if len(result[line_count] + vlans) > other_line_len:
                result.append("")
                line_count += 1
                result[line_count] += vlans + ","
            else:
                result[line_count] += vlans + ","

    # Remove trailing orphan commas
    for idx in range(0, len(result)):
        result[idx] = result[idx].rstrip(",")

    # Sometimes text wraps to next line, but there are no remaining VLANs
    if "" in result:
        result.remove("")

    return result
