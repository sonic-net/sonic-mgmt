#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The vlan_expander plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type


def vlan_expander(data):
    expanded_list = []
    for each in data.split(","):
        if "-" in each:
            f, t = map(int, each.split("-"))
            expanded_list.extend(range(f, t + 1))
        else:
            expanded_list.append(int(each))
    return sorted(expanded_list)
