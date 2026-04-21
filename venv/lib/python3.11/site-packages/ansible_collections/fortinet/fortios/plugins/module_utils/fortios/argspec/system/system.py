#
# -*- coding: utf-8 -*-
# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""
The arg spec for the fortios_facts module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class SystemArgs(object):
    """The arg spec for the fortios_facts module
    """

    FACT_SYSTEM_SUBSETS = frozenset([
        'system_current-admins_select',
        'system_firmware_select',
        'system_fortimanager_status',
        'system_ha-checksums_select',
        'system_interface_select',
        'system_status_select',
        'system_time_select',
    ])

    def __init__(self, **kwargs):
        pass
