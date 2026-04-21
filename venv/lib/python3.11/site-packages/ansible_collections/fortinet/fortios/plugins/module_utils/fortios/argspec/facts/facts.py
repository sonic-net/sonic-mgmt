from __future__ import (absolute_import, division, print_function)
# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

"""
The arg spec for the fortios monitor module.
"""


class FactsArgs(object):
    """ The arg spec for the fortios monitor module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": False},
        "gather_subset": {
            "required": True, "type": "list", "elements": "dict",
            "options": {
                "fact": {"required": True, "type": "str"},
                "filters": {"required": False, "type": "list", "elements": "dict"}
            }
        }
    }
