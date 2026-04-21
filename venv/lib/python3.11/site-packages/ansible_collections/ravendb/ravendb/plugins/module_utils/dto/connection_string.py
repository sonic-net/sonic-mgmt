# -*- coding: utf-8 -*-
#
# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ConnectionStringSpec(object):
    def __init__(self, cs_type, name, properties=None):
        self.cs_type = str(cs_type or "").upper()
        self.name = name
        self.properties = properties or {}
