#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment
    DOCUMENTATION = r'''
options:
    total_pages:
        description:
          - total_pages(int), use with perPage to get total results up to total_pages*perPage; -1 for all pages
        type: str
        required: true
    direction:
        description:
          - direction (string), direction to paginate, either "next" (default) or "prev" page
        type: str
        default: https://api.meraki.com/api/v1
'''
