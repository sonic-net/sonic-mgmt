#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
author: Francisco Munoz (@fmunoz)
description: Information module for devices _live_tools _arp_table
extends_documentation_fragment:
  - cisco.meraki.module_info
module: devices_live_tools_arp_table_info
notes:
  - Paths used are
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
short_description: Information module for devices _live _tools _arp _table
version_added: 2.16.0
"""

EXAMPLES = r"""
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample:
  - {}
"""
