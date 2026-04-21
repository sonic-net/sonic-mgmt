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
    dnac_host:
        description:
          - The Cisco DNA Center hostname.
        type: str
        required: true
    dnac_port:
        description:
          - The Cisco DNA Center port.
        type: int
        default: 443
    dnac_username:
        description:
          - The Cisco DNA Center username to authenticate.
        type: str
        default: admin
        aliases: [ user ]
    dnac_password:
        description:
          - The Cisco DNA Center password to authenticate.
        type: str
    dnac_verify:
        description:
          - Flag to enable or disable SSL certificate verification.
        type: bool
        default: true
    dnac_version:
        description:
          - Informs the SDK which version of Cisco DNA Center to use.
        type: str
        default: 2.3.7.6
    dnac_debug:
        description:
          - Flag for Cisco DNA Center SDK to enable debugging.
        type: bool
        default: false
    validate_response_schema:
        description:
          - Flag for Cisco DNA Center SDK to enable the validation of request bodies against a JSON schema.
        type: bool
        default: true
notes:
    - "Supports C(check_mode)"
    - "The plugin runs on the control node and does not use any ansible connection plugins, but instead the embedded connection manager from Cisco DNAC SDK"
    - "The parameters starting with dnac_ are used by the Cisco DNAC Python SDK to establish the connection"
'''
