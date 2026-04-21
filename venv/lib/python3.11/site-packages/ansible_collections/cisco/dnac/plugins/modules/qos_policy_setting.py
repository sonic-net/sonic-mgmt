#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: qos_policy_setting
short_description: Resource module for Qos Policy Setting
description:
  - Manage operation update of the resource Qos Policy
    Setting.
  - API to update the application QoS policy setting.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deployByDefaultOnWiredDevices:
    description: Flag to indicate whether QoS policy
      should be deployed automatically on wired network
      device when it is provisioned. This would be only
      applicable for cases where the network device
      is assigned to a site where a QoS policy has been
      configured.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy UpdatesTheApplicationQoSPolicySetting
    description: Complete reference of the UpdatesTheApplicationQoSPolicySetting
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-the-application-qo-s-policy-setting
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.updates_the_application_qo_s_policy_setting,
  - Paths used are
    put /dna/intent/api/v1/qosPolicySetting,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.qos_policy_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    deployByDefaultOnWiredDevices: true
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
