#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_external_trusted_ca
short_description: Manages external-trusted-ca objects on Checkpoint over Web Services API
description:
  - Manages external-trusted-ca objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  base64_certificate:
    description:
      - Certificate file encoded in base64.
    type: str
  retrieve_crl_from_http_servers:
    description:
      - Whether to retrieve Certificate Revocation List from http servers.
    type: bool
  crl_cache_method:
    description:
      - Weather to retrieve new Certificate Revocation List after the certificate expires or after a fixed period.
    type: str
    choices: ['timeout', 'expiration date']
  crl_cache_timeout:
    description:
      - When to fetch new Certificate Revocation List (in minutes).
    type: int
  allow_certificates_from_branches:
    description:
      - Allow only certificates from listed branches.
    type: bool
  branches:
    description:
      - Branches to allow certificates from. Required only if "allow-certificates-from-branches" set to "true".
    type: list
    elements: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-external-trusted-ca
  cp_mgmt_external_trusted_ca:
    base64_certificate:
      "MIICujCCAaKgAwIBAgIIP1+IHWHbl0EwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAxMJd3d3LnouY29tMB4XDTIzMTEyOTEyMzAwMFoXDTI0MTEyMDE2MDAwMFowFDESMBAGA1UEAxMJd3d3LnouY29tMI
       BIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoBreRGuq8u43GBog+ZaAnaR8ZF8cT2ppvtd3JoFmzTOQivLIt9sNtFYqEgHCtnNkKn9TRrxN14YscHgKIxfDSVlC9Rh0rrBvWgFqcm715Whr99Ogx
       JbYFkusFWJarSejIFx4n6MM48MJxLdtCP6Hy1G2cj1BCiCHj4i3VIVaDE/aMkSqJbYEvf+vFqUWxY8/uEuKI/HGhI7mhUPW4NSGL0Oafz5eEFVsxqV5NA19/JJZ9NajSkyANnaNL5raxGV0oeqaE3JB3lS
       ZfWbH6mQsToUxxwIQfsZiIBozajDdTgP3Kn4SMY0b+I/WAWgfigMSDTAIR8J1sdzGXy2w2kqQIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBUgrHztHwC1E0mU5c4reMrHg+
       +YRHrgJNHVIYQbL5I2TJHk9S3UZsynoMa1CO86rReOtR5xoGv4PCkyyOW+PNlWUtXF3tNgqWj/21+XzG4RBHPw89TaTxRCdo+MHX58fi07SIzKjmxfdkEi+7+HQEQluDZGViolrGBAw2rXq/SZ3q/11mNq
       b5ZyqyOa2u1sBF1ApvG5a/FBRTaO8gaiNelRf0PGYkuV+1HhF2XyP8Qk565d+uxUH5M7eHF2PNyVk/r/36T+x+UMql9y9iizA0ekuAjXLok1xYl3Vw4S5zXCXYtNZLOVrs+plJb7IrlElyTOAbDFuPugh0
       edz7uZ"
    name: external_ca
    state: present

- name: set-external-trusted-ca
  cp_mgmt_external_trusted_ca:
    base64_certificate:
      "MIICujCCAaKgAwIBAgIIFbLYzT2+3TMwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAxMJd3d3LnouY29tMB4XDTI0MDIwMTEyMzEwMFoXDTI0MTIzMTE2MDAwMFowFDESMBAGA1UEAxMJd3d3LnouY29tMI
       BIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoBreRGuq8u43GBog+ZaAnaR8ZF8cT2ppvtd3JoFmzTOQivLIt9sNtFYqEgHCtnNkKn9TRrxN14YscHgKIxfDSVlC9Rh0rrBvWgFqcm715Whr99Ogx
       JbYFkusFWJarSejIFx4n6MM48MJxLdtCP6Hy1G2cj1BCiCHj4i3VIVaDE/aMkSqJbYEvf+vFqUWxY8/uEuKI/HGhI7mhUPW4NSGL0Oafz5eEFVsxqV5NA19/JJZ9NajSkyANnaNL5raxGV0oeqaE3JB3lS
       ZfWbH6mQsToUxxwIQfsZiIBozajDdTgP3Kn4SMY0b+I/WAWgfigMSDTAIR8J1sdzGXy2w2kqQIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBxaE9O/LCjKfWeugPeDPvr3Ld
       i1mYsgNIyN+ES1iDoJHXrBQpVzZelJRr8leFgbghGUX7Fwdh1qZ2Jw6nmD1oe/Q7jkPzTngb6dIMI/kFK4eXcS4GJ3S7yGobLB7QUKK1vrYWZdNuAzR6jMRmFECS+lPF7zlTexnwwOkATMp6lzS7xEpEhk
       8eLpSQnYzvsM+rL9voU5q9MrdAJ2XaCZe4Crv75NdYU6ljD2eSYDrO148Tg480TlvT5wzBuyanKhI/Po2oLEVWU7h5tkensHKB5zvxigIr9ZkczdzVbbrRFi2jSQy+VxYWc0zCo/uO+yaKmmLfGDQEb8wZ
       Y1Ml27"
    crl_cache_method: expiration date
    name: external_ca
    retrieve_crl_from_http_servers: 'false'
    state: present

- name: delete-external-trusted-ca
  cp_mgmt_external_trusted_ca:
    name: external_ca
    state: absent
"""

RETURN = """
cp_mgmt_external_trusted_ca:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        base64_certificate=dict(type='str'),
        retrieve_crl_from_http_servers=dict(type='bool'),
        crl_cache_method=dict(type='str', choices=['timeout', 'expiration date']),
        crl_cache_timeout=dict(type='int'),
        allow_certificates_from_branches=dict(type='bool'),
        branches=dict(type='list', elements='str'),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'external-trusted-ca'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
