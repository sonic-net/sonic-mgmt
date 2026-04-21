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
module: cp_mgmt_identity_provider
short_description: Manages identity-provider objects on Checkpoint over Web Services API
description:
  - Manages identity-provider objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 JHF management version.
version_added: "6.5.0"
author: "Dor Berenstein (@chkp-dorbe)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  usage:
    description:
      - Usage of Identity Provider.
    type: str
    choices: ['managing_administrator_access', 'gateway_policy_and_logs']
  gateway:
    description:
      - Gateway for the SAML Identity Provider usage.
        Identified by name or UID. <font color="red">Required only when</font> 'usage' is set to 'gateway_policy_and_logs'.
    type: str
  service:
    description:
      - Service for the selected gateway. <font color="red">Required only when</font> 'usage' is set to 'gateway_policy_and_logs'.
    type: str
    choices: ['none', 'identity awareness', 'mobile access', 'vpn']
  data_receiving:
    description:
      - Data receiving method from the SAML Identity Provider.
    type: str
    choices: ['metadata_file', 'manually']
  received_identifier:
    description:
      - Received Identifier (Entity ID) based on the provider data. <font color="red">Required only when</font> 'data-receiving' is set to 'manually'.
    type: str
  login_url:
    description:
      - Login URL based on the provider data. <font color="red">Required only when</font> 'data-receiving' is set to 'manually'.
    type: str
  base64_metadata_file:
    description:
      - Metadata file encoded in base64 based on the provider data. <font color="red">Required only when</font> 'data-receiving' is set to 'metadata_file'.
    type: str
  base64_certificate:
    description:
      - Certificate file encoded in base64 based on provider data. <font color="red">Required only when</font> 'data-receiving' is set to 'manually'.
    type: str
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
  tags:
    description:
      - Collection of tag identifiers.
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
- name: add-identity-provider
  cp_mgmt_identity_provider:
    base64_certificate: |
        LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4RENDQWRpZ0F3SUJBZ0lRUTBWZVpLdVBLb0pQUWhaNGhDaWRzREFOQmdrcWhraUc5dzBCQVFzRkFEQTBNVEl3TUFZRFZRUURFeWxOYVdOeWIzTn
        ablFnUVhwMWNtVWdSbVZrWlhKaGRHVmtJRk5UVHlCRFpYSjBhV1pwWTJGMFpUQWVGdzB4T0RBME1UVXhNVEl6TXpOYUZ3MHlNVEEwTVRVeE1USXpNek5hTURReE1qQXdCZ05WQkFNVEtVMXBZM0p2YzI5b
        RDQkJlblZ5WlNCR1pXUmxjbUYwWldRZ1UxTlBJRU5sY25ScFptbGpZWFJsTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0VXVqYUd0OFhaODl2dXZ5a3lRVzVYb24vOFIv
        VB0ejRhYjBNM3RNVXZHWHozVXh0V1pTRStUR1hydjN3VHRLMCs4RmtNeXVKYUhGSXBLLzRVREZpRk1yQmxzR0Z1dmtTc1p5VjIzZlNGN3paaXlUWTZUN0EwcCtnczUwNVhEOUdBYjlWYmR3R0cwK0tDVnl
        c1ZRZ1YySXdKZ2l5aHF3RUNvY3dCcmFuN251SytURU5EMmwyZjlZcng1b1JNRU56NzB3bHlIMzZPWkJtdDBrNTk4L1doMEhEWUxaZW8wZHlTV3JOd3dlWXZTeEU4L01kbTQzWEV1U3pialR6ZnNNMHZVUn
        GQlNyVUxFYURPMS9JUDJVcjdCc2dId1JJL3hmb3FJbUsxS2twVXEwQWxjVEFpM3YxdTl6Qy9xTGdQd0F5UUl2dzlVQ3NpcnJQQTBZMFlPaFFJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUURja
        9qZEd6L0FJQ2pqTTBaN21ZbGdQNXpic2FRNWRDMmNqZjRESnFta21zV3VmUnBDNHNic3VoODcwY0NCS2N1dmgrb0dpekJRSHJQbTRUaEl2ZklsS0w4WGpMQVhiRnVSUG9IQWcwOHNMWGR2UFRCVE52REYx
        WhvcU5zMmo2ZUZxL2ROdXF2ZUJIcjVENXRLblYyWEJHRUhFOVJFOVdUa1pRT2MwaEhtQ3dNbWNZb3JYRzhCa3l1OXFwNXhyMDZMQ0htMnJLcnI2ZENRVldBV0R0MzhiS2t5STRobTVSNTVCclR5UldSdzI
        RS9YaFEwVksva1FJYW9GZ0hvaWo0ekg5bmxlZnZMbmhaZDVPRzROL29OS2pBKy9LbkVqaTdPQXhKWVNaR1FmRjU0R1AwQTE4VnF1NVVGaFBKMUZFQXZ5YjR0QnZtTzM1NFFVUys5UTY2agotLS0tLUVORC
        DRVJUSUZJQ0FURS0tLS0t
    data_receiving: manually
    login_url: https://login.checkpointonline.com/621ac12d-4afb-479c-9c14-13e7b743cd07/saml2
    name: TestIdp2
    received_identifier: https://sts.checkpoint.net/621ac12d-4afb-479c-9c14-13e7b743cd07/
    state: present
    usage: managing_administrator_access

- name: set-identity-provider
  cp_mgmt_identity_provider:
    base64_certificate: |
        LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4RENDQWRpZ0F3SUJBZ0lRUTBWZVpLdVBLb0pQUWhaNGhDaWRzREFOQmdrcWhraUc5dzBCQVFzRkFEQTBNVEl3TUFZRFZRUURFeWxOYVdOeWIzTn
        ablFnUVhwMWNtVWdSbVZrWlhKaGRHVmtJRk5UVHlCRFpYSjBhV1pwWTJGMFpUQWVGdzB4T0RBME1UVXhNVEl6TXpOYUZ3MHlNVEEwTVRVeE1USXpNek5hTURReE1qQXdCZ05WQkFNVEtVMXBZM0p2YzI5b
        RDQkJlblZ5WlNCR1pXUmxjbUYwWldRZ1UxTlBJRU5sY25ScFptbGpZWFJsTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0VXVqYUd0OFhaODl2dXZ5a3lRVzVYb24vOFIv
        VB0ejRhYjBNM3RNVXZHWHozVXh0V1pTRStUR1hydjN3VHRLMCs4RmtNeXVKYUhGSXBLLzRVREZpRk1yQmxzR0Z1dmtTc1p5VjIzZlNGN3paaXlUWTZUN0EwcCtnczUwNVhEOUdBYjlWYmR3R0cwK0tDVnl
        c1ZRZ1YySXdKZ2l5aHF3RUNvY3dCcmFuN251SytURU5EMmwyZjlZcng1b1JNRU56NzB3bHlIMzZPWkJtdDBrNTk4L1doMEhEWUxaZW8wZHlTV3JOd3dlWXZTeEU4L01kbTQzWEV1U3pialR6ZnNNMHZVUn
        GQlNyVUxFYURPMS9JUDJVcjdCc2dId1JJL3hmb3FJbUsxS2twVXEwQWxjVEFpM3YxdTl6Qy9xTGdQd0F5UUl2dzlVQ3NpcnJQQTBZMFlPaFFJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUURja
        9qZEd6L0FJQ2pqTTBaN21ZbGdQNXpic2FRNWRDMmNqZjRESnFta21zV3VmUnBDNHNic3VoODcwY0NCS2N1dmgrb0dpekJRSHJQbTRUaEl2ZklsS0w4WGpMQVhiRnVSUG9IQWcwOHNMWGR2UFRCVE52REYx
        WhvcU5zMmo2ZUZxL2ROdXF2ZUJIcjVENXRLblYyWEJHRUhFOVJFOVdUa1pRT2MwaEhtQ3dNbWNZb3JYRzhCa3l1OXFwNXhyMDZMQ0htMnJLcnI2ZENRVldBV0R0MzhiS2t5STRobTVSNTVCclR5UldSdzI
        RS9YaFEwVksva1FJYW9GZ0hvaWo0ekg5bmxlZnZMbmhaZDVPRzROL29OS2pBKy9LbkVqaTdPQXhKWVNaR1FmRjU0R1AwQTE4VnF1NVVGaFBKMUZFQXZ5YjR0QnZtTzM1NFFVUys5UTY2agotLS0tLUVORC
        DRVJUSUZJQ0FURS0tLS0t
    data_receiving: manually
    login_url: https://login.checkpointonline.com/621ac12d-4afb-479c-9c14-13e7b743cd07/saml2
    name: TestIdp
    received_identifier: https://sts.checkpoint.net/621ac12d-4afb-479c-9c14-13e7b743cd07/
    state: present
    usage: managing_administrator_access

- name: delete-identity-provider
  cp_mgmt_identity_provider:
    name: TestIdp
    state: absent
"""

RETURN = """
cp_mgmt_identity_provider:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        usage=dict(type='str', choices=['managing_administrator_access', 'gateway_policy_and_logs']),
        gateway=dict(type='str'),
        service=dict(type='str', choices=['none', 'identity awareness', 'mobile access', 'vpn']),
        data_receiving=dict(type='str', choices=['metadata_file', 'manually']),
        received_identifier=dict(type='str'),
        login_url=dict(type='str'),
        base64_metadata_file=dict(type='str'),
        base64_certificate=dict(type='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        tags=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'identity-provider'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
