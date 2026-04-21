#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_mav_config
short_description: NetApp ONTAP multi-admin verification (MAV) global setting
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 23.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Enable/disable multi-admin verification (MAV) configuration.
  - Multi-admin verification is not required to enable the feature. However, it is required to disable the feature.
  - Multi-admin verification is required for any modification to be done while multi-admin approval is enabled.
  - Until the pending request gets approved, request info is returned in the module output.
    Once approved the module needs to be run again to apply the intended updates.
options:
  state:
    description:
      - Modify MAV global setting, only present is supported.
    choices: ['present']
    type: str
    default: present

  enabled:
    description:
      - Specifies whether multi-admin approval is currently configured or not.
      - By default, the feature is disabled and the value is set to false.
    type: bool
    default: false

  required_approvers:
    description:
      - Specifies the required number of approvers to approve the request which is inherited by the rule if required-approvers is not provided for the rule.
      - The default and minimum number of required approvers is 1.
    type: int

  approval_groups:
    description:
      - Specifies the list of global approval groups which are inherited by the rule if the approval-groups is not provided for the rule.
      - The default value is an empty list.
    type: list
    elements: str

  approval_expiry:
    description:
      - Specifies the time, in ISO-8601 duration format, that the approvers have after a new execution request
        is submitted to approve or disapprove the request before the request expires.
      - The default value is one hour (PT1H), the minimum supported value is one second (PT1S),
        and the maximum supported value is 14 days (P14D).
    type: str

  execution_expiry:
    description:
      - Specifies the time, in ISO-8601 duration format, that the authorized users have after a request
        is approved to execute the requested operation before the request expires.
      - The default value is one hour (PT1H), the minimum supported value is one second (PT1S),
        and the maximum supported value is 14 days (P14D).
    type: str

notes:
  - Only supported with REST and requires ONTAP 9.11.1 or later.
"""

EXAMPLES = """
- name: Enable multi-admin approval
  netapp.ontap.na_ontap_mav_config:
    state: present
    enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Update MAV configuration
  netapp.ontap.na_ontap_mav_config:
    state: present
    approval_groups: ["group1", "group2"]
    execution_expiry: "P14D"
    approval_expiry: "P14D"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

# this generates multi-admin-verify request which needs approval
- name: Disable multi-admin approval
  netapp.ontap.na_ontap_mav_config:
    state: present
    enabled: false
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always
"""

RETURN = """
request_info:
    description: Returns multi-admin-verify request information while trying to disable MAV global setting, empty for enable or modify operations.
    returned: always
    type: dict
    sample: {
        "request_info": {
            "calling: security/multi-admin-verify: got {'message': 'The security multi-admin-verify request (index 1) requires approval.', 'code': '262325'}."
            }
        }
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapMAVConfig:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            enabled=dict(required=False, type='bool', default=False),
            required_approvers=dict(required=False, type='int'),
            approval_groups=dict(required=False, type='list', elements='str'),
            approval_expiry=dict(required=False, type='str'),
            execution_expiry=dict(required=False, type='str')
        ))

        self.extra_responses = {}
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_mav_config:', 9, 11, 1)

    def get_mav_settings(self):
        """ Retrieves multi-admin-verify settings """
        api = 'security/multi-admin-verify'
        fields = 'enabled,required_approvers,approval_groups,approval_expiry,execution_expiry'
        record, error = rest_generic.get_one_record(self.rest_api, api, fields=fields)
        if error:
            self.module.fail_json(msg="Error fetching multi-admin-verify global settings: %s" % (to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            return {
                'enabled': record.get('enabled'),
                'required_approvers': record.get('required_approvers'),
                'approval_groups': record.get('approval_groups'),
                'approval_expiry': record.get('approval_expiry'),
                'execution_expiry': record.get('execution_expiry')
            }
        return None

    def modify_mav_settings(self, modify):
        """ Updates multi-admin-verify settings """
        api = 'security/multi-admin-verify'
        extra_responses = None
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid_or_name=None, body=modify)

        if error:
            if 'The security multi-admin-verify request' in error and 'requires approval' in error:
                self.na_helper.changed = False
                self.extra_responses = dict(request_info=error)
            else:
                self.module.fail_json(msg="Error modifying multi-admin-verify global settings: %s." % (to_native(error)),
                                      exception=traceback.format_exc())

    def apply(self):
        current = self.get_mav_settings()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            self.modify_mav_settings(modify)
        result = netapp_utils.generate_result(changed=self.na_helper.changed, modify=modify, extra_responses=self.extra_responses)
        self.module.exit_json(**result)


def main():
    mav_config = NetAppOntapMAVConfig()
    mav_config.apply()


if __name__ == '__main__':
    main()
