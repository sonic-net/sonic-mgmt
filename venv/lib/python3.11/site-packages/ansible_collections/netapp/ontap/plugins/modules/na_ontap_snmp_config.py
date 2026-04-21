#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_snmp_config
short_description: NetApp ONTAP module to modify SNMP configuration.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.9.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Modify cluster wide SNMP configuration.
  - Enable or disable SNMP on a cluster.
options:
  state:
    description:
      - Modify SNMP configuration, only present is supported.
    choices: ['present']
    type: str
    default: present
  enabled:
    description:
      - Specifies whether to enable or disable SNMP.
    type: bool
    required: false
  auth_traps_enabled:
    description:
      - Specifies whether to enable or disable SNMP authentication traps.
    type: bool
    required: false
  traps_enabled:
    description:
      - Specifies whether to enable or disable SNMP traps.
      - Requires ONTAP 9.10.1 or later.
    type: bool
    required: false

notes:
  - Only supported with REST and requires ONTAP 9.7 or later.
"""

EXAMPLES = """
- name: Disable SNMP on cluster
  netapp.ontap.na_ontap_snmp_config:
    state: present
    enabled: false
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Modify SNMP configuration
  netapp.ontap.na_ontap_snmp_config:
    state: present
    auth_traps_enabled: true
    traps_enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapSNMPConfig:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            enabled=dict(required=False, type='bool'),
            auth_traps_enabled=dict(required=False, type='bool'),
            traps_enabled=dict(required=False, type='bool')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_snmp_config:', 9, 7)
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, [['traps_enabled', (9, 10, 1)]])

    def get_snmp_config_rest(self):
        """Retrieve cluster wide SNMP configuration"""
        fields = 'enabled'
        if self.parameters.get('auth_traps_enabled') is not None:
            fields += ',auth_traps_enabled'
        if 'traps_enabled' in self.parameters and self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            fields += ',traps_enabled'
        record, error = rest_generic.get_one_record(self.rest_api, 'support/snmp', None, fields)
        if error:
            self.module.fail_json(msg="Error fetching SNMP configuration: %s" % to_native(error), exception=traceback.format_exc())
        if record:
            return {
                'enabled': record.get('enabled'),
                'auth_traps_enabled': record.get('auth_traps_enabled'),
                'traps_enabled': record.get('traps_enabled')
            }
        return None

    def modify_snmp_config_rest(self, modify):
        """Update cluster wide SNMP configuration"""
        dummy, error = rest_generic.patch_async(self.rest_api, 'support/snmp', None, modify)
        if error:
            self.module.fail_json(msg='Error modifying SNMP configuration: %s.' % to_native(error), exception=traceback.format_exc())

    def apply(self):
        current = self.get_snmp_config_rest()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            self.modify_snmp_config_rest(modify)
        result = netapp_utils.generate_result(changed=self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    snmp_config = NetAppOntapSNMPConfig()
    snmp_config.apply()


if __name__ == '__main__':
    main()
