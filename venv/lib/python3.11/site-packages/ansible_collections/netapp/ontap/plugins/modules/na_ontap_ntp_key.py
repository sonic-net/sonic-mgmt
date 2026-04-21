#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: na_ontap_ntp_key
short_description: NetApp ONTAP NTP key
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.21.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create or delete or modify NTP key in ONTAP
options:
  state:
    description:
      - Whether the specified NTP key should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'
  id:
    description:
      - NTP symmetric authentication key ID. The ID must be in the range 1 to 65535.
    required: True
    type: int
  digest_type:
    description:
      - NTP symmetric authentication key type. Only SHA1 currently supported.
    choices: ['sha1']
    type: str
    required: True
  value:
    description:
      - NTP symmetric authentication key value. The value must be exactly 40 hexadecimal digits for SHA1 keys.
    type: str
    required: True
"""

EXAMPLES = """
- name: Create NTP key
  netapp.ontap.na_ontap_ntp_key:
    state: present
    digest_type: sha1
    value: "{{ key_value }}"
    id: 1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete NTP key
  netapp.ontap.na_ontap_ntp_key:
    state: absent
    id: 1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapNTPKey:
    """ object initialize and class methods """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            id=dict(required=True, type='int'),
            digest_type=dict(required=True, type='str', choices=['sha1']),
            value=dict(required=True, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_ntp_key', 9, 7)

    def get_ntp_key(self):
        api = 'cluster/ntp/keys'
        options = {'id': self.parameters['id'],
                   'fields': 'id,digest_type,value'}
        record, error = rest_generic.get_one_record(self.rest_api, api, options)
        if error:
            self.module.fail_json(msg='Error fetching key with id %s: %s' % (self.parameters['id'], to_native(error)),
                                  exception=traceback.format_exc())
        return record

    def create_ntp_key(self):
        api = 'cluster/ntp/keys'
        params = {
            'id': self.parameters['id'],
            'digest_type': self.parameters['digest_type'],
            'value': self.parameters['value']
        }
        dummy, error = rest_generic.post_async(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error creating key with id %s: %s' % (self.parameters['id'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_ntp_key(self):
        dummy, error = rest_generic.delete_async(self.rest_api, 'cluster/ntp/keys', str(self.parameters['id']))
        if error:
            self.module.fail_json(msg='Error deleting key with id %s: %s' % (self.parameters['id'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_ntp_key(self, modify):
        body = {}
        if 'digest_type' in modify:
            body['digest_type'] = self.parameters['digest_type']
        if 'value' in modify:
            body['value'] = self.parameters['value']
        if body:
            dummy, error = rest_generic.patch_async(self.rest_api, 'cluster/ntp/keys', str(self.parameters['id']), body)
            if error:
                self.module.fail_json(msg='Error modifying key with id %s: %s' % (self.parameters['id'], to_native(error)),
                                      exception=traceback.format_exc())

    def apply(self):
        cd_action = None
        current = self.get_ntp_key()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_ntp_key()
            elif cd_action == 'delete':
                self.delete_ntp_key()
            elif modify:
                self.modify_ntp_key(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """ Create object and call apply """
    ntp_obj = NetAppOntapNTPKey()
    ntp_obj.apply()


if __name__ == '__main__':
    main()
