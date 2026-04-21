#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_wwpn_alias
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = '''

module: na_ontap_wwpn_alias
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
short_description: NetApp ONTAP set FCP WWPN Alias
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '20.4.0'
description:
    - Create/Delete FCP WWPN Alias

options:
  state:
    description:
    - Whether the specified alias should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  name:
    description:
    - The name of the alias to create or delete.
    required: true
    type: str

  wwpn:
    description:
    - WWPN of the alias.
    type: str

  vserver:
    description:
    - The name of the vserver to use.
    required: true
    type: str

'''

EXAMPLES = '''
- name: Create FCP Alias
  netapp.ontap.na_ontap_wwpn_alias:
    state: present
    name: alias1
    wwpn: 01:02:03:04:0a:0b:0c:0d
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete FCP Alias
  netapp.ontap.na_ontap_wwpn_alias:
    state: absent
    name: alias1
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
'''

RETURN = '''
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils


class NetAppOntapWwpnAlias(object):
    ''' ONTAP WWPN alias operations '''
    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=[
                'present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            wwpn=dict(required=False, type='str'),
            vserver=dict(required=True, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[('state', 'present', ['wwpn'])],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # REST API should be used for ONTAP 9.6 or higher.
        self.rest_api = OntapRestAPI(self.module)
        if self.rest_api.is_rest():
            self.use_rest = True
        else:
            self.module.fail_json(msg=self.rest_api.requires_ontap_9_6('na_ontap_wwpn_alias'))

    def get_alias(self, uuid):
        params = {'fields': 'alias,wwpn',
                  'alias': self.parameters['name'],
                  'svm.uuid': uuid}
        api = 'network/fc/wwpn-aliases'
        message, error = self.rest_api.get(api, params)
        if error is not None:
            self.module.fail_json(msg="Error on fetching wwpn alias: %s" % error)
        if message['num_records'] > 0:
            return {'name': message['records'][0]['alias'],
                    'wwpn': message['records'][0]['wwpn'],
                    }
        else:
            return None

    def create_alias(self, uuid, is_modify=False):
        params = {'alias': self.parameters['name'],
                  'wwpn': self.parameters['wwpn'],
                  'svm.uuid': uuid}
        api = 'network/fc/wwpn-aliases'
        dummy, error = self.rest_api.post(api, params)
        if error is not None:
            if is_modify:
                self.module.fail_json(msg="Error on modifying wwpn alias when trying to re-create alias: %s." % error)
            else:
                self.module.fail_json(msg="Error on creating wwpn alias: %s." % error)

    def delete_alias(self, uuid, is_modify=False):
        api = 'network/fc/wwpn-aliases/%s/%s' % (uuid, self.parameters['name'])
        dummy, error = self.rest_api.delete(api)
        if error is not None:
            if is_modify:
                self.module.fail_json(msg="Error on modifying wwpn alias when trying to delete alias: %s." % error)
            else:
                self.module.fail_json(msg="Error on deleting wwpn alias: %s." % error)

    def get_svm_uuid(self):
        """
        Get a svm's UUID
        :return: uuid of the svm.
        """
        params = {'fields': 'uuid', 'name': self.parameters['vserver']}
        api = "svm/svms"
        message, error = self.rest_api.get(api, params)
        if error is not None:
            self.module.fail_json(msg="Error on fetching svm uuid: %s" % error)
        return message['records'][0]['uuid']

    def apply(self):
        cd_action, uuid, modify = None, None, None
        uuid = self.get_svm_uuid()
        current = self.get_alias(uuid)
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.create_alias(uuid)
                elif cd_action == 'delete':
                    self.delete_alias(uuid)
                elif modify:
                    self.delete_alias(uuid, is_modify=True)
                    self.create_alias(uuid, is_modify=True)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    alias = NetAppOntapWwpnAlias()
    alias.apply()


if __name__ == '__main__':
    main()
