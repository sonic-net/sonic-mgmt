#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_cifs_privileges
short_description: NetApp ONTAP CIFS privileges
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.13.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Add/modify/reset privileges of the local or Active Directory user or group.
options:
  state:
    description:
        - Specifies whether to add/update or reset the specified CIFS privileges.
    choices: ['present', 'absent']
    type: str
    default: present

  name:
    description:
      - The name of the local or Active Directory user or group name.
    required: true
    type: str

  vserver:
    description:
      - the name of the data vserver to use.
    required: true
    type: str

  privileges:
    description:
      - Specifies the list of privileges to be retained for a user or group.
      - SeTcbPrivilege - Allows user to act as part of the operating system
      - SeBackupPrivilege - Allows user to back up files and directories, overriding any ACLs
      - SeRestorePrivilege - Allows user to restore files and directories, overriding any ACLs
      - SeTakeOwnershipPrivilege - Allows user to take ownership of files or other objects
      - SeSecurityPrivilege - Allows user to manage auditing and viewing/dumping/clearing the security log
      - SeChangeNotifyPrivilege - Allows user to bypass traverse checking
    type: list
    elements: str

notes:
  - Only supported with REST and requires ONTAP 9.10 or later.
  - Specified C(privileges) will replace all the existing privileges associated with the user or group when state is present.
"""

EXAMPLES = """
- name: Add privileges to the specified local user
  netapp.ontap.na_ontap_cifs_privileges:
    state: present
    vserver: ansibleSVM
    name: CIFS\\local_user1
    privileges: ["SeTcbPrivilege"]
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Update privileges of the specified local user
  netapp.ontap.na_ontap_cifs_privileges:
    state: present
    vserver: ansibleSVM
    name: CIFS\\local_user1
    privileges: ["SeTcbPrivilege", "SeBackupPrivilege"]
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Reset privileges of the specified local user
  netapp.ontap.na_ontap_cifs_privileges:
    state: absent
    vserver: ansibleSVM
    name: CIFS\\local_user1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_vserver


class NetAppOntapCifsPrivileges:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            privileges=dict(required=False, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['privileges']),
            ],
            supports_check_mode=True
        )
        self.svm_uuid = None

        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_cifs_privileges:', 9, 10, 1)

    def get_svm_uuid(self):
        self.svm_uuid, dummy = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'], self.module, True)

    def get_cifs_privileges(self):
        """ Retrieves privileges of the specified local or Active Directory user or group and SVM """
        self.get_svm_uuid()
        api = 'protocols/cifs/users-and-groups/privileges'
        fields = 'name,privileges'
        params = {
            'svm.uuid': self.svm_uuid,
            'name': self.parameters['name'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error fetching CIFS privileges for %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            return {
                'name': record.get('name'),
                'privileges': record.get('privileges')
            }
        return None

    def add_cifs_privileges(self):
        """ Add privileges to the local or Active Directory user or group for the SVM """
        api = 'protocols/cifs/users-and-groups/privileges'
        body = {
            'svm.uuid': self.svm_uuid,
            'name': self.parameters['name'],
            'privileges': self.parameters['privileges']
        }
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error adding CIFS privileges for %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_cifs_privileges(self, modify, reset=False):
        """ Update or reset the privileges of the specified local or Active Directory user or group and SVM """
        if reset:
            self.parameters['privileges'] = []
        api = 'protocols/cifs/users-and-groups/privileges'
        uuids = '%s/%s' % (self.svm_uuid, self.parameters['name'])
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuids, modify)
        if error:
            self.module.fail_json(msg='Error modifying CIFS privileges for %s: %s.' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_cifs_privileges()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            # check if CIFS Server NetBIOS Name is not given in input;
            # if not add it to the given local user or group name for maintaining idempotency
            if current['name'] != self.parameters['name'] and current['name'].split('\\')[1] == self.parameters['name']:
                self.parameters['name'] = current['name']
            # convert the privilege to lower case to match with GET response
            self.parameters['privileges'] = [privilege.lower() for privilege in self.parameters['privileges']]
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.add_cifs_privileges()
            elif cd_action == 'delete':
                self.modify_cifs_privileges(modify, reset=True)
            elif modify:
                self.modify_cifs_privileges(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    cifs_privileges = NetAppOntapCifsPrivileges()
    cifs_privileges.apply()


if __name__ == '__main__':
    main()
