#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_publickey
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_publickey

short_description: NetApp ONTAP publickey configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Add, modify, or remove publickeys.
  - Requires ONTAP 9.7 or later, and only supports REST.

options:
  state:
    description:
      - Whether the specified publickey should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'
  account:
    description:
      - The name of the user account.
    required: true
    type: str
  comment:
    description:
      - Optional comment for the public key.
    type: str
  delete_all:
    description:
      - If index is not present, with state=absent, delete all public key for this user account.
    type: bool
    default: false
  index:
    description:
      - Index number for the public key.
      - If index is not present, with state=present, the public key is always added, using the next available index.
      - If index is not present, with state=present, the module is not idempotent.
      - If index is not present, with state=absent, if only one key is found, it is deleted.  Otherwise an error is reported.
      - See also C(delete_all) option.
    type: int
  public_key:
    description:
      - The public key.
    type: str
  vserver:
    description:
      - The name of the vserver to use.
      - Omit this option for cluster scoped user accounts.
    type: str

notes:
  - This module supports check_mode.
  - This module is not idempotent if index is omitted.
'''

EXAMPLES = """
- name: Create publickey
  netapp.ontap.na_ontap_publickey:
    state: present
    account: SampleUser
    index: 0
    public_key: "{{ netapp_publickey }}"
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete single publickey
  netapp.ontap.na_ontap_publickey:
    state: absent
    account: SampleUser
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify single publickey
  netapp.ontap.na_ontap_publickey:
    state: present
    account: SampleUser
    comment: ssh key for XXXX
    index: 0
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
cd_action:
  description: whether a public key is created or deleted.
  returned: success
  type: str

modify:
  description: attributes that were modified if the key already exists.
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapPublicKey:
    """
    Common operations to manage public keys.
    """

    def __init__(self):
        self.use_rest = False
        argument_spec = netapp_utils.na_ontap_rest_only_spec()
        argument_spec.update(dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            account=dict(required=True, type='str'),
            comment=dict(type='str'),
            delete_all=dict(type='bool', default=False),
            index=dict(type='int'),
            public_key=dict(type='str'),
            vserver=dict(type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=argument_spec,
            mutually_exclusive=[
                ('delete_all', 'index')
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # REST API is required
        self.rest_api = OntapRestAPI(self.module)
        # check version
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_publickey', 9, 7)

    def get_public_keys(self):
        api = 'security/authentication/publickeys'
        query = {
            'account.name': self.parameters['account'],
            'fields': 'account,owner,index,public_key,comment'
        }
        if self.parameters.get('vserver') is None:
            # vserser is empty for cluster
            query['scope'] = 'cluster'
        else:
            query['owner.name'] = self.parameters['vserver']

        if self.parameters.get('index') is not None:
            query['index'] = self.parameters['index']

        response, error = self.rest_api.get(api, query)
        if self.parameters.get('index') is not None:
            record, error = rrh.check_for_0_or_1_records(api, response, error)
            records = [record]
        else:
            records, error = rrh.check_for_0_or_more_records(api, response, error)
        if error:
            msg = "Error in get_public_key: %s" % error
            self.module.fail_json(msg=msg)
        if records is None or records == [None]:
            records = []
        # flatten {'account': {'name': 'some_name'}} into {'account': 'some_name'} to match input parameters
        return [dict([(k, v if k != 'account' else v['name']) for k, v in record.items()]) for record in records]

    def create_public_key(self):
        api = 'security/authentication/publickeys'
        body = {
            'account.name': self.parameters['account'],
            'public_key': self.parameters['public_key']
        }
        if self.parameters.get('vserver') is not None:
            # vserser is empty for cluster
            body['owner.name'] = self.parameters['vserver']
        for attr in ('comment', 'index'):
            value = self.parameters.get(attr)
            if value is not None:
                body[attr] = value

        dummy, error = self.rest_api.post(api, body)
        if error:
            msg = "Error in create_public_key: %s" % error
            self.module.fail_json(msg=msg)

    def modify_public_key(self, current, modify):
        # not supported in 2.6
        # sourcery skip: dict-comprehension
        api = 'security/authentication/publickeys/%s/%s/%d' % (current['owner']['uuid'], current['account'], current['index'])
        body = {}
        modify_copy = dict(modify)
        for key in modify:
            if key in ('comment', 'public_key'):
                body[key] = modify_copy.pop(key)
        if modify_copy:
            msg = 'Error: attributes not supported in modify: %s' % modify_copy
            self.module.fail_json(msg=msg)
        if not body:
            msg = 'Error: nothing to change - modify called with: %s' % modify
            self.module.fail_json(msg=msg)
        if 'public_key' not in body:
            # if not present, REST API reports 502 Server Error: Proxy Error for url
            body['public_key'] = current['public_key']

        dummy, error = self.rest_api.patch(api, body)
        if error:
            msg = "Error in modify_public_key: %s" % error
            self.module.fail_json(msg=msg)

    def delete_public_key(self, current):
        api = 'security/authentication/publickeys/%s/%s/%d' % (current['owner']['uuid'], current['account'], current['index'])
        dummy, error = self.rest_api.delete(api)
        if error:
            msg = "Error in delete_public_key: %s" % error
            self.module.fail_json(msg=msg)

    def get_actions(self):
        """Determines whether a create, delete, modify action is required
           If index is provided, we expect to find 0 or 1 record.
           If index is not provided:
               1. As documented in ONTAP, a create without index should add a new public key.
                    This is not idempotent, and this rules out a modify operation.
               2. When state is absent, if a single record is found, we assume a delete.
               3. When state is absent, if more than one record is found, a delete action is rejected with 1 exception:
                    we added a delete_all option, so that all existing keys can be deleted.
        """
        cd_action, current, modify = None, None, None
        if self.parameters['state'] == 'present' and self.parameters.get('index') is None:
            # always create, by keeping current as None
            self.module.warn('Module is not idempotent if index is not provided with state=present.')
            records = []
        else:
            records = self.get_public_keys()
            if len(records) > 1:
                if self.parameters['state'] == 'absent' and self.parameters.get('delete_all'):
                    cd_action = 'delete_all'
                    self.na_helper.changed = True
                else:
                    msg = 'index is required as more than one public_key exists for user account %s: ' % self.parameters['account']
                    msg += str(records)
                    self.module.fail_json(msg='Error: %s' % msg)
            elif len(records) == 1:
                current = records[0]

        if cd_action is None:
            cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            if current and 'comment' not in current:
                # force an entry as REST does not return anything if no comment was set
                current['comment'] = ''
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        return cd_action, modify, records

    def apply(self):
        cd_action, modify, records = self.get_actions()

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_public_key()
            elif cd_action in ('delete', 'delete_all'):
                # there is exactly 1 record for delete
                # and 2 or more records for delete_all
                for record in records:
                    self.delete_public_key(record)
            elif modify:
                # there is exactly 1 record for modify
                self.modify_public_key(records[0], modify)

        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapPublicKey()
    obj.apply()


if __name__ == '__main__':
    main()
