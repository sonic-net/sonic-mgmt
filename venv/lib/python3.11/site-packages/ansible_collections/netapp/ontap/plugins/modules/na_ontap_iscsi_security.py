#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_iscsi_security
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete/Modify iscsi security.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_rest
module: na_ontap_iscsi_security
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified initiator should exist or not.
    default: present
    type: str
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  auth_type:
    description:
      - Specifies the authentication type.
    choices: ['chap', 'none', 'deny']
    type: str
  initiator:
    description:
      - Specifies the name of the initiator.
    required: true
    type: str
  address_ranges:
    description:
      - May be a single IPv4 or IPv6 address or a range containing a startaddress and an end address.
      - The start and end addresses themselves are included in the range.
      - If not present, the initiator is allowed to log in from any IP address.
    type: list
    elements: str
  inbound_username:
    description:
      - Inbound CHAP username.
      - Required for CHAP. A null username is not allowed.
    type: str
  inbound_password:
    description:
      - Inbound CHAP user password.
      - Can not be modified. If want to change password, delete and re-create the initiator.
    type: str
  outbound_username:
    description:
      - Outbound CHAP user name.
    type: str
  outbound_password:
    description:
      - Outbound CHAP user password.
      - Can not be modified. If want to change password, delete and re-create the initiator.
    type: str
short_description: "NetApp ONTAP Manage iscsi security."
version_added: "19.11.0"
'''

EXAMPLES = """
- name: Create iscsi security
  netapp.ontap.na_ontap_iscsi_security:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    vserver: test_svm
    state: present
    initiator: eui.9999956789abcdef
    inbound_username: user_1
    inbound_password: password_1
    outbound_username: user_2
    outbound_password: password_2
    auth_type: chap
    address_ranges: 10.125.10.0-10.125.10.10,10.125.193.78

- name: Modify outbound username
  netapp.ontap.na_ontap_iscsi_security:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    vserver: test_svm
    state: present
    initiator: eui.9999956789abcdef
    inbound_username: user_1
    inbound_password: password_1
    outbound_username: user_out_3
    outbound_password: password_3
    auth_type: chap
    address_ranges: 10.125.10.0-10.125.10.10,10.125.193.78

- name: Modify address
  netapp.ontap.na_ontap_iscsi_security:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    vserver: test_svm
    state: present
    initiator: eui.9999956789abcdef
    address_ranges: 10.125.193.90,10.125.10.20-10.125.10.30
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppONTAPIscsiSecurity:
    """
    Class with iscsi security methods
    """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            auth_type=dict(required=False, type='str', choices=['chap', 'none', 'deny']),
            inbound_password=dict(required=False, type='str', no_log=True),
            inbound_username=dict(required=False, type='str'),
            initiator=dict(required=True, type='str'),
            address_ranges=dict(required=False, type='list', elements='str'),
            outbound_password=dict(required=False, type='str', no_log=True),
            outbound_username=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            required_if=[
                ['auth_type', 'chap', ['inbound_username', 'inbound_password']]
            ],
            required_together=[
                ['inbound_username', 'inbound_password'],
                ['outbound_username', 'outbound_password'],
            ],
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_iscsi_security:', 9, 6)
        self.uuid = self.get_svm_uuid()

    def get_initiator(self):
        """
        Get current initiator.
        :return: dict of current initiator details.
        """
        params = {'fields': '*', 'initiator': self.parameters['initiator']}
        api = 'protocols/san/iscsi/credentials'
        message, error = self.rest_api.get(api, params)
        if error is not None:
            self.module.fail_json(msg="Error on fetching initiator: %s" % error)
        if message['num_records'] > 0:
            record = message['records'][0]
            initiator_details = {'auth_type': record['authentication_type']}
            if initiator_details['auth_type'] == 'chap':
                if record['chap'].get('inbound'):
                    initiator_details['inbound_username'] = record['chap']['inbound']['user']
                else:
                    initiator_details['inbound_username'] = None
                if record['chap'].get('outbound'):
                    initiator_details['outbound_username'] = record['chap']['outbound']['user']
                else:
                    initiator_details['outbound_username'] = None
            if record.get('initiator_address'):
                if record['initiator_address'].get('ranges'):
                    ranges = []
                    for address_range in record['initiator_address']['ranges']:
                        if address_range['start'] == address_range['end']:
                            ranges.append(address_range['start'])
                        else:
                            ranges.append(address_range['start'] + '-' + address_range['end'])
                    initiator_details['address_ranges'] = ranges
                else:
                    initiator_details['address_ranges'] = []
            else:
                initiator_details['address_ranges'] = []
            return initiator_details

    def create_initiator(self):
        """
        Create initiator.
        :return: None.
        """
        body = {
            'authentication_type': self.parameters['auth_type'],
            'initiator': self.parameters['initiator']
        }

        if self.parameters['auth_type'] == 'chap':
            chap_info = {'inbound': {'user': self.parameters['inbound_username'], 'password': self.parameters['inbound_password']}}

            if self.parameters.get('outbound_username'):
                chap_info['outbound'] = {'user': self.parameters['outbound_username'], 'password': self.parameters['outbound_password']}
            body['chap'] = chap_info
        address_info = self.get_address_info(self.parameters.get('address_ranges'))
        if address_info is not None:
            body['initiator_address'] = {'ranges': address_info}
        body['svm'] = {'uuid': self.uuid, 'name': self.parameters['vserver']}
        api = 'protocols/san/iscsi/credentials'
        dummy, error = self.rest_api.post(api, body)
        if error is not None:
            self.module.fail_json(msg="Error on creating initiator: %s" % error)

    def delete_initiator(self):
        """
        Delete initiator.
        :return: None.
        """
        api = 'protocols/san/iscsi/credentials/{0}/{1}'.format(self.uuid, self.parameters['initiator'])
        dummy, error = self.rest_api.delete(api)
        if error is not None:
            self.module.fail_json(msg="Error on deleting initiator: %s" % error)

    def modify_initiator(self, modify, current):
        """
        Modify initiator.
        :param modify: dict of modify attributes.
        :return: None.
        """
        body = {}
        use_chap = False
        chap_update = False
        chap_update_inbound = False
        chap_update_outbound = False

        if modify.get('auth_type'):
            body['authentication_type'] = modify.get('auth_type')
            if modify['auth_type'] == 'chap':
                # change in auth_type
                chap_update = True
                use_chap = True
        elif current.get('auth_type') == 'chap':
            # we're already using chap
            use_chap = True

        if use_chap and (modify.get('inbound_username') or modify.get('inbound_password')):
            # change in chap inbound credentials
            chap_update = True
            chap_update_inbound = True

        if use_chap and (modify.get('outbound_username') or modify.get('outbound_password')):
            # change in chap outbound credentials
            chap_update = True
            chap_update_outbound = True

        if chap_update and not chap_update_inbound and 'inbound_username' in self.parameters:
            # use credentials from input
            chap_update_inbound = True

        if chap_update and not chap_update_outbound and 'outbound_username' in self.parameters:
            # use credentials from input
            chap_update_outbound = True

        if chap_update:
            chap_info = dict()
            # set values from self.parameters as they may not show as modified
            if chap_update_inbound:
                chap_info['inbound'] = {'user': self.parameters['inbound_username'], 'password': self.parameters['inbound_password']}
            else:
                # use current values as inbound username/password are required
                chap_info['inbound'] = {'user': current.get('inbound_username'), 'password': current.get('inbound_password')}
            if chap_update_outbound:
                chap_info['outbound'] = {'user': self.parameters['outbound_username'], 'password': self.parameters['outbound_password']}
            body['chap'] = chap_info
            # PATCH fails if this is not present, even though there is no change
            body['authentication_type'] = 'chap'

        address_info = self.get_address_info(modify.get('address_ranges'))
        if address_info is not None:
            body['initiator_address'] = {'ranges': address_info}
        api = 'protocols/san/iscsi/credentials/{0}/{1}'.format(self.uuid, self.parameters['initiator'])
        dummy, error = self.rest_api.patch(api, body)
        if error is not None:
            self.module.fail_json(msg="Error on modifying initiator: %s - params: %s" % (error, body))

    def get_address_info(self, address_ranges):
        if address_ranges is None:
            return None
        address_info = []
        for address in address_ranges:
            address_range = {}
            if '-' in address:
                address_range['end'] = address.split('-')[1]
                address_range['start'] = address.split('-')[0]
            else:
                address_range['end'] = address
                address_range['start'] = address
            address_info.append(address_range)
        return address_info

    def apply(self):
        """
        check create/delete/modify operations if needed.
        :return: None.
        """
        current = self.get_initiator()
        action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if action == 'create':
                self.create_initiator()
            elif action == 'delete':
                self.delete_initiator()
            elif modify:
                self.modify_initiator(modify, current)
        result = netapp_utils.generate_result(self.na_helper.changed, action, modify)
        self.module.exit_json(**result)

    def get_svm_uuid(self):
        """
        Get a svm's UUID
        :return: uuid of the svm.
        """
        params = {'fields': 'uuid', 'name': self.parameters['vserver']}
        api = "svm/svms"
        message, error = self.rest_api.get(api, params)
        record, error = rrh.check_for_0_or_1_records(api, message, error)
        if error is not None:
            self.module.fail_json(msg="Error on fetching svm uuid: %s" % error)
        if record is None:
            self.module.fail_json(msg="Error on fetching svm uuid, SVM not found: %s" % self.parameters['vserver'])
        return message['records'][0]['uuid']


def main():
    """Execute action"""
    iscsi_obj = NetAppONTAPIscsiSecurity()
    iscsi_obj.apply()


if __name__ == '__main__':
    main()
