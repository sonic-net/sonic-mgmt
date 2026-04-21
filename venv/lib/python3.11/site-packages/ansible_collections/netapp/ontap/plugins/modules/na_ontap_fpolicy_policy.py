#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: na_ontap_fpolicy_policy
short_description: NetApp ONTAP - Create, delete or modify an FPolicy policy.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete or modify an FPolicy policy. Fpolicy scope must exist before running this module.
- FPolicy is a file access notification framework that enables an administrator to monitor file and directory access in storage configured for CIFS and NFS.
options:
  state:
    description:
    - Whether the fPolicy policy should exist or not
    choices: ['present', 'absent']
    type: str
    default: present

  vserver:
    description:
    - the name of the vserver to create the policy on
    type: str
    required: True

  name:
    description:
    - Name of the policy.
    type: str
    required: True

  allow_privileged_access:
    description:
    - Specifies if privileged access should be given to FPolicy servers registered for the policy.
    type: bool

  engine:
    description:
    - Name of the Engine. External engines must be created prior to running this task.
    type: str

  events:
    description:
    - Events for file access monitoring.
    type: list
    elements: str
    required: True

  is_mandatory:
    description:
    - Specifies the action to take on a file access event in the case when all primary and secondary servers are down or no response is received from the
    - FPolicy servers within a given timeout period. When True, file access events will be denied under these circumstances
    type: bool

  is_passthrough_read_enabled:
    description:
    - Specifies if passthrough-read should be allowed to FPolicy servers registered for the policy.
    type: bool

  privileged_user_name:
    description:
    - User name for privileged access.
    type: str

'''

EXAMPLES = """
- name: Create FPolicy policy
  netapp.ontap.na_ontap_fpolicy_policy:
    state: present
    vserver: svm1
    name: fpolicy_policy
    events: fcpolicy_event
    engine: fpolicy_ext_engine
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify FPolicy policy
  netapp.ontap.na_ontap_fpolicy_policy:
    state: present
    vserver: svm1
    name: fpolicy_policy
    events: fcpolicy_event
    is_mandatory: false
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete FPolicy policy
  netapp.ontap.na_ontap_fpolicy_policy:
    state: absent
    vserver: svm1
    name: fpolicy_policy
    events: fcpolicy_event
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI


class NetAppOntapFpolicyPolicy():

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            allow_privileged_access=dict(required=False, type='bool'),
            engine=dict(required=False, type='str'),
            events=dict(required=True, type='list', elements='str'),
            is_mandatory=dict(required=False, type='bool'),
            is_passthrough_read_enabled=dict(required=False, type='bool'),
            privileged_user_name=dict(required=False, type='str')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_fpolicy_policy(self):
        """
       Check if FPolicy policy exists, if it exists get the current state of the policy.
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy"
            query = {
                'vserver': self.parameters['vserver'],
                'policy-name': self.parameters['name'],
                'fields': 'events,engine,allow-privileged-access,is-mandatory,is-passthrough-read-enabled,privileged-user-name'
            }

            message, error = self.rest_api.get(api, query)
            if error:
                self.module.fail_json(msg=error)
            if len(message.keys()) == 0:
                return None
            if 'records' in message and len(message['records']) == 0:
                return None
            if 'records' not in message:
                error = "Unexpected response in get_fpolicy_policy from %s: %s" % (api, repr(message))
                self.module.fail_json(msg=error)
            return_value = {
                'vserver': message['records'][0]['vserver'],
                'name': message['records'][0]['policy_name'],
                'events': message['records'][0]['events'],
                'engine': message['records'][0]['engine'],
                'is_mandatory': message['records'][0]['is_mandatory'],
                'is_passthrough_read_enabled': message['records'][0]['is_passthrough_read_enabled']
            }
            allow_privileged_access = True if message['records'][0]['allow_privileged_access'] == 'yes' else False
            return_value['allow_privileged_access'] = allow_privileged_access
            if 'privileged_user_name' in message['records'][0]:
                return_value['privileged_user_name'] = message['records'][0]['privileged_user_name']

            return return_value

        else:
            return_value = None

            fpolicy_policy_obj = netapp_utils.zapi.NaElement('fpolicy-policy-get-iter')
            fpolicy_policy_config = netapp_utils.zapi.NaElement('fpolicy-policy-info')
            fpolicy_policy_config.add_new_child('policy-name', self.parameters['name'])
            fpolicy_policy_config.add_new_child('vserver', self.parameters['vserver'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(fpolicy_policy_config)
            fpolicy_policy_obj.add_child_elem(query)

            try:
                result = self.server.invoke_successfully(fpolicy_policy_obj, True)

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error searching for fPolicy policy %s on vserver %s: %s' % (self.parameters['name'], self.parameters['vserver'], to_native(error)),
                    exception=traceback.format_exc())
            if result.get_child_by_name('attributes-list'):
                fpolicy_policy_attributes = result['attributes-list']['fpolicy-policy-info']
                events = []
                if fpolicy_policy_attributes.get_child_by_name('events'):
                    for event in fpolicy_policy_attributes.get_child_by_name('events').get_children():
                        events.append(event.get_content())

                return_value = {
                    'vserver': fpolicy_policy_attributes.get_child_content('vserver'),
                    'name': fpolicy_policy_attributes.get_child_content('policy-name'),
                    'events': events,
                    'allow_privileged_access': self.na_helper.get_value_for_bool(
                        from_zapi=True, value=fpolicy_policy_attributes.get_child_content('allow-privileged-access')),
                    'engine': fpolicy_policy_attributes.get_child_content('engine-name'),
                    'is_mandatory': self.na_helper.get_value_for_bool(
                        from_zapi=True, value=fpolicy_policy_attributes.get_child_content('is-mandatory')),
                    'is_passthrough_read_enabled': self.na_helper.get_value_for_bool(
                        from_zapi=True, value=fpolicy_policy_attributes.get_child_content('is-passthrough-read-enabled')),
                    'privileged_user_name': fpolicy_policy_attributes.get_child_content('privileged-user-name')
                }

            return return_value

    def create_fpolicy_policy(self):
        """
        Create an FPolicy policy.
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy"
            body = {
                'vserver': self.parameters['vserver'],
                'policy-name': self.parameters['name'],
                'events': self.parameters['events']
            }
            for parameter in ('engine', 'allow_privileged_access', 'is_mandatory', 'is_passthrough_read_enabled', 'privileged_user_name'):
                if parameter in self.parameters:
                    body[parameter.replace('_', '-')] = self.parameters[parameter]

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

        else:
            fpolicy_policy_obj = netapp_utils.zapi.NaElement('fpolicy-policy-create')
            fpolicy_policy_obj.add_new_child('policy-name', self.parameters['name'])
            if 'is_mandatory' in self.parameters:
                fpolicy_policy_obj.add_new_child('is-mandatory', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_mandatory']))
            if 'engine' in self.parameters:
                fpolicy_policy_obj.add_new_child('engine-name', self.parameters['engine'])
            if 'allow_privileged_access' in self.parameters:
                fpolicy_policy_obj.add_new_child(
                    'allow-privileged-access', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['allow_privileged_access'])
                )
            if 'is_passthrough_read_enabled' in self.parameters:
                fpolicy_policy_obj.add_new_child(
                    'is-passthrough-read-enabled', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_passthrough_read_enabled'])
                )
            events_obj = netapp_utils.zapi.NaElement('events')
            for event in self.parameters['events']:
                events_obj.add_new_child('event-name', event)
            fpolicy_policy_obj.add_child_elem(events_obj)

            if 'privileged_user_name' in self.parameters:
                fpolicy_policy_obj.add_new_child('privileged-user-name', self.parameters['privileged_user_name'])
            try:
                self.server.invoke_successfully(fpolicy_policy_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error creating fPolicy policy %s on vserver %s: %s' % (self.parameters['name'], self.parameters['vserver'], to_native(error)),
                    exception=traceback.format_exc()
                )

    def modify_fpolicy_policy(self, modify):
        """
        Modify an FPolicy policy.
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy"
            query = {'vserver': self.parameters['vserver']}
            query['policy-name'] = self.parameters['name']
            dummy, error = self.rest_api.patch(api, modify, query)
            if error:
                self.module.fail_json(msg=error)
        else:
            fpolicy_policy_obj = netapp_utils.zapi.NaElement('fpolicy-policy-modify')
            fpolicy_policy_obj.add_new_child('policy-name', self.parameters['name'])
            if 'is_mandatory' in self.parameters:
                fpolicy_policy_obj.add_new_child('is-mandatory', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_mandatory']))
            if 'engine' in self.parameters:
                fpolicy_policy_obj.add_new_child('engine-name', self.parameters['engine'])
            if 'allow_privileged_access' in self.parameters:
                fpolicy_policy_obj.add_new_child(
                    'allow-privileged-access', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['allow_privileged_access'])
                )
            if 'is_passthrough_read_enabled' in self.parameters:
                fpolicy_policy_obj.add_new_child(
                    'is-passthrough-read-enabled', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_passthrough_read_enabled'])
                )
            events_obj = netapp_utils.zapi.NaElement('events')
            for event in self.parameters['events']:
                events_obj.add_new_child('event-name', event)
            fpolicy_policy_obj.add_child_elem(events_obj)

            if 'privileged_user_name' in self.parameters:
                fpolicy_policy_obj.add_new_child('privileged-user-name', self.parameters['privileged_user_name'])
            try:
                self.server.invoke_successfully(fpolicy_policy_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error modifying fPolicy policy %s on vserver %s: %s' %
                    (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def delete_fpolicy_policy(self):
        """
        Delete an FPolicy policy.
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy"
            body = {
                'vserver': self.parameters['vserver'],
                'policy-name': self.parameters['name']
            }
            dummy, error = self.rest_api.delete(api, body)
            if error:
                self.module.fail_json(msg=error)

        else:
            fpolicy_policy_obj = netapp_utils.zapi.NaElement('fpolicy-policy-delete')
            fpolicy_policy_obj.add_new_child('policy-name', self.parameters['name'])

            try:
                self.server.invoke_successfully(fpolicy_policy_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error deleting fPolicy policy %s on vserver %s: %s' %
                    (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def apply(self):
        current = self.get_fpolicy_policy()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.create_fpolicy_policy()
                elif cd_action == 'delete':
                    self.delete_fpolicy_policy()
                elif modify:
                    self.modify_fpolicy_policy(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapFpolicyPolicy()
    command.apply()


if __name__ == '__main__':
    main()
