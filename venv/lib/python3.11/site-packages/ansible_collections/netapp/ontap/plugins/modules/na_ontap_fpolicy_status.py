#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_fpolicy_status
short_description: NetApp ONTAP - Enables or disables the specified fPolicy policy
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Enable or disable fPolicy policy.
options:
  state:
    description:
    - Whether the fPolicy policy is enabled or disabled.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - Name of the vserver to enable fPolicy on.
    type: str
    required: true

  policy_name:
    description:
    - Name of the policy.
    type: str
    required: true

  sequence_number:
    description:
    - Policy Sequence Number.
    type: int

notes:
- check_mode not supported.
"""

EXAMPLES = """
- name: Enable fPolicy policy
  netapp.ontap.na_ontap_fpolicy_status:
    state: present
    vserver: svm1
    policy_name: fpolicy_policy
    sequence_number: 10
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    https: true
    validate_certs: false

- name: Disable fPolicy policy
  netapp.ontap.na_ontap_fpolicy_status:
    state: absent
    vserver: svm1
    policy_name: fpolicy_policy
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    https: true
    validate_certs: false
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapFpolicyStatus(object):
    """
        Enables or disabled NetApp ONTAP fPolicy
    """
    def __init__(self):
        """
            Initialize the ONTAP fPolicy status class
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            policy_name=dict(required=True, type='str'),
            sequence_number=dict(required=False, type='int')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[('state', 'present', ['sequence_number'])],
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if self.parameters['state'] == 'present':
            self.parameters['status'] = True
        else:
            self.parameters['status'] = False

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_fpolicy_policy_status(self):
        """
        Check to see the status of the fPolicy policy
        :return: dict of status properties
        """
        return_value = None

        if self.use_rest:
            api = '/protocols/fpolicy'
            query = {
                'svm.name': self.parameters['vserver'],
                'fields': 'policies'
            }

            message, error = self.rest_api.get(api, query)
            if error:
                self.module.fail_json(msg=error)
            records, error = rrh.check_for_0_or_more_records(api, message, error)
            if records is not None:
                for policy in records[0]['policies']:
                    if policy['name'] == self.parameters['policy_name']:
                        return_value = {}
                        return_value['vserver'] = records[0]['svm']['name']
                        return_value['policy_name'] = policy['name']
                        return_value['status'] = policy['enabled']
                        break
            if not return_value:
                self.module.fail_json(msg='Error getting fPolicy policy %s for vserver %s as policy does not exist' %
                                          (self.parameters['policy_name'], self.parameters['vserver']))
            return return_value

        else:

            fpolicy_status_obj = netapp_utils.zapi.NaElement('fpolicy-policy-status-get-iter')
            fpolicy_status_info = netapp_utils.zapi.NaElement('fpolicy-policy-status-info')
            fpolicy_status_info.add_new_child('policy-name', self.parameters['policy_name'])
            fpolicy_status_info.add_new_child('vserver', self.parameters['vserver'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(fpolicy_status_info)
            fpolicy_status_obj.add_child_elem(query)

            try:
                result = self.server.invoke_successfully(fpolicy_status_obj, True)

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error getting status for fPolicy policy %s for vserver %s: %s' %
                                          (self.parameters['policy_name'], self.parameters['vserver'], to_native(error)),
                                      exception=traceback.format_exc())

            if result.get_child_by_name('attributes-list'):
                fpolicy_status_attributes = result['attributes-list']['fpolicy-policy-status-info']

                return_value = {
                    'vserver': fpolicy_status_attributes.get_child_content('vserver'),
                    'policy_name': fpolicy_status_attributes.get_child_content('policy-name'),
                    'status': self.na_helper.get_value_for_bool(True, fpolicy_status_attributes.get_child_content('status')),
                }
            return return_value

    def get_svm_uuid(self):
        """
        Gets SVM uuid based on name
        :return: string of uuid
        """
        api = '/svm/svms'
        query = {
            'name': self.parameters['vserver']
        }
        message, error = self.rest_api.get(api, query)

        if error:
            self.module.fail_json(msg=error)

        return message['records'][0]['uuid']

    def enable_fpolicy_policy(self):
        """
        Enables fPolicy policy
        :return: nothing
        """

        if self.use_rest:
            api = '/protocols/fpolicy/%s/policies/%s' % (self.svm_uuid, self.parameters['policy_name'])
            body = {
                'enabled': self.parameters['status'],
                'priority': self.parameters['sequence_number']
            }

            dummy, error = self.rest_api.patch(api, body)
            if error:
                self.module.fail_json(msg=error)

        else:
            fpolicy_enable_obj = netapp_utils.zapi.NaElement('fpolicy-enable-policy')
            fpolicy_enable_obj.add_new_child('policy-name', self.parameters['policy_name'])
            fpolicy_enable_obj.add_new_child('sequence-number', self.na_helper.get_value_for_int(False, self.parameters['sequence_number']))
            try:
                self.server.invoke_successfully(fpolicy_enable_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error enabling fPolicy policy %s on vserver %s: %s' %
                                          (self.parameters['policy_name'], self.parameters['vserver'], to_native(error)),
                                      exception=traceback.format_exc())

    def disable_fpolicy_policy(self):
        """
        Disables fPolicy policy
        :return: nothing
        """

        if self.use_rest:
            api = '/protocols/fpolicy/%s/policies/%s' % (self.svm_uuid, self.parameters['policy_name'])
            body = {
                'enabled': self.parameters['status']
            }

            dummy, error = self.rest_api.patch(api, body)
            if error:
                self.module.fail_json(msg=error)

        else:

            fpolicy_disable_obj = netapp_utils.zapi.NaElement('fpolicy-disable-policy')
            fpolicy_disable_obj.add_new_child('policy-name', self.parameters['policy_name'])

            try:
                self.server.invoke_successfully(fpolicy_disable_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error disabling fPolicy policy %s on vserver %s: %s' %
                                          (self.parameters['policy_name'], self.parameters['vserver'], to_native(error)),
                                      exception=traceback.format_exc())

    def apply(self):
        if self.use_rest:
            self.svm_uuid = self.get_svm_uuid()

        current = self.get_fpolicy_policy_status()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if modify['status']:
                    self.enable_fpolicy_policy()
                elif not modify['status']:
                    self.disable_fpolicy_policy()
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    """
    Enables or disables NetApp ONTAP fPolicy
    """
    command = NetAppOntapFpolicyStatus()
    command.apply()


if __name__ == '__main__':
    main()
