#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_snaplock_clock

short_description: NetApp ONTAP Sets the snaplock compliance clock.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Sets the Snaplock compliance clock on NetApp ONTAP.

options:
  node:
    description:
      - Name of the node to set compliance clock on.
    type: str
    required: true

'''

EXAMPLES = """
- name: Set node compliance clock
  netapp.ontap.na_ontap_snaplock_clock:
    node: cluster1-01
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
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapSnaplockClock:
    '''Class with SnapLock clock operations'''

    def __init__(self):
        '''Initialize module parameters'''

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            node=dict(required=True, type='str'),
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
                self.module.fail_json(msg=netapp_utils.netapp)
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_snaplock_node_compliance_clock(self):

        if self.use_rest:
            """
            Return snaplock-node-compliance-clock query results
            :return: dict of clock info
            """
            api = "private/cli/snaplock/compliance-clock"
            query = {
                'fields': 'node,time',
                'node': self.parameters['node'],
            }
            message, error = self.rest_api.get(api, query)
            records, error = rrh.check_for_0_or_1_records(api, message, error)

            if error is None and records is not None:
                return_value = {
                    'node': message['records'][0]['node'],
                    'compliance_clock_time': message['records'][0]['time']
                }

            if error:
                self.module.fail_json(msg=error)

            if not records:
                error = "REST API did not return snaplock compliance clock for node %s" % (self.parameters['node'])
                self.module.fail_json(msg=error)

        else:
            """
            Return snaplock-node-compliance-clock query results
            :param node_name: name of the cluster node
            :return: NaElement
            """

            node_snaplock_clock = netapp_utils.zapi.NaElement('snaplock-get-node-compliance-clock')
            node_snaplock_clock.add_new_child('node', self.parameters['node'])

            try:
                result = self.server.invoke_successfully(node_snaplock_clock, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error fetching snaplock compliance clock for node %s : %s'
                                      % (self.parameters['node'], to_native(error)),
                                      exception=traceback.format_exc())

            return_value = None

            if result.get_child_by_name('snaplock-node-compliance-clock'):
                node_snaplock_clock_attributes = result['snaplock-node-compliance-clock']['compliance-clock-info']
                return_value = {
                    'compliance_clock_time': node_snaplock_clock_attributes['formatted-snaplock-compliance-clock'],
                }
        return return_value

    def set_snaplock_node_compliance_clock(self):
        '''Set ONTAP snaplock compliance clock for each node'''
        if self.use_rest:
            api = "private/cli/snaplock/compliance-clock/initialize"
            query = {
                "node": self.parameters['node']
            }

            body = {}
            dummy, error = self.rest_api.patch(api, body, query)
            if error:
                self.module.fail_json(msg=error)
        else:
            node_snaplock_clock_obj = netapp_utils.zapi.NaElement('snaplock-set-node-compliance-clock')
            node_snaplock_clock_obj.add_new_child('node', self.parameters['node'])

            try:
                result = self.server.invoke_successfully(node_snaplock_clock_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error setting snaplock compliance clock for node %s : %s'
                                          % (self.parameters['node'], to_native(error)),
                                          exception=traceback.format_exc())
            return result

    def apply(self):
        current = self.get_snaplock_node_compliance_clock()

        if current['compliance_clock_time'] == "ComplianceClock is not configured.":
            self.na_helper.changed = True

        if self.na_helper.changed and not self.module.check_mode:
            self.set_snaplock_node_compliance_clock()

        self.module.exit_json(changed=self.na_helper.changed)


def main():
    '''Set snaplock compliance clock'''
    obj = NetAppOntapSnaplockClock()
    obj.apply()


if __name__ == '__main__':
    main()
