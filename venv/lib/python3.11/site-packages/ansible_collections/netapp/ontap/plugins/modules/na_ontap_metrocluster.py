#!/usr/bin/python
"""
(c) 2020-2025, NetApp, Inc
 # GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
module: na_ontap_metrocluster
short_description: NetApp ONTAP set up a MetroCluster
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '20.9.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
requirements:
    - ONTAP >= 9.8

description:
    - Configure MetroCluster.
options:
  state:
    choices: ['present']
    description:
      - Present to set up a MetroCluster
    default: present
    type: str
  dr_pairs:
    description: disaster recovery pair
    type: list
    required: true
    elements: dict
    suboptions:
      node_name:
        description:
          - the name of the main node
        required: true
        type: str
      partner_node_name:
        description:
          - the name of the main partner node
        required: true
        type: str
  partner_cluster_name:
    description:
      - The name of the partner Cluster
    required: true
    type: str
'''

EXAMPLES = '''
- name: Create MetroCluster
  netapp.ontap.na_ontap_metrocluster:
    dr_pairs:
      - partner_node_name: rha17-a2
        node_name: rha17-b2
    partner_cluster_name: rha2-b2b1_siteB
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppONTAPMetroCluster(object):
    ''' ONTAP metrocluster operations '''
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present'], default='present'),
            dr_pairs=dict(required=True, type='list', elements='dict', options=dict(
                node_name=dict(required=True, type='str'),
                partner_node_name=dict(required=True, type='str')
            )),
            partner_cluster_name=dict(required=True, type='str')
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
            self.module.fail_json(msg=self.rest_api.requires_ontap_9_6('na_ontap_metrocluster'))

    def get_metrocluster(self):
        attrs = None
        api = 'cluster/metrocluster'
        options = {'fields': '*'}
        message, error = self.rest_api.get(api, options)
        if error:
            self.module.fail_json(msg=error)
        if message is not None:
            local = message['local']
            if local['configuration_state'] != "not_configured":
                attrs = {
                    'configuration_state': local['configuration_state'],
                    'partner_cluster_reachable': local['partner_cluster_reachable'],
                    'partner_cluster_name': local['cluster']['name']
                }
        return attrs

    def create_metrocluster(self):
        api = 'cluster/metrocluster'
        options = {}
        dr_pairs = []
        for pair in self.parameters['dr_pairs']:
            dr_pairs.append({'node': {'name': pair['node_name']},
                             'partner': {'name': pair['partner_node_name']}})
        partner_cluster = {'name': self.parameters['partner_cluster_name']}
        data = {'dr_pairs': dr_pairs, 'partner_cluster': partner_cluster}
        message, error = self.rest_api.post(api, data, options)
        if error is not None:
            self.module.fail_json(msg="%s" % error)
        message, error = self.rest_api.wait_on_job(message['job'])
        if error:
            self.module.fail_json(msg="%s" % error)

    def apply(self):
        current = self.get_metrocluster()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.create_metrocluster()
                # Since there is no modify or delete, we will return no change
                else:
                    self.module.fail_json(msg="Modify and Delete currently not support in API")
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    obj = NetAppONTAPMetroCluster()
    obj.apply()


if __name__ == '__main__':
    main()
