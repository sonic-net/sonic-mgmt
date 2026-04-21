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
module: na_ontap_metrocluster_dr_group
short_description: NetApp ONTAP manage MetroCluster DR Group
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 20.11.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
requirements:
    - ONTAP >= 9.8
description:
    - Create/Delete MetroCluster DR Group
    - Create only supports MCC IP
    - Delete supports both MCC IP and MCC FC
options:
  state:
    choices: ['present', 'absent']
    description:
      add or remove DR groups
    default: present
    type: str
  dr_pairs:
    description: disaster recovery pairs
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
      - The name of the partner cluster
    required: true
    type: str
'''

EXAMPLES = '''
- name: Create MetroCluster DR group
  netapp.ontap.na_ontap_metrocluster_dr_group:
    dr_pairs:
      - partner_name: carchi_cluster3_01
        node_name: carchi_cluster1_01
    partner_cluster_name: carchi_cluster3
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Delete MetroCluster DR group
  netapp.ontap.na_ontap_metrocluster_dr_group:
    dr_pairs:
      - partner_name: carchi_cluster3_01
        node_name: carchi_cluster1_01
    state: absent
    partner_cluster_name: carchi_cluster3
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


class NetAppONTAPMetroClusterDRGroup(object):
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], default='present'),
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
            self.module.fail_json(msg=self.rest_api.requires_ontap_version('na_ontap_metrocluster_dr_group',
                                                                           version='9.8'))

    def get_dr_group(self):
        return_attrs = None
        for pair in self.parameters['dr_pairs']:
            api = 'cluster/metrocluster/dr-groups'
            options = {'fields': '*',
                       'dr_pairs.node.name': pair['node_name'],
                       'dr_pairs.partner.name': pair['partner_node_name'],
                       'partner_cluster.name': self.parameters['partner_cluster_name']}
            message, error = self.rest_api.get(api, options)
            if error:
                self.module.fail_json(msg=error)
            if 'records' in message and message['num_records'] == 0:
                continue
            elif 'records' not in message or message['num_records'] != 1:
                error = "Unexpected response from %s: %s" % (api, repr(message))
                self.module.fail_json(msg=error)
            record = message['records'][0]
            return_attrs = {
                'partner_cluster_name': record['partner_cluster']['name'],
                'dr_pairs': [],
                'id': record['id']
            }
            for dr_pair in record['dr_pairs']:
                return_attrs['dr_pairs'].append({'node_name': dr_pair['node']['name'], 'partner_node_name': dr_pair['partner']['name']})
            # if we have an return_dr_id we don't need to loop anymore
            break
        return return_attrs

    def get_dr_group_ids_from_nodes(self):
        delete_ids = []
        for pair in self.parameters['dr_pairs']:
            api = 'cluster/metrocluster/nodes'
            options = {'fields': '*',
                       'node.name': pair['node_name']}
            message, error = self.rest_api.get(api, options)
            if error:
                self.module.fail_json(msg=error)
            if 'records' in message and message['num_records'] == 0:
                continue
            elif 'records' not in message or message['num_records'] != 1:
                error = "Unexpected response from %s: %s" % (api, repr(message))
                self.module.fail_json(msg=error)
            record = message['records'][0]
            if int(record['dr_group_id']) not in delete_ids:
                delete_ids.append(int(record['dr_group_id']))
        return delete_ids

    def create_dr_group(self):
        api = 'cluster/metrocluster/dr-groups'
        dr_pairs = []
        for pair in self.parameters['dr_pairs']:
            dr_pairs.append({'node': {'name': pair['node_name']},
                             'partner': {'name': pair['partner_node_name']}})
        partner_cluster = {'name': self.parameters['partner_cluster_name']}
        data = {'dr_pairs': dr_pairs, 'partner_cluster': partner_cluster}
        message, error = self.rest_api.post(api, data)
        if error is not None:
            self.module.fail_json(msg="%s" % error)
        message, error = self.rest_api.wait_on_job(message['job'])
        if error:
            self.module.fail_json(msg="%s" % error)

    def delete_dr_groups(self, dr_ids):
        for dr_id in dr_ids:
            api = 'cluster/metrocluster/dr-groups/' + str(dr_id)
            message, error = self.rest_api.delete(api)
            if error:
                self.module.fail_json(msg=error)
            message, error = self.rest_api.wait_on_job(message['job'])
            if error:
                self.module.fail_json(msg="%s" % error)

    def apply(self):
        current = self.get_dr_group()
        delete_ids = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and current is None and self.parameters['state'] == 'absent':
            # check if there is some FC group to delete
            delete_ids = self.get_dr_group_ids_from_nodes()
            if delete_ids:
                cd_action = 'delete'
                self.na_helper.changed = True
        elif cd_action == 'delete':
            delete_ids = [current['id']]
        if cd_action and not self.module.check_mode:
            if cd_action == 'create':
                self.create_dr_group()
            if cd_action == 'delete':
                self.delete_dr_groups(delete_ids)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    obj = NetAppONTAPMetroClusterDRGroup()
    obj.apply()


if __name__ == '__main__':
    main()
