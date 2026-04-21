#!/usr/bin/python

"""
 (c) 2018-2025, NetApp, Inc
 # GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """

module: na_ontap_lun_map_reporting_nodes

short_description: NetApp ONTAP LUN maps reporting nodes
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.2.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Add and Remove LUN map reporting nodes.

options:
  state:
    description:
      - Whether to add or remove reporting nodes
    choices: ['present', 'absent']
    type: str
    default: present

  initiator_group_name:
    description:
      - Initiator group to map to the given LUN.
    required: true
    type: str

  path:
    description:
      - Path of the LUN.
      - For ASA R2 systems, The path should match the format <name>[@<snapshot-name>].
    required: true
    type: str

  vserver:
    required: true
    description:
      - The name of the vserver owning the LUN.
    type: str

  nodes:
    required: true
    description:
      - List of reporting nodes to add or remove
    type: list
    elements: str

notes:
  - supports ZAPI and REST. REST requires ONTAP 9.10.1 or later.
  - supports check mode.
"""

EXAMPLES = """
- name: Create Lun Map reporting nodes
  netapp.ontap.na_ontap_lun_map_reporting_nodes:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    vserver: vs1
    state: present
    initiator_group_name: carchigroup
    path: /vol/carchiVolTest/carchiLunTest
    nodes: [node2]

- name: Delete Lun Map reporting nodes
  netapp.ontap.na_ontap_lun_map_reporting_nodes:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    vserver: vs1
    state: absent
    initiator_group_name: carchigroup
    path: /vol/carchiVolTest/carchiLunTest
    nodes: [node2]
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_ontap_personality


class NetAppOntapLUNMapReportingNodes:
    ''' add or remove reporting nodes from a lun map '''
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            initiator_group_name=dict(required=True, type='str'),
            path=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            nodes=dict(required=True, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.lun_uuid, self.igroup_uuid, self.nodes_uuids = None, None, {}
        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            msg = 'REST requires ONTAP 9.10.1 or later for na_ontap_lun_map_reporting_nodes'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)
        self.asa_r2_system = False
        if self.use_rest:
            if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 0):
                self.asa_r2_system = rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)
                if self.asa_r2_system:
                    if 'path' in self.parameters:
                        self.module.warn('For ASA R2 systems, The path should match the format <name>[@<snapshot-name>].'
                                         'The name must begin with a letter or \"_\" and contain only \"_\" and alphanumeric character')
                        # If the path is passed as vol/vol1/lun1 it will be converted to lun1 for asa r2 systems.
                        self.parameters['path'] = self.parameters.get('path').split("/")[-1]
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_lun_map_reporting_nodes(self):
        """
        Return list of reporting nodes from the LUN map

        :return: list of reporting nodes
        :rtype: list
        """
        if self.use_rest:
            return self.get_lun_map_reporting_nodes_rest()
        query_details = netapp_utils.zapi.NaElement('lun-map-info')
        query_details.add_new_child('path', self.parameters['path'])
        query_details.add_new_child('initiator-group', self.parameters['initiator_group_name'])
        query_details.add_new_child('vserver', self.parameters['vserver'])

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)

        lun_query = netapp_utils.zapi.NaElement('lun-map-get-iter')
        lun_query.add_child_elem(query)

        try:
            result = self.server.invoke_successfully(lun_query, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting LUN map for %s: %s' %
                                  (self.parameters['initiator_group_name'], to_native(error)),
                                  exception=traceback.format_exc())
        try:
            num_records = int(result.get_child_content('num-records'))
        except TypeError:
            self.module.fail_json(msg="Error: unexpected ZAPI response for lun-map-get-iter: %s" % result.to_string())
        if num_records == 0:
            return None
        alist = result.get_child_by_name('attributes-list')
        info = alist.get_child_by_name('lun-map-info')
        reporting_nodes = info.get_child_by_name('reporting-nodes')
        node_list = []
        if reporting_nodes:
            for node in reporting_nodes.get_children():
                node_list.append(node.get_content())
        return node_list

    def add_lun_map_reporting_nodes(self, nodes):
        reporting_nodes_obj = netapp_utils.zapi.NaElement('lun-map-add-reporting-nodes')
        reporting_nodes_obj.add_new_child('igroup', self.parameters['initiator_group_name'])
        reporting_nodes_obj.add_new_child('path', self.parameters['path'])
        nodes_obj = netapp_utils.zapi.NaElement('nodes')
        for node in nodes:
            nodes_obj.add_new_child('filer-id', node)
        reporting_nodes_obj.add_child_elem(nodes_obj)
        try:
            self.server.invoke_successfully(reporting_nodes_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating LUN map reporting nodes for %s: %s' %
                                  (self.parameters['initiator_group_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def remove_lun_map_reporting_nodes(self, nodes):
        reporting_nodes_obj = netapp_utils.zapi.NaElement('lun-map-remove-reporting-nodes')
        reporting_nodes_obj.add_new_child('igroup', self.parameters['initiator_group_name'])
        reporting_nodes_obj.add_new_child('path', self.parameters['path'])
        nodes_obj = netapp_utils.zapi.NaElement('nodes')
        for node in nodes:
            nodes_obj.add_new_child('filer-id', node)
        reporting_nodes_obj.add_child_elem(nodes_obj)
        try:
            self.server.invoke_successfully(reporting_nodes_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting LUN map reporting nodes for %s: %s' %
                                  (self.parameters['initiator_group_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_lun_map_reporting_nodes_rest(self):
        api = 'protocols/san/lun-maps'
        query = {
            'lun.name': self.parameters['path'],
            'igroup.name': self.parameters['initiator_group_name'],
            'svm.name': self.parameters['vserver'],
            'fields': 'reporting_nodes,lun.uuid,igroup.uuid'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error getting LUN map for %s: %s' %
                                  (self.parameters['initiator_group_name'], to_native(error)))
        if record:
            self.lun_uuid = record['lun']['uuid']
            self.igroup_uuid = record['igroup']['uuid']
            node_list = []
            for node in record.get('reporting_nodes', []):
                self.nodes_uuids[node['name']] = node['uuid']
                node_list.append(node['name'])
            return node_list
        return None

    def add_lun_map_reporting_nodes_rest(self, node):
        api = 'protocols/san/lun-maps/%s/%s/reporting-nodes' % (self.lun_uuid, self.igroup_uuid)
        dummy, error = rest_generic.post_async(self.rest_api, api, {'name': node})
        if error:
            self.module.fail_json(msg='Error creating LUN map reporting node for %s: %s' %
                                  (self.parameters['initiator_group_name'], to_native(error)))

    def remove_lun_map_reporting_nodes_rest(self, node):
        api = 'protocols/san/lun-maps/%s/%s/reporting-nodes' % (self.lun_uuid, self.igroup_uuid)
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.nodes_uuids[node])
        if error:
            self.module.fail_json(msg='Error deleting LUN map reporting nodes for %s: %s' %
                                  (self.parameters['initiator_group_name'], to_native(error)))

    def apply(self):
        reporting_nodes = self.get_lun_map_reporting_nodes()
        if reporting_nodes is None:
            self.module.fail_json(msg='Error: LUN map not found for vserver %s, LUN path: %s, igroup: %s' %
                                  (self.parameters['vserver'], self.parameters['path'], self.parameters['initiator_group_name']))
        if self.parameters['state'] == 'present':
            nodes_to_add = [node for node in self.parameters['nodes'] if node not in reporting_nodes]
            nodes_to_delete = list()
        else:
            nodes_to_add = list()
            nodes_to_delete = [node for node in self.parameters['nodes'] if node in reporting_nodes]
        cd_action = None
        changed = len(nodes_to_add) > 0 or len(nodes_to_delete) > 0
        if changed and not self.module.check_mode:
            if nodes_to_add:
                cd_action = 'add_node'
                if self.use_rest:
                    for node in nodes_to_add:
                        self.add_lun_map_reporting_nodes_rest(node)
                else:
                    self.add_lun_map_reporting_nodes(nodes_to_add)
            if nodes_to_delete:
                cd_action = 'remove_node'
                if self.use_rest:
                    for node in nodes_to_delete:
                        self.remove_lun_map_reporting_nodes_rest(node)
                else:
                    self.remove_lun_map_reporting_nodes(nodes_to_delete)
        result = netapp_utils.generate_result(changed, cd_action, extra_responses={'reporting_nodes': reporting_nodes,
                                                                                   'nodes_to_add': nodes_to_add,
                                                                                   'nodes_to_delete': nodes_to_delete})
        self.module.exit_json(**result)


def main():
    na_module = NetAppOntapLUNMapReportingNodes()
    na_module.apply()


if __name__ == '__main__':
    main()
