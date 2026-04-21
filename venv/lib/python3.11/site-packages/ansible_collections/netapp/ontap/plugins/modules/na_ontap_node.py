#!/usr/bin/python

# (c) 2018-2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
module: na_ontap_node
short_description: NetApp ONTAP Modify or Rename a node.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Modify or Rename an ONTAP node.
options:
  name:
    description:
    - The name for the node
    required: true
    type: str

  from_name:
    description:
    - The name of the node to be renamed.  If I(name) already exists, no action will be performed.
    type: str

  location:
    description:
    - The location for the node
    type: str

  asset_tag:
    description:
    - The asset tag for the node, not supported by REST
    type: str

'''

EXAMPLES = """
- name: Modify node
  netapp.ontap.na_ontap_node:
    name: laurentncluster-2
    location: SF1
    asset_tag: mytag
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Rename node
  netapp.ontap.na_ontap_node:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    from_name: laurentn-vsim1
    name: laurentncluster-2

- name: Modify and rename node
  netapp.ontap.na_ontap_node:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    location: SF2
    from_name: laurentn-vsim1
    name: laurentncluster-2
"""

RETURN = """
"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh
import copy

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapNode(object):
    """
    Rename and modify node
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            location=dict(required=False, type='str'),
            asset_tag=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = OntapRestAPI(self.module)

        # some attributes are not supported in REST implementation
        unsupported_rest_properties = ['asset_tag']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)
        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.cluster = netapp_utils.setup_na_ontap_zapi(module=self.module)
        return

    def update_node_details(self, uuid, modify):
        api = 'cluster/nodes/%s' % uuid
        data = {}
        if 'from_name' in self.parameters:
            data['name'] = self.parameters['name']
        if 'location' in self.parameters:
            data['location'] = self.parameters['location']
        if not data:
            self.module.fail_json(msg='Nothing to update in the modified attributes: %s' % modify)
        response, error = self.rest_api.patch(api, body=data)
        response, error = rrh.check_for_error_and_job_results(api, response, error, self.rest_api)
        if error:
            self.module.fail_json(msg='Error while modifying node details: %s' % error)

    def modify_node(self, modify=None, uuid=None):
        """
        Modify an existing node
        :return: none
        """
        if self.use_rest:
            self.update_node_details(uuid, modify)
        else:
            node_obj = netapp_utils.zapi.NaElement('system-node-modify')
            node_obj.add_new_child('node', self.parameters['name'])
            if 'location' in self.parameters:
                node_obj.add_new_child('node-location', self.parameters['location'])
            if 'asset_tag' in self.parameters:
                node_obj.add_new_child('node-asset-tag', self.parameters['asset_tag'])
            try:
                self.cluster.invoke_successfully(node_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying node: %s' %
                                      (to_native(error)),
                                      exception=traceback.format_exc())

    def rename_node(self):
        """
        Rename an existing node
        :return: none
        """
        node_obj = netapp_utils.zapi.NaElement('system-node-rename')
        node_obj.add_new_child('node', self.parameters['from_name'])
        node_obj.add_new_child('new-name', self.parameters['name'])
        try:
            self.cluster.invoke_successfully(node_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming node: %s' %
                                  (to_native(error)),
                                  exception=traceback.format_exc())

    def get_node(self, name):
        if self.use_rest:
            api = 'cluster/nodes'
            query = {
                'fields': 'name,uuid,location',
                'name': name
            }
            message, error = self.rest_api.get(api, query)
            node, error = rrh.check_for_0_or_1_records(api, message, error)
            if error:
                self.module.fail_json(msg='Error while fetching node details: %s' % error)
            if node:
                if 'location' not in message['records'][0]:
                    node_location = ''
                else:
                    node_location = message['records'][0]['location']
                return dict(
                    name=message['records'][0]['name'],
                    uuid=message['records'][0]['uuid'],
                    location=node_location)
            return None
        else:
            node_obj = netapp_utils.zapi.NaElement('system-node-get')
            node_obj.add_new_child('node', name)
            try:
                result = self.cluster.invoke_successfully(node_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                if to_native(error.code) == "13115":
                    # 13115 (EINVALIDINPUTERROR) if the node does not exist
                    return None
                else:
                    self.module.fail_json(msg=to_native(
                        error), exception=traceback.format_exc())
            attributes = result.get_child_by_name('attributes')
            if attributes is not None:
                node_info = attributes.get_child_by_name('node-details-info')
                node_location = node_info.get_child_content('node-location')
                node_location = node_location if node_location is not None else ''
                node_tag = node_info.get_child_content('node-tag')
                node_tag = node_tag if node_tag is not None else ''
                return dict(
                    name=node_info['node'],
                    location=node_location,
                    asset_tag=node_tag)
            return None

    def apply(self):
        from_exists = None
        modify, modify_dict = None, None
        uuid = None
        current = self.get_node(self.parameters['name'])
        if current is None and 'from_name' in self.parameters:
            from_exists = self.get_node(self.parameters['from_name'])
            if from_exists is None:
                self.module.fail_json(msg='Node not found: %s' % self.parameters['from_name'])
            uuid = from_exists['uuid'] if 'uuid' in from_exists else None
            # since from_exists contains the node name, modify will at least contain the node name if a rename is required.
            modify = self.na_helper.get_modified_attributes(from_exists, self.parameters)
        elif current is not None:
            uuid = current['uuid'] if 'uuid' in current else None
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        allowed_options = ['name', 'location']
        if not self.use_rest:
            allowed_options.append('asset_tag')
        if modify:
            if any(x not in allowed_options for x in modify):
                self.module.fail_json(msg='Too many modified attributes found: %s, allowed: %s' % (modify, allowed_options))
            modify_dict = copy.deepcopy(modify)
        if current is None and from_exists is None:
            msg = 'from_name: %s' % self.parameters.get('from_name') if 'from_name' in self.parameters \
                  else 'name: %s' % self.parameters['name']
            self.module.fail_json(msg='Node not found: %s' % msg)
        if self.na_helper.changed:
            if not self.module.check_mode:
                if not self.use_rest:
                    if 'name' in modify:
                        self.rename_node()
                        modify.pop('name')
                if modify:
                    self.modify_node(modify, uuid)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify_dict)
        self.module.exit_json(**result)


def main():
    """
    Start, Stop and Enable node services.
    """
    obj = NetAppOntapNode()
    obj.apply()


if __name__ == '__main__':
    main()
