#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---

module: na_ontap_ucadapter
short_description: NetApp ONTAP UC adapter configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
    - modify the UC adapter mode and type taking pending type and mode into account.

options:
  state:
    description:
      - Whether the specified adapter should exist.
    required: false
    choices: ['present']
    default: 'present'
    type: str

  adapter_name:
    description:
      - Specifies the adapter name.
    required: true
    type: str

  node_name:
    description:
      - Specifies the adapter home node.
    required: true
    type: str

  mode:
    description:
      - Specifies the mode of the adapter.
    type: str

  type:
    description:
      - Specifies the fc4 type of the adapter.
    type: str

  pair_adapters:
    description:
      - Specifies the list of adapters which also need to be offline along with the current adapter during modifying.
      - If specified adapter works in a group or pair, the other adapters might also need to offline before modify the specified adapter.
      - The mode of pair_adapters are modified along with the adapter, the type of the pair_adapters are not modified.
    type: list
    elements: str
    version_added: '20.6.0'

'''

EXAMPLES = '''
- name: Modify adapter
  netapp.ontap.na_ontap_adapter:
    state: present
    adapter_name: 0e
    pair_adapters: 0f
    node_name: laurentn-vsim1
    mode: fc
    type: target
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
'''

RETURN = '''
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapadapter:
    ''' object to describe  adapter info '''

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present'], default='present', type='str'),
            adapter_name=dict(required=True, type='str'),
            node_name=dict(required=True, type='str'),
            mode=dict(required=False, type='str'),
            type=dict(required=False, type='str'),
            pair_adapters=dict(required=False, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.adapters_uuids = {}
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Set up Rest API
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_adapter(self):
        """
        Return details about the adapter
        :param:
            name : Name of the name of the adapter

        :return: Details about the adapter. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_adapter_rest()
        adapter_info = netapp_utils.zapi.NaElement('ucm-adapter-get')
        adapter_info.add_new_child('adapter-name', self.parameters['adapter_name'])
        adapter_info.add_new_child('node-name', self.parameters['node_name'])
        try:
            result = self.server.invoke_successfully(adapter_info, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching ucadapter details: %s: %s'
                                      % (self.parameters['node_name'], to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('attributes'):
            adapter_attributes = result.get_child_by_name('attributes').\
                get_child_by_name('uc-adapter-info')
            return_value = {
                'mode': adapter_attributes.get_child_content('mode'),
                'pending-mode': adapter_attributes.get_child_content('pending-mode'),
                'type': adapter_attributes.get_child_content('fc4-type'),
                'pending-type': adapter_attributes.get_child_content('pending-fc4-type'),
                'status': adapter_attributes.get_child_content('status'),
            }
            return return_value
        return None

    def modify_adapter(self):
        """
        Modify the adapter.
        """
        if self.use_rest:
            return self.modify_adapter_rest()
        params = {'adapter-name': self.parameters['adapter_name'],
                  'node-name': self.parameters['node_name']}
        if self.parameters.get('type') is not None:
            params['fc4-type'] = self.parameters['type']
        if self.parameters.get('mode') is not None:
            params['mode'] = self.parameters['mode']
        adapter_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'ucm-adapter-modify', ** params)
        try:
            self.server.invoke_successfully(adapter_modify,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg='Error modifying adapter %s: %s' % (self.parameters['adapter_name'], to_native(e)),
                                  exception=traceback.format_exc())

    def online_or_offline_adapter(self, status, adapter_name):
        """
        Bring a Fibre Channel target adapter offline/online.
        """
        if self.use_rest:
            return self.online_or_offline_adapter_rest(status, adapter_name)
        if status == 'down':
            adapter = netapp_utils.zapi.NaElement('fcp-adapter-config-down')
        elif status == 'up':
            adapter = netapp_utils.zapi.NaElement('fcp-adapter-config-up')
        adapter.add_new_child('fcp-adapter', adapter_name)
        adapter.add_new_child('node', self.parameters['node_name'])
        try:
            self.server.invoke_successfully(adapter,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg='Error trying to %s fc-adapter %s: %s' % (status, adapter_name, to_native(e)),
                                  exception=traceback.format_exc())

    def get_adapters_uuids(self):
        missing_adapters = []
        adapters = [self.parameters['adapter_name']] + self.parameters.get('pair_adapters', [])
        for adapter in adapters:
            adapter_uuid = self.get_adapter_uuid(adapter)
            if adapter_uuid is None:
                missing_adapters.append(adapter)
            else:
                self.adapters_uuids[adapter] = adapter_uuid
        if missing_adapters:
            self.module.fail_json(msg="Error: Adapter(s) %s not exist" % (', ').join(missing_adapters))

    def get_adapter_uuid(self, adapter):
        api = 'network/fc/ports'
        params = {
            'name': adapter,
            'node.name': self.parameters['node_name'],
            'fields': 'uuid'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error fetching adapter %s uuid" % adapter)
        return record['uuid'] if record else None

    def get_adapter_rest(self):
        api = 'private/cli/ucadmin'
        params = {
            'node': self.parameters['node_name'],
            'adapter': self.parameters['adapter_name'],
            'fields': 'pending_mode,pending_type,current_mode,current_type,status_admin'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching ucadapter details: %s: %s'
                                      % (self.parameters['node_name'], to_native(error)))
        if record:
            return {
                'mode': self.na_helper.safe_get(record, ['current_mode']),
                'pending-mode': self.na_helper.safe_get(record, ['pending_mode']),
                'type': self.na_helper.safe_get(record, ['current_type']),
                'pending-type': self.na_helper.safe_get(record, ['pending_type']),
                'status': self.na_helper.safe_get(record, ['status_admin'])
            }
        return None

    def modify_adapter_rest(self):
        api = 'private/cli/ucadmin'
        query = {
            'node': self.parameters['node_name'],
            'adapter': self.parameters['adapter_name']
        }
        body = {}
        if self.parameters.get('type') is not None:
            body['type'] = self.parameters['type']
        if self.parameters.get('mode') is not None:
            body['mode'] = self.parameters['mode']
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body, query)
        if error:
            self.module.fail_json(msg='Error modifying adapter %s: %s' % (self.parameters['adapter_name'], to_native(error)))

    def online_or_offline_adapter_rest(self, status, adapter_name):
        api = 'network/fc/ports'
        body = {'enabled': True if status == 'up' else False}
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.adapters_uuids[adapter_name], body)
        if error:
            self.module.fail_json(msg='Error trying to %s fc-adapter %s: %s' % (status, adapter_name, to_native(error)))

    def apply(self):
        ''' calling all adapter features '''
        changed = False
        current = self.get_adapter()

        def need_to_change(expected, pending, current):
            if expected is None:
                return False
            elif pending is not None:
                return pending != expected
            elif current is not None:
                return current != expected
            return False

        if current:
            if self.parameters.get('type') is not None:
                changed = need_to_change(self.parameters['type'], current['pending-type'], current['type'])
            changed = changed or need_to_change(self.parameters.get('mode'), current['pending-mode'], current['mode'])
        if changed and self.use_rest:
            self.get_adapters_uuids()
        if changed and not self.module.check_mode:
            self.online_or_offline_adapter('down', self.parameters['adapter_name'])
            if self.parameters.get('pair_adapters') is not None:
                for adapter in self.parameters['pair_adapters']:
                    self.online_or_offline_adapter('down', adapter)
            self.modify_adapter()
            self.online_or_offline_adapter('up', self.parameters['adapter_name'])
            if self.parameters.get('pair_adapters') is not None:
                for adapter in self.parameters['pair_adapters']:
                    self.online_or_offline_adapter('up', adapter)

        self.module.exit_json(changed=changed)


def main():
    adapter = NetAppOntapadapter()
    adapter.apply()


if __name__ == '__main__':
    main()
