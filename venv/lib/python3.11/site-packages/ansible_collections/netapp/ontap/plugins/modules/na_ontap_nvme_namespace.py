#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete NVME namespace
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_nvme_namespace
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified namespace should exist or not.
    default: present
    type: str
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  ostype:
    description:
      - Specifies the ostype for initiators
    choices: ['windows', 'linux', 'vmware', 'xen', 'hyper_v']
    type: str
  size:
    description:
      - Size in bytes.
        Range is [0..2^63-1].
    type: int
  size_unit:
    description:
    - The unit used to interpret the size parameter.
    choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
    type: str
    default: 'b'
  path:
    description:
      - Namespace path.
      - The name of the NVMe namespace.
      - NVMe namespace names are paths of the form "/vol/<volume>[/<qtree>]/<namespace>" where the qtree name is optional.
      - For ASA R2 systems, The path should match the format <name>[@<snapshot-name>].
    required: true
    type: str
  block_size:
    description:
      - Size in bytes of a logical block. Possible values are 512 (Data ONTAP 9.6 and later), 4096. The default value is 4096.
    choices: [512, 4096]
    type: int
    version_added: '20.5.0'
  provisioning_options:
    description:
      - Options that are applied to the operation.
      - This option is available only for ASA R2 systems.
    type: dict
    version_added: '23.0.0'
    suboptions:
      count:
        description:
          - The number of LUNs to provision with these properties.
          - Only POST requests based on space.size  are supported.
          - When provided, the name is considered a prefix, and a suffix of the form _<N> is generated
            where N is the next available numeric index, starting with 1.
        type: int
short_description: "NetApp ONTAP Manage NVME Namespace"
version_added: 2.8.0
'''

EXAMPLES = """
- name: Create NVME Namespace
  netapp.ontap.na_ontap_nvme_namespace:
    state: present
    ostype: linux
    path: /vol/ansible/test
    size: 5
    size_unit: mb
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create NVME Namespace ASA R2 system
  netapp.ontap.na_ontap_nvme_namespace:
    state: present
    ostype: linux
    path: /vol/ansible/test
    size: 5
    size_unit: mb
    provisioning_options:
      count: 2
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify NVME Namespace
  netapp.ontap.na_ontap_nvme_namespace:
    state: present
    ostype: linux
    path: /vol/ansible/test
    size: 10
    size_unit: mb
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete NVME Namespace
  netapp.ontap.na_ontap_nvme_namespace:
    state: absent
    ostype: linux
    path: /vol/ansible/test
    size: 10
    size_unit: mb
    vserver: "{{ vserver }}"
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_ontap_personality


class NetAppONTAPNVMENamespace:
    """
    Class with NVME namespace methods
    """

    def __init__(self):

        self.namespace_uuid = None
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            ostype=dict(required=False, type='str', choices=['windows', 'linux', 'vmware', 'xen', 'hyper_v']),
            path=dict(required=True, type='str'),
            size=dict(required=False, type='int'),
            size_unit=dict(default='b', choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb'], type='str'),
            block_size=dict(required=False, choices=[512, 4096], type='int'),
            provisioning_options=dict(required=False, type='dict', options=dict(
                count=dict(type='int'),
            ))
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[('state', 'present', ['ostype', 'size'])],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = OntapRestAPI(self.module)
        partially_supported_rest_properties = [['provisioning_options', (9, 16, 0)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, [], partially_supported_rest_properties)
        if self.parameters.get('size'):
            self.parameters['size'] = self.parameters['size'] * \
                netapp_utils.POW2_BYTE_MAP[self.parameters['size_unit']]
        self.asa_r2_system = False
        if self.use_rest:
            if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 0):
                self.asa_r2_system = rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)
                if self.asa_r2_system:
                    if 'path' in self.parameters:
                        self.module.warn('For ASA R2 systems, The path should match the format <name>[@<snapshot-name>].'
                                         'The name must begin with a letter or \"_\" and contain only \"_\" and alphanumeric character')
                        # If the path is passed as vol/vol1/ns it will be converted to ns for asa r2 systems.
                        self.parameters['path'] = self.parameters.get('path').split("/")[-1]
                if not self.asa_r2_system and 'provisioning_options' in self.parameters:
                    self.module.fail_json(msg='ONTAP does not support provisioning_options')
        if self.use_rest and 'size' in self.parameters:
            if 'block_size' not in self.parameters and self.parameters.get('os_type') != 'vmware':
                self.default_block_size = 4096
            else:
                self.default_block_size = 512
            self.parameters['size'] = ((self.parameters['size'] + self.default_block_size - 1) // self.default_block_size) * self.default_block_size
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_namespace(self):
        """
        Get current namespace details
        :return: dict if namespace exists, None otherwise
        """
        if self.use_rest:
            return self.get_namespace_rest()
        namespace_get = netapp_utils.zapi.NaElement('nvme-namespace-get-iter')
        query = {
            'query': {
                'nvme-namespace-info': {
                    'path': self.parameters['path'],
                    'vserver': self.parameters['vserver']
                }
            }
        }
        namespace_get.translate_struct(query)
        try:
            result = self.server.invoke_successfully(namespace_get, enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching namespace info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            return result
        return None

    def create_namespace(self):
        """
        Create a NVME Namespace
        """
        if self.use_rest:
            return self.create_namespace_rest()
        options = {'path': self.parameters['path'],
                   'ostype': self.parameters['ostype'],
                   'size': self.parameters['size']
                   }
        if self.parameters.get('block_size'):
            options['block-size'] = self.parameters['block_size']
        namespace_create = netapp_utils.zapi.NaElement('nvme-namespace-create')
        namespace_create.translate_struct(options)
        try:
            self.server.invoke_successfully(namespace_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating namespace for path %s: %s'
                                  % (self.parameters.get('path'), to_native(error)),
                                  exception=traceback.format_exc())

    def delete_namespace(self):
        """
        Delete a NVME Namespace
        """
        if self.use_rest:
            return self.delete_namespace_rest()
        options = {'path': self.parameters['path']
                   }
        namespace_delete = netapp_utils.zapi.NaElement.create_node_with_children('nvme-namespace-delete', **options)
        try:
            self.server.invoke_successfully(namespace_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting namespace for path %s: %s'
                                      % (self.parameters.get('path'), to_native(error)),
                                  exception=traceback.format_exc())

    def get_namespace_rest(self):
        api = 'storage/namespaces'
        params = {
            'svm.name': self.parameters['vserver'],
            'fields': 'space.size,uuid'
        }
        response, error = rest_generic.get_0_or_more_records(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching namespace info for vserver: %s' % self.parameters['vserver'])

        existing_namespaces = {}

        if response:
            for record in response:
                existing_namespaces[record['name']] = {
                    'uuid': record['uuid'],
                    'size': record['space']['size']
                }

        requested_name = self.parameters['path']
        if requested_name in existing_namespaces:
            self.namespace_uuid = existing_namespaces[requested_name]['uuid']
            return {'size' : existing_namespaces[requested_name]['size']}  # Returns exact match

        base_name = requested_name.rsplit('-', 1)[0]  # extract base name if n exists
        matching_names = {
            name: data for name, data in existing_namespaces.items() if name.startswith(base_name + "_")
        }
        if matching_names:
            first_match = next(iter(matching_names.values()))
            return {'size': first_match['size']}
        self.namespace_uuid = None
        return None

    def create_namespace_rest(self):
        api = 'storage/namespaces'
        body = {'svm.name': self.parameters['vserver'],
                'os_type': self.parameters['ostype'],
                'name': self.parameters['path'],
                'space.size': self.parameters['size']}
        if self.parameters.get('block_size') is not None:
            body['space.block_size'] = self.parameters['block_size']
        if self.parameters.get('provisioning_options') is not None:
            body['provisioning_options'] = self.parameters['provisioning_options']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating namespace for vserver %s: %s' % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_namespace_rest(self):
        api = 'storage/namespaces'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.namespace_uuid)
        if error:
            self.module.fail_json(msg='Error deleting namespace for vserver %s: %s' % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_namespace_rest(self):
        api = 'storage/namespaces'
        body = {'space.size': self.parameters['size']}
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.namespace_uuid, body)
        if error:
            self.module.fail_json(msg='Error modifying namespace for vserver %s: %s' % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        """
        Apply action to NVME Namespace
        """
        current = self.get_namespace()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None and self.namespace_uuid is not None else None

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_namespace()
            elif cd_action == 'delete':
                self.delete_namespace()
            elif modify:
                self.modify_namespace_rest()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    community_obj = NetAppONTAPNVMENamespace()
    community_obj.apply()


if __name__ == '__main__':
    main()
