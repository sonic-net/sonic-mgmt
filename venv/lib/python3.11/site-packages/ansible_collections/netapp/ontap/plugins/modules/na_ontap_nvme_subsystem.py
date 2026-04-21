#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete NVME subsystem
  - Associate(modify) host/map to NVME subsystem
  - NVMe service should be existing in the data vserver with NVMe protocol as a pre-requisite
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_nvme_subsystem
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified subsystem should exist or not.
    default: present
    type: str
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  subsystem:
    description:
      - Specifies the subsystem
    required: true
    type: str
  ostype:
    description:
      - Specifies the ostype for initiators
    choices: ['windows', 'linux', 'vmware', 'xen', 'hyper_v']
    type: str
  skip_host_check:
    description:
      - Skip host check
      - Required to delete an NVMe Subsystem with attached NVMe namespaces
    default: false
    type: bool
  skip_mapped_check:
    description:
      - Skip mapped namespace check
      - Required to delete an NVMe Subsystem with attached NVMe namespaces
    default: false
    type: bool
  hosts:
    description:
      - List of host NQNs (NVMe Qualification Name) associated to the controller.
    type: list
    elements: str
  paths:
    description:
      - List of Namespace paths to be associated with the subsystem.
      - For ASA R2 systems, The paths should match the format <name>[@<snapshot-name>].
    type: list
    elements: str
short_description: "NetApp ONTAP Manage NVME Subsystem"
version_added: 2.8.0
'''

EXAMPLES = """
- name: Create NVME Subsystem
  netapp.ontap.na_ontap_nvme_subsystem:
    state: present
    subsystem: test_sub
    vserver: test_dest
    ostype: linux
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete NVME Subsystem
  netapp.ontap.na_ontap_nvme_subsystem:
    state: absent
    subsystem: test_sub
    vserver: test_dest
    skip_host_check: true
    skip_mapped_check: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Associate NVME Subsystem host/map
  netapp.ontap.na_ontap_nvme_subsystem:
    state: present
    subsystem: "{{ subsystem }}"
    ostype: linux
    hosts: nqn.1992-08.com.netapp:sn.3017cfc1e2ba11e89c55005056b36338:subsystem.ansible
    paths: /vol/ansible/test,/vol/ansible/test1
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify NVME subsystem map
  netapp.ontap.na_ontap_nvme_subsystem:
    state: present
    subsystem: test_sub
    vserver: test_dest
    skip_host_check: true
    skip_mapped_check: true
    paths: /vol/ansible/test
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_ontap_personality


class NetAppONTAPNVMESubsystem:
    """
    Class with NVME subsytem methods
    """

    def __init__(self):

        self.subsystem_uuid = None
        self.namespace_list = []
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            subsystem=dict(required=True, type='str'),
            ostype=dict(required=False, type='str', choices=['windows', 'linux', 'vmware', 'xen', 'hyper_v']),
            skip_host_check=dict(required=False, type='bool', default=False),
            skip_mapped_check=dict(required=False, type='bool', default=False),
            hosts=dict(required=False, type='list', elements='str'),
            paths=dict(required=False, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.asa_r2_system = False
        if self.use_rest:
            if self.rest_api.meets_rest_minimum_version(True, 9, 16, 0):
                self.asa_r2_system = rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)
                if self.asa_r2_system:
                    if 'paths' in self.parameters:
                        self.module.warn('For ASA R2 systems, The paths should match the format <name>[@<snapshot-name>].'
                                         'The name must begin with a letter or \"_\" and contain only \"_\" and alphanumeric character')
                        # If the path is passed as vol/vol1/ns it will be converted to ns for asa r2 systems.
                        self.parameters['paths'] = [item.split("/")[-1] for item in self.parameters['paths']]
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_subsystem(self):
        """
        Get current subsystem details
        :return: dict if subsystem exists, None otherwise
        """
        if self.use_rest:
            return self.get_subsystem_rest()
        result = self.get_zapi_info('nvme-subsystem-get-iter', 'nvme-subsystem-info')
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            return True
        return None

    def create_subsystem(self):
        """
        Create a NVME Subsystem
        """
        if self.use_rest:
            return self.create_subsystem_rest()
        options = {'subsystem': self.parameters['subsystem'],
                   'ostype': self.parameters['ostype']
                   }
        subsystem_create = netapp_utils.zapi.NaElement('nvme-subsystem-create')
        subsystem_create.translate_struct(options)
        try:
            self.server.invoke_successfully(subsystem_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating subsystem for %s: %s'
                                  % (self.parameters.get('subsystem'), to_native(error)),
                                  exception=traceback.format_exc())

    def delete_subsystem(self):
        """
        Delete a NVME subsystem
        """
        if self.use_rest:
            return self.delete_subsystem_rest()
        options = {'subsystem': self.parameters['subsystem'],
                   'skip-host-check': 'true' if self.parameters.get('skip_host_check') else 'false',
                   'skip-mapped-check': 'true' if self.parameters.get('skip_mapped_check') else 'false',
                   }
        subsystem_delete = netapp_utils.zapi.NaElement.create_node_with_children('nvme-subsystem-delete', **options)
        try:
            self.server.invoke_successfully(subsystem_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting subsystem for %s: %s'
                                      % (self.parameters.get('subsystem'), to_native(error)),
                                  exception=traceback.format_exc())

    def get_subsystem_host_map(self, type):
        """
        Get current subsystem host details
        :return: list if host exists, None otherwise
        """
        if type == 'hosts':
            zapi_get, zapi_info, zapi_type = 'nvme-subsystem-host-get-iter', 'nvme-target-subsystem-host-info', 'host-nqn'
        elif type == 'paths':
            zapi_get, zapi_info, zapi_type = 'nvme-subsystem-map-get-iter', 'nvme-target-subsystem-map-info', 'path'
        result = self.get_zapi_info(zapi_get, zapi_info, zapi_type)
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attrs_list = result.get_child_by_name('attributes-list')
            return_list = [item[zapi_type] for item in attrs_list.get_children()]
            return {type: return_list}
        return None

    def get_zapi_info(self, zapi_get_method, zapi_info, zapi_type=None):
        subsystem_get = netapp_utils.zapi.NaElement(zapi_get_method)
        query = {
            'query': {
                zapi_info: {
                    'subsystem': self.parameters.get('subsystem'),
                    'vserver': self.parameters.get('vserver')
                }
            }
        }
        subsystem_get.translate_struct(query)
        qualifier = " %s" % zapi_type if zapi_type else ""
        try:
            result = self.server.invoke_successfully(subsystem_get, enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching subsystem%s info: %s' % (qualifier, to_native(error)),
                                  exception=traceback.format_exc())
        return result

    def add_subsystem_host_map(self, data, type):
        """
        Add a NVME Subsystem host/map
        :param: data: list of hosts/paths to be added
        :param: type: hosts/paths
        """
        if type == 'hosts':
            zapi_add, zapi_type = 'nvme-subsystem-host-add', 'host-nqn'
        elif type == 'paths':
            zapi_add, zapi_type = 'nvme-subsystem-map-add', 'path'

        for item in data:
            options = {'subsystem': self.parameters['subsystem'],
                       zapi_type: item
                       }
            subsystem_add = netapp_utils.zapi.NaElement.create_node_with_children(zapi_add, **options)
            try:
                self.server.invoke_successfully(subsystem_add, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error adding %s for subsystem %s: %s'
                                      % (item, self.parameters.get('subsystem'), to_native(error)),
                                      exception=traceback.format_exc())

    def remove_subsystem_host_map(self, data, type):
        """
        Remove a NVME Subsystem host/map
        :param: data: list of hosts/paths to be added
        :param: type: hosts/paths
        """
        if type == 'hosts':
            zapi_remove, zapi_type = 'nvme-subsystem-host-remove', 'host-nqn'
        elif type == 'paths':
            zapi_remove, zapi_type = 'nvme-subsystem-map-remove', 'path'

        for item in data:
            options = {'subsystem': self.parameters['subsystem'],
                       zapi_type: item
                       }
            subsystem_remove = netapp_utils.zapi.NaElement.create_node_with_children(zapi_remove, **options)
            try:
                self.server.invoke_successfully(subsystem_remove, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error removing %s for subsystem %s: %s'
                                          % (item, self.parameters.get('subsystem'), to_native(error)),
                                      exception=traceback.format_exc())

    def associate_host_map(self, types):
        """
        Check if there are hosts or paths to be associated with the subsystem
        """
        action_add_dict = {}
        action_remove_dict = {}
        for type in types:
            current = None
            if self.parameters.get(type):
                if self.use_rest:
                    if self.subsystem_uuid:
                        current = self.get_subsystem_host_map_rest(type)
                else:
                    current = self.get_subsystem_host_map(type)
                if current:
                    add_items = self.na_helper.\
                        get_modified_attributes(current, self.parameters, get_list_diff=True).get(type)
                    remove_items = [item for item in current[type] if item not in self.parameters.get(type)]
                else:
                    add_items = self.parameters[type]
                    remove_items = {}
                if add_items:
                    action_add_dict[type] = add_items
                    self.na_helper.changed = True
                if remove_items:
                    action_remove_dict[type] = remove_items
                    self.na_helper.changed = True
        return action_add_dict, action_remove_dict

    def modify_host_map(self, add_host_map, remove_host_map):
        for type, data in sorted(add_host_map.items()):
            if self.use_rest:
                self.add_subsystem_host_map_rest(data, type)
            else:
                self.add_subsystem_host_map(data, type)
        for type, data in sorted(remove_host_map.items()):
            if self.use_rest:
                self.remove_subsystem_host_map_rest(data, type)
            else:
                self.remove_subsystem_host_map(data, type)

    def get_subsystem_rest(self):
        api = 'protocols/nvme/subsystems'
        params = {'svm.name': self.parameters['vserver'], 'name': self.parameters['subsystem']}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            if self.na_helper.ignore_missing_vserver_on_delete(error):
                return None
            self.module.fail_json(msg='Error fetching subsystem info for vserver: %s, %s' % (self.parameters['vserver'], to_native(error)))
        if record:
            self.subsystem_uuid = record['uuid']
            return record
        return None

    def get_subsystem_host_map_rest(self, type):
        if type == 'hosts':
            api = 'protocols/nvme/subsystems/%s/hosts' % self.subsystem_uuid
            records, error = rest_generic.get_0_or_more_records(self.rest_api, api)
            if error:
                self.module.fail_json(msg='Error fetching subsystem host info for vserver: %s: %s' % (self.parameters['vserver'], to_native(error)))
            if records is not None:
                return {type: [record['nqn'] for record in records]}
            return None
        if type == 'paths':
            api = 'protocols/nvme/subsystem-maps'
            query = {'svm.name': self.parameters['vserver'], 'subsystem.name': self.parameters['subsystem']}
            records, error = rest_generic.get_0_or_more_records(self.rest_api, api, query)
            if error:
                self.module.fail_json(msg='Error fetching subsystem map info for vserver: %s: %s' % (self.parameters['vserver'], to_native(error)))
            if records is not None:
                return_list = []
                for each in records:
                    return_list.append(each['namespace']['name'])
                    self.namespace_list.append(each['namespace'])
                return {type: return_list}
            return None

    def add_subsystem_host_map_rest(self, data, type):
        if type == 'hosts':
            records = [{'nqn': item} for item in data]
            api = 'protocols/nvme/subsystems/%s/hosts' % self.subsystem_uuid
            body = {'records': records}
            dummy, error = rest_generic.post_async(self.rest_api, api, body)
            if error:
                self.module.fail_json(
                    msg='Error adding %s for subsystem %s: %s' % (records, self.parameters['subsystem'], to_native(error)), exception=traceback.format_exc())
        elif type == 'paths':
            api = 'protocols/nvme/subsystem-maps'
            for item in data:
                body = {'subsystem.name': self.parameters['subsystem'],
                        'svm.name': self.parameters['vserver'],
                        'namespace.name': item
                        }
                dummy, error = rest_generic.post_async(self.rest_api, api, body)
                if error:
                    self.module.fail_json(
                        msg='Error adding %s for subsystem %s: %s' % (item, self.parameters['subsystem'], to_native(error)), exception=traceback.format_exc())

    def remove_subsystem_host_map_rest(self, data, type):
        if type == 'hosts':
            for item in data:
                api = 'protocols/nvme/subsystems/%s/hosts/%s' % (self.subsystem_uuid, item)
                dummy, error = rest_generic.delete_async(self.rest_api, api, None)
                if error:
                    self.module.fail_json(msg='Error removing %s for subsystem %s: %s'
                                              % (item, self.parameters['subsystem'], to_native(error)), exception=traceback.format_exc())
        elif type == 'paths':
            for item in data:
                namespace_uuid = None
                for each in self.namespace_list:
                    if each['name'] == item:
                        namespace_uuid = each['uuid']
                api = 'protocols/nvme/subsystem-maps/%s/%s' % (self.subsystem_uuid, namespace_uuid)
                body = {'subsystem.name': self.parameters['subsystem'],
                        'svm.name': self.parameters['vserver'],
                        'namespace.name': item
                        }
                dummy, error = rest_generic.delete_async(self.rest_api, api, None, body=body)
                if error:
                    self.module.fail_json(msg='Error removing %s for subsystem %s: %s'
                                              % (item, self.parameters['subsystem'], to_native(error)), exception=traceback.format_exc())

    def create_subsystem_rest(self):
        api = 'protocols/nvme/subsystems'
        body = {'svm.name': self.parameters['vserver'],
                'os_type': self.parameters['ostype'],
                'name': self.parameters['subsystem']}
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating subsystem for vserver %s: %s' % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_subsystem_rest(self):
        api = 'protocols/nvme/subsystems'
        body = {'allow_delete_while_mapped': 'true' if self.parameters.get('skip_mapped_check') else 'false',
                'allow_delete_with_hosts': 'true' if self.parameters.get('skip_host_check') else 'false'}
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.subsystem_uuid, body=body)
        if error:
            self.module.fail_json(msg='Error deleting subsystem for vserver %s: %s' % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        """
        Apply action to NVME subsystem
        """
        types = ['hosts', 'paths']
        current = self.get_subsystem()
        add_host_map, remove_host_map = dict(), dict()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('ostype') is None:
            self.module.fail_json(msg="Error: Missing required parameter 'ostype' for creating subsystem")
        if cd_action != 'delete' and self.parameters['state'] == 'present':
            add_host_map, remove_host_map = self.associate_host_map(types)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_subsystem()
                self.get_subsystem()
                self.modify_host_map(add_host_map, remove_host_map)
            elif cd_action == 'delete':
                self.delete_subsystem()
            elif cd_action is None:
                self.modify_host_map(add_host_map, remove_host_map)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    community_obj = NetAppONTAPNVMESubsystem()
    community_obj.apply()


if __name__ == '__main__':
    main()
