#!/usr/bin/python
"""
this is ipspace module

# (c) 2018, NTT Europe Ltd.
# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: na_ontap_ipspace

short_description: NetApp ONTAP Manage an ipspace

version_added: 2.9.0

author:
      - NTTE Storage Engineering (@vicmunoz) <cl.eng.sto@ntt.eu>

description:
      - Manage an ipspace for an Ontap Cluster

extends_documentation_fragment:
      - netapp.ontap.netapp.na_ontap

options:
    state:
        description:
            - Whether the specified ipspace should exist or not
        choices: ['present', 'absent']
        type: str
        default: present
    name:
        description:
            - The name of the ipspace to manage
        required: true
        type: str
    from_name:
        description:
            - Name of the existing ipspace to be renamed to name
        type: str
'''

EXAMPLES = """
- name: Create ipspace
  netapp.ontap.na_ontap_ipspace:
    state: present
    name: ansibleIpspace
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete ipspace
  netapp.ontap.na_ontap_ipspace:
    state: absent
    name: ansibleIpspace
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Rename ipspace
  netapp.ontap.na_ontap_ipspace:
    state: present
    name: ansibleIpspace_newname
    from_name: ansibleIpspace
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapIpspace(object):
    '''Class with ipspace operations'''

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.uuid = None
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def ipspace_get_iter(self, name):
        """
        Return net-ipspaces-get-iter query results
        :param name: Name of the ipspace
        :return: NaElement if ipspace found, None otherwise
        """
        ipspace_get_iter = netapp_utils.zapi.NaElement('net-ipspaces-get-iter')
        query_details = netapp_utils.zapi.NaElement.create_node_with_children(
            'net-ipspaces-info', **{'ipspace': name})
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)
        ipspace_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(
                ipspace_get_iter, enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            # Error 14636 denotes an ipspace does not exist
            # Error 13073 denotes an ipspace not found
            if to_native(error.code) == "14636" or to_native(error.code) == "13073":
                return None
            self.module.fail_json(
                msg="Error getting ipspace %s: %s" % (name, to_native(error)),
                exception=traceback.format_exc())
        return result

    def get_ipspace(self, name=None):
        """
        Fetch details if ipspace exists
        :param name: Name of the ipspace to be fetched
        :return:
            Dictionary of current details if ipspace found
            None if ipspace is not found
        """
        if name is None:
            name = self.parameters['name']
        if self.use_rest:
            api = 'network/ipspaces'
            query = {'name': name, 'fields': 'uuid'}
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                self.module.fail_json(msg="Error getting ipspace %s: %s" % (name, error))
            if record:
                self.uuid = record['uuid']
                return record
            return None
        else:
            ipspace_get = self.ipspace_get_iter(name)
            if (ipspace_get and ipspace_get.get_child_by_name('num-records') and
                    int(ipspace_get.get_child_content('num-records')) >= 1):
                current_ipspace = dict()
                attr_list = ipspace_get.get_child_by_name('attributes-list')
                attr = attr_list.get_child_by_name('net-ipspaces-info')
                current_ipspace['name'] = attr.get_child_content('ipspace')
                return current_ipspace
            return None

    def create_ipspace(self):
        """
        Create ipspace
        :return: None
        """
        if self.use_rest:
            api = 'network/ipspaces'
            body = {'name': self.parameters['name']}
            dummy, error = rest_generic.post_async(self.rest_api, api, body)
            if error:
                self.module.fail_json(msg="Error provisioning ipspace %s: %s" % (self.parameters['name'], error))
        else:
            ipspace_create = netapp_utils.zapi.NaElement.create_node_with_children(
                'net-ipspaces-create', **{'ipspace': self.parameters['name']})
            try:
                self.server.invoke_successfully(ipspace_create,
                                                enable_tunneling=False)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg="Error provisioning ipspace %s: %s" % (
                        self.parameters['name'],
                        to_native(error)),
                    exception=traceback.format_exc())

    def delete_ipspace(self):
        """
        Destroy ipspace
        :return: None
        """
        if self.use_rest:
            api = 'network/ipspaces'
            dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid)
            if error:
                self.module.fail_json(msg="Error removing ipspace %s: %s" % (self.parameters['name'], error))
        else:
            ipspace_destroy = netapp_utils.zapi.NaElement.create_node_with_children(
                'net-ipspaces-destroy',
                **{'ipspace': self.parameters['name']})
            try:
                self.server.invoke_successfully(
                    ipspace_destroy, enable_tunneling=False)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg="Error removing ipspace %s: %s" % (
                        self.parameters['name'],
                        to_native(error)),
                    exception=traceback.format_exc())

    def rename_ipspace(self):
        """
        Rename an ipspace
        :return: Nothing
        """
        if self.use_rest:
            api = 'network/ipspaces'
            body = {'name': self.parameters['name']}
            dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
            if error:
                self.module.fail_json(msg="Error renaming ipspace %s: %s" % (self.parameters['from_name'], error))
        else:
            ipspace_rename = netapp_utils.zapi.NaElement.create_node_with_children(
                'net-ipspaces-rename',
                **{'ipspace': self.parameters['from_name'],
                   'new-name': self.parameters['name']})
            try:
                self.server.invoke_successfully(ipspace_rename,
                                                enable_tunneling=False)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg="Error renaming ipspace %s: %s" % (
                        self.parameters['from_name'],
                        to_native(error)),
                    exception=traceback.format_exc())

    def apply(self):
        """
        Apply action to the ipspace
        :return: Nothing
        """
        current = self.get_ipspace()
        # rename and create are mutually exclusive
        rename, modify = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('from_name'):
            rename = self.na_helper.is_rename_action(
                self.get_ipspace(self.parameters['from_name']),
                current)
            if rename is None:
                self.module.fail_json(
                    msg="Error renaming: ipspace %s does not exist" %
                    self.parameters['from_name'])
            # reset cd_action to None and add name to modify to indicate rename.
            cd_action = None
            modify = {'name': self.parameters['name']}

        if self.na_helper.changed and not self.module.check_mode:
            if rename:
                self.rename_ipspace()
            elif cd_action == 'create':
                self.create_ipspace()
            elif cd_action == 'delete':
                self.delete_ipspace()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action
    :return: nothing
    """
    obj = NetAppOntapIpspace()
    obj.apply()


if __name__ == '__main__':
    main()
