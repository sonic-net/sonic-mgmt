#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: na_ontap_local_hosts
short_description: NetApp ONTAP local hosts
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 22.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create or delete or modify local hosts in ONTAP.
options:
  state:
    description:
      - Whether the specified local hosts should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'
  owner:
    description:
      - Name of the data SVM or cluster.
    required: True
    type: str
  aliases:
    description:
      - The list of aliases.
    type: list
    elements: str
  host:
    description:
      - Canonical hostname.
      - minimum length is 1 and maximum length is 255.
    type: str
  address:
    description:
      - IPv4/IPv6 address in dotted form.
    required: True
    type: str
"""

EXAMPLES = """
- name: Create IP to host mapping
  netapp.ontap.na_ontap_local_hosts:
    state: present
    address: 10.10.10.10
    host: example.com
    aliases: ['ex1.com', 'ex2.com']
    owner: svm1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify IP to host mapping
  netapp.ontap.na_ontap_local_hosts:
    state: present
    address: 10.10.10.10
    owner: svm1
    host: example1.com
    aliases: ['ex1.com', 'ex2.com', 'ex3.com']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete host object
  netapp.ontap.na_ontap_local_hosts:
    state: absent
    address: 10.10.10.10
    owner: svm1
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, netapp_ipaddress


class NetAppOntapLocalHosts:
    """ object initialize and class methods """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            owner=dict(required=True, type='str'),
            address=dict(required=True, type='str'),
            aliases=dict(required=False, type='list', elements='str'),
            host=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.parameters['address'] = netapp_ipaddress.validate_and_compress_ip_address(self.parameters['address'], self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.owner_uuid = None
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_local_hosts', 9, 10, 1)

    def get_local_host_rest(self):
        '''
        Retrieves IP to hostname mapping for SVM of the cluster.
        '''
        api = 'name-services/local-hosts'
        query = {'owner.name': self.parameters['owner'],
                 'address': self.parameters['address'],
                 'fields': 'address,hostname,owner.name,owner.uuid,aliases'}
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error fetching IP to hostname mappings for %s: %s' % (self.parameters['owner'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.owner_uuid = record['owner']['uuid']
            return {
                'address': self.na_helper.safe_get(record, ['address']),
                'host': self.na_helper.safe_get(record, ['hostname']),
                'aliases': self.na_helper.safe_get(record, ['aliases'])
            }
        return record

    def create_local_host_rest(self):
        '''
        Creates a new IP to hostname mapping.
        '''
        api = 'name-services/local-hosts'
        body = {'owner.name': self.parameters.get('owner'),
                'address': self.parameters.get('address'),
                'hostname': self.parameters.get('host')}
        if 'aliases' in self.parameters:
            body['aliases'] = self.parameters.get('aliases')
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating IP to hostname mappings for %s: %s' % (self.parameters['owner'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_local_host_rest(self, modify):
        '''
        For a specified SVM and IP address, modifies the corresponding IP to hostname mapping.
        '''
        body = {}
        if 'aliases' in modify:
            body['aliases'] = self.parameters['aliases']
        if 'host' in modify:
            body['hostname'] = self.parameters['host']
        api = 'name-services/local-hosts/%s/%s' % (self.owner_uuid, self.parameters['address'])
        if body:
            dummy, error = rest_generic.patch_async(self.rest_api, api, None, body)
            if error:
                self.module.fail_json(msg='Error updating IP to hostname mappings for %s: %s' % (self.parameters['owner'], to_native(error)),
                                      exception=traceback.format_exc())

    def delete_local_host_rest(self):
        '''
        vserver services name-service dns hosts delete.
        '''
        api = 'name-services/local-hosts/%s/%s' % (self.owner_uuid, self.parameters['address'])
        dummy, error = rest_generic.delete_async(self.rest_api, api, None)
        if error:
            self.module.fail_json(msg='Error deleting IP to hostname mappings for %s: %s' % (self.parameters['owner'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        cd_action = None
        current = self.get_local_host_rest()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_local_host_rest()
            elif cd_action == 'delete':
                self.delete_local_host_rest()
            elif modify:
                self.modify_local_host_rest(modify)
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    """ Create object and call apply """
    hosts_obj = NetAppOntapLocalHosts()
    hosts_obj.apply()


if __name__ == '__main__':
    main()
