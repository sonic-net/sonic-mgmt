#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_bgp_config
short_description: NetApp ONTAP network BGP configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.13.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/ modify/ delete BGP configuration for a node.
options:
  state:
    description:
        - Specifies whether to create/ update or delete the border gateway protocol (BGP) configuration for a node.
    choices: ['present', 'absent']
    type: str
    default: present

  node:
    description:
      - Specifies the node on which configuration details will be managed.
    required: true
    type: str

  asn:
    description:
      - Specifies the autonomous system number (ASN). The ASN attribute is a positive integer of the range from 1 to 4,294,967,295.
      - It should typically be chosen from RFC6996 "Autonomous System (AS) Reservation for Private Use" or
        the AS number assigned to the operator's organization.
    type: int

  hold_time:
    description:
      - Specifies the hold time in seconds. The default value is 180.
    type: int
    default: 180

  router_id:
    description:
      - Specifies the local router ID. The router-id value takes the form of an IPv4 address.
      - The default router-id will be initialized using a local IPv4 address in admin vserver if not given for create operation.
    type: str

notes:
  - Only supported with REST and requires ONTAP 9.6 or later.
"""

EXAMPLES = """
- name: Create BGP configuration for a node
  netapp.ontap.na_ontap_bgp_config:
    state: present
    node: "csahu-node1"
    asn: 10
    hold_time: 180
    router_id: "10.0.1.112"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Modify BGP configuration for a node
  netapp.ontap.na_ontap_bgp_config:
    state: present
    node: "csahu-node1"
    hold_time: 360
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Delete BGP configuration for a node
  netapp.ontap.na_ontap_bgp_config:
    state: absent
    node: "csahu-node1"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapBgpConfiguration:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            node=dict(required=True, type='str'),
            asn=dict(required=False, type='int'),
            hold_time=dict(required=False, type='int', default=180),
            router_id=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_bgp_config:', 9, 6)

    def get_bgp_config(self):
        """ Retrieves border gateway protocol (BGP) configuration for the given node """
        api = 'private/cli/network/bgp/config'
        fields = 'node,asn,hold-time,router-id'
        params = {
            'node': self.parameters['node'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error fetching BGP configuration for %s: %s" % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            return {
                'node': record.get('node'),
                'asn': record.get('asn'),
                'hold_time': record.get('hold_time'),
                'router_id': record.get('router_id')
            }
        return None

    def create_bgp_config(self):
        """ Creates border gateway protocol (BGP) configuration for the given node """
        api = 'private/cli/network/bgp/config'
        body = {
            'node': self.parameters['node']
        }
        options = ('asn', 'hold_time', 'router_id')
        for option in options:
            if option in self.parameters:
                body[option] = self.parameters[option]
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating BGP configuration for %s: %s" % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_bgp_config(self, modify):
        """ Modifues border gateway protocol (BGP) configuration for the given node """
        api = 'private/cli/network/bgp/config'
        params = {
            'node': self.parameters['node']
        }
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid_or_name=None, body=modify, query=params)
        if error:
            self.module.fail_json(msg='Error modifying BGP configuration for %s: %s.' % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_bgp_config(self):
        """ Deletes border gateway protocol (BGP) configuration for the given node """
        api = 'private/cli/network/bgp/config'
        params = {
            'node': self.parameters['node']
        }
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid=None, query=params)
        if error:
            self.module.fail_json(msg='Error deleting BGP configuration for %s: %s.' % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_bgp_config()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_bgp_config()
            elif cd_action == 'delete':
                self.delete_bgp_config()
            elif modify:
                self.modify_bgp_config(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    bgp_config = NetAppOntapBgpConfiguration()
    bgp_config.apply()


if __name__ == '__main__':
    main()
