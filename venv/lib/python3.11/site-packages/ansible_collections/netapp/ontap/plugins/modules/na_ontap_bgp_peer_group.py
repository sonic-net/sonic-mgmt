#!/usr/bin/python

# (c) 2024-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_bgp_peer_group
short_description: NetApp ONTAP module to create, modify or delete bgp peer group.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_rest
version_added: '22.0.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create, modify or delete bgp peer group.
options:
  state:
    description:
      - Create or delete BGP peer group.
    choices: ['present', 'absent']
    type: str
    default: present
  name:
    description:
      - Name of the BGP peer group.
    type: str
    required: true
  from_name:
    description:
      - Name of the existing BGP peer group to be renamed to C(name).
    type: str
  ipspace:
    description:
      - IPSpace name, cannot be modified after creation.
    type: str
  local:
    description:
      - Information describing the local interface that is being used to peer with a router using BGP.
      - When creating BGP peer group, an existing BGP interface is used by specifying the interface, or create a new one by specifying the port and IP address.
      - Cannot be modified after creation.
    type: dict
    suboptions:
      interface:
        description:
          - An existing BGP interface.
          - If interface not found, module will try to create BGP interface using C(local.ip) and C(local.port).
        type: dict
        suboptions:
          name:
            description:
              - BGP interface name.
            type: str
      ip:
        description:
          - IP information, requird to create a new interface.
        type: dict
        suboptions:
          address:
            description:
              - IPv4 or IPv6 address, example 10.10.10.7.
            type: str
          netmask:
            description:
              - Input as netmask length (16) or IPv4 mask (255.255.0.0).
              - For IPv6, the default value is 64 with a valid range of 1 to 127.
            type: str
      port:
        description:
          - Port and node information, required to create a new interface.
        type: dict
        suboptions:
          name:
            description:
              - Port name.
            type: str
          node:
            description:
              - Name of node on which the port is located.
            type: dict
            suboptions:
              name:
                description:
                  - Node name
                type: str
  peer:
    description:
      - Information describing the router to peer with
    type: dict
    suboptions:
      address:
        description:
          - Peer router address.
        type: str
      asn:
        description:
          - Autonomous system number of peer.
          - Cannot be modified after creation.
        type: int
  use_peer_as_next_hop:
    description:
      - Specifies whether the peer group uses the peer address as a next hop route.
      - This field requires ONTAP version 9.9 or later.
    type: bool
    version_added: '22.12.0'
"""

EXAMPLES = """
- name: Create BGP peer group with existing bgp interface bgp_lif.
  netapp.ontap.na_ontap_bgp_peer_group:
    name: peer_group
    ipspace: Default
    local:
      interface:
        name: bgp_lif
    peer:
      address: 10.10.10.19
      asn: 65501
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Create new BGP interface new_bgp_lif and BGP peer group peer_group_1.
  netapp.ontap.na_ontap_bgp_peer_group:
    name: peer_group_1
    ipspace: Default
    local:
      interface:
        name: new_bgp_lif
      ip:
        address: 10.10.10.20
        netmask: 24
      port:
        name: e0a
        node:
          name: ontap98-01
    peer:
      address: 10.10.10.20
      asn: 65500
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

# this will create bgp interface with random name.
- name: Create BGP interface without interface name and BGP peer group peer_group_2.
  netapp.ontap.na_ontap_bgp_peer_group:
    name: peer_group_2
    ipspace: Default
    local:
      ip:
        address: 10.10.10.22
        netmask: 24
      port:
        name: e0a
        node:
          name: ontap98-01
    peer:
      address: 10.10.10.22
      asn: 65512
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Modify peer address.
  netapp.ontap.na_ontap_bgp_peer_group:
    name: peer_group_2
    ipspace: Default
    peer:
      address: 10.10.55.22
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Rename BGP peer group name and modify peer address.
  netapp.ontap.na_ontap_bgp_peer_group:
    from_name: peer_group_2
    name: new_peer_group
    ipspace: Default
    peer:
      address: 10.10.55.40
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Delete BGP peer group.
  netapp.ontap.na_ontap_bgp_peer_group:
    name: new_peer_group
    ipspace: Default
    state: absent
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, netapp_ipaddress


class NetAppOntapBgpPeerGroup:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            ipspace=dict(required=False, type='str'),
            local=dict(required=False, type='dict', options=dict(
                interface=dict(required=False, type='dict', options=dict(
                    name=dict(required=False, type='str'),
                )),
                ip=dict(required=False, type='dict', options=dict(
                    address=dict(required=False, type='str'),
                    netmask=dict(required=False, type='str')
                )),
                port=dict(required=False, type='dict', options=dict(
                    name=dict(required=False, type='str'),
                    node=dict(required=False, type='dict', options=dict(
                        name=dict(required=False, type='str')
                    ))
                ))
            )),
            peer=dict(required=False, type='dict', options=dict(
                address=dict(required=False, type='str'),
                asn=dict(required=False, type='int')
            )),
            use_peer_as_next_hop=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        if self.na_helper.safe_get(self.parameters, ['peer', 'address']):
            self.parameters['peer']['address'] = netapp_ipaddress.validate_and_compress_ip_address(self.parameters['peer']['address'], self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_bgp_peer_group', 9, 7)
        partially_supported_rest_properties = [[('use_peer_as_next_hop'), (9, 9, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(parameters=self.parameters,
                                                                   partially_supported_rest_properties=partially_supported_rest_properties)
        self.parameters = self.na_helper.filter_out_none_entries(self.parameters)

    def get_bgp_peer_group(self, name=None):
        """
        Get BGP peer group.
        """
        if name is None:
            name = self.parameters['name']
        api = 'network/ip/bgp/peer-groups'
        query = {
            'name': name,
            'fields': 'name,uuid,peer'
        }
        if 'ipspace' in self.parameters:
            query['ipspace.name'] = self.parameters['ipspace']
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error fetching BGP peer group %s: %s' % (name, to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.uuid = record['uuid']
            return {
                'name': self.na_helper.safe_get(record, ['name']),
                'peer': {
                    'address': self.na_helper.safe_get(record, ['peer', 'address']),
                    'asn': self.na_helper.safe_get(record, ['peer', 'asn'])
                },
                'use_peer_as_next_hop': self.na_helper.safe_get(record, ['peer', 'is_next_hop'])
            }
        return None

    def create_bgp_peer_group(self):
        """
        Create BGP peer group.
        """
        api = 'network/ip/bgp/peer-groups'
        body = {
            'name': self.parameters['name'],
            'local': self.parameters['local'],
            'peer': self.parameters['peer']
        }
        if 'ipspace' in self.parameters:
            body['ipspace.name'] = self.parameters['ipspace']
        if 'use_peer_as_next_hop' in self.parameters:
            body['peer.is_next_hop'] = self.parameters['use_peer_as_next_hop']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating BGP peer group %s: %s.' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_bgp_peer_group(self, modify):
        """
        Modify BGP peer group.
        """
        api = 'network/ip/bgp/peer-groups'
        body = {}
        if 'name' in modify:
            body['name'] = modify['name']
        if 'peer' in modify:
            body['peer'] = modify['peer']
        if 'use_peer_as_next_hop' in modify:
            body['peer.is_next_hop'] = modify['use_peer_as_next_hop']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            name = self.parameters['from_name'] if 'name' in modify else self.parameters['name']
            self.module.fail_json(msg='Error modifying BGP peer group %s: %s.' % (name, to_native(error)),
                                  exception=traceback.format_exc())

    def delete_bgp_peer_group(self):
        """
        Delete BGP peer group.
        """
        api = 'network/ip/bgp/peer-groups'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid)
        if error:
            self.module.fail_json(msg='Error deleting BGP peer group %s: %s.' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_bgp_peer_group()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = None
        if cd_action == 'create':
            if self.parameters.get('from_name'):
                current = self.get_bgp_peer_group(self.parameters['from_name'])
                if not current:
                    self.module.fail_json(msg="Error renaming BGP peer group, %s does not exist." % self.parameters['from_name'])
                cd_action = None
            elif not self.parameters.get('local') or not self.parameters.get('peer'):
                self.module.fail_json(msg="Error creating BGP peer group %s, local and peer are required in create." % self.parameters['name'])
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if self.na_helper.safe_get(modify, ['peer', 'asn']):
                self.module.fail_json(msg="Error: cannot modify peer asn.")
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_bgp_peer_group()
            elif cd_action == 'delete':
                self.delete_bgp_peer_group()
            else:
                self.modify_bgp_peer_group(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    bgp_obj = NetAppOntapBgpPeerGroup()
    bgp_obj.apply()


if __name__ == '__main__':
    main()
