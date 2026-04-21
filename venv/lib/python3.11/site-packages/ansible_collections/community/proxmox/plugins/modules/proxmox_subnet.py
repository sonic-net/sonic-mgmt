#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_subnet
short_description: Create/Update/Delete subnets from SDN
version_added: "1.4.0"
description:
  - Create, update, or delete subnets in Proxmox SDN.
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
options:
  state:
    description:
      - Desired state of the subnet configuration.
    type: str
    choices: ['present', 'absent']
    default: present
  update:
    description:
      - If O(state=present) then it will update the subnet if needed.
    type: bool
    default: True
  dhcp_range_update_mode:
    description:
      - Only applicable for O(state=present) and it will honor and only make changes when O(update=true)
      - If set to append and new dhcp_range passed it will just append to existing ranges.
      - And If no dhcp_range passed and there are existing ranges it will just ignore existing ranges and only update other params if needed
      - If set to overwrite and new dhcp_range passed it will overwrite existing ranges.
      - If no dhcp_range passed and there are existing ranges it will delete all dhcp_ranges
    type: str
    default: append
    choices: ['append', 'overwrite']
  subnet:
    description:
      - Subnet CIDR.
    type: str
    required: true
  vnet:
    description:
      - The virtual network to which the subnet belongs.
    type: str
    required: true
  zone:
    description:
      - Vnet Zone.
    type: str
  dhcp_dns_server:
    description:
      - IP address for the DNS server.
    type: str
  dhcp_range:
    description:
      - Range of IP addresses for DHCP.
    type: list
    elements: dict
    suboptions:
      start:
        description:
          - Starting IP address of the DHCP range.
        type: str
        required: true
      end:
        description:
          - Ending IP address of the DHCP range.
        type: str
        required: true
  dnszoneprefix:
    description:
      - Prefix for the DNS zone.
    type: str
  gateway:
    description:
      - Subnet Gateway. Will be assign on vnet for layer3 zones.
    type: str
  lock_token:
    description:
      - the token for unlocking the global SDN configuration.
    type: str
  snat:
    description:
      - Enable Source NAT for the subnet.
    type: bool
    default: False
  delete:
    description:
      - A list of settings you want to delete.
    type: str
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Create a subnet
  community.proxmox.proxmox_subnet:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    vnet: test
    subnet: 10.10.2.0/24
    zone: ans1
    state: present
    dhcp_range:
      - start: 10.10.2.5
        end: 10.10.2.50
      - start: 10.10.2.100
        end: 10.10.2.150
    snat: true

- name: Delete a subnet
  community.proxmox.proxmox_subnet:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    vnet: test
    subnet: 10.10.2.0/24
    zone: ans1
    state: absent
"""

RETURN = r"""
subnet:
  description:
    - Subnet ID which was created/updated/deleted
  returned: on success
  type: str
  sample:
    ans1-10.10.2.0-24
"""

import copy
from ipaddress import IPv4Address
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox_sdn import ProxmoxSdnAnsible
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec,
    ansible_to_proxmox_bool,
    compare_list_of_dicts

)


def get_proxmox_args():
    return dict(
        state=dict(type="str", choices=["present", "absent"], default='present', required=False),
        update=dict(type="bool", default=True),
        subnet=dict(type="str", required=True),
        vnet=dict(type="str", required=True),
        zone=dict(type="str", required=False),
        dhcp_dns_server=dict(type="str", required=False),
        dhcp_range_update_mode=dict(type='str', choices=['append', 'overwrite'], default='append'),
        dhcp_range=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                start=dict(type='str', required=True),
                end=dict(type='str', required=True)
            )
        ),
        dnszoneprefix=dict(type='str', required=False),
        gateway=dict(type='str', required=False),
        lock_token=dict(type="str", required=False, no_log=False),
        snat=dict(type='bool', default=False, required=False),
        delete=dict(type="str", required=False)
    )


def get_ansible_module():
    module_args = proxmox_auth_argument_spec()
    module_args.update(get_proxmox_args())

    return AnsibleModule(
        argument_spec=module_args,
        required_if=[
            ('state', 'present', ['subnet', 'vnet', 'zone']),
            ('state', 'absent', ['zone', 'vnet', 'subnet']),
        ]
    )


def get_dhcp_range(dhcp_range=None):
    if not dhcp_range:
        return None

    def extract(item):
        start = item.get('start-address') or item.get('start')
        end = item.get('end-address') or item.get('end')
        return f"start-address={start},end-address={end}"

    return [extract(x) for x in dhcp_range]


def compare_dhcp_ranges(existing_ranges, new_ranges):
    def to_tuple(r):
        return int(IPv4Address(r['start-address'])), int(IPv4Address(r['end-address']))

    existing_intervals = [to_tuple(r) for r in existing_ranges]

    new_dhcp_ranges = []
    partial_overlap = False

    for dhcp_range in new_ranges:
        tuple_dhcp_range = to_tuple(dhcp_range)
        if tuple_dhcp_range not in existing_intervals:
            new_dhcp_ranges.append(dhcp_range)
        for (start, end) in existing_intervals:
            if not (tuple_dhcp_range[1] < start or tuple_dhcp_range[0] > end):
                if tuple_dhcp_range != (start, end):
                    partial_overlap = True
    return new_dhcp_ranges, partial_overlap


class ProxmoxSubnetAnsible(ProxmoxSdnAnsible):
    def __init__(self, module):
        super(ProxmoxSubnetAnsible, self).__init__(module)
        self.params = module.params

    def run(self):
        state = self.params.get("state")
        update = self.params.get("update")

        subnet_params = {
            'subnet': self.params.get('subnet'),
            'type': 'subnet',
            'vnet': self.params.get('vnet'),
            'dhcp-dns-server': self.params.get('dhcp_dns_server'),
            'dhcp-range': get_dhcp_range(dhcp_range=self.params.get('dhcp_range')),
            'dnszoneprefix': self.params.get('dnszoneprefix'),
            'gateway': self.params.get('gateway'),
            'lock-token': None,
            'snat': ansible_to_proxmox_bool(self.params.get('snat'))
        }

        if state == 'present':
            self.subnet_present(**subnet_params)
        elif state == 'absent':
            self.subnet_absent(**subnet_params)

    def get_subnets(self, vnet_name):
        try:
            return self.proxmox_api.cluster().sdn().vnets(vnet_name).subnets().get()
        except Exception as e:
            self.module.fail_json(f'Failed to retrieve subnets {e}')

    def update_subnet(self, **subnet_params):
        new_subnet = copy.deepcopy(subnet_params)
        subnet_id = f"{self.params['zone']}-{new_subnet['subnet'].replace('/', '-')}"
        vnet_name = new_subnet['vnet']
        dhcp_range_update_mode = self.params.get('dhcp_range_update_mode')

        new_subnet['cidr'] = new_subnet['subnet']
        new_subnet['network'] = new_subnet['subnet'].split('/')[0]
        new_subnet['mask'] = new_subnet['subnet'].split('/')[1]
        new_subnet['zone'] = self.params.get('zone')
        new_subnet['id'] = subnet_id
        new_subnet['subnet'] = subnet_id

        subnet_params['delete'] = self.params.get('delete')

        existing_subnets = self.get_subnets(vnet_name)

        # Check for subnet params other than dhcp-range
        x, subnet_update = compare_list_of_dicts(
            existing_list=existing_subnets,
            new_list=[new_subnet],
            uid='id',
            params_to_ignore=['digest', 'dhcp-range', 'lock-token']
        )

        existing_subnet = [x for x in existing_subnets if x['subnet'] == subnet_id][0]

        # Check dhcp-range
        update_dhcp = False
        if self.params.get('dhcp_range'):
            new_dhcp_range = [
                {'start-address': d.get('start'), 'end-address': d.get('end')}
                for d in self.params.get('dhcp_range')
            ]
            new_dhcp, partial_overlap = compare_dhcp_ranges(
                existing_ranges=existing_subnet['dhcp-range'],
                new_ranges=new_dhcp_range
            )

            if dhcp_range_update_mode == 'append':
                if partial_overlap:
                    self.module.fail_json(
                        msg="There are partially overlapping DHCP ranges. this is not allowed."
                    )

                if len(new_dhcp) > 0:
                    update_dhcp = True
                    new_dhcp.extend(existing_subnet['dhcp-range'])  # By Default API overwrites DHCP Range
                    subnet_params['dhcp-range'] = get_dhcp_range(new_dhcp)

            elif dhcp_range_update_mode == 'overwrite' and new_dhcp:
                update_dhcp = True

        elif not self.params.get('dhcp_range') and existing_subnet['dhcp-range']:
            if dhcp_range_update_mode == 'append':
                self.module.warn(
                    "dhcp_range_update_mode is set to append, but you didn't provide any DHCP ranges for the subnet. "
                    "Existing ranges will be ignored."
                )

            elif dhcp_range_update_mode == 'overwrite':
                update_dhcp = True
                self.module.warn(
                    "dhcp_range_update_mode is set to overwrite, but no DHCP ranges were provided for the subnet. "
                    "All existing DHCP ranges will be deleted."
                )
                if self.params.get('delete'):
                    subnet_params['delete'] = f"{subnet_params['delete']},dhcp-range"
                else:
                    subnet_params['delete'] = "dhcp-range"

        if subnet_update or update_dhcp:
            self.module.warn(f"{subnet_params}, {update_dhcp}")
            if self.params.get('update'):
                try:
                    subnet_params['lock-token'] = self.get_global_sdn_lock()
                    subnet = getattr(self.proxmox_api.cluster().sdn().vnets(vnet_name).subnets(), subnet_id)
                    subnet_params['digest'] = subnet.get()['digest']
                    del subnet_params['type']
                    del subnet_params['subnet']

                    subnet.put(**subnet_params)
                    self.apply_sdn_changes_and_release_lock(lock=subnet_params['lock-token'])
                    self.module.exit_json(
                        changed=True, subnet=subnet_id, msg=f'Updated subnet {subnet_id}'
                    )
                except Exception as e:
                    self.rollback_sdn_changes_and_release_lock(lock=subnet_params['lock-token'])
                    self.module.fail_json(
                        msg=f'Failed to update subnet. Rolling back all changes : {e}'
                    )
            else:
                self.module.fail_json(
                    msg=f"Subnet {subnet_id} needs to be updated but update is false."
                )
        else:
            self.module.exit_json(
                changed=False,
                subnet=subnet_id,
                msg=f'subnet {subnet_id} is already present with correct parameters.'
            )

    def subnet_present(self, **subnet_params):
        vnet_name = subnet_params['vnet']
        subnet_cidr = subnet_params['subnet']
        subnet_id = f"{self.params['zone']}-{subnet_params['subnet'].replace('/', '-')}"

        try:
            existing_subnets = self.get_subnets(vnet_name)

            # Check if subnet already present
            if subnet_id in [x['subnet'] for x in existing_subnets]:
                self.update_subnet(**subnet_params)
            else:
                subnet_params['lock-token'] = self.get_global_sdn_lock()
                self.proxmox_api.cluster().sdn().vnets(vnet_name).subnets().post(**subnet_params)
                self.apply_sdn_changes_and_release_lock(lock=subnet_params['lock-token'])
                self.module.exit_json(
                    changed=True, subnet=subnet_id, msg=f'Created new subnet {subnet_cidr}'
                )
        except Exception as e:
            self.rollback_sdn_changes_and_release_lock(lock=subnet_params['lock-token'])
            self.module.fail_json(
                msg=f'Failed to create subnet. Rolling back all changes : {e}'
            )

    def subnet_absent(self, **subnet_params):
        vnet_name = subnet_params['vnet']
        subnet_id = f"{self.params['zone']}-{subnet_params['subnet'].replace('/', '-')}"

        params = {
            'subnet': subnet_id,
            'vnet': vnet_name,
            'lock-token': None
        }

        existing_subnets = self.get_subnets(vnet_name)
        try:
            # Check if subnet already present
            if subnet_id in [x['subnet'] for x in existing_subnets]:
                params['lock-token'] = self.get_global_sdn_lock()
                self.proxmox_api.cluster().sdn().vnets(vnet_name).subnets(subnet_id).delete(**params)
                self.apply_sdn_changes_and_release_lock(lock=params['lock-token'])
                self.module.exit_json(
                    changed=True, subnet=subnet_id, msg=f'Deleted subnet {subnet_id}'
                )
            else:
                self.module.exit_json(
                    changed=False, subnet=subnet_id, msg=f'subnet {subnet_id} already not present.'
                )
        except Exception as e:
            self.rollback_sdn_changes_and_release_lock(lock=params['lock-token'])
            self.module.fail_json(
                msg=f'Failed to delete subnet. Rolling back all changes. : {e}'
            )


def main():
    module = get_ansible_module()
    proxmox = ProxmoxSubnetAnsible(module)

    try:
        proxmox.run()
    except Exception as e:
        module.fail_json(msg=f'An error occurred: {e}')


if __name__ == "__main__":
    main()
