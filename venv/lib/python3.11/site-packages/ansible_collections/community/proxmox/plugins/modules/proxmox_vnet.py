#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_vnet
short_description: Manage virtual networks in Proxmox SDN.
version_added: "1.4.0"
description:
  - Create, update, or delete virtual networks in Proxmox SDN.
  - Configure network isolation, VLAN awareness, and other network settings.
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
options:
  state:
    description:
      - Desired state of the virtual network.
    type: str
    choices: ['present', 'absent']
    default: present
  update:
    description:
      - If O(state=present) then it will update the vnet if needed.
    type: bool
    default: True
  vnet:
    description:
      - The name of the virtual network to be managed.
    type: str
  zone:
    description:
      - zone for the virtual network.
    type: str
  alias:
    description:
      - An optional alias for the virtual network.
    type: str
  isolate_ports:
    description:
      - Enable isolation of ports within the virtual network.
    type: bool
    default: False
  lock_token:
    description:
      - The token for unlocking the global SDN configuration.
    type: str
  tag:
    description:
      - Tag for the virtual network.
    type: int
  vlanaware:
    description:
      - Enable VLAN awareness for the virtual network.
    type: bool
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
- name: Create a vnet
  community.proxmox.proxmox_vnet:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    vnet: anstest
    zone: ans1
    state: present

- name: Update a vnet
  community.proxmox.proxmox_vnet:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    vnet: anstest
    zone: ans1
    alias: anst
    state: present
    update: true

- name: Delete a vnet
  community.proxmox.proxmox_vnet:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    vnet: anstest
    zone: ans1
    state: absent
"""

RETURN = r"""
vnet:
  description:
    - vnet name which was created/updated/deleted.
  returned: on success
  type: str
  sample:
    anstest
"""

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
        update=dict(type="bool", default=True, required=False),
        vnet=dict(type="str", required=False),
        zone=dict(type="str", required=False),
        alias=dict(type="str", required=False),
        isolate_ports=dict(type="bool", default=False, required=False),
        lock_token=dict(type="str", required=False, no_log=False),
        tag=dict(type="int", required=False),
        vlanaware=dict(type="bool", required=False),
        delete=dict(type="str", required=False)
    )


def get_ansible_module():
    module_args = proxmox_auth_argument_spec()
    module_args.update(get_proxmox_args())

    return AnsibleModule(
        argument_spec=module_args,
        required_if=[
            ('state', 'present', ['vnet', 'zone']),
            ('state', 'absent', ['vnet'])
        ]
    )


class ProxmoxVnetAnsible(ProxmoxSdnAnsible):
    def __init__(self, module):
        super(ProxmoxVnetAnsible, self).__init__(module)
        self.params = module.params

    def run(self):
        state = self.params.get("state")
        update = self.params.get("update")

        vnet_params = {
            'vnet': self.params.get('vnet'),
            'zone': self.params.get('zone'),
            'alias': self.params.get('alias'),
            'isolate-ports': ansible_to_proxmox_bool(self.params.get('isolate_ports')),
            'lock-token': None,
            'tag': self.params.get('tag'),
            'type': 'vnet',
            'vlanaware': ansible_to_proxmox_bool(self.params.get('vlanaware'))
        }

        if state == 'present':
            self.vnet_present(update=update, vnet_params=vnet_params)
        elif state == 'absent':
            self.vnet_absent(vnet_params['vnet'])

    def get_vnet_detail(self):
        try:
            return self.proxmox_api.cluster().sdn().vnets().get()
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve vnet information from cluster: {e}'
            )

    def vnet_present(self, update, vnet_params):
        vnet_name = vnet_params['vnet']
        existing_vnet = [vnet for vnet in self.get_vnet_detail() if vnet.get('vnet') == vnet_name]
        vnet_to_create, vnet_to_update = compare_list_of_dicts(
            existing_list=existing_vnet,
            new_list=[vnet_params],
            uid='vnet',
            params_to_ignore=['digest', 'lock-token']
        )

        # Check if vnet needs to be updated
        if len(vnet_to_update) > 0:
            if update:
                vnet_params['lock-token'] = self.get_global_sdn_lock()
                vnet_params['digest'] = existing_vnet[0]['digest']
                vnet_params['delete'] = self.params.get('delete')
                del vnet_params['type']

                try:
                    self.proxmox_api.cluster().sdn().vnets(vnet_name).put(**vnet_params)
                    self.apply_sdn_changes_and_release_lock(vnet_params['lock-token'])
                    self.module.exit_json(
                        changed=True, vnet=vnet_name, msg=f'updated vnet {vnet_name}'
                    )
                except Exception as e:
                    self.module.warn(f'Failed to update vnet - {e}')
                    self.rollback_sdn_changes_and_release_lock(vnet_params['lock-token'])
                    self.module.fail_json(
                        msg=f'Failed to update vnet - {e}. Rolling back all changes.'
                    )
            else:
                self.module.fail_json(
                    msg=f'vnet {vnet_name} needs to be updated but update is false.'
                )
        elif len(vnet_to_create) > 0:
            try:
                vnet_params['lock-token'] = self.get_global_sdn_lock()
                self.proxmox_api.cluster().sdn().vnets().post(**vnet_params)
                self.apply_sdn_changes_and_release_lock(vnet_params['lock-token'])
                self.module.exit_json(
                    changed=True, vnet=vnet_name, msg=f'Create new vnet {vnet_name}'
                )
            except Exception as e:
                self.module.warn(f'Failed to create vnet - {e}')
                self.rollback_sdn_changes_and_release_lock(vnet_params['lock-token'])
                self.module.fail_json(
                    msg=f'Failed to create vnet - {e}. Rolling back all changes.'
                )
        else:
            self.module.exit_json(
                changed=False,
                vnet=vnet_name,
                msg=f'vnet {vnet_name} is already in desired state.'
            )

    def vnet_absent(self, vnet_name):
        available_vnets = [vnet['vnet'] for vnet in self.get_vnet_detail()]

        if vnet_name not in available_vnets:
            self.module.exit_json(
                changed=False, vnet=vnet_name, msg=f"vnet already doesn't exist  {vnet_name}"
            )
        else:
            vnet_params = {
                'vnet': vnet_name,
                'lock-token': self.get_global_sdn_lock()
            }
            try:
                self.proxmox_api.cluster().sdn().vnets(vnet_name).delete(**vnet_params)
                self.apply_sdn_changes_and_release_lock(vnet_params['lock-token'])
                self.module.exit_json(
                    changed=True, vnet=vnet_name, msg=f'Deleted vnet {vnet_name}'
                )
            except Exception as e:
                self.module.warn(f'Failed to update vnet - {e}')
                self.rollback_sdn_changes_and_release_lock(vnet_params['lock-token'])
                self.module.fail_json(
                    msg=f'Failed to delete vnet. Rolling back all changes - {e}'
                )


def main():
    module = get_ansible_module()
    proxmox = ProxmoxVnetAnsible(module)

    try:
        proxmox.run()
    except Exception as e:
        module.fail_json(msg=f'An error occurred: {e}')


if __name__ == "__main__":
    main()
