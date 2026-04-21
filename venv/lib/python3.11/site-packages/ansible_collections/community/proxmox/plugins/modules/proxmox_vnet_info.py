#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_vnet_info
short_description: Retrieve information about one or more Proxmox VE SDN vnets.
version_added: "1.4.0"
description:
  - Retrieve information about one or more Proxmox VE SDN vnets.
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
options:
  vnet:
    description:
      - Restrict results to a specific vnet.
    type: str

extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
  - community.proxmox.attributes.info_module
"""

EXAMPLES = r"""
- name: Get all vnet details
  community.proxmox.proxmox_vnet_info:
    api_user: "{{ proxmox.api_user }}"
    api_token_id: "{{ proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ proxmox.api_host }}"
    validate_certs: false

- name: Get details for vnet - test
  community.proxmox.proxmox_vnet_info:
    api_user: "{{ proxmox.api_user }}"
    api_token_id: "{{ proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ proxmox.api_host }}"
    vnet: test
    validate_certs: false
"""

RETURN = r"""
vnets:
    description: List of vnets.
    returned: on success
    type: list
    elements: dict
    sample:
      [
        {
          "digest": "01505201eb33919888fb0cacba27d3aae803f6d2",
          "firewall_rules": [],
          "subnets": [
            {
              "cidr": "10.10.100.0/24",
              "dhcp-range": [],
              "digest": "47684c511d9b67e8eb41b93bc5c0b078786b0ee3",
              "id": "lab-10.10.100.0-24",
              "mask": "24",
              "network": "10.10.100.0",
              "snat": 1,
              "subnet": "lab-10.10.100.0-24",
              "type": "subnet",
              "vnet": "lab",
              "zone": "lab"
            }
          ],
          "tag": 100,
          "type": "vnet",
          "vnet": "lab",
          "zone": "lab"
        },
        {
          "digest": "01505201eb33919888fb0cacba27d3aae803f6d2",
          "firewall_rules": [
            {
              "action": "ACCEPT",
              "dest": "+sdn/test2-gateway",
              "digest": "36016a02a5387d4c1171d29be966d550216bc500",
              "enable": 1,
              "log": "nolog",
              "macro": "DNS",
              "pos": 0,
              "type": "forward"
            },
            {
              "action": "ACCEPT",
              "digest": "36016a02a5387d4c1171d29be966d550216bc500",
              "enable": 1,
              "log": "nolog",
              "macro": "DHCPfwd",
              "pos": 1,
              "type": "forward"
            }
          ],
          "subnets": [
            {
              "cidr": "10.10.0.0/24",
              "dhcp-range": [
                {
                  "end-address": "10.10.0.50",
                  "start-address": "10.10.0.5"
                }
              ],
              "digest": "47684c511d9b67e8eb41b93bc5c0b078786b0ee3",
              "gateway": "10.10.0.1",
              "id": "test1-10.10.0.0-24",
              "mask": "24",
              "network": "10.10.0.0",
              "subnet": "test1-10.10.0.0-24",
              "type": "subnet",
              "vnet": "test2",
              "zone": "test1"
            },
            {
              "cidr": "10.10.1.0/24",
              "dhcp-range": [
                {
                  "end-address": "10.10.1.50",
                  "start-address": "10.10.1.5"
                }
              ],
              "digest": "47684c511d9b67e8eb41b93bc5c0b078786b0ee3",
              "gateway": "10.10.1.0",
              "id": "test1-10.10.1.0-24",
              "mask": "24",
              "network": "10.10.1.0",
              "subnet": "test1-10.10.1.0-24",
              "type": "subnet",
              "vnet": "test2",
              "zone": "test1"
            }
          ],
          "type": "vnet",
          "vnet": "test2",
          "zone": "test1"
        }
      ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec,
    ProxmoxAnsible
)


class ProxmoxVnetInfoAnsible(ProxmoxAnsible):
    def get_subnets(self, vnet):
        try:
            return self.proxmox_api.cluster().sdn().vnets(vnet).subnets().get()
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve subnet information from vnet {vnet}: {e}'
            )

    def get_firewall(self, vnet_name):
        try:
            return self.proxmox_api.cluster().sdn().vnets(vnet_name).firewall().rules().get()
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve subnet information from vnet {vnet_name}: {e}'
            )

    def get_vnet_detail(self):
        try:
            vnets = self.proxmox_api.cluster().sdn().vnets().get()
            for vnet in vnets:
                vnet['subnets'] = self.get_subnets(vnet['vnet'])
                vnet['firewall_rules'] = self.get_firewall(vnet['vnet'])
            return vnets
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve vnet information from cluster: {e}'
            )


def main():
    module_args = proxmox_auth_argument_spec()
    vnet_info_args = dict(
        vnet=dict(type="str", required=False)
    )
    module_args.update(vnet_info_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_together=[("api_token_id", "api_token_secret")],
        required_one_of=[("api_password", "api_token_id")],
        supports_check_mode=True,
    )

    proxmox = ProxmoxVnetInfoAnsible(module)
    vnet = module.params['vnet']
    vnets = proxmox.get_vnet_detail()

    if vnet:
        vnets = [vnet_details for vnet_details in vnets if vnet_details['vnet'] == vnet]

    module.exit_json(
        changed=False,
        vnets=vnets,
        msg='Successfully retrieved vnet info'
    )


if __name__ == "__main__":
    main()
