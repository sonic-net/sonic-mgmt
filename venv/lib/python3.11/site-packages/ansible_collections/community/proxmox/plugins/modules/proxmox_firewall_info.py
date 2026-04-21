#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_firewall_info
short_description: Manage firewall rules in Proxmox
version_added: "1.4.0"
description:
    - Get firewall rules at cluster/group/vnet/node/vm level.
    - Get firewall security groups at cluster level.
    - Get aliases at cluster/VM level.
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
options:
  level:
    description:
      - Level at which the firewall rule applies.
    type: str
    choices:
      - cluster
      - group
      - vnet
      - node
      - vm
    default: cluster
  node:
    description:
      - Name of the node.
      - Only needed when O(level=node).
    type: str
  vmid:
    description:
      - ID of the VM to which the rule applies.
      - Only needed when O(level=vm).
    type: int
  vnet:
    description:
      - Name of the virtual network for the rule.
      - Only needed when O(level=vnet).
    type: str
  pos:
    description:
      - Position of the rule in the list.
    type: int
  group:
    description:
      - Name of the group to which the rule belongs.
      - Only needed when O(level=group).
    type: str
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
  - community.proxmox.attributes.info_module
"""

EXAMPLES = r"""
- name: Get Cluster level firewall rules, aliases, and security groups
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    level: cluster
"""

RETURN = r"""
groups:
    description:
      - List of firewall security groups.
      - This will always be given for cluster level regardless of the level passed.
      - Because only at cluster level we can have firewall security groups.
    returned: on success
    type: list
    elements: str
    sample:
      [ "test" ]

ip_sets:
    description:
      - List of IP Sets.
      - These are only supported on the O(level) = cluster, other inputs are ignored.
    returned: on success
    type: list
    elements: dict
    sample:
          [
                {
                    "cidrs": [],
                    "digest": "8c4a5e793355b2a877659315faaa78cbd0bc9f6c",
                    "name": "emptytest"
                },
                {
                    "cidrs": [
                        {
                            "cidr": "192.168.1.10",
                            "comment": "Proxmox pve-01",
                            "digest": "ed830373d096f6b9f868e59c6182e0b2042e6bad",
                            "nomatch": false
                        },
                        {
                            "cidr": "192.168.1.11",
                            "comment": "Proxmox pve-02",
                            "digest": "ed830373d096f6b9f868e59c6182e0b2042e6bad",
                            "nomatch": true
                        }
                    ],
                    "comment": "PVE hosts",
                    "digest": "8c4a5e793355b2a877659315faaa78cbd0bc9f6c",
                    "name": "hypervisors"
                },
                {
                    "cidrs": [
                        {
                            "cidr": "10.10.1.0",
                            "comment": "Proxmox pve-01",
                            "digest": "f15cef67632375227d849ee0a449d845ab136677",
                            "nomatch": false
                        }
                    ],
                    "comment": "PVE hosts",
                    "digest": "8c4a5e793355b2a877659315faaa78cbd0bc9f6c",
                    "name": "test"
                }
          ]

aliases:
    description:
      - List of alias present at given level.
      - Aliases are only available for cluster and VM level so if any other level it'll be empty list.
    returned: on success
    type: list
    elements: dict
    sample:
        [
            {
                "cidr": "10.10.1.0/24",
                "digest": "978391f460484e8d4fb3ca785cfe5a9d16fe8b1f",
                "ipversion": 4,
                "name": "test1"
            },
            {
                "cidr": "10.10.2.0/24",
                "digest": "978391f460484e8d4fb3ca785cfe5a9d16fe8b1f",
                "ipversion": 4,
                "name": "test2"
            },
            {
                "cidr": "10.10.3.0/24",
                "digest": "978391f460484e8d4fb3ca785cfe5a9d16fe8b1f",
                "ipversion": 4,
                "name": "test3"
            }
        ]

firewall_rules:
    description: List of firewall rules at given level.
    returned: on success
    type: list
    elements: dict
    sample:
      [
        {
            "action": "ACCEPT",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "dport": "53",
            "enable": 1,
            "ipversion": 4,
            "log": "nolog",
            "pos": 0,
            "proto": "udp",
            "source": "192.168.1.0/24",
            "type": "in"
        },
        {
            "action": "ACCEPT",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "dport": "53",
            "enable": 1,
            "ipversion": 4,
            "log": "nolog",
            "pos": 1,
            "proto": "tcp",
            "source": "192.168.1.0/24",
            "type": "in"
        },
        {
            "action": "ACCEPT",
            "dest": "192.168.1.0/24",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "enable": 1,
            "ipversion": 4,
            "log": "nolog",
            "pos": 2,
            "type": "out"
        },
        {
            "action": "ACCEPT",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "enable": 1,
            "ipversion": 4,
            "log": "nolog",
            "pos": 3,
            "source": "192.168.1.0/24",
            "type": "in"
        },
        {
            "action": "ACCEPT",
            "dest": "+sdn/test2-gateway",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "enable": 1,
            "iface": "test2",
            "log": "nolog",
            "macro": "DNS",
            "pos": 4,
            "type": "in"
        },
        {
            "action": "ACCEPT",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "enable": 1,
            "iface": "test2",
            "log": "nolog",
            "macro": "DHCPfwd",
            "pos": 5,
            "type": "in"
        },
        {
            "action": "ACCEPT",
            "dest": "+sdn/test2-all",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "dport": "68",
            "enable": 1,
            "log": "nolog",
            "pos": 6,
            "proto": "udp",
            "source": "+sdn/test2-gateway",
            "sport": "67",
            "type": "out"
        },
        {
            "action": "DROP",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "enable": 1,
            "log": "nolog",
            "pos": 7,
            "type": "in"
        },
        {
            "action": "DROP",
            "digest": "b5ddaed23b415b9368706fc9edc83d037526aae9",
            "enable": 1,
            "log": "nolog",
            "pos": 8,
            "type": "out"
        }
      ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox_sdn import ProxmoxSdnAnsible
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import proxmox_auth_argument_spec


def get_proxmox_args():
    return dict(
        level=dict(type="str", choices=["cluster", "node", "vm", "vnet", "group"], default="cluster", required=False),
        node=dict(type="str", required=False),
        vmid=dict(type="int", required=False),
        vnet=dict(type="str", required=False),
        group=dict(type="str", required=False),
        pos=dict(type="int", required=False),
    )


def get_ansible_module():
    module_args = proxmox_auth_argument_spec()
    module_args.update(get_proxmox_args())

    return AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('level', 'vm', ['vmid']),
            ('level', 'node', ['node']),
            ('level', 'vnet', ['vnet']),
            ('level', 'group', ['group']),
        ]
    )


class ProxmoxFirewallInfoAnsible(ProxmoxSdnAnsible):
    def __init__(self, module):
        super(ProxmoxFirewallInfoAnsible, self).__init__(module)
        self.params = module.params

    def run(self):
        level = self.params.get("level")

        if level == "vm":
            vm = self.get_vm(vmid=self.params.get('vmid'))
            node = self.proxmox_api.nodes(vm['node'])
            virt = node(vm['type'])
            firewall_obj = virt(str(vm['vmid'])).firewall
            rules_obj = firewall_obj().rules

        elif level == "node":
            firewall_obj = self.proxmox_api.nodes(self.params.get('node')).firewall
            rules_obj = firewall_obj().rules

        elif level == "vnet":
            firewall_obj = self.proxmox_api.cluster().sdn().vnets(self.params.get('vnet')).firewall
            rules_obj = firewall_obj().rules

        elif level == "group":
            firewall_obj = None
            rules_obj = self.proxmox_api.cluster().firewall().groups(self.params.get("group"))

        else:
            firewall_obj = self.proxmox_api.cluster().firewall
            rules_obj = firewall_obj().rules

        rules = self.get_fw_rules(rules_obj, pos=self.params.get('pos'))
        groups = self.get_groups()
        aliases = self.get_aliases(firewall_obj=firewall_obj)
        ip_sets = self.get_ip_sets()
        self.module.exit_json(
            changed=False,
            firewall_rules=rules,
            groups=groups,
            aliases=aliases,
            ip_sets=ip_sets,
            msg='successfully retrieved firewall rules and groups'
        )


def main():
    module = get_ansible_module()
    proxmox = ProxmoxFirewallInfoAnsible(module)

    try:
        proxmox.run()
    except Exception as e:
        module.fail_json(msg=f'An error occurred: {e}')


if __name__ == "__main__":
    main()
