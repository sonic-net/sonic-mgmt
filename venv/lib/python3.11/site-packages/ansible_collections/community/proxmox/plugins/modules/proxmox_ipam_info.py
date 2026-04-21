#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_ipam_info
short_description: Retrieve information about IPAMs.
version_added: "1.4.0"
description:
  - Retrieve all IPs under IPAM and limit it by IP or IPAM.
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
options:
  ipam:
    description:
      - Limit results to a single IPAM.
    type: str
  vmid:
    description:
      - Get IP of a VM under IPAM.
    type: int

extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
  - community.proxmox.attributes.info_module
"""

EXAMPLES = r"""
- name: Get all IPs under all IPAM
  community.proxmox.proxmox_ipam_info:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false

- name: Get all IPs under pve IPAM
  community.proxmox.proxmox_ipam_info:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    ipam: pve

- name: Get IP under IPAM of vmid 102
  community.proxmox.proxmox_ipam_info:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    vmid: 102
"""

RETURN = r"""
ips:
  description: Filter by vmid
  returned: on success
  type: list
  elements: dict
  sample:
     [
        {
            "hostname": "ns3.proxmox.pc",
            "ip": "10.10.5.5",
            "mac": "BC:24:11:0E:72:04",
            "subnet": "10.10.5.0/24",
            "vmid": 102,
            "vnet": "test",
            "zone": "ans1"
        },
        {
            "hostname": "ns3.proxmox.pc",
            "ip": "10.10.0.8",
            "mac": "BC:24:11:F3:B1:81",
            "subnet": "10.10.0.0/24",
            "vmid": 102,
            "vnet": "test2",
            "zone": "test1"
        }
    ]
ipams:
  description: List of all IPAMs and IPs under them.
  returned: on success
  type: dict
  elements: dict
  sample:
    {
        "pve": [
            {
                "gateway": 1,
                "ip": "10.10.1.0",
                "subnet": "10.10.1.0/24",
                "vnet": "test2",
                "zone": "test1"
            },
            {
                "hostname": "ns3.proxmox.pc.test3",
                "ip": "10.10.0.6",
                "mac": "BC:24:11:0E:72:04",
                "subnet": "10.10.0.0/24",
                "vmid": 102,
                "vnet": "test2",
                "zone": "test1"
            },
            {
                "hostname": "ns4.proxmox.pc",
                "ip": "10.10.0.7",
                "mac": "BC:24:11:D5:CD:82",
                "subnet": "10.10.0.0/24",
                "vmid": 103,
                "vnet": "test2",
                "zone": "test1"
            },
            {
                "gateway": 1,
                "ip": "10.10.0.1",
                "subnet": "10.10.0.0/24",
                "vnet": "test2",
                "zone": "test1"
            },
            {
                "hostname": "ns2.proxmox.pc.test3",
                "ip": "10.10.0.5",
                "mac": "BC:24:11:86:77:56",
                "subnet": "10.10.0.0/24",
                "vmid": 101,
                "vnet": "test2",
                "zone": "test1"
            }
        ]
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec,
    ProxmoxAnsible
)


def get_proxmox_args():
    return dict(
        ipam=dict(type="str", required=False),
        vmid=dict(type='int', required=False)
    )


def get_ansible_module():
    module_args = proxmox_auth_argument_spec()
    module_args.update(get_proxmox_args())
    return AnsibleModule(argument_spec=module_args, supports_check_mode=True)


class ProxmoxIpamInfoAnsible(ProxmoxAnsible):
    def __init__(self, module):
        super(ProxmoxIpamInfoAnsible, self).__init__(module)
        self.params = module.params

    def run(self):
        vmid = self.params.get('vmid')
        ipam = self.params.get('ipam')
        if vmid:
            self.module.exit_json(
                changed=False, ips=self.get_ip_by_vmid(vmid)
            )

        elif self.params.get('ipam'):
            if ipam not in self.get_ipams():
                self.module.fail_json(
                    msg=f'IPAM {ipam} is not present'
                )
            else:
                self.module.exit_json(
                    changed=False,
                    ipams=self.get_ipam_status()[ipam]
                )
        else:
            self.module.exit_json(
                changed=False,
                ipams=self.get_ipam_status()
            )

    def get_ipams(self):
        try:
            ipams = self.proxmox_api.cluster().sdn().ipams().get()
            return [ipam['ipam'] for ipam in ipams]
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve IPAM information {e}'
            )

    def get_ipam_status(self):
        try:
            ipam_status = dict()
            ipams = self.get_ipams()
            for ipam_id in ipams:
                ipam_status[ipam_id] = self.proxmox_api.cluster().sdn().ipams(ipam_id).status().get()
            return ipam_status
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve IPAM status {e}'
            )

    def get_ip_by_vmid(self, vmid):
        ipam_status = self.get_ipam_status()
        ips = []
        for ipam in ipam_status.values():
            for item in ipam:
                if item.get('vmid') == vmid:
                    ips.append(item)
        return ips


def main():
    module = get_ansible_module()
    proxmox = ProxmoxIpamInfoAnsible(module)

    try:
        proxmox.run()
    except Exception as e:
        module.fail_json(msg=f'An error occurred: {e}')


if __name__ == "__main__":
    main()
