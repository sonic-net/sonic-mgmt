#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_zone
short_description: Manage Proxmox zone configurations.
description:
  - Create/Update/Delete proxmox sdn zones.
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
version_added: "1.4.0"
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
options:
    advertise_subnets:
      description:
        - Advertise EVPN subnets if you have silent hosts.
      type: bool
    bridge:
      description:
        - Specify the bridge interface to use.
      type: str
    bridge_disable_mac_learning:
      description:
        - Disable auto MAC address learning on the bridge interface.
      type: bool
    controller:
      description:
        - FRR router name.
      type: str
    dhcp:
      description:
        - Type of the DHCP backend for this zone.
      type: str
      choices:
        - dnsmasq
    disable_arp_nd_suppression:
      description:
        - Disable IPv4 ARP and IPv6 neighbour discovery suppression.
      type: bool
    dns:
      description:
        - DNS API server.
      type: str
    dnszone:
      description:
        - DNS domain zone.
      type: str
    dp_id:
      description:
        - Faucet dataplane ID.
      type: int
    exitnodes:
      description:
        - List of cluster node names.
      type: str
    exitnodes_local_routing:
      description:
        - Allow exitnodes to connect to EVPN guests.
      type: bool
    exitnodes_primary:
      description:
        - Force traffic to this exit node first.
      type: str
    fabric:
      description:
        - SDN fabric to use as underlay for this VXLAN zone.
      type: str
    ipam:
      description:
        - Use a specific IPAM.
      type: str
    mac:
      description:
        - Anycast logical router MAC address.
      type: str
    mtu:
      description:
        - Set the Maximum Transmission Unit (MTU).
      type: int
    nodes:
      description:
        - List of cluster node names.
      type: str
    peers:
      description:
        - Peers address list.
      type: str
    reversedns:
      description:
        - Reverse DNS API server.
      type: str
    rt_import:
      description:
        - Route-Target import.
      type: str
    state:
      description:
        - The desired state of the zone configuration.
      type: str
      choices:
        - present
        - absent
      default: present
    tag:
      description:
        - Service-VLAN tag.
      type: int
    type:
      description:
        - Specify the type of zone.
      type: str
      choices:
        - evpn
        - faucet
        - qinq
        - simple
        - vlan
        - vxlan
    update:
      description:
        - If O(state=present) and zone exists it'll update.
      type: bool
      default: true
    vlan_protocol:
      description:
        - Specify the VLAN protocol to use.
      type: str
      choices:
        - 802.1q
        - 802.1ad
    vrf_vxlan:
      description:
        - Specify the VRF VXLAN identifier.
      type: int
    vxlan_port:
      description:
        - VXLAN tunnel UDP port (default 4789).
      type: int
    zone:
      description:
        - Unique zone name.
      type: str
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Create a simple zone
  community.proxmox.proxmox_zone:
    api_user: "root@pam"
    api_password: "{{ vault.proxmox.root_password }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    type: simple
    zone: ansible
    state: present

- name: Create a vlan zone
  community.proxmox.proxmox_zone:
    api_user: "root@pam"
    api_password: "{{ vault.proxmox.root_password }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    type: vlan
    zone: ansible
    state: present
    bridge: vmbr0

- name: Delete a zone
  community.proxmox.proxmox_zone:
    api_user: "root@pam"
    api_password: "{{ vault.proxmox.root_password }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    type: simple
    zone: ansible
    state: absent
"""

RETURN = r"""
zone:
    description:
      - Name of the zone which was created/updated/deleted
    returned: on success
    type: str
    sample:
      test
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox_sdn import ProxmoxSdnAnsible
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec,
    ansible_to_proxmox_bool
)


def get_proxmox_args():
    return dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        update=dict(type="bool", default=True),
        type=dict(type="str",
                  choices=["evpn", "faucet", "qinq", "simple", "vlan", "vxlan"],
                  required=False),
        zone=dict(type="str", required=False),
        advertise_subnets=dict(type="bool", required=False),
        bridge=dict(type="str", required=False),
        bridge_disable_mac_learning=dict(type="bool", required=False),
        controller=dict(type="str", required=False),
        dhcp=dict(type="str", choices=["dnsmasq"], required=False),
        disable_arp_nd_suppression=dict(type="bool", required=False),
        dns=dict(type="str", required=False),
        dnszone=dict(type="str", required=False),
        dp_id=dict(type="int", required=False),
        exitnodes=dict(type="str", required=False),
        exitnodes_local_routing=dict(type="bool", required=False),
        exitnodes_primary=dict(type="str", required=False),
        fabric=dict(type="str", required=False),
        ipam=dict(type="str", required=False),
        mac=dict(type="str", required=False),
        mtu=dict(type="int", required=False),
        nodes=dict(type="str", required=False),
        peers=dict(type="str", required=False),
        reversedns=dict(type="str", required=False),
        rt_import=dict(type="str", required=False),
        tag=dict(type="int", required=False),
        vlan_protocol=dict(type="str", choices=["802.1q", "802.1ad"], required=False),
        vrf_vxlan=dict(type="int", required=False),
        vxlan_port=dict(type="int", required=False),
    )


def get_ansible_module():
    module_args = proxmox_auth_argument_spec()
    module_args.update(get_proxmox_args())

    return AnsibleModule(
        argument_spec=module_args,
        required_if=[
            ('state', 'present', ['type', 'zone']),
            ('state', 'absent', ['zone'])
        ]
    )


class ProxmoxZoneAnsible(ProxmoxSdnAnsible):
    def __init__(self, module):
        super(ProxmoxZoneAnsible, self).__init__(module)
        self.params = module.params

    def validate_params(self):
        zone_type = self.params.get('type')
        if self.params.get('state') == 'present':
            if zone_type == 'vlan':
                return self.params.get('bridge')
            elif zone_type == 'qinq':
                return self.params.get('tag') and self.params.get('vlan_protocol')
            elif zone_type == 'vxlan':
                return self.params.get('fabric')
            elif zone_type == 'evpn':
                return self.params.get('controller') and self.params.get('vrf_vxlan')
            else:
                return True
        else:
            return True

    def run(self):
        state = self.params.get('state')
        update = self.params.get('update')
        zone_type = self.params.get('type')

        if not self.validate_params():
            required_params = {
                'vlan': ['bridge'],
                'qinq': ['bridge', 'tag', 'vlan_protocol'],
                'vxlan': ['fabric'],
                'evpn': ['controller', 'vrf_vxlan']
            }
            self.module.fail_json(
                msg=f'to create zone of type {zone_type} it needs - {required_params[zone_type]}'
            )

        zone_params = {
            "type": self.params.get("type"),
            "zone": self.params.get("zone"),
            "advertise-subnets": ansible_to_proxmox_bool(self.params.get("advertise_subnets")),
            "bridge": self.params.get("bridge"),
            "bridge-disable-mac-learning": ansible_to_proxmox_bool(self.params.get("bridge_disable_mac_learning")),
            "controller": self.params.get("controller"),
            "dhcp": self.params.get("dhcp"),
            "disable-arp-nd-suppression": ansible_to_proxmox_bool(self.params.get("disable_arp_nd_suppression")),
            "dns": self.params.get("dns"),
            "dnszone": self.params.get("dnszone"),
            "dp-id": self.params.get("dp_id"),
            "exitnodes": self.params.get("exitnodes"),
            "exitnodes-local-routing": ansible_to_proxmox_bool(self.params.get("exitnodes_local_routing")),
            "exitnodes-primary": self.params.get("exitnodes_primary"),
            "fabric": self.params.get("fabric"),
            "ipam": self.params.get("ipam"),
            "lock-token": None,
            "mac": self.params.get("mac"),
            "mtu": self.params.get("mtu"),
            "nodes": self.params.get("nodes"),
            "peers": self.params.get("peers"),
            "reversedns": self.params.get("reversedns"),
            "rt-import": self.params.get("rt_import"),
            "tag": self.params.get("tag"),
            "vlan-protocol": self.params.get("vlan_protocol"),
            "vrf-vxlan": self.params.get("vrf_vxlan"),
            "vxlan-port": self.params.get("vxlan_port"),
        }

        if state == "present":
            self.zone_present(update, **zone_params)

        elif state == "absent":
            self.zone_absent(
                zone_name=zone_params.get('zone'),
                lock=zone_params.get('lock-token')
            )

    def zone_present(self, update, **kwargs):
        available_zones = {x.get('zone'): {'type': x.get('type'), 'digest': x.get('digest')} for x in self.get_zones()}
        zone_name = kwargs.get("zone")
        zone_type = kwargs.get("type")

        # Check if zone already exists
        if zone_name in available_zones.keys() and not update:
            self.module.exit_json(
                changed=False, zone=zone_name, msg=f'Zone {zone_name} already exists and update is false!'
            )
        if zone_name in available_zones.keys() and update:
            if zone_type != available_zones[zone_name]['type']:
                self.module.fail_json(
                    msg=f'zone {zone_name} exists with different type and we cannot change type post fact.'
                )
            try:
                kwargs['lock-token'] = self.get_global_sdn_lock()
                kwargs['digest'] = available_zones[zone_name]['digest']
                del kwargs['zone']
                del kwargs['type']

                self.proxmox_api.cluster().sdn().zones(zone_name).put(**kwargs)
                self.apply_sdn_changes_and_release_lock(kwargs['lock-token'])
                self.module.exit_json(
                    changed=True, zone=zone_name, msg=f'Updated zone - {zone_name}'
                )
            except Exception as e:
                self.rollback_sdn_changes_and_release_lock(kwargs['lock-token'])
                self.module.fail_json(
                    msg=f'Failed to update zone {zone_name} - {e}'
                )
        # Zone does not exist and gets created
        else:
            try:
                kwargs['lock-token'] = self.get_global_sdn_lock()

                self.proxmox_api.cluster().sdn().zones().post(**kwargs)
                self.apply_sdn_changes_and_release_lock(kwargs['lock-token'])
                self.module.exit_json(
                    changed=True, zone=zone_name, msg=f'Created new Zone - {zone_name}'
                )
            except Exception as e:
                self.rollback_sdn_changes_and_release_lock(kwargs['lock-token'])
                self.module.fail_json(
                    msg=f'Failed to create zone {zone_name} - {e}'
                )

    def zone_absent(self, zone_name, lock=None):
        available_zones = [x.get('zone') for x in self.get_zones()]
        params = {'lock-token': lock}

        if zone_name not in available_zones:
            self.module.exit_json(
                changed=False, zone=zone_name, msg=f"zone {zone_name} is absent."
            )
        try:
            params['lock-token'] = self.get_global_sdn_lock()
            self.proxmox_api.cluster().sdn().zones(zone_name).delete(**params)
            self.apply_sdn_changes_and_release_lock(params['lock-token'])
            self.module.exit_json(
                changed=True, zone=zone_name, msg=f'Successfully deleted zone {zone_name}'
            )
        except Exception as e:
            self.rollback_sdn_changes_and_release_lock(params['lock-token'])
            self.module.fail_json(
                msg=f'Failed to delete zone {zone_name} {e}. Rolling back all pending changes.'
            )


def main():
    module = get_ansible_module()
    proxmox = ProxmoxZoneAnsible(module)

    try:
        proxmox.run()
    except Exception as e:
        module.fail_json(msg=f'An error occurred: {e}')


if __name__ == "__main__":
    main()
