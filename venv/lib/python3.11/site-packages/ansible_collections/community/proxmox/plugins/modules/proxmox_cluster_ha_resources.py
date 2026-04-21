#!/usr/bin/python

# Copyright (c) 2025, Markus Kötter <koetter@cispa.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-FileCopyrightText: (c) 2025, Markus Kötter <koetter@cispa.de>
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: proxmox_cluster_ha_resources

short_description: Management of HA groups in Proxmox VE Cluster

version_added: "1.1.0"

description:
  - Configure HA groups via C(/cluster/ha/groups).

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none

options:
    state:
        description: create or delete
        required: true
        choices: ['present', 'absent']
        type: str
    name:
        description: |
            HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: V(vm:100) / V(ct:100) ).
            For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
            The API documentation refers to this field as \"sid\".
        required: true
        type: str
    comment:
        description: Description
        required: false
        default: ""
        type: str
    group:
        description: The HA group identifier.
        required: false
        type: str
    max_relocate:
        description: Maximal number of service relocate tries when a service failes to start.
        required: false
        type: int
        default: 1
    max_restart:
        description: Maximal number of tries to restart the service on a node after its start failed.
        required: false
        type: int
        default: 1
    hastate:
        description: Requested resource state. The CRM reads this state and acts accordingly. Please note that V(enabled) is just an alias for V(started).
        type: str
        choices: ["started", "stopped", "disabled", "ignored"]
        default: started

extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes

author:
    - Markus Kötter (@commonism)
'''

EXAMPLES = r'''
- name: Add VM to HA group
  community.proxmox.proxmox_cluster_ha_resources:
    api_host: "{{ ansible_host }}"
    api_password: "{{ proxmox_root_pw | default(lookup('ansible.builtin.env', 'PROXMOX_PASSWORD', default='')) }}"
    api_user: root@pam
    name: vm:100
    state: "present"
    group: ha0
    max_relocate: 2
    max_restart: 2
  delegate_to: localhost

- name: Delete vm from HA group
  community.proxmox.proxmox_cluster_ha_resources:
    api_host: "{{ ansible_host }}"
    api_password: "{{ proxmox_root_pw | default(lookup('ansible.builtin.env', 'PROXMOX_PASSWORD', default='')) }}"
    api_user: root@pam
    state: "absent"
    name: vm:100
  delegate_to: localhost

- name: Add VM to HA group based on 'ha_' tag
  community.proxmox.proxmox_cluster_ha_resources:
    api_host: "{{ ansible_host }}"
    api_password: "{{ proxmox_root_pw | default(lookup('ansible.builtin.env', 'PROXMOX_PASSWORD', default='')) }}"
    api_user: root@pam
    name: "{{ proxmox_type }}:{{ proxmox_vmid }}"
    state: "present"
    group: "{{ proxmox_tags | split(';') | select('match', '^ha_') }}"
    max_relocate: 2
    max_restart: 2
  delegate_to: localhost
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
old_groups:
    description: The original name param that was passed in.
    type: list
    returned: always
new_groups:
    description: The output message that the test module generates.
    type: list
    returned: when changed
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (proxmox_auth_argument_spec,
                                                                                ProxmoxAnsible)


class ProxmoxClusterHAResourcesAnsible(ProxmoxAnsible):
    def _get(self):
        resources = self.proxmox_api.cluster.ha.resources.get()
        return resources

    def _post(self, **data):
        return self.proxmox_api.cluster.ha.resources.post(**data)

    def _put(self, sid, data):
        return self.proxmox_api.cluster.ha.resources(sid).put(**data)

    def _delete(self, sid):
        return self.proxmox_api.cluster.ha.resources(sid).delete()

    def create(self, resources, sid, comment, group, max_relocate, max_restart, state):
        data = {
            "comment": comment,
            "group": group,
            "max_relocate": max_relocate,
            "max_restart": max_restart,
            "state": state,
        }

        # Normalize input SIDs to version without : in them
        if ':' in sid:
            sid = sid.partition(':')[2]

        for resource in resources:
            if resource["sid"].partition(':')[2] != sid:
                continue

            # Compare all keys in the desired state against current state
            if all(resource.get(k) == v for k, v in data.items()):
                return False
            else:
                self._put(sid, data)
                return True

        self._post(sid=sid, **data)
        return True

    def delete(self, resources, sid):
        for resource in resources:
            if resource["sid"] != sid:
                continue
            self._delete(sid)
            return True

        return False


def run_module():
    module_args = proxmox_auth_argument_spec()

    acl_args = dict(
        state=dict(choices=['present', 'absent'], required=True),
        name=dict(type='str', required=True),
        comment=dict(type='str', default="", required=False),
        group=dict(type='str', required=False),
        max_relocate=dict(type='int', default=1, required=False),
        max_restart=dict(type='int', default=1, required=False),
        hastate=dict(choices=["started", "stopped", "disabled", "ignored"], default="started", required=False)
    )

    module_args.update(acl_args)

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    proxmox = ProxmoxClusterHAResourcesAnsible(module)

    sid = module.params['name']
    comment = module.params['comment']
    group = module.params['group']
    max_relocate = module.params['max_relocate']
    max_restart = module.params['max_restart']
    state = module.params['hastate']
    try:
        resources = proxmox._get()

        if module.params["state"] == "present":
            changed = proxmox.create(resources, sid, comment, group, max_relocate, max_restart, state)
        else:
            changed = proxmox.delete(resources, sid)

        result['changed'] = changed
    except Exception as e:
        module.fail_json(msg=str(e), **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
