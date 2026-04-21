#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2024 Binero AB
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: trunk
short_description: Add or delete trunks from an OpenStack cloud.
author: OpenStack Ansible SIG
description:
   - Add or delete trunk from an OpenStack cloud.
options:
    state:
        description:
          - Should the resource be present or absent.
        choices: [present, absent]
        default: present
        type: str
    name:
        description:
          - Name that has to be given to the trunk.
          - This port attribute cannot be updated.
        type: str
        required: true
    port:
        description:
          - The name or ID of the port for the trunk.
        type: str
        required: false
    sub_ports:
        description:
          - The sub ports on the trunk.
        type: list
        required: false
        elements: dict
        suboptions:
            port:
                description: The ID or name of the port.
                type: str
            segmentation_type:
                description: The segmentation type to use.
                type: str
            segmentation_id:
                description: The segmentation ID to use.
                type: int
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Create a trunk
- openstack.cloud.trunk:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: trunk1
    port: port1

# Create a trunk with a subport
- openstack.cloud.trunk:
    state: present
    cloud: my-cloud
    name: trunk1
    port: port1
    sub_ports:
      - name: subport1
        segmentation_type: vlan
        segmentation_id: 123

# Remove a trunk
- openstack.cloud.trunk:
    state: absent
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: trunk1
'''

RETURN = '''
trunk:
    description: Dictionary describing the trunk.
    type: dict
    returned: On success when I(state) is C(present).
    contains:
        created_at:
            description: Timestamp when the trunk was created.
            returned: success
            type: str
            sample: "2022-02-03T13:28:25Z"
        description:
            description: The trunk description.
            returned: success
            type: str
        id:
            description: The trunk ID.
            returned: success
            type: str
            sample: "3ec25c97-7052-4ab8-a8ba-92faf84148de"
        is_admin_state_up:
            description: |
                The administrative state of the trunk, which is up C(True) or
                down C(False).
            returned: success
            type: bool
            sample: true
        name:
            description: The trunk name.
            returned: success
            type: str
            sample: "trunk_name"
        port_id:
            description: The ID of the port for the trunk
            returned: success
            type: str
            sample: "5ec25c97-7052-4ab8-a8ba-92faf84148df"
        project_id:
            description: The ID of the project who owns the trunk.
            returned: success
            type: str
            sample: "aa1ede4f-3952-4131-aab6-3b8902268c7d"
        revision_number:
            description: The revision number of the resource.
            returned: success
            type: int
            sample: 0
        status:
            description: The trunk status. Value is C(ACTIVE) or C(DOWN).
            returned: success
            type: str
            sample: "ACTIVE"
        sub_ports:
            description: List of sub ports on the trunk.
            returned: success
            type: list
            sample: []
        tags:
            description: The list of tags on the resource.
            returned: success
            type: list
            sample: []
        tenant_id:
            description: Same as I(project_id). Deprecated.
            returned: success
            type: str
            sample: "51fce036d7984ba6af4f6c849f65ef00"
        updated_at:
            description: Timestamp when the trunk was last updated.
            returned: success
            type: str
            sample: "2022-02-03T13:28:25Z"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class TrunkModule(OpenStackModule):
    argument_spec = dict(
        state=dict(default='present', choices=['absent', 'present']),
        name=dict(required=True),
        port=dict(),
        sub_ports=dict(type='list', elements='dict'),
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('port',)),
        ],
        supports_check_mode=True
    )

    def run(self):
        port_name_or_id = self.params['port']
        name_or_id = self.params['name']
        state = self.params['state']

        port = None
        if port_name_or_id:
            port = self.conn.network.find_port(
                port_name_or_id, ignore_missing=False)

        trunk = self.conn.network.find_trunk(name_or_id)

        sub_ports = []
        psp = self.params['sub_ports'] or []
        for sp in psp:
            subport = self.conn.network.find_port(
                sp['port'], ignore_missing=False)
            sub_ports.append(subport)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, trunk, sub_ports))

        if state == 'present' and not trunk:
            # create trunk
            trunk = self._create(name_or_id, port)
            self.exit_json(changed=True,
                           trunk=trunk.to_dict(computed=False))
        elif state == 'present' and trunk:
            # update trunk
            update = self._build_update(trunk, sub_ports)
            if update:
                trunk = self._update(trunk, update)

            self.exit_json(changed=bool(update),
                           trunk=trunk.to_dict(computed=False))
        elif state == 'absent' and trunk:
            # delete trunk
            self._delete(trunk)
            self.exit_json(changed=True)
        elif state == 'absent' and not trunk:
            # do nothing
            self.exit_json(changed=False)

    def _build_update(self, trunk, sub_ports):
        add_sub_ports = []
        del_sub_ports = []

        for sp in sub_ports:
            found = False
            for tsp in trunk['sub_ports']:
                if tsp['port_id'] == sp['id']:
                    found = True
                    break
            if found is False:
                psp = self.params['sub_ports'] or []
                for k in psp:
                    if sp['name'] == k['port']:
                        spobj = {
                            'port_id': sp['id'],
                            'segmentation_type': k['segmentation_type'],
                            'segmentation_id': k['segmentation_id'],
                        }
                        add_sub_ports.append(spobj)
                        break

        for tsp in trunk['sub_ports']:
            found = False
            for sp in sub_ports:
                if sp['id'] == tsp['port_id']:
                    found = True
                    break
            if found is False:
                del_sub_ports.append({'port_id': tsp['port_id']})

        update = {}

        if len(add_sub_ports) > 0:
            update['add_sub_ports'] = add_sub_ports

        if len(del_sub_ports) > 0:
            update['del_sub_ports'] = del_sub_ports

        return update

    def _create(self, name, port):
        args = {}
        args['name'] = name
        args['port_id'] = port.id

        return self.conn.network.create_trunk(**args)

    def _delete(self, trunk):
        sub_ports = []
        for sp in trunk['sub_ports']:
            sub_ports.append({'port_id': sp['port_id']})

        self.conn.network.delete_trunk_subports(trunk.id, sub_ports)
        self.conn.network.delete_trunk(trunk.id)

    def _update(self, trunk, update):
        if update.get('add_sub_ports', None):
            self.conn.network.add_trunk_subports(
                trunk, update['add_sub_ports'])

        if update.get('del_sub_ports', None):
            self.conn.network.delete_trunk_subports(
                trunk, update['del_sub_ports'])

        return self.conn.network.find_trunk(trunk.id)

    def _will_change(self, state, trunk, sub_ports):
        if state == 'present' and not trunk:
            return True
        elif state == 'present' and trunk:
            return bool(self._build_update(trunk, sub_ports))
        elif state == 'absent' and trunk:
            return True
        else:
            return False


def main():
    module = TrunkModule()
    module()


if __name__ == '__main__':
    main()
