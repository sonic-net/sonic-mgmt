#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: baremetal_node_action
short_description: Activate/Deactivate Bare Metal nodes from OpenStack
author: OpenStack Ansible SIG
description:
    - Deploy to Bare Metal nodes controlled by Ironic.
options:
    deploy:
      description:
       - Indicates if the resource should be deployed. Allows for deployment
         logic to be disengaged and control of the node power or maintenance
         state to be changed.
      type: bool
      default: true
    config_drive:
      description:
        - A configdrive file or HTTP(S) URL that will be passed along to the
          node.
      type: raw
    instance_info:
      description:
        - Definition of the instance information which is used to deploy
          the node.  This information is only required when I(state) is
          set to C(present) or C(on).
      type: dict
      suboptions:
        image_source:
          description:
            - An HTTP(S) URL where the image can be retrieved from.
        image_checksum:
          description:
            - The checksum of image_source.
        image_disk_format:
          description:
            - The type of image that has been requested to be deployed.
    maintenance:
      description:
        - Set node into maintenance mode.
        - The power state as controlled with I(power) will not be changed
          when maintenance mode of a node is changed.
      type: bool
    maintenance_reason:
      description:
        - A string expression regarding the reason a node is in a
          maintenance mode.
      type: str
    name:
      description:
        - Name or ID of the Bare Metal node.
      type: str
      required: true
      aliases: ['id', 'uuid']
    power:
      description:
        - A setting to allow power state to be asserted allowing nodes
          that are not yet deployed to be powered on, and nodes that
          are deployed to be powered off.
        - I(power) can be C(present), C(absent), C(maintenance), C(on) or
          C(off).
      choices: ['present', 'absent', 'maintenance', 'on', 'off']
      default: present
      type: str
    state:
      description:
        - Indicates desired state of the resource.
        - I(state) can be C(present), C(absent), C(maintenance), C(on) or
          C(off).
      choices: ['present', 'absent', 'maintenance', 'on', 'off']
      default: present
      type: str
    timeout:
      description:
        - Number of seconds to wait for the node activation or deactivation
          to complete.
      type: int
      default: 1800
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
# Activate a node by booting an image with a configdrive attached
- openstack.cloud.baremetal_node_action:
    instance_info:
      image_source: "http://192.168.1.1/deploy_image.img"
      image_checksum: "356a6b55ecc511a20c33c946c4e678af"
      image_disk_format: "qcow"
    delegate_to: localhost
    deploy: true
    cloud: "openstack"
    config_drive: "http://192.168.1.1/host-configdrive.iso"
    maintenance: false
    power: present
    uuid: "d44666e1-35b3-4f6b-acb0-88ab7052da69"
    state: present

# Activate a node by booting an image with a configdrive json object
- openstack.cloud.baremetal_node_action:
    auth_type: None
    auth:
        endpoint: "http://192.168.1.1:6385/"
    id: "d44666e1-35b3-4f6b-acb0-88ab7052da69"
    config_drive:
      meta_data:
        hostname: node1
        public_keys:
          default: ssh-rsa AAA...BBB==
    delegate_to: localhost
    instance_info:
      image_source: "http://192.168.1.1/deploy_image.img"
      image_checksum: "356a6b55ecc511a20c33c946c4e678af"
      image_disk_format: "qcow"
'''

RETURN = r'''
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class BaremetalNodeActionModule(OpenStackModule):

    argument_spec = dict(
        config_drive=dict(type='raw'),
        deploy=dict(type='bool', default=True),
        instance_info=dict(type='dict'),
        maintenance=dict(type='bool'),
        maintenance_reason=dict(),
        name=dict(required=True, aliases=['id', 'uuid']),
        power=dict(default='present',
                   choices=['present', 'absent', 'maintenance', 'on', 'off']),
        state=dict(default='present',
                   choices=['present', 'absent', 'maintenance', 'on', 'off']),
        timeout=dict(type='int', default=1800),  # increased default value
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('instance_info',)),
        ],
    )

    def run(self):
        # Fail early on invalid arguments
        config_drive = self.params['config_drive']
        if config_drive and not isinstance(config_drive, (str, dict)):
            self.fail_json(msg='config_drive must be of type str or dict,'
                               ' not {0}'.format(type(config_drive)))

        # User has requested desired state to be in maintenance state.
        if self.params['state'] == 'maintenance':
            if self.params['maintenance'] is False:
                self.fail_json(
                    msg='state=maintenance contradicts with maintenance=false')
            self.params['maintenance'] = True

        name_or_id = self.params['name']
        node = self.conn.baremetal.find_node(name_or_id, ignore_missing=False)

        if node['provision_state'] in ['cleaning',
                                       'deleting',
                                       'wait call-back']:
            self.fail_json(msg='Node is in {0} state, cannot act upon the'
                               ' request as the node is in a transition'
                               ' state'.format(node['provision_state']))

        changed = False

        # Update maintenance state
        if self.params['maintenance']:
            maintenance_reason = self.params['maintenance_reason']
            if not node['maintenance'] \
               or node['maintenance_reason'] != maintenance_reason:
                self.conn.baremetal.set_node_maintenance(
                    node['id'], reason=maintenance_reason)
                self.exit_json(changed=True)
        else:  # self.params['maintenance'] is False
            if node['maintenance']:
                self.conn.baremetal.unset_node_maintenance(node['id'])
                if node['provision_state'] in 'active':
                    # Maintenance state changed
                    self.exit_json(changed=True)
                changed = True
                node = self.conn.baremetal.get_node(node['id'])

        # Update power state
        if node['power_state'] == 'power on':
            if self.params['power'] in ['absent', 'off']:
                # User has requested the node be powered off.
                self.conn.baremetal.set_node_power_state(node['id'],
                                                         'power off')
                self.exit_json(changed=True)
        elif node['power_state'] == 'power off':
            if self.params['power'] not in ['absent', 'off'] \
               or self.params['state'] not in ['absent', 'off']:
                # In the event the power has been toggled on and
                # deployment has been requested, we need to skip this
                # step.
                if self.params['power'] == 'present' \
                   and not self.params['deploy']:
                    # Node is powered down when it is not awaiting to be
                    # provisioned
                    self.conn.baremetal.set_node_power_state(node['id'],
                                                             'power on')
                    changed = True
                    node = self.conn.baremetal.get_node(node['id'])
        else:
            self.fail_json(msg='Node has unknown power state {0}'
                               .format(node['power_state']))

        if self.params['state'] in ['present', 'on']:
            if not self.params['deploy']:
                # User request has explicitly disabled deployment logic
                self.exit_json(changed=changed)

            if 'active' in node['provision_state']:
                # Node already in an active state
                self.exit_json(changed=changed)

            # TODO(TheJulia): Update instance info, however info is
            # deployment specific. Perhaps consider adding rebuild
            # support, although there is a known desire to remove
            # rebuild support from Ironic at some point in the future.
            self.conn.baremetal.update_node(
                node['id'],
                instance_info=self.params['instance_info'])
            self.conn.baremetal.validate_node(node['id'])
            self.conn.baremetal.set_node_provision_state(
                node['id'],
                target='active',
                config_drive=self.params['config_drive'],
                wait=self.params['wait'],
                timeout=self.params['timeout'])

            # TODO(TheJulia): Add more error checking..
            self.exit_json(changed=True)

        elif node['provision_state'] not in 'deleted':
            self.conn.baremetal.update_node(node['id'], instance_info={})
            self.conn.baremetal.set_node_provision_state(
                node['id'],
                target='deleted',
                wait=self.params['wait'],
                timeout=self.params['timeout'])
            self.exit_json(changed=True)

        else:
            # self.params['state'] in ['absent', 'off']
            # and node['provision_state'] in 'deleted'
            self.exit_json(changed=changed)


def main():
    module = BaremetalNodeActionModule()
    module()


if __name__ == "__main__":
    main()
