#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2014, Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: baremetal_node
short_description: Create/Delete Bare Metal Resources from OpenStack
author: OpenStack Ansible SIG
description:
    - Create or Remove Ironic nodes from OpenStack.
options:
    bios_interface:
      description:
        - The bios interface for this node, e.g. C(no-bios).
      type: str
    boot_interface:
      description:
        - The boot interface for this node, e.g. C(pxe).
      type: str
    chassis_id:
      description:
        - Associate the node with a pre-defined chassis.
      type: str
      aliases: ['chassis_uuid']
    console_interface:
      description:
        - The console interface for this node, e.g. C(no-console).
      type: str
    deploy_interface:
      description:
        - The deploy interface for this node, e.g. C(iscsi).
      type: str
    driver:
      description:
        - The name of the Ironic Driver to use with this node.
        - Required when I(state) is C(present)
      type: str
    driver_info:
      description:
        - Information for this node's driver. Will vary based on which
          driver is in use. Any sub-field which is populated will be validated
          during creation. For compatibility reasons sub-fields `power`,
          `deploy`, `management` and `console` are flattened.
      required: true
      type: dict
    id:
      description:
        - ID to be given to the baremetal node. Will be auto-generated on
          creation if not specified, and I(name) is specified.
        - Definition of I(id) will always take precedence over I(name).
      type: str
      aliases: ['uuid']
    inspect_interface:
      description:
        - The interface used for node inspection, e.g. C(no-inspect).
      type: str
    management_interface:
      description:
        - The interface for out-of-band management of this node, e.g.
          "ipmitool".
      type: str
    name:
      description:
        - unique name identifier to be given to the resource.
      type: str
    network_interface:
      description:
        - The network interface provider to use when describing
          connections for this node.
      type: str
    nics:
      description:
        - 'A list of network interface cards, eg, C( - mac: aa:bb:cc:aa:bb:cc)'
        - This node attribute cannot be updated.
      required: true
      type: list
      elements: dict
      suboptions:
        mac:
            description: The MAC address of the network interface card.
            type: str
            required: true
    power_interface:
      description:
        - The interface used to manage power actions on this node, e.g.
          C(ipmitool).
      type: str
    properties:
      description:
        - Definition of the physical characteristics of this node
        - Used for scheduling purposes
      type: dict
      suboptions:
        cpu_arch:
          description:
            - CPU architecture (x86_64, i686, ...)
          type: str
        cpus:
          description:
            - Number of CPU cores this machine has
          type: str
        memory_mb:
          description:
            - Amount of RAM  in MB this machine has
          aliases: ['ram']
          type: str
        local_gb:
          description:
            - Size in GB of first storage device in this machine (typically
              /dev/sda)
          aliases: ['disk_size']
          type: str
        capabilities:
          description:
            - Special capabilities for this node such as boot_option etc.
            - For more information refer to
              U(https://docs.openstack.org/ironic/latest/install/advanced.html).
          type: str
        root_device:
          description:
            - Root disk device hints for deployment.
            - For allowed hints refer to
              U(https://docs.openstack.org/ironic/latest/install/advanced.html).
          type: dict
    raid_interface:
      description:
        - Interface used for configuring raid on this node.
      type: str
    rescue_interface:
      description:
        - Interface used for node rescue, e.g. C(no-rescue).
      type: str
    resource_class:
      description:
        - The specific resource type to which this node belongs.
      type: str
    skip_update_of_masked_password:
      description:
        - Deprecated, no longer used.
        - Updating or specifing a password has not been supported for a while.
      type: bool
    state:
      description:
        - Indicates desired state of the resource
      choices: ['present', 'absent']
      default: present
      type: str
    storage_interface:
      description:
        - Interface used for attaching and detaching volumes on this node, e.g.
          C(cinder).
      type: str
    timeout:
      description:
        - Number of seconds to wait for the newly created node to reach the
          available state.
      type: int
      default: 1800
    vendor_interface:
      description:
        - Interface for all vendor-specific actions on this node, e.g.
          C(no-vendor).
      type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Enroll a node with some basic properties and driver info
  openstack.cloud.baremetal_node:
    chassis_id: "00000000-0000-0000-0000-000000000001"
    cloud: "devstack"
    driver: "pxe_ipmitool"
    driver_info:
      ipmi_address: "1.2.3.4"
      ipmi_username: "admin"
      ipmi_password: "adminpass"
    id: "00000000-0000-0000-0000-000000000002"
    nics:
      - mac: "aa:bb:cc:aa:bb:cc"
      - mac: "dd:ee:ff:dd:ee:ff"
    properties:
      capabilities: "boot_option:local"
      cpu_arch: "x86_64"
      cpus: 2
      local_gb: 64
      memory_mb: 8192
      root_device:
        wwn: "0x4000cca77fc4dba1"
'''

RETURN = r'''
node:
    description: Dictionary describing the Bare Metal node.
    type: dict
    returned: On success when I(state) is 'present'.
    contains:
        allocation_id:
            description: The UUID of the allocation associated with the node.
                         If not null, will be the same as instance_id (the
                         opposite is not always true). Unlike instance_id,
                         this field is read-only. Please use the Allocation API
                         to remove allocations.
            returned: success
            type: str
        bios_interface:
            description: The bios interface to be used for this node.
            returned: success
            type: str
        boot_interface:
            description: The boot interface for a node, e.g. "pxe".
            returned: success
            type: str
        boot_mode:
            description: The boot mode for a node, either "uefi" or "bios"
            returned: success
            type: str
        chassis_id:
            description: UUID of the chassis associated with this node. May be
                         empty or None.
            returned: success
            type: str
        clean_step:
            description: The current clean step.
            returned: success
            type: str
        conductor:
            description: |
                The conductor currently servicing a node.
            returned: success
            type: str
        conductor_group:
            description: The conductor group for a node.
            returned: success
            type: str
        console_interface:
            description: The console interface for a node, e.g. "no-console".
            returned: success
            type: str
        created_at:
            description: Bare Metal node created at timestamp.
            returned: success
            type: str
        deploy_interface:
            description: The deploy interface for a node, e.g. "direct".
            returned: success
            type: str
        deploy_step:
            description: The current deploy step.
            returned: success
            type: str
        driver:
            description: The name of the driver.
            returned: success
            type: str
        driver_info:
            description: All the metadata required by the driver to manage this
                         node. List of fields varies between drivers, and can
                         be retrieved from the
                         /v1/drivers/<DRIVER_NAME>/properties resource.
            returned: success
            type: dict
        driver_internal_info:
            description: Internal metadata set and stored by the node's driver.
            returned: success
            type: dict
        extra:
            description: A set of one or more arbitrary metadata key and value
                         pairs.
            returned: success
            type: dict
        fault:
            description: The fault indicates the active fault detected by
                         ironic, typically the node is in "maintenance mode".
                         None means no fault has been detected by ironic.
                         "power failure" indicates ironic failed to retrieve
                         power state from this node. There are other possible
                         types, e.g., "clean failure" and "rescue abort
                         failure".
            returned: success
            type: str
        id:
            description: The UUID for the resource.
            returned: success
            type: str
        inspect_interface:
            description: The interface used for node inspection.
            returned: success
            type: str
        instance_id:
            description: UUID of the Nova instance associated with this node.
            returned: success
            type: str
        instance_info:
            description: Information used to customize the deployed image. May
                         include root partition size, a base 64 encoded config
                         drive, and other metadata. Note that this field is
                         erased automatically when the instance is deleted
                         (this is done by requesting the node provision state
                         be changed to DELETED).
            returned: success
            type: dict
        is_automated_clean_enabled:
            description: Indicates whether the node will perform automated
                         clean or not.
            returned: success
            type: bool
        is_console_enabled:
            description: Indicates whether console access is enabled or
                         disabled on this node.
            returned: success
            type: bool
        is_maintenance:
            description: Whether or not this node is currently in "maintenance
                         mode". Setting a node into maintenance mode removes it
                         from the available resource pool and halts some
                         internal automation. This can happen manually (eg, via
                         an API request) or automatically when Ironic detects a
                         hardware fault that prevents communication with the
                         machine.
            returned: success
            type: bool
        is_protected:
            description: Whether the node is protected from undeploying,
                         rebuilding and deletion.
            returned: success
            type: bool
        is_retired:
            description: Whether the node is retired and can hence no longer be
                         provided, i.e. move from manageable to available, and
                         will end up in manageable after cleaning (rather than
                         available).
            returned: success
            type: bool
        is_secure_boot:
            description: Indicates whether node is currently booted with
                         secure_boot turned on.
            returned: success
            type: bool
        last_error:
            description: Any error from the most recent (last) transaction that
                         started but failed to finish.
            returned: success
            type: str
        links:
            description: A list of relative links, including self and bookmark
                         links.
            returned: success
            type: list
        maintenance_reason:
            description: User-settable description of the reason why this node
                         was placed into maintenance mode
            returned: success
            type: str
        management_interface:
            description: Interface for out-of-band node management.
            returned: success
            type: str
        name:
            description: Human-readable identifier for the node resource. May
                         be undefined. Certain words are reserved.
            returned: success
            type: str
        network_interface:
            description: Which Network Interface provider to use when plumbing
                         the network connections for this node.
            returned: success
            type: str
        owner:
            description: A string or UUID of the tenant who owns the object.
            returned: success
            type: str
        ports:
            description: List of ironic ports on this node.
            returned: success
            type: list
        port_groups:
            description: List of ironic port groups on this node.
            returned: success
            type: list
        power_interface:
            description: Interface used for performing power actions on the
                         node, e.g. "ipmitool".
            returned: success
            type: str
        power_state:
            description: The current power state of this node. Usually, "power
                         on" or "power off", but may be "None" if Ironic is
                         unable to determine the power state (eg, due to
                         hardware failure).
            returned: success
            type: str
        properties:
            description: Physical characteristics of this node. Populated by
                         ironic-inspector during inspection. May be edited via
                         the REST API at any time.
            returned: success
            type: dict
        protected_reason:
            description: The reason the node is marked as protected.
            returned: success
            type: str
        provision_state:
            description: The current provisioning state of this node.
            returned: success
            type: str
        raid_config:
            description: Represents the current RAID configuration of the node.
                         Introduced with the cleaning feature.
            returned: success
            type: dict
        raid_interface:
            description: Interface used for configuring RAID on this node.
            returned: success
            type: str
        rescue_interface:
            description: The interface used for node rescue, e.g. "no-rescue".
            returned: success
            type: str
        reservation:
            description: The name of an Ironic Conductor host which is holding
                         a lock on this node, if a lock is held. Usually
                         "null", but this field can be useful for debugging.
            returned: success
            type: str
        resource_class:
            description: A string which can be used by external schedulers to
                         identify this node as a unit of a specific type of
                         resource. For more details, see
                         https://docs.openstack.org/ironic/latest/install/configure-nova-flavors.html
            returned: success
            type: str
        retired_reason:
            description: The reason the node is marked as retired.
            returned: success
            type: str
        states:
            description: Links to the collection of states.
            returned: success
            type: list
        storage_interface:
            description: Interface used for attaching and detaching volumes on
                         this node, e.g. "cinder".
            returned: success
            type: str
        target_power_state:
            description: If a power state transition has been requested, this
                         field represents the requested (ie, "target") state,
                         either "power on" or "power off".
            returned: success
            type: str
        target_provision_state:
            description: If a provisioning action has been requested, this
                         field represents the requested (ie, "target") state.
                         Note that a node may go through several states during
                         its transition to this target state. For instance,
                         when requesting an instance be deployed to an
                         AVAILABLE node, the node may go through the following
                         state change progression, AVAILABLE -> DEPLOYING ->
                         DEPLOYWAIT -> DEPLOYING -> ACTIVE
            returned: success
            type: str
        target_raid_config:
            description: Represents the requested RAID configuration of the
                         node, which will be applied when the node next
                         transitions through the CLEANING state. Introduced
                         with the cleaning feature.
            returned: success
            type: dict
        traits:
            description: List of traits for this node.
            returned: success
            type: list
        updated_at:
            description: Bare Metal node updated at timestamp.
            returned: success
            type: str
        vendor_interface:
            description: Interface for vendor-specific functionality on this
                         node, e.g. "no-vendor".
            returned: success
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class BaremetalNodeModule(OpenStackModule):
    argument_spec = dict(
        bios_interface=dict(),
        boot_interface=dict(),
        chassis_id=dict(aliases=['chassis_uuid']),
        console_interface=dict(),
        deploy_interface=dict(),
        driver=dict(),
        driver_info=dict(type='dict', required=True),
        id=dict(aliases=['uuid']),
        inspect_interface=dict(),
        management_interface=dict(),
        name=dict(),
        network_interface=dict(),
        nics=dict(type='list', required=True, elements='dict'),
        power_interface=dict(),
        properties=dict(
            type='dict',
            options=dict(
                cpu_arch=dict(),
                cpus=dict(),
                memory_mb=dict(aliases=['ram']),
                local_gb=dict(aliases=['disk_size']),
                capabilities=dict(),
                root_device=dict(type='dict'),
            ),
        ),
        raid_interface=dict(),
        rescue_interface=dict(),
        resource_class=dict(),
        skip_update_of_masked_password=dict(
            type='bool',
            removed_in_version='3.0.0',
            removed_from_collection='openstack.cloud',
        ),
        state=dict(default='present', choices=['present', 'absent']),
        storage_interface=dict(),
        timeout=dict(default=1800, type='int'),  # increased default value
        vendor_interface=dict(),
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('driver',)),
        ],
        required_one_of=[
            ('id', 'name'),
        ],
        supports_check_mode=True,
    )

    def run(self):
        name_or_id = \
            self.params['id'] if self.params['id'] else self.params['name']
        node = self.conn.baremetal.find_node(name_or_id)
        state = self.params['state']

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, node))

        if state == 'present' and not node:
            node = self._create()
            self.exit_json(changed=True,
                           node=node.to_dict(computed=False))

        elif state == 'present' and node:
            update = self._build_update(node)
            if update:
                node = self._update(node, update)
            self.exit_json(changed=bool(update),
                           node=node.to_dict(computed=False))

        elif state == 'absent' and node:
            self._delete(node)
            self.exit_json(changed=True)

        elif state == 'absent' and not node:
            self.exit_json(changed=False)

    def _build_update(self, node):
        update = {}
        # TODO(TheJulia): Presently this does not support updating nics.
        #                 Support needs to be added.

        # Update all known updateable attributes
        node_attributes = dict(
            (k, self.params[k])
            for k in [
                'bios_interface',
                'boot_interface',
                'chassis_id',
                'console_interface',
                'deploy_interface',
                'driver',
                'driver_info',
                'inspect_interface',
                'management_interface',
                'name',
                'network_interface',
                'power_interface',
                'raid_interface',
                'rescue_interface',
                'resource_class',
                'storage_interface',
                'vendor_interface',
            ]
            if k in self.params and self.params[k] is not None
            and self.params[k] != node[k])

        properties = self.params['properties']
        if properties is not None:
            properties = dict(
                (k, v) for k, v in properties.items() if v is not None)
            if properties and properties != node['properties']:
                node_attributes['properties'] = properties

        # name can only be updated if id is given
        if self.params['id'] is None and 'name' in node_attributes:
            self.fail_json(msg='The name of a node cannot be updated without'
                               ' specifying an id')

        if node_attributes:
            update['node_attributes'] = node_attributes

        return update

    def _create(self):
        kwargs = {}

        for k in ('bios_interface',
                  'boot_interface',
                  'chassis_id',
                  'console_interface',
                  'deploy_interface',
                  'driver',
                  'driver_info',
                  'id',
                  'inspect_interface',
                  'management_interface',
                  'name',
                  'network_interface',
                  'power_interface',
                  'raid_interface',
                  'rescue_interface',
                  'resource_class',
                  'storage_interface',
                  'vendor_interface'):
            if self.params[k] is not None:
                kwargs[k] = self.params[k]

        properties = self.params['properties']
        if properties is not None:
            properties = dict(
                (k, v) for k, v in properties.items() if v is not None)
            if properties:
                kwargs['properties'] = properties

        node = self.conn.register_machine(
            nics=self.params['nics'],
            wait=self.params['wait'],
            timeout=self.params['timeout'],
            **kwargs)

        self.exit_json(changed=True, node=node.to_dict(computed=False))

    def _delete(self, node):
        self.conn.unregister_machine(
            nics=self.params['nics'], uuid=node['id'])

    def _update(self, node, update):
        node_attributes = update.get('node_attributes')
        if node_attributes:
            node = self.conn.baremetal.update_node(
                node['id'], **node_attributes)

        return node

    def _will_change(self, state, node):
        if state == 'present' and not node:
            return True
        elif state == 'present' and node:
            return bool(self._build_update(node))
        elif state == 'absent' and node:
            return True
        else:
            # state == 'absent' and not node:
            return False


def main():
    module = BaremetalNodeModule()
    module()


if __name__ == "__main__":
    main()
