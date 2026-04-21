#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 by Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r'''
module: baremetal_node_info
short_description: Retrieve information about Bare Metal nodes from OpenStack
author: OpenStack Ansible SIG
description:
    - Retrieve information about Bare Metal nodes from OpenStack.
options:
    mac:
      description:
        - MAC address that is used to attempt to identify the host.
      type: str
    name:
      description:
        - Name or ID of the baremetal node.
      type: str
      aliases: ['node']
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather information about all baremeal nodes
  openstack.cloud.baremetal_node_info:
    cloud: "devstack"
  register: nodes

- debug: var=nodes

- name: Gather information about a baremeal node
  openstack.cloud.baremetal_node_info:
    cloud: "devstack"
    name: "00000000-0000-0000-0000-000000000002"
  register: nodes

- debug: var=nodes
'''

RETURN = r'''
nodes:
    description: |
        Bare Metal node list. A subset of the dictionary keys listed below may
        be returned, depending on your cloud provider.
    returned: always
    type: list
    elements: dict
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
            description: The conductor currently servicing a node.
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
baremetal_nodes:
    description: Same as C(nodes), kept for backward compatibility.
    returned: always
    type: list
    elements: dict
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class BaremetalNodeInfoModule(OpenStackModule):
    argument_spec = dict(
        mac=dict(),
        name=dict(aliases=['node']),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('mac', 'name'),
        ],
        supports_check_mode=True,
    )

    def run(self):
        name_or_id = self.params['name']
        mac = self.params['mac']

        node_id = None
        if name_or_id:
            # self.conn.baremetal.nodes() does not support searching by name or
            # id which we want to provide for backward compatibility
            node = self.conn.baremetal.find_node(name_or_id)
            if node:
                node_id = node['id']
        elif mac:
            # self.conn.get_machine_by_mac(mac) is not necessary
            # because nodes can be filtered by instance_id
            baremetal_port = self.conn.get_nic_by_mac(mac)
            if baremetal_port:
                node_id = baremetal_port['node_id']

        if name_or_id or mac:
            if node_id:
                # fetch node details with self.conn.baremetal.get_node()
                # because self.conn.baremetal.nodes() does not provide a
                # query parameter to filter by a node's id
                node = self.conn.baremetal.get_node(node_id)
                nodes = [node.to_dict(computed=False)]
            else:  # not node_id
                # return empty list when no matching node could be found
                # because *_info modules do not raise errors on missing
                # resources
                nodes = []
        else:  # not name_or_id and not mac
            nodes = [node.to_dict(computed=False) for node in
                     self.conn.baremetal.nodes(details=True)]

        self.exit_json(changed=False,
                       nodes=nodes,
                       # keep for backward compatibility
                       baremetal_nodes=nodes)


def main():
    module = BaremetalNodeInfoModule()
    module()


if __name__ == "__main__":
    main()
