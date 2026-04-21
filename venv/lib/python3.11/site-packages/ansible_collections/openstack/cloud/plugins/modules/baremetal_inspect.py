#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015-2016, Hewlett Packard Enterprise Development Company LP
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: baremetal_inspect
short_description: Explicitly triggers baremetal node introspection in ironic.
author: OpenStack Ansible SIG
description:
    - Requests Ironic to set a node into inspect state in order to collect
      metadata regarding the node. This command may be out of band or in-band
      depending on the ironic driver configuration. This is only possible on
      nodes in 'manageable' and 'available' state.
options:
    mac:
      description:
        - unique mac address that is used to attempt to identify the host.
      type: str
    name:
      description:
        - Name or id of the node to inspect.
        - Mutually exclusive with I(mac)
      type: str
      aliases: [id, uuid]
extends_documentation_fragment:
- openstack.cloud.openstack
'''

RETURN = '''
node:
  description: A dictionary describing the node after inspection
  returned: changed
  type: dict
  contains:
    allocation_id:
      description: The UUID of the allocation associated with the node.
      type: str
    bios_interface:
      description: The bios interface to be used for this node.
      type: str
    boot_interface:
      description: The boot interface for a Node, e.g. "pxe".
      type: str
    boot_mode:
      description: The current boot mode state (uefi/bios).
      type: str
    chassis_id:
      description: UUID of the chassis associated with this Node.
      type: str
    clean_step:
      description: |
        The current clean step. Introduced with the cleaning feature.
      type: str
    conductor:
      description: The conductor currently servicing a node.
      type: str
    conductor_group:
      description: The conductor group for a node.
      type: str
    console_interface:
      description: Console interface to use when working with serial console.
      type: str
      sample: no-console
    created_at:
      description: Timestamp at which the node was last updated.
      type: str
    deploy_interface:
      description: The deploy interface for a node
      type: str
      sample: iscsi
    deploy_step:
      description: The current deploy step.
      type: str
    driver:
      description: The name of the driver.
      type: str
    driver_info:
      description: |
        All the metadata required by the driver to manage this Node. List
        of fields varies between drivers.
      type: dict
    driver_internal_info:
      description: Internal metadata set and stored by the Node's driver.
      type: dict
    extra:
      description: A set of one or more arbitrary metadata key and value pairs.
      type: dict
    fault:
      description: |
        The fault indicates the active fault detected by ironic, typically the
        Node is in "maintenance mode". None means no fault has been detected by
        ironic. "power failure" indicates ironic failed to retrieve power state
        from this node. There are other possible types, e.g., "clean failure"
        and "rescue abort failure".
      type: str
    id:
      description: The UUID for the resource.
      type: str
    inspect_interface:
      description: The interface used for node inspection.
      type: str
      sample: no-inspect
    instance_id:
      description: UUID of the Nova instance associated with this Node.
      type: str
    instance_info:
      description: |
        Information used to customize the deployed image. May include root
        partition size, a base 64 encoded config drive, and other metadata.
        Note that this field is erased automatically when the instance is
        deleted (this is done by requesting the Node provision state be changed
        to DELETED).
      type: dict
    is_automated_clean_enabled:
      description: Override enabling of automated cleaning.
      type: bool
    is_console_enabled:
      description: |
        Indicates whether console access is enabled or disabled on this node.
      type: bool
    is_maintenance:
      description: |
        Whether or not this Node is currently in "maintenance mode". Setting
        a Node into maintenance mode removes it from the available resource
        pool and halts some internal automation. This can happen manually (eg,
        via an API request) or automatically when Ironic detects a hardware
        fault that prevents communication with the machine.
      type: bool
    is_protected:
      description: |
        Whether the node is protected from undeploying, rebuilding and
        deletion.
      type: bool
    is_retired:
      description: Whether the node is marked for retirement.
      type: bool
    is_secure_boot:
      description: |
        Whether the node is currently booted with secure boot turned on.
      type: bool
    last_error:
      description: |
        Any error from the most recent (last) transaction that started but
        failed to finish.
      type: str
    links:
      description: |
        A list of relative links. Includes the self and bookmark links.
      type: list
    maintenance_reason:
      description: |
        User-settable description of the reason why this Node was placed into
        maintenance mode.
      type: str
    management_interface:
      description: Interface for out-of-band node management.
      type: str
      sample: ipmitool
    name:
      description: |
        Human-readable identifier for the Node resource. Certain words are
        reserved.
      type: str
    network_interface:
      description: |
        Which Network Interface provider to use when plumbing the network
        connections for this Node.
      type: str
    owner:
      description: A string or UUID of the tenant who owns the object.
      type: str
    port_groups:
      description: Links to the collection of portgroups on this node.
      type: list
    ports:
      description: Links to the collection of ports on this node
      type: list
    power_interface:
      description: Interface used for performing power actions on the node.
      type: str
      sample: ipmitool
    power_state:
      description: |
        The current power state of this Node. Usually, "power on" or "power
        off", but may be "None" if Ironic is unable to determine the power
        state (eg, due to hardware failure).
      type: str
    properties:
      description: Properties of the node as found by inspection
      type: dict
      contains:
        memory_mb:
          description: Amount of node memory as updated in the node properties
          type: str
          sample: "1024"
        cpu_arch:
          description: Detected CPU architecture type
          type: str
          sample: "x86_64"
        local_gb:
          description: |
            Total size of local disk storage as updated in node properties.
          type: str
          sample: "10"
        cpus:
          description: |
            Count of cpu cores defined in the updated node properties.
          type: str
          sample: "1"
    protected_reason:
      description: The reason the node is marked as protected.
      type: str
    provision_state:
      description: The current provisioning state of this Node.
      type: str
    raid_config:
      description: |
        Represents the current RAID configuration of the node. Introduced with
        the cleaning feature.
      type: dict
    raid_interface:
      description: Interface used for configuring RAID on this node.
      type: str
      sample: no-raid
    rescue_interface:
      description: The interface used for node rescue.
      type: str
      sample: no-rescue
    reservation:
      description: |
        The name of an Ironic Conductor host which is holding a lock on this
        node, if a lock is held. Usually "null", but this field can be useful
        for debugging.
      type: str
    resource_class:
      description: |
        A string which can be used by external schedulers to identify this
        Node as a unit of a specific type of resource.
      type: str
    retired_reason:
      description: TODO
      type: str
    states:
      description: |
        Links to the collection of states. Note that this resource is also
        used to request state transitions.
      type: list
    storage_interface:
      description: |
        Interface used for attaching and detaching volumes on this node, e.g.
        "cinder".
      type: str
    target_power_state:
      description: |
        If a power state transition has been requested, this field represents
        the requested (ie, "target") state, either "power on" or "power off".
      type: str
    target_provision_state:
      description: |
        If a provisioning action has been requested, this field represents
        the requested (ie, "target") state. Note that a Node may go through
        several states during its transition to this target state. For
        instance, when requesting an instance be deployed to an AVAILABLE
        Node, the Node may go through the following state change progression:
        AVAILABLE -> DEPLOYING -> DEPLOYWAIT -> DEPLOYING -> ACTIVE.
      type: str
    target_raid_config:
      description: |
        Represents the requested RAID configuration of the node, which will
        be applied when the Node next transitions through the CLEANING state.
        Introduced with the cleaning feature.
      type: dict
    traits:
      description: List of traits for this node.
      type: list
    updated_at:
      description: TODO
      type: str
    vendor_interface:
      description: |
        Interface for vendor-specific functionality on this node, e.g.
        "no-vendor".
      type: str
'''

EXAMPLES = '''
# Invoke node inspection
- openstack.cloud.baremetal_inspect:
    name: "testnode1"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class BaremetalInspectModule(OpenStackModule):
    argument_spec = dict(
        name=dict(aliases=['uuid', 'id']),
        mac=dict(),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('name', 'mac'),
        ],
        required_one_of=[
            ('name', 'mac'),
        ],
    )

    def run(self):
        node_name_or_id = self.params['name']
        node = None
        if node_name_or_id is not None:
            node = self.conn.baremetal.find_node(node_name_or_id)
        else:
            node = self.conn.get_machine_by_mac(self.params['mac'])

        if node is None:
            self.fail_json(msg="node not found.")

        node = self.conn.inspect_machine(node['id'],
                                         wait=self.params['wait'],
                                         timeout=self.params['timeout'])
        node = node.to_dict(computed=False)
        # TODO(TheJulia): diff properties, ?and ports? and determine
        # if a change occurred.  In theory, the node is always changed
        # if introspection is able to update the record.
        self.exit_json(changed=True, node=node)


def main():
    module = BaremetalInspectModule()
    module()


if __name__ == "__main__":
    main()
