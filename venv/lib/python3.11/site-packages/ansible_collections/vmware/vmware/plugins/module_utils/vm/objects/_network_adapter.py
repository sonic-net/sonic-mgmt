"""
Network adapter object representation for VM configuration management.

This module provides classes for managing VMware virtual network adapters and their
associated configurations. It supports different types of network backings including
distributed virtual switches (DVS), NSX-T logical switches, and standard vSwitches.

Classes:
    NetworkAdapterResourceAllocation: Manages resource allocation settings for network adapters
    NetworkAdapterPortgroup: Abstract base class for network portgroup configurations
    DvsNetworkAdapterPortgroup: Handles distributed virtual switch portgroup configurations
    NsxtNetworkAdapterPortgroup: Handles NSX-T logical switch configurations
    VswitchNetworkAdapterPortgroup: Handles standard vSwitch portgroup configurations
    NetworkAdapter: Main class representing a virtual network adapter

The module is designed to work with VMware's pyVmomi library and integrates with
the VM configuration management system to handle network adapter creation, modification,
and change detection.
"""

from abc import ABC

try:
    from pyVmomi import vim
except ImportError:
    pass

from ._abstract import AbstractVsphereObject


class NetworkAdapterResourceAllocation(AbstractVsphereObject):
    """
    Manages resource allocation settings for virtual network adapters.

    This class handles the configuration of network resource allocation including
    shares, reservations, and limits for virtual network adapters. It provides
    methods to convert between VMware API objects and internal representations.

    Attributes:
        shares (int, optional): Custom shares value when shares_level is "custom"
        shares_level (str, optional): Pre-defined shares level ("low", "normal", "high", "custom")
        reservation (int, optional): Reserved network bandwidth in Mbps
        limit (int, optional): Maximum network bandwidth in Mbps
        _raw_object: Original VMware resource allocation object
        _live_object: Corresponding live device for change detection
    """

    def __init__(
        self,
        shares=None,
        shares_level=None,
        reservation=None,
        limit=None,
        raw_object=None,
    ):
        """
        Initialize network adapter resource allocation.

        Args:
            shares (int, optional): Custom shares value. Only used when shares_level is "custom"
            shares_level (str, optional): Pre-defined allocation level ("low", "normal", "high", "custom")
            reservation (int, optional): Reserved network bandwidth in Mbps
            limit (int, optional): Maximum network bandwidth in Mbps
            raw_object: Original VMware resource allocation object
        """
        super().__init__(raw_object=raw_object)
        self.shares = shares
        self.shares_level = shares_level
        self.reservation = reservation
        self.limit = limit

    @classmethod
    def from_live_device_spec(cls, live_device_spec):
        """
        Create instance from VMware device allocation specification.

        Args:
            live_device_spec: VMware VirtualEthernetCard.ResourceAllocation object

        Returns:
            NetworkAdapterResourceAllocation: Configured resource allocation instance
        """
        return cls(
            shares=(
                live_device_spec.share.shares
                if live_device_spec.share.level == "custom"
                else None
            ),
            shares_level=(
                live_device_spec.share.level
                if live_device_spec.share.level != "custom"
                else None
            ),
            reservation=live_device_spec.reservation,
            limit=live_device_spec.limit,
            raw_object=live_device_spec,
        )

    def differs_from_live_object(self):
        """
        Check if this resource allocation differs from the linked live device.

        Returns:
            bool: True if there are differences, False otherwise
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return (
            self._compare_attributes_for_changes(self.shares, self._live_object.shares)
            or self._compare_attributes_for_changes(
                self.shares_level, self._live_object.shares_level
            )
            or self._compare_attributes_for_changes(
                self.reservation, self._live_object.reservation
            )
            or self._compare_attributes_for_changes(self.limit, self._live_object.limit)
        )

    def to_new_spec(self):
        """
        Convert to VMware resource allocation specification for new devices.

        Returns:
            vim.vm.device.VirtualEthernetCard.ResourceAllocation or None:
                VMware resource allocation spec, or None if no allocation configured
        """
        if (
            self.shares is None
            and self.shares_level is None
            and self.limit is None
            and self.reservation is None
        ):
            return None

        allocation = vim.vm.device.VirtualEthernetCard.ResourceAllocation()
        if self.shares_level is not None or self.shares is not None:
            shares_info = vim.SharesInfo()
            if self.shares is not None:
                shares_info.level = "custom"
                shares_info.shares = self.shares
            else:
                shares_info.level = self.shares_level
            allocation.share = shares_info

        if self.limit is not None:
            allocation.limit = self.limit

        if self.reservation is not None:
            allocation.reservation = self.reservation

        return allocation

    def to_update_spec(self):
        """
        Convert to VMware resource allocation specification for device updates.

        Returns:
            vim.vm.device.VirtualEthernetCard.ResourceAllocation or None:
                VMware resource allocation spec, or None if no allocation configured
        """
        return self.to_new_spec()

    def _to_module_output(self):
        """
        Generate a module output friendly representation of the resource allocation.

        Returns:
            dict
        """
        return {
            "shares": self.shares,
            "shares_level": self.shares_level,
            "reservation": self.reservation,
            "limit": self.limit,
        }


class NetworkAdapterPortgroup(AbstractVsphereObject, ABC):
    """
    Abstract base class for network adapter portgroup configurations.

    This class provides the foundation for different types of network portgroup
    configurations including distributed virtual switches, NSX-T logical switches,
    and standard vSwitches.
    """

    def __init__(self, raw_object=None):
        """
        Initialize network adapter portgroup.

        Args:
            raw_object: Original VMware portgroup object
        """
        super().__init__(raw_object=raw_object)

    @classmethod
    def from_live_device_spec(cls, live_device_spec):
        """
        Create appropriate portgroup instance from live VMware device backing.

        Args:
            live_device_spec: VMware device backing object

        Returns:
            NetworkAdapterPortgroup: Appropriate portgroup subclass instance
        """
        if hasattr(live_device_spec, "port"):
            return DvsNetworkAdapterPortgroup(
                live_device_spec.port.portgroupKey,
                live_device_spec.port.switchUuid,
                raw_object=live_device_spec,
            )
        elif hasattr(live_device_spec, "opaqueNetworkId"):
            return NsxtNetworkAdapterPortgroup(
                live_device_spec.opaqueNetworkId, raw_object=live_device_spec
            )
        else:
            return VswitchNetworkAdapterPortgroup(
                live_device_spec.deviceName,
                live_device_spec.network,
                raw_object=live_device_spec,
            )

    @classmethod
    def from_portgroup(cls, portgroup):
        """
        Create appropriate portgroup instance from live VMware portgroup object.

        Args:
            portgroup: VMware portgroup object

        Returns:
            NetworkAdapterPortgroup or None: Appropriate portgroup subclass instance, or None if portgroup is None
        """
        if portgroup is None:
            return None

        if hasattr(portgroup, "key"):
            return DvsNetworkAdapterPortgroup(
                portgroup.key, portgroup.config.distributedVirtualSwitch.uuid
            )
        elif hasattr(portgroup, "capability"):
            return NsxtNetworkAdapterPortgroup(portgroup.summary.opaqueNetworkId)
        else:
            return VswitchNetworkAdapterPortgroup(portgroup.name, portgroup)


class DvsNetworkAdapterPortgroup(NetworkAdapterPortgroup):
    """
    Handles distributed virtual switch (DVS) portgroup configurations.

    This class manages network adapter configurations that connect to distributed
    virtual switch portgroups, which are used in VMware vSphere environments with
    distributed switches.

    Attributes:
        portgroup_key (str): Portgroup key identifier
        switch_uuid (str): Distributed virtual switch UUID
    """

    def __init__(self, portgroup_key, switch_uuid, raw_object=None):
        """
        Initialize DVS network adapter portgroup.

        Args:
            portgroup_key (str): Portgroup key identifier
            switch_uuid (str): Distributed virtual switch UUID
            raw_object: Original VMware portgroup object
        """
        super().__init__(raw_object=raw_object)
        self.portgroup_key = portgroup_key
        self.switch_uuid = switch_uuid

    def to_new_spec(self):
        """
        Convert to VMware DVS portgroup backing specification for new devices.

        Returns:
            vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo:
                VMware DVS portgroup backing spec
        """
        dvs_port_connection = vim.dvs.PortConnection()
        dvs_port_connection.portgroupKey = self.portgroup_key
        dvs_port_connection.switchUuid = self.switch_uuid
        backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
        backing.port = dvs_port_connection

        return backing

    def to_update_spec(self):
        """
        Convert to VMware DVS portgroup backing specification for device updates.

        Returns:
            vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo:
                VMware DVS portgroup backing spec
        """
        return self.to_new_spec()

    def differs_from_live_object(self):
        """
        Check if this DVS portgroup differs from the linked live device.

        Returns:
            bool: True if there are differences, False otherwise
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return self._compare_attributes_for_changes(
            self.portgroup_key, self._live_object.portgroup_key
        ) or self._compare_attributes_for_changes(
            self.switch_uuid, self._live_object.switch_uuid
        )

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.

        Returns:
            dict
        """
        return {
            "portgroup_key": self.portgroup_key,
            "switch_uuid": self.switch_uuid,
        }


class NsxtNetworkAdapterPortgroup(NetworkAdapterPortgroup):
    """
    Handles NSX-T logical switch configurations.

    This class manages network adapter configurations that connect to NSX-T
    logical switches, providing network virtualization capabilities in VMware
    environments with NSX-T integration.

    Attributes:
        opaque_network_id (str): NSX-T logical switch opaque network ID
    """

    def __init__(self, opaque_network_id, raw_object=None):
        """
        Initialize NSX-T network adapter portgroup.

        Args:
            opaque_network_id (str): NSX-T logical switch opaque network ID
            raw_object: Original VMware portgroup object
        """
        super().__init__(raw_object)
        self.opaque_network_id = opaque_network_id

    def to_new_spec(self):
        """
        Convert to VMware NSX-T portgroup backing specification for new devices.

        Returns:
            vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo:
                VMware NSX-T portgroup backing spec
        """
        backing = vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo()
        backing.opaqueNetworkType = "nsx.LogicalSwitch"
        backing.opaqueNetworkId = self.opaque_network_id
        backing.deviceInfo.summary = "nsx.LogicalSwitch: %s" % self.opaque_network_id

        return backing

    def to_update_spec(self):
        """
        Convert to VMware NSX-T portgroup backing specification for device updates.

        Returns:
            vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo:
                VMware NSX-T portgroup backing spec
        """
        return self.to_new_spec()

    def differs_from_live_object(self):
        """
        Check if this NSX-T portgroup differs from the linked live device.

        Returns:
            bool: True if there are differences, False otherwise
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return self._compare_attributes_for_changes(
            self.opaque_network_id, self._live_object.opaque_network_id
        )

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.

        Returns:
            dict
        """
        return {
            "opaque_network_id": self.opaque_network_id,
        }


class VswitchNetworkAdapterPortgroup(NetworkAdapterPortgroup):
    """
    Handles standard vSwitch portgroup configurations.

    This class manages network adapter configurations that connect to standard
    VMware vSwitch portgroups, which are the traditional networking option in
    vSphere environments.

    Attributes:
        name (str): Portgroup name
        network: VMware network object reference
    """

    def __init__(self, name, network, raw_object=None):
        """
        Initialize vSwitch network adapter portgroup.

        Args:
            name (str): Portgroup name
            network: VMware network object reference
            raw_object: Original VMware portgroup object
        """
        super().__init__(raw_object=raw_object)
        self.name = name
        self.network = network

    def to_new_spec(self):
        """
        Convert to VMware vSwitch portgroup backing specification for new devices.

        Returns:
            vim.vm.device.VirtualEthernetCard.NetworkBackingInfo:
                VMware vSwitch portgroup backing spec
        """
        backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
        backing.network = self.network
        backing.deviceName = self.name

        return backing

    def to_update_spec(self):
        """
        Convert to VMware vSwitch portgroup backing specification for device updates.

        Returns:
            vim.vm.device.VirtualEthernetCard.NetworkBackingInfo:
                VMware vSwitch portgroup backing spec
        """
        return self.to_new_spec()

    def differs_from_live_object(self):
        """
        Check if this vSwitch portgroup differs from the linked live device.

        Returns:
            bool: True if there are differences, False otherwise
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return self._compare_attributes_for_changes(
            self.name, self._live_object.name
        ) or self._compare_attributes_for_changes(
            self.network, self._live_object.network
        )

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.

        Returns:
            dict
        """
        return {
            "name": self.name,
            "network": self.network._GetMoId(),
        }


class NetworkAdapter(AbstractVsphereObject):
    """
    Represents a virtual network adapter for VM configuration.

    This class encapsulates the properties and behavior of a virtual network adapter,
    including its portgroup configuration, adapter type, connection settings, resource
    allocation, and MAC address. It provides methods to create VMware device specifications
    for both new adapter creation and existing adapter modification.

    The adapter maintains references to both the desired configuration and any existing
    VM device, enabling change detection and spec generation.

    Attributes:
        index (int): The global index of the network adapter
        adapter_vim_class (class): Vim class of the network adapter (e.g., vim.vm.device.VirtualE1000)
        portgroup (NetworkAdapterPortgroup): Portgroup configuration for this adapter
        connect_at_power_on (bool): Whether to connect the adapter when VM starts
        connected (bool): Current connection state of the adapter
        resource_allocation (NetworkAdapterResourceAllocation): Resource allocation settings
        mac_address (str): MAC address of the network adapter ("automatic" for generated)
        _raw_object: Original VMware device object
        _live_object: Corresponding live device for change detection
    """

    def __init__(
        self,
        index,
        adapter_vim_class,
        connect_at_power_on,
        connected,
        mac_address,
        resource_allocation: NetworkAdapterResourceAllocation,
        portgroup: NetworkAdapterPortgroup,
        raw_object=None,
    ):
        """
        Initialize a new network adapter object.

        Args:
            index (int): The global index of the network adapter
            adapter_vim_class (class): Vim class of the network adapter
            connect_at_power_on (bool): Whether to connect the adapter when VM starts
            connected (bool): Current connection state of the adapter
            mac_address (str): MAC address ("automatic" for generated, specific address for manual)
            resource_allocation (NetworkAdapterResourceAllocation): Resource allocation settings
            portgroup (NetworkAdapterPortgroup): Portgroup configuration
            raw_object: Original VMware device object
        """
        super().__init__(raw_object=raw_object)
        self.index = index
        self.adapter_vim_class = adapter_vim_class
        self.portgroup = portgroup
        self.connect_at_power_on = connect_at_power_on
        self.connected = connected
        self.resource_allocation = resource_allocation
        self.mac_address = mac_address

    @classmethod
    def from_live_device_spec(cls, live_device_spec):
        """
        Create network adapter instance from VMware device specification.

        Args:
            live_device_spec: VMware VirtualDeviceSpec object

        Returns:
            NetworkAdapter: Configured network adapter instance
        """
        return cls(
            index="",
            adapter_vim_class=type(live_device_spec),
            portgroup=NetworkAdapterPortgroup.from_live_device_spec(
                live_device_spec.backing
            ),
            connect_at_power_on=live_device_spec.connectable.startConnected,
            connected=live_device_spec.connectable.connected,
            mac_address=(
                "automatic"
                if live_device_spec.addressType == "generated"
                else live_device_spec.macAddress
            ),
            resource_allocation=NetworkAdapterResourceAllocation.from_live_device_spec(
                live_device_spec.resourceAllocation
            ),
            raw_object=live_device_spec,
        )

    def differs_from_live_object(self):
        """
        Check if this network adapter differs from the linked live device.

        Returns:
            bool: True if there are differences, False otherwise
        """
        if not self.has_a_linked_live_vm_device():
            return True

        att = [
            (self.portgroup, self._live_object.portgroup),
            (self.resource_allocation, self._live_object.resource_allocation),
            (self.mac_address, self._live_object.mac_address),
            (self.connect_at_power_on, self._live_object.connect_at_power_on),
            (self.connected, self._live_object.connected),
        ]

        for a in att:
            if self._compare_attributes_for_changes(a[0], a[1]):
                return True
        return False

    def to_new_spec(self):
        """
        Convert to VMware device specification for new network adapter creation.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for new adapter
        """
        network_adapter_spec = vim.vm.device.VirtualDeviceSpec()
        network_adapter_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        network_adapter_spec.device = (
            self.adapter_vim_class()
            if self.adapter_vim_class is not None
            else vim.vm.device.VirtualVmxnet3()
        )
        network_adapter_spec.device.key = self._new_spec_key

        network_adapter_spec.device.deviceInfo = vim.Description()
        network_adapter_spec.device.connectable = (
            vim.vm.device.VirtualDevice.ConnectInfo()
        )
        if self.mac_address == "automatic" or self.mac_address is None:
            network_adapter_spec.device.addressType = "generated"
        else:
            network_adapter_spec.device.addressType = "manual"
            network_adapter_spec.device.macAddress = self.mac_address

        self._update_network_adapter_spec_with_options(network_adapter_spec)
        return network_adapter_spec

    def to_update_spec(self):
        """
        Convert to VMware device specification for network adapter updates.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for adapter update
        """
        network_adapter_spec = vim.vm.device.VirtualDeviceSpec()
        network_adapter_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        network_adapter_spec.device = self._raw_object or self._live_object._raw_object

        if self.mac_address == "automatic":
            network_adapter_spec.device.addressType = "generated"
        elif self.mac_address is not None:
            network_adapter_spec.device.addressType = "manual"
            network_adapter_spec.device.macAddress = self.mac_address

        self._update_network_adapter_spec_with_options(network_adapter_spec)
        return network_adapter_spec

    def link_corresponding_live_object(self, abstract_vsphere_object: "NetworkAdapter"):
        """
        Link this network adapter to its corresponding live device for change detection.

        Args:
            abstract_vsphere_object (NetworkAdapter): The live network adapter device to link
        """
        super().link_corresponding_live_object(abstract_vsphere_object)
        self.portgroup.link_corresponding_live_object(abstract_vsphere_object.portgroup)
        self.resource_allocation.link_corresponding_live_object(
            abstract_vsphere_object.resource_allocation
        )

    def __str__(self):
        """
        Get a human-readable name for this network adapter.

        Generates a descriptive name including the adapter type, portgroup name, and index
        for easy identification in error messages and logs.

        Returns:
            str: Human-readable network adapter name (e.g., "Network Adapter 1")
        """
        return "Network Adapter %s" % self.index

    def _update_network_adapter_spec_with_options(self, network_adapter_spec):
        """
        Set the network adapter spec options that are shared between create and update operations.

        Args:
            network_adapter_spec: VMware device specification to configure

        Side Effects:
            Modifies the provided network_adapter_spec with network adapter properties.
        """
        if self.connect_at_power_on is not None:
            network_adapter_spec.device.connectable.startConnected = (
                self.connect_at_power_on
            )

        if self.connected is not None:
            network_adapter_spec.device.connectable.connected = self.connected

        allocation_spec = self.resource_allocation.to_new_spec()
        if allocation_spec is not None:
            network_adapter_spec.device.resourceAllocation = allocation_spec

        portgroup_spec = self.portgroup.to_new_spec()
        if portgroup_spec is not None:
            network_adapter_spec.device.backing = portgroup_spec

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.

        Returns:
            dict
        """
        return {
            "object_type": "network adapter",
            "type": (
                None
                if self.adapter_vim_class is None
                else self.adapter_vim_class.__name__.lower()
            ),
            "portgroup": self.portgroup._to_module_output(),
            "connect_at_power_on": self.connect_at_power_on,
            "connected": self.connected,
            "resource_allocation": self.resource_allocation._to_module_output(),
            "mac_address": self.mac_address,
        }
