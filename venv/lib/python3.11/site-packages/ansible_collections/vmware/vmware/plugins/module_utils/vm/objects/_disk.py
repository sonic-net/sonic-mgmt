"""
Disk object representation for VM configuration management.

This module provides the Disk class, which represents a virtual disk
and handles the creation and modification of VMware disk specifications.
It manages disk properties such as size, provisioning type, and placement.

It is meant to represent one of the items in the module's 'disks'
parameter.
"""

try:
    from pyVmomi import vim
except ImportError:
    pass

from ansible_collections.vmware.vmware.plugins.module_utils.vm._utils import (
    format_size_str_as_kb,
)

from ._abstract import AbstractVsphereObject


class Disk(AbstractVsphereObject):
    """
    Represents a virtual disk for VM configuration.

    This class encapsulates the properties and behavior of a virtual disk,
    including its size, provisioning type, mode, and controller assignment. It
    provides methods to create VMware device specifications for both new
    disk creation and existing disk modification.

    The disk maintains references to both the desired configuration and
    any existing VM device, enabling change detection and spec generation.

    Attributes:
        size (int): Disk size in kilobytes
        provisioning (str): Disk provisioning type ('thin', 'thick', 'eagerzeroedthick')
        mode (str): Disk mode ('persistent', 'independent_persistent', etc.)
        datastore: pyvmomi Datastore object to create the disk on
        filename (str): Filename of the disk on the datastore
        unit_number (int): Unit number on the controller
        enable_sharing (bool): Whether to enable sharing between multiple VMs
        controller: Controller object this disk is attached to

        _on_removal_detach_only (bool): Whether to detach the disk or delete it from the datastore when removing the disk.
                                        This is only used for live objects, and is set when creating the object from a live device specification.
    """

    def __init__(
        self,
        size,
        provisioning,
        mode,
        datastore,
        filename,
        controller,
        unit_number,
        enable_sharing,
        raw_object=None,
    ):
        """
        Initialize a new disk object.

        Args:
            size (str): Human-readable disk size (e.g., "100gb", "512mb")
            provisioning (str): Disk provisioning type ('thin', 'thick', 'eagerzeroedthick')
            mode (str): Disk mode for persistence behavior
            datastore: pyvmomi Datastore object to create the disk on
            controller: Controller object to attach this disk to
            unit_number (int): Unit number on the controller (Acceptable values depend on the controller type.)
            raw_object: Existing VMware device object (when linked)

        Side Effects:
            Converts size string to kilobytes.
            Registers this disk with the controller.
        """
        super().__init__(raw_object=raw_object)
        self.size = format_size_str_as_kb(size)
        self.provisioning = provisioning
        self.mode = mode
        self.enable_sharing = enable_sharing
        self.unit_number = unit_number
        self.datastore = datastore
        self.filename = filename
        self.controller = controller
        self._on_removal_detach_only = False
        # only connect parameter objects to the controllers
        if raw_object is None:
            self.controller.add_device(self)

    @classmethod
    def from_live_device_spec(cls, live_device_spec, controller, on_removal_detach_only=False):
        """
        Create disk instance from VMware device specification.
        Args:
            live_device_spec: VMware VirtualDeviceSpec object
        Returns:
            Disk: Configured disk instance
        """
        if live_device_spec.backing.thinProvisioned:
            provisioning = "thin"
        elif live_device_spec.backing.eagerlyScrub:
            provisioning = "eagerzeroedthick"
        else:
            provisioning = "thick"

        obj = cls(
            controller=controller,
            size="%skb" % live_device_spec.capacityInKB,
            provisioning=provisioning,
            mode=live_device_spec.backing.diskMode,
            datastore=live_device_spec.backing.datastore,
            filename=live_device_spec.backing.fileName,
            enable_sharing=live_device_spec.backing.sharing == "sharingMultiWriter",
            unit_number=live_device_spec.unitNumber,
            raw_object=live_device_spec,
        )
        obj._on_removal_detach_only = on_removal_detach_only
        return obj

    def __str__(self):
        """
        Get a human-readable name for this disk.

        Returns:
            str: Human-readable disk name (e.g., "Disk - SCSI Controller 0 Unit 1")
        """
        return "Disk - %s Unit %s" % (self.controller, self.unit_number)

    def to_update_spec(self):
        """
        Create a VMware device specification for updating an existing disk.

        Generates a device specification that can be used to modify the
        properties of an existing disk on a VM. The specification includes
        all current disk properties.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for disk update

        Side Effects:
            Caches the generated specification in self._spec
        """
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        disk_spec.device = self._raw_object or self._live_object._raw_object

        self._update_disk_spec_with_options(disk_spec)
        return disk_spec

    def to_new_spec(self):
        """
        Create a VMware device specification for adding a new disk.

        Generates a device specification that can be used to add this disk
        to a VM. Includes file creation operation and assigns a temporary
        device key for VMware's internal tracking.
        The device key is overwritten by VMware when the disk is created.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for disk creation
        """
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.key = self._new_spec_key
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()

        if self.provisioning == "thin":
            disk_spec.device.backing.thinProvisioned = True
        elif self.provisioning == "eagerzeroedthick":
            disk_spec.device.backing.eagerlyScrub = True

        if self.datastore is not None:
            disk_spec.device.backing.fileName = "[%s]" % self.datastore.name

        if self.mode is None:
            disk_spec.device.backing.diskMode = "persistent"

        self._update_disk_spec_with_options(disk_spec)
        return disk_spec

    def to_removal_spec(self):
        """
        Create a VMware device specification for removing an existing disk.
        """
        disk_spec = super().to_removal_spec()
        if not self._on_removal_detach_only:
            disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.destroy
        return disk_spec

    def _update_disk_spec_with_options(self, disk_spec):
        """
        Apply disk configuration options to a device specification.

        Sets the disk's size, mode, and controller assignment
        on the provided device specification. This is shared logic used by
        both create and update operations.

        Args:
            disk_spec: VMware device specification to configure

        Side Effects:
            Modifies the provided disk_spec with disk properties.
        """
        disk_spec.device.controllerKey = self.controller.key
        disk_spec.device.unitNumber = self.unit_number
        disk_spec.device.capacityInKB = self.size
        if self.mode is not None:
            disk_spec.device.backing.diskMode = self.mode

        if self.filename is not None:
            disk_spec.device.backing.fileName = self.filename

        if self.enable_sharing is not None:
            disk_spec.device.backing.sharing = (
                "sharingMultiWriter" if self.enable_sharing else "sharingNone"
            )

    def differs_from_live_object(self):
        """
        Check if the linked VM device differs from desired configuration.

        Compares the properties of an existing VM disk device with the
        desired configuration to determine if changes are needed. Used
        for change detection in existing VMs.

        Skips checking provisioning type, as it is not possible to update this value.

        Returns:
            bool: True if the device differs from desired config, False if in sync
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return (
            self._compare_attributes_for_changes(self.size, self._live_object.size)
            or self._compare_attributes_for_changes(
                self.filename, self._live_object.filename
            )
            or self._compare_attributes_for_changes(self.mode, self._live_object.mode)
            or self._compare_attributes_for_changes(
                self.enable_sharing, self._live_object.enable_sharing
            )
        )

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.
        Returns:
            dict
        """
        return {
            "object_type": "virtual disk",
            "controller": str(self.controller),
            "size": self.size,
            "provisioning": self.provisioning,
            "mode": self.mode,
            "unit_number": self.unit_number,
            "datastore": getattr(self.datastore, "name", "N/A"),
            "filename": self.filename,
            "enable_sharing": self.enable_sharing,
        }
