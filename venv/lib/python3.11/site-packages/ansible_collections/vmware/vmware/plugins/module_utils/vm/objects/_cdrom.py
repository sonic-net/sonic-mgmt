"""
CD-ROM object representation for VM configuration management.

This module provides classes for managing VMware virtual cdroms and their
associated configurations. It supports different types of cdrom backings including
iso, emulated, and passthrough.

Classes:
    Cdrom: Main class representing a virtual cdrom

The module is designed to work with VMware's pyVmomi library and integrates with
the VM configuration management system to handle cdrom creation, modification,
and change detection.
"""

try:
    from pyVmomi import vim
except ImportError:
    pass

from ._abstract import AbstractVsphereObject


class Cdrom(AbstractVsphereObject):
    """
    Represents a virtual cdrom for VM configuration.

    This class encapsulates the properties and behavior of a virtual cdrom,
    including its backing configuration and connection settings. It provides
    methods to create VMware device specifications for both new cdrom creation
    and existing cdrom modification.

    Attributes:
        controller (Controller): The controller for this cdrom
        unit_number (int): The unit number of this cdrom
        connect_at_power_on (bool): Whether to connect the cdrom when VM starts
        iso_media_path (str): The path to the ISO media for this cdrom
        client_device_mode (str): The client device mode for this cdrom
        _raw_object: Original VMware device object
        _live_object: Corresponding live device for change detection
    """

    def __init__(
        self,
        controller,
        unit_number,
        connect_at_power_on,
        iso_media_path,
        client_device_mode,
        raw_object=None,
    ):
        """
        Initialize a new cdrom object.

        Args:
            controller (Controller): The controller for this cdrom
            unit_number (int): The unit number of this cdrom
            connect_at_power_on (bool): Whether to connect the cdrom when VM starts
            iso_media_path (str): The path to the ISO media for this cdrom
            client_device_mode (str): The client device mode for this cdrom
            raw_object: Original VMware device object
        """
        super().__init__(raw_object=raw_object)
        self.controller = controller
        self.unit_number = unit_number
        self.connect_at_power_on = connect_at_power_on
        self.iso_media_path = iso_media_path
        self.client_device_mode = client_device_mode
        # Only attach the param devices to the controller
        if not raw_object:
            self.controller.add_device(self)

    @classmethod
    def from_live_device_spec(cls, live_device_spec, controller):
        """
        Create cdrom instance from VMware device specification.

        Args:
            live_device_spec: VMware VirtualDeviceSpec object

        Returns:
            Cdrom: Configured cdrom instance
        """
        if isinstance(
            live_device_spec.backing, vim.vm.device.VirtualCdrom.IsoBackingInfo
        ):
            client_device_mode = None
            iso_media_path = live_device_spec.backing.fileName
        elif isinstance(
            live_device_spec.backing, vim.vm.device.VirtualCdrom.RemoteAtapiBackingInfo
        ):
            client_device_mode = "emulated"
            iso_media_path = None
        elif isinstance(
            live_device_spec.backing,
            vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo,
        ):
            client_device_mode = "passthrough"
            iso_media_path = None
        else:
            raise ValueError(
                "Unexpected CDROM backing on VM device, unable to determine client_device_mode and iso_media_path attributes."
            )

        return cls(
            controller=controller,
            unit_number=live_device_spec.unitNumber,
            connect_at_power_on=live_device_spec.connectable.startConnected,
            iso_media_path=iso_media_path,
            client_device_mode=client_device_mode,
            raw_object=live_device_spec,
        )

    def differs_from_live_object(self):
        """
        Check if this cdrom differs from the linked live device.

        Returns:
            bool: True if there are differences, False otherwise
        """
        if not self.has_a_linked_live_vm_device():
            return True

        att = [
            (self.iso_media_path, self._live_object.iso_media_path),
            (self.client_device_mode, self._live_object.client_device_mode),
        ]
        if self.iso_media_path is not None:
            att.append(
                (self.connect_at_power_on, self._live_object.connect_at_power_on)
            )

        for a in att:
            if self._compare_attributes_for_changes(a[0], a[1]):
                return True
        return False

    def to_new_spec(self):
        """
        Convert to VMware device specification for new cdrom creation.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for new cdrom
        """
        cdrom_spec = vim.vm.device.VirtualDeviceSpec()
        cdrom_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        cdrom_spec.device = vim.vm.device.VirtualCdrom()
        cdrom_spec.device.key = self._new_spec_key

        cdrom_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        cdrom_spec.device.connectable.allowGuestControl = True

        # default the backing if the user didn't specify
        if self.client_device_mode is None and self.iso_media_path is None:
            cdrom_spec.device.backing = (
                vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo()
            )

        self._update_cdrom_spec_with_options(cdrom_spec)
        return cdrom_spec

    def to_update_spec(self):
        """
        Convert to VMware device specification for cdrom updates.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for cdrom update
        """
        cdrom_spec = vim.vm.device.VirtualDeviceSpec()
        cdrom_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        cdrom_spec.device = self._raw_object or self._live_object._raw_object

        self._update_cdrom_spec_with_options(cdrom_spec)
        return cdrom_spec

    def __str__(self):
        """
        Get a human-readable name for this cdrom.

        Returns:
            str: Human-readable cdrom name (e.g., "CD-ROM - SCSI Controller 0 Unit 1")
        """
        return "CD-ROM - %s Unit %s" % (self.controller, self.unit_number)

    def _update_cdrom_spec_with_options(self, cdrom_spec):
        """
        Set the cdrom spec options that are shared between create and update operations.

        Args:
            cdrom_spec: VMware device specification to configure

        Side Effects:
            Modifies the provided cdrom_spec with cdrom properties.
        """
        if self.connect_at_power_on is not None:
            cdrom_spec.device.connectable.startConnected = self.connect_at_power_on

        cdrom_spec.device.controllerKey = self.controller.key
        cdrom_spec.device.unitNumber = self.unit_number

        if self.iso_media_path is not None:
            cdrom_spec.device.backing = vim.vm.device.VirtualCdrom.IsoBackingInfo()
            cdrom_spec.device.backing.fileName = self.iso_media_path
        elif self.client_device_mode == "emulated":
            cdrom_spec.device.backing = (
                vim.vm.device.VirtualCdrom.RemoteAtapiBackingInfo()
            )
        elif self.client_device_mode == "passthrough":
            cdrom_spec.device.backing = (
                vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo()
            )

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.

        Returns:
            dict
        """
        return {
            "object_type": "cdrom",
            "controller": str(self.controller),
            "unit_number": self.unit_number,
            "connect_at_power_on": self.connect_at_power_on,
            "iso_media_path": self.iso_media_path,
            "client_device_mode": self.client_device_mode,
        }
