"""
NVDIMM object representations for VM configuration management.

This module provides NVDIMM object classes that represent NVDIMM devices
and their associated controllers. NVDIMMs are managed separately from
the controller, but the two are closely linked.
"""

from random import randint

try:
    from pyVmomi import vim
except ImportError:
    pass

from ._abstract import AbstractVsphereObject


class NvdimmDeviceController(AbstractVsphereObject):
    """
    NVDIMM controller for managing NVDIMM devices.
    NVDIMM controllers are extremely limited in configuration options.
    """
    def __init__(self, raw_object=None):
        super().__init__(raw_object=raw_object)
        self._new_spec_key = -randint(1, 99999)

    @property
    def key(self):
        """
        Get the VMware device key for this controller.

        The device key is VMware's unique identifier for the controller. This
        property returns the key from either the existing device or the
        generated specification.

        A negative, unique key should be used for the new spec. VMware
        will overwrite this key with its own unique key when the controller is created.
        """
        if self.represents_live_vm_device():
            return self._raw_object.key
        if self.has_a_linked_live_vm_device():
            return self._live_object.key

        return self._new_spec_key

    @classmethod
    def from_live_device_spec(cls, live_device_spec):
        """
        Create NvdimmDeviceController instance from VMware device specification.
        Args:
            live_device_spec: VMware VirtualDeviceSpec object
        Returns:
            NVDIMM controller: Configured NVDIMM controller instance
        """
        return cls(raw_object=live_device_spec)

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.

        Returns:
            dict
        """
        return {
            "device_type": "nvdimm controller",
        }

    def to_new_spec(self):
        """
        Create a VMware device specification for adding a new NVDIMM controller.

        Generates a device specification that can be used to add this NVDIMM
        controller to a VM.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for NVDIMM controller creation
        """
        spec = vim.vm.device.VirtualDeviceSpec()
        spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add

        spec.device = vim.vm.device.VirtualNVDIMMController()
        spec.device.deviceInfo = vim.Description()
        spec.device.key = self._new_spec_key

        return spec

    def to_update_spec(self):
        """
        Create a VMware device specification for updating an existing NVDIMM controller.

        Since there is nothing to update, there's not much to do here.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for NVDIMM controller update
        """
        spec = vim.vm.device.VirtualDeviceSpec()
        spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        spec.device = self._raw_object or self._live_object._raw_object

        return spec

    def differs_from_live_object(self):
        """
        Check if the linked VM device differs from desired configuration.

        NVDIMM controllers cannot be updated, so we always return False.
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return False


class Nvdimm(AbstractVsphereObject):
    """
    Object representation of a NVDIMM device.

    The API has limited options for configuring NVDIMM devices. There are
    also no identifiers, other than the index of the NVDIMM (similar to network adapters).
    """

    def __init__(self, size_mb, index, controller, raw_object=None):
        super().__init__(raw_object=raw_object)
        self.size_mb = size_mb
        self.index = index
        self._new_spec_key = -randint(1, 99999)
        self.controller = controller

    @classmethod
    def from_live_device_spec(cls, live_device_spec, controller):
        """
        Create Nvdimm instance from VMware device specification.
        Args:
            live_device_spec: VMware VirtualDeviceSpec object
        Returns:
            NVDIMM: Configured NVDIMM instance
        """
        return cls(
            size_mb=live_device_spec.capacityInMB,
            index=live_device_spec.deviceInfo.label.replace("NVDIMM ", ""),
            controller=controller,
            raw_object=live_device_spec,
        )

    @property
    def key(self):
        """
        Get the VMware device key for this NVDIMM.

        The device key is VMware's unique identifier for the NVDIMM. This
        property returns the key from either the existing device or the
        generated specification.
        """
        if self.represents_live_vm_device():
            return self._raw_object.key
        if self.has_a_linked_live_vm_device():
            return self._live_object.key

        return self._new_spec_key

    def __str__(self):
        return "NVDIMM %s" % (self.index)

    def to_update_spec(self):
        """
        Create a VMware device specification for updating an existing NVDIMM.

        Generates a device specification that can be used to modify the
        properties of an existing NVDIMM on a VM. The specification includes
        all current NVDIMM properties.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for NVDIMM update
        """
        spec = vim.vm.device.VirtualDeviceSpec()
        spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        spec.device = self._raw_object or self._live_object._raw_object

        spec.device.capacityInMB = self.size_mb

        return spec

    def to_new_spec(self):
        """
        Create a VMware device specification for adding a new NVDIMM.

        Generates a device specification that can be used to add this NVDIMM
        to a VM. Includes file creation operation and assigns a temporary
        device key for VMware's internal tracking.
        The device key is overwritten by VMware when the NVDIMM is created.

        Returns:
            vim.vm.device.VirtualDeviceSpec: VMware device specification for NVDIMM creation
        """
        spec = vim.vm.device.VirtualDeviceSpec()
        spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
        spec.device = vim.vm.device.VirtualNVDIMM()
        spec.device.controllerKey = self.controller.key
        spec.device.key = self._new_spec_key

        spec.device.deviceInfo = vim.Description()
        spec.device.backing = vim.vm.device.VirtualNVDIMM.BackingInfo()
        spec.device.capacityInMB = self.size_mb

        return spec

    def differs_from_live_object(self):
        """
        Check if the linked VM device differs from desired configuration.

        Compares the properties of an existing VM NVDIMM device with the
        desired configuration to determine if changes are needed. Used
        for change detection in existing VMs.

        Returns:
            bool: True if the device differs from desired config, False if in sync
        """
        if not self.has_a_linked_live_vm_device():
            return True

        return self._compare_attributes_for_changes(
            self.size_mb, self._live_object.size_mb
        )

    def _to_module_output(self):
        """
        Generate module output friendly representation of this object.
        Returns:
            dict
        """
        return {
            "object_type": "nvdimm",
            "label": str(self),
            "size_mb": self.size_mb,
        }
