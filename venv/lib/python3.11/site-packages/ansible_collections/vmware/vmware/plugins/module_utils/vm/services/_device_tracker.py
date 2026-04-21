"""
Device tracking service for VM configuration management.

This module provides the DeviceTracker service, which tracks VMware device
specifications during VM configuration operations to enable proper error
reporting and device management.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.services._abstract import (
    AbstractService,
)

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractDeviceLinkedParameterHandler,
)


class DeviceTracker(AbstractService):
    """
    Service for tracking VMware device specifications during configuration.

    This service maintains a registry of devices that are being modified during
    VM configuration. It enables translation between the device's location in
    the spec (ID) and the actual device object for better error reporting and
    debugging.

    It also handles the linking of VM devices to their appropriate handlers
    objects.

    The tracker is particularly useful when VMware API calls fail with device
    IDs that need to be mapped back to the original device specifications.
    """

    def __init__(self):
        """
        Initialize the device tracker.

        Creates an empty list to store device specifications in the order
        they are tracked.
        """
        self.spec_id_to_device = list()
        self.unlinked_devices = list()

    def track_device_id_from_spec(self, device):
        """
        Track a device for later reference.

        Adds a device to the tracker, assigning it the next
        available device ID (based on list position). This allows later
        translation from device IDs back to device objects.

        Args:
            device: VMware device object to track

        Side Effects:
            Appends the device to the internal tracking list.
        """
        self.spec_id_to_device.append(device)

    def translate_device_id_to_device(self, device_id):
        """
        Translate a device ID back to its corresponding device.

        VMware API error messages often reference devices by numeric IDs.
        This method translates those IDs back to the original device
        specifications for better error reporting.

        Args:
            device_id (int): One-based device ID from VMware error messages

        Returns:
            Device specification object corresponding to the device ID

        Raises:
            IndexError: If device_id is out of range or invalid
        """
        return self.spec_id_to_device[device_id - 1]

    def link_vm_devices_to_handler_devices(
        self,
        vm_devices,
        device_linked_handlers: list[AbstractDeviceLinkedParameterHandler],
    ):
        """
        Link existing VM devices to their appropriate handlers.

        This method iterates over all devices on the VM and attempts to link
        them to handlers that can manage them. Devices that cannot be linked
        are considered unmanaged and will be removed from the VM.

        Device linking rules:
        - If a device type matches a handler's vim_device_class, try to link it
        - If an object is returned, the device is unmanaged and should be removed
        - If no handler matches the device type, it's out of scope (ignored)

        Side effect:
            unlinked_devices: Populates this objects unlinked_devices attribute
        """
        managed_device_types = tuple()
        for handler in device_linked_handlers:
            if isinstance(handler.vim_device_class, tuple):
                managed_device_types += handler.vim_device_class
            else:
                managed_device_types += tuple([handler.vim_device_class])

        for device in vm_devices:
            # some devices are not managed by this module (like VMCI),
            # so we should skip them instead of failing to link and removing them
            if not isinstance(device, managed_device_types):
                continue

            for handler in device_linked_handlers:
                if not handler.PARAMS_DEFINED_BY_USER:
                    continue

                if not isinstance(device, handler.vim_device_class):
                    continue

                unlinked_device = handler.link_vm_device(device)
                if unlinked_device is not None:
                    self.unlinked_devices.append(unlinked_device)
                break
