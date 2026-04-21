"""
CD-ROM parameter handler for VM configuration.

This module provides the CdromParameterHandler class which manages virtual cdrom
configuration including cdrom creation, modification, and controller assignment.
It handles cdrom parameter validation, device linking, and VMware specification
generation for cdrom management.

The handler works closely with controller handlers to ensure proper cdrom
placement and validates cdrom parameters against available controllers.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractDeviceLinkedParameterHandler,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm.objects._cdrom import (
    Cdrom,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm._utils import (
    parse_device_node,
)

try:
    from pyVmomi import vim
except ImportError:
    pass


class CdromParameterHandler(AbstractDeviceLinkedParameterHandler):
    """
    Handler for virtual cdrom configuration parameters.

    This handler manages the creation, modification, and validation of virtual
    cdroms on VMs. It processes cdrom parameters, validates controller assignments,
    and generates VMware device specifications for cdrom operations.

    The handler requires coordination with controller handlers to ensure that
    cdroms are properly assigned to available controllers. It validates device
    node specifications and ensures that all required controllers exist.

    Managed Parameters:
    - cdroms: List of cdrom configurations with media_path, mode, and device_node

    Each cdrom configuration includes:
    - media_path: The path to the ISO file to mount on the VM.
    - mode: The mode of the CD-ROM when in C(client) mode.
    - client_device_mode: The mode of the CD-ROM when in C(client) mode.
    - device_node: Controller assignment (e.g., "scsi:0:1", "sata:0:0")

    Attributes:
        controller_handlers (list): List of controller handlers for cdrom assignment
    """

    HANDLER_NAME = "cdrom"

    def __init__(
        self,
        error_handler,
        params,
        change_set,
        vm,
        device_tracker,
        controller_handlers,
        **kwargs
    ):
        """
        Initialize the cdrom parameter handler.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing cdrom configuration
            change_set: Service for tracking configuration changes and requirements
            vm: VM object being configured (None for new VM creation)
            device_tracker: Service for device identification and error reporting
            controller_handlers (list): List of controller handlers for cdrom assignment
        """
        super().__init__(error_handler, params, change_set, vm, device_tracker)
        self._check_if_params_are_defined_by_user(
            "cdroms", required_for_vm_creation=False
        )
        self.controller_handlers = controller_handlers

    @property
    def vim_device_class(self):
        """
        Get the VMware device class for this controller type.
        """
        return vim.vm.device.VirtualCdrom

    def verify_parameter_constraints(self):
        """
        Validate cdrom parameter constraints and requirements.

        Parses cdrom parameters and validates that at least one cdrom is defined
        for VM creation or modification. Validates that all required controllers
        exist and that cdrom specifications are valid.

        Raises:
            Calls error_handler.fail_with_parameter_error() for invalid cdrom
            parameters, missing controllers, or missing cdrom definitions.
        """
        if len(self.managed_parameter_objects) == 0:
            try:
                self._parse_cdrom_params()
            except ValueError as e:
                self.error_handler.fail_with_parameter_error(
                    parameter_name="cdroms",
                    message="Error parsing cdrom parameters: %s" % str(e),
                    details={"error": str(e)},
                )

    def _parse_cdrom_params(self):
        """
        Parse cdrom parameters and create Cdrom objects.

        Processes the cdrom parameter list, validates device node specifications,
        and creates Cdrom objects with proper controller assignments. Validates
        that all required controllers exist and are configured.

        Raises:
            ValueError: For invalid device node specifications or parameter formats
            Calls error_handler.fail_with_parameter_error() for missing controllers
        """
        cdrom_params = self.params.get("cdroms") or []
        for index, cdrom_param in enumerate(cdrom_params):
            controller_type, controller_bus_number, unit_number = parse_device_node(
                cdrom_param["device_node"]
            )
            if controller_type.lower() not in ["sata", "ide"]:
                self.error_handler.fail_with_parameter_error(
                    parameter_name="cdroms",
                    message="Only SATA and IDE controllers are supported for CD-ROMs. Device node %s is not valid."
                    % cdrom_param["device_node"],
                    details={"violating_param": cdrom_param},
                )

            controller = None
            for controller_handler in self.controller_handlers:
                if controller_type == controller_handler.category:
                    controller = controller_handler.managed_parameter_objects.get(
                        controller_bus_number
                    )
                    break

            if controller is None:
                self.error_handler.fail_with_parameter_error(
                    parameter_name="cdroms",
                    message="No controller has been configured for device %s. You must specify this controller in the appropriate controller parameter."
                    % cdrom_param["device_node"],
                    details={
                        "device_node": cdrom_param["device_node"],
                        "available_controllers": [
                            str(c)
                            for ch in self.controller_handlers
                            for c in ch.managed_parameter_objects.values()
                        ],
                    },
                )

            cdrom = Cdrom(
                iso_media_path=cdrom_param.get("iso_media_path"),
                client_device_mode=cdrom_param.get("client_device_mode"),
                controller=controller,
                unit_number=unit_number,
                connect_at_power_on=cdrom_param.get("connect_at_power_on"),
            )
            self.managed_parameter_objects[index] = cdrom

    def link_vm_device(self, device):
        """
        Link a VMware cdrom device to the appropriate cdrom object.

        Matches a VMware cdrom device to the corresponding cdrom object based
        on controller key and unit number. This establishes the connection
        between the existing VM device and the handler's cdrom representation.

        Args:
            device: VMware VirtualCdrom device to link

        Raises:
            Exception: If no matching cdrom object is found for the device

        Side Effects:
            Sets the _device attribute on the matching cdrom object.
        """
        for cdrom in self.managed_parameter_objects.values():
            if cdrom.has_a_linked_live_vm_device():
                continue

            if (
                device.unitNumber == cdrom.unit_number
                and device.controllerKey == cdrom.controller.key
            ):
                cdrom.link_corresponding_live_object(
                    Cdrom.from_live_device_spec(device, cdrom.controller)
                )
                return

        if self.params.get("cdroms_remove_unmanaged"):
            # device is unlinked and should be removed
            return Cdrom.from_live_device_spec(device, None)
        else:
            # the device is not linked to anything, and no DeviceLinkError was raised,
            # so the module will ignore it
            return
