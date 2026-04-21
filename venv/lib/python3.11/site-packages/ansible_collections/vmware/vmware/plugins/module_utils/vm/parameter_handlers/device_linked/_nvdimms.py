"""
NVDIMM parameter handler for VM configuration.

This module provides the NvdimmParameterHandler class which manages NVDIMM
configuration including NVDIMM creation, modification, and controller assignment.
It handles NVDIMM parameter validation, device linking, and VMware specification
generation for NVDIMM operations.

NVDIMMs are unique, in that one controller must exist when any NVDIMM is present
and the user cannot manage the controller in the UI. It just appears.
Therefore, this handler manages the controller and the NVDIMMs together.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractDeviceLinkedParameterHandler,
    DeviceLinkError,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm.objects._nvdimm import (
    Nvdimm,
    NvdimmDeviceController,
)

try:
    from pyVmomi import vim
except ImportError:
    pass


class NvdimmParameterHandler(AbstractDeviceLinkedParameterHandler):
    """
    Handler for NVDIMM configuration parameters.

    Each NVDIMM configuration includes:
        - size_mb: NVDIMM size in MB
    """

    HANDLER_NAME = "nvdimm"

    def __init__(
        self, error_handler, params, change_set, vm, device_tracker, **kwargs
    ):
        """
        Initialize the NVDIMM parameter handler.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing NVDIMM configuration
            change_set: Service for tracking configuration changes and requirements
            vm: VM object being configured (None for new VM creation)
            device_tracker: Service for device identification and error reporting
        """
        super().__init__(error_handler, params, change_set, vm, device_tracker)
        self._check_if_params_are_defined_by_user("nvdimms", required_for_vm_creation=False)

        self.nvdimms = []
        self.controller = None

    @property
    def vim_device_class(self):
        """
        Get the VMware device class for this controller type.
        """
        return (vim.vm.device.VirtualNVDIMMController, vim.vm.device.VirtualNVDIMM)

    def verify_parameter_constraints(self):
        """
        Validate NVDIMM parameter constraints and requirements.

        Parses NVDIMM parameters and validates that at least one NVDIMM is defined
        for VM creation or modification. Validates that all required controllers
        exist and that NVDIMM specifications are valid.

        Raises:
            Calls error_handler.fail_with_parameter_error() for invalid NVDIMM
            parameters, missing controllers, or missing NVDIMM definitions.
        """
        if len(self.nvdimms) == 0:
            try:
                self._parse_nvdimm_params()
            except ValueError as e:
                self.error_handler.fail_with_parameter_error(
                    parameter_name="nvdimms",
                    message="Error parsing NVDIMM parameters: %s" % str(e),
                    details={"error": str(e)},
                )

    def _parse_nvdimm_params(self):
        """
        Parse NVDIMM parameters and create Nvdimm objects.

        Processes the NVDIMM parameter list, validates device node specifications,
        and creates Nvdimm objects with proper controller assignments. Validates
        that all required controllers exist and are configured.

        Side Effects:
            Populates self.nvdimms with Nvdimm objects representing desired configuration.
            Populates self.controller with NvdimmDeviceController object representing the controller.
        """
        nvdimm_params = self.params.get("nvdimms") or []
        if len(nvdimm_params) != 0:
            self.controller = NvdimmDeviceController()

        for index, nvdimm_param in enumerate(nvdimm_params):
            nvdimm = Nvdimm(
                size_mb=nvdimm_param.get("size_mb"),
                index=index,
                controller=self.controller,
            )
            self.nvdimms.append(nvdimm)

    def populate_config_spec_with_parameters(self, configspec):
        """
        Populate VMware configuration specification with NVDIMM parameters.

        Adds NVDIMM device specifications to the configuration for both new
        NVDIMM creation and existing NVDIMM modification. Tracks device IDs
        for proper error reporting and device management.
        This includes the controller and the NVDIMMs.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Adds NVDIMM device specifications to configspec.deviceChange.
            Adds controller device specification to configspec.deviceChange.
            Tracks device IDs through device_tracker for error reporting.
        """
        for nvdimm_obj in self.change_set.objects_to_add:
            self.device_tracker.track_device_id_from_spec(nvdimm_obj)
            configspec.deviceChange.append(nvdimm_obj.to_new_spec())
        for nvdimm_obj in self.change_set.objects_to_update:
            self.device_tracker.track_device_id_from_spec(nvdimm_obj)
            configspec.deviceChange.append(nvdimm_obj.to_update_spec())

    def compare_live_config_with_desired_config(self):
        """
        Compare current VM NVDIMM configuration with desired configuration.

        Analyzes each NVDIMM to determine if it needs to be added, updated,
        or is already in sync with the desired configuration. Categorizes
        NVDIMMs based on their current state and required changes.
        Controllers cannot be modified, so we only care if it needs to be added.

        Returns:
            ParameterChangeSet: Updated change set with NVDIMM change requirements

        Side Effects:
            Updates change_set with NVDIMM objects categorized by required actions.
        """
        if self.controller is not None and not self.controller.has_a_linked_live_vm_device():
            self.change_set.objects_to_add.append(self.controller)

        for nvdimm in self.nvdimms:
            if not nvdimm.has_a_linked_live_vm_device():
                self.change_set.objects_to_add.append(nvdimm)
            elif nvdimm.differs_from_live_object():
                self.change_set.objects_to_update.append(nvdimm)

        return self.change_set

    def link_vm_device(self, device):
        """
        Link a VMware NVDIMM device to the appropriate NVDIMM object.

        Matches a VMware NVDIMM device to the corresponding NVDIMM object based
        on controller key and unit number. This establishes the connection
        between the existing VM device and the handler's NVDIMM representation.

        Args:
            device: VMware VirtualNVDIMM device to link

        Returns:
            Object or None: None if the device was successfully linked, otherwise
            an object representing the unlinked device.

        Side Effects:
            Sets the _device attribute on the matching disk object.
        """
        if isinstance(device, vim.vm.device.VirtualNVDIMMController):
            output = self._link_nvdimm_controller(device)
        elif isinstance(device, vim.vm.device.VirtualNVDIMM):
            output = self._link_nvdimm_device(device)
        else:
            raise DeviceLinkError("Unsupported device type %s" % type(device).__name__)

        if self.params.get("nvdimms_remove_unmanaged"):
            # return a representation of the unlinked device, so we can remove it
            return output
        else:
            # return nothing, so even if the device wasn't linked, the module
            # doesn't try to remove it
            return None

    def _link_nvdimm_device(self, device):
        for param_nvdimm in self.nvdimms:
            if not param_nvdimm.has_a_linked_live_vm_device():
                param_nvdimm.link_corresponding_live_object(
                    Nvdimm.from_live_device_spec(device, self.controller)
                )
                return

        return Nvdimm.from_live_device_spec(device, self.controller)

    def _link_nvdimm_controller(self, device):
        if not self.controller.has_a_linked_live_vm_device():
            self.controller.link_corresponding_live_object(
                NvdimmDeviceController.from_live_device_spec(device)
            )
            return

        return NvdimmDeviceController.from_live_device_spec(device)
