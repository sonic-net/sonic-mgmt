"""
Memory parameter handler for VM configuration.

This module provides parameter handlers for memory configuration,
including validation of resource constraints, hot-add capabilities,
and power cycle requirements. This handler manages the memory
resources of virtual machines.

Memory in VMware VMs cannot be decreased once allocated, only increased.
The handler supports memory hot-add when enabled, allowing memory
increases without VM power cycling.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractParameterHandler,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm._change_set import (
    PowerCycleRequiredError,
)

try:
    from pyVmomi import vim
except ImportError:
    pass


class MemoryParameterHandler(AbstractParameterHandler):
    """
    Handler for memory configuration parameters.

    This handler manages memory-related VM settings including memory size
    and hot-add capabilities. It enforces memory constraints such as
    preventing memory decrease and validates memory hot-add operations.

    Memory in VMware VMs cannot be decreased once allocated, only increased.
    The handler supports memory hot-add when enabled, allowing memory
    increases without VM power cycling.

    Managed Parameters:
    - memory.size_mb: Memory size in megabytes
    - memory.enable_hot_add: Enable memory hot-add capability
    - memory.shares: Custom number of shares of memory allocated to the virtual machine
    - memory.shares_level: The allocation level of memory resource for the virtual machine
    - memory.limit: Maximum amount of memory that the virtual machine can use
    - memory.reservation: Minimum amount of memory that the virtual machine must have
    - memory.reserve_all_memory: Whether to reserve (lock) all memory allocated for the VM

    Attributes:
        memory_params (dict): Memory-specific parameters from module input
    """

    HANDLER_NAME = "memory"

    def __init__(self, error_handler, params, change_set, vm, **kwargs):
        """
        Initialize the memory parameter handler.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing VM configuration
            change_set: Service for tracking configuration changes and requirements
            vm: VM object being configured (None for new VM creation)
            **kwargs: Additional keyword arguments. Other handlers may require specific
                      services and allowing kwargs makes initialization more flexible.
        """
        super().__init__(error_handler, params, change_set, vm)
        self._check_if_params_are_defined_by_user(
            "memory", required_for_vm_creation=True
        )
        self.memory_params = self.params.get("memory") or {}

    def verify_parameter_constraints(self):
        """
        Validate memory parameter constraints and requirements.

        For new VM creation, validates that required memory parameters
        are present. For existing VMs, enforces that memory cannot be
        decreased from its current value.

        Raises:
            Calls error_handler.fail_with_parameter_error() for missing
            required parameters or invalid memory decrease attempts.
        """
        self._verify_memory_size_parameter_constraints()
        self._verify_reservation_parameter_constraints()

    def _verify_memory_size_parameter_constraints(self):
        memory_size_mb = self.memory_params.get("size_mb")
        if self.vm is None:
            if memory_size_mb is None:
                self.error_handler.fail_with_parameter_error(
                    parameter_name="memory.size_mb",
                    message="memory.size_mb attribute is mandatory for VM creation",
                )

            return

        if (
            memory_size_mb is not None
            and memory_size_mb < self.vm.config.hardware.memoryMB
        ):
            self.error_handler.fail_with_parameter_error(
                parameter_name="memory.size_mb",
                message="Memory cannot be decreased once added to a VM.",
                details={
                    "size_mb": memory_size_mb,
                    "current_size_mb": self.vm.config.hardware.memoryMB,
                },
            )

    def _verify_reservation_parameter_constraints(self):
        if self.memory_params.get("reservation") is None:
            return

        memory_size_mb = (
            self.memory_params.get("size_mb") or self.vm.config.hardware.memoryMB
        )
        if memory_size_mb < self.memory_params.get("reservation"):
            self.error_handler.fail_with_parameter_error(
                parameter_name="memory.reservation",
                message="Memory reservation cannot be greater than the VM's memory size.",
                details={
                    "size_mb": memory_size_mb,
                    "reservation": self.memory_params.get("reservation"),
                },
            )

    def populate_config_spec_with_parameters(self, configspec):
        """
        Update VMware configuration specification with memory parameters.

        Maps memory parameters to the appropriate VMware configuration
        specification attributes. Only sets parameters that are explicitly
        provided by the user.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Modifies configspec with memory-related settings including size
            and hot-add capabilities.
        """
        param_to_configspec_attr = {
            "enable_hot_add": "memoryHotAddEnabled",
            "size_mb": "memoryMB",
            "reserve_all_memory": "memoryReservationLockedToMax",
        }
        for param_name, configspec_attr in param_to_configspec_attr.items():
            value = self.memory_params.get(param_name)
            if value is not None:
                setattr(configspec, configspec_attr, value)

        self._populate_config_spec_with_memory_allocation_parameters(configspec)

    def compare_live_config_with_desired_config(self):
        """
        Compare current VM memory configuration with desired configuration.

        Detects differences between current and desired memory settings,
        handling special cases for hot-add operations. Memory increases
        require a power cycle unless hot-add is enabled.
        """
        self._check_memory_changes_with_hot_add()
        param_mappings = [
            ("memory.enable_hot_add", "config.memoryHotAddEnabled"),
            ("memory.shares", "config.memoryAllocation.shares.shares"),
            ("memory.limit", "config.memoryAllocation.limit"),
            ("memory.reservation", "config.memoryAllocation.reservation"),
            ("memory.reserve_all_memory", "config.memoryReservationLockedToMax"),
        ]
        for param_name, attribute_path in param_mappings:
            self.change_set.check_if_change_is_required(
                param_name, attribute_path, power_sensitive=True
            )

        if self.memory_params.get("shares") is None:
            self.change_set.check_if_change_is_required(
                "memory.shares_level",
                "config.memoryAllocation.shares.level",
                power_sensitive=True,
            )

        return self.change_set

    def _check_memory_changes_with_hot_add(self):
        """
        Check memory changes with hot-add capability consideration.

        Validates memory size changes against hot-add capabilities.
        If hot-add is enabled, allows memory increases without power cycling.
        Otherwise, requires power cycle or fails with appropriate error.

        Raises:
            Calls error_handler.fail_with_power_cycle_error() if memory
            increases are attempted without hot-add capability.
        """
        try:
            self.change_set.check_if_change_is_required(
                "memory.size_mb",
                "config.hardware.memoryMB",
                power_sensitive=True,
                errors_fatal=False,
            )
        except PowerCycleRequiredError:
            size_mb = self.memory_params.get("size_mb")
            current_size_mb = self.vm.config.hardware.memoryMB
            if size_mb > current_size_mb and not self.vm.config.memoryHotAddEnabled:
                self.error_handler.fail_with_power_cycle_error(
                    parameter_name="memory.size_mb",
                    message="Memory cannot be increased while the VM is powered on, "
                    "unless memory hot add is already enabled.",
                    details={
                        "size_mb": size_mb,
                        "current_size_mb": current_size_mb,
                        "memory_hot_add_enabled": self.vm.config.memoryHotAddEnabled,
                    },
                )
            # hot add is allowed, so we can proceed with the change without power cycling
            self.change_set.power_cycle_required = False

    def _populate_config_spec_with_memory_allocation_parameters(self, configspec):
        """
        Populate the configspec with the memory allocation resource parameters.
        Args:
            configspec: VMware VirtualMachineConfigSpec to populate
        Side Effects:
            Modifies configspec with memory allocation parameters, like shares, limit, reservation.
        """
        shares_level_param = self.memory_params.get("shares_level")
        shares_param = self.memory_params.get("shares")
        limit_param = self.memory_params.get("limit")
        reservation_param = self.memory_params.get("reservation")

        if (
            shares_level_param is None
            and shares_param is None
            and limit_param is None
            and reservation_param is None
        ):
            return

        allocation = vim.ResourceAllocationInfo()
        if shares_level_param is not None or shares_param is not None:
            shares_info = vim.SharesInfo()
            if shares_param is not None:
                shares_info.level = "custom"
                shares_info.shares = shares_param
            else:
                shares_info.level = shares_level_param
            allocation.shares = shares_info

        if limit_param is not None:
            allocation.limit = limit_param

        if reservation_param is not None:
            allocation.reservation = reservation_param

        configspec.memoryAllocation = allocation
