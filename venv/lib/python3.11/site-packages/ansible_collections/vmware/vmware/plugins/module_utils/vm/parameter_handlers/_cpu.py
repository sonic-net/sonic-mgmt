"""
CPU parameter handler for VM configuration.

This module provides parameter handlers for CPU configuration,
including validation of resource constraints, hot-add/remove capabilities,
and power cycle requirements. This handler manages the computational
resources of virtual machines.

The handler supports CPU hot-add/remove operations when the VM is powered on,
with appropriate validation and error handling for unsupported operations.
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


class CpuParameterHandler(AbstractParameterHandler):
    """
    Handler for CPU configuration parameters.

    This handler manages CPU-related VM settings including core count,
    cores per socket, performance counters, and hot-add/remove capabilities.
    It validates CPU topology constraints and handles power cycle requirements
    for configuration changes.

    The handler supports CPU hot-add/remove operations when enabled, allowing
    CPU changes without VM power cycling. It enforces proper CPU topology
    validation and handles the relationship between total cores and cores per socket.

    Managed Parameters:
    - cpu.cores: Total number of CPU cores
    - cpu.cores_per_socket: Number of cores per CPU socket
    - cpu.enable_performance_counters: Enable vPMC performance counters
    - cpu.enable_hot_add: Enable CPU hot-add capability
    - cpu.enable_hot_remove: Enable CPU hot-remove capability
    - cpu.shares: Custom number of shares of CPU allocated to this virtual machine
    - cpu.shares_level: The allocation level of CPU resources for the virtual machine
    - cpu.limit: The maximum number of CPUs the VM can use
    - cpu.reservation: The amount of CPU resource that is guaranteed available to the virtual machine

    Attributes:
        cpu_params (dict): CPU-specific parameters from module input.
    """

    HANDLER_NAME = "cpu"

    def __init__(self, error_handler, params, change_set, vm, **kwargs):
        """
        Initialize the CPU parameter handler.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing VM configuration
            change_set: Service for tracking configuration changes and requirements
            vm: VM object being configured (None for new VM creation)
            **kwargs: Additional keyword arguments. Other handlers may require specific
                      services and allowing kwargs makes initialization more flexible.
        """
        super().__init__(error_handler, params, change_set, vm)
        self._check_if_params_are_defined_by_user("cpu", required_for_vm_creation=True)
        self.cpu_params = self.params.get("cpu") or {}

    def verify_parameter_constraints(self):
        """
        Validate CPU parameter constraints and relationships.

        Validates the relationship between total cores and cores per socket,
        ensuring that total cores is evenly divisible by cores per socket.
        For new VM creation, validates that required parameters are present.

        Raises:
            Calls error_handler.fail_with_parameter_error() for invalid CPU topology
            or missing required parameters for VM creation.
        """
        self._validate_cpu_socket_relationship()
        if self.vm is None:
            self._validate_params_for_creation()

    def _validate_cpu_socket_relationship(self):
        """
        Validate that total cores is evenly divisible by cores per socket.

        Ensures valid CPU topology by verifying that the total number of
        CPU cores can be evenly distributed across the specified number
        of cores per socket.

        Raises:
            Calls error_handler.fail_with_parameter_error() if cores is not
            evenly divisible by cores_per_socket.
        """
        cores = self.cpu_params.get("cores", 0)
        # this cannot be 0 since it is used as a denominator, but 1 will still work
        cores_per_socket = self.cpu_params.get("cores_per_socket", 1)

        if cores and cores_per_socket and cores % cores_per_socket != 0:
            self.error_handler.fail_with_parameter_error(
                parameter_name="cpu.cores",
                message="cpu.cores must be a multiple of cpu.cores_per_socket",
                details={"cores": cores, "cores_per_socket": cores_per_socket},
            )

    def _validate_params_for_creation(self):
        """
        Validate required parameters for new VM creation.

        Ensures that essential CPU parameters are provided when creating
        a new VM. The cores parameter is mandatory for VM creation.

        Raises:
            Calls error_handler.fail_with_parameter_error() for missing
            required parameters.
        """
        self._validate_cpu_socket_relationship()
        if not self.cpu_params.get("cores"):
            self.error_handler.fail_with_parameter_error(
                parameter_name="cpu.cores",
                message="cpu.cores attribute is mandatory for VM creation",
            )

    def populate_config_spec_with_parameters(self, configspec):
        """
        Update VMware configuration specification with CPU parameters.

        Maps CPU parameters to the appropriate VMware configuration
        specification attributes. Only sets parameters that are explicitly
        provided by the user.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Modifies configspec with CPU-related settings including core count,
            cores per socket, performance counters, and hot-add/remove capabilities.
        """
        param_to_configspec_attr = {
            "cores": "numCPUs",
            "cores_per_socket": "numCoresPerSocket",
            "enable_hot_add": "cpuHotAddEnabled",
            "enable_hot_remove": "cpuHotRemoveEnabled",
            "enable_performance_counters": "vPMCEnabled",
        }
        for param_name, configspec_attr in param_to_configspec_attr.items():
            value = self.cpu_params.get(param_name)
            if value is not None:
                setattr(configspec, configspec_attr, value)

        self._populate_config_spec_with_cpu_allocation_parameters(configspec)

    def compare_live_config_with_desired_config(self):
        """
        Compare current VM CPU configuration with desired configuration.

        Detects differences between current and desired CPU settings,
        handling special cases for hot-add/remove operations. Most CPU
        changes require a power cycle unless hot-add/remove is enabled.

        Side Effects:
            Updates change_set with detected configuration differences.
            May handle CPU hot-add/remove operations without power cycling.
        """
        self._check_cpu_changes_with_hot_add_remove()

        # Define parameter mappings for change detection
        param_mappings = [
            ("cpu.cores_per_socket", "config.hardware.numCoresPerSocket"),
            ("cpu.enable_hot_add", "config.cpuHotAddEnabled"),
            ("cpu.enable_hot_remove", "config.cpuHotRemoveEnabled"),
            ("cpu.enable_performance_counters", "config.vPMCEnabled"),
            ("cpu.shares", "config.cpuAllocation.shares.shares"),
            ("cpu.limit", "config.cpuAllocation.limit"),
            ("cpu.reservation", "config.cpuAllocation.reservation"),
        ]

        for param_name, attribute_path in param_mappings:
            self.change_set.check_if_change_is_required(
                param_name, attribute_path, power_sensitive=True
            )

        if self.cpu_params.get("shares") is None:
            self.change_set.check_if_change_is_required(
                "cpu.shares_level",
                "config.cpuAllocation.shares.level",
                power_sensitive=True,
            )

    def _check_cpu_changes_with_hot_add_remove(self):
        """
        Check CPU core changes with hot-add/remove capability consideration.

        Validates CPU core changes against hot-add/remove capabilities.
        If hot-add/remove is enabled, allows CPU changes without power cycling.
        Otherwise, requires power cycle or fails with appropriate error.

        Raises:
            Calls error_handler.fail_with_power_cycle_error() if CPU changes
            are attempted without appropriate hot-add/remove capabilities.

        Side Effects:
            May disable power_cycle_required flag if hot-add/remove is enabled.
        """
        try:
            self.change_set.check_if_change_is_required(
                "cpu.cores",
                "config.hardware.numCPU",
                power_sensitive=True,
                errors_fatal=False,
            )
        except PowerCycleRequiredError:
            cores = self.cpu_params.get("cores")
            current_cores = self.vm.config.hardware.numCPU
            if cores < current_cores and not self.vm.config.cpuHotRemoveEnabled:
                self.error_handler.fail_with_power_cycle_error(
                    parameter_name="cpu.cores",
                    message="CPUs cannot be decreased while the VM is powered on, "
                    "unless CPU hot remove is already enabled.",
                    details={
                        "cores": cores,
                        "current_cores": current_cores,
                        "cpu_hot_remove_enabled": self.vm.config.cpuHotRemoveEnabled,
                    },
                )
            if cores > current_cores and not self.vm.config.cpuHotAddEnabled:
                self.error_handler.fail_with_power_cycle_error(
                    parameter_name="cpu.cores",
                    message="CPUs cannot be increased while the VM is powered on, "
                    "unless CPU hot add is already enabled.",
                    details={
                        "cores": cores,
                        "current_cores": current_cores,
                        "cpu_hot_add_enabled": self.vm.config.cpuHotAddEnabled,
                    },
                )
            # hot add/remove is allowed, so we can proceed with the change without power cycling
            self.change_set.power_cycle_required = False

    def _populate_config_spec_with_cpu_allocation_parameters(self, configspec):
        """
        Populate the configspec with the CPU allocation resource parameters.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Modifies configspec with CPU allocation parameters, like shares, limit, reservation.
        """
        shares_level_param = self.cpu_params.get("shares_level")
        shares_param = self.cpu_params.get("shares")
        limit_param = self.cpu_params.get("limit")
        reservation_param = self.cpu_params.get("reservation")

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

        configspec.cpuAllocation = allocation
