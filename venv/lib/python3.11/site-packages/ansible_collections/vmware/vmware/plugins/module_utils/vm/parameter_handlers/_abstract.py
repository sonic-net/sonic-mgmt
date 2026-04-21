"""
Abstract base classes for VM parameter handlers.

This module defines the base classes that establish the parameter handler
architecture. All parameter handlers follow a consistent three-phase pattern
for processing VM configuration parameters: validation, change detection,
and configuration specification population.

The architecture supports two main handler types:
- AbstractParameterHandler handlers: Process VM-level settings (CPU, memory, metadata)
- Device-linked handlers: Manage parameters tied to specific devices (controllers, disks)
"""

from abc import ABC, abstractmethod


class AbstractParameterHandler(ABC):
    """
    Base class for all VM parameter handlers.

    This abstract class establishes the fundamental interface that all
    parameter handlers must implement. It defines the three-phase pattern
    for parameter processing and provides common initialization for error
    handling, parameter access, and change tracking.

    The three phases are:
    1. Parameter validation (verify_parameter_constraints)
    2. Change detection (compare_live_config_with_desired_config)
    3. Specification population (populate_config_spec_with_parameters)

    This pattern ensures consistent behavior across all parameter types
    while allowing specialized implementations for different VM components.

    Attributes:
        error_handler: Service for handling parameter validation errors
        params (dict): Module parameters containing desired configuration
        change_set: Service for tracking configuration changes
    """

    HANDLER_NAME = None
    PARAMS_DEFINED_BY_USER = True

    def __init__(self, error_handler, params, change_set, vm):
        """
        Initialize the parameter handler with common dependencies.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing desired VM configuration
            change_set: Service for tracking configuration changes and requirements
            vm: VM object being configured (None for new VM creation)
        """
        if self.HANDLER_NAME is None or not self.HANDLER_NAME:
            raise NotImplementedError(
                "ParameterHandler subclasses must define the HANDLER_NAME attribute"
            )

        self.vm = vm
        self.error_handler = error_handler
        self.params = params
        self.change_set = change_set

    def _check_if_params_are_defined_by_user(
        self, parameter_name, required_for_vm_creation=False
    ):
        """
        Check if the relevant parameters are defined by the user, and update internal
        flag appropriately.
        Optionally fail if the parameters are not defined by the user, and if the vm is None,
        meaning the parameters are required for VM creation.

        """
        if self.params.get(parameter_name) is None:
            self.PARAMS_DEFINED_BY_USER = False
            if self.vm is None and required_for_vm_creation:
                self.error_handler.fail_with_parameter_error(
                    parameter_name=parameter_name,
                    message="The %s parameter is mandatory for VM creation"
                    % parameter_name,
                )
            return

    @abstractmethod
    def verify_parameter_constraints(self):
        """
        Validate parameters for creation and modification operations.

        This method should check parameter values, combinations, and constraints
        specific to the handler's domain. It should validate both individual
        parameter values and cross-parameter relationships.

        Raises:
            Should call error_handler methods to report validation failures.
            The module will terminate if parameters are invalid.

        Note:
            This method should try to not perform vSphere API calls or access live VM state.
            It should only validate the input parameters themselves.
            This will allow the user to be alerted to invalid parameters more quickly, since
            configuration can take a non-trivial amount of time.
        """
        raise NotImplementedError

    @abstractmethod
    def populate_config_spec_with_parameters(self, configspec):
        """
        Update a configuration specification with parameters for this handler.

        This method should map module parameters to the appropriate VMware
        configuration specification fields. It should only set parameters
        that are explicitly provided by the user, allowing other handlers
        to manage their own configuration domains.

        Args:
            configspec: VMware configuration specification object to update

        Side Effects:
            Modifies the configspec object with parameter values.
            Should not modify parameters managed by other handlers.

        Note:
            For parameters not specified by the user, the handler should either
            omit them (preserving existing values) or use appropriate defaults.
        """
        raise NotImplementedError

    @abstractmethod
    def compare_live_config_with_desired_config(self):
        """
        Check if current VM configuration differs from desired configuration.

        This method should compare the current VM state with the desired
        state specified in the module parameters. It should identify what
        changes are needed without performing the actual changes.

        The method should use the change_set service to record detected
        differences. It should not validate parameters (that's done separately)
        or return information about what specific values differ.

        Side Effects:
            Updates change_set with detected configuration differences.
            May set flags for operations requiring VM power cycles.

        Note:
            This method should focus on detection, not validation or modification.
            It should work with live VM objects and vSphere API data.
        """
        raise NotImplementedError


class AbstractDeviceLinkedParameterHandler(AbstractParameterHandler):
    """
    Base class for parameter handlers that manage VM hardware devices.

    This class extends AbstractParameterHandler for handlers that work with
    specific hardware devices like controllers and disks. It provides device
    linking capabilities and enforces that subclasses specify their VMware
    device class.

    Device-linked handlers must:
    1. Define vim_device_class to specify the VMware device type
    2. Implement link_vm_device() to associate existing devices with handler objects
    3. Use device_tracker for device identification and error reporting

    Attributes:
        vim_device_class: VMware device class(es) this handler manages (must be overridden)
        device_type_to_sub_class_map (dict): Registry of device types to handler classes
        device_tracker: Service for device identification and error reporting
        managed_parameter_objects (dict[any,AbstractVsphereObject]): Dictionary of parameter objects managed by this handler
    """

    def __init__(self, error_handler, params, change_set, vm, device_tracker):
        """
        Initialize a device-linked parameter handler.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing desired device configuration
            change_set: Service for tracking configuration changes and requirements
            device_tracker: Service for device identification and error reporting

        Raises:
            NotImplementedError: If vim_device_class is not defined by subclass
        """
        super().__init__(error_handler, params, change_set, vm)
        self.managed_parameter_objects = dict()  # {key: parameter_object}
        self.device_tracker = device_tracker

    @property
    @abstractmethod
    def vim_device_class(self):
        """
        Get the VMware device class this handler manages. This is a property so vim imports can
        be done lazily, and not cause sanity checks to fail.
        Can be a single class, or a tuple of classes.
        """
        raise NotImplementedError

    @property
    def device_type_to_sub_class_map(self):
        """
        Get a map of device types to their corresponding sub-classes. This is a property so vim imports can
        be done lazily, and not cause sanity checks to fail.

        Returns:
            dict: A dictionary mapping device types to their corresponding sub-classes.
        """
        return dict()

    @abstractmethod
    def link_vm_device(self, device):
        """
        Link a vSphere device to the handler's managed objects.

        This method should validate that the provided device matches an object
        managed by this handler and establish the connection between the VMware
        device and the handler's internal representation.

        For example, a disk handler should verify that the device is a disk
        it recognizes and link it to the appropriate disk object for change
        detection and configuration management.

        Args:
            device: VMware device object to link to the handler

        Raises:
            Should raise appropriate errors if the device doesn't match any
            managed objects or if linking fails for other reasons.

        Side Effects:
            Establishes connection between VMware device and handler objects.
            May update internal state to track device relationships.
        """
        raise NotImplementedError

    def populate_config_spec_with_parameters(self, configspec):
        """
        Populate VMware configuration specification with device linked parameters.

        Adds device specifications to the configuration for both new
        device creation and existing device modification. Tracks device IDs
        for proper error reporting and device management.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Adds device specifications to configspec.deviceChange.
            Tracks device IDs through device_tracker for error reporting.
        """
        for device_object in self.change_set.objects_to_add:
            self.device_tracker.track_device_id_from_spec(device_object)
            configspec.deviceChange.append(device_object.to_new_spec())
        for device_object in self.change_set.objects_to_update:
            self.device_tracker.track_device_id_from_spec(device_object)
            configspec.deviceChange.append(device_object.to_update_spec())

    def compare_live_config_with_desired_config(self):
        """
        Compare current VM device configuration with desired configuration.

        Analyzes each device to determine if it needs to be added, updated,
        or is already in sync with the desired configuration. Categorizes
        devices based on their current state and required changes.

        Returns:
            ParameterChangeSet: Updated change set with device change requirements

        Side Effects:
            Updates change_set with device objects categorized by required actions.
        """
        for device_object in self.managed_parameter_objects.values():
            if not device_object.has_a_linked_live_vm_device():
                self.change_set.objects_to_add.append(device_object)
            elif device_object.differs_from_live_object():
                self.change_set.objects_to_update.append(device_object)

        return self.change_set


class DeviceLinkError(Exception):
    """
    Exception raised when a device cannot be linked to a parameter handler.
    """

    pass
