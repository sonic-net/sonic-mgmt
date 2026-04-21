"""
Error handling service for VM configuration management.

This module provides the ErrorHandler service, which centralizes error handling
and reporting for the VM configuration system. It provides standardized error
messages and integrates with Ansible's module failure mechanisms.
"""

import re

try:
    from pyVmomi import vim
except ImportError:
    pass

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.vmware.vmware.plugins.module_utils.vm.services._abstract import (
    AbstractService,
)


class ErrorHandler(AbstractService):
    """
    Service for handling and reporting VM configuration errors.

    This service provides a centralized way to handle different types of errors
    that can occur during VM configuration. It formats error messages consistently
    and integrates with Ansible's module failure system to provide structured
    error information.

    The service supports different error categories, such as:
    - Parameter validation errors
    - Power cycle requirement errors
    - Device configuration errors
    """

    def __init__(self, module, device_tracker):
        """
        Initialize the error handler.

        Args:
            module: Ansible module instance for reporting failures
        """
        self.module = module
        self.device_tracker = device_tracker

    def _generic_fail_json(self, parameter_name, message, error_code, details=None):
        """
        Generic helpermethod for failing with structured error information.

        This method provides a consistent structure for all error failures,
        including parameter names, error codes, and additional details.

        Args:
            parameter_name (str): Name of the parameter causing the error
            message (str): Human-readable error message
            error_code (str): Structured error code for programmatic handling
            details (dict, optional): Additional error details

        Side Effects:
            Calls module.fail_json() which terminates module execution
        """
        if details is None:
            details = dict()
        details["parameter_name"] = parameter_name
        self.module.fail_json(msg=message, error_code=error_code, details=details)

    def fail_with_power_cycle_error(self, parameter_name, message=None, details=None):
        """
        Fail due to a parameter change requiring VM power cycling.

        This method is called when a parameter change requires the VM to be
        powered off, but power cycling is not allowed by the module configuration.

        Args:
            parameter_name (str): Name of the parameter requiring power cycling
            message (str, optional): Custom error message. If None, a default message is used
            details (dict, optional): Additional error details

        Side Effects:
            Calls module.fail_json() which terminates module execution
        """
        if message is None:
            message = (
                "Configuring %s is not supported while the VM is powered on."
                % parameter_name
            )
        self._generic_fail_json(
            parameter_name, message, "POWER_CYCLE_REQUIRED", details
        )

    def fail_with_generic_power_cycle_error(self, desired_power_state):
        """
        Fail with a more generic message related to power cycling. This error is not tied to a
        specific parameter and should only be used as a fallback/safety net.
        The use case would be that the module knows the VM needs to be powered off in the main module flow,
        but for whatever reason the parameter handlers did not verify that the power cycle is allowed.

        Args:
            desired_power_state (str): The desired power state of the VM. "powered off" or "powered on", usually

        """
        message = (
            "VM needs to be %s to make changes. You can allow this module to "
            "automatically power cycle the VM with the allow_power_cycling parameter."
            % desired_power_state
        )
        self.module.fail_json(msg=message, error_code="POWER_CYCLE_REQUIRED")

    def fail_with_parameter_error(self, parameter_name, message, details=None):
        """
        Fail due to invalid or problematic parameter values.

        This method is called when parameter validation fails or when
        parameters have invalid values or combinations.

        Args:
            parameter_name (str): Name of the problematic parameter
            message (str): Description of the parameter problem
            details (dict, optional): Additional error details

        Side Effects:
            Calls module.fail_json() which terminates module execution
        """
        self._generic_fail_json(parameter_name, message, "PARAMETER_ERROR", details)

    def fail_with_vm_config_error(self, error, message=""):
        """
        Fail due to invalid VM configuration.
        """
        try:
            if isinstance(error, vim.fault.InvalidDeviceSpec) or re.search(
                r"Invalid [\w]+ for device", str(message)
            ):
                self._fail_with_device_configuration_error(error)
            else:
                self.module.fail_json(
                    msg=str(error.faultMessage[0].message),
                    error_code="VM_CONFIG_ERROR",
                    error_type=str(type(error)),
                    error_raw=to_native(error),
                )
        except Exception as excep:
            self._generic_fail_json(
                parameter_name="",
                message="Failed to configure VM: %s" % str(error),
                error_code="UNKNOWN_VM_CONFIG_ERROR",
                details=dict(
                    error_type=str(type(error)),
                    handler_exception=str(type(excep)),
                    handler_exception_message=str(excep),
                ),
            )

    def _fail_with_device_configuration_error(self, error):
        """
        Fail due to invalid device configuration.

        This method handles VMware API errors related to device configuration
        problems. It attempts to parse device IDs from error messages and
        provide detailed information about which device caused the problem.

        Args:
            error: VMware API error object containing device configuration details

        Side Effects:
            Calls module.fail_json() which terminates module execution
        """
        try:
            device_id = str(error).split("'")[1]
            device = self.device_tracker.translate_device_id_to_device(int(device_id))
        except (KeyError, IndexError):
            self.module.fail_json(
                msg="A device has an invalid configuration, so the VM cannot be configured.",
                error_code="UNKNOWN_VM_DEVICE_ERROR",
                original_error=error,
            )

        if device.represents_live_vm_device():
            action = "remove"
        elif device.has_a_linked_live_vm_device():
            action = "update"
        else:
            action = "add"

        self.module.fail_json(
            msg=(
                "Failed to %s device %s. Please check the device configuration and try again."
                % (action, device)
            ),
            original_error=str(error),
            device_action=action,
            violating_device=device._to_module_output(),
        )
