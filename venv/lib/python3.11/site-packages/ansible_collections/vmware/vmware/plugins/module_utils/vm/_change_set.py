"""
Change tracking system for VM parameter modifications.

This module provides the ParameterChangeSet class, which tracks changes to VM
parameters and manages power cycle requirements. It supports both individual
handler change tracking and aggregation of changes across multiple handlers.
"""

import functools
import operator


class PowerCycleRequiredError(Exception):
    """
    Exception raised when a parameter change requires VM power cycling.

    This exception is used in non-fatal error handling scenarios where
    the caller needs to decide whether the VM config allows the change
    or if the module should fail.
    """

    pass


class ParameterChangeSet:
    """
    Tracks parameter changes and power cycle requirements for VM configuration.

    This class implements change detection by comparing desired parameters
    with current VM state. It tracks whether any changes are required and
    whether those changes necessitate powering off the VM. Multiple change
    sets can be aggregated to determine overall configuration state.

    Attributes:
        params (dict): Module parameters containing desired configuration
        vm: vSphere VM object (None for new VMs)
        error_handler: Service for handling validation errors
        power_cycle_required (bool): Whether changes require VM power cycling
        objects_to_add (list): Objects that need to be added to the VM. May not be used, depending on the handler.
        objects_to_update (list): Objects that need to be updated on the VM. May not be used, depending on the handler.
        objects_to_remove (list): Objects that need to be removed from the VM. May not be used, depending on the handler.
        _changed_parameters (dict): Dictionary of changed parameters with old and new values
    Read-only Properties:
        changes (dict): Dictionary of all changes to the VM that would be done, including parameters with old and new values
    """

    def __init__(self, params, vm, error_handler):
        """
        Initialize the parameter change set.

        Args:
            params (dict): Module parameters containing desired configuration
            vm: vSphere VM object (None for new VMs)
            error_handler: Service for handling validation errors
        """
        self.params = params
        self.vm = vm
        self.error_handler = error_handler
        self.power_cycle_required = False
        self._changed_parameters = dict()
        self.objects_to_add = []
        self.objects_to_update = []
        self.objects_to_remove = []

    @property
    def changes(self):
        return {
            "changed_parameters": self._changed_parameters,
            "objects_to_add": [
                obj.to_change_set_output()["new_value"] for obj in self.objects_to_add
            ],
            "objects_to_update": [
                obj.to_change_set_output() for obj in self.objects_to_update
            ],
            "objects_to_remove": [
                obj.to_change_set_output()["old_value"]
                for obj in self.objects_to_remove
            ],
        }

    def are_changes_required(self):
        if self.vm is None:
            return True

        return any(
            [
                len(self._changed_parameters) > 0,
                len(self.objects_to_add) > 0,
                len(self.objects_to_update) > 0,
                len(self.objects_to_remove) > 0,
            ]
        )

    def check_if_change_is_required(
        self, parameter_name, vm_attribute, power_sensitive=False, errors_fatal=True
    ):
        """
        Check if a parameter change is required by comparing desired vs current state.

        This method compares a module parameter with the corresponding VM attribute
        to determine if a change is needed. It also handles power state validation
        for changes that require the VM to be powered off.

        Args:
            parameter_name (str): Dot-notation path to the parameter in module params
            vm_attribute (str): Dot-notation path to the attribute in the VM object
            power_sensitive (bool): Whether this change requires VM power cycling
            errors_fatal (bool): Whether to cause a module failure or raise an exception
                                 for power issues. A caller can handle an exception when
                                 that is appropriate; a module failure is fatal.

        Side Effects:
            Sets changed_parameters if parameter differs from VM state.
            Sets power_cycle_required to True if change needs power cycling.
            May call error_handler.fail_with_power_cycle_error() if errors_fatal=True.
            May raise PowerCycleRequiredError if errors_fatal=False.
        """
        self._check_if_param_differs_from_vm(parameter_name, vm_attribute)
        if parameter_name not in self._changed_parameters:
            return

        if power_sensitive and self.vm is not None:
            self._check_if_change_violates_power_state(
                parameter_name, errors_fatal=errors_fatal
            )

    def _check_if_param_differs_from_vm(self, parameter_name, vm_attribute):
        """
        Compare a parameter value with the corresponding VM attribute.

        Uses dot notation to navigate nested parameter and VM object structures.
        Sets _changed_parameters if values differ.

        Args:
            parameter_name (str): Dot-notation path to parameter (e.g., "cpu.cores")
            vm_attribute (str): Dot-notation path to VM attribute (e.g., "config.hardware.numCPU")

        Side Effects:
            Sets _changed_parameters if values differ.
            No action if parameter is not specified or values match.
        """
        try:
            param_value = functools.reduce(
                operator.getitem, parameter_name.split("."), self.params
            )
        except KeyError:
            return

        if param_value is None:
            # user did not specify this parameter, but ansible "set" it to None so
            # we missed the KeyError that would have been raised above.
            return

        try:
            vm_value = functools.reduce(getattr, vm_attribute.split("."), self.vm)
        except AttributeError:
            vm_value = None

        if param_value == vm_value:
            return

        self._changed_parameters[parameter_name] = {
            "old_value": vm_value,
            "new_value": param_value,
        }

    def _check_if_change_violates_power_state(self, parameter_name, errors_fatal=True):
        """
        Check if a required change violates VM power state constraints.

        Some VM configuration changes require the VM to be powered off. This
        method checks if the VM is powered on and handles the power cycle
        requirement based on module parameters and error handling preferences.

        Args:
            parameter_name (str): Name of the parameter requiring the change
            errors_fatal (bool): Whether to raise errors or exceptions

        Side Effects:
            Sets power_cycle_required to True if allow_power_cycling is enabled.
            Calls error_handler.fail_with_power_cycle_error() if errors_fatal=True.
            Raises PowerCycleRequiredError if errors_fatal=False.
        """
        power_state = self.vm.runtime.powerState
        if power_state != "poweredOn" or not self.are_changes_required():
            return

        if self.params.get("allow_power_cycling"):
            self.power_cycle_required = True
        elif errors_fatal:
            self.error_handler.fail_with_power_cycle_error(parameter_name)
        else:
            raise PowerCycleRequiredError(parameter_name)

    def propagate_required_changes_from(self, other):
        """
        Aggregate changes from another change set into this one.

        This method implements the aggregation logic for combining multiple
        handler change sets into a master change set. It uses logical OR
        operations to determine overall state.

        Args:
            other (ParameterChangeSet): Another change set to aggregate

        Raises:
            ValueError: If other is not a ParameterChangeSet instance

        Side Effects:
            Merges self._changed_parameters using other._changed_parameters.
            Updates power_cycle_required using logical OR with other.power_cycle_required.
        """
        if not hasattr(other, "_changed_parameters") and not hasattr(
            other, "power_cycle_required"
        ):
            raise ValueError("change_set must be an instance of ParameterChangeSet")

        self._changed_parameters.update(other._changed_parameters)
        self.objects_to_add.extend(other.objects_to_add)
        self.objects_to_update.extend(other.objects_to_update)
        self.objects_to_remove.extend(other.objects_to_remove)

        self.power_cycle_required = (
            self.power_cycle_required or other.power_cycle_required
        )
