"""
Main VM configuration orchestrator.

This module contains the Configurator class, which coordinates all parameter
handlers to validate, detect changes, and apply VM configuration modifications.
It implements a composite pattern where individual handlers track their own
changes and the configurator aggregates the overall state.
"""


class Configurator:
    """
    Main hardware configurator that orchestrates different hardware handlers.

    This class coordinates the VM configuration process by managing multiple
    parameter handlers (for example, CPU, memory, disks, controllers) and aggregating their
    change sets to determine overall VM configuration state. It follows a
    three-phase process: validation, change detection, and configuration application.
    """

    def __init__(self, device_tracker, vm, controller_handlers, handlers, change_set):
        """
        Initialize the configurator with all required components.

        Args:
            device_tracker: Service for tracking VMware devices and linking them to their place (ID) in the config spec
            vm: The vSphere VM object (or None for new VMs)
            controller_handlers: List of controller parameter handlers
            handlers: List of non-controller parameter handlers
            change_set: Master change set for aggregating all changes
        """
        self.device_tracker = device_tracker
        self.vm = vm
        # Controller handlers are separate from the other handlers because they need to
        # be processed and initiated before the disk params are parsed.
        self.controller_handlers = controller_handlers
        self.handlers = handlers
        self.all_handlers = self.controller_handlers + self.handlers
        self.change_set = change_set

    def prepare_parameter_handlers(self):
        """
        Validate all hardware parameters for VM creation.

        This method validates parameter constraints across all handlers and
        links existing VM devices to their appropriate handlers. Controller
        handlers are processed first because disk parameters depend on
        controllers being parsed and managed.

        Side Effects:
            - Calls verify_parameter_constraints() on all handlers
            - Links VM devices to their appropriate handlers
            - Sets change_set.objects_to_remove with devices that couldn't be linked
        """
        # Controller handlers need to be processed and initiated before the disk params are parsed
        for handler in self.controller_handlers:
            handler.verify_parameter_constraints()

        for handler in self.handlers:
            handler.verify_parameter_constraints()

        if self.vm is not None:
            self.device_tracker.link_vm_devices_to_handler_devices(
                self.vm.config.hardware.device,
                self.controller_handlers
                + [
                    handler
                    for handler in self.handlers
                    if hasattr(handler, "vim_device_class")
                ],
            )

    def stage_configuration_changes(self):
        """
        Check if current VM config differs from desired config.

        This method implements the change detection phase by having each handler
        compare its current configuration with the desired state. Individual
        handler change sets are then aggregated into the master change set.

        Returns:
            ParameterChangeSet: The master change set containing aggregated changes

        Side Effects:
            - Updates change_set.power_cycle_required based on handler states
        """
        for handler in self.all_handlers:
            handler.compare_live_config_with_desired_config()
            self.change_set.propagate_required_changes_from(handler.change_set)

        self.change_set.objects_to_remove = self.device_tracker.unlinked_devices

        return self.change_set

    def apply_staged_changes_to_config_spec(self, configspec):
        """
        Update config spec with all hardware parameters.

        This method applies all staged changes to the VMware configuration
        specification. It first removes unlinked devices, then allows each
        handler with pending changes to modify the config spec.

        Args:
            configspec: VMware VM configuration specification to modify
            **kwargs: Additional parameters passed to handlers

        Side Effects:
            - Modifies configspec.deviceChange for device removals
            - Allows handlers to modify configspec for their changes
            - Tracks device IDs for error reporting
        """
        for device in self.change_set.objects_to_remove:
            self.device_tracker.track_device_id_from_spec(device)
            configspec.deviceChange.append(device.to_removal_spec())

        for handler in self.all_handlers:
            if handler.change_set.are_changes_required():
                handler.populate_config_spec_with_parameters(configspec)
