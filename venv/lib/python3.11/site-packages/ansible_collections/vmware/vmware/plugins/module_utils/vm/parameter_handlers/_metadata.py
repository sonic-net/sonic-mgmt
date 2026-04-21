"""
VM metadata parameter handler for high-level VM configuration.

This module handles fundamental VM properties such as name, guest operating
system ID, and datastore placement. These are considered metadata because
they define the VM's identity and basic characteristics rather than specific
hardware configurations.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractParameterHandler,
)

try:
    from pyVmomi import vim
except ImportError:
    pass


class MetadataParameterHandler(AbstractParameterHandler):
    """
    Handler for VM metadata parameters like name, guest ID, and basic file store structure.

    This handler manages the basic VM identity and placement properties. It handles
    validation of required parameters for new VMs and ensures proper datastore
    configuration.

    Managed Parameters:
    - name: VM display name
    - guest_id: Guest operating system identifier
    - datastore: Storage location for VM files
    - hardware_version: Hardware version for VM

    Attributes:
        placement: Placement service for VM placement resolution
    """

    HANDLER_NAME = "metadata"

    def __init__(self, error_handler, params, change_set, vm, placement, **kwargs):
        """
        Initialize the metadata parameter handler.

        Args:
            error_handler: Error handling service for parameter validation failures
            params (dict): Module parameters containing VM configuration
            change_set: Change tracking service for detecting configuration differences
            vm: Existing VM object (None for new VM creation)
            placement: Placement service for cluster resource resolution
            **kwargs: Additional keyword arguments. Other handlers may require specific
                      services and allowing kwargs makes initialization more flexible.
        """
        super().__init__(error_handler, params, change_set, vm)
        self.placement = placement

    def verify_parameter_constraints(self):
        """
        Validate required parameters for VM creation.

        For new VM creation, ensures that essential metadata parameters
        (name, guest_id, datastore) are provided by the user. These are
        fundamental requirements that cannot be inferred or defaulted.
        """
        if self.vm is None:
            for param in ["name", "guest_id", "datastore"]:
                if not self.params.get(param):
                    self.error_handler.fail_with_parameter_error(
                        parameter_name=param,
                        message="%s is a required parameter for VM creation." % param,
                    )

    def compare_live_config_with_desired_config(self):
        """
        Compare current VM metadata with desired configuration.

        Checks if the VM's current name and guest ID match the desired
        values specified in the module parameters. Uses the change set
        service to track which properties need updates.
        """
        self.change_set.check_if_change_is_required("name", "name")
        self.change_set.check_if_change_is_required("guest_id", "config.guestId")

    def populate_config_spec_with_parameters(self, configspec):
        """
        Populate VMware configuration specification with metadata parameters.

        Sets the VM name, guest ID, and file location in the configuration
        specification. For new VMs, establishes the initial file structure
        and datastore placement using the placement service.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Modifies configspec with VM name, guest ID, and file location.
            For new VMs, sets up initial datastore placement structure.
        """
        if self.params.get("name"):
            configspec.name = self.params["name"]
        elif self.vm is not None:
            configspec.name = self.vm.name

        if self.vm is None:
            configspec.files = vim.vm.FileInfo(
                logDirectory=None,
                snapshotDirectory=None,
                suspendDirectory=None,
                vmPathName="[%s]" % self.placement.get_datastore().name,
            )

        if self.params.get("guest_id"):
            configspec.guestId = self.params["guest_id"]

        # only apply hardware version if we are creating a new VM, upgrading is not supported
        # in this module
        if self.params.get("hardware_version") and self.vm is None:
            configspec.version = "vmx-%02d" % self.params["hardware_version"]
