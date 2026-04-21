"""
Network adapter parameter handler for VM network adapter configuration.

This module provides the NetworkAdapterParameterHandler class which manages virtual network adapter
configuration including network adapter creation, modification, and portgroup assignment.
It handles network adapter parameter validation, device linking, and VMware specification
generation for storage management.

The handler works closely with portgroup handlers to ensure proper network adapter
placement and validates network adapter parameters against available portgroups.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractDeviceLinkedParameterHandler,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm.objects._network_adapter import (
    NetworkAdapter,
    NetworkAdapterPortgroup,
    NetworkAdapterResourceAllocation,
)

try:
    from pyVmomi import vim
except ImportError:
    pass


class NetworkAdapterParameterHandler(AbstractDeviceLinkedParameterHandler):
    """
    Handler for virtual network adapter configuration parameters.

    This handler manages the creation, modification, and validation of virtual
    network adapters on VMs. It processes network adapter parameters, validates
    controller assignments, and generates VMware device specifications for network
    adapter operations.

    The handler requires coordination with controller handlers to ensure that
    network adapters are properly assigned to available controllers. It validates
    device specifications and ensures that all required controllers exist.

    Managed Parameters:
    - network_adapters: List of network adapter configurations with portgroup_name, adapter_type, and device_node

    Each network adapter configuration includes:
    - portgroup_name: Name of the portgroup or distributed virtual portgroup for this interface.
    - adapter_type: Type of the network adapter.
    - connect_at_power_on: Specifies whether or not to connect the network adapter when the virtual machine starts.
    - shares: The percentage of network resources allocated to the network adapter.
    - shares_level: The pre-defined allocation level of network resources for the network adapter.
    - reservation: The amount of network resources reserved for the network adapter.
    - limit: The maximum amount of network resources the network adapter can use.
    - mac_address: The MAC address of the network adapter.
    """

    HANDLER_NAME = "network_adapters"

    def __init__(
        self,
        error_handler,
        params,
        change_set,
        vm,
        device_tracker,
        vsphere_object_cache,
        **kwargs
    ):
        """
        Initialize the network adapter parameter handler.

        Args:
            error_handler: Service for parameter validation error handling
            params (dict): Module parameters containing network adapter configuration
            change_set: Service for tracking configuration changes and requirements
            vm: VM object being configured (None for new VM creation)
            device_tracker: Service for device identification and error reporting
            vsphere_object_cache: Service for caching vsphere objects
        """
        super().__init__(error_handler, params, change_set, vm, device_tracker)
        self.vsphere_object_cache = vsphere_object_cache
        self._check_if_params_are_defined_by_user(
            "network_adapters", required_for_vm_creation=False
        )

    @property
    def type_parameters_to_vim_device_class_map(self):
        return {
            "e1000": vim.vm.device.VirtualE1000,
            "e1000e": vim.vm.device.VirtualE1000e,
            "pcnet32": vim.vm.device.VirtualPCNet32,
            "vmxnet2": vim.vm.device.VirtualVmxnet2,
            "vmxnet3": vim.vm.device.VirtualVmxnet3,
            "sriov": vim.vm.device.VirtualSriovEthernetCard,
        }

    @property
    def vim_device_class(self):
        return tuple(self.type_parameters_to_vim_device_class_map.values())

    def verify_parameter_constraints(self):
        """
        Validate network adapter parameter constraints and requirements.

        Parses network adapter parameters. Validates that all required portgroups
        exist and that network adapter specifications are valid.

        Raises:
            Calls error_handler.fail_with_parameter_error() for invalid network adapter
            parameters, missing portgroups, or missing network adapter definitions.
        """
        if len(self.managed_parameter_objects) == 0:
            try:
                self._parse_network_adapter_params()
            except ValueError as e:
                self.error_handler.fail_with_parameter_error(
                    parameter_name=self.HANDLER_NAME,
                    message="Error parsing %s parameter: %s"
                    % (self.HANDLER_NAME, str(e)),
                    details={"error": str(e)},
                )

    def _parse_network_adapter_params(self):
        """
        Parse network adapter parameters and create NetworkAdapter objects.

        Processes the network adapter parameter list, validates specifications,
        and creates NetworkAdapter objects.
        """
        adapter_params = self.params.get(self.HANDLER_NAME) or []
        for index, adapter_param in enumerate(adapter_params):
            resource_allocation = NetworkAdapterResourceAllocation(
                shares=adapter_param.get("shares"),
                shares_level=adapter_param.get("shares_level"),
                reservation=adapter_param.get("reservation"),
                limit=adapter_param.get("limit"),
            )
            try:
                network_portgroup = NetworkAdapterPortgroup.from_portgroup(
                    portgroup=self.vsphere_object_cache.get_portgroup(
                        adapter_param.get("network")
                    ),
                )
            except Exception as e:
                self.error_handler.fail_with_parameter_error(
                    parameter_name=self.HANDLER_NAME,
                    message="Error looking up the portgroup %s for network adapter %s: %s"
                    % (adapter_param.get("network"), index, str(e)),
                    details={"error": str(e)},
                )

            try:
                adapter_class = None
                if adapter_param.get("adapter_type") is not None:
                    adapter_class = self.type_parameters_to_vim_device_class_map[
                        adapter_param.get("adapter_type")
                    ]
                network_adapter = NetworkAdapter(
                    index=index,
                    adapter_vim_class=adapter_class,
                    connect_at_power_on=adapter_param.get("connect_at_power_on"),
                    connected=adapter_param.get("connected"),
                    mac_address=adapter_param.get("mac_address"),
                    resource_allocation=resource_allocation,
                    portgroup=network_portgroup,
                )
            except KeyError as e:
                self.error_handler.fail_with_parameter_error(
                    parameter_name=self.HANDLER_NAME,
                    message="Unsupported adapter type %s"
                    % adapter_param.get("adapter_type"),
                    details={"adapter_param": adapter_param},
                )
            self.managed_parameter_objects[index] = network_adapter

    def link_vm_device(self, device):
        """
        Link a VMware network adapter device to the appropriate network adapter object.

        This links the object representation of the live network adapter device to the
        object representation of the network adapter parameters specified by the user.
        That way, parameters can easily be compared to the live device.

        Args:
            device: vsphere object representing the live network adapter device

        Returns:
            AbstractVsphereObject or None: None if the device was linked, otherwise an AbstractVsphereObject representing the unlinked device
        """
        for param_adapter in self.managed_parameter_objects.values():
            # Network adapters are not easily identified, but vmware always lists them in the same order.
            # So we can just link the first one that doesn't have a linked device.
            if param_adapter.has_a_linked_live_vm_device():
                continue

            if param_adapter.adapter_vim_class is not None and not isinstance(
                device, param_adapter.adapter_vim_class
            ):
                self.error_handler.fail_with_parameter_error(
                    parameter_name=self.HANDLER_NAME,
                    message="Network adapter type %s in parameters does not match the device type %s, and changing types is not supported."
                    % (
                        getattr(param_adapter.adapter_vim_class, "__name__", "none"),
                        type(device).__name__,
                    ),
                    details={
                        "param_adapter": str(param_adapter),
                        "device_label": device.deviceInfo.label,
                    },
                )

            param_adapter.link_corresponding_live_object(
                NetworkAdapter.from_live_device_spec(device)
            )
            return

        if self.params.get("network_adapters_remove_unmanaged"):
            # device is unlinked and should be removed
            return NetworkAdapter.from_live_device_spec(device)
        else:
            # the device is not linked to anything, and no DeviceLinkError was raised,
            # so the module will ignore it
            return
