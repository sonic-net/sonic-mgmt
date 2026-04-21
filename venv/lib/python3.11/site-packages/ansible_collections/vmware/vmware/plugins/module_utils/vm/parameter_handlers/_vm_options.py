"""
VM options parameter handler for advanced VM configuration settings.

This module handles advanced VM configuration options including security settings,
encryption features, firmware configuration, and console session management.
These options control various VM behaviors and security features beyond basic
hardware configuration.
"""

from ansible_collections.vmware.vmware.plugins.module_utils.vm.parameter_handlers._abstract import (
    AbstractParameterHandler,
)

try:
    from pyVmomi import vim
except ImportError:
    pass


class VmOptionsParameterHandler(AbstractParameterHandler):
    """
    Handler for VM configuration options including security, encryption, and firmware settings.

    This handler manages advanced VM configuration options that control security features,
    encryption settings, firmware configuration, and console session management. It provides
    validation for security-related parameter constraints and ensures proper configuration
    of virtualization-based security features.

    Managed Parameters:
    - maximum_remote_console_sessions: Maximum number of concurrent remote console sessions (0-40)
    - encrypted_vmotion: Encryption mode for vMotion operations
    - encrypted_fault_tolerance: Encryption mode for fault tolerance
    - enable_encryption: Enable VM encryption for vMotion and fault tolerance
    - enable_hardware_assisted_virtualization: Enable nested virtualization
    - enable_io_mmu: Enable IO MMU
    - enable_virtual_based_security: Enable Virtualization Based Security
    - enable_secure_boot: Enable UEFI secure boot
    - boot_firmware: Boot firmware type (BIOS/EFI)

    Attributes:
        _vm_option_params: Dictionary containing VM option parameters from module input
    """

    HANDLER_NAME = "vm_options"

    def __init__(self, error_handler, params, change_set, vm, **kwargs):
        """
        Initialize the VM options parameter handler.

        Args:
            error_handler: Error handling service for parameter validation failures
            params (dict): Module parameters containing VM configuration
            change_set: Change tracking service for detecting configuration differences
            vm: Existing VM object (None for new VM creation)
            **kwargs: Additional keyword arguments. Other handlers may require specific
                      services and allowing kwargs makes initialization more flexible.
        """
        super().__init__(error_handler, params, change_set, vm)
        self._check_if_params_are_defined_by_user(
            "vm_options", required_for_vm_creation=False
        )

        # remap the fault tolerance encryption parameter to vmwares enums
        if self.params.get("vm_options") is not None:
            original_ft_encryption = self.params["vm_options"].get(
                "encrypted_fault_tolerance"
            )
            if original_ft_encryption is not None:
                self.params["vm_options"]["encrypted_fault_tolerance"] = (
                    "ftEncryption%s" % original_ft_encryption.capitalize()
                )

        self._vm_option_params = self.params.get("vm_options") or {}

    def verify_parameter_constraints(self):
        """
        Verify that the VM option parameters are valid.

        Validates parameter constraints including:
        - Maximum remote console sessions range (0-40)
        - Virtualization Based Security requirements (EFI firmware and secure boot)
        """
        if self._vm_option_params.get("maximum_remote_console_sessions"):
            if (
                self._vm_option_params["maximum_remote_console_sessions"] < 0
                or self._vm_option_params["maximum_remote_console_sessions"] > 40
            ):
                self.error_handler.fail_with_parameter_error(
                    parameter_name="maximum_remote_console_sessions",
                    message="Maximum remote console sessions must be between 0 and 40.",
                )

        self._verify_parameter_constraints_virt_based_security()
        self._verify_parameter_constraints_enable_encryption()

    def __get_effective_boot_firmware(self, return_both=False):
        """
        Helper function to return the effective boot firmware value.
        This is the value that would exist after the module completes.
        """
        firmware = self._vm_option_params.get("boot_firmware")
        if self.vm is not None:
            vm_firmware = self.vm.config.firmware
        else:
            vm_firmware = None

        if return_both:
            return firmware, vm_firmware
        elif firmware is not None:
            return firmware
        else:
            return vm_firmware

    def __get_effective_secure_boot(self, return_both=False):
        """
        Helper function to return the effective secure boot value.
        This is the value that would exist after the module completes.
        """
        secure_boot = self._vm_option_params.get("enable_secure_boot")
        if self.vm is not None:
            vm_secure_boot = getattr(self.vm.config.bootOptions, "efiSecureBootEnabled")
        else:
            vm_secure_boot = None

        if return_both:
            return secure_boot, vm_secure_boot
        elif secure_boot is not None:
            return secure_boot
        else:
            return vm_secure_boot

    def _verify_parameter_constraints_enable_secure_boot(self):
        """
        Verify that secure boot can be enabled.
        """
        enable_secure_boot = self._vm_option_params.get("enable_secure_boot")
        if enable_secure_boot is None and self.vm is not None:
            enable_secure_boot = getattr(
                self.vm.config.bootOptions, "efiSecureBootEnabled"
            )

    def _verify_parameter_constraints_virt_based_security(self):
        """
        Verify that the parameters, or VM state, are valid for Virtualization Based Security.
        """
        enable_vbs = self._vm_option_params.get("enable_virtual_based_security")
        if enable_vbs is None and self.vm is not None:
            enable_vbs = getattr(self.vm.config.flags, "vbsEnabled")

        if not enable_vbs:
            return

        enable_hardware_assisted_virtualization = self._vm_option_params.get(
            "enable_hardware_assisted_virtualization"
        )
        if enable_hardware_assisted_virtualization is None and self.vm is not None:
            enable_hardware_assisted_virtualization = self.vm.config.nestedHVEnabled

        firmware = self.__get_effective_boot_firmware()
        secure_boot = self.__get_effective_secure_boot()

        if enable_vbs and (
            not firmware
            or not secure_boot
            or not enable_hardware_assisted_virtualization
        ):
            self.error_handler.fail_with_parameter_error(
                parameter_name="enable_virtual_based_security",
                message="Virtualization Based Security requires EFI boot firmware, secure boot, and hardware assisted virtualization.",
                details={
                    "enable_virtual_based_security": enable_vbs,
                    "firmware": firmware,
                    "secure_boot": secure_boot,
                    "enable_hardware_assisted_virtualization": enable_hardware_assisted_virtualization,
                },
            )

    def _verify_parameter_constraints_enable_encryption(self):
        """
        Verify that encryption can be enabled.
        """
        enable_encryption = self._vm_option_params.get("enable_encryption")
        if enable_encryption is None and self.vm is not None:
            enable_encryption = self.vm.config.sevEnabled

        secure_boot = self.__get_effective_secure_boot()
        firmware = self.__get_effective_boot_firmware()

        if enable_encryption and (secure_boot or firmware == "bios"):
            self.error_handler.fail_with_parameter_error(
                parameter_name="enable_encryption",
                message="Encryption requires EFI boot firmware and disabled secure boot.",
                details={
                    "enable_encryption": enable_encryption,
                    "enable_secure_boot": secure_boot,
                    "boot_firmware": firmware,
                },
            )

        self.__verify_parameter_constraints_enable_encryption_hot_add(
            enable_encryption=enable_encryption
        )

    def __verify_parameter_constraints_enable_encryption_hot_add(
        self, enable_encryption
    ):
        """
        Verify that encryption can be enabled if memory or CPU hot-add/hot-remove is disabled.

        Unlike firmware and secure boot, hot-add/hot-remove cannot be disabled in the same module call as
        encryption is enabled. Vsphere doesn't like it for whatever reason.
        """
        memory_params = self.params.get("memory") or dict()
        param_memory_hot_add = memory_params.get("enable_hot_add")
        vm_memory_hot_add = (
            False if self.vm is None else self.vm.config.memoryHotAddEnabled
        )

        cpu_params = self.params.get("cpu") or dict()
        param_cpu_hot_add = cpu_params.get("enable_hot_add")
        vm_cpu_hot_add = False if self.vm is None else self.vm.config.cpuHotAddEnabled

        param_cpu_hot_remove = cpu_params.get("enable_hot_remove")
        vm_cpu_hot_remove = (
            False if self.vm is None else self.vm.config.cpuHotRemoveEnabled
        )

        if enable_encryption and (
            param_memory_hot_add
            or vm_memory_hot_add
            or param_cpu_hot_add
            or vm_cpu_hot_add
        ):
            self.error_handler.fail_with_parameter_error(
                parameter_name="enable_encryption",
                message="Encryption cannot be enabled if memory or CPU hot-add is currently enabled or is being enabled.",
                details={
                    "enable_encryption": enable_encryption,
                    "memory.enable_hot_add": param_memory_hot_add or vm_memory_hot_add,
                    "cpu.enable_hot_add": param_cpu_hot_add or vm_cpu_hot_add,
                    "cpu.enable_hot_remove": param_cpu_hot_remove or vm_cpu_hot_remove,
                },
            )

    def compare_live_config_with_desired_config(self):
        """
        Compare current VM configuration options with desired configuration.

        Checks if the VM's current configuration options (security settings, encryption,
        firmware, console sessions) match the desired values specified in the module parameters.
        Uses the change set service to track which properties need updates.

        Side Effects:
            Updates change_set with detected differences between current and desired state.
        """
        self.change_set.check_if_change_is_required(
            "vm_options.maximum_remote_console_sessions",
            "config.maxMksConnections",
            power_sensitive=True,
        )
        self.change_set.check_if_change_is_required(
            "vm_options.encrypted_vmotion", "config.migrateEncryption"
        )
        self.change_set.check_if_change_is_required(
            "vm_options.encrypted_fault_tolerance", "config.ftEncryptionMode"
        )
        self.change_set.check_if_change_is_required(
            "vm_options.enable_encryption", "config.sevEnabled", power_sensitive=True
        )
        self.change_set.check_if_change_is_required(
            "vm_options.enable_hardware_assisted_virtualization",
            "config.nestedHVEnabled",
            power_sensitive=True,
        )
        self.change_set.check_if_change_is_required(
            "vm_options.enable_io_mmu", "config.flags.vvtdEnabled"
        )
        self.change_set.check_if_change_is_required(
            "vm_options.enable_virtual_based_security", "config.flags.vbsEnabled"
        )
        self.change_set.check_if_change_is_required(
            "vm_options.enable_secure_boot", "config.bootOptions.efiSecureBootEnabled"
        )
        self.change_set.check_if_change_is_required(
            "vm_options.boot_firmware", "config.firmware", power_sensitive=True
        )

    def populate_config_spec_with_parameters(self, configspec):
        """
        Populate VMware configuration specification with VM option parameters.

        Sets various VM configuration options in the configuration specification
        including security settings, encryption options, firmware configuration,
        and console session limits.

        Args:
            configspec: VMware VirtualMachineConfigSpec to populate

        Side Effects:
            Modifies configspec with VM option parameters including security,
            encryption, firmware, and console session settings.
        """
        param_to_configspec_attr = {
            "maximum_remote_console_sessions": "maxMksConnections",
            "encrypted_vmotion": "migrateEncryption",
            "encrypted_fault_tolerance": "ftEncryptionMode",
            "enable_encryption": "sevEnabled",
            "enable_hardware_assisted_virtualization": "nestedHVEnabled",
            "boot_firmware": "firmware",
        }
        for param_name, configspec_attr in param_to_configspec_attr.items():
            value = self._vm_option_params.get(param_name)
            if value is not None:
                setattr(configspec, configspec_attr, value)

        flag_params_to_configspec_attr = {
            "enable_io_mmu": "vvtdEnabled",
            "enable_virtual_based_security": "vbsEnabled",
        }
        for param_name, configspec_attr in flag_params_to_configspec_attr.items():
            value = self._vm_option_params.get(param_name)
            if value is not None:
                if configspec.flags is None:
                    configspec.flags = vim.vm.FlagInfo()
                setattr(configspec.flags, configspec_attr, value)

        param_enable_secure_boot = self._vm_option_params.get("enable_secure_boot")
        if param_enable_secure_boot is not None:
            if configspec.bootOptions is None:
                configspec.bootOptions = vim.vm.BootOptions()
            configspec.bootOptions.efiSecureBootEnabled = param_enable_secure_boot
