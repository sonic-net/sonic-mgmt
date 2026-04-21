#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_apply_customization
short_description: Applies a customization specification to a virtual machine.
description:
    - This module is used to apply a customization specification to a virtual machine. It always applies the specification
      defined here, and always reports a change.
    - Customization specifications are run once when a VM is powered on or rebooted. This module just
      applies the customization specification to the VM, making sure that it will be run during the next power cycle.
    - Since customization is run asynchronously, you should check the VM logs to ensure that the customization was
      applied successfully. See the examples for ways to ensure the customization was applied successfully in a playbook.
    - Once the VM is started, the pending customization is applied. Even if that fails, the customization is then cleared. Meaning, you
      need to re-apply the customization spec in order to try again. Simply rebooting the VM will not change anything.
    - Customization leverages VMWare Tools to inject the customization specification into the VM. For a list of supported
      operating systems, see the Broadcom documentation http://partnerweb.vmware.com/programs/guestOS/guest-os-customization-matrix.pdf
    - Custom script execution is disabled by default. To enable it, you can run as an administrator
      'vmware-toolbox-cmd config set deployPkg enable-custom-scripts  true'

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    name:
        description:
            - Name of the virtual machine to manage.
            - Virtual machine names in vCenter are not necessarily unique, which may be problematic, see O(name_match).
            - This is required when the VM does not exist, or if O(moid) or O(uuid) is not supplied.
        type: str
    name_match:
        description:
            - If multiple virtual machines matching the name, use the first or last found.
        default: first
        choices: [ first, last ]
        type: str
    uuid:
        description:
            - UUID of the instance to manage if known, this is VMware's unique identifier.
            - This is required if O(name) or O(moid) is not supplied.
        type: str
    moid:
        description:
            - Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance.
            - This is required if O(name) or O(uuid) is not supplied.
        type: str
    use_instance_uuid:
        description:
            - Whether to use the VMware instance UUID rather than the BIOS UUID.
        default: false
        type: bool
    folder:
        description:
            - Destination folder, absolute or relative path to find an existing guest.
            - Should be the full folder path, with or without the 'datacenter/vm/' prefix
            - For example 'datacenter_name/vm/path/to/folder' or 'path/to/folder'.
            - You cannot use this module to modify the placement of a VM once it has been created.
        type: str
        required: false
    datacenter:
        description:
            - The datacenter in which to search for the VM.
        type: str
        required: false
        aliases: [ datacenter_name ]
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute
              or relative.
            - This option is useful when your environment has a complex folder structure. By default,
              modules will try to intelligently determine if the path is absolute or relative.
              They may mistakenly prepend the datacenter name or other folder names, and this option
              can be used to avoid this.
        type: bool
        required: false
        default: false

    # start customization options
    existing_spec_name:
        description:
            - The name of the existing customization specification in vSphere to apply to the VM.
            - One and only one of O(existing_spec_name), O(cloud_init), O(windows_sysprep), or O(unix_prep) must be specified.
        type: str
        required: false

    cloud_init:
        description:
            - The cloud-init configuration to apply to the VM.
            - Only applicable for Linux guests.
            - The OS must already have cloud-init and perl installed.
            - One and only one of O(existing_spec_name), O(cloud_init), O(windows_sysprep), or O(unix_prep) must be specified.
        type: dict
        required: false
        suboptions:
            user_data_string:
                description:
                    - The user data script to apply to the VM. This is usually a cloud-config yaml file or shell script.
                    - The max size of the userdata is 524288 bytes.
                    - For more information see https://cloudinit.readthedocs.io/en/latest/topics/format.html
                type: str
                required: false
            instance_data:
                description:
                    - The instance data to apply to the VM.
                    - Instance data includes the network, instance id and hostname that cloud-init processes to configure the VM. It is
                      in json or yaml format.
                    - The max size of the instance data is 524288 bytes.
                    - For more information see https://cloudinit.readthedocs.io/en/latest/explanation/instancedata.html
                    - This option expects the instance data to be passed in as a dictionary. It is mutually exclusive with O(cloud_init.instance_data_string).
                    - One of O(cloud_init.instance_data) or O(cloud_init.instance_data_string) must be specified.
                type: dict
                required: false
            instance_data_string:
                description:
                    - Similar to O(cloud_init.instance_data), but this option allows you to pass the instance data as a string.
                    - One of O(cloud_init.instance_data) or O(cloud_init.instance_data_string) must be specified.
                type: str
                required: false

    windows_sysprep:
        description:
            - The Windows Sysprep configuration to apply to the VM.
            - Only applicable for Windows guests.
            - One and only one of O(existing_spec_name), O(cloud_init), O(windows_sysprep), or O(unix_prep) must be specified.
        type: dict
        required: false
        suboptions:
            post_customization_action:
                description:
                    - The power-related action to take once the sysprep process is complete. This is either a reboot, a shutdown, or nothing at all.
                type: str
                default: reboot
                choices: [ reboot, noreboot, shutdown ]
            gui_run_once_commands:
                description:
                    - A list of commands to run once the GUI is available.
                    - This occurs at first user logon, after guest customization has completed.
                type: list
                elements: str
                default: []
            auto_logon:
                description:
                    - If true, the machine will automatically log on as Administrator.
                    - If this is true, O(windows_sysprep.password) is required.
                type: bool
                required: false
                default: false
            auto_logon_count:
                description:
                    - Specify the number of times the machine should automatically log on as Administrator, if O(windows_sysprep.auto_logon) is true.
                    - Generally it should be 1, but if your setup requires a number of reboots, you may want to increase it.
                type: int
                required: false
                default: 1
            password:
                description:
                    - The local Administrator password for the machine.
                    - You must specify a password. If there is no password, meaning it should be blank, set this value to ''.
                    - If the password is null, you cannot use O(windows_sysprep.auto_logon). Customization will fail.
                type: str
                required: true
            timezone:
                description:
                    - The timezone to set for the machine.
                    - This should be an integer value matching the index from the Microsoft documentation. For example,
                      index 000 would be just be 0.
                    - See the Microsoft documentation for a list of valid timezone index values,
                      https://support.microsoft.com/en-us/help/973627/microsoft-time-zone-index-values
                type: int
                required: false
            workgroup:
                description:
                    - The name of the workgroup for the machine to join.
                    - Only one of O(windows_sysprep.workgroup) or O(windows_sysprep.domain) can be specified.
                type: str
                required: false
            domain:
                description:
                    - The name of the domain for the machine to join.
                    - Only one of O(windows_sysprep.workgroup) or O(windows_sysprep.domain) can be specified.
                type: dict
                required: false
                suboptions:
                    join_user_name:
                        description:
                            - The username of the domain user to use to join the domain.
                            - This user does not need to be a domain administrator, but it must have the ability to join
                              computers to the domain.
                        type: str
                        required: false
                    join_user_password:
                        description:
                            - The password of the domain user to use to join the domain.
                            - Required if O(windows_sysprep.domain.join_user_name) is specified.
                        type: str
                        required: false
                    name:
                        description:
                            - The name of the domain to join.
                        type: str
                        required: false
                    ou:
                        description:
                            - Specify the full LDAP path name of the OU to which the computer should belong. For example, OU=MyOu,DC=MyDom,DC=MyCompany,DC=com
                            - Only available for vSphere API Release 8.0.2.0 and later.
                        type: str
                        required: false
            hostname:
                description:
                    - Specify the host, or compute, name for this machine.
                    - Computer name may contain letters (A-Z), numbers(0-9) and hyphens (-) but no spaces or periods (.).
                    - The name may not consists entirely of digits.
                    - Hostname is restricted to 15 characters in length. If the hostname is longer than 15 characters, it will be truncated to 15 characters.
                type: str
                required: false
            users_full_name:
                description:
                    - The full name of the user to be associated with this machine.
                type: str
                required: false
            users_org_name:
                description:
                    - The organization name of the user to be associated with this machine.
                type: str
                required: false
            product_id:
                description:
                    - Microsoft Sysprep requires that a valid serial number be included in the answer file when mini-setup runs.
                    - This serial number is ignored if the original guest operating system was installed using a volume-licensed CD.
                type: str
                required: false

    unix_prep:
        description:
            - The Unix Prep configuration to apply to the VM.
            - Only applicable for Linux guests.
            - The OS must already have perl installed.
            - One and only one of O(existing_spec_name), O(cloud_init), O(windows_sysprep), or O(unix_prep) must be specified.
        type: dict
        required: false
        suboptions:
            domain:
                description:
                    - The fully qualified domain name for the machine.
                type: str
                required: true
            hostname:
                description:
                    - The hostname to set for the machine.
                type: str
                required: true
            hardware_clock_utc:
                description:
                    - Whether to set the hardware clock to UTC or use the local timezone.
                    - If true, the hardware clock will be set to UTC.
                type: bool
                required: false
            timezone:
                description:
                    - The case sensitive name of the timezone to set for the machine.
                    - For a list of valid timezone values, see the Broadcom documentation,
                      https://developer.broadcom.com/xapis/vsphere-web-services-api/8.0.3/timezone.html
                type: str
                required: false
            script_string:
                description:
                    - The script to run before and after the GOS customization process.
                    - Specify the script as a string, including the shebang line.
                    - The script is executed as the root user.
                type: str
                required: false

    use_dhcpv4_for_all_nics:
        description:
            - If true, DHCPv4 will be used for all network adapters on the VM.
            - If false, you must specify all adapters in O(nic_specific_settings) due to VMware's API requirements.
        type: bool
        default: false
    nic_specific_settings:
        description:
            - Specify settings for specific network adapters.
            - This setting is required if O(use_dhcpv4_for_all_nics) is false or unspecified.
            - If this setting is used, you need to specify an item in this list for all network adapters on your VM
              due to VMware's API requirements.
        type: list
        elements: dict
        required: false
        suboptions:
            mac_address:
                description:
                    - Specify the MAC address of the network adapter to manage.
                    - This is using the MAC address as an identifier. You cannot change the MAC address of an adapter with this module.
                    - You should either specify the MAC address for all items in this list, or none of them.
                    - If you do not specify the MAC address, the customizations will be applied to network adapters in the same order
                      as they are defined here (for example, the first item in this list will be applied to the first network adapter on the VM).
                type: str
                required: false
            resolution_suffix:
                description:
                    - A DNS suffix to use for this network adapter.
                type: str
                required: false
            dns_servers:
                description:
                    - A list of DNS servers to use for this network adapter.
                type: list
                elements: str
                required: false
            ipv4:
                description:
                    - Specify the IPv4 address to use for a virtual network adapter.
                    - This section must be specified but it can be left empty to use DHCP.
                type: dict
                required: true
                suboptions:
                    address:
                        description:
                            - Specify the IP address to use for a virtual network adapter, essentially assigning a static IP address.
                            - If this is not specified, DHCP will be used.
                            - This is required if O(nic_specific_settings[].ipv4.subnet_mask) is specified.
                        type: str
                        required: false
                    gateways:
                        description:
                            - Specify a list of gateways, in order of preference, to use for the IP address.
                        type: list
                        elements: str
                        required: false
                    subnet_mask:
                        description:
                            - Specify the subnet mask to use for a virtual network adapter with a static IP address.
                            - This should be a string in CIDR notation, for example '255.255.255.0'
                            - This is required if O(nic_specific_settings[].ipv4.address) is specified.
                        type: str
                        required: false
            ipv6:
                description:
                    - Specify the IPv6 address to use for a virtual network adapter.
                type: dict
                required: false
                suboptions:
                    address:
                        description:
                            - Specify the IPv6 address to use for a virtual network adapter, essentially assigning a static IP address.
                            - If this is not specified, DHCP will be used.
                            - This is required if O(nic_specific_settings[].ipv6.subnet_mask) is specified.
                        type: str
                        required: false
                    subnet_mask:
                        description:
                            - Specify the subnet mask to use for a virtual network adapter with a static IP address.
                            - This is required if O(nic_specific_settings[].ipv6.address) is specified.
                            - This should be an integer representing the prefix length, for example 64.
                        type: int
                        required: false
                    gateways:
                        description:
                            - Specify a list of gateways, in order of preference, to use for the IP address.
                        type: list
                        elements: str
                        required: false
            netbios_mode:
                description:
                    - Specify the NetBIOS mode to use.
                    - This only applies to Windows guests.
                type: str
                required: false
                choices: [ disableNetBIOS, enableNetBIOS, enableNetBIOSViaDHCP]
            primary_wins_server:
                description:
                    - Specify the IP address of the primary WINS server to use.
                    - This only applies to Windows guests.
                type: str
                required: false
            secondary_wins_server:
                description:
                    - Specify the IP address of the secondary WINS server to use.
                    - This only applies to Windows guests.
                type: str
                required: false

    global_dns:
        description:
            - The global DNS configuration to apply to the VM. These apply to any network adapter this is not explicitly configured.
        type: dict
        required: true
        suboptions:
            servers:
                description:
                    - A list of DNS servers to use.
                    - If this list is empty or not specified then the guest operating system is expected to use a DHCP server to get its DNS server settings.
                    - These DNS server settings are listed in order of preference.
                type: list
                elements: str
            resolution_suffixes:
                description:
                    - A list of DNS name resolution suffixes to use.
                    - This list applies to both Windows and Linux guest customization.
                type: list
                elements: str


extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
# Full deployment example
- name: Deploy a VM from a template
  vmware.vmware.deploy_folder_template:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    datacenter: "my-datacenter"
    vm_name: "my_vm"
    template_name: "my_template"
  register: _deploy_vm

- name: Set VM hardware settings
  vmware.vmware.vm:
    moid: "{{ _deploy_vm.vm.moid }}"
    cpu:
      cores: 4
      cores_per_socket: 2
    memory:
      size_mb: 8096
    disks:
      - size: 80gb
        provisioning: thin
        device_node: SCSI(0:0)
      - size: 10gb
        provisioning: thick
        device_node: SCSI(0:1)
      - size: 1tb
        provisioning: thin
        device_node: SCSI(1:0)
        datastore: ArchiveDatastore
    scsi_controllers:
      - controller_type: paravirtual
        bus_number: 0
      - controller_type: paravirtual
        bus_number: 1
        bus_sharing: virtualSharing
    network_adapters:
      - network: VM Network
        adapter_type: vmxnet3
        connected: true
        connect_at_power_on: true
      - network: Management
        adapter_type: vmxnet3
        connected: true
        connect_at_power_on: true
        mac_address: 11:11:11:11:11:11

- name: Set VM customization spec
  vmware.vmware.vm_customization:
    moid: "{{ _deploy_vm.vm.moid }}"
    datacenter: "my-datacenter"
    use_ipv4_dhcp_for_all_nics: true
    cloud_init:
      instance_data:
        instance-id: "{{ _deploy_vm.vm.moid }}"
        hostname: "{{ _deploy_vm.vm.name }}"
        network:
          version: 2
          ethernets:
            nics:
              match:
                name: e*
              dhcp4: true
              dhcp6: false
        public_ssh_keys:
          - "{{ lookup('ansible.builtin.file', vmware_vm_ssh_public_key_file_path) }}"

      user_data_string: |
        #cloud-config
        hostname: {{ _deploy_vm.vm.name }}
        fqdn: {{ _deploy_vm.vm.name }}.contoso.com

        disable_root: false
        ssh_pwauth: false
        ssh_deletekeys: true
        ssh:
          emit_keys_to_console: false
        no_ssh_fingerprints: false
        ssh_authorized_keys:
          - {{ lookup('ansible.builtin.file', vmware_vm_ssh_public_key_file_path) }}

        users:
          - name: root
            ssh_authorized_keys:
              - {{ lookup('ansible.builtin.file', vmware_vm_ssh_public_key_file_path) }}
            lock_passwd: false

        write_files:
          - path: /etc/cloud/cloud-init.disabled
            permissions: "0644"
            content: ""

- name: Power on VM
  vmware.vmware.vm_powerstate:
    moid: "{{ _deploy_vm.vm.moid }}"
    datacenter: "my-datacenter"
    state: powered-on

- name: Wait for customization to complete
  ansible.builtin.wait_for:
    path: /etc/cloud/cloud-init.disabled
    state: present
  delegate_to: "{{ _deploy_vm.vm.name }}"
'''

RETURN = r'''
vm:
    description:
        - Information about the target VM
    returned: On success
    type: dict
    sample:
        moid: vm-79828
        name: test-d9c1-vm
'''
from abc import ABC, abstractmethod
import json

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import (
    TaskError, RunningTaskMonitor
)


class Identity(ABC):
    """
    Interface class for all identity specifications. "Identity" is a VMware term for the type
    of customization specification.
    """
    def __init__(self, params):
        self.params = params

    @staticmethod
    def create_from_params(params):
        if params.get('windows_sysprep'):
            return WinSysprepIdentity(params.get('windows_sysprep'))
        elif params.get('cloud_init'):
            return CloudInitIdentity(params.get('cloud_init'))
        elif params.get('unix_prep'):
            return UnixPrepIdentity(params.get('unix_prep'))
        elif params.get('existing_spec_name'):
            return None
        else:
            # this should never happen, we enforce this in the argument spec
            raise ValueError("One of the supported customization options must be specified")

    @abstractmethod
    def create_identity_spec(self):
        pass


class CloudInitIdentity(Identity):
    """
    Identity specification for Cloud-Init.
    """
    def create_identity_spec(self):
        spec = vim.vm.customization.CloudinitPrep()
        if self.params.get('instance_data'):
            try:
                spec.metadata = json.dumps(self.params.get('instance_data'))
            except TypeError as e:
                self.module.fail_json(msg="Failed to convert instance data to JSON: %s" % e)
        else:
            spec.metadata = self.params.get('instance_data_string')

        if self.params.get('user_data_string'):
            spec.userdata = self.params.get('user_data_string')

        return spec


class WinSysprepIdentity(Identity):
    """
    Identity specification for Windows Sysprep. Obviously only applicable to Windows guests.
    """
    def create_identity_spec(self):
        spec = vim.vm.customization.Sysprep()
        if self.params.get('gui_run_once_commands'):
            gui_run_once = vim.vm.customization.GuiRunOnce()
            gui_run_once.commandList = self.params.get('gui_run_once_commands')
            spec.guiRunOnce = gui_run_once

        spec.guiUnattended = self._create_gui_unattended_spec()
        spec.identification = self._create_indentification_spec()
        spec.userData = self._create_user_data_spec()

        return spec

    def _create_gui_unattended_spec(self):
        subspec = vim.vm.customization.GuiUnattended()
        subspec.autoLogon = self.params.get('auto_logon')
        subspec.autoLogonCount = self.params.get('auto_logon_count')
        if self.params.get('password') is not None:
            _password = vim.vm.customization.Password()
            _password.plainText = True
            _password.value = self.params.get('password')
            subspec.password = _password
        if self.params.get('timezone') is not None:
            subspec.timeZone = self.params.get('timezone')
        return subspec

    def _create_indentification_spec(self):
        subspec = vim.vm.customization.Identification()
        if self.params.get('workgroup') is not None:
            subspec.joinWorkgroup = self.params.get('workgroup')

        elif self.params.get('domain') is not None:
            domain_opts = self.params.get('domain')
            _opts = {
                'join_user_name': 'domainAdmin',
                'name': 'joinDomain',
                'ou': 'domainOU',
            }
            for key, value in _opts.items():
                if domain_opts.get(key) is not None:
                    setattr(subspec, value, domain_opts.get(key))

            if domain_opts.get('join_user_password') is not None:
                _password = vim.vm.customization.Password()
                _password.plainText = True
                _password.value = domain_opts.get('join_user_password')
                subspec.domainAdminPassword = _password

        return subspec

    def _create_user_data_spec(self):
        subspec = vim.vm.customization.UserData()
        _opts = {
            'users_full_name': 'fullName',
            'users_org_name': 'orgName',
            'product_id': 'productId'
        }
        for key, value in _opts.items():
            if self.params.get(key) is not None:
                setattr(subspec, value, self.params.get(key))

        if self.params.get('hostname') is not None:
            name = vim.vm.customization.FixedName()
            name.name = self.params.get('hostname')
            subspec.computerName = name

        return subspec


class UnixPrepIdentity(Identity):
    """
    Identity specification for Unix Prep. Obviously only applicable to Linux guests.
    """
    def create_identity_spec(self):
        spec = vim.vm.customization.LinuxPrep()
        spec.domain = self.params.get('domain')
        hostname = vim.vm.customization.FixedName()
        hostname.name = self.params.get('hostname')
        spec.hostName = hostname

        if self.params.get('hardware_clock_utc') is not None:
            spec.hwClockUTC = self.params.get('hardware_clock_utc')
        if self.params.get('timezone') is not None:
            spec.timeZone = self.params.get('timezone')
        if self.params.get('script_string') is not None:
            spec.scriptText = self.params.get('script_string')

        return spec


class VMCustomizationModule(ModulePyvmomiBase):
    def __init__(self, module):
        super().__init__(module)
        self.identity = Identity.create_from_params(self.params)
        self.vm = self.get_vms_using_params(fail_on_missing=True)[0]
        self._customization_spec = None

    def check_customization_spec(self):
        """
        VMware can do some internal validation of the customization spec before applying it.
        They claim to do schema validation and VM state validation, but its not clear if they
        do both of those on just VMs from templates or already existing VMs as well.
        """
        if self.identity is None:
            self._customization_spec = self._lookup_existing_spec()
        else:
            self._customization_spec = self._create_spec()

        try:
            self.vm.CheckCustomizationSpec(self._customization_spec)
        except (vmodl.RuntimeFault, vim.fault.CustomizationFault) as e:
            self.module.fail_json(
                msg="Failed to validate customization spec: %s" % e.msg,
                error_code="VIM_FAULT",
                error_type=str(type(e)),
                error_raw=to_native(e),
            )

    def apply_customization_spec(self):
        """
        Apply the customization spec to the VM. This just "queues" the customization spec for
        application, it doesn't actually apply it. The actual application is done when the VM is powered on next.
        """
        if self._customization_spec is None:
            self.check_customization_spec()

        try:
            task = self.vm.CustomizeVM_Task(self._customization_spec)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()  # pylint: disable=disallowed-name
        except TaskError as e:
            self.module.fail_json(msg="Failed to apply customization spec: %s" % e)
        except (vmodl.RuntimeFault, vim.fault.InvalidState, vim.fault.InvalidPowerState, vim.fault.TaskInProgress) as e:
            self.module.fail_json(
                msg="%s" % e.msg,
                error_code="VIM_FAULT",
                error_type=str(type(e)),
                error_raw=to_native(e),
            )

        return task_result

    def _lookup_existing_spec(self):
        """
        Lookup an existing customization specification by name. Users can define specs in vSphere, and
        then reference them by name when applying them to a VM.
        """
        custom_spec_name = self.params.get('existing_spec_name')
        cc_mgr = self.content.customizationSpecManager
        if cc_mgr.DoesCustomizationSpecExist(name=custom_spec_name):
            temp_spec = cc_mgr.GetCustomizationSpec(name=custom_spec_name)
            return temp_spec.spec
        else:
            self.module.fail_json(
                msg="Unable to find customization specification '%s' in vSphere." % custom_spec_name
            )

    def _create_spec(self):
        """
        Create a new customization specification. Specifications depend on the "identity" type
        primarily. But there are some common options that are shared between all identities.
        """
        spec = vim.vm.customization.Specification()

        spec.globalIPSettings = self._create_global_ip_settings_spec()
        spec.identity = self.identity.create_identity_spec()
        if self.params.get('use_dhcpv4_for_all_nics'):
            spec.nicSettingMap = self._create_default_nic_setting_map_spec()
        else:
            spec.nicSettingMap = self._create_custom_nic_setting_map_spec()

        customization_options = self._create_options_spec()
        if customization_options:
            spec.options = customization_options

        return spec

    def _create_global_ip_settings_spec(self):
        spec = vim.vm.customization.GlobalIPSettings()
        if not self.params.get('global_dns'):
            return spec

        global_dns_opts = self.params.get('global_dns')
        if global_dns_opts.get('servers'):
            spec.dnsServerList = global_dns_opts.get('servers')
        if global_dns_opts.get('resolution_suffixes'):
            spec.dnsSuffixList = global_dns_opts.get('resolution_suffixes')
        return spec

    def _create_options_spec(self):
        win_sysprep_opts = self.params.get('windows_sysprep')
        if not win_sysprep_opts:
            return None

        spec = vim.vm.customization.WinOptions()
        spec.reboot = win_sysprep_opts.get('post_customization_action')
        return spec

    def _create_default_nic_setting_map_spec(self):
        spec_list = []
        vm_nics = [dev for dev in self.vm.config.hardware.device if hasattr(dev, 'macAddress')]
        for _ in range(len(vm_nics)):  # pylint: disable=disallowed-name
            spec = vim.vm.customization.AdapterMapping()
            adapter_ip_settings = vim.vm.customization.IPSettings()
            self._populate_ipv4_settings(adapter_ip_settings, {})
            spec.adapter = adapter_ip_settings
            spec_list.append(spec)

        return spec_list

    def _create_custom_nic_setting_map_spec(self):
        spec_list = []
        for nic_setting in self.params.get('nic_specific_settings'):
            spec = vim.vm.customization.AdapterMapping()
            if nic_setting.get('mac_address'):
                spec.macAddress = nic_setting.get('mac_address')

            adapter_ip_settings = vim.vm.customization.IPSettings()
            _opts = {
                'dns_servers': 'dnsServerList',
                'resolution_suffix': 'dnsDomain',
                'primary_wins_server': 'primaryWINS',
                'secondary_wins_server': 'secondaryWINS',
                'netbios_mode': 'netBIOS',
                'gateway': 'gateways',
            }
            for key, value in _opts.items():
                if nic_setting.get(key) is not None:
                    setattr(adapter_ip_settings, value, nic_setting.get(key))

            self._populate_ipv4_settings(adapter_ip_settings, nic_setting.get('ipv4'))
            self._populate_ipv6_settings(adapter_ip_settings, nic_setting.get('ipv6'))

            spec.adapter = adapter_ip_settings
            spec_list.append(spec)

        return spec_list

    def _populate_ipv4_settings(self, adapter_ip_settings, ipv4_settings):
        if ipv4_settings is None:
            ipv4_settings = {}

        if ipv4_settings.get('address') is None:
            adapter_ip_settings.ip = vim.vm.customization.DhcpIpGenerator()
        else:
            static_ip = vim.vm.customization.FixedIp()
            static_ip.ipAddress = ipv4_settings.get('address')
            adapter_ip_settings.ip = static_ip
            adapter_ip_settings.subnetMask = ipv4_settings.get('subnet_mask')

        if ipv4_settings.get('gateways') is not None:
            # not a typo, just a confusing name with gateway vs gateways
            adapter_ip_settings.gateway = ipv4_settings.get('gateways')

        return

    def _populate_ipv6_settings(self, adapter_ip_settings, ipv6_settings):
        if ipv6_settings is None:
            return

        ipV6Spec = vim.vm.customization.IPSettings.IpV6AddressSpec()
        if ipv6_settings.get('address') is None:
            ipV6Spec.ip = [vim.vm.customization.DhcpIpV6Generator()]
        else:
            fixed_ip = vim.vm.customization.FixedIpV6()
            fixed_ip.ipAddress = ipv6_settings.get('address')
            fixed_ip.subnetMask = ipv6_settings.get('subnet_mask')
            ipV6Spec.ip = [fixed_ip]

        if ipv6_settings.get('gateways') is not None:
            ipV6Spec.gateway = ipv6_settings.get('gateways')

        adapter_ip_settings.ipV6Spec = ipV6Spec


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(),
            **dict(
                name=dict(type='str', required=False),
                name_match=dict(type='str', choices=['first', 'last'], default='first'),
                uuid=dict(type='str'),
                moid=dict(type='str'),
                use_instance_uuid=dict(type='bool', default=False),
                folder=dict(type='str', required=False),
                folder_paths_are_absolute=dict(type='bool', required=False, default=False),
                datacenter=dict(type='str', required=False, aliases=['datacenter_name']),

                existing_spec_name=dict(type='str', required=False),

                cloud_init=dict(
                    type='dict', required=False, options=dict(
                        user_data_string=dict(type='str', required=False),
                        instance_data=dict(type='dict', required=False),
                        instance_data_string=dict(type='str', required=False),
                    ),
                    mutually_exclusive=[
                        ('instance_data', 'instance_data_string'),
                    ],
                    required_one_of=[
                        ('instance_data', 'instance_data_string'),
                    ],
                ),

                windows_sysprep=dict(
                    type='dict', required=False, options=dict(
                        post_customization_action=dict(type='str', required=False, choices=['reboot', 'noreboot', 'shutdown'], default='reboot'),
                        gui_run_once_commands=dict(type='list', elements='str', required=False, default=[]),
                        auto_logon=dict(type='bool', required=False, default=False),
                        auto_logon_count=dict(type='int', required=False, default=1),
                        password=dict(type='str', required=True, no_log=True),
                        timezone=dict(type='int', required=False),
                        workgroup=dict(type='str', required=False),
                        domain=dict(
                            type='dict', required=False, options=dict(
                                join_user_name=dict(type='str', required=False),
                                join_user_password=dict(type='str', required=False, no_log=True),
                                name=dict(type='str', required=False),
                                ou=dict(type='str', required=False),
                            ),
                            required_together=[
                                ('join_user_name', 'join_user_password'),
                            ],
                        ),
                        hostname=dict(type='str', required=False),
                        users_full_name=dict(type='str', required=False),
                        users_org_name=dict(type='str', required=False),
                        product_id=dict(type='str', required=False),
                    ),
                    mutually_exclusive=[
                        ('workgroup', 'domain'),
                    ]
                ),

                unix_prep=dict(
                    type='dict', required=False, options=dict(
                        domain=dict(type='str', required=True),
                        hostname=dict(type='str', required=True),
                        hardware_clock_utc=dict(type='bool', required=False),
                        timezone=dict(type='str', required=False),
                        script_string=dict(type='str', required=False),
                    ),
                ),

                use_dhcpv4_for_all_nics=dict(type='bool', default=False),
                nic_specific_settings=dict(
                    type='list', elements='dict', required=False, options=dict(
                        mac_address=dict(type='str', required=False),
                        resolution_suffix=dict(type='str', required=False),
                        dns_servers=dict(type='list', elements='str', required=False),
                        ipv4=dict(
                            type='dict', required=True, options=dict(
                                address=dict(type='str', required=False),
                                gateways=dict(type='list', elements='str', required=False),
                                subnet_mask=dict(type='str', required=False),
                            ),
                            required_together=[
                                ('address', 'subnet_mask'),
                            ],
                        ),
                        ipv6=dict(
                            type='dict', required=False, options=dict(
                                address=dict(type='str', required=False),
                                subnet_mask=dict(type='int', required=False),
                                gateways=dict(type='list', elements='str', required=False),
                            ),
                            required_together=[
                                ('address', 'subnet_mask'),
                            ],
                        ),
                        netbios_mode=dict(type='str', required=False, choices=['disableNetBIOS', 'enableNetBIOS', 'enableNetBIOSViaDHCP']),
                        primary_wins_server=dict(type='str', required=False),
                        secondary_wins_server=dict(type='str', required=False),
                    ),
                ),

                global_dns=dict(
                    type='dict', required=True, options=dict(
                        servers=dict(type='list', elements='str', required=False),
                        resolution_suffixes=dict(type='list', elements='str', required=False),
                    ),
                ),
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ('name', 'uuid', 'moid'),
            ('windows_sysprep', 'cloud_init', 'unix_prep', 'existing_spec_name'),
        ],
        required_one_of=[
            ('name', 'uuid', 'moid'),
            ('windows_sysprep', 'cloud_init', 'unix_prep', 'existing_spec_name'),
        ],
        required_if=[
            ('use_dhcpv4_for_all_nics', False, ('nic_specific_settings',)),
        ],
    )

    result = dict(
        changed=False,
        vm=dict(
            moid=None,
            name=None
        )
    )

    cust_module = VMCustomizationModule(module)
    cust_module.check_customization_spec()
    if not module.check_mode:
        cust_module.apply_customization_spec()
    result['vm']['moid'] = cust_module.vm._GetMoId()
    result['vm']['name'] = cust_module.vm.name
    result['changed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    main()
