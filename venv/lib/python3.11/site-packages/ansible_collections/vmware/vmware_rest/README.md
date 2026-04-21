# Ansible Collection: vmware.vmware_rest

This repo hosts the `vmware.vmware_rest` Ansible Collection.

The **vmware.vmware_rest** collection is part of the **Red Hat Ansible Certified Content for VMware** offering that brings Ansible automation to VMware. This collection brings forward the possibility to manage vSphere resources and automate operator tasks.

This collection is based upon VMware vSphere REST API interface and does not rely on the VMware SDKs [`Pyvmomi`](https://github.com/vmware/pyvmomi) and [`vSphere Automation SDK for Python`](https://github.com/vmware/vsphere-automation-sdk-python).

System programmers can enable pipelines to setup, tear down and deploy VMs while system administrators can automate time consuming repetitive tasks inevitably freeing up their time. New VMware users can find comfort in Ansible's familiarity and expedite their proficiency in record time.

### Known limitations

#### VM Template and folder structure

These modules are based on the [vSphere REST API](https://developer.vmware.com/apis/vsphere-automation/latest/). This API doesn't provide any mechanism to list or clone VM templates when they are stored in a VM folder.
To circumvent this limitation, you should store your VM templates in a [Content Library](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.vm_admin.doc/GUID-254B2CE8-20A8-43F0-90E8-3F6776C2C896.html).

#### Slower execution times

This collection is capable of leveraging a feature of the cloud.common collection called the "turbo server". This is a caching mechanism that speeds up repeated API calls, but it does come with some downsides.

This collection has used turbo mode up until version 4.8.0. With the release of 4.8.0, turbo mode is disabled by default but can be re-enabled using an environment variable. Read more [here](docs/turbo_mode.md).



## Requirements

The host running the tasks must have the python requirements described in [requirements.txt](https://github.com/ansible-collections/vmware.vmware_rest/blob/main/requirements.txt)
Once the collection is installed, you can install them into a python environment using pip: `pip install -r ~/.ansible/collections/ansible_collections/vmware/vmware_rest/requirements.txt`

### vSphere compatibility

The 3.0.0 version of this collection supports vSphere 7.x.
The 4.0.0 version of this collection supports vSphere 8.x.

### Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.15.0**.


## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install vmware.vmware_rest
```

You can also include it in a requirements.yml file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```sh
collections:
  - name: vmware.vmware_rest
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```sh
ansible-galaxy collection install vmware.vmware_rest --upgrade
```

You can also install a specific version of the collection, for example, if you need to install a different version. Use the following syntax to install version 1.0.0:

```sh
ansible-galaxy collection install vmware.vmware_rest:1.0.0
```


## Use Cases

* Use Case Name: Modify vCenter Appliance Configuration
  * Actors:
    * System Admin
  * Description:
    * A systems administrator can modify the configuration of a running vCenter appliance.
  * Modules:
    * `vmware.vmware_rest.appliance_access_consolecli` - Sets the enabled state of the console-based controlled CLI (TTY1)
    * `vmware.vmware_rest.appliance_access_dcui` - Sets the enabled state of Direct Console User Interface (DCUI TTY2)
    * `vmware.vmware_rest.appliance_access_shell` - Sets the enabled state of BASH, that is, access to BASH from within the controlled CLI
    * `vmware.vmware_rest.appliance_access_ssh` - Sets the enabled state of the SSH-based controlled CLI
    * `vmware.vmware_rest.appliance_networking_dns_domains` - Sets DNS search domains
    * `vmware.vmware_rest.appliance_networking_dns_hostname` - Sets the Fully Qualified Domain Name
    * `vmware.vmware_rest.appliance_networking_dns_servers` - Sets the DNS server configuration
    * `vmware.vmware_rest.appliance_networking_firewall_inbound` - Sets the ordered list of firewall rules to allow or deny traffic from one or more incoming IP addresses
    * `vmware.vmware_rest.appliance_networking_interfaces_ipv4` - Sets the IPv4 network configuration for specific network interface
    * `vmware.vmware_rest.appliance_networking_interfaces_ipv6` - Sets the IPv6 network configuration for specific interface
    * `vmware.vmware_rest.appliance_networking_noproxy` - Sets servers for which no proxy configuration should be applied
    * `vmware.vmware_rest.appliance_networking_proxy` - Configures which proxy server to use for the specified protocol
    * `vmware.vmware_rest.appliance_ntp` - Sets the NTP servers
    * `vmware.vmware_rest.appliance_system_globalfips` - Enables/Disables Global FIPS mode for the appliance
    * `vmware.vmware_rest.appliance_system_time_timezone` - Sets the time zone
    * `vmware.vmware_rest.appliance_timesync` - Sets the time synchronization mode
    * `vmware.vmware_rest.appliance_vmon_service` - Lists the details of services managed by vMon

* Use Case Name: Manage a Content Library
  * Actors:
    * System Admin
  * Description:
    * The system administrator can create or manage a content library.
  * Modules:
    * `vmware.vmware_rest.content_configuration` - Updates the library configuration
    * `vmware.vmware_rest.content_locallibrary` - Creates a new local library
    * `vmware.vmware_rest.content_subscribedlibrary` - Creates a new subscribed library

* Use Case Name: Manage a VMs Settings
  * Actors:
    * System Admin
  * Description:
    * The system administrator can manage a VMs settings.
  * Modules:
    * `vmware.vmware_rest.vcenter_vm_guest_customization` - Applies a customization specification on the virtual machine
    * `vmware.vmware_rest.vcenter_vm_guest_filesystem_directories` - Creates a directory in the guest operating system
    * `vmware.vmware_rest.vcenter_vm_guest_power` - Modifies a virtual machine's power state
    * `vmware.vmware_rest.vcenter_vm_hardware_adapter_sata` - Adds a virtual SATA adapter to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_adapter_scsi` - Adds a virtual SCSI adapter to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_boot_device` - Sets the virtual devices that will be used to boot the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_boot` - Updates the boot-related settings of a virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_cdrom` - Adds a virtual CD-ROM device to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_cpu` - Updates the CPU-related settings of a virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_disk` - Adds a virtual disk to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_ethernet` - Adds a virtual Ethernet adapter to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_memory` - Updates the memory-related settings of a virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_parallel` - Adds a virtual parallel port to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware` - Updates the virtual hardware settings of a virtual machine
    * `vmware.vmware_rest.vcenter_vm_hardware_serial` - Adds a virtual serial port to the virtual machine
    * `vmware.vmware_rest.vcenter_vm_power` - Operates a boot, hard shutdown, hard reset or hard suspend on a guest
    * `vmware.vmware_rest.vcenter_vm_storage_policy` - Updates the storage policy configuration of a virtual machine and/or its associated virtual hard disks
    * `vmware.vmware_rest.vcenter_vm_tools_installer` - Connects the VMware Tools CD installer as a CD-ROM for the guest operating system
    * `vmware.vmware_rest.vcenter_vm_tools` - Updates the properties of VMware Tools

## Testing

All releases will meet the following test criteria.

* 100% success for [Integration](https://github.com/ansible-collections/vmware.vmware_rest/blob/main/tests/integration) tests.
* 100% success for [Sanity](https://docs.ansible.com/ansible/latest/dev_guide/testing/sanity/index.html#all-sanity-tests) tests as part of [ansible-test](https://docs.ansible.com/ansible/latest/dev_guide/testing.html#run-sanity-tests).
* 100% success for [ansible-lint](https://ansible.readthedocs.io/projects/lint/) allowing only false positives.


## Contributing

This community is currently accepting contributions. We encourage you to open [git issues](https://github.com/ansible-collections/vmware.vmware_rest/issues) for bugs, comments or feature requests.
Please feel free to submit a PR to resolve the issue. Modules are generated so changes to them most likely will not be applied directly.

Refer to the [Ansible community guide](https://docs.ansible.com/ansible/devel/community/index.html).

### Development

This collection can be generated using the [content_builder](https://github.com/ansible-community/ansible.content_builder) tool. Please refer to the [vmware module generation](https://github.com/ansible-collections/vmware.vmware_rest/blob/main/development.md).


## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'vmware'](https://forum.ansible.com/tag/vmware): subscribe to participate in collection-related conversations.
  * [Ansible VMware Automation Working Group](https://forum.ansible.com/g/ansible-vmware): by joining the team you will automatically get subscribed to the posts tagged with ['vmware'](https://forum.ansible.com/tag/vmware).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).


## Support

As Red Hat Ansible [Certified Content](https://catalog.redhat.com/software/search?target_platforms=Red%20Hat%20Ansible%20Automation%20Platform), this collection is entitled to [support](https://access.redhat.com/support/) through [Ansible Automation Platform](https://www.redhat.com/en/technologies/management/ansible) (AAP).

If a support case cannot be opened with Red Hat and the collection has been obtained either from [Galaxy](https://galaxy.ansible.com/ui/) or [GitHub](https://github.com/ansible-collections/vmware.vmware_rest), there is community support available at no charge. Community support is limited to the collection; community support does not include any of the Ansible Automation Platform components or [ansible-core](https://github.com/ansible/ansible).


## Release Notes and Roadmap

A list of available releases can be found on the github [release page](https://github.com/ansible-collections/vmware.vmware_rest/releases).
A changelog may be found attached to the release, or in the [CHANGELOG.rst](https://github.com/ansible-collections/vmware.vmware_rest/blob/main/CHANGELOG.rst)

Note, some collections release before an ansible-core version reaches End of Life (EOL), thus the version of ansible-core that is supported must be a version that is currently supported.
For AAP users, to see the supported ansible-core versions, review the [AAP Life Cycle](https://access.redhat.com/support/policy/updates/ansible-automation-platform).
For Galaxy and GitHub users, to see the supported ansible-core versions, review the [ansible-core support matrix](https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix).


## Related Information

The `vmware.vmware` collection offers additional functionality. It is also a certified collection.
The `community.vmware` collection offers additional community supported functionality.

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)

## License Information

GNU General Public License v3.0 or later
See [LICENSE](https://github.com/ansible-collections/vmware.vmware_rest/blob/main/LICENSE) to see the full text.
