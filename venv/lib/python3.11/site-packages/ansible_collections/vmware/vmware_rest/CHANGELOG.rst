=================================
vmware.vmware\_rest Release Notes
=================================

.. contents:: Topics

v4.9.0
======

Major Changes
-------------

- Remove ``cloud.common`` as a dependency, so it will not be installed automatically anymore (https://github.com/ansible-collections/vmware.vmware_rest/pull/621).

Known Issues
------------

- The lookup plugins use ``cloud.common``, but this collection does not support ansible-core 2.19 or higher (https://github.com/ansible-collections/vmware.vmware_rest/pull/621).

v4.8.1
======

Bugfixes
--------

- Allow cloud.common 5.0.0 and later again (https://github.com/ansible-collections/vmware.vmware_rest/pull/614).

v4.8.0
======

Major Changes
-------------

- modules - disable turbo mode for module execution by default. Make it optional to enable it using an environment variable (https://github.com/ansible-collections/vmware.vmware_rest/issues/499)

Minor Changes
-------------

- change cloud.common dependency to 4.1 to support anisble 2.19

Deprecated Features
-------------------

- lookup plugins - Deprecate all lookup plugins in favor of vmware.vmware.moid_from_path (https://github.com/ansible-collections/vmware.vmware_rest/pull/608)

v4.7.0
======

Minor Changes
-------------

- Deprecated modules with redundant functionality in vmware.vmware. The next major release is currently not planned, so no removal date is provided. See https://github.com/ansible-collections/vmware.vmware_rest/issues/589

v4.6.0
======

v4.5.0
======

Minor Changes
-------------

- info - changed relative links in README.md to absolute links

Bugfixes
--------

- module_utils - fixed return value for vmware.vmware_rest.vcenter_vm_guest_filesystem_directories module

v4.4.0
======

Bugfixes
--------

- vcenter_ovf_libraryitem - Update documentation to mention the metadata cannot be updated via conventional means. Added example showing workaround (https://github.com/ansible-collections/vmware.vmware_rest/issues/385)

v4.3.0
======

Deprecated Features
-------------------

- content_library_item_info - the module has been deprecated and will be removed in vmware.vmware_rest 5.0.0

Bugfixes
--------

- lookup plugins - Fixed issue where datacenter search filter was never properly set

v4.2.0
======

Minor Changes
-------------

- add a new ci job to the collection to run integration tests on bm vmware env
- vcenter_vm_guest_customization - Added better examples that cover more use-cases (https://github.com/ansible-collections/vmware.vmware_rest/pull/534).

Bugfixes
--------

- Fixed grammatical error in vcenter_rest_log_file parameter description
- vcenter_vm_guest_customization - Fixed typos and spacing in the module examples

v4.1.0
======

Minor Changes
-------------

- cluster_moid - Fix bug where lookup would return incosistent results for objects in nested paths. Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- datacenter_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- datastore_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- folder_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- host_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- network_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- resource_pool_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)
- vm_moid - Fix bug where lookup would return incosistent results for objects in nested paths Fixes issues https://github.com/ansible-collections/vmware.vmware_rest/issues/500 https://github.com/ansible-collections/vmware.vmware_rest/pull/445 https://github.com/ansible-collections/vmware.vmware_rest/issues/324 (https://github.com/ansible-collections/vmware.vmware_rest/pull/523)

Bugfixes
--------

- README - fixed various typos in documentation
- lookup - fixed issue where searching for datacenter contents would throw an exception instead of returning expected results

v4.0.1
======

Bugfixes
--------

- Removed the scenario guides which are pretty much unmaintained and, therefor, possibly outdated and misleading (https://github.com/ansible-collections/vmware.vmware_rest/pull/524).

v4.0.0
======

Minor Changes
-------------

- cluster_moid - updated documentation around lookup plugin usage
- datacenter_moid - updated documentation around lookup plugin usage
- datastore_moid - updated documentation around lookup plugin usage
- folder_moid - updated documentation around lookup plugin usage
- host_moid - updated documentation around lookup plugin usage
- network_moid - updated documentation around lookup plugin usage
- resource_pool_moid - updated documentation around lookup plugin usage
- vm_moid - updated documentation around lookup plugin usage

Breaking Changes / Porting Guide
--------------------------------

- Removing any support for ansible-core <=2.14

v3.0.1
======

Minor Changes
-------------

- Add requires_ansible to manifest (https://github.com/ansible-community/ansible.content_builder/pull/76).
- Generate action_groups for the vmware.vmware_rest collection (https://github.com/ansible-community/ansible.content_builder/issues/75).
- Use folder attribute for host and dc module only (https://github.com/ansible-community/ansible.content_builder/pull/79).

Bugfixes
--------

- content_library_item_info - fixed error with unsupported property
- lookup plugins - Refactor to use native options configuration via doc_fragment, which ensures that vcenter_validate_certs=false is honored (https://github.com/ansible-collections/vmware.vmware_rest/issues/425).

v3.0.0
======

Release Summary
---------------

This major release drops support for ansible-core versions lower than 2.14. The vmware.vmware_rest colllection 3.0.0 supports vSphere versions greater than 7.0.3.

Minor Changes
-------------

- Use 7.0 U3 API spec to build the modules (https://github.com/ansible-collections/vmware.vmware_rest/pull/449).

Breaking Changes / Porting Guide
--------------------------------

- Remove support for ansible-core < 2.14

v2.3.1
======

Minor Changes
-------------

- set version in galaxy.yml to allow install from git repo

Bugfixes
--------

- Allow filters with the space (See: https://github.com/ansible-collections/vmware.vmware_rest/issues/362).
- Handle spaces and special characters in resource names for lookup plugins (See: https://github.com/ansible-collections/vmware.vmware_rest/issues/356).

v2.3.0
======

New Modules
-----------

- vcenter_vm_guest_customization - Applies a customization specification on the virtual machine
- vcenter_vm_guest_power - Issues a request to the guest operating system asking it to perform a soft shutdown, standby (suspend) or soft reboot
- vcenter_vm_guest_power_info - Returns information about the guest operating system power state.
- vcenter_vm_storage_policy_compliance - Returns the storage policy Compliance {@link Info} of a virtual machine after explicitly re-computing compliance check.
- vcenter_vm_tools_installer - Connects the VMware Tools CD installer as a CD-ROM for the guest operating system
- vcenter_vm_tools_installer_info - Get information about the VMware Tools installer.

v2.2.0
======

Minor Changes
-------------

- Add news example for clone, instant clone and template on Content Library.
- documentation - clarify that the VMware vCenter API doesn't allow the cloning of template if there are not if Library.
- vcenter_vm - Add new examples (clone and instant clone).

Bugfixes
--------

- vcenter_datacenter - Ensure the idempotency works as expected.

New Modules
-----------

- vcenter_vmtemplate_libraryitems - Creates a library item in content library from a virtual machine
- vcenter_vmtemplate_libraryitems_info - Returns information about a virtual machine template contained in the library item specified by {@param.name templateLibraryItem}

v2.1.6
======

v2.1.5
======

Minor Changes
-------------

- Adjust the release version of the lookup plugins fro, 2.0.1 to 2.1.0.
- ``vcenter_network_info`` - add an example with a Distributed Virtual Switch, a.k.a dvswitch (https://github.com/ansible-collections/vmware.vmware_rest/pull/316).

Bugfixes
--------

- Adjust the cloud.common dependency to require 2.0.4 or greater (https://github.com/ansible-collections/vmware.vmware_rest/pull/315).

v2.1.4
======

Minor Changes
-------------

- Add more EXAMPLE blocks in the documenation of the modules.

Bugfixes
--------

- Add support for Python 3.10.

v2.1.3
======

Minor Changes
-------------

- The module_utils/vmware.py is licensed under BSD.
- add some missing example blocks.

Bugfixes
--------

- "remove the following modules vcenter_vm_guest_environment_info vcenter_vm_guest_environment_info " "vcenter_vm_guest_filesystemy vcenter_vm_guest_filesystem_files vcenter_vm_guest_filesystem_files_info " "vcenter_vm_guest_processes vcenter_vm_guest_processes_info because they don't work as expected."

v2.1.2
======

Minor Changes
-------------

- The examples uses the FQCN of the built-in modules

Bugfixes
--------

- vcenter_ovf_libraryitem - properly catch errors.

v2.1.1
======

Minor Changes
-------------

- ``content_subscribedlibrary`` - use FQCN in the example.

Bugfixes
--------

- Address a condition where the subkey item was not properly identified (https://github.com/ansible-collections/vmware_rest_code_generator/pull/181).
- vcenter_datacenter - Ensure pass stat=absent on a non-existing item won't raise an error (https://github.com/ansible-collections/vmware_rest_code_generator/pull/182).
- vcenter_vm_guest_customize - Add examples.
- vcenter_vm_hardware_ethernet - Ensure we can attach a NIC to another network (https://github.com/ansible-collections/vmware.vmware_rest/issues/267).

v2.1.0
======

Minor Changes
-------------

- ``vcenter_vm_guest_customization`` - remove the module until vSphere API end-point work properly.
- bump the default timeout to 600s to give more time to the slow operations.
- new moid lookup filter plugins to convert a resource path to a MOID.
- use turbo mode cache for lookup plugins.

Bugfixes
--------

- ``appliance_networking_dns_servers`` - returns error on failure.

v2.0.0
======

Minor Changes
-------------

- Handle import error with correct exception raised while importing aiohttp

Breaking Changes / Porting Guide
--------------------------------

- The vmware_rest 2.0.0 support vSphere 7.0.2 onwards.
- vcenter_vm_storage_policy - the format of the ``disks`` parameter has changed.
- vcenter_vm_storage_policy - the module has a new mandatory paramter: ``vm_home``.

Bugfixes
--------

- Properly handle ``validate_certs`` as a boolean and accept all the standard Ansible values (``yes``, ``true``, ``y``, ``no``, etc).

New Modules
-----------

- appliance_access_consolecli - Set enabled state of the console-based controlled CLI (TTY1).
- appliance_access_consolecli_info - Get enabled state of the console-based controlled CLI (TTY1).
- appliance_access_dcui - Set enabled state of Direct Console User Interface (DCUI TTY2).
- appliance_access_dcui_info - Get enabled state of Direct Console User Interface (DCUI TTY2).
- appliance_access_shell - Set enabled state of BASH, that is, access to BASH from within the controlled CLI.
- appliance_access_shell_info - Get enabled state of BASH, that is, access to BASH from within the controlled CLI.
- appliance_access_ssh - Set enabled state of the SSH-based controlled CLI.
- appliance_access_ssh_info - Get enabled state of the SSH-based controlled CLI.
- appliance_health_applmgmt_info - Get health status of applmgmt services.
- appliance_health_database_info - Returns the health status of the database.
- appliance_health_databasestorage_info - Get database storage health.
- appliance_health_load_info - Get load health.
- appliance_health_mem_info - Get memory health.
- appliance_health_softwarepackages_info - Get information on available software updates available in the remote vSphere Update Manager repository
- appliance_health_storage_info - Get storage health.
- appliance_health_swap_info - Get swap health.
- appliance_health_system_info - Get overall health of system.
- appliance_infraprofile_configs - Exports the desired profile specification.
- appliance_infraprofile_configs_info - List all the profiles which are registered.
- appliance_localaccounts - Create a new local user account.
- appliance_localaccounts_globalpolicy - Set the global password policy.
- appliance_localaccounts_globalpolicy_info - Get the global password policy.
- appliance_localaccounts_info - Get the local user account information.
- appliance_monitoring_info - Get monitored item info
- appliance_monitoring_query - Get monitoring data.
- appliance_networking - Reset and restarts network configuration on all interfaces, also this will renew the DHCP lease for DHCP IP address.
- appliance_networking_dns_domains - Set DNS search domains.
- appliance_networking_dns_domains_info - Get list of DNS search domains.
- appliance_networking_dns_hostname - Set the Fully Qualified Domain Name.
- appliance_networking_dns_hostname_info - Get the Fully Qualified Doman Name.
- appliance_networking_dns_servers - Set the DNS server configuration
- appliance_networking_dns_servers_info - Get DNS server configuration.
- appliance_networking_firewall_inbound - Set the ordered list of firewall rules to allow or deny traffic from one or more incoming IP addresses
- appliance_networking_firewall_inbound_info - Get the ordered list of firewall rules
- appliance_networking_info - Get Networking information for all configured interfaces.
- appliance_networking_interfaces_info - Get information about a particular network interface.
- appliance_networking_interfaces_ipv4 - Set IPv4 network configuration for specific network interface.
- appliance_networking_interfaces_ipv4_info - Get IPv4 network configuration for specific NIC.
- appliance_networking_interfaces_ipv6 - Set IPv6 network configuration for specific interface.
- appliance_networking_interfaces_ipv6_info - Get IPv6 network configuration for specific interface.
- appliance_networking_noproxy - Sets servers for which no proxy configuration should be applied
- appliance_networking_noproxy_info - Returns servers for which no proxy configuration will be applied.
- appliance_networking_proxy - Configures which proxy server to use for the specified protocol
- appliance_networking_proxy_info - Gets the proxy configuration for a specific protocol.
- appliance_ntp - Set NTP servers
- appliance_ntp_info - Get the NTP configuration status
- appliance_services - Restarts a service
- appliance_services_info - Returns the state of a service.
- appliance_shutdown - Cancel pending shutdown action.
- appliance_shutdown_info - Get details about the pending shutdown action.
- appliance_system_globalfips - Enable/Disable Global FIPS mode for the appliance
- appliance_system_globalfips_info - Get current appliance FIPS settings.
- appliance_system_storage - Resize all partitions to 100 percent of disk size.
- appliance_system_storage_info - Get disk to partition mapping.
- appliance_system_time_info - Get system time.
- appliance_system_time_timezone - Set time zone.
- appliance_system_time_timezone_info - Get time zone.
- appliance_system_version_info - Get the version.
- appliance_timesync - Set time synchronization mode.
- appliance_timesync_info - Get time synchronization mode.
- appliance_update_info - Gets the current status of the appliance update.
- appliance_vmon_service - Lists details of services managed by vMon.
- appliance_vmon_service_info - Returns the state of a service.
- content_configuration - Updates the configuration
- content_configuration_info - Retrieves the current configuration values.
- content_library_item_info - Returns the {@link ItemModel} with the given identifier.
- content_locallibrary - Creates a new local library.
- content_locallibrary_info - Returns a given local library.
- content_subscribedlibrary - Creates a new subscribed library
- content_subscribedlibrary_info - Returns a given subscribed library.
- vcenter_ovf_libraryitem - Creates a library item in content library from a virtual machine or virtual appliance
- vcenter_vm_guest_environment_info - Reads a single environment variable from the guest operating system
- vcenter_vm_guest_filesystem - Initiates an operation to transfer a file to or from the guest
- vcenter_vm_guest_filesystem_directories - Creates a directory in the guest operating system
- vcenter_vm_guest_filesystem_files - Creates a temporary file
- vcenter_vm_guest_filesystem_files_info - Returns information about a file or directory in the guest
- vcenter_vm_guest_operations_info - Get information about the guest operation status.
- vcenter_vm_guest_processes - Starts a program in the guest operating system
- vcenter_vm_guest_processes_info - Returns the status of a process running in the guest operating system, including those started by {@link Processes#create} that may have recently completed

v1.0.2
======

Minor Changes
-------------

- vcenter_resourcepool - add example in documentation.
- vcenter_resourcepool_info - add example in documentation.

v1.0.1
======

Minor Changes
-------------

- Ensure the shellcheck sanity test pass

v1.0.0
======

Minor Changes
-------------

- documentation - clarify that we don't have any required parameters.
- vcenter_host_connect - remove the module, use ``vcenter_host``
- vcenter_host_disconnect - remove the module, use ``vcenter_host``
- vcenter_storage_policies - remove vcenter_storage_policies
- vcenter_storage_policies_compliance_vm_info - remove the module
- vcenter_storage_policies_entities_compliance_info - remove the module
- vcenter_storage_policies_vm_info - remove the module

New Modules
-----------

- vcenter_cluster_info - Collect the information associated with the vCenter clusters
- vcenter_datacenter - Manage the datacenter of a vCenter
- vcenter_datacenter_info - Collect the information associated with the vCenter datacenters
- vcenter_datastore_info - Collect the information associated with the vCenter datastores
- vcenter_folder_info - Collect the information associated with the vCenter folders
- vcenter_host - Manage the host of a vCenter
- vcenter_host_info - Collect the information associated with the vCenter hosts
- vcenter_network_info - Collect the information associated with the vCenter networks
- vcenter_resourcepool - Manage the resourcepool of a vCenter
- vcenter_resourcepool_info - Collect the information associated with the vCenter resourcepools
- vcenter_storage_policies_info - Collect the information associated with the vCenter storage policiess
- vcenter_vm - Manage the vm of a vCenter
- vcenter_vm_guest_identity_info - Collect the guest identity information
- vcenter_vm_guest_localfilesystem_info - Collect the guest localfilesystem information
- vcenter_vm_guest_networking_info - Collect the guest networking information
- vcenter_vm_guest_networking_interfaces_info - Collect the guest networking interfaces information
- vcenter_vm_guest_networking_routes_info - Collect the guest networking routes information
- vcenter_vm_hardware - Manage the hardware of a VM
- vcenter_vm_hardware_adapter_sata - Manage the SATA adapter of a VM
- vcenter_vm_hardware_adapter_sata_info - Collect the SATA adapter information from a VM
- vcenter_vm_hardware_adapter_scsi - Manage the SCSI adapter of a VM
- vcenter_vm_hardware_adapter_scsi_info - Collect the SCSI adapter information from a VM
- vcenter_vm_hardware_boot - Manage the boot of a VM
- vcenter_vm_hardware_boot_device - Manage the boot device of a VM
- vcenter_vm_hardware_boot_device_info - Collect the boot device information from a VM
- vcenter_vm_hardware_boot_info - Collect the boot information from a VM
- vcenter_vm_hardware_cdrom - Manage the cdrom of a VM
- vcenter_vm_hardware_cdrom_info - Collect the cdrom information from a VM
- vcenter_vm_hardware_cpu - Manage the cpu of a VM
- vcenter_vm_hardware_cpu_info - Collect the cpu information from a VM
- vcenter_vm_hardware_disk - Manage the disk of a VM
- vcenter_vm_hardware_disk_info - Collect the disk information from a VM
- vcenter_vm_hardware_ethernet - Manage the ethernet of a VM
- vcenter_vm_hardware_ethernet_info - Collect the ethernet information from a VM
- vcenter_vm_hardware_floppy - Manage the floppy of a VM
- vcenter_vm_hardware_floppy_info - Collect the floppy information from a VM
- vcenter_vm_hardware_info - Manage the info of a VM
- vcenter_vm_hardware_memory - Manage the memory of a VM
- vcenter_vm_hardware_memory_info - Collect the memory information from a VM
- vcenter_vm_hardware_parallel - Manage the parallel of a VM
- vcenter_vm_hardware_parallel_info - Collect the parallel information from a VM
- vcenter_vm_hardware_serial - Manage the serial of a VM
- vcenter_vm_hardware_serial_info - Collect the serial information from a VM
- vcenter_vm_info - Collect the  information from a VM
- vcenter_vm_libraryitem_info - Collect the libraryitem  information from a VM
- vcenter_vm_power - Manage the power of a VM
- vcenter_vm_power_info - Collect the power  information from a VM
- vcenter_vm_storage_policy - Manage the storage policy of a VM
- vcenter_vm_storage_policy_compliance_info - Collect the storage policy compliance  information from a VM
- vcenter_vm_storage_policy_info - Collect the storage policy  information from a VM
- vcenter_vm_tools - Manage the tools of a VM
- vcenter_vm_tools_info - Collect the tools  information from a VM

v0.4.0
======

Minor Changes
-------------

- The format of the output of the Modules is now documented in the RETURN block.
- vcenter_rest_log_file - this optional parameter can be used to point on the log file where all the HTTP interaction will be record.

v0.3.0
======

Minor Changes
-------------

- Better documentation
- The module RETURN sections are now defined.
- vcenter_resourcepool - new module
- vcenter_resourcepool_info - new module
- vcenter_storage_policies - new module
- vcenter_storage_policies_compliance_vm_info - new module
- vcenter_storage_policies_entities_compliance_info - new module
- vcenter_storage_policies_info - new module
- vcenter_storage_policies_vm_info - new module

Deprecated Features
-------------------

- vcenter_vm_storage_policy_compliance - drop the module, it returns 404 error.
- vcenter_vm_tools - remove the ``upgrade`` state.
- vcenter_vm_tools_installer - remove the module from the collection.

v0.2.0
======

Bugfixes
--------

- Improve the documentation of the modules
- minor_changes - drop vcenter_vm_compute_policies_info because the API is flagged as Technology Preview
- minor_changes - drop vcenter_vm_console_tickets because the API is flagged as Technology Preview
- minor_changes - drop vcenter_vm_guest_power and keep vcenter_vm_power which provides the same features

v0.1.0
======

Bugfixes
--------

- Fix logic in vmware_cis_category_info module.
