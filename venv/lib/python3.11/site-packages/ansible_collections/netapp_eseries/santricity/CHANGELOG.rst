===================================================
Netapp E-Series SANtricity Collection Release Notes
===================================================

.. contents:: Topics


v1.4.1
======

Bugfixes
--------

- Fixed pep8, pylint, and validate-modules issues found by ansible-test.
- Updated outdated command in unit tests.

v1.4.0
======

Minor Changes
-------------

- netapp_eseries.santricity.na_santricity_iscsi_interface - Add support of iSCSI HIC speed.
- netapp_eseries.santricity.nar_santricity_host - Add support of iSCSI HIC speed.

Bugfixes
--------

- netapp_eseries.santricity.na_santricity_mgmt_interface - Add the ability to configure DNS, NTP and SSH separately from management interfaces.
- netapp_eseries.santricity.nar_santricity_host - Fix default MTU value for NVMe RoCE.
- netapp_eseries.santricity.nar_santricity_management - Add tasks to set DNS, NTP and SSH globally separately from management interfaces.

v1.3.1
======

Minor Changes
-------------

- Require Ansible 2.10 or later.
- na_santricity_volume - Add size_tolerance option to handle the difference in volume size with SANtricity System Manager.
- nar_santricity_common - utilize provided eseries management information to determine network to search.

Bugfixes
--------

- na_santricity_mgmt_interface - Fix default required_if state option for na_santricity_mgmt_interface
- netapp_eseries.santricity.nar_santricity_host - Fix default MTU value for NVMe RoCE.

v1.3.0
======

Minor Changes
-------------

- na_santricity_global - Add controller_shelf_id argument to set controller shelf identifier.
- na_santricity_volume - Add flag to control whether volume expansion operations are allowed.
- na_santricity_volume - Add volume write cache mirroring option.
- nar_santricity_host - Add volume write cache mirroring options.

Bugfixes
--------

- santricity_host - Ensure a list of volumes are provided to prevent netapp_eseries.santricity.santricity_host (lookup) index is string not integer exception.

v1.2.13
=======

Bugfixes
--------

- Fix availability of client certificate change.

v1.2.12
=======

Bugfixes
--------

- Fix host and host port names from being changed to lower case.

v1.2.11
=======

Bugfixes
--------

- Fix login banner message option bytes error in na_santricity_global.

v1.2.10
=======

Minor Changes
-------------

- Add login banner message to na_santricity_global module and nar_santricity_management role.
- Add usable drive option for na_santricity_storagepool module and nar_santricity_host role which can be used to choose selected drives for storage pool/volumes or define a pattern drive selection.

Bugfixes
--------

- Fix PEM certificate/key imports in the na_santricity_server_certificate module.
- Fix na_santricity_mgmt_interface IPv4 and IPv6 form validation.

v1.2.9
======

Minor Changes
-------------

- Add eseries_system_old_password variable to faciliate changing the storage system's admin password.
- Add remove_unspecified_user_certificates variable to the client certificates module.

Bugfixes
--------

- Fix missing proxy client and server certificate in management role.
- Fix missing proxy validate_certs and change current proxy password variables.
- Fix server certificate module not forwarding certificate imports to the embedded web services.

v1.2.8
======

Bugfixes
--------

- Fix pkcs8 private key passphrase issue.
- Fix storage system admin password change from web services proxy in na_santricity_auth module.

v1.2.7
======

v1.2.6
======

Bugfixes
--------

- Fix jinja issue with collecting certificates paths in nar_santricity_management role.

v1.2.5
======

Bugfixes
--------

- Add missing http(s) proxy username and password parameters from na_santricity_asup module and nar_santricity_management role."
- Add missing storage pool configuration parameter, criteria_drive_interface_type, to nar_santricity_host role.

v1.2.4
======

v1.2.3
======

Minor Changes
-------------

- Added nvme4k as a drive type interface to the na_santricity_storagepool module.
- Added options for critical and warning threshold setting in na_santricity_storagepool module and nar_santricity_host role.
- Fix dynamic disk pool critical and warning threshold settings.

Bugfixes
--------

- Fix drive firmware upgrade issue that prevented updating firware when drive was in use.

v1.2.2
======

v1.2.1
======

Release Summary
---------------

Release 1.2.2 simply removes resource-provisioned volumes feature from collection.

Minor Changes
-------------

- Add IPv6 and FQDN support for NTP
- Add IPv6 support for DNS
- Add criteria_drive_max_size option to na_santricity_storagepool and nar_santricity_host role.
- Add resource-provisioned volumes option to globals and nar_santricity_management role.
- Remove resource-provisioned volumes setting from na_santicity_global module and nar_santricity_management role."

v1.2.0
======

Release Summary
---------------

1.2.0 release of ``netapp_eseries.santricity`` collection on 2021-03-01.

Minor Changes
-------------

- na_santricity_discover - Add support for discovering storage systems directly using devmgr/v2/storage-systems/1/about endpoint since its old method of discover is being deprecated.
- na_santricity_facts - Add storage system information to facilitate ``netapp_eseries.host`` collection various protocol configuration.
- na_santricity_server_certificate - New module to configure storage system's web server certificate configuration.
- na_santricity_snapshot - New module to configure NetApp E-Series Snapshot consistency groups any number of base volumes.
- na_santricity_volume - Add percentage size unit (pct) and which allows the creates volumes based on the total storage pool size.
- nar_santricity_host - Add eseries_storage_pool_configuration list options, criteria_volume_count, criteria_reserve_free_capacity_pct, and common_volume_host to facilitate volumes based on percentages of storage pool or volume group.
- nar_santricity_host - Add support for snapshot group creation.
- nar_santricity_host - Improve host mapping information discovery.
- nar_santricity_host - Improve storage system discovery related error messages.
- nar_santricity_management - Add support for server certificate management.

Bugfixes
--------

- nar_santricity_host - Fix README.md examples.

v1.1.0
======

Release Summary
---------------

This release focused on providing volume details to through the netapp_volumes_by_initiators in the na_santricity_facts module, improving on the nar_santricity_common role storage system API information and resolving issues.

Minor Changes
-------------

- Add functionality to remove all inventory configuration in the nar_santricity_host role. Set configuration.eseries_remove_all_configuration=True to remove all storage pool/volume configuration, host, hostgroup, and lun mapping configuration.
- Add host_types, host_port_protocols, host_port_information, hostside_io_interface_protocols to netapp_volumes_by_initiators in the na_santricity_facts module.
- Add storage pool information to the volume_by_initiator facts.
- Add storage system not found exception to the common role's build_info task.
- Add volume_metadata option to na_santricity_volume module, add volume_metadata information to the netapp_volumes_by_initiators dictionary in na_santricity_facts module, and update the nar_santricity_host role with the option.
- Improve nar_santricity_common storage system api determinations; attempts to discover the storage system using the information provided in the inventory before attempting to search the subnet.
- Increased the storage system discovery connection timeouts to 30 seconds to prevent systems from not being discovered over slow connections.
- Minimize the facts gathered for the host initiators.
- Update ib iser determination to account for changes in firmware 11.60.2.
- Use existing Web Services Proxy storage system identifier when one is already created and one is not provided in the inventory.
- Utilize eseries_iscsi_iqn before searching host for iqn in nar_santricity_host role.

Bugfixes
--------

- Fix check_port_type method for ib iser when ib is the port type.
- Fix examples in the netapp_e_mgmt_interface module.
- Fix issue with changing host port name.
- Fix na_santricity_lun_mapping unmapping issue; previously mapped volumes failed to be unmapped.
