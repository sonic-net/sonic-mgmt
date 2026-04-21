=============================
kaytus.ksmanage Release Notes
=============================

.. contents:: Topics


v2.0.0
======

Major Changes
-------------

- Add new modules system_lock_mode_info, edit_system_lock_mode(https://github.com/ieisystem/kaytus.ksmanage/pull/27).

Bugfixes
--------

- Edit ansible devel version tests to our CI test scripts (https://github.com/ieisystem/kaytus.ksmanage/pull/26).
- Modify the title information in changelogs config.yaml (https://github.com/ieisystem/kaytus.ksmanage/pull/25).

New Modules
-----------

- edit_system_lock_mode - Set system lock mode information
- system_lock_mode_info - Get system lock mode information

v1.2.2
======

Bugfixes
--------

- Remove venv files that were accidentally bundled in 1.2.2(https://github.com/ieisystem/kaytus.ksmanage/pull/23).

v1.2.1
======

Bugfixes
--------

- Change the example gather_facts no to false(https://github.com/ieisystem/kaytus.ksmanage/pull/20).
- Delete the unwanted links.yml file (https://github.com/ieisystem/kaytus.ksmanage/pull/21).

v1.2.0
======

Removed Features (previously deprecated)
----------------------------------------

- add_ldisk - Delete the ``add_ldisk.info`` parameter. Use ``kaytus.ksmanage.pdisk_info`` instead (https://github.com/ieisystem/kaytus.ksmanage/pull/17).
- edit_ldisk - Delete the ``edit_ldisk.info`` parameter. Use ``kaytus.ksmanage.ldisk_info`` instead (https://github.com/ieisystem/kaytus.ksmanage/pull/17).
- edit_pdisk - Delete the ``edit_pdisk.info`` parameter. Use ``kaytus.ksmanage.pdisk_info`` instead (https://github.com/ieisystem/kaytus.ksmanage/pull/17).

Bugfixes
--------

- Add ansible 2.17 version tests to our CI test scripts (https://github.com/ieisystem/kaytus.ksmanage/pull/16).
- Delete the useless __init__.py file in modules and module_utils (https://github.com/ieisystem/kaytus.ksmanage/pull/15).
- ksmanage - Changed the message that no dependencies were installed (https://github.com/ieisystem/kaytus.ksmanage/pull/18).

v1.1.3
======

Minor Changes
-------------

- Change the value of the dn field in the example so that the written argument does not contain Spaces.

v1.1.2
======

Minor Changes
-------------

- Fix problems such as typos or grammatical errors in the document.

v1.1.1
======

Minor Changes
-------------

- Fix any issues in your module that don't meet the ansible module format and documentation requirements.

v1.1.0
======

Minor Changes
-------------

- Fix any issues in your module that don't meet the ansible module format and documentation requirements.

v1.0.0
======

Major Changes
-------------

- add all modules.

Minor Changes
-------------

- Modify the README.md file version to publish the reference link.

Bugfixes
--------

- Modify the inmanage error referenced in modules utils.

New Modules
-----------

- ad_group - Manage active directory group information
- ad_group_info - Get active directory group information
- ad_info - Get active directory information
- adapter_info - Get adapter information
- add_ldisk - Create logical disk
- alert_policy_info - Get alert policy
- audit_log_info - Get BMC audit log information
- auto_capture_info - Get auto capture screen information
- backplane_info - Get disk backplane information
- backup - Backup server settings
- bios_export - Export BIOS config
- bios_import - Import BIOS config
- bios_info - Get BIOS setup
- bmc_info - Get BMC information
- boot_image_info - Get bmc boot image information
- boot_option_info - Get BIOS boot options
- clear_audit_log - Clear BMC audit log
- clear_event_log - Clear event log
- clear_system_log - Clear BMC system log
- collect_blackbox - Collect blackbox log
- collect_log - Collect logs
- connect_media_info - Get remote images redirection information
- cpu_info - Get CPU information
- del_session - Delete session
- dns_info - Get dns information
- download_auto_screenshot - Download auto screenshots
- download_manual_screenshot - Download manual screenshots
- edit_ad - Set active directory information
- edit_alert_policy - Set alert policy
- edit_auto_capture - Set auto capture screen
- edit_bios - Set BIOS setup attributes
- edit_boot_image - Set bmc boot image
- edit_boot_option - Set BIOS boot options
- edit_connect_media - Start/Stop virtual media Image
- edit_dns - Set dns information
- edit_event_log_policy - Set event log policy
- edit_fan - Set fan information
- edit_fru - Set fru settings
- edit_ipv4 - Set ipv4 information
- edit_ipv6 - Set ipv6 information
- edit_kvm - Set KVM
- edit_ldap - Set ldap information
- edit_ldisk - Set logical disk
- edit_log_setting - Set bmc system and audit log setting
- edit_m6_log_setting - Set bmc system and audit log setting
- edit_manual_capture - Set manual capture screen
- edit_media_instance - Set Virtual Media Instance
- edit_ncsi - Set ncsi information
- edit_network - Set network information
- edit_network_bond - Set network bond
- edit_network_link - Set network link
- edit_ntp - Set NTP
- edit_pdisk - Set physical disk
- edit_power_budget - Set power budget information
- edit_power_restore - Set power restore information
- edit_power_status - Set power status information
- edit_preserve_config - Set preserve config
- edit_psu_config - Set psu config information
- edit_psu_peak - Set psu peak information
- edit_restore_factory_default - Set preserver config
- edit_service - Set service settings
- edit_smtp - Set SMTP information
- edit_smtp_com - Set SMTP information
- edit_smtp_dest - Set SMTP information
- edit_snmp - Set snmp
- edit_snmp_trap - Set snmp trap
- edit_threshold - Set threshold information
- edit_uid - Set UID
- edit_virtual_media - Set virtual media
- edit_vlan - Set vlan information
- event_log_info - Get event log information
- event_log_policy_info - Get event log policy information
- fan_info - Get fan information
- fru_info - Get fru information
- fw_version_info - Get firmware version information
- gpu_info - Get GPU information
- hard_disk_info - Get hard disk information
- hba_info - Get CPU information
- kvm_info - Get KVM information
- ldap_group - Manage ldap group information
- ldap_group_info - Get ldap group information
- ldap_info - Get ldap information
- ldisk_info - Get logical disks information
- log_setting_info - Get bmc log setting information
- media_instance_info - Get Virtual Media Instance information
- mem_info - Get memory information
- ncsi_info - Get ncsi information
- network_bond_info - Get network bond information
- network_info - Get network information
- network_link_info - Get network link information
- ntp_info - Get NTP information
- onboard_disk_info - Get onboard disks information
- pcie_info - Get PCIE information
- pdisk_info - Get physical disks information
- power_budget_info - Get power budget information
- power_consumption_info - Get power consumption information
- power_restore_info - Get power restore information
- power_status_info - Get power status information
- preserve_config_info - Get preserve config information
- psu_config_info - Get psu config information
- psu_info - Get psu information
- psu_peak_info - Get psu peak information
- raid_info - Get RAID/HBA card and controller information
- reset_bmc - BMC reset
- reset_kvm - KVM reset
- restore - Restore server settings
- self_test_info - Get self test information
- sensor_info - Get sensor information
- server_info - Get server status information
- service_info - Get service information
- session_info - Get online session information
- smtp_info - Get SMTP information
- snmp_info - Get snmp get/set information
- snmp_trap_info - Get snmp trap information
- support_info - Get support information
- system_log_info - Get BMC system log information
- temp_info - Get temp information
- threshold_info - Get threshold information
- uid_info - Get UID information
- update_cpld - Update CPLD
- update_fw - Update firmware
- update_psu - Update PSU
- user - Manage user
- user_group - Manage user group
- user_group_info - Get user group information
- user_info - Get user information
- virtual_media_info - Get Virtual Media information
- volt_info - Get volt information
