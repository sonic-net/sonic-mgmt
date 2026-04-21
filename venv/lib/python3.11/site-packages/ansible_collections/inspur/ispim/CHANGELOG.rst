==========================
Inspur.Ispim Release Notes
==========================

.. contents:: Topics


v2.2.4
======

Bugfixes
--------

- Edit ansible devel version tests to our CI test scripts  (https://github.com/ispim/inspur.ispim/pull/39).
- Modify the automated tests and add support for version 2.18. (https://github.com/ispim/inspur.ispim/pull/40).
- Modify the automated tests and add support for version 2.18. (https://github.com/ispim/inspur.ispim/pull/45).
- Modify the ism.py file in the module_utils directory, and change the reference path of iteritems to be a reference from within Python. (https://github.com/ispim/inspur.ispim/pull/46).

v2.2.3
======

Bugfixes
--------

- Change the ansible version in meta/runtime.yml to 2.15.0(https://github.com/ispim/inspur.ispim/pull/37).

v2.2.2
======

Bugfixes
--------

- Remove venv files that were accidentally bundled in 2.2.1 (https://github.com/ispim/inspur.ispim/pull/35).

v2.2.1
======

Minor Changes
-------------

- Modify ansible-test.yml to add the ansible 2.17 test https://github.com/ispim/inspur.ispim/pull/33.
- Modify ansible-test.yml to add the ansible2.16 test.

v2.2.0
======

Minor Changes
-------------

- Modify edit_smtp_com and add description information.

v2.1.0
======

New Modules
-----------

- inspur.ispim.hba_info - Get CPU information

v2.0.1
======

Minor Changes
-------------

- Change the ansible-test.yml application file version.
- Modify logical disk creation, add MV raid card compatible.

v2.0.0
======

Minor Changes
-------------

- The edit_bios module adds the list field.

New Modules
-----------

- inspur.ispim.update_psu - Update PSU

v1.3.0
======

Minor Changes
-------------

- Change the ansible-test.yml application file version.
- Change the description of the edit_bios module file_url field.
- Modify the description information of the backup module item field.
- Modify the description of the media_attach, retry_count, and retry_time_interval fields of the edit_kvm module.
- Modify the description of the secure_channel field of the edit_media_instance module.
- Modify the description of the slot and vname fields of the add_ldisk module.
- Modify the edit_ntp module example.
- Modify the edit_snmp_trap module version field description information.
- Modify the mode field description information of update_fw module.
- Modify the name field description of the user_group module.
- Modify the restore module example.
- Modify the supporting properties and description information of the edit_ncsi module edit_ncsi field.
- The edit_power_budget module adds the except_action field.

New Modules
-----------

- inspur.ispim.edit_m6_log_setting - Set bmc system and audit log setting
- inspur.ispim.support_info - Get support information

v1.2.0
======

Minor Changes
-------------

- Modify the tags fields in Galaxy.yml.
- edit_power_budget add 'domain' field.
- edit_snmp module add 'v1status','v2status','v3status','read_community','read_write_community' fields.
- edit_snmp_trap module modifies the version value.
- eidt_ad module add 'ssl_enalbe' field, modify the timeout field description.
- eidt_ldisk module add 'duration' field.
- eidt_pdisk module add 'duration' field.
- modify the edit_log_setting module description.
- modify the edit_ncsi module description and parameter values.
- user module add 'uid','access' fields.
- user_group module add 'general','power','media','kvm','security','debug','self' fields.

Bugfixes
--------

- edit_snmp_trap module modifies input parameter errors in the example.

v1.1.0
======

Minor Changes
-------------

- Edit_dns adds new field to M6 model.
- Modify the authors and tags fields in Galaxy.yml.

v1.0.1
======

Minor Changes
-------------

- Add notes and Requirements fields to DOCUMENTATION.
- Delete the bindep.txt file.
- Modify the Ansible version in meta/runtime.yml.

v1.0.0
======

Minor Changes
-------------

- Add all modules.

New Modules
-----------

- inspur.ispim.ad_group - Manage active directory group information
- inspur.ispim.ad_group_info - Get active directory group information
- inspur.ispim.ad_info - Get active directory information
- inspur.ispim.adapter_info - Get adapter information
- inspur.ispim.add_ldisk - Create logical disk
- inspur.ispim.alert_policy_info - Get alert policy
- inspur.ispim.audit_log_info - Get BMC audit log information
- inspur.ispim.auto_capture_info - Get auto capture screen information
- inspur.ispim.backplane_info - Get disk backplane information
- inspur.ispim.backup - Backup server settings
- inspur.ispim.bios_export - Export BIOS config
- inspur.ispim.bios_import - Import BIOS config
- inspur.ispim.bios_info - Get BIOS setup
- inspur.ispim.bmc_info - Get BMC information
- inspur.ispim.boot_image_info - Get bmc boot image information
- inspur.ispim.boot_option_info - Get BIOS boot options
- inspur.ispim.clear_audit_log - Clear BMC audit log
- inspur.ispim.clear_event_log - Clear event log
- inspur.ispim.clear_system_log - Clear BMC system log
- inspur.ispim.collect_blackbox - Collect blackbox log
- inspur.ispim.collect_log - Collect logs
- inspur.ispim.connect_media_info - Get remote images redirection information
- inspur.ispim.cpu_info - Get CPU information
- inspur.ispim.del_session - Delete session
- inspur.ispim.dns_info - Get dns information
- inspur.ispim.download_auto_screenshot - Download auto screenshots
- inspur.ispim.download_manual_screenshot - Download manual screenshots
- inspur.ispim.edit_ad - Set active directory information
- inspur.ispim.edit_alert_policy - Set alert policy
- inspur.ispim.edit_auto_capture - Set auto capture screen
- inspur.ispim.edit_bios - Set BIOS setup attributes
- inspur.ispim.edit_boot_image - Set bmc boot image
- inspur.ispim.edit_boot_option - Set BIOS boot options
- inspur.ispim.edit_connect_media - Start/Stop virtual media Image
- inspur.ispim.edit_dns - Set dns information
- inspur.ispim.edit_event_log_policy - Set event log policy
- inspur.ispim.edit_fan - Set fan information
- inspur.ispim.edit_fru - Set fru settings
- inspur.ispim.edit_ipv4 - Set ipv4 information
- inspur.ispim.edit_ipv6 - Set ipv6 information
- inspur.ispim.edit_kvm - Set KVM
- inspur.ispim.edit_ldap - Set ldap information
- inspur.ispim.edit_ldisk - Set logical disk
- inspur.ispim.edit_log_setting - Set bmc system and audit log setting
- inspur.ispim.edit_manual_capture - Set manual capture screen
- inspur.ispim.edit_media_instance - Set Virtual Media Instance
- inspur.ispim.edit_ncsi - Set ncsi information
- inspur.ispim.edit_network - Set network information
- inspur.ispim.edit_network_bond - Set network bond
- inspur.ispim.edit_network_link - Set network link
- inspur.ispim.edit_ntp - Set NTP
- inspur.ispim.edit_pdisk - Set physical disk
- inspur.ispim.edit_power_budget - Set power budget information
- inspur.ispim.edit_power_restore - Set power restore information
- inspur.ispim.edit_power_status - Set power status information
- inspur.ispim.edit_preserve_config - Set preserve config
- inspur.ispim.edit_psu_config - Set psu config information
- inspur.ispim.edit_psu_peak - Set psu peak information
- inspur.ispim.edit_restore_factory_default - Set preserver config
- inspur.ispim.edit_service - Set service settings
- inspur.ispim.edit_smtp - Set SMTP information
- inspur.ispim.edit_smtp_com - Set SMTP information
- inspur.ispim.edit_smtp_dest - Set SMTP information
- inspur.ispim.edit_snmp - Set snmp
- inspur.ispim.edit_snmp_trap - Set snmp trap
- inspur.ispim.edit_threshold - Set threshold information
- inspur.ispim.edit_uid - Set UID
- inspur.ispim.edit_virtual_media - Set virtual media
- inspur.ispim.edit_vlan - Set vlan information
- inspur.ispim.event_log_info - Get event log information
- inspur.ispim.event_log_policy_info - Get event log policy information
- inspur.ispim.fan_info - Get fan information
- inspur.ispim.fru_info - Get fru information
- inspur.ispim.fw_version_info - Get firmware version information
- inspur.ispim.gpu_info - Get GPU information
- inspur.ispim.hard_disk_info - Get hard disk information
- inspur.ispim.kvm_info - Get KVM information
- inspur.ispim.ldap_group - Manage ldap group information
- inspur.ispim.ldap_group_info - Get ldap group information
- inspur.ispim.ldap_info - Get ldap information
- inspur.ispim.ldisk_info - Get logical disks information
- inspur.ispim.log_setting_info - Get bmc log setting information
- inspur.ispim.media_instance_info - Get Virtual Media Instance information
- inspur.ispim.mem_info - Get memory information
- inspur.ispim.ncsi_info - Get ncsi information
- inspur.ispim.network_bond_info - Get network bond information
- inspur.ispim.network_info - Get network information
- inspur.ispim.network_link_info - Get network link information
- inspur.ispim.ntp_info - Get NTP information
- inspur.ispim.onboard_disk_info - Get onboard disks information
- inspur.ispim.pcie_info - Get PCIE information
- inspur.ispim.pdisk_info - Get physical disks information
- inspur.ispim.power_budget_info - Get power budget information
- inspur.ispim.power_consumption_info - Get power consumption information
- inspur.ispim.power_restore_info - Get power restore information
- inspur.ispim.power_status_info - Get power status information
- inspur.ispim.preserve_config_info - Get preserve config information
- inspur.ispim.psu_config_info - Get psu config information
- inspur.ispim.psu_info - Get psu information
- inspur.ispim.psu_peak_info - Get psu peak information
- inspur.ispim.raid_info - Get RAID/HBA card and controller information
- inspur.ispim.reset_bmc - BMC reset
- inspur.ispim.reset_kvm - KVM reset
- inspur.ispim.restore - Restore server settings
- inspur.ispim.self_test_info - Get self test information
- inspur.ispim.sensor_info - Get sensor information
- inspur.ispim.server_info - Get server status information
- inspur.ispim.service_info - Get service information
- inspur.ispim.session_info - Get online session information
- inspur.ispim.smtp_info - Get SMTP information
- inspur.ispim.snmp_info - Get snmp get/set information
- inspur.ispim.snmp_trap_info - Get snmp trap information
- inspur.ispim.system_log_info - Get BMC system log information
- inspur.ispim.temp_info - Get temp information
- inspur.ispim.threshold_info - Get threshold information
- inspur.ispim.uid_info - Get UID information
- inspur.ispim.update_cpld - Update CPLD
- inspur.ispim.update_fw - Update firmware
- inspur.ispim.user - Manage user
- inspur.ispim.user_group - Manage user group
- inspur.ispim.user_group_info - Get user group information
- inspur.ispim.user_info - Get user information
- inspur.ispim.virtual_media_info - Get Virtual Media information
- inspur.ispim.volt_info - Get volt information
