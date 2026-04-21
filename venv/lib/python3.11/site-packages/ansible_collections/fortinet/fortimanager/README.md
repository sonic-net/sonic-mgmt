![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

# fortinet.fortimanager:2.11.0 - configuring FortiManager

## Description

FortiManager Ansible Collection includes the modules that are able to configure FortiManager.

[Documentation](https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest) for the collection.

## Requirements

- Ansible Core 2.15.0 or above
- Python 3.9 or above

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install fortinet.fortimanager
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: fortinet.fortimanager
```

To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install fortinet.fortimanager --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 2.0.0:

```
ansible-galaxy collection install fortinet.fortimanager:==2.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.


## Use Cases

See [example here](https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest/playbook.html) to run your first playbook.


## Testing

Testing is done by the Fortinet team. Before each new FMG Ansible release, it is tested with the latest patches from all FMG minor releases.


## Support

For any questions regarding FortiManager Ansible, please create a [github issue](https://github.com/fortinet-ansible-dev/ansible-galaxy-fortimanager-collection/issues).


## Release Notes and Roadmap

Please check [release note here](https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest/release.html).

FortiManager Ansible is expected to be updated every two months.

## Related Information

[Documentation](https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest) for the collection.

## Modules
The collection provides the following modules:

* `fmgr_adom_options`  Options.
* `fmgr_antivirus_mmschecksum`  Configure MMS content checksum list.
* `fmgr_antivirus_mmschecksum_entries`  modify this MMS content checksum list.
* `fmgr_antivirus_notification`  Configure AntiVirus notification lists.
* `fmgr_antivirus_notification_entries`  modify this antivirus notification list.
* `fmgr_antivirus_profile`  Configure AntiVirus profiles.
* `fmgr_antivirus_profile_cifs`  Configure CIFS AntiVirus options.
* `fmgr_antivirus_profile_contentdisarm`  AV Content Disarm and Reconstruction settings.
* `fmgr_antivirus_profile_ftp`  Configure FTP AntiVirus options.
* `fmgr_antivirus_profile_http`  Configure HTTP AntiVirus options.
* `fmgr_antivirus_profile_imap`  Configure IMAP AntiVirus options.
* `fmgr_antivirus_profile_mapi`  Configure MAPI AntiVirus options.
* `fmgr_antivirus_profile_nacquar`  Configure AntiVirus quarantine settings.
* `fmgr_antivirus_profile_nntp`  Configure NNTP AntiVirus options.
* `fmgr_antivirus_profile_outbreakprevention`  Configure Virus Outbreak Prevention settings.
* `fmgr_antivirus_profile_pop3`  Configure POP3 AntiVirus options.
* `fmgr_antivirus_profile_smb`  Configure SMB AntiVirus options.
* `fmgr_antivirus_profile_smtp`  Configure SMTP AntiVirus options.
* `fmgr_antivirus_profile_ssh`  Configure SFTP and SCP AntiVirus options.
* `fmgr_apcfgprofile`  Configure AP local configuration profiles.
* `fmgr_apcfgprofile_commandlist`  AP local configuration command list.
* `fmgr_application_casi_profile`  Cloud Access Security Inspection.
* `fmgr_application_casi_profile_entries`  Application entries.
* `fmgr_application_categories`  Application categories.
* `fmgr_application_custom`  Configure custom application signatures.
* `fmgr_application_group`  Configure firewall application groups.
* `fmgr_application_internetservice`  Show Internet service application.
* `fmgr_application_internetservice_entry`  Entries in the Internet service database.
* `fmgr_application_internetservicecustom`  Configure custom Internet service applications.
* `fmgr_application_internetservicecustom_disableentry`  Disable entries in the Internet service database.
* `fmgr_application_internetservicecustom_disableentry_iprange`  IP ranges in the disable entry.
* `fmgr_application_internetservicecustom_entry`  Entries added to the Internet service database and custom database.
* `fmgr_application_internetservicecustom_entry_portrange`  Port ranges in the custom entry.
* `fmgr_application_list`  Configure application control lists.
* `fmgr_application_list_defaultnetworkservices`  Default network service entries.
* `fmgr_application_list_entries`  Application list entries.
* `fmgr_application_list_entries_parameters`  Application parameters.
* `fmgr_application_list_entries_parameters_members`  Parameter tuple members.
* `fmgr_arrpprofile`  Configure WiFi Automatic Radio Resource Provisioning.
* `fmgr_authentication_scheme`  Configure Authentication Schemes.
* `fmgr_bleprofile`  Configure Bluetooth Low Energy profile.
* `fmgr_bonjourprofile`  Configure Bonjour profiles.
* `fmgr_bonjourprofile_policylist`  Bonjour policy list.
* `fmgr_casb_profile`  Configure CASB profile.
* `fmgr_casb_profile_saasapplication`  CASB profile SaaS application.
* `fmgr_casb_profile_saasapplication_accessrule`  CASB profile access rule.
* `fmgr_casb_profile_saasapplication_customcontrol`  CASB profile custom control.
* `fmgr_casb_profile_saasapplication_customcontrol_option`  CASB custom control option.
* `fmgr_casb_saasapplication`  Configure CASB SaaS application.
* `fmgr_casb_useractivity`  Configure CASB user activity.
* `fmgr_casb_useractivity_controloptions`  CASB control options.
* `fmgr_casb_useractivity_controloptions_operations`  CASB control option operations.
* `fmgr_casb_useractivity_match`  CASB user activity match rules.
* `fmgr_casb_useractivity_match_rules`  CASB user activity rules.
* `fmgr_certificate_template`  Certificate template.
* `fmgr_cifs_domaincontroller`  Define known domain controller servers.
* `fmgr_cifs_profile`  Configure CIFS profile.
* `fmgr_cifs_profile_filefilter`  File filter.
* `fmgr_cifs_profile_filefilter_entries`  File filter entries.
* `fmgr_cifs_profile_serverkeytab`  Server keytab.
* `fmgr_cloud_orchestaws`  Cloud orchest aws.
* `fmgr_cloud_orchestawsconnector`  Cloud orchest awsconnector.
* `fmgr_cloud_orchestawstemplate_autoscaleexistingvpc`  Cloud orchest awstemplate autoscale existing vpc.
* `fmgr_cloud_orchestawstemplate_autoscalenewvpc`  Cloud orchest awstemplate autoscale new vpc.
* `fmgr_cloud_orchestawstemplate_autoscaletgwnewvpc`  Cloud orchest awstemplate autoscale tgw new vpc.
* `fmgr_cloud_orchestration`  Cloud orchestration.
* `fmgr_credentialstore_domaincontroller`  Define known domain controller servers.
* `fmgr_devprof_device_profile_fortianalyzer`  System template device profile fortianalyzer.
* `fmgr_devprof_device_profile_fortiguard`  System template device profile fortiguard.
* `fmgr_devprof_import`  Devprof import.
* `fmgr_devprof_log_fortianalyzer_setting`  Global FortiAnalyzer settings.
* `fmgr_devprof_log_fortianalyzercloud_setting`  Global FortiAnalyzer Cloud settings.
* `fmgr_devprof_log_syslogd_filter`  Filters for remote system server.
* `fmgr_devprof_log_syslogd_filter_excludelist`  System template log syslogd filter exclude list.
* `fmgr_devprof_log_syslogd_filter_excludelist_fields`  System template log syslogd filter exclude list fields.
* `fmgr_devprof_log_syslogd_filter_freestyle`  Free style filters.
* `fmgr_devprof_log_syslogd_setting`  Global settings for remote syslog server.
* `fmgr_devprof_log_syslogd_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgr_devprof_system_centralmanagement`  Configure central management.
* `fmgr_devprof_system_centralmanagement_serverlist`  Additional severs that the FortiGate can use for updates.
* `fmgr_devprof_system_dns`  Configure DNS.
* `fmgr_devprof_system_emailserver`  Configure the email server used by the FortiGate various things.
* `fmgr_devprof_system_global`  Configure global attributes.
* `fmgr_devprof_system_ntp`  Configure system NTP information.
* `fmgr_devprof_system_ntp_ntpserver`  Configure the FortiGate to connect to any available third-party NTP server.
* `fmgr_devprof_system_replacemsg_admin`  Replacement messages.
* `fmgr_devprof_system_replacemsg_alertmail`  Replacement messages.
* `fmgr_devprof_system_replacemsg_auth`  Replacement messages.
* `fmgr_devprof_system_replacemsg_devicedetectionportal`  Replacement messages.
* `fmgr_devprof_system_replacemsg_ec`  Replacement messages.
* `fmgr_devprof_system_replacemsg_fortiguardwf`  Replacement messages.
* `fmgr_devprof_system_replacemsg_ftp`  Replacement messages.
* `fmgr_devprof_system_replacemsg_http`  Replacement messages.
* `fmgr_devprof_system_replacemsg_mail`  Replacement messages.
* `fmgr_devprof_system_replacemsg_mms`  Replacement messages.
* `fmgr_devprof_system_replacemsg_nacquar`  Replacement messages.
* `fmgr_devprof_system_replacemsg_nntp`  Replacement messages.
* `fmgr_devprof_system_replacemsg_spam`  Replacement messages.
* `fmgr_devprof_system_replacemsg_sslvpn`  Replacement messages.
* `fmgr_devprof_system_replacemsg_trafficquota`  Replacement messages.
* `fmgr_devprof_system_replacemsg_utm`  Replacement messages.
* `fmgr_devprof_system_replacemsg_webproxy`  Replacement messages.
* `fmgr_devprof_system_snmp_community`  SNMP community configuration.
* `fmgr_devprof_system_snmp_community_hosts`  Configure IPv4 SNMP managers.
* `fmgr_devprof_system_snmp_community_hosts6`  Configure IPv6 SNMP managers.
* `fmgr_devprof_system_snmp_sysinfo`  SNMP system info configuration.
* `fmgr_devprof_system_snmp_user`  SNMP user configuration.
* `fmgr_diameterfilter_profile`  Configure Diameter filter profiles.
* `fmgr_dlp_datatype`  Configure predefined data type used by DLP blocking.
* `fmgr_dlp_dictionary`  Configure dictionaries used by DLP blocking.
* `fmgr_dlp_dictionary_entries`  DLP dictionary entries.
* `fmgr_dlp_exactdatamatch`  Configure exact-data-match template used by DLP scan.
* `fmgr_dlp_exactdatamatch_columns`  DLP exact-data-match column types.
* `fmgr_dlp_filepattern`  Configure file patterns used by DLP blocking.
* `fmgr_dlp_filepattern_entries`  Configure file patterns used by DLP blocking.
* `fmgr_dlp_fpsensitivity`  Create self-explanatory DLP sensitivity levels to be used when setting sensitivity under config fp-doc-source.
* `fmgr_dlp_label`  Configure labels used by DLP blocking.
* `fmgr_dlp_label_entries`  DLP label entries.
* `fmgr_dlp_profile`  Configure DLP profiles.
* `fmgr_dlp_profile_rule`  Set up DLP rules for this profile.
* `fmgr_dlp_sensitivity`  Create self-explanatory DLP sensitivity levels to be used when setting sensitivity under config fp-doc-source.
* `fmgr_dlp_sensor`  Configure DLP sensors.
* `fmgr_dlp_sensor_entries`  DLP sensor entries.
* `fmgr_dlp_sensor_filter`  Set up DLP filters for this sensor.
* `fmgr_dnsfilter_domainfilter`  Configure DNS domain filters.
* `fmgr_dnsfilter_domainfilter_entries`  DNS domain filter entries.
* `fmgr_dnsfilter_profile`  Configure DNS domain filter profiles.
* `fmgr_dnsfilter_profile_dnstranslation`  DNS translation settings.
* `fmgr_dnsfilter_profile_domainfilter`  Domain filter settings.
* `fmgr_dnsfilter_profile_ftgddns`  FortiGuard DNS Filter settings.
* `fmgr_dnsfilter_profile_ftgddns_filters`  FortiGuard DNS domain filters.
* `fmgr_dnsfilter_profile_urlfilter`  URL filter settings.
* `fmgr_dnsfilter_urlfilter`  Configure URL filter list.
* `fmgr_dnsfilter_urlfilter_entries`  DNS URL filter.
* `fmgr_dvm_cmd_add_device`  Add a device to the Device Manager database.
* `fmgr_dvm_cmd_add_devlist`  Add multiple devices to the Device Manager database.
* `fmgr_dvm_cmd_changehaseq`  Modify HA sequence to promote a slave to become the master of the cluster.
* `fmgr_dvm_cmd_del_device`  Delete a device.
* `fmgr_dvm_cmd_del_devlist`  Delete a list of devices.
* `fmgr_dvm_cmd_discover_device`  Probe a remote device and retrieve its device information and system status.
* `fmgr_dvm_cmd_import_devlist`  Import a list of ADOMs and devices.
* `fmgr_dvm_cmd_reload_devlist`  Retrieve a list of devices.
* `fmgr_dvm_cmd_update_device`  Refresh the FGFM connection and system information of a device.
* `fmgr_dvm_cmd_update_devlist`  Refresh FGFM connection and system information for a list of devices.
* `fmgr_dvmdb_adom`  ADOM table, most attributes are read-only and can only be changed internally.
* `fmgr_dvmdb_adom_objectmember`  ADOM table, most attributes are read-only and can only be changed internally.
* `fmgr_dvmdb_device`  Device table, most attributes are read-only and can only be changed internally.
* `fmgr_dvmdb_device_replace_sn`  Replace devices serial number with new value.
* `fmgr_dvmdb_device_vdom`  Device VDOM table.
* `fmgr_dvmdb_folder`  Device manager database folder.
* `fmgr_dvmdb_group`  Device group table.
* `fmgr_dvmdb_group_objectmember`  Device group table.
* `fmgr_dvmdb_metafields_adom`  Device manager database meta fields adom.
* `fmgr_dvmdb_metafields_device`  Device manager database meta fields device.
* `fmgr_dvmdb_metafields_group`  Device manager database meta fields group.
* `fmgr_dvmdb_revision`  ADOM revision table.
* `fmgr_dvmdb_script`  Script table.
* `fmgr_dvmdb_script_execute`  Run script.
* `fmgr_dvmdb_script_objectmember`  Script table.
* `fmgr_dvmdb_script_scriptschedule`  Script schedule table.
* `fmgr_dvmdb_upgrade`  Device manager database upgrade.
* `fmgr_dvmdb_workflow_approve`  Device manager database workflow approve.
* `fmgr_dvmdb_workflow_discard`  Device manager database workflow discard.
* `fmgr_dvmdb_workflow_drop`  Device manager database workflow drop.
* `fmgr_dvmdb_workflow_reject`  Device manager database workflow reject.
* `fmgr_dvmdb_workflow_repair`  Device manager database workflow repair.
* `fmgr_dvmdb_workflow_revert`  Device manager database workflow revert.
* `fmgr_dvmdb_workflow_review`  Device manager database workflow review.
* `fmgr_dvmdb_workflow_save`  Device manager database workflow save.
* `fmgr_dvmdb_workflow_start`  Continue a workflow session.
* `fmgr_dvmdb_workflow_submit`  Device manager database workflow submit.
* `fmgr_dvmdb_workspace_commit`  Commit change.
* `fmgr_dvmdb_workspace_commit_dev`  Commit change.
* `fmgr_dvmdb_workspace_commit_obj`  Commit change.
* `fmgr_dvmdb_workspace_commit_pkg`  Commit change.
* `fmgr_dvmdb_workspace_lock`  Lock an entire ADOM.
* `fmgr_dvmdb_workspace_lock_dev`  Lock a device.
* `fmgr_dvmdb_workspace_lock_obj`  Lock a specific object, where the url contains the full path to the object.
* `fmgr_dvmdb_workspace_lock_pkg`  Lock a specific package, where the url includes both the folder.
* `fmgr_dvmdb_workspace_unlock`  Unlock an entire ADOM.
* `fmgr_dvmdb_workspace_unlock_dev`  Unlock a device.
* `fmgr_dvmdb_workspace_unlock_obj`  Unlock a specific object, where the url contains the full path to the object.
* `fmgr_dvmdb_workspace_unlock_pkg`  Unlock a specific package, where the url includes both the folder.
* `fmgr_dynamic_address`  Dynamic address.
* `fmgr_dynamic_address_dynamicaddrmapping`  Dynamic address dynamic addr mapping.
* `fmgr_dynamic_certificate_local`  Dynamic certificate local.
* `fmgr_dynamic_certificate_local_dynamicmapping`  Dynamic certificate local dynamic mapping.
* `fmgr_dynamic_input_interface`  Dynamic input interface.
* `fmgr_dynamic_input_interface_dynamicmapping`  Dynamic input interface dynamic mapping.
* `fmgr_dynamic_interface`  Dynamic interface.
* `fmgr_dynamic_interface_dynamicmapping`  Dynamic interface dynamic mapping.
* `fmgr_dynamic_interface_platformmapping`  Dynamic interface platform mapping.
* `fmgr_dynamic_ippool`  Dynamic ippool.
* `fmgr_dynamic_multicast_interface`  Dynamic multicast interface.
* `fmgr_dynamic_multicast_interface_dynamicmapping`  Dynamic multicast interface dynamic mapping.
* `fmgr_dynamic_vip`  Dynamic vip.
* `fmgr_dynamic_virtualwanlink_members`  FortiGate interfaces added to the virtual-wan-link.
* `fmgr_dynamic_virtualwanlink_members_dynamicmapping`  FortiGate interfaces added to the virtual-wan-link.
* `fmgr_dynamic_virtualwanlink_neighbor`  Dynamic virtual wan link neighbor.
* `fmgr_dynamic_virtualwanlink_neighbor_dynamicmapping`  Dynamic virtual wan link neighbor dynamic mapping.
* `fmgr_dynamic_virtualwanlink_server`  Dynamic virtual wan link server.
* `fmgr_dynamic_virtualwanlink_server_dynamicmapping`  Dynamic virtual wan link server dynamic mapping.
* `fmgr_dynamic_vpntunnel`  Dynamic vpntunnel.
* `fmgr_dynamic_vpntunnel_dynamicmapping`  Dynamic vpntunnel dynamic mapping.
* `fmgr_emailfilter_blockallowlist`  Configure anti-spam block/allow list.
* `fmgr_emailfilter_blockallowlist_entries`  Anti-spam block/allow entries.
* `fmgr_emailfilter_bwl`  Configure anti-spam black/white list.
* `fmgr_emailfilter_bwl_entries`  Anti-spam black/white list entries.
* `fmgr_emailfilter_bword`  Configure AntiSpam banned word list.
* `fmgr_emailfilter_bword_entries`  Spam filter banned word.
* `fmgr_emailfilter_dnsbl`  Configure AntiSpam DNSBL/ORBL.
* `fmgr_emailfilter_dnsbl_entries`  Spam filter DNSBL and ORBL server.
* `fmgr_emailfilter_fortishield`  Configure FortiGuard - AntiSpam.
* `fmgr_emailfilter_iptrust`  Configure AntiSpam IP trust.
* `fmgr_emailfilter_iptrust_entries`  Spam filter trusted IP addresses.
* `fmgr_emailfilter_mheader`  Configure AntiSpam MIME header.
* `fmgr_emailfilter_mheader_entries`  Spam filter mime header content.
* `fmgr_emailfilter_options`  Configure AntiSpam options.
* `fmgr_emailfilter_profile`  Configure Email Filter profiles.
* `fmgr_emailfilter_profile_filefilter`  File filter.
* `fmgr_emailfilter_profile_filefilter_entries`  File filter entries.
* `fmgr_emailfilter_profile_gmail`  Gmail.
* `fmgr_emailfilter_profile_imap`  IMAP.
* `fmgr_emailfilter_profile_mapi`  MAPI.
* `fmgr_emailfilter_profile_msnhotmail`  MSN Hotmail.
* `fmgr_emailfilter_profile_otherwebmails`  Other supported webmails.
* `fmgr_emailfilter_profile_pop3`  POP3.
* `fmgr_emailfilter_profile_smtp`  SMTP.
* `fmgr_emailfilter_profile_yahoomail`  Yahoo! Mail.
* `fmgr_endpointcontrol_fctems`  Configure FortiClient Enterprise Management Server.
* `fmgr_exec_fgfm_reclaimdevtunnel`  Reclaim management tunnel to device.
* `fmgr_extendercontroller_dataplan`  FortiExtender dataplan configuration.
* `fmgr_extendercontroller_extenderprofile`  FortiExtender extender profile configuration.
* `fmgr_extendercontroller_extenderprofile_cellular`  FortiExtender cellular configuration.
* `fmgr_extendercontroller_extenderprofile_cellular_controllerreport`  FortiExtender controller report configuration.
* `fmgr_extendercontroller_extenderprofile_cellular_modem1`  Configuration options for modem 1.
* `fmgr_extendercontroller_extenderprofile_cellular_modem1_autoswitch`  FortiExtender auto switch configuration.
* `fmgr_extendercontroller_extenderprofile_cellular_modem2`  Configuration options for modem 2.
* `fmgr_extendercontroller_extenderprofile_cellular_modem2_autoswitch`  FortiExtender auto switch configuration.
* `fmgr_extendercontroller_extenderprofile_cellular_smsnotification`  FortiExtender cellular SMS notification configuration.
* `fmgr_extendercontroller_extenderprofile_cellular_smsnotification_alert`  SMS alert list.
* `fmgr_extendercontroller_extenderprofile_cellular_smsnotification_receiver`  SMS notification receiver list.
* `fmgr_extendercontroller_extenderprofile_lanextension`  FortiExtender lan extension configuration.
* `fmgr_extendercontroller_extenderprofile_lanextension_backhaul`  LAN extension backhaul tunnel configuration.
* `fmgr_extendercontroller_simprofile`  Extender controller sim profile.
* `fmgr_extendercontroller_simprofile_autoswitchprofile`  Extender controller sim profile auto switch profile.
* `fmgr_extendercontroller_template`  Extender controller template.
* `fmgr_extensioncontroller_dataplan`  FortiExtender dataplan configuration.
* `fmgr_extensioncontroller_extenderprofile`  FortiExtender extender profile configuration.
* `fmgr_extensioncontroller_extenderprofile_cellular`  FortiExtender cellular configuration.
* `fmgr_extensioncontroller_extenderprofile_cellular_controllerreport`  FortiExtender controller report configuration.
* `fmgr_extensioncontroller_extenderprofile_cellular_modem1`  Configuration options for modem 1.
* `fmgr_extensioncontroller_extenderprofile_cellular_modem1_autoswitch`  FortiExtender auto switch configuration.
* `fmgr_extensioncontroller_extenderprofile_cellular_modem2`  Configuration options for modem 2.
* `fmgr_extensioncontroller_extenderprofile_cellular_modem2_autoswitch`  FortiExtender auto switch configuration.
* `fmgr_extensioncontroller_extenderprofile_cellular_smsnotification`  FortiExtender cellular SMS notification configuration.
* `fmgr_extensioncontroller_extenderprofile_cellular_smsnotification_alert`  SMS alert list.
* `fmgr_extensioncontroller_extenderprofile_cellular_smsnotification_receiver`  SMS notification receiver list.
* `fmgr_extensioncontroller_extenderprofile_lanextension`  FortiExtender lan extension configuration.
* `fmgr_extensioncontroller_extenderprofile_lanextension_backhaul`  LAN extension backhaul tunnel configuration.
* `fmgr_extensioncontroller_extenderprofile_wifi`  FortiExtender wifi configuration.
* `fmgr_extensioncontroller_extenderprofile_wifi_radio1`  Radio-1 config for Wi-Fi 2.
* `fmgr_extensioncontroller_extenderprofile_wifi_radio2`  Radio-2 config for Wi-Fi 5GHz.
* `fmgr_extensioncontroller_extendervap`  FortiExtender wifi vap configuration.
* `fmgr_filefilter_profile`  Configure file-filter profiles.
* `fmgr_filefilter_profile_rules`  File filter rules.
* `fmgr_firewall_accessproxy`  Configure Access Proxy.
* `fmgr_firewall_accessproxy6`  Configure IPv6 access proxy.
* `fmgr_firewall_accessproxy6_apigateway`  Set IPv4 API Gateway.
* `fmgr_firewall_accessproxy6_apigateway6`  Set IPv6 API Gateway.
* `fmgr_firewall_accessproxy6_apigateway6_quic`  QUIC setting.
* `fmgr_firewall_accessproxy6_apigateway6_realservers`  Select the real servers that this Access Proxy will distribute traffic to.
* `fmgr_firewall_accessproxy6_apigateway6_sslciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgr_firewall_accessproxy6_apigateway_quic`  QUIC setting.
* `fmgr_firewall_accessproxy6_apigateway_realservers`  Select the real servers that this Access Proxy will distribute traffic to.
* `fmgr_firewall_accessproxy6_apigateway_sslciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgr_firewall_accessproxy_apigateway`  Set API Gateway.
* `fmgr_firewall_accessproxy_apigateway6`  Set IPv6 API Gateway.
* `fmgr_firewall_accessproxy_apigateway6_quic`  QUIC setting.
* `fmgr_firewall_accessproxy_apigateway6_realservers`  Select the real servers that this Access Proxy will distribute traffic to.
* `fmgr_firewall_accessproxy_apigateway6_sslciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgr_firewall_accessproxy_apigateway_quic`  QUIC setting.
* `fmgr_firewall_accessproxy_apigateway_realservers`  Select the real servers that this Access Proxy will distribute traffic to.
* `fmgr_firewall_accessproxy_apigateway_sslciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgr_firewall_accessproxy_realservers`  Select the SSL real servers that this Access Proxy will distribute traffic to.
* `fmgr_firewall_accessproxy_serverpubkeyauthsettings`  Server SSH public key authentication settings.
* `fmgr_firewall_accessproxy_serverpubkeyauthsettings_certextension`  Configure certificate extension for user certificate.
* `fmgr_firewall_accessproxysshclientcert`  Configure Access Proxy SSH client certificate.
* `fmgr_firewall_accessproxysshclientcert_certextension`  Configure certificate extension for user certificate.
* `fmgr_firewall_accessproxyvirtualhost`  Configure Access Proxy virtual hosts.
* `fmgr_firewall_address`  Configure IPv4 addresses.
* `fmgr_firewall_address6`  Configure IPv6 firewall addresses.
* `fmgr_firewall_address6_dynamicmapping`  Configure IPv6 firewall addresses.
* `fmgr_firewall_address6_dynamicmapping_subnetsegment`  IPv6 subnet segments.
* `fmgr_firewall_address6_list`  IP address list.
* `fmgr_firewall_address6_profilelist`  List of NSX service profiles that use this address.
* `fmgr_firewall_address6_subnetsegment`  IPv6 subnet segments.
* `fmgr_firewall_address6_tagging`  Config object tagging.
* `fmgr_firewall_address6template`  Configure IPv6 address templates.
* `fmgr_firewall_address6template_subnetsegment`  IPv6 subnet segments.
* `fmgr_firewall_address6template_subnetsegment_values`  Subnet segment values.
* `fmgr_firewall_address_dynamicmapping`  Configure IPv4 addresses.
* `fmgr_firewall_address_list`  IP address list.
* `fmgr_firewall_address_profilelist`  List of NSX service profiles that use this address.
* `fmgr_firewall_address_tagging`  Config object tagging.
* `fmgr_firewall_addrgrp`  Configure IPv4 address groups.
* `fmgr_firewall_addrgrp6`  Configure IPv6 address groups.
* `fmgr_firewall_addrgrp6_dynamicmapping`  Configure IPv6 address groups.
* `fmgr_firewall_addrgrp6_tagging`  Config object tagging.
* `fmgr_firewall_addrgrp_dynamicmapping`  Configure IPv4 address groups.
* `fmgr_firewall_addrgrp_tagging`  Config object tagging.
* `fmgr_firewall_carrierendpointbwl`  Carrier end point black/white list tables.
* `fmgr_firewall_carrierendpointbwl_entries`  Carrier end point black/white list.
* `fmgr_firewall_casbprofile`  Firewall casb profile.
* `fmgr_firewall_casbprofile_saasapplication`  Firewall casb profile saas application.
* `fmgr_firewall_casbprofile_saasapplication_accessrule`  Firewall casb profile saas application access rule.
* `fmgr_firewall_casbprofile_saasapplication_customcontrol`  Firewall casb profile saas application custom control.
* `fmgr_firewall_casbprofile_saasapplication_customcontrol_option`  Firewall casb profile saas application custom control option.
* `fmgr_firewall_decryptedtrafficmirror`  Configure decrypted traffic mirror.
* `fmgr_firewall_explicitproxyaddress`  Explicit web proxy address configuration.
* `fmgr_firewall_explicitproxyaddress_headergroup`  HTTP header group.
* `fmgr_firewall_explicitproxyaddrgrp`  Explicit web proxy address group configuration.
* `fmgr_firewall_gtp`  Configure GTP.
* `fmgr_firewall_gtp_apn`  APN.
* `fmgr_firewall_gtp_ieremovepolicy`  IE remove policy.
* `fmgr_firewall_gtp_ievalidation`  IE validation.
* `fmgr_firewall_gtp_imsi`  IMSI.
* `fmgr_firewall_gtp_ippolicy`  IP policy.
* `fmgr_firewall_gtp_messagefilter`  Message filter.
* `fmgr_firewall_gtp_messageratelimit`  Message rate limiting.
* `fmgr_firewall_gtp_messageratelimitv0`  Message rate limiting for GTP version 0.
* `fmgr_firewall_gtp_messageratelimitv1`  Message rate limiting for GTP version 1.
* `fmgr_firewall_gtp_messageratelimitv2`  Message rate limiting for GTP version 2.
* `fmgr_firewall_gtp_noippolicy`  No IP policy.
* `fmgr_firewall_gtp_perapnshaper`  Per APN shaper.
* `fmgr_firewall_gtp_policy`  Policy.
* `fmgr_firewall_gtp_policyv2`  Apply allow or deny action to each GTPv2-c packet.
* `fmgr_firewall_identitybasedroute`  Configure identity based routing.
* `fmgr_firewall_identitybasedroute_rule`  Rule.
* `fmgr_firewall_internetservice`  Show Internet Service application.
* `fmgr_firewall_internetservice_entry`  Entries in the Internet Service database.
* `fmgr_firewall_internetserviceaddition`  Configure Internet Services Addition.
* `fmgr_firewall_internetserviceaddition_entry`  Entries added to the Internet Service addition database.
* `fmgr_firewall_internetserviceaddition_entry_portrange`  Port ranges in the custom entry.
* `fmgr_firewall_internetservicecustom`  Configure custom Internet Services.
* `fmgr_firewall_internetservicecustom_disableentry`  Disable entries in the Internet Service database.
* `fmgr_firewall_internetservicecustom_disableentry_iprange`  IP ranges in the disable entry.
* `fmgr_firewall_internetservicecustom_entry`  Entries added to the Internet Service database and custom database.
* `fmgr_firewall_internetservicecustom_entry_portrange`  Port ranges in the custom entry.
* `fmgr_firewall_internetservicecustomgroup`  Configure custom Internet Service group.
* `fmgr_firewall_internetserviceextension`  Configure Internet Services Extension.
* `fmgr_firewall_internetserviceextension_disableentry`  Disable entries in the Internet Service database.
* `fmgr_firewall_internetserviceextension_disableentry_ip6range`  IPv6 ranges in the disable entry.
* `fmgr_firewall_internetserviceextension_disableentry_iprange`  IPv4 ranges in the disable entry.
* `fmgr_firewall_internetserviceextension_disableentry_portrange`  Port ranges in the disable entry.
* `fmgr_firewall_internetserviceextension_entry`  Entries added to the Internet Service extension database.
* `fmgr_firewall_internetserviceextension_entry_portrange`  Port ranges in the custom entry.
* `fmgr_firewall_internetservicegroup`  Configure group of Internet Service.
* `fmgr_firewall_internetservicename`  Define internet service names.
* `fmgr_firewall_ippool`  Configure IPv4 IP pools.
* `fmgr_firewall_ippool6`  Configure IPv6 IP pools.
* `fmgr_firewall_ippool6_dynamicmapping`  Configure IPv6 IP pools.
* `fmgr_firewall_ippool_dynamicmapping`  Configure IPv4 IP pools.
* `fmgr_firewall_ippoolgrp`  Configure IPv4 pool groups.
* `fmgr_firewall_ldbmonitor`  Configure server load balancing health monitors.
* `fmgr_firewall_mmsprofile`  Configure MMS profiles.
* `fmgr_firewall_mmsprofile_dupe`  Duplicate configuration.
* `fmgr_firewall_mmsprofile_flood`  Flood configuration.
* `fmgr_firewall_mmsprofile_notification`  Notification configuration.
* `fmgr_firewall_mmsprofile_notifmsisdn`  Notification for MSISDNs.
* `fmgr_firewall_mmsprofile_outbreakprevention`  Configure Virus Outbreak Prevention settings.
* `fmgr_firewall_multicastaddress`  Configure multicast addresses.
* `fmgr_firewall_multicastaddress6`  Configure IPv6 multicast address.
* `fmgr_firewall_multicastaddress6_tagging`  Config object tagging.
* `fmgr_firewall_multicastaddress_tagging`  Config object tagging.
* `fmgr_firewall_networkservicedynamic`  Configure Dynamic Network Services.
* `fmgr_firewall_profilegroup`  Configure profile groups.
* `fmgr_firewall_profileprotocoloptions`  Configure protocol options.
* `fmgr_firewall_profileprotocoloptions_cifs`  Configure CIFS protocol options.
* `fmgr_firewall_profileprotocoloptions_cifs_filefilter`  File filter.
* `fmgr_firewall_profileprotocoloptions_cifs_filefilter_entries`  File filter entries.
* `fmgr_firewall_profileprotocoloptions_cifs_serverkeytab`  Server keytab.
* `fmgr_firewall_profileprotocoloptions_dns`  Configure DNS protocol options.
* `fmgr_firewall_profileprotocoloptions_ftp`  Configure FTP protocol options.
* `fmgr_firewall_profileprotocoloptions_http`  Configure HTTP protocol options.
* `fmgr_firewall_profileprotocoloptions_imap`  Configure IMAP protocol options.
* `fmgr_firewall_profileprotocoloptions_mailsignature`  Configure Mail signature.
* `fmgr_firewall_profileprotocoloptions_mapi`  Configure MAPI protocol options.
* `fmgr_firewall_profileprotocoloptions_nntp`  Configure NNTP protocol options.
* `fmgr_firewall_profileprotocoloptions_pop3`  Configure POP3 protocol options.
* `fmgr_firewall_profileprotocoloptions_smtp`  Configure SMTP protocol options.
* `fmgr_firewall_profileprotocoloptions_ssh`  Configure SFTP and SCP protocol options.
* `fmgr_firewall_proxyaddress`  Web proxy address configuration.
* `fmgr_firewall_proxyaddress_headergroup`  HTTP header group.
* `fmgr_firewall_proxyaddress_tagging`  Config object tagging.
* `fmgr_firewall_proxyaddrgrp`  Web proxy address group configuration.
* `fmgr_firewall_proxyaddrgrp_tagging`  Config object tagging.
* `fmgr_firewall_schedule_group`  Schedule group configuration.
* `fmgr_firewall_schedule_onetime`  Onetime schedule configuration.
* `fmgr_firewall_schedule_recurring`  Recurring schedule configuration.
* `fmgr_firewall_service_category`  Configure service categories.
* `fmgr_firewall_service_custom`  Configure custom services.
* `fmgr_firewall_service_group`  Configure service groups.
* `fmgr_firewall_shaper_peripshaper`  Configure per-IP traffic shaper.
* `fmgr_firewall_shaper_trafficshaper`  Configure shared traffic shaper.
* `fmgr_firewall_shapingprofile`  Configure shaping profiles.
* `fmgr_firewall_shapingprofile_shapingentries`  Define shaping entries of this shaping profile.
* `fmgr_firewall_ssh_localca`  SSH proxy local CA.
* `fmgr_firewall_sslsshprofile`  Configure SSL/SSH protocol options.
* `fmgr_firewall_sslsshprofile_dot`  Configure DNS over TLS options.
* `fmgr_firewall_sslsshprofile_echoutersni`  ClientHelloOuter SNIs to be blocked.
* `fmgr_firewall_sslsshprofile_ftps`  Configure FTPS options.
* `fmgr_firewall_sslsshprofile_https`  Configure HTTPS options.
* `fmgr_firewall_sslsshprofile_imaps`  Configure IMAPS options.
* `fmgr_firewall_sslsshprofile_pop3s`  Configure POP3S options.
* `fmgr_firewall_sslsshprofile_smtps`  Configure SMTPS options.
* `fmgr_firewall_sslsshprofile_ssh`  Configure SSH options.
* `fmgr_firewall_sslsshprofile_ssl`  Configure SSL options.
* `fmgr_firewall_sslsshprofile_sslexempt`  Servers to exempt from SSL inspection.
* `fmgr_firewall_sslsshprofile_sslserver`  SSL servers.
* `fmgr_firewall_trafficclass`  Configure names for shaping classes.
* `fmgr_firewall_vendormac`  Show vendor and the MAC address they have.
* `fmgr_firewall_vip`  Configure virtual IP for IPv4.
* `fmgr_firewall_vip46`  Configure IPv4 to IPv6 virtual IPs.
* `fmgr_firewall_vip46_dynamicmapping`  Configure IPv4 to IPv6 virtual IPs.
* `fmgr_firewall_vip46_realservers`  Real servers.
* `fmgr_firewall_vip6`  Configure virtual IP for IPv6.
* `fmgr_firewall_vip64`  Configure IPv6 to IPv4 virtual IPs.
* `fmgr_firewall_vip64_dynamicmapping`  Configure IPv6 to IPv4 virtual IPs.
* `fmgr_firewall_vip64_realservers`  Real servers.
* `fmgr_firewall_vip6_dynamicmapping`  Configure virtual IP for IPv6.
* `fmgr_firewall_vip6_dynamicmapping_realservers`  Select the real servers that this server load balancing VIP will distribute traffic to.
* `fmgr_firewall_vip6_dynamicmapping_sslciphersuites`  SSL/TLS cipher suites acceptable from a client, ordered by priority.
* `fmgr_firewall_vip6_quic`  QUIC setting.
* `fmgr_firewall_vip6_realservers`  Select the real servers that this server load balancing VIP will distribute traffic to.
* `fmgr_firewall_vip6_sslciphersuites`  SSL/TLS cipher suites acceptable from a client, ordered by priority.
* `fmgr_firewall_vip6_sslserverciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgr_firewall_vip_dynamicmapping`  Configure virtual IP for IPv4.
* `fmgr_firewall_vip_dynamicmapping_realservers`  Select the real servers that this server load balancing VIP will distribute traffic to.
* `fmgr_firewall_vip_dynamicmapping_sslciphersuites`  SSL/TLS cipher suites acceptable from a client, ordered by priority.
* `fmgr_firewall_vip_gslbpublicips`  Publicly accessible IP addresses for the FortiGSLB service.
* `fmgr_firewall_vip_quic`  QUIC setting.
* `fmgr_firewall_vip_realservers`  Select the real servers that this server load balancing VIP will distribute traffic to.
* `fmgr_firewall_vip_sslciphersuites`  SSL/TLS cipher suites acceptable from a client, ordered by priority.
* `fmgr_firewall_vip_sslserverciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgr_firewall_vipgrp`  Configure IPv4 virtual IP groups.
* `fmgr_firewall_vipgrp46`  Configure IPv4 to IPv6 virtual IP groups.
* `fmgr_firewall_vipgrp6`  Configure IPv6 virtual IP groups.
* `fmgr_firewall_vipgrp64`  Configure IPv6 to IPv4 virtual IP groups.
* `fmgr_firewall_vipgrp_dynamicmapping`  Configure IPv4 virtual IP groups.
* `fmgr_firewall_wildcardfqdn_custom`  Config global/VDOM Wildcard FQDN address.
* `fmgr_firewall_wildcardfqdn_group`  Config global Wildcard FQDN address groups.
* `fmgr_fmg_device_blueprint`  Fmg device blueprint.
* `fmgr_fmg_fabric_authorization_template`  Fmg fabric authorization template.
* `fmgr_fmg_fabric_authorization_template_platforms`  Fmg fabric authorization template platforms.
* `fmgr_fmg_sasemanager_settings`  Fmg sase manager settings.
* `fmgr_fmg_sasemanager_status`  Fmg sase manager status.
* `fmgr_fmg_variable`  Fmg variable.
* `fmgr_fmg_variable_dynamicmapping`  Fmg variable dynamic mapping.
* `fmgr_fmupdate_analyzer_virusreport`  Send virus detection notification to FortiGuard.
* `fmgr_fmupdate_avips_advancedlog`  Enable/disable logging of FortiGuard antivirus and IPS update packages received by FortiManagers built-in FortiGuard.
* `fmgr_fmupdate_avips_webproxy`  Configure the web proxy for use with FortiGuard antivirus and IPS updates.
* `fmgr_fmupdate_customurllist`  Configure the URL database for rating and filtering.
* `fmgr_fmupdate_diskquota`  Configure disk space available for use by the Upgrade Manager.
* `fmgr_fmupdate_fctservices`  Configure FortiGuard to provide services to FortiClient installations.
* `fmgr_fmupdate_fdssetting`  Configure FortiGuard settings.
* `fmgr_fmupdate_fdssetting_pushoverride`  Enable/disable push updates, and override the default IP address and port used by FortiGuard to send antivirus and IPS push messages...
* `fmgr_fmupdate_fdssetting_pushoverridetoclient`  Enable/disable push updates, and override the default IP address and port used by FortiGuard to send antivirus and IPS push messages...
* `fmgr_fmupdate_fdssetting_pushoverridetoclient_announceip`  Announce IP addresses for the device.
* `fmgr_fmupdate_fdssetting_serveroverride`  Server override configure.
* `fmgr_fmupdate_fdssetting_serveroverride_servlist`  Override server.
* `fmgr_fmupdate_fdssetting_updateschedule`  Configure the schedule when built-in FortiGuard retrieves antivirus and IPS updates.
* `fmgr_fmupdate_fgdsetting`  Cli fmupdate fgd setting.
* `fmgr_fmupdate_fgdsetting_serveroverride`  Cli fmupdate fgd setting server override.
* `fmgr_fmupdate_fwmsetting`  Configure firmware management settings.
* `fmgr_fmupdate_fwmsetting_upgradetimeout`  Configure the timeout value of image upgrade process.
* `fmgr_fmupdate_multilayer`  Configure multilayer mode.
* `fmgr_fmupdate_publicnetwork`  Enable/disable access to the public FortiGuard.
* `fmgr_fmupdate_serveraccesspriorities`  Configure priorities for FortiGate units accessing antivirus updates and web filtering services.
* `fmgr_fmupdate_serveraccesspriorities_privateserver`  Configure multiple FortiManager units and private servers.
* `fmgr_fmupdate_serveroverridestatus`  Configure strict/loose server override.
* `fmgr_fmupdate_service`  Enable/disable services provided by the built-in FortiGuard.
* `fmgr_fmupdate_webspam_fgdsetting`  Configure the FortiGuard run parameters.
* `fmgr_fmupdate_webspam_fgdsetting_serveroverride`  Server override configure.
* `fmgr_fmupdate_webspam_fgdsetting_serveroverride_servlist`  Override server.
* `fmgr_fmupdate_webspam_webproxy`  Configure the web proxy for use with FortiGuard antivirus and IPS updates.
* `fmgr_fsp_vlan`  FortiSwitch VLAN template.
* `fmgr_fsp_vlan_dhcpserver`  Configure DHCP servers.
* `fmgr_fsp_vlan_dhcpserver_excluderange`  Exclude one or more ranges of IP addresses from being assigned to clients.
* `fmgr_fsp_vlan_dhcpserver_iprange`  DHCP IP range configuration.
* `fmgr_fsp_vlan_dhcpserver_options`  DHCP options.
* `fmgr_fsp_vlan_dhcpserver_reservedaddress`  Options for the DHCP server to assign IP settings to specific MAC addresses.
* `fmgr_fsp_vlan_dynamicmapping`  Fsp vlan dynamic mapping.
* `fmgr_fsp_vlan_dynamicmapping_dhcpserver`  Configure DHCP servers.
* `fmgr_fsp_vlan_dynamicmapping_dhcpserver_excluderange`  Exclude one or more ranges of IP addresses from being assigned to clients.
* `fmgr_fsp_vlan_dynamicmapping_dhcpserver_iprange`  DHCP IP range configuration.
* `fmgr_fsp_vlan_dynamicmapping_dhcpserver_options`  DHCP options.
* `fmgr_fsp_vlan_dynamicmapping_dhcpserver_reservedaddress`  Options for the DHCP server to assign IP settings to specific MAC addresses.
* `fmgr_fsp_vlan_dynamicmapping_interface`  Fsp vlan dynamic mapping interface.
* `fmgr_fsp_vlan_dynamicmapping_interface_ipv6`  IPv6 of interface.
* `fmgr_fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist`  Advertised IPv6 delegated prefix list.
* `fmgr_fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr`  Extra IPv6 address prefixes of interface.
* `fmgr_fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist`  Advertised prefix list.
* `fmgr_fsp_vlan_dynamicmapping_interface_ipv6_vrrp6`  IPv6 VRRP configuration.
* `fmgr_fsp_vlan_dynamicmapping_interface_secondaryip`  Second IP address of interface.
* `fmgr_fsp_vlan_dynamicmapping_interface_vrrp`  VRRP configuration.
* `fmgr_fsp_vlan_dynamicmapping_interface_vrrp_proxyarp`  VRRP Proxy ARP configuration.
* `fmgr_fsp_vlan_interface`  Configure interfaces.
* `fmgr_fsp_vlan_interface_ipv6`  IPv6 of interface.
* `fmgr_fsp_vlan_interface_ipv6_ip6delegatedprefixlist`  Advertised IPv6 delegated prefix list.
* `fmgr_fsp_vlan_interface_ipv6_ip6extraaddr`  Extra IPv6 address prefixes of interface.
* `fmgr_fsp_vlan_interface_ipv6_ip6prefixlist`  Advertised prefix list.
* `fmgr_fsp_vlan_interface_ipv6_vrrp6`  IPv6 VRRP configuration.
* `fmgr_fsp_vlan_interface_secondaryip`  Second IP address of interface.
* `fmgr_fsp_vlan_interface_vrrp`  VRRP configuration.
* `fmgr_fsp_vlan_interface_vrrp_proxyarp`  VRRP Proxy ARP configuration.
* `fmgr_gtp_apn`  Configure APN for GTP.
* `fmgr_gtp_apngrp`  Configure APN groups for GTP.
* `fmgr_gtp_ieallowlist`  IE allow list.
* `fmgr_gtp_ieallowlist_entries`  Entries of allow list for unknown or out-of-state IEs.
* `fmgr_gtp_iewhitelist`  IE white list.
* `fmgr_gtp_iewhitelist_entries`  Entries of white list.
* `fmgr_gtp_messagefilterv0v1`  Message filter for GTPv0/v1 messages.
* `fmgr_gtp_messagefilterv2`  Message filter for GTPv2 messages.
* `fmgr_gtp_rattimeoutprofile`  RAT timeout profile.
* `fmgr_gtp_tunnellimit`  GTP tunnel limiter.
* `fmgr_hotspot20_anqp3gppcellular`  Configure 3GPP public land mobile network.
* `fmgr_hotspot20_anqp3gppcellular_mccmnclist`  Mobile Country Code and Mobile Network Code configuration.
* `fmgr_hotspot20_anqpipaddresstype`  Configure IP address type availability.
* `fmgr_hotspot20_anqpnairealm`  Configure network access identifier.
* `fmgr_hotspot20_anqpnairealm_nailist`  NAI list.
* `fmgr_hotspot20_anqpnairealm_nailist_eapmethod`  EAP Methods.
* `fmgr_hotspot20_anqpnairealm_nailist_eapmethod_authparam`  EAP auth param.
* `fmgr_hotspot20_anqpnetworkauthtype`  Configure network authentication type.
* `fmgr_hotspot20_anqproamingconsortium`  Configure roaming consortium.
* `fmgr_hotspot20_anqproamingconsortium_oilist`  Organization identifier list.
* `fmgr_hotspot20_anqpvenuename`  Configure venue name duple.
* `fmgr_hotspot20_anqpvenuename_valuelist`  Name list.
* `fmgr_hotspot20_anqpvenueurl`  Configure venue URL.
* `fmgr_hotspot20_anqpvenueurl_valuelist`  URL list.
* `fmgr_hotspot20_h2qpadviceofcharge`  Configure advice of charge.
* `fmgr_hotspot20_h2qpadviceofcharge_aoclist`  AOC list.
* `fmgr_hotspot20_h2qpadviceofcharge_aoclist_planinfo`  Plan info.
* `fmgr_hotspot20_h2qpconncapability`  Configure connection capability.
* `fmgr_hotspot20_h2qpoperatorname`  Configure operator friendly name.
* `fmgr_hotspot20_h2qpoperatorname_valuelist`  Name list.
* `fmgr_hotspot20_h2qposuprovider`  Configure online sign up.
* `fmgr_hotspot20_h2qposuprovider_friendlyname`  OSU provider friendly name.
* `fmgr_hotspot20_h2qposuprovider_servicedescription`  OSU service name.
* `fmgr_hotspot20_h2qposuprovidernai`  Configure online sign up.
* `fmgr_hotspot20_h2qposuprovidernai_nailist`  OSU NAI list.
* `fmgr_hotspot20_h2qptermsandconditions`  Configure terms and conditions.
* `fmgr_hotspot20_h2qpwanmetric`  Configure WAN metrics.
* `fmgr_hotspot20_hsprofile`  Configure hotspot profile.
* `fmgr_hotspot20_icon`  Configure OSU provider icon.
* `fmgr_hotspot20_icon_iconlist`  Icon list.
* `fmgr_hotspot20_qosmap`  Configure QoS map set.
* `fmgr_hotspot20_qosmap_dscpexcept`  Differentiated Services Code Point.
* `fmgr_hotspot20_qosmap_dscprange`  Differentiated Services Code Point.
* `fmgr_icap_profile`  Configure ICAP profiles.
* `fmgr_icap_profile_icapheaders`  Configure ICAP forwarded request headers.
* `fmgr_icap_profile_respmodforwardrules`  ICAP response mode forward rules.
* `fmgr_icap_profile_respmodforwardrules_headergroup`  HTTP header group.
* `fmgr_icap_server`  Configure ICAP servers.
* `fmgr_icap_servergroup`  Configure an ICAP server group consisting of multiple forward servers.
* `fmgr_icap_servergroup_serverlist`  Add ICAP servers to a list to form a server group.
* `fmgr_ips_baseline_sensor`  Configure IPS sensor.
* `fmgr_ips_baseline_sensor_entries`  IPS sensor filter.
* `fmgr_ips_baseline_sensor_entries_exemptip`  Traffic from selected source or destination IP addresses is exempt from this signature.
* `fmgr_ips_baseline_sensor_filter`  Ips baseline sensor filter.
* `fmgr_ips_baseline_sensor_override`  Ips baseline sensor override.
* `fmgr_ips_baseline_sensor_override_exemptip`  Ips baseline sensor override exempt ip.
* `fmgr_ips_custom`  Configure IPS custom signature.
* `fmgr_ips_sensor`  Configure IPS sensor.
* `fmgr_ips_sensor_entries`  IPS sensor filter.
* `fmgr_ips_sensor_entries_exemptip`  Traffic from selected source or destination IP addresses is exempt from this signature.
* `fmgr_log_customfield`  Configure custom log fields.
* `fmgr_log_npuserver`  Configure all the log servers and create the server groups.
* `fmgr_log_npuserver_servergroup`  create server group.
* `fmgr_log_npuserver_serverinfo`  configure server info.
* `fmgr_metafields_system_admin_user`  Cli meta fields system admin user.
* `fmgr_mpskprofile`  Configure MPSK profile.
* `fmgr_mpskprofile_mpskgroup`  List of multiple PSK groups.
* `fmgr_mpskprofile_mpskgroup_mpskkey`  List of multiple PSK entries.
* `fmgr_nacprofile`  Configure WiFi network access control.
* `fmgr_pkg_authentication_rule`  Configure Authentication Rules.
* `fmgr_pkg_authentication_setting`  Configure authentication setting.
* `fmgr_pkg_central_dnat`  Policy package central dnat.
* `fmgr_pkg_central_dnat6`  Policy package central dnat6.
* `fmgr_pkg_firewall_acl`  Configure IPv4 access control list.
* `fmgr_pkg_firewall_acl6`  Configure IPv6 access control list.
* `fmgr_pkg_firewall_centralsnatmap`  Configure central SNAT policies.
* `fmgr_pkg_firewall_consolidated_policy`  Configure consolidated IPv4/IPv6 policies.
* `fmgr_pkg_firewall_consolidated_policy_sectionvalue`  Configure consolidated IPv4/IPv6 policies.
* `fmgr_pkg_firewall_dospolicy`  Configure IPv4 DoS policies.
* `fmgr_pkg_firewall_dospolicy6`  Configure IPv6 DoS policies.
* `fmgr_pkg_firewall_dospolicy6_anomaly`  Anomaly name.
* `fmgr_pkg_firewall_dospolicy_anomaly`  Anomaly name.
* `fmgr_pkg_firewall_explicitproxypolicy`  Configure Explicit proxy policies.
* `fmgr_pkg_firewall_explicitproxypolicy_identitybasedpolicy`  Identity-based policy.
* `fmgr_pkg_firewall_explicitproxypolicy_sectionvalue`  Configure Explicit proxy policies.
* `fmgr_pkg_firewall_hyperscalepolicy`  Configure IPv4/IPv6 policies.
* `fmgr_pkg_firewall_hyperscalepolicy46`  Configure IPv4 to IPv6 policies.
* `fmgr_pkg_firewall_hyperscalepolicy6`  Configure IPv6 policies.
* `fmgr_pkg_firewall_hyperscalepolicy64`  Configure IPv6 to IPv4 policies.
* `fmgr_pkg_firewall_interfacepolicy`  Configure IPv4 interface policies.
* `fmgr_pkg_firewall_interfacepolicy6`  Configure IPv6 interface policies.
* `fmgr_pkg_firewall_interfacepolicy6_sectionvalue`  Configure IPv6 interface policies.
* `fmgr_pkg_firewall_interfacepolicy_sectionvalue`  Configure IPv4 interface policies.
* `fmgr_pkg_firewall_localinpolicy`  Configure user defined IPv4 local-in policies.
* `fmgr_pkg_firewall_localinpolicy6`  Configure user defined IPv6 local-in policies.
* `fmgr_pkg_firewall_multicastpolicy`  Configure multicast NAT policies.
* `fmgr_pkg_firewall_multicastpolicy6`  Configure IPv6 multicast NAT policies.
* `fmgr_pkg_firewall_policy`  Configure IPv4 policies.
* `fmgr_pkg_firewall_policy46`  Configure IPv4 to IPv6 policies.
* `fmgr_pkg_firewall_policy6`  Configure IPv6 policies.
* `fmgr_pkg_firewall_policy64`  Configure IPv6 to IPv4 policies.
* `fmgr_pkg_firewall_policy6_sectionvalue`  Configure IPv6 policies.
* `fmgr_pkg_firewall_policy_sectionvalue`  Configure IPv4 policies.
* `fmgr_pkg_firewall_policy_vpndstnode`  Policy package firewall policy vpn dst node.
* `fmgr_pkg_firewall_policy_vpnsrcnode`  Policy package firewall policy vpn src node.
* `fmgr_pkg_firewall_proxypolicy`  Configure proxy policies.
* `fmgr_pkg_firewall_proxypolicy_sectionvalue`  Configure proxy policies.
* `fmgr_pkg_firewall_securitypolicy`  Configure NGFW IPv4/IPv6 application policies.
* `fmgr_pkg_firewall_securitypolicy_sectionvalue`  Configure NGFW IPv4/IPv6 application policies.
* `fmgr_pkg_firewall_shapingpolicy`  Configure shaping policies.
* `fmgr_pkg_footer_policy`  Configure IPv4/IPv6 policies.
* `fmgr_pkg_footer_policy6`  Configure IPv6 policies.
* `fmgr_pkg_footer_shapingpolicy`  Configure shaping policies.
* `fmgr_pkg_header_policy`  Configure IPv4/IPv6 policies.
* `fmgr_pkg_header_policy6`  Configure IPv6 policies.
* `fmgr_pkg_header_shapingpolicy`  Configure shaping policies.
* `fmgr_pkg_user_nacpolicy`  Configure NAC policy matching pattern to identify matching NAC devices.
* `fmgr_pkg_videofilter_youtubekey`  Configure YouTube API keys.
* `fmgr_pm_config_meta_reference`  Meta reference.
* `fmgr_pm_config_metafields_firewall_address`  Meta fields firewall address.
* `fmgr_pm_config_metafields_firewall_addrgrp`  Meta fields firewall addrgrp.
* `fmgr_pm_config_metafields_firewall_centralsnatmap`  Meta fields firewall central snat map.
* `fmgr_pm_config_metafields_firewall_policy`  Meta fields firewall policy.
* `fmgr_pm_config_metafields_firewall_service_custom`  Meta fields firewall service custom.
* `fmgr_pm_config_metafields_firewall_service_group`  Meta fields firewall service group.
* `fmgr_pm_config_pblock_firewall_consolidated_policy`  Configure consolidated IPv4/IPv6 policies.
* `fmgr_pm_config_pblock_firewall_consolidated_policy_sectionvalue`  Configure consolidated IPv4/IPv6 policies.
* `fmgr_pm_config_pblock_firewall_policy`  Configure IPv4/IPv6 policies.
* `fmgr_pm_config_pblock_firewall_policy6`  Configure IPv6 policies.
* `fmgr_pm_config_pblock_firewall_policy6_sectionvalue`  Configure IPv6 policies.
* `fmgr_pm_config_pblock_firewall_policy_sectionvalue`  Configure IPv4/IPv6 policies.
* `fmgr_pm_config_pblock_firewall_proxypolicy`  Configure proxy policies.
* `fmgr_pm_config_pblock_firewall_proxypolicy_sectionvalue`  Configure proxy policies.
* `fmgr_pm_config_pblock_firewall_securitypolicy`  Configure NGFW IPv4/IPv6 application policies.
* `fmgr_pm_config_pblock_firewall_securitypolicy_sectionvalue`  Configure NGFW IPv4/IPv6 application policies.
* `fmgr_pm_config_reset_database`  Reset Global ADOM to a specific version.
* `fmgr_pm_config_upgrade`  Upgrade an ADOM to the next version.
* `fmgr_pm_config_workspace_commit`  Commit changes to an ADOM.
* `fmgr_pm_config_workspace_lock`  Lock an ADOM in workspace mode.
* `fmgr_pm_config_workspace_unlock`  Unlock an ADOM.
* `fmgr_pm_devprof_adom`  System template adom.
* `fmgr_pm_devprof_pkg`  System template adom.
* `fmgr_pm_devprof_scopemember`  System template scope member.
* `fmgr_pm_pblock_adom`  Policy block adom.
* `fmgr_pm_pblock_obj`  Policy block adom.
* `fmgr_pm_pkg`  Policy package or folder.
* `fmgr_pm_pkg_adom`  Policy package or folder.
* `fmgr_pm_pkg_global`  Policy package or folder.
* `fmgr_pm_pkg_scopemember`  Policy package or folder.
* `fmgr_pm_wanprof_adom`  Sd wan template adom.
* `fmgr_pm_wanprof_pkg`  Sd wan template adom.
* `fmgr_pm_wanprof_scopemember`  Sd wan template scope member.
* `fmgr_qosprofile`  Configure WiFi quality of service.
* `fmgr_region`  Configure FortiAP regions.
* `fmgr_router_accesslist`  Configure access lists.
* `fmgr_router_accesslist6`  Configure IPv6 access lists.
* `fmgr_router_accesslist6_rule`  Rule.
* `fmgr_router_accesslist_rule`  Rule.
* `fmgr_router_aspathlist`  Configure Autonomous System.
* `fmgr_router_aspathlist_rule`  AS path list rule.
* `fmgr_router_communitylist`  Configure community lists.
* `fmgr_router_communitylist_rule`  Community list rule.
* `fmgr_router_prefixlist`  Configure IPv4 prefix lists.
* `fmgr_router_prefixlist6`  Configure IPv6 prefix lists.
* `fmgr_router_prefixlist6_rule`  IPv6 prefix list rule.
* `fmgr_router_prefixlist_rule`  IPv4 prefix list rule.
* `fmgr_router_routemap`  Configure route maps.
* `fmgr_router_routemap_rule`  Rule.
* `fmgr_sctpfilter_profile`  Configure SCTP filter profiles.
* `fmgr_sctpfilter_profile_ppidfilters`  PPID filters list.
* `fmgr_securityconsole_abort`  Abort and cancel a security console task.
* `fmgr_securityconsole_assign_package`  Assign or unassign global policy package to ADOM packages.
* `fmgr_securityconsole_cliprof_check`  Securityconsole cliprof check.
* `fmgr_securityconsole_import_dev_objs`  Import objects from device to ADOM, or from ADOM to Global.
* `fmgr_securityconsole_install_device`  Securityconsole install device.
* `fmgr_securityconsole_install_objects_v2`  Securityconsole install objects v2.
* `fmgr_securityconsole_install_package`  Copy and install a policy package to devices.
* `fmgr_securityconsole_install_preview`  Generate install preview for a device.
* `fmgr_securityconsole_package_cancel_install`  Cancel policy install and clear preview cache.
* `fmgr_securityconsole_package_clone`  Clone a policy package within the same ADOM.
* `fmgr_securityconsole_package_commit`  Install policies to device from preview cache.
* `fmgr_securityconsole_package_move`  Move and/or rename a policy package within the same ADOM.
* `fmgr_securityconsole_pblock_clone`  Securityconsole policy block clone.
* `fmgr_securityconsole_preview_result`  Retrieve the result of previous install/preview command.
* `fmgr_securityconsole_reinstall_package`  Re-install a policy package that had been previously installed.
* `fmgr_securityconsole_sign_certificate_template`  Generate and sign certificate on the target device.
* `fmgr_securityconsole_template_cli_preview`  Securityconsole template cli preview.
* `fmgr_spamfilter_bwl`  Configure anti-spam black/white list.
* `fmgr_spamfilter_bwl_entries`  Anti-spam black/white list entries.
* `fmgr_spamfilter_bword`  Configure AntiSpam banned word list.
* `fmgr_spamfilter_bword_entries`  Spam filter banned word.
* `fmgr_spamfilter_dnsbl`  Configure AntiSpam DNSBL/ORBL.
* `fmgr_spamfilter_dnsbl_entries`  Spam filter DNSBL and ORBL server.
* `fmgr_spamfilter_iptrust`  Configure AntiSpam IP trust.
* `fmgr_spamfilter_iptrust_entries`  Spam filter trusted IP addresses.
* `fmgr_spamfilter_mheader`  Configure AntiSpam MIME header.
* `fmgr_spamfilter_mheader_entries`  Spam filter mime header content.
* `fmgr_spamfilter_profile`  Configure AntiSpam profiles.
* `fmgr_spamfilter_profile_gmail`  Gmail.
* `fmgr_spamfilter_profile_imap`  IMAP.
* `fmgr_spamfilter_profile_mapi`  MAPI.
* `fmgr_spamfilter_profile_msnhotmail`  MSN Hotmail.
* `fmgr_spamfilter_profile_pop3`  POP3.
* `fmgr_spamfilter_profile_smtp`  SMTP.
* `fmgr_spamfilter_profile_yahoomail`  Yahoo! Mail.
* `fmgr_sshfilter_profile`  SSH filter profile.
* `fmgr_sshfilter_profile_filefilter`  File filter.
* `fmgr_sshfilter_profile_filefilter_entries`  File filter entries.
* `fmgr_sshfilter_profile_shellcommands`  SSH command filter.
* `fmgr_switchcontroller_acl_group`  Configure ACL groups to be applied on managed FortiSwitch ports.
* `fmgr_switchcontroller_acl_ingress`  Configure ingress ACL policies to be applied on managed FortiSwitch ports.
* `fmgr_switchcontroller_acl_ingress_action`  ACL actions.
* `fmgr_switchcontroller_acl_ingress_classifier`  ACL classifiers.
* `fmgr_switchcontroller_customcommand`  Configure the FortiGate switch controller to send custom commands to managed FortiSwitch devices.
* `fmgr_switchcontroller_dsl_policy`  DSL policy.
* `fmgr_switchcontroller_dynamicportpolicy`  Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
* `fmgr_switchcontroller_dynamicportpolicy_policy`  Port policies with matching criteria and actions.
* `fmgr_switchcontroller_fortilinksettings`  Configure integrated FortiLink settings for FortiSwitch.
* `fmgr_switchcontroller_fortilinksettings_nacports`  NAC specific configuration.
* `fmgr_switchcontroller_lldpprofile`  Configure FortiSwitch LLDP profiles.
* `fmgr_switchcontroller_lldpprofile_customtlvs`  Configuration method to edit custom TLV entries.
* `fmgr_switchcontroller_lldpprofile_medlocationservice`  Configuration method to edit Media Endpoint Discovery.
* `fmgr_switchcontroller_lldpprofile_mednetworkpolicy`  Configuration method to edit Media Endpoint Discovery.
* `fmgr_switchcontroller_macpolicy`  Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device.
* `fmgr_switchcontroller_managedswitch`  Configure FortiSwitch devices that are managed by this FortiGate.
* `fmgr_switchcontroller_managedswitch_customcommand`  Configuration method to edit FortiSwitch commands to be pushed to this FortiSwitch device upon rebooting the FortiGate switch contro...
* `fmgr_switchcontroller_managedswitch_dhcpsnoopingstaticclient`  Configure FortiSwitch DHCP snooping static clients.
* `fmgr_switchcontroller_managedswitch_ipsourceguard`  IP source guard.
* `fmgr_switchcontroller_managedswitch_ipsourceguard_bindingentry`  IP and MAC address configuration.
* `fmgr_switchcontroller_managedswitch_ports`  Managed-switch port list.
* `fmgr_switchcontroller_managedswitch_ports_dhcpsnoopoption82override`  Configure DHCP snooping option 82 override.
* `fmgr_switchcontroller_managedswitch_remotelog`  Configure logging by FortiSwitch device to a remote syslog server.
* `fmgr_switchcontroller_managedswitch_routeoffloadrouter`  Configure route offload MCLAG IP address.
* `fmgr_switchcontroller_managedswitch_snmpcommunity`  Configuration method to edit Simple Network Management Protocol.
* `fmgr_switchcontroller_managedswitch_snmpcommunity_hosts`  Configure IPv4 SNMP managers.
* `fmgr_switchcontroller_managedswitch_snmpsysinfo`  Configuration method to edit Simple Network Management Protocol.
* `fmgr_switchcontroller_managedswitch_snmptrapthreshold`  Configuration method to edit Simple Network Management Protocol.
* `fmgr_switchcontroller_managedswitch_snmpuser`  Configuration method to edit Simple Network Management Protocol.
* `fmgr_switchcontroller_managedswitch_vlan`  Configure VLAN assignment priority.
* `fmgr_switchcontroller_ptp_profile`  Global PTP profile.
* `fmgr_switchcontroller_qos_dot1pmap`  Configure FortiSwitch QoS 802.
* `fmgr_switchcontroller_qos_ipdscpmap`  Configure FortiSwitch QoS IP precedence/DSCP.
* `fmgr_switchcontroller_qos_ipdscpmap_map`  Maps between IP-DSCP value to COS queue.
* `fmgr_switchcontroller_qos_qospolicy`  Configure FortiSwitch QoS policy.
* `fmgr_switchcontroller_qos_queuepolicy`  Configure FortiSwitch QoS egress queue policy.
* `fmgr_switchcontroller_qos_queuepolicy_cosqueue`  COS queue configuration.
* `fmgr_switchcontroller_securitypolicy_8021x`  Configure 802.
* `fmgr_switchcontroller_securitypolicy_captiveportal`  Names of VLANs that use captive portal authentication.
* `fmgr_switchcontroller_switchinterfacetag`  Configure switch object tags.
* `fmgr_switchcontroller_trafficpolicy`  Configure FortiSwitch traffic policy.
* `fmgr_switchcontroller_vlanpolicy`  Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy.
* `fmgr_sys_api_sdnconnector`  Query SDN connector data.
* `fmgr_sys_cloud_orchest`  Sys cloud orchest.
* `fmgr_sys_generate_wsdl`  Generate WSDL for specific module and objects.
* `fmgr_sys_hitcount`  Sys hitcount.
* `fmgr_sys_login_challenge`  Answer a log in challenge question, used following a login/user or login/challenge command.
* `fmgr_sys_login_user`  Log into the device with user name and password.
* `fmgr_sys_logout`  Log out a session.
* `fmgr_sys_proxy_json`  Send and receive JSON request to/from managed devices.
* `fmgr_sys_reboot`  Restart FortiManager.
* `fmgr_sys_task_result`  Sys task result.
* `fmgr_system_admin_group`  User group.
* `fmgr_system_admin_group_member`  Group members.
* `fmgr_system_admin_ldap`  LDAP server entry configuration.
* `fmgr_system_admin_ldap_adom`  Admin domain.
* `fmgr_system_admin_profile`  Admin profile.
* `fmgr_system_admin_profile_datamaskcustomfields`  Customized datamask fields.
* `fmgr_system_admin_profile_writepasswdprofiles`  Profile list.
* `fmgr_system_admin_profile_writepasswduserlist`  User list.
* `fmgr_system_admin_radius`  Configure radius.
* `fmgr_system_admin_setting`  Admin setting.
* `fmgr_system_admin_tacacs`  TACACS+ server entry configuration.
* `fmgr_system_admin_user`  Admin user.
* `fmgr_system_admin_user_adom`  Admin domain.
* `fmgr_system_admin_user_adomexclude`  Excluding admin domain.
* `fmgr_system_admin_user_appfilter`  App filter.
* `fmgr_system_admin_user_dashboard`  Custom dashboard widgets.
* `fmgr_system_admin_user_dashboardtabs`  Custom dashboard.
* `fmgr_system_admin_user_ipsfilter`  IPS filter.
* `fmgr_system_admin_user_metadata`  Configure meta data.
* `fmgr_system_admin_user_policyblock`  Policy block write access.
* `fmgr_system_admin_user_policypackage`  Policy package access.
* `fmgr_system_admin_user_restrictdevvdom`  Restricted to these devices/VDOMs.
* `fmgr_system_admin_user_webfilter`  Web filter.
* `fmgr_system_alertconsole`  Alert console.
* `fmgr_system_alertemail`  Configure alertemail.
* `fmgr_system_alertevent`  Alert events.
* `fmgr_system_alertevent_alertdestination`  Alert destination.
* `fmgr_system_autodelete`  Automatic deletion policy for logs, reports, archived, and quarantined files.
* `fmgr_system_autodelete_dlpfilesautodeletion`  Automatic deletion policy for DLP archives.
* `fmgr_system_autodelete_logautodeletion`  Automatic deletion policy for device logs.
* `fmgr_system_autodelete_quarantinefilesautodeletion`  Automatic deletion policy for quarantined files.
* `fmgr_system_autodelete_reportautodeletion`  Automatic deletion policy for reports.
* `fmgr_system_backup_allsettings`  Scheduled backup settings.
* `fmgr_system_certificate_ca`  CA certificate.
* `fmgr_system_certificate_crl`  Certificate Revocation List.
* `fmgr_system_certificate_local`  Local keys and certificates.
* `fmgr_system_certificate_oftp`  OFTP certificates and keys.
* `fmgr_system_certificate_remote`  Remote certificate.
* `fmgr_system_certificate_ssh`  SSH certificates and keys.
* `fmgr_system_connector`  Configure connector.
* `fmgr_system_csf`  Add this device to a Security Fabric or set up a new Security Fabric on this device.
* `fmgr_system_csf_fabricconnector`  Fabric connector configuration.
* `fmgr_system_csf_trustedlist`  Pre-authorized and blocked security fabric nodes.
* `fmgr_system_customlanguage`  Configure custom languages.
* `fmgr_system_dhcp_server`  Configure DHCP servers.
* `fmgr_system_dhcp_server_excluderange`  Exclude one or more ranges of IP addresses from being assigned to clients.
* `fmgr_system_dhcp_server_iprange`  DHCP IP range configuration.
* `fmgr_system_dhcp_server_options`  DHCP options.
* `fmgr_system_dhcp_server_reservedaddress`  Options for the DHCP server to assign IP settings to specific MAC addresses.
* `fmgr_system_dm`  Configure dm.
* `fmgr_system_dns`  DNS configuration.
* `fmgr_system_docker`  Docker host.
* `fmgr_system_externalresource`  Configure external resource.
* `fmgr_system_fips`  Settings for FIPS-CC mode.
* `fmgr_system_fmgcluster`  fmg clsuter.
* `fmgr_system_fmgcluster_peer`  Peer.
* `fmgr_system_fortiguard`  Configure FortiGuard services.
* `fmgr_system_fortiview_autocache`  FortiView auto-cache settings.
* `fmgr_system_fortiview_setting`  FortiView settings.
* `fmgr_system_geoipcountry`  System geoip country.
* `fmgr_system_geoipoverride`  Configure geographical location mapping for IP address.
* `fmgr_system_geoipoverride_ip6range`  Table of IPv6 ranges assigned to country.
* `fmgr_system_geoipoverride_iprange`  Table of IP ranges assigned to country.
* `fmgr_system_global`  Global range attributes.
* `fmgr_system_guiact`  System settings through GUI.
* `fmgr_system_ha`  HA configuration.
* `fmgr_system_ha_monitoredinterfaces`  Monitored interfaces.
* `fmgr_system_ha_monitoredips`  Monitored IP addresses.
* `fmgr_system_ha_peer`  Peer.
* `fmgr_system_hascheduledcheck`  Scheduled HA integrity check.
* `fmgr_system_interface`  Interface configuration.
* `fmgr_system_interface_ipv6`  IPv6 of interface.
* `fmgr_system_interface_member`  Physical interfaces that belong to the aggregate or redundant interface.
* `fmgr_system_localinpolicy`  IPv4 local in policy configuration.
* `fmgr_system_localinpolicy6`  IPv6 local in policy configuration.
* `fmgr_system_locallog_disk_filter`  Filter for disk logging.
* `fmgr_system_locallog_disk_setting`  Settings for local disk logging.
* `fmgr_system_locallog_fortianalyzer2_filter`  Filter for FortiAnalyzer2 logging.
* `fmgr_system_locallog_fortianalyzer2_setting`  Settings for locallog to fortianalyzer.
* `fmgr_system_locallog_fortianalyzer3_filter`  Filter for FortiAnalyzer3 logging.
* `fmgr_system_locallog_fortianalyzer3_setting`  Settings for locallog to fortianalyzer.
* `fmgr_system_locallog_fortianalyzer_filter`  Filter for FortiAnalyzer logging.
* `fmgr_system_locallog_fortianalyzer_setting`  Settings for locallog to fortianalyzer.
* `fmgr_system_locallog_memory_filter`  Filter for memory logging.
* `fmgr_system_locallog_memory_setting`  Settings for memory buffer.
* `fmgr_system_locallog_setting`  Settings for locallog logging.
* `fmgr_system_locallog_syslogd2_filter`  Filter for syslog logging.
* `fmgr_system_locallog_syslogd2_setting`  Settings for remote syslog server.
* `fmgr_system_locallog_syslogd3_filter`  Filter for syslog logging.
* `fmgr_system_locallog_syslogd3_setting`  Settings for remote syslog server.
* `fmgr_system_locallog_syslogd_filter`  Filter for syslog logging.
* `fmgr_system_locallog_syslogd_setting`  Settings for remote syslog server.
* `fmgr_system_log_alert`  Log based alert settings.
* `fmgr_system_log_devicedisable`  Disable client device logging.
* `fmgr_system_log_deviceselector`  Accept/reject devices matching specified filter types.
* `fmgr_system_log_fospolicystats`  FortiOS policy statistics settings.
* `fmgr_system_log_interfacestats`  Interface statistics settings.
* `fmgr_system_log_ioc`  IoC settings.
* `fmgr_system_log_maildomain`  FortiMail domain setting.
* `fmgr_system_log_ratelimit`  Logging rate limit.
* `fmgr_system_log_ratelimit_device`  Device log rate limit.
* `fmgr_system_log_ratelimit_ratelimits`  Per device or ADOM log rate limits.
* `fmgr_system_log_settings`  Log settings.
* `fmgr_system_log_settings_rollinganalyzer`  Log rolling policy for Network Analyzer logs.
* `fmgr_system_log_settings_rollinglocal`  Log rolling policy for local logs.
* `fmgr_system_log_settings_rollingregular`  Log rolling policy for device logs.
* `fmgr_system_log_topology`  Logging topology settings.
* `fmgr_system_log_ueba`  UEBAsettings.
* `fmgr_system_logfetch_clientprofile`  Log-fetch client profile settings.
* `fmgr_system_logfetch_clientprofile_devicefilter`  List of device filter.
* `fmgr_system_logfetch_clientprofile_logfilter`  Log content filters.
* `fmgr_system_logfetch_serversettings`  Log-fetch server settings.
* `fmgr_system_mail`  Alert emails.
* `fmgr_system_mcpolicydisabledadoms`  Multicast policy disabled adoms.
* `fmgr_system_meta`  System meta.
* `fmgr_system_meta_sysmetafields`  System meta sys meta fields.
* `fmgr_system_metadata_admins`  Configure admins.
* `fmgr_system_npu`  Configure NPU attributes.
* `fmgr_system_npu_backgroundssescan`  Configure driver background scan for SSE.
* `fmgr_system_npu_dosoptions`  NPU DoS configurations.
* `fmgr_system_npu_dswdtsprofile`  Configure NPU DSW DTS profile.
* `fmgr_system_npu_dswqueuedtsprofile`  Configure NPU DSW Queue DTS profile.
* `fmgr_system_npu_fpanomaly`  NP6Lite anomaly protection.
* `fmgr_system_npu_hpe`  Host protection engine configuration.
* `fmgr_system_npu_icmpratectrl`  Configure the rate of ICMP messages generated by this FortiGate.
* `fmgr_system_npu_ipreassembly`  IP reassebmly engine configuration.
* `fmgr_system_npu_isfnpqueues`  Configure queues of switch port connected to NP6 XAUI on ingress path.
* `fmgr_system_npu_npqueues`  Configure queue assignment on NP7.
* `fmgr_system_npu_npqueues_ethernettype`  Configure a NP7 QoS Ethernet Type.
* `fmgr_system_npu_npqueues_ipprotocol`  Configure a NP7 QoS IP Protocol.
* `fmgr_system_npu_npqueues_ipservice`  Configure a NP7 QoS IP Service.
* `fmgr_system_npu_npqueues_profile`  Configure a NP7 class profile.
* `fmgr_system_npu_npqueues_scheduler`  Configure a NP7 QoS Scheduler.
* `fmgr_system_npu_nputcam`  Configure NPU TCAM policies.
* `fmgr_system_npu_nputcam_data`  Data fields of TCAM.
* `fmgr_system_npu_nputcam_mask`  Mask fields of TCAM.
* `fmgr_system_npu_nputcam_miract`  Mirror action of TCAM.
* `fmgr_system_npu_nputcam_priact`  Priority action of TCAM.
* `fmgr_system_npu_nputcam_sact`  Source action of TCAM.
* `fmgr_system_npu_nputcam_tact`  Target action of TCAM.
* `fmgr_system_npu_portcpumap`  Configure NPU interface to CPU core mapping.
* `fmgr_system_npu_portnpumap`  Configure port to NPU group mapping.
* `fmgr_system_npu_portpathoption`  Configure port using NPU or Intel-NIC.
* `fmgr_system_npu_priorityprotocol`  Configure NPU priority protocol.
* `fmgr_system_npu_ssehascan`  Configure driver HA scan for SSE.
* `fmgr_system_npu_swehhash`  Configure switch enhanced hashing.
* `fmgr_system_npu_swtrhash`  Configure switch traditional hashing.
* `fmgr_system_npu_tcptimeoutprofile`  Configure TCP timeout profile.
* `fmgr_system_npu_udptimeoutprofile`  Configure UDP timeout profile.
* `fmgr_system_ntp`  NTP settings.
* `fmgr_system_ntp_ntpserver`  NTP server.
* `fmgr_system_objecttag`  Configure object tags.
* `fmgr_system_objecttagging`  Configure object tagging.
* `fmgr_system_passwordpolicy`  Password policy.
* `fmgr_system_replacemsggroup`  Configure replacement message groups.
* `fmgr_system_replacemsggroup_admin`  Replacement message table entries.
* `fmgr_system_replacemsggroup_alertmail`  Replacement message table entries.
* `fmgr_system_replacemsggroup_auth`  Replacement message table entries.
* `fmgr_system_replacemsggroup_automation`  Replacement message table entries.
* `fmgr_system_replacemsggroup_custommessage`  Replacement message table entries.
* `fmgr_system_replacemsggroup_devicedetectionportal`  Replacement message table entries.
* `fmgr_system_replacemsggroup_ec`  Replacement message table entries.
* `fmgr_system_replacemsggroup_fortiguardwf`  Replacement message table entries.
* `fmgr_system_replacemsggroup_ftp`  Replacement message table entries.
* `fmgr_system_replacemsggroup_http`  Replacement message table entries.
* `fmgr_system_replacemsggroup_icap`  Replacement message table entries.
* `fmgr_system_replacemsggroup_mail`  Replacement message table entries.
* `fmgr_system_replacemsggroup_mm1`  Replacement message table entries.
* `fmgr_system_replacemsggroup_mm3`  Replacement message table entries.
* `fmgr_system_replacemsggroup_mm4`  Replacement message table entries.
* `fmgr_system_replacemsggroup_mm7`  Replacement message table entries.
* `fmgr_system_replacemsggroup_mms`  Replacement message table entries.
* `fmgr_system_replacemsggroup_nacquar`  Replacement message table entries.
* `fmgr_system_replacemsggroup_nntp`  Replacement message table entries.
* `fmgr_system_replacemsggroup_spam`  Replacement message table entries.
* `fmgr_system_replacemsggroup_sslvpn`  Replacement message table entries.
* `fmgr_system_replacemsggroup_trafficquota`  Replacement message table entries.
* `fmgr_system_replacemsggroup_utm`  Replacement message table entries.
* `fmgr_system_replacemsggroup_webproxy`  Replacement message table entries.
* `fmgr_system_replacemsgimage`  Configure replacement message images.
* `fmgr_system_report_autocache`  Report auto-cache settings.
* `fmgr_system_report_estbrowsetime`  Report estimated browse time settings.
* `fmgr_system_report_group`  Report group.
* `fmgr_system_report_group_chartalternative`  Chart alternatives.
* `fmgr_system_report_group_groupby`  Group-by variables.
* `fmgr_system_report_setting`  Report settings.
* `fmgr_system_route`  Routing table configuration.
* `fmgr_system_route6`  Routing table configuration.
* `fmgr_system_saml`  Global settings for SAML authentication.
* `fmgr_system_saml_fabricidp`  Authorized identity providers.
* `fmgr_system_sdnconnector`  Configure connection to SDN Connector.
* `fmgr_system_sdnconnector_compartmentlist`  Configure OCI compartment list.
* `fmgr_system_sdnconnector_externalaccountlist`  Configure AWS external account list.
* `fmgr_system_sdnconnector_externalip`  Configure GCP external IP.
* `fmgr_system_sdnconnector_forwardingrule`  Configure GCP forwarding rule.
* `fmgr_system_sdnconnector_gcpprojectlist`  Configure GCP project list.
* `fmgr_system_sdnconnector_nic`  Configure Azure network interface.
* `fmgr_system_sdnconnector_nic_ip`  Configure IP configuration.
* `fmgr_system_sdnconnector_ociregionlist`  Configure OCI region list.
* `fmgr_system_sdnconnector_route`  Configure GCP route.
* `fmgr_system_sdnconnector_routetable`  Configure Azure route table.
* `fmgr_system_sdnconnector_routetable_route`  Configure Azure route.
* `fmgr_system_sdnproxy`  Configure SDN proxy.
* `fmgr_system_smsserver`  Configure SMS server for sending SMS messages to support user authentication.
* `fmgr_system_sniffer`  Interface sniffer.
* `fmgr_system_snmp_community`  SNMP community configuration.
* `fmgr_system_snmp_community_hosts`  Allow hosts configuration.
* `fmgr_system_snmp_community_hosts6`  Allow hosts configuration for IPv6.
* `fmgr_system_snmp_sysinfo`  SNMP configuration.
* `fmgr_system_snmp_user`  SNMP user configuration.
* `fmgr_system_socfabric`  SOC Fabric.
* `fmgr_system_socfabric_trustedlist`  Pre-authorized security fabric nodes.
* `fmgr_system_sql`  SQL settings.
* `fmgr_system_sql_customindex`  List of SQL index fields.
* `fmgr_system_sql_customskipidx`  List of aditional SQL skip index fields.
* `fmgr_system_sql_tsindexfield`  List of SQL text search index fields.
* `fmgr_system_sslciphersuites`  Configure preferred SSL/TLS cipher suites.
* `fmgr_system_syslog`  Syslog servers.
* `fmgr_system_virtualwirepair`  Configure virtual wire pairs.
* `fmgr_system_webproxy`  Configure system web proxy.
* `fmgr_system_workflow_approvalmatrix`  workflow approval matrix.
* `fmgr_system_workflow_approvalmatrix_approver`  Approver.
* `fmgr_telemetrycontroller_agentprofile`  Configure FortiTelemetry agent profiles.
* `fmgr_telemetrycontroller_application_predefine`  Configure FortiTelemetry predefined applications.
* `fmgr_telemetrycontroller_profile`  Configure FortiTelemetry profiles.
* `fmgr_telemetrycontroller_profile_application`  Configure applications.
* `fmgr_telemetrycontroller_profile_application_sla`  Service level agreement.
* `fmgr_template`  Require device/vdom scope member.
* `fmgr_templategroup`  Require device/vdom scope member.
* `fmgr_um_image_upgrade`  The older API for updating the firmware of specific device.
* `fmgr_um_image_upgrade_ext`  Update the firmware of specific device.
* `fmgr_ums_setting`  Ums setting.
* `fmgr_user_adgrp`  Configure FSSO groups.
* `fmgr_user_certificate`  Configure certificate users.
* `fmgr_user_clearpass`  User clearpass.
* `fmgr_user_connector`  User connector.
* `fmgr_user_device`  Configure devices.
* `fmgr_user_device_dynamicmapping`  Configure devices.
* `fmgr_user_device_tagging`  Config object tagging.
* `fmgr_user_deviceaccesslist`  Configure device access control lists.
* `fmgr_user_deviceaccesslist_devicelist`  Device list.
* `fmgr_user_devicecategory`  Configure device categories.
* `fmgr_user_devicegroup`  Configure device groups.
* `fmgr_user_devicegroup_dynamicmapping`  Configure device groups.
* `fmgr_user_devicegroup_tagging`  Config object tagging.
* `fmgr_user_domaincontroller`  Configure domain controller entries.
* `fmgr_user_domaincontroller_extraserver`  extra servers.
* `fmgr_user_exchange`  Configure MS Exchange server entries.
* `fmgr_user_externalidentityprovider`  Configure external identity provider.
* `fmgr_user_flexvm`  User flexvm.
* `fmgr_user_fortitoken`  Configure FortiToken.
* `fmgr_user_fsso`  Configure Fortinet Single Sign On.
* `fmgr_user_fsso_dynamicmapping`  Configure Fortinet Single Sign On.
* `fmgr_user_fssopolling`  Configure FSSO active directory servers for polling mode.
* `fmgr_user_fssopolling_adgrp`  LDAP Group Info.
* `fmgr_user_group`  Configure user groups.
* `fmgr_user_group_dynamicmapping`  Configure user groups.
* `fmgr_user_group_dynamicmapping_guest`  Guest User.
* `fmgr_user_group_dynamicmapping_match`  Group matches.
* `fmgr_user_group_dynamicmapping_sslvpnoschecklist`  User group dynamic mapping sslvpn os check list.
* `fmgr_user_group_guest`  Guest User.
* `fmgr_user_group_match`  Group matches.
* `fmgr_user_json`  User json.
* `fmgr_user_krbkeytab`  Configure Kerberos keytab entries.
* `fmgr_user_ldap`  Configure LDAP server entries.
* `fmgr_user_ldap_dynamicmapping`  Configure LDAP server entries.
* `fmgr_user_local`  Configure local users.
* `fmgr_user_nsx`  User nsx.
* `fmgr_user_nsx_service`  User nsx service.
* `fmgr_user_passwordpolicy`  Configure user password policy.
* `fmgr_user_peer`  Configure peer users.
* `fmgr_user_peergrp`  Configure peer groups.
* `fmgr_user_pop3`  POP3 server entry configuration.
* `fmgr_user_pxgrid`  User pxgrid.
* `fmgr_user_radius`  Configure RADIUS server entries.
* `fmgr_user_radius_accountingserver`  Additional accounting servers.
* `fmgr_user_radius_dynamicmapping`  Configure RADIUS server entries.
* `fmgr_user_radius_dynamicmapping_accountingserver`  Additional accounting servers.
* `fmgr_user_saml`  SAML server entry configuration.
* `fmgr_user_saml_dynamicmapping`  SAML server entry configuration.
* `fmgr_user_scim`  Configure SCIM client entries.
* `fmgr_user_securityexemptlist`  Configure security exemption list.
* `fmgr_user_securityexemptlist_rule`  Configure rules for exempting users from captive portal authentication.
* `fmgr_user_tacacs`  Configure TACACS+ server entries.
* `fmgr_user_tacacs_dynamicmapping`  Configure TACACS+ server entries.
* `fmgr_user_vcenter`  User vcenter.
* `fmgr_user_vcenter_rule`  User vcenter rule.
* `fmgr_utmprofile`  Configure UTM.
* `fmgr_vap`  Configure Virtual Access Points.
* `fmgr_vap_dynamicmapping`  Configure Virtual Access Points.
* `fmgr_vap_macfilterlist`  Create a list of MAC addresses for MAC address filtering.
* `fmgr_vap_mpskkey`  Pre-shared keys that can be used to connect to this virtual access point.
* `fmgr_vap_portalmessageoverrides`  Individual message overrides.
* `fmgr_vap_vlanname`  Table for mapping VLAN name to VLAN ID.
* `fmgr_vap_vlanpool`  VLAN pool.
* `fmgr_vapgroup`  Configure virtual Access Point.
* `fmgr_videofilter_keyword`  Configure video filter keywords.
* `fmgr_videofilter_keyword_word`  List of keywords.
* `fmgr_videofilter_profile`  Configure VideoFilter profile.
* `fmgr_videofilter_profile_filters`  YouTube filter entries.
* `fmgr_videofilter_profile_fortiguardcategory`  Configure FortiGuard categories.
* `fmgr_videofilter_profile_fortiguardcategory_filters`  Configure VideoFilter FortiGuard category.
* `fmgr_videofilter_youtubechannelfilter`  Configure YouTube channel filter.
* `fmgr_videofilter_youtubechannelfilter_entries`  YouTube filter entries.
* `fmgr_videofilter_youtubekey`  Configure YouTube API keys.
* `fmgr_virtualpatch_profile`  Configure virtual-patch profile.
* `fmgr_virtualpatch_profile_exemption`  Exempt devices or rules.
* `fmgr_voip_profile`  Configure VoIP profiles.
* `fmgr_voip_profile_msrp`  MSRP.
* `fmgr_voip_profile_sccp`  SCCP.
* `fmgr_voip_profile_sip`  SIP.
* `fmgr_vpn_certificate_ca`  CA certificate.
* `fmgr_vpn_certificate_ocspserver`  OCSP server configuration.
* `fmgr_vpn_certificate_remote`  Remote certificate as a PEM file.
* `fmgr_vpn_ipsec_fec`  Configure Forward Error Correction.
* `fmgr_vpn_ipsec_fec_mappings`  FEC redundancy mapping table.
* `fmgr_vpn_ssl_settings`  Configure SSL VPN.
* `fmgr_vpn_ssl_settings_authenticationrule`  Authentication rule for SSL VPN.
* `fmgr_vpnmgr_node`  VPN node for VPN Manager.
* `fmgr_vpnmgr_node_iprange`  Vpnmgr node ip range.
* `fmgr_vpnmgr_node_ipv4excluderange`  Vpnmgr node ipv4 exclude range.
* `fmgr_vpnmgr_node_protectedsubnet`  Vpnmgr node protected subnet.
* `fmgr_vpnmgr_node_summaryaddr`  Vpnmgr node summary addr.
* `fmgr_vpnmgr_vpntable`  Vpnmgr vpntable.
* `fmgr_vpnsslweb_hostchecksoftware`  SSL-VPN host check software.
* `fmgr_vpnsslweb_hostchecksoftware_checkitemlist`  Check item list.
* `fmgr_vpnsslweb_portal`  Portal.
* `fmgr_vpnsslweb_portal_bookmarkgroup`  Portal bookmark group.
* `fmgr_vpnsslweb_portal_bookmarkgroup_bookmarks`  Bookmark table.
* `fmgr_vpnsslweb_portal_bookmarkgroup_bookmarks_formdata`  Form data.
* `fmgr_vpnsslweb_portal_landingpage`  Landing page options.
* `fmgr_vpnsslweb_portal_landingpage_formdata`  Form data.
* `fmgr_vpnsslweb_portal_macaddrcheckrule`  Client MAC address check rule.
* `fmgr_vpnsslweb_portal_oschecklist`  SSL VPN OS checks.
* `fmgr_vpnsslweb_portal_splitdns`  Split DNS for SSL VPN.
* `fmgr_vpnsslweb_realm`  Realm.
* `fmgr_vpnsslweb_virtualdesktopapplist`  SSL-VPN virtual desktop application list.
* `fmgr_vpnsslweb_virtualdesktopapplist_apps`  Applications.
* `fmgr_waf_mainclass`  Hidden table for datasource.
* `fmgr_waf_profile`  Web application firewall configuration.
* `fmgr_waf_profile_addresslist`  Black address list and white address list.
* `fmgr_waf_profile_constraint`  WAF HTTP protocol restrictions.
* `fmgr_waf_profile_constraint_contentlength`  HTTP content length in request.
* `fmgr_waf_profile_constraint_exception`  HTTP constraint exception.
* `fmgr_waf_profile_constraint_headerlength`  HTTP header length in request.
* `fmgr_waf_profile_constraint_hostname`  Enable/disable hostname check.
* `fmgr_waf_profile_constraint_linelength`  HTTP line length in request.
* `fmgr_waf_profile_constraint_malformed`  Enable/disable malformed HTTP request check.
* `fmgr_waf_profile_constraint_maxcookie`  Maximum number of cookies in HTTP request.
* `fmgr_waf_profile_constraint_maxheaderline`  Maximum number of HTTP header line.
* `fmgr_waf_profile_constraint_maxrangesegment`  Maximum number of range segments in HTTP range line.
* `fmgr_waf_profile_constraint_maxurlparam`  Maximum number of parameters in URL.
* `fmgr_waf_profile_constraint_method`  Enable/disable HTTP method check.
* `fmgr_waf_profile_constraint_paramlength`  Maximum length of parameter in URL, HTTP POST request or HTTP body.
* `fmgr_waf_profile_constraint_urlparamlength`  Maximum length of parameter in URL.
* `fmgr_waf_profile_constraint_version`  Enable/disable HTTP version check.
* `fmgr_waf_profile_method`  Method restriction.
* `fmgr_waf_profile_method_methodpolicy`  HTTP method policy.
* `fmgr_waf_profile_signature`  WAF signatures.
* `fmgr_waf_profile_signature_customsignature`  Custom signature.
* `fmgr_waf_profile_signature_mainclass`  Main signature class.
* `fmgr_waf_profile_urlaccess`  URL access list.
* `fmgr_waf_profile_urlaccess_accesspattern`  URL access pattern.
* `fmgr_waf_signature`  Hidden table for datasource.
* `fmgr_waf_subclass`  Hidden table for datasource.
* `fmgr_wagprofile`  Configure wireless access gateway.
* `fmgr_wanopt_authgroup`  Configure WAN optimization authentication groups.
* `fmgr_wanopt_peer`  Configure WAN optimization peers.
* `fmgr_wanopt_profile`  Configure WAN optimization profiles.
* `fmgr_wanopt_profile_cifs`  Enable/disable CIFS.
* `fmgr_wanopt_profile_ftp`  Enable/disable FTP WAN Optimization and configure FTP WAN Optimization features.
* `fmgr_wanopt_profile_http`  Enable/disable HTTP WAN Optimization and configure HTTP WAN Optimization features.
* `fmgr_wanopt_profile_mapi`  Enable/disable MAPI email WAN Optimization and configure MAPI WAN Optimization features.
* `fmgr_wanopt_profile_tcp`  Enable/disable TCP WAN Optimization and configure TCP WAN Optimization features.
* `fmgr_wanprof_system_sdwan`  Configure redundant internet connections using SD-WAN.
* `fmgr_wanprof_system_sdwan_duplication`  Create SD-WAN duplication rule.
* `fmgr_wanprof_system_sdwan_healthcheck`  SD-WAN status checking or health checking.
* `fmgr_wanprof_system_sdwan_healthcheck_sla`  Service level agreement.
* `fmgr_wanprof_system_sdwan_members`  FortiGate interfaces added to the SD-WAN.
* `fmgr_wanprof_system_sdwan_neighbor`  Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
* `fmgr_wanprof_system_sdwan_service`  Create SD-WAN rules.
* `fmgr_wanprof_system_sdwan_service_sla`  Service level agreement.
* `fmgr_wanprof_system_sdwan_zone`  Configure SD-WAN zones.
* `fmgr_wanprof_system_virtualwanlink`  Configure redundant internet connections using SD-WAN.
* `fmgr_wanprof_system_virtualwanlink_healthcheck`  SD-WAN status checking or health checking.
* `fmgr_wanprof_system_virtualwanlink_healthcheck_sla`  Service level agreement.
* `fmgr_wanprof_system_virtualwanlink_members`  Physical FortiGate interfaces added to the virtual-wan-link.
* `fmgr_wanprof_system_virtualwanlink_neighbor`  SD-WAN neighbor table.
* `fmgr_wanprof_system_virtualwanlink_service`  Create SD-WAN rules or priority rules.
* `fmgr_wanprof_system_virtualwanlink_service_sla`  Service level agreement.
* `fmgr_webfilter_categories`  Webfilter categories.
* `fmgr_webfilter_content`  Configure Web filter banned word table.
* `fmgr_webfilter_content_entries`  Configure banned word entries.
* `fmgr_webfilter_contentheader`  Configure content types used by Web filter.
* `fmgr_webfilter_contentheader_entries`  Configure content types used by web filter.
* `fmgr_webfilter_ftgdlocalcat`  Configure FortiGuard Web Filter local categories.
* `fmgr_webfilter_ftgdlocalrating`  Configure local FortiGuard Web Filter local ratings.
* `fmgr_webfilter_profile`  Configure Web filter profiles.
* `fmgr_webfilter_profile_antiphish`  AntiPhishing profile.
* `fmgr_webfilter_profile_antiphish_custompatterns`  Custom username and password regex patterns.
* `fmgr_webfilter_profile_antiphish_inspectionentries`  AntiPhishing entries.
* `fmgr_webfilter_profile_filefilter`  File filter.
* `fmgr_webfilter_profile_filefilter_entries`  File filter entries.
* `fmgr_webfilter_profile_ftgdwf`  FortiGuard Web Filter settings.
* `fmgr_webfilter_profile_ftgdwf_filters`  FortiGuard filters.
* `fmgr_webfilter_profile_ftgdwf_quota`  FortiGuard traffic quota settings.
* `fmgr_webfilter_profile_override`  Web Filter override settings.
* `fmgr_webfilter_profile_urlextraction`  Configure URL Extraction.
* `fmgr_webfilter_profile_web`  Web content filtering settings.
* `fmgr_webfilter_profile_youtubechannelfilter`  YouTube channel filter.
* `fmgr_webfilter_urlfilter`  Configure URL filter lists.
* `fmgr_webfilter_urlfilter_entries`  URL filter entries.
* `fmgr_webproxy_forwardserver`  Configure forward-server addresses.
* `fmgr_webproxy_forwardservergroup`  Configure a forward server group consisting or multiple forward servers.
* `fmgr_webproxy_forwardservergroup_serverlist`  Add web forward servers to a list to form a server group.
* `fmgr_webproxy_profile`  Configure web proxy profiles.
* `fmgr_webproxy_profile_headers`  Configure HTTP forwarded requests headers.
* `fmgr_webproxy_wisp`  Configure Wireless Internet service provider.
* `fmgr_widsprofile`  Configure wireless intrusion detection system.
* `fmgr_wireless_accesscontrollist`  Configure WiFi bridge access control list.
* `fmgr_wireless_accesscontrollist_layer3ipv4rules`  AP ACL layer3 ipv4 rule list.
* `fmgr_wireless_accesscontrollist_layer3ipv6rules`  AP ACL layer3 ipv6 rule list.
* `fmgr_wireless_address`  Configure the client with its MAC address.
* `fmgr_wireless_addrgrp`  Configure the MAC address group.
* `fmgr_wireless_ssidpolicy`  Configure WiFi SSID policies.
* `fmgr_wireless_syslogprofile`  Configure Wireless Termination Points.
* `fmgr_wireless_vap_ip6prefixlist`  Wireless controller vap ip6 prefix list.
* `fmgr_wtpprofile`  Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
* `fmgr_wtpprofile_denymaclist`  List of MAC addresses that are denied access to this WTP, FortiAP, or AP.
* `fmgr_wtpprofile_eslsesdongle`  ESL SES-imagotag dongle configuration.
* `fmgr_wtpprofile_lan`  WTP LAN port mapping.
* `fmgr_wtpprofile_lbs`  Set various location based service.
* `fmgr_wtpprofile_platform`  WTP, FortiAP, or AP platform.
* `fmgr_wtpprofile_radio1`  Configuration options for radio 1.
* `fmgr_wtpprofile_radio2`  Configuration options for radio 2.
* `fmgr_wtpprofile_radio3`  Configuration options for radio 3.
* `fmgr_wtpprofile_radio4`  Configuration options for radio 4.
* `fmgr_wtpprofile_splittunnelingacl`  Split tunneling ACL filter list.



## License Information

FortiManager Ansible Collection follows [GNU General Public License v3.0](https://github.com/fortinet-ansible-dev/ansible-galaxy-fortimanager-collection/blob/main/LICENSE).