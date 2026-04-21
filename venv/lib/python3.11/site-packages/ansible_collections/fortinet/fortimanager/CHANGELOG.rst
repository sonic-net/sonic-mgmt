===================================
Fortinet.Fortimanager Release Notes
===================================

.. contents:: Topics


v2.11.0
=======

Release Summary
---------------

Release fortinet.fortimanager 2.11.0

Minor Changes
-------------

- Supported new schemas in FortiManager 7.0.14, 7.2.10, 7.2.11.

Bugfixes
--------

- Changed the logic of getting FortiManager system information to prevent permission denied error.
- Supported module_defaults. General variables can be specified in one place by using module_defaults.

v2.10.0
=======

Release Summary
---------------

Release fortinet.fortimanager 2.10.0

Minor Changes
-------------

- Supported new modules in FortiManager 7.4.6, 7.4.7, 7.6.3.

Bugfixes
--------

- Added "gather_facts" to all example playbooks.
- Fixed a BUG that occurred when username/password and access token were used at the same time.

New Modules
-----------

- fortinet.fortimanager.fmgr_dlp_exactdatamatch - Configure exact-data-match template used by DLP scan.
- fortinet.fortimanager.fmgr_dlp_exactdatamatch_columns - DLP exact-data-match column types.
- fortinet.fortimanager.fmgr_dlp_label - Configure labels used by DLP blocking.
- fortinet.fortimanager.fmgr_dlp_label_entries - DLP label entries.
- fortinet.fortimanager.fmgr_extensioncontroller_extendervap - FortiExtender wifi vap configuration.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension - Configure Internet Services Extension.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension_disableentry - Disable entries in the Internet Service database.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension_disableentry_ip6range - IPv6 ranges in the disable entry.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension_disableentry_iprange - IPv4 ranges in the disable entry.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension_disableentry_portrange - Port ranges in the disable entry.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension_entry - Entries added to the Internet Service extension database.
- fortinet.fortimanager.fmgr_firewall_internetserviceextension_entry_portrange - Port ranges in the custom entry.
- fortinet.fortimanager.fmgr_fmupdate_fgdsetting - Cli fmupdate fgd setting
- fortinet.fortimanager.fmgr_fmupdate_fgdsetting_serveroverride - Cli fmupdate fgd setting server override
- fortinet.fortimanager.fmgr_gtp_rattimeoutprofile - RAT timeout profile
- fortinet.fortimanager.fmgr_icap_servergroup - Configure an ICAP server group consisting of multiple forward servers.
- fortinet.fortimanager.fmgr_icap_servergroup_serverlist - Add ICAP servers to a list to form a server group.
- fortinet.fortimanager.fmgr_system_log_deviceselector - Accept/reject devices matching specified filter types.
- fortinet.fortimanager.fmgr_telemetrycontroller_agentprofile - Configure FortiTelemetry agent profiles.
- fortinet.fortimanager.fmgr_telemetrycontroller_application_predefine - Configure FortiTelemetry predefined applications.
- fortinet.fortimanager.fmgr_telemetrycontroller_profile - Configure FortiTelemetry profiles.
- fortinet.fortimanager.fmgr_telemetrycontroller_profile_application - Configure applications.
- fortinet.fortimanager.fmgr_telemetrycontroller_profile_application_sla - Service level agreement
- fortinet.fortimanager.fmgr_user_scim - Configure SCIM client entries.
- fortinet.fortimanager.fmgr_wireless_vap_ip6prefixlist - Wireless controller vap ip6 prefix list

v2.9.1
======

Release Summary
---------------

Release fortinet.fortimanager 2.9.1

Bugfixes
--------

- Changed the default playbook examples for each module to pass ansible-lint.
- Corrected mainkey of some modules.

v2.9.0
======

Release Summary
---------------

Release fortinet.fortimanager 2.9.0

Minor Changes
-------------

- Supported FortiManager 7.2.9, 7.4.6, 7.6.2. Added 3 new modules.

Bugfixes
--------

- Changed parameter type of some parameters.

New Modules
-----------

- fortinet.fortimanager.fmgr_gtp_ieallowlist - IE allow list.
- fortinet.fortimanager.fmgr_gtp_ieallowlist_entries - Entries of allow list for unknown or out-of-state IEs.
- fortinet.fortimanager.fmgr_ums_setting - Ums setting

v2.8.2
======

Release Summary
---------------

Release fortinet.fortimanager 2.8.2

Bugfixes
--------

- Modified built-in document to support sanity tests in ansible-core 2.18.0. No functionality changed.

v2.8.1
======

Release Summary
---------------

Release fortinet.fortimanager 2.8.1

Bugfixes
--------

- Fixed a bug where rc_failed and rc_succeeded did not work.

v2.8.0
======

Release Summary
---------------

Release fortinet.fortimanager 2.8.0

Minor Changes
-------------

- Supported FortiManager 6.2.13, 6.4.15, 7.0.13, 7.2.8, 7.4.5, 7.6.1. Added 1 new module.
- Supported check diff for some modules except "fmgr_generic". You can use "ansible-playbook -i <your-host-file> <your-playbook> --check --diff" to check what changes your playbook will make to the FortiManager.

Bugfixes
--------

- Changed all input argument name in ansible built-in documentation to the underscore format. E.g., changed "var-name" to "var_name".
- Improved code logic, reduced redundant requests for system information.

New Modules
-----------

- fortinet.fortimanager.fmgr_pkg_videofilter_youtubekey - Configure YouTube API keys.

v2.7.0
======

Release Summary
---------------

Release fortinet.fortimanager 2.7.0

Minor Changes
-------------

- Supported FortiManager 7.6.0. Added 7 new modules.
- Supported check mode for all modules except "fmgr_generic". You can use "ansible-playbook -i <your-host-file> <your-playbook> --check" to validate whether your playbook will make any changes to the FortiManager.

Bugfixes
--------

- Fixed Bug in "fmgr_fact"
- Improved documentation.

New Modules
-----------

- fortinet.fortimanager.fmgr_fmg_sasemanager_settings - Fmg sase manager settings
- fortinet.fortimanager.fmgr_fmg_sasemanager_status - Fmg sase manager status
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_proxypolicy - Configure proxy policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_proxypolicy_sectionvalue - Configure proxy policies.
- fortinet.fortimanager.fmgr_system_admin_user_policyblock - Policy block write access.
- fortinet.fortimanager.fmgr_system_fmgcluster - fmg clsuter.
- fortinet.fortimanager.fmgr_system_fmgcluster_peer - Peer.

v2.6.0
======

Release Summary
---------------

release fortinet.fortimanager 2.6.0

Minor Changes
-------------

- Supported FortiManager 7.4.3. 7 new modules.
- Supported ansible-core 2.17.

Bugfixes
--------

- Added more description in the documentation.
- Deleted 9 fmgr_switchcontroller_managedswitch_* modules. Will support them in FortiManager Device Ansible.
- Improved fmgr_fact, fmgr_clone, fmgr_move.

New Modules
-----------

- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_wifi - FortiExtender wifi configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_wifi_radio1 - Radio-1 config for Wi-Fi 2.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_wifi_radio2 - Radio-2 config for Wi-Fi 5GHz
- fortinet.fortimanager.fmgr_firewall_sslsshprofile_echoutersni - ClientHelloOuter SNIs to be blocked.
- fortinet.fortimanager.fmgr_system_log_ueba - UEBAsettings.
- fortinet.fortimanager.fmgr_system_npu_icmpratectrl - Configure the rate of ICMP messages generated by this FortiGate.
- fortinet.fortimanager.fmgr_user_externalidentityprovider - Configure external identity provider.

v2.5.0
======

Release Summary
---------------

release fortinet.fortimanager 2.5.0

Minor Changes
-------------

- Renamed the input argument "message" to "fmgr_message" to comply with Ansible requirements.

Bugfixes
--------

- Improved bypass_validation. If you now set bypass_validation to true, it will allow you to send parameters that are not defined in the schema.
- Improved documentation, added description for all "no description" modules.
- Improved documentation.
- Supported "state:absent" for all modules end with "_objectmember", "_scopemember", and "_scetionvalue".
- Supported FortiManager 6.4.14, 7.0.11, 7.0.12, 7.2.5.

v2.4.0
======

Release Summary
---------------

release fortinet.fortimanager 2.4.0

Minor Changes
-------------

- Added deprecated warning to invalid argument name, please change the invalid argument name such as "var-name", "var name" to "var_name".
- Supported fortimanager 7.4.2, 21 new modules.

Bugfixes
--------

- Changed revision to v_range to reduce the size of the code.
- Fixed the behavior of module fmgr_firewall_internetservicecustom.
- Fixed the behavior of some modules that contain the argument policyid.
- Improved example ansible playbooks.
- Improved the logic of fmgr_fact, fmgr_clone, fmgr_rename, fmgr_move. Usage remains unchanged.
- Reduced the size of module_arg_spec in each module.
- Removed most of the sanity test ignores.

New Modules
-----------

- fortinet.fortimanager.fmgr_diameterfilter_profile - Configure Diameter filter profiles.
- fortinet.fortimanager.fmgr_firewall_accessproxysshclientcert - Configure Access Proxy SSH client certificate.
- fortinet.fortimanager.fmgr_firewall_accessproxysshclientcert_certextension - Configure certificate extension for user certificate.
- fortinet.fortimanager.fmgr_firewall_vip6_quic - QUIC setting.
- fortinet.fortimanager.fmgr_firewall_vip_gslbpublicips - Publicly accessible IP addresses for the FortiGSLB service.
- fortinet.fortimanager.fmgr_sctpfilter_profile - Configure SCTP filter profiles.
- fortinet.fortimanager.fmgr_sctpfilter_profile_ppidfilters - PPID filters list.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_vlan - Configure VLAN assignment priority.
- fortinet.fortimanager.fmgr_system_admin_profile_writepasswdprofiles - Profile list.
- fortinet.fortimanager.fmgr_system_admin_profile_writepasswduserlist - User list.
- fortinet.fortimanager.fmgr_system_npu_nputcam - Configure NPU TCAM policies.
- fortinet.fortimanager.fmgr_system_npu_nputcam_data - Data fields of TCAM.
- fortinet.fortimanager.fmgr_system_npu_nputcam_mask - Mask fields of TCAM.
- fortinet.fortimanager.fmgr_system_npu_nputcam_miract - Mirror action of TCAM.
- fortinet.fortimanager.fmgr_system_npu_nputcam_priact - Priority action of TCAM.
- fortinet.fortimanager.fmgr_system_npu_nputcam_sact - Source action of TCAM.
- fortinet.fortimanager.fmgr_system_npu_nputcam_tact - Target action of TCAM.
- fortinet.fortimanager.fmgr_videofilter_keyword - Configure video filter keywords.
- fortinet.fortimanager.fmgr_videofilter_keyword_word - List of keywords.
- fortinet.fortimanager.fmgr_videofilter_profile_filters - YouTube filter entries.
- fortinet.fortimanager.fmgr_videofilter_youtubekey - Configure YouTube API keys.

v2.3.1
======

Release Summary
---------------

release fortinet.fortimanager 2.3.1

Bugfixes
--------

- Added missing enum values for some arguments.
- Change minimum required ansible-core version to 2.14.0
- Fixed a bug where ansible may skip update incorrectly.
- Support FortiManager 7.0.10

v2.3.0
======

Release Summary
---------------

release fortinet.fortimanager 2.3.0

Minor Changes
-------------

- Some arguments can support both list or string format input now.
- Support newest versions for FortiManager v6.2 ~ v7.4

Bugfixes
--------

- Add 'access_token' in 'fmgr_generic'.
- Add param 'platform' in 'fmgr_wtpprofile' and param 'interface' in 'fmgr_fsp_vlan'.
- Fix a bug that collection may update the resource when it does not need to.
- Fix some modules missing revision (used for version warning).
- Fixed the bug that would report an error when providing access_token and username/password at the same time.
- Improve document.
- Improve fmgr_fact. 'changed' will not be true anymore if you get the result.
- Improve sanity tests.
- When the JSON data sent by FortiManager is not in the right format, the collection can still execute correctly.

New Modules
-----------

- fortinet.fortimanager.fmgr_casb_profile - Configure CASB profile.
- fortinet.fortimanager.fmgr_casb_profile_saasapplication - CASB profile SaaS application.
- fortinet.fortimanager.fmgr_casb_profile_saasapplication_accessrule - CASB profile access rule.
- fortinet.fortimanager.fmgr_casb_profile_saasapplication_customcontrol - CASB profile custom control.
- fortinet.fortimanager.fmgr_casb_profile_saasapplication_customcontrol_option - CASB custom control option.
- fortinet.fortimanager.fmgr_casb_saasapplication - Configure CASB SaaS application.
- fortinet.fortimanager.fmgr_casb_useractivity - Configure CASB user activity.
- fortinet.fortimanager.fmgr_casb_useractivity_controloptions - CASB control options.
- fortinet.fortimanager.fmgr_casb_useractivity_controloptions_operations - CASB control option operations.
- fortinet.fortimanager.fmgr_casb_useractivity_match - CASB user activity match rules.
- fortinet.fortimanager.fmgr_casb_useractivity_match_rules - CASB user activity rules.
- fortinet.fortimanager.fmgr_dvmdb_upgrade - no description
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6_quic - QUIC setting.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway_quic - QUIC setting.
- fortinet.fortimanager.fmgr_firewall_accessproxy_apigateway6_quic - QUIC setting.
- fortinet.fortimanager.fmgr_firewall_accessproxy_apigateway_quic - QUIC setting.
- fortinet.fortimanager.fmgr_firewall_casbprofile - no description
- fortinet.fortimanager.fmgr_firewall_casbprofile_saasapplication - no description
- fortinet.fortimanager.fmgr_firewall_casbprofile_saasapplication_accessrule - no description
- fortinet.fortimanager.fmgr_firewall_casbprofile_saasapplication_customcontrol - no description
- fortinet.fortimanager.fmgr_firewall_casbprofile_saasapplication_customcontrol_option - no description
- fortinet.fortimanager.fmgr_firewall_vendormac - Show vendor and the MAC address they have.
- fortinet.fortimanager.fmgr_firewall_vip_quic - QUIC setting.
- fortinet.fortimanager.fmgr_pm_config_meta_reference - no description
- fortinet.fortimanager.fmgr_securityconsole_install_objects_v2 - no description
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_routeoffloadrouter - Configure route offload MCLAG IP address.
- fortinet.fortimanager.fmgr_switchcontroller_ptp_profile - Global PTP profile.
- fortinet.fortimanager.fmgr_system_csf - Add this device to a Security Fabric or set up a new Security Fabric on this device.
- fortinet.fortimanager.fmgr_system_csf_fabricconnector - Fabric connector configuration.
- fortinet.fortimanager.fmgr_system_csf_trustedlist - Pre-authorized and blocked security fabric nodes.
- fortinet.fortimanager.fmgr_system_sdnproxy - Configure SDN proxy.
- fortinet.fortimanager.fmgr_virtualpatch_profile - Configure virtual-patch profile.
- fortinet.fortimanager.fmgr_virtualpatch_profile_exemption - Exempt devices or rules.

v2.2.1
======

Release Summary
---------------

release fortinet.fortimanager 2.2.1

Bugfixes
--------

- Fix a bug where the user may not be able to use workspace_locking_adom if the workspace mode is per-adom.
- Improve login logic in httpapi plugin.

v2.2.0
======

Release Summary
---------------

release fortinet.fortimanager to support FMG v6.0 - v7.4.

Major Changes
-------------

- Support all FortiManager versions in 6.2, 6.4, 7.0, 7.2 and 7.4. 139 new modules.
- Support token based authentication.

Minor Changes
-------------

- Corrected the behavior of module fmgr_pkg_firewall_consolidated_policy_sectionvalue and fmgr_pkg_firewall_securitypolicy_sectionvalue.
- Improve documentation.

Bugfixes
--------

- Corrected description of parameters in documentation.
- Fixed Many sanity test warnings and errors.
- Fixed a bug where users might not be able to login.
- Fixed version_added in the document. The value of this parameter is the version each module first supported in the FortiManager Ansible Collection.

New Modules
-----------

- fortinet.fortimanager.fmgr_application_casi_profile - Cloud Access Security Inspection.
- fortinet.fortimanager.fmgr_application_casi_profile_entries - Application entries.
- fortinet.fortimanager.fmgr_application_internetservice - Show Internet service application.
- fortinet.fortimanager.fmgr_application_internetservice_entry - Entries in the Internet service database.
- fortinet.fortimanager.fmgr_application_internetservicecustom - Configure custom Internet service applications.
- fortinet.fortimanager.fmgr_application_internetservicecustom_disableentry - Disable entries in the Internet service database.
- fortinet.fortimanager.fmgr_application_internetservicecustom_disableentry_iprange - IP ranges in the disable entry.
- fortinet.fortimanager.fmgr_application_internetservicecustom_entry - Entries added to the Internet service database and custom database.
- fortinet.fortimanager.fmgr_application_internetservicecustom_entry_portrange - Port ranges in the custom entry.
- fortinet.fortimanager.fmgr_cloud_orchestaws - no description
- fortinet.fortimanager.fmgr_cloud_orchestawsconnector - no description
- fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscaleexistingvpc - no description
- fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscalenewvpc - no description
- fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscaletgwnewvpc - no description
- fortinet.fortimanager.fmgr_cloud_orchestration - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter_excludelist - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter_excludelist_fields - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter_freestyle - Free style filters.
- fortinet.fortimanager.fmgr_devprof_log_syslogd_setting_customfieldname - Custom field name for CEF format logging.
- fortinet.fortimanager.fmgr_dnsfilter_profile_urlfilter - URL filter settings.
- fortinet.fortimanager.fmgr_dnsfilter_urlfilter - Configure URL filter list.
- fortinet.fortimanager.fmgr_dnsfilter_urlfilter_entries - DNS URL filter.
- fortinet.fortimanager.fmgr_emailfilter_profile_yahoomail - Yahoo! Mail.
- fortinet.fortimanager.fmgr_extensioncontroller_dataplan - FortiExtender dataplan configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile - FortiExtender extender profile configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular - FortiExtender cellular configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_controllerreport - FortiExtender controller report configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem1 - Configuration options for modem 1.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem1_autoswitch - FortiExtender auto switch configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem2 - Configuration options for modem 2.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem2_autoswitch - FortiExtender auto switch configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_smsnotification - FortiExtender cellular SMS notification configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_smsnotification_alert - SMS alert list.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_smsnotification_receiver - SMS notification receiver list.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension - FortiExtender lan extension configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension_backhaul - LAN extension backhaul tunnel configuration.
- fortinet.fortimanager.fmgr_firewall_accessproxy6 - Configure IPv6 access proxy.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway - Set IPv4 API Gateway.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6 - Set IPv6 API Gateway.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6_realservers - Select the real servers that this Access Proxy will distribute traffic to.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6_sslciphersuites - SSL/TLS cipher suites to offer to a server, ordered by priority.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway_realservers - Select the real servers that this Access Proxy will distribute traffic to.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway_sslciphersuites - SSL/TLS cipher suites to offer to a server, ordered by priority.
- fortinet.fortimanager.fmgr_firewall_address6_profilelist - List of NSX service profiles that use this address.
- fortinet.fortimanager.fmgr_firewall_address_profilelist - List of NSX service profiles that use this address.
- fortinet.fortimanager.fmgr_firewall_explicitproxyaddress - Explicit web proxy address configuration.
- fortinet.fortimanager.fmgr_firewall_explicitproxyaddress_headergroup - HTTP header group.
- fortinet.fortimanager.fmgr_firewall_explicitproxyaddrgrp - Explicit web proxy address group configuration.
- fortinet.fortimanager.fmgr_firewall_gtp_messagefilter - Message filter.
- fortinet.fortimanager.fmgr_firewall_ippoolgrp - Configure IPv4 pool groups.
- fortinet.fortimanager.fmgr_firewall_networkservicedynamic - Configure Dynamic Network Services.
- fortinet.fortimanager.fmgr_fmg_fabric_authorization_template - no description
- fortinet.fortimanager.fmgr_fmg_fabric_authorization_template_platforms - no description
- fortinet.fortimanager.fmgr_fmupdate_fwmsetting_upgradetimeout - Configure the timeout value of image upgrade process.
- fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_vrrp - VRRP configuration.
- fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_vrrp_proxyarp - VRRP Proxy ARP configuration.
- fortinet.fortimanager.fmgr_fsp_vlan_interface_vrrp_proxyarp - VRRP Proxy ARP configuration.
- fortinet.fortimanager.fmgr_ips_baseline_sensor - Configure IPS sensor.
- fortinet.fortimanager.fmgr_ips_baseline_sensor_entries - IPS sensor filter.
- fortinet.fortimanager.fmgr_ips_baseline_sensor_entries_exemptip - Traffic from selected source or destination IP addresses is exempt from this signature.
- fortinet.fortimanager.fmgr_ips_baseline_sensor_filter - no description
- fortinet.fortimanager.fmgr_ips_baseline_sensor_override - no description
- fortinet.fortimanager.fmgr_ips_baseline_sensor_override_exemptip - no description
- fortinet.fortimanager.fmgr_log_npuserver - Configure all the log servers and create the server groups.
- fortinet.fortimanager.fmgr_log_npuserver_servergroup - create server group.
- fortinet.fortimanager.fmgr_log_npuserver_serverinfo - configure server info.
- fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy - Configure Explicit proxy policies.
- fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy_identitybasedpolicy - Identity-based policy.
- fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy_sectionvalue - Configure Explicit proxy policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy - Configure IPv4/IPv6 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy46 - Configure IPv4 to IPv6 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy6 - Configure IPv6 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy64 - Configure IPv6 to IPv4 policies.
- fortinet.fortimanager.fmgr_pkg_user_nacpolicy - Configure NAC policy matching pattern to identify matching NAC devices.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_consolidated_policy - Configure consolidated IPv4/IPv6 policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_consolidated_policy_sectionvalue - Configure consolidated IPv4/IPv6 policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_policy6 - Configure IPv6 policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_policy6_sectionvalue - Configure IPv6 policies.
- fortinet.fortimanager.fmgr_pm_devprof_scopemember - no description
- fortinet.fortimanager.fmgr_pm_pkg_scopemember - Policy package or folder.
- fortinet.fortimanager.fmgr_pm_wanprof_scopemember - no description
- fortinet.fortimanager.fmgr_securityconsole_template_cli_preview - no description
- fortinet.fortimanager.fmgr_switchcontroller_acl_group - Configure ACL groups to be applied on managed FortiSwitch ports.
- fortinet.fortimanager.fmgr_switchcontroller_acl_ingress - Configure ingress ACL policies to be applied on managed FortiSwitch ports.
- fortinet.fortimanager.fmgr_switchcontroller_acl_ingress_action - ACL actions.
- fortinet.fortimanager.fmgr_switchcontroller_acl_ingress_classifier - ACL classifiers.
- fortinet.fortimanager.fmgr_switchcontroller_dynamicportpolicy - Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
- fortinet.fortimanager.fmgr_switchcontroller_dynamicportpolicy_policy - Port policies with matching criteria and actions.
- fortinet.fortimanager.fmgr_switchcontroller_fortilinksettings - Configure integrated FortiLink settings for FortiSwitch.
- fortinet.fortimanager.fmgr_switchcontroller_fortilinksettings_nacports - NAC specific configuration.
- fortinet.fortimanager.fmgr_switchcontroller_macpolicy - Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_dhcpsnoopingstaticclient - Configure FortiSwitch DHCP snooping static clients.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_ports_dhcpsnoopoption82override - Configure DHCP snooping option 82 override.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_staticmac - Configuration method to edit FortiSwitch Static and Sticky MAC.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_stpinstance - Configuration method to edit Spanning Tree Protocol
- fortinet.fortimanager.fmgr_switchcontroller_switchinterfacetag - Configure switch object tags.
- fortinet.fortimanager.fmgr_switchcontroller_trafficpolicy - Configure FortiSwitch traffic policy.
- fortinet.fortimanager.fmgr_switchcontroller_vlanpolicy - Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy.
- fortinet.fortimanager.fmgr_sys_cloud_orchest - no description
- fortinet.fortimanager.fmgr_system_npu_backgroundssescan - Configure driver background scan for SSE.
- fortinet.fortimanager.fmgr_system_npu_dosoptions - NPU DoS configurations.
- fortinet.fortimanager.fmgr_system_npu_dswdtsprofile - Configure NPU DSW DTS profile.
- fortinet.fortimanager.fmgr_system_npu_dswqueuedtsprofile - Configure NPU DSW Queue DTS profile.
- fortinet.fortimanager.fmgr_system_npu_hpe - Host protection engine configuration.
- fortinet.fortimanager.fmgr_system_npu_ipreassembly - IP reassebmly engine configuration.
- fortinet.fortimanager.fmgr_system_npu_npqueues - Configure queue assignment on NP7.
- fortinet.fortimanager.fmgr_system_npu_npqueues_ethernettype - Configure a NP7 QoS Ethernet Type.
- fortinet.fortimanager.fmgr_system_npu_npqueues_ipprotocol - Configure a NP7 QoS IP Protocol.
- fortinet.fortimanager.fmgr_system_npu_npqueues_ipservice - Configure a NP7 QoS IP Service.
- fortinet.fortimanager.fmgr_system_npu_npqueues_profile - Configure a NP7 class profile.
- fortinet.fortimanager.fmgr_system_npu_npqueues_scheduler - Configure a NP7 QoS Scheduler.
- fortinet.fortimanager.fmgr_system_npu_portpathoption - Configure port using NPU or Intel-NIC.
- fortinet.fortimanager.fmgr_system_npu_ssehascan - Configure driver HA scan for SSE.
- fortinet.fortimanager.fmgr_system_npu_swtrhash - Configure switch traditional hashing.
- fortinet.fortimanager.fmgr_system_npu_tcptimeoutprofile - Configure TCP timeout profile.
- fortinet.fortimanager.fmgr_system_npu_udptimeoutprofile - Configure UDP timeout profile.
- fortinet.fortimanager.fmgr_system_objecttag - Configure object tags.
- fortinet.fortimanager.fmgr_system_sdnconnector_compartmentlist - Configure OCI compartment list.
- fortinet.fortimanager.fmgr_system_sdnconnector_ociregionlist - Configure OCI region list.
- fortinet.fortimanager.fmgr_system_socfabric_trustedlist - Pre-authorized security fabric nodes
- fortinet.fortimanager.fmgr_um_image_upgrade - The older API for updating the firmware of specific device.
- fortinet.fortimanager.fmgr_um_image_upgrade_ext - Update the firmware of specific device.
- fortinet.fortimanager.fmgr_user_certificate - Configure certificate users.
- fortinet.fortimanager.fmgr_user_deviceaccesslist - Configure device access control lists.
- fortinet.fortimanager.fmgr_user_deviceaccesslist_devicelist - Device list.
- fortinet.fortimanager.fmgr_user_flexvm - no description
- fortinet.fortimanager.fmgr_user_json - no description
- fortinet.fortimanager.fmgr_user_saml_dynamicmapping - SAML server entry configuration.
- fortinet.fortimanager.fmgr_vpnsslweb_portal_landingpage - Landing page options.
- fortinet.fortimanager.fmgr_vpnsslweb_portal_landingpage_formdata - Form data.
- fortinet.fortimanager.fmgr_vpnsslweb_virtualdesktopapplist - SSL-VPN virtual desktop application list.
- fortinet.fortimanager.fmgr_vpnsslweb_virtualdesktopapplist_apps - Applications.
- fortinet.fortimanager.fmgr_wireless_accesscontrollist - Configure WiFi bridge access control list.
- fortinet.fortimanager.fmgr_wireless_accesscontrollist_layer3ipv4rules - AP ACL layer3 ipv4 rule list.
- fortinet.fortimanager.fmgr_wireless_accesscontrollist_layer3ipv6rules - AP ACL layer3 ipv6 rule list.
- fortinet.fortimanager.fmgr_wireless_address - Configure the client with its MAC address.
- fortinet.fortimanager.fmgr_wireless_addrgrp - Configure the MAC address group.
- fortinet.fortimanager.fmgr_wireless_ssidpolicy - Configure WiFi SSID policies.
- fortinet.fortimanager.fmgr_wireless_syslogprofile - Configure Wireless Termination Points

v2.1.7
======

Release Summary
---------------

hotpath for backward-compatibility fix

Major Changes
-------------

- Fix compatibility issue for ansible 2.9.x and ansible-base 2.10.x.
- support Ansible changelogs.

v2.1.6
======

Release Summary
---------------

release fortinet.fortimanager to support FMG 7.2.x

Major Changes
-------------

- Many fixes for Ansible sanity test warnings & errors.
- Support FortiManager Schema 7.2.0 , 98 new modules

Minor Changes
-------------

- Best Practice Notes
