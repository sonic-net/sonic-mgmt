==============================
Check_Point.Mgmt Release Notes
==============================

.. contents:: Topics

v6.7.0
======

Release Summary
---------------

This is release 6.7.0 of ``check_point.mgmt``, released on 2025-11-11.

New Modules
-----------

- check_point.mgmt.cp_mgmt_best_practice_facts - Get best-practice objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_change_password_on_next_login - Change Check Point password on next login.
- check_point.mgmt.cp_mgmt_compliance_scan - Runs the Compliance Software Blade scan. The scan evaluates the configuration compliance with the relevant best practices.
- check_point.mgmt.cp_mgmt_logical_server - Manages logical-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_logical_server_facts - Get logical-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_renew_scaled_sharing_server_certificate - Renew the server certificate for the scaled sharing on the specified PDP Security Gateway or Cluster.
- check_point.mgmt.cp_mgmt_set_compliance_settings - Edit existing Compliance Settings.
- check_point.mgmt.cp_mgmt_set_cp_password_requirements - Set Check Point password requirements.
- check_point.mgmt.cp_mgmt_set_default_administrator_settings - Set default administrator settings.
- check_point.mgmt.cp_mgmt_set_login_restrictions - Set login restrictions.
- check_point.mgmt.cp_mgmt_set_smart_console_idle_timeout - Set SmartConsole idle timeout settings.
- check_point.mgmt.cp_mgmt_set_trust - Configure a Trusted communication between the Management Server and the managed Security Gateway.
- check_point.mgmt.cp_mgmt_show_compliance_settings - Retrieve all Compliance Settings.
- check_point.mgmt.cp_mgmt_show_cp_password_requirements - Retrieve existing Check Point password requirements.
- check_point.mgmt.cp_mgmt_show_default_administrator_settings - Retrieve existing default administrator settings.
- check_point.mgmt.cp_mgmt_show_login_restrictions - Retrieve existing login restrictions.
- check_point.mgmt.cp_mgmt_show_smart_console_idle_timeout - Retrieve existing SmartConsole idle timeout settings.
- check_point.mgmt.cp_mgmt_subordinate_ca - Manages subordinate-ca objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_subordinate_ca_facts - Get subordinate-ca objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_test_trust - Test an existing Trusted communication between the Management Server and the managed Security Gateway.
- check_point.mgmt.cp_mgmt_voip_domain_h323_gatekeeper - Manages voip-domain-h323-gatekeeper objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_h323_gatekeeper_facts - Get voip-domain-h323-gatekeeper objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_h323_gateway - Manages voip-domain-h323-gateway objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_h323_gateway_facts - Get voip-domain-h323-gateway objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_mgcp_call_agent - Manages voip-domain-mgcp-call-agent objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_mgcp_call_agent_facts - Get voip-domain-mgcp-call-agent objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_sccp_call_manager - Manages voip-domain-sccp-call-manager objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_sccp_call_manager_facts - Get voip-domain-sccp-call-manager objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_sip_proxy - Manages voip-domain-sip-proxy objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_voip_domain_sip_proxy_facts - Get voip-domain-sip-proxy objects facts on Checkpoint over Web Services API

v6.6.0
======

Release Summary
---------------

This is release 6.6.0 of ``check_point.mgmt``, released on 2025-10-30.

Minor Changes
-------------

- Support check mode (--check)
- check_point.mgmt.cp_mgmt_access_rule_facts - support async-response with customized HF.

v6.5.0
======

Release Summary
---------------

This is release 6.5.0 of "check_point.mgmt", released on 2025-09-04.

Minor Changes
-------------

- added new parameter 'ips_settings' to 'cp_mgmt_simple_cluster' and 'cp_mgmt_simple_gateway' modules.
- added new parameter 'override_vpn_domains' to 'cp_mgmt_set_vpn_community_remote_access' module.
- added new parameter 'show_installation_targets' to 'cp_mgmt_package_facts' module.
- added new parameters (such as 'permanent_tunnels', excluded_services, etc.) to 'cp_mgmt_vpn_community_meshed' and 'cp_mgmt_vpn_community_star' modules.

New Modules
-----------

- check_point.mgmt.cp_mgmt_identity_provider - Manages identity-provider objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_identity_provider_facts - Get identity-provider objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_if_map_server - Manages if-map-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_if_map_server_facts - Get if-map-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_ldap_group - Manages ldap-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_ldap_group_facts - Get ldap-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_log_exporter - Manages log-exporter objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_log_exporter_facts - Get log-exporter objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_mms - Manages resource-mms objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_mms_facts - Get resource-mms objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_tcp - Manages resource-tcp objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_tcp_facts - Get resource-tcp objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_uri_for_qos - Manages resource-uri-for-qos objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_uri_for_qos_facts - Get resource-uri-for-qos objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_run_app_control_update - Runs Application Control & URL Filtering database update.
- check_point.mgmt.cp_mgmt_securemote_dns_server - Manages securemote-dns-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_securemote_dns_server_facts - Get securemote-dns-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_securid_server - Manages securid-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_securid_server_facts - Get securid-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_set_anti_malware_update_schedule - Set both Anti-Bot and Anti-Virus update schedules.
- check_point.mgmt.cp_mgmt_set_app_control_update_schedule - Set the Application Control and URL Filtering update schedule.
- check_point.mgmt.cp_mgmt_show_anti_malware_update_schedule - Retrieve existing Anti-Bot and Anti-Virus update schedules.
- check_point.mgmt.cp_mgmt_show_app_control_status - Get app-control-status objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_show_app_control_update_schedule - Get app-control-status objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_syslog_server - Manages syslog-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_syslog_server_facts - Get syslog-server objects facts on Checkpoint over Web Services API

v6.4.1
======

Release Summary
---------------

This is release 6.4.1 of "check_point.mgmt", released on 2025-06-03.

Bugfixes
--------

- Added required management version to the documentation for all collection modules.
- module_utils/checkpoint – Prevent redundant logout call when there is no authentication header 'X-chkp-sid'.

v6.4.0
======

Release Summary
---------------

This is release 6.4.0 of "check_point.mgmt", released on 2025-02-20.

Minor Changes
-------------

- added missing parameters such as 'filter', 'domains_to_process' and 'async_response' to the relevant resources modules.

New Modules
-----------

- check_point.mgmt.cp_mgmt_user_template - Manages user-template objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_user_template_facts - Get user-template objects facts on Checkpoint over Web Services API

v6.3.0
======

Release Summary
---------------

This is release 6.3.0 of ``check_point.mgmt``, released on 2025-01-23.

Minor Changes
-------------

- check_point.mgmt.cp_mgmt_lsm_cluster - support additional parameters (dynamic-objects, tags and topology)
- check_point.mgmt.cp_mgmt_lsm_gateway - support additional parameters (device_id, dynamic-objects, tags and topology)

New Modules
-----------

- check_point.mgmt.cp_mgmt_user - Manages user objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_user_facts - Get user objects facts on Checkpoint over Web Services API

v6.2.1
======

Release Summary
---------------

This is release 6.2.1 of ``check_point.mgmt``, released on 2024-08-28.


v6.2.0
======

Release Summary
---------------

This is release 6.2.0 of ``check_point.mgmt``, released on 2024-08-27.

New Modules
-----------

- check_point.mgmt.cp_mgmt_interface - Manages interface objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_interface_facts - Get interface objects facts on Checkpoint over Web Services API

v6.1.1
======

Release Summary
---------------

This is release 6.1.1 of ``check_point.mgmt``, released on 2024-08-12.

Bugfixes
--------

- module_utils/checkpoint - Remove usage of CertificateError causing failures in ansible-core 2.17.

v6.1.0
======

Release Summary
---------------

This is release 6.1.0 of ``check_point.mgmt``, released on 2024-07-08.

New Modules
-----------

- check_point.mgmt.cp_mgmt_set_https_advanced_settings - Configure advanced settings for HTTPS Inspection.
- check_point.mgmt.cp_mgmt_show_https_advanced_settings - Show advanced settings for HTTPS Inspection.

v6.0.0
======

Release Summary
---------------

This is release 6.0.0 of ``check_point.mgmt``, released on 2024-06-16.

Major Changes
-------------

- New R82 Resource Modules
- Support relative positioning for sections

New Modules
-----------

- check_point.mgmt.cp_mgmt_add_custom_trusted_ca_certificate - Create new custom trusted CA certificate.
- check_point.mgmt.cp_mgmt_add_outbound_inspection_certificate - Add outbound-inspection-certificate
- check_point.mgmt.cp_mgmt_cp_trusted_ca_certificate_facts - Retrieve existing Check Point trusted CA certificate objects facts on Checkpoint devices.
- check_point.mgmt.cp_mgmt_custom_trusted_ca_certificate_facts - Retrieve existing custom trusted CA certificate objects facts on Checkpoint devices.
- check_point.mgmt.cp_mgmt_data_type_compound_group - Manages data-type-compound-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_compound_group_facts - Get data-type-compound-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_file_attributes - Manages data-type-file-attributes objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_file_attributes_facts - Get data-type-file-attributes objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_file_group_facts - Get data-type-file-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_group - Manages data-type-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_group_facts - Get data-type-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_keywords - Manages data-type-keywords objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_keywords_facts - Get data-type-keywords objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_patterns - Manages data-type-patterns objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_patterns_facts - Get data-type-patterns objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_traditional_group - Manages data-type-traditional-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_traditional_group_facts - Get data-type-traditional-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_weighted_keywords - Manages data-type-weighted-keywords objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_data_type_weighted_keywords_facts - Get data-type-weighted-keywords objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_delete_custom_trusted_ca_certificate - Delete existing custom trusted CA certificate using name or uid.
- check_point.mgmt.cp_mgmt_delete_infinity_idp - Delete Infinity Identity Provider from the Infinity Portal using object name or uid.
- check_point.mgmt.cp_mgmt_delete_infinity_idp_object - Delete users/groups/machines from the Identity Provider using object name or uid.
- check_point.mgmt.cp_mgmt_delete_outbound_inspection_certificate - Delete outbound-inspection-certificate
- check_point.mgmt.cp_mgmt_external_trusted_ca - Manages external-trusted-ca objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_external_trusted_ca_facts - Get external-trusted-ca objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_https_rule - Manages https-rule objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_https_rule_facts - Get https-rule objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_import_outbound_inspection_certificate - Import Outbound Inspection certificate for HTTPS inspection.
- check_point.mgmt.cp_mgmt_infinity_idp_facts - Get Infinity Identity Provider objects facts from the Infinity Portal.
- check_point.mgmt.cp_mgmt_infinity_idp_object_facts - Retrieve users/groups/machines objects facts from the Identity Provider.
- check_point.mgmt.cp_mgmt_limit - Manages limit objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_limit_facts - Get limit objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_access_profile_rule - Manages mobile-access-profile-rule objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_access_profile_rule_facts - Get mobile-access-profile-rule objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_access_profile_section - Manages mobile-access-profile-section objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_access_rule - Manages mobile-access-rule objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_access_rule_facts - Get mobile-access-rule objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_access_section - Manages mobile-access-section objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_profile - Manages mobile-profile objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_mobile_profile_facts - Get mobile-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_multiple_key_exchanges - Manages multiple-key-exchanges objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_multiple_key_exchanges_facts - Get multiple-key-exchanges objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_network_probe - Manages network-probe objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_network_probe_facts - Get network-probe objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_opsec_trusted_ca - Manages opsec-trusted-ca objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_opsec_trusted_ca_facts - Get opsec-trusted-ca objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_outbound_inspection_certificate_facts - Get outbound-inspection-certificate objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_override_categorization - Manages override-categorization objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_override_categorization_facts - Get override-categorization objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_passcode_profile - Manages passcode-profile objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_passcode_profile_facts - Get passcode-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_cifs - Manages resource-cifs objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_cifs_facts - Get resource-cifs objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_ftp - Manages resource-ftp objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_ftp_facts - Get resource-ftp objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_smtp - Manages resource-smtp objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_smtp_facts - Get resource-smtp objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_uri - Manages resource-uri objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_resource_uri_facts - Get resource-uri objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_set_app_control_advanced_settings - Edit Application Control & URL Filtering Blades' Settings.
- check_point.mgmt.cp_mgmt_set_content_awareness_advanced_settings - Edit Content Awareness Blades' Settings.
- check_point.mgmt.cp_mgmt_set_cp_trusted_ca_certificate - Edit existing Check Point trusted CA certificate using name or uid.
- check_point.mgmt.cp_mgmt_set_gateway_global_use - Enable or disable global usage on a specific target.
- check_point.mgmt.cp_mgmt_set_internal_trusted_ca - Edit existing Internal CA object.
- check_point.mgmt.cp_mgmt_set_outbound_inspection_certificate - Edit outbound-inspection-certificate
- check_point.mgmt.cp_mgmt_show_app_control_advanced_settings - Show Application Control & URL Filtering Blades' Settings.
- check_point.mgmt.cp_mgmt_show_content_awareness_advanced_settings - Show Content Awareness Blades' Settings.
- check_point.mgmt.cp_mgmt_show_gateway_capabilities - Show supported Check Point Gateway capabilities such as versions, hardwares, platforms and blades.
- check_point.mgmt.cp_mgmt_show_gateway_global_use - Show global usage of a specific target.
- check_point.mgmt.cp_mgmt_show_internal_trusted_ca - Retrieve existing Internal CA object.
- check_point.mgmt.cp_mgmt_show_last_published_session - Shows the last published session.
- check_point.mgmt.cp_mgmt_show_mobile_access_profile_section - Retrieve existing Mobile Access Profile section using section name or uid.
- check_point.mgmt.cp_mgmt_show_mobile_access_section - Retrieve existing Mobile Access section using section name or uid.
- check_point.mgmt.cp_mgmt_verify_management_license - Check how many Security Gateway objects the Management Server license supports.
- check_point.mgmt.cp_mgmt_vsx_provisioning_tool - Run the VSX provisioning tool with the specified parameters.

v5.2.3
======

Release Summary
---------------

This is release 5.2.3 of ``check_point.mgmt``, released on 2024-03-04.

v5.2.2
======

Release Summary
---------------

This is release 5.2.2 of ``check_point.mgmt``, released on 2024-01-28.

v5.2.1
======

Release Summary
---------------

This is release 5.2.1 of ``check_point.mgmt``, released on 2024-01-16

v5.2.0
======

Release Summary
---------------

This is release 5.2.0 of ``check_point.mgmt``, released on 2024-01-10.

Minor Changes
-------------

- New resource modules for R81.20 JHF Take 43

New Modules
-----------

- check_point.mgmt.cp_mgmt_add_central_license - Add central license.
- check_point.mgmt.cp_mgmt_central_license_facts - Get central-license objects facts on Checkpoint over Web Services API.
- check_point.mgmt.cp_mgmt_delete_central_license - Delete central license.
- check_point.mgmt.cp_mgmt_distribute_cloud_licenses - Distribute licenses to target CloudGuard gateways.
- check_point.mgmt.cp_mgmt_show_cloud_licenses_usage - Show attached licenses usage.
- check_point.mgmt.cp_mgmt_show_ha_status - Retrieve domain high availability status.

v5.1.3
======

Release Summary
---------------

This is release 5.1.3 of ``check_point.mgmt``, released on 2023-12-13.

Bugfixes
--------

- httpapi/checkpoint.py - Raise a fatal error if login wasn't successful.

v5.1.2
======

Release Summary
---------------

This is release 5.1.2 of ``check_point.mgmt``, released on 2023-12-12.

Minor Changes
-------------

- meta/runtime.yml - update minimum Ansible version required to 2.14.0.

v5.1.1
======

Release Summary
---------------

This is release 5.1.1 of ``check_point.mgmt``, released on 2023-05-25.

Bugfixes
--------

- module_utils/checkpoint.py - fixed compile issue (Syntax Error) on python 2.7

v5.1.0
======

Release Summary
---------------

This is release 5.1.0 of ``check_point.mgmt``, released on 2023-05-18.

Minor Changes
-------------

- cp_mgmt_vpn_community_star - new fields added.
- show command modules  - no longer return result of changed=True.

Bugfixes
--------

- cp_mgmt_access_rules - split vpn param that can accept either a String or list of objects to two

v5.0.0
======

Release Summary
---------------

This is release 5.0.0 of ``check_point.mgmt``, released on 2023-04-17.

Deprecated Features
-------------------

- add/set/delete nat-rule modules - will be replaced by the single cp_mgmt_nat_rule module.
- cp_mgmt_show_task/s modules - will be replaced by the by the single cp_mgmt_task_facts module.

New Modules
-----------

- check_point.mgmt.cp_mgmt_abort_get_interfaces - Attempt to abort an on-going "get-interfaces" operation.
- check_point.mgmt.cp_mgmt_access_layers - Manages ACCESS LAYERS resource module
- check_point.mgmt.cp_mgmt_access_point_name - Manages access-point-name objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_access_point_name_facts - Get access-point-name objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_add_repository_package - Add the software package to the central repository.
- check_point.mgmt.cp_mgmt_add_updatable_object - Import an updatable object from the repository to the management server.
- check_point.mgmt.cp_mgmt_checkpoint_host - Manages checkpoint-host objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_checkpoint_host_facts - Get checkpoint-host objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_delete_repository_package - Delete the repository software package from the central repository.
- check_point.mgmt.cp_mgmt_delete_updatable_object - Delete existing object using object name or uid.
- check_point.mgmt.cp_mgmt_dynamic_global_network_object - Manages dynamic-global-network-object objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_dynamic_global_network_object_facts - Get dynamic-global-network-object objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_export_management - Export the primary Security Management Server database or the primary Multi-Domain Server database or the single Domain database and the applicable Check Point configuration.
- check_point.mgmt.cp_mgmt_export_smart_task - Export SmartTask to a file.
- check_point.mgmt.cp_mgmt_get_attachment - Retrieves a packet capture or blob data, according to the attributes of a log record.
- check_point.mgmt.cp_mgmt_get_interfaces - Get physical interfaces with or without their topology from a Gaia Security Gateway or Cluster.
- check_point.mgmt.cp_mgmt_gsn_handover_group - Manages gsn-handover-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_gsn_handover_group_facts - Get gsn-handover-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_ha_full_sync - Perform full sync from active server to standby peer.
- check_point.mgmt.cp_mgmt_hosts - Manages HOSTS resource module
- check_point.mgmt.cp_mgmt_https_layer - Manages https-layer objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_https_layer_facts - Get https-layer objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_import_management - Import the primary Security Management Server database or the primary Multi-Domain Server database or the single Domain database and the applicable Check Point configuration.
- check_point.mgmt.cp_mgmt_import_smart_task - Import SmartTask from a file.
- check_point.mgmt.cp_mgmt_ips_protection_extended_attribute_facts - Get ips-protection-extended-attribute objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lock_object - Lock object using uid or {name and type}.
- check_point.mgmt.cp_mgmt_lsv_profile - Manages lsv-profile objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsv_profile_facts - Get lsv-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_nat_rule - Manages nat-rule objects on Checkpoint over Web Services API.
- check_point.mgmt.cp_mgmt_radius_group - Manages radius-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_radius_group_facts - Get radius-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_radius_server - Manages radius-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_radius_server_facts - Get radius-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_repository_package_facts - Get repository-package objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_service_citrix_tcp - Manages service-citrix-tcp objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_service_citrix_tcp_facts - Get service-citrix-tcp objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_service_compound_tcp - Manages service-compound-tcp objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_service_compound_tcp_facts - Get service-compound-tcp objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_set_api_settings - Edit API settings, the changes will be applied after publish followed by running 'api restart' command.
- check_point.mgmt.cp_mgmt_set_cloud_services - Set the connection settings between the Management Server and Check Point's Infinity Portal.
- check_point.mgmt.cp_mgmt_set_global_domain - Edit Global domain object using domain name or UID.
- check_point.mgmt.cp_mgmt_set_ha_state - Switch domain server high availability state.
- check_point.mgmt.cp_mgmt_set_ips_update_schedule - Edit IPS Update Schedule.
- check_point.mgmt.cp_mgmt_set_login_message - Edit Login message.
- check_point.mgmt.cp_mgmt_set_policy_settings - Edit Policy settings, the changes will be applied after publish.
- check_point.mgmt.cp_mgmt_set_vpn_community_remote_access - Edit existing Remote Access object. Using object name or uid is optional.
- check_point.mgmt.cp_mgmt_show_api_settings - Retrieve API Settings.
- check_point.mgmt.cp_mgmt_show_api_versions - Shows all supported API versions and current API version (the latest one).
- check_point.mgmt.cp_mgmt_show_azure_ad_content - Retrieve AzureAD Objects from Azure AD Server.
- check_point.mgmt.cp_mgmt_show_changes - Show changes between two sessions.
- check_point.mgmt.cp_mgmt_show_commands - Retrieve all of the supported Management API commands with their description.
- check_point.mgmt.cp_mgmt_show_gateways_and_servers - Shows list of Gateways & Servers sorted by name.
- check_point.mgmt.cp_mgmt_show_global_domain - Retrieve existing object using object name or uid.
- check_point.mgmt.cp_mgmt_show_ha_state - Retrieve domain high availability state.
- check_point.mgmt.cp_mgmt_show_ips_status - show ips status on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_show_ips_update_schedule - Retrieve IPS Update Schedule.
- check_point.mgmt.cp_mgmt_show_layer_structure - Shows the entire layer structure.
- check_point.mgmt.cp_mgmt_show_login_message - Retrieve Login message.
- check_point.mgmt.cp_mgmt_show_place_holder - Retrieve existing object using object uid.
- check_point.mgmt.cp_mgmt_show_policy_settings - Show Policy settings.
- check_point.mgmt.cp_mgmt_show_software_packages_per_targets - Shows software packages on targets.
- check_point.mgmt.cp_mgmt_show_unused_objects - Retrieve all unused objects.
- check_point.mgmt.cp_mgmt_show_updatable_objects_repository_content - Shows the content of the available updatable objects from the Check Point User Center.
- check_point.mgmt.cp_mgmt_show_validations - Show all validation incidents limited to 500.
- check_point.mgmt.cp_mgmt_smart_task - Manages smart-task objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_smart_task_facts - Get smart-task objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_smart_task_trigger_facts - Get smart-task-trigger objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_tacacs_group - Manages tacacs-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_tacacs_group_facts - Get tacacs-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_tacacs_server - Manages tacacs-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_tacacs_server_facts - Get tacacs-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_task_facts - Get task objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_threat_layers - Manages THREAT LAYERS resource module
- check_point.mgmt.cp_mgmt_time_group - Manages time-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_time_group_facts - Get time-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_unlock_administrator - Unlock administrator.
- check_point.mgmt.cp_mgmt_unlock_object - Unlock object using uid or {name and type}.
- check_point.mgmt.cp_mgmt_updatable_object_facts - Get updatable-object objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_update_updatable_objects_repository_content - Updates the content of the Updatable Objects repository from the Check Point User Center.
- check_point.mgmt.cp_mgmt_user_group - Manages user-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_user_group_facts - Get user-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_vpn_community_remote_access_facts - Get vpn-community-remote-access objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_vsx_run_operation - Run the VSX operation by its name and parameters.
- check_point.mgmt.cp_mgmt_where_used - Searches for usage of the target object in other objects and rules.

v4.0.0
======

Release Summary
---------------

This is release 4.0.0 of ``check_point.mgmt``, released on 2022-09-14.

Major Changes
-------------

- plugins/httpapi/checkpoint - Support for Smart-1 Cloud with new variable 'ansible_cloud_mgmt_id'

Breaking Changes / Porting Guide
--------------------------------

- cp_mgmt_access_role - the 'machines' parameter now accepts a single str and a new parameter 'machines_list' of type dict has been added. the 'users' parameter now accepts a single str and a new parameter 'users_list' of type dict has been added.
- cp_mgmt_access_rule - the 'vpn' parameter now accepts a single str and a new parameter 'vpn_list' of type dict has been added. the 'position_by_rule' parameter has been changed to 'relative_position' with support of positioning above/below a section (and not just a rule). the 'relative_position' parameter has also 'top' and 'bottom' suboptions which allows positioning a rule at the top and bottom of a section respectively. a new parameter 'search_entire_rulebase' has been added to allow the relative positioning to be unlimited (was previously limited to 50 rules)
- cp_mgmt_administrator - the 'permissions_profile' parameter now accepts a single str and a new parameter 'permissions_profile_list' of type dict has been added.
- cp_mgmt_publish - the 'uid' parameter has been removed.

Bugfixes
--------

- cp_mgmt_access_rule - support for relative positioning for rulebase with more than 50 rules (https://github.com/CheckPointSW/CheckPointAnsibleMgmtCollection/issues/69)
- cp_mgmt_administrator - specifying the administartor's permissions profile now works for both SMC and MDS (https://github.com/CheckPointSW/CheckPointAnsibleMgmtCollection/issues/83)
- meta/runtime.yml - update value of minimum ansible version and remove redirect (https://github.com/CheckPointSW/CheckPointAnsibleMgmtCollection/issues/84)

v3.2.0
======

Release Summary
---------------

This is release 3.2.0 of ``check_point.mgmt``, released on 2022-08-09.

v3.1.0
======

Release Summary
---------------

This is release 3.1.0 of ``check_point.mgmt``, released on 2022-07-04.

v3.0.0
======

Release Summary
---------------

This is release 3.0.0 of ``check_point.mgmt``, released on 2022-06-07.

New Modules
-----------

- check_point.mgmt.cp_mgmt_add_rules_batch - Creates new rules in batch. Use this API to achieve optimum performance when adding more than one rule.
- check_point.mgmt.cp_mgmt_approve_session - Workflow feature - Approve and Publish the session.
- check_point.mgmt.cp_mgmt_check_network_feed - Check if a target can reach or parse a network feed; can work with an existing feed object or with a new one (by providing all relevant feed parameters).
- check_point.mgmt.cp_mgmt_check_threat_ioc_feed - Check if a target can reach or parse a threat IOC feed; can work with an existing feed object or with a new one (by providing all relevant feed parameters).
- check_point.mgmt.cp_mgmt_cluster_members_facts - Retrieve all existing cluster members in domain.
- check_point.mgmt.cp_mgmt_connect_cloud_services - Securely connect the Management Server to Check Point's Infinity Portal. <br>This is a preliminary operation so that the management server can use various Check Point cloud-based security services hosted in the Infinity Portal.
- check_point.mgmt.cp_mgmt_delete_rules_batch - Delete rules in batch from the same layer. Use this API to achieve optimum performance when removing more than one rule.
- check_point.mgmt.cp_mgmt_disconnect_cloud_services - Disconnect the Management Server from Check Point's Infinity Portal.
- check_point.mgmt.cp_mgmt_domain_permissions_profile - Manages domain-permissions-profile objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_domain_permissions_profile_facts - Get domain-permissions-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_get_platform - Get actual platform (Hardware, Version, OS) from gateway, cluster or Check Point host.
- check_point.mgmt.cp_mgmt_idp_administrator_group - Manages idp-administrator-group objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_idp_administrator_group_facts - Get idp-administrator-group objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_idp_to_domain_assignment_facts - Get idp-to-domain-assignment objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_install_lsm_policy - Executes the lsm-install-policy on a given list of targets. Install the LSM policy that defined on the attached LSM profile on the targets devices.
- check_point.mgmt.cp_mgmt_install_lsm_settings - Executes the lsm-install-settings on a given list of targets. Install the provisioning settings that defined on the object on the targets devices.
- check_point.mgmt.cp_mgmt_interoperable_device - Manages interoperable-device objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_interoperable_device_facts - Get interoperable-device objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsm_cluster_profile_facts - Get lsm-cluster-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsm_gateway_profile_facts - Get lsm-gateway-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsm_run_script - Executes the lsm-run-script on a given list of targets. Run the given script on the targets devices.
- check_point.mgmt.cp_mgmt_md_permissions_profile - Manages md-permissions-profile objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_md_permissions_profile_facts - Get md-permissions-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_network_feed - Manages network-feed objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_network_feed_facts - Get network-feed objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_objects_facts - Get objects objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_provisioning_profile_facts - Get provisioning-profile objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_reject_session - Workflow feature - Return the session to the submitter administrator.
- check_point.mgmt.cp_mgmt_repository_script - Manages repository-script objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_repository_script_facts - Get repository-script objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_reset_sic - Reset Secure Internal Communication (SIC). To complete the reset operation need also to reset the device in the Check Point Configuration Tool (by running cpconfig in Clish or Expert mode). Communication will not be possible until you reset and re-initialize the device properly.
- check_point.mgmt.cp_mgmt_set_global_properties - Edit Global Properties.
- check_point.mgmt.cp_mgmt_set_idp_default_assignment - Set default Identity Provider assignment to be use for Management server administrator access.
- check_point.mgmt.cp_mgmt_set_idp_to_domain_assignment - Set Identity Provider assignment to domain, to allow administrator login to that domain using that identity provider, if there is no Identity Provider assigned to the domain the 'idp-default-assignment' will be used. This command only available  for Multi-Domain server.
- check_point.mgmt.cp_mgmt_set_threat_advanced_settings - Edit Threat Prevention's Blades' Settings.
- check_point.mgmt.cp_mgmt_show_cloud_services - Show the connection status of the Management Server to Check Point's Infinity Portal.
- check_point.mgmt.cp_mgmt_show_global_properties - Retrieve Global Properties.
- check_point.mgmt.cp_mgmt_show_idp_default_assignment - Retrieve default Identity Provider assignment that used for Management server administrator access.
- check_point.mgmt.cp_mgmt_show_servers_and_processes - Shows the status of all processes in the current machine (Multi-Domain Server and all Domain Management / Log Servers). <br>This command is available only on Multi-Domain Server.
- check_point.mgmt.cp_mgmt_show_threat_advanced_settings - Show Threat Prevention's Blades' Settings.
- check_point.mgmt.cp_mgmt_simple_cluster - Manages simple-cluster objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_simple_cluster_facts - Get simple-cluster objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_smtp_server - Manages smtp-server objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_smtp_server_facts - Get smtp-server objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_submit_session - Workflow feature - Submit the session for approval.
- check_point.mgmt.cp_mgmt_test_sic_status - Test SIC Status reflects the state of the gateway after it has received the certificate issued by the ICA. If the SIC status is Unknown then there is no connection between the gateway and the Security Management Server. If the SIC status is No Communication, an error message will appear. It may contain specific instructions on how to fix the situation.
- check_point.mgmt.cp_mgmt_update_provisioned_satellites - Executes the update-provisioned-satellites on center gateways of VPN communities.

v2.3.0
======

New Modules
-----------

- check_point.mgmt.cp_mgmt_lsm_cluster - Manages lsm-cluster objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsm_cluster_facts - Get lsm-cluster objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsm_gateway - Manages lsm-gateway objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_lsm_gateway_facts - Get lsm-gateway objects facts on Checkpoint over Web Services API

v2.2.0
======

New Modules
-----------

- check_point.mgmt.cp_mgmt_access_rules - Manages access-rules objects on Check Point over Web Services API

v2.1.0
======

New Modules
-----------

- check_point.mgmt.cp_mgmt_add_domain - Create new object
- check_point.mgmt.cp_mgmt_delete_domain - Delete existing object using object name or uid.
- check_point.mgmt.cp_mgmt_domain_facts - Get domain objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_identity_tag - Manages identity-tag objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_identity_tag_facts - Get identity-tag objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_install_database - Copies the user database and network objects information to specified targets.
- check_point.mgmt.cp_mgmt_mds - Manages mds objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_set_domain - Edit existing object using object name or uid.
- check_point.mgmt.cp_mgmt_trusted_client - Manages trusted-client objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_trusted_client_facts - Get trusted-client objects facts on Checkpoint over Web Services API

v2.0.0
======

New Modules
-----------

- check_point.mgmt.cp_mgmt_access_section - Manages access-section objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_add_api_key - Add API key for administrator, to enable login with it. For the key to be valid publish is needed.
- check_point.mgmt.cp_mgmt_add_data_center_object - Imports a Data Center Object from a Data Center Server.<br> Data Center Object represents an object in the cloud environment.
- check_point.mgmt.cp_mgmt_add_nat_rule - Create new object.
- check_point.mgmt.cp_mgmt_data_center_object_facts - Get data-center-object objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_delete_api_key - Delete the API key. For the key to be invalid publish is needed.
- check_point.mgmt.cp_mgmt_delete_data_center_object - Delete existing object using object name or uid.
- check_point.mgmt.cp_mgmt_delete_nat_rule - Delete existing object using object name or uid.
- check_point.mgmt.cp_mgmt_https_section - Manages https-section objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_install_software_package - Installs the software package on target machines.
- check_point.mgmt.cp_mgmt_nat_rule_facts - Get nat-rule objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_nat_section - Manages nat-section objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_set_nat_rule - Edit existing object using object name or uid.
- check_point.mgmt.cp_mgmt_set_session - Edit user's current session.
- check_point.mgmt.cp_mgmt_show_access_section - Retrieve existing object using object name or uid.
- check_point.mgmt.cp_mgmt_show_https_section - Retrieve existing HTTPS Inspection section using section name or uid and layer name.
- check_point.mgmt.cp_mgmt_show_logs - Showing logs according to the given filter.
- check_point.mgmt.cp_mgmt_show_nat_section - Retrieve existing object using object name or uid.
- check_point.mgmt.cp_mgmt_show_software_package_details - Gets the software package information from the cloud.
- check_point.mgmt.cp_mgmt_show_task - Show task progress and details.
- check_point.mgmt.cp_mgmt_show_tasks - Retrieve all tasks and show their progress and details.
- check_point.mgmt.cp_mgmt_uninstall_software_package - Uninstalls the software package from target machines.
- check_point.mgmt.cp_mgmt_verify_software_package - Verifies the software package on target machines.

v1.0.0
======

New Modules
-----------

- check_point.mgmt.cp_mgmt_access_layer - Manages access-layer objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_access_layer_facts - Get access-layer objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_access_role - Manages access-role objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_access_role_facts - Get access-role objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_access_rule - Manages access-rule objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_access_rule_facts - Get access-rule objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_address_range - Manages address-range objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_address_range_facts - Get address-range objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_administrator - Manages administrator objects on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_administrator_facts - Get administrator objects facts on Checkpoint over Web Services API
- check_point.mgmt.cp_mgmt_application_site - Manages application-site objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_application_site_category - Manages application-site-category objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_application_site_category_facts - Get application-site-category objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_application_site_facts - Get application-site objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_application_site_group - Manages application-site-group objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_application_site_group_facts - Get application-site-group objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_assign_global_assignment - assign global assignment on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_discard - All changes done by user are discarded and removed from database.
- check_point.mgmt.cp_mgmt_dns_domain - Manages dns-domain objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_dns_domain_facts - Get dns-domain objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_dynamic_object - Manages dynamic-object objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_dynamic_object_facts - Get dynamic-object objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_exception_group - Manages exception-group objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_exception_group_facts - Get exception-group objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_global_assignment - Manages global-assignment objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_global_assignment_facts - Get global-assignment objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_group - Manages group objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_group_facts - Get group objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_group_with_exclusion - Manages group-with-exclusion objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_group_with_exclusion_facts - Get group-with-exclusion objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_host - Manages host objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_host_facts - Get host objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_install_policy - install policy on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_mds_facts - Get Multi-Domain Server (mds) objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_multicast_address_range - Manages multicast-address-range objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_multicast_address_range_facts - Get multicast-address-range objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_network - Manages network objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_network_facts - Get network objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_package - Manages package objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_package_facts - Get package objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_publish - All the changes done by this user will be seen by all users only after publish is called.
- check_point.mgmt.cp_mgmt_put_file - put file on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_run_ips_update - Runs IPS database update. If "package-path" is not provided server will try to get the latest package from the User Center.
- check_point.mgmt.cp_mgmt_run_script - Executes the script on a given list of targets.
- check_point.mgmt.cp_mgmt_security_zone - Manages security-zone objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_security_zone_facts - Get security-zone objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_dce_rpc - Manages service-dce-rpc objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_dce_rpc_facts - Get service-dce-rpc objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_group - Manages service-group objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_group_facts - Get service-group objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_icmp - Manages service-icmp objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_icmp6 - Manages service-icmp6 objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_icmp6_facts - Get service-icmp6 objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_icmp_facts - Get service-icmp objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_other - Manages service-other objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_other_facts - Get service-other objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_rpc - Manages service-rpc objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_rpc_facts - Get service-rpc objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_sctp - Manages service-sctp objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_sctp_facts - Get service-sctp objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_tcp - Manages service-tcp objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_tcp_facts - Get service-tcp objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_udp - Manages service-udp objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_service_udp_facts - Get service-udp objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_session_facts - Get session objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_simple_gateway - Manages simple-gateway objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_simple_gateway_facts - Get simple-gateway objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_tag - Manages tag objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_tag_facts - Get tag objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_exception - Manages threat-exception objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_exception_facts - Get threat-exception objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_indicator - Manages threat-indicator objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_indicator_facts - Get threat-indicator objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_layer - Manages threat-layer objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_layer_facts - Get threat-layer objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_profile - Manages threat-profile objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_profile_facts - Get threat-profile objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_protection_override - Edit existing object using object name or uid.
- check_point.mgmt.cp_mgmt_threat_rule - Manages threat-rule objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_threat_rule_facts - Get threat-rule objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_time - Manages time objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_time_facts - Get time objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_verify_policy - Verifies the policy of the selected package.
- check_point.mgmt.cp_mgmt_vpn_community_meshed - Manages vpn-community-meshed objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_vpn_community_meshed_facts - Get vpn-community-meshed objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_vpn_community_star - Manages vpn-community-star objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_vpn_community_star_facts - Get vpn-community-star objects facts on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_wildcard - Manages wildcard objects on Check Point over Web Services API
- check_point.mgmt.cp_mgmt_wildcard_facts - Get wildcard objects facts on Check Point over Web Services API
