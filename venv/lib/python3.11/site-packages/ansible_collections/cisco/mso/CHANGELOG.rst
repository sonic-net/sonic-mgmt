==========================================
Cisco MSO Ansible Collection Release Notes
==========================================

.. contents:: Topics

This changelog describes changes after version 0.0.4.

v2.12.0
=======

Release Summary
---------------

Release v2.12.0 of the ``ansible-mso`` collection on 2025-11-19.
This changelog describes all changes made to the modules and plugins included in this collection since v2.11.0.

Minor Changes
-------------

- Add parent_type, node_id, path, port_channel, virtual_port_channel, encapsulation_type and encapsulation_value options to ndo_l3out_bgp_peer.
- Add ptp option to ndo_l3out_routed_interface and ndo_l3out_routed_sub_interface.

Bugfixes
--------

- Fix updates of multicast_route_map_policy in mso_schema_template_vrf_rp.
- Fix updates of multicast_route_map_source_filter and multicast_route_map_destination_filter in mso_schema_template_bd.

New Modules
-----------

- cisco.mso.ndo_l3out_floating_svi_interface - Manage L3Out Floating SVI Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_floating_svi_interface_path_attributes - Manage L3Out Floating SVI Interface Path Attributes on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_secondary_ip - Manage L3Out Secondary IP Address on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_svi_interface - Manage L3Out SVI Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_match_rule_community_term - Manage Match Community Terms on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_match_rule_policy - Manage Match Rule Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_match_rule_prefix - Manage Match Prefix List on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_route_map_policy_route_control - Manage Route Map Policy for Route Control on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_route_map_policy_route_control_context - Manage Route Map Policy for Route Control Context on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_set_rule_policy - Manage Tenant Set Rule Policies on Cisco Nexus Dashboard Orchestrator (NDO).

v2.11.0
=======

Release Summary
---------------

Release v2.11.0 of the ``ansible-mso`` collection on 2025-07-17.
This changelog describes all changes made to the modules and plugins included in this collection since v2.10.0.

Minor Changes
-------------

- Add admin_state attribute to mso_schema_site_anp_epg module.
- Improved ndo modules returned current value with actual API response.

Bugfixes
--------

- Fix API endpoint to query local and remote users in ND4.0

New Modules
-----------

- cisco.mso.ndo_fabric_span_session - Manage Fabric SPAN Sessions on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_fabric_span_session_source - Manage Fabric SPAN Sessions Source on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_fabric_span_session_source_filter - Manage Fabric SPAN Sessions Source Filter on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_bgp_peer - Manage L3Out BGP Peer on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_node_static_route - Manage L3Out Node Static Routes on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_node_static_route_next_hop - Manage L3Out Node Static Route Next Hops on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_routed_interface - Manage L3Out Routed Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_l3out_routed_sub_interface - Manage L3Out Routed Sub-Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_pod_profile - Manage Pod Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_pod_settings - Manage Pod Settings on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_qos_class_policy - Manage QoS Class Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_schema_template_contract_service_chain - Manage the Schema Template Contract Service Chaining workflow on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_service_device_cluster - Manage Service Device Clusters on Cisco Nexus Dashboard Orchestrator (NDO).
- cisco.mso.ndo_tenant_span_session - Manage Tenant SPAN Sessions on Cisco Nexus Dashboard Orchestrator (NDO).

v2.10.0
=======

Release Summary
---------------

Release v2.10.0 of the ``ansible-mso`` collection on 2025-04-19.
This changelog describes all changes made to the modules and plugins included in this collection since v2.9.0.

Minor Changes
-------------

- Add ep_move_detection_mode attribute in mso_schema_template_bd.
- Add mso_schema_template_anp_epg_annotation module.
- Add mso_schema_template_anp_epg_intra_epg_contract module.
- Add name attribute to mso_schema_template_external_epg_subnet module.
- Add ndo_ipsla_track_list and ndo_ipsla_monitoring_policy modules.
- Add ndo_l3out_node_routing_policy, ndo_l3out_interface_routing_policy, and ndo_tenant_bgp_peer_prefix_policy modules.
- Add ndo_l3out_template, ndo_l3out_annotation, ndo_l3out_interface_group_policy, and ndo_l3out_node_group_policy modules.
- Add ndo_mcp_global_policy module.
- Add ndo_ntp_policy, ndo_ptp_policy, and ndo_ptp_policy_profiles modules.
- Add ndo_physical_interface, ndo_port_channel_interface, ndo_virtual_port_channel_interface, ndo_node_profile, and ndo_fex_device modules to support NDO Fabric Resource Policies.
- Add ndo_qos_dscp_cos_translation_policy module.
- Add ndo_synce_interface_policy, ndo_interface_setting, ndo_node_setting, and ndo_macsec_policy modules.
- Add ndo_tenant_custom_qos_policy module.
- Add ndo_tenant_igmp_interface_policy, ndo_tenant_igmp_snooping_policy, and ndo_tenant_mld_snooping_policy modules.
- Add qos_level attribute to the mso_schema_template_external_epg module.
- Add support for Ansible 2.18 and dropped support for Ansible 2.15 as required by Ansible Galaxy.
- Add support for site configuration for tenant policy template in ndo_template module.

Bugfixes
--------

- Fix query results for bulk query to display correct static_paths in mso_schema_site_anp_epg_staticport module
- Fix replace operation for bulk present without force replace in mso_schema_site_anp_epg_staticport module

v2.9.0
======

Release Summary
---------------

Release v2.9.0 of the ``ansible-mso`` collection on 2024-08-06.
This changelog describes all changes made to the modules and plugins included in this collection since v2.8.0.

Minor Changes
-------------

- Add new module ndo_schema_template_bd_dhcp_policy to support BD DHCP Policy configuration in NDO version 4.1 and later
- Add support to use an APIC DN as VRF reference in mso_schema_site_bd_l3out

Bugfixes
--------

- Fix to be able to reference APIC only L3Out in mso_schema_site_external_epg

v2.8.0
======

Release Summary
---------------

Release v2.8.0 of the ``ansible-mso`` collection on 2024-07-12.
This changelog describes all changes made to the modules and plugins included in this collection since v2.7.0.

Minor Changes
-------------

- Add module mso_schema_template_vrf_rp to support multicast vrf rp in application templates
- Add module ndo_dhcp_option_policy to support dhcp option policy configuration in tenant templates
- Add module ndo_dhcp_relay_policy to support dhcp relay policy configuration in tenant templates
- Add module ndo_l3_domain and ndo_physical_domain to support domain configuration in fabric policy templates
- Add module ndo_vlan_pool to support vlan pool configuration in fabric policy templates
- Add site_aware_policy_enforcement and bd_enforcement_status arguments to the mso_schema_template_vrf module
- Add support for multicast route map filters in mso_schema_template_bd

Bugfixes
--------

- Fix to avoid making updates to attributes that are not provided which could lead to removal of configuration in mso_schema_template_bd
- Fix to avoid making updates to attributes that are not provided which could lead to removal of configuration in mso_schema_template_vrf

v2.7.0
======

Release Summary
---------------

Release v2.7.0 of the ``ansible-mso`` collection on 2024-07-02.
This changelog describes all changes made to the modules and plugins included in this collection since v2.6.0.

Minor Changes
-------------

- Added module ndo_route_map_policy_multicast to support multicast route map policies configuration in tenant templates
- Added module ndo_template to support creation of tenant, l3out, fabric_policy, fabric_resource, monitoring_tenant, monitoring_access and service_device templates

v2.6.0
======

Release Summary
---------------

Release v2.6.0 of the ``ansible-mso`` collection on 2024-04-06.
This changelog describes all changes made to the modules and plugins included in this collection since v2.5.0.

Minor Changes
-------------

- Add Azure Cloud site support to mso_schema_site_contract_service_graph
- Add Azure Cloud site support to mso_schema_site_service_graph
- Add functionality to resolve same name in remote and local user.
- Add l3out_template and l3out_schema arguments to mso_schema_site_external_epg (#394)
- Add mso_schema_site_contract_service_graph module to manage site contract service graph
- Add mso_schema_site_contract_service_graph_listener module to manage Azure site contract service graph listeners and update other modules
- Add new parameter remote_user to add multiple remote users associated with multiple login domains
- Add support for replacing all existing contracts with new provided contracts in a single operation with one request and adding/removing multiple contracts in multiple operations with a single request in mso_schema_template_anp_epg_contract module
- Add support for replacing all existing static ports with new provided static ports in a single operation with one request and adding/removing multiple static ports in multiple operations with a single request in mso_schema_template_anp_epg_staticport module
- Add support for required attributes introduced in NDO 4.2 for mso_schema_site_anp_epg_domain
- Support for creation of schemas without templates with the mso_schema module

Bugfixes
--------

- Fix TypeError for iteration on NoneType in mso_schema_template
- Fixed the useg_subnet logic in mso_schema_template_anp_epg_useg_attribute

v2.5.0
======

Release Summary
---------------

Release v2.5.0 of the ``ansible-mso`` collection on 2023-08-04.
This changelog describes all changes made to the modules and plugins included in this collection since v2.4.0.

Minor Changes
-------------

- Add login domain attribute to mso httpapi connection plugin with restructure of connection parameter handling
- Add mso_schema_template_anp_epg_useg_attribute and mso_schema_site_anp_epg_useg_attribute modules to manage EPG uSeg attributes (#370)

Bugfixes
--------

- Fix mso_tenant_site "site not found" issue on absent (#368)

v2.4.0
======

Release Summary
---------------

Release v2.4.0 of the ``ansible-mso`` collection on 2023-04-19.
This changelog describes all changes made to the modules and plugins included in this collection since v2.3.0.

Minor Changes
-------------

- Add ip_data_plane_learning and preferred_group arguments to mso_schema_template_vrf module (#358)

Bugfixes
--------

- Add attributes to payload for changed schema behaviour of deploymentImmediacy (deployImmediacy) and vmmDomainProperties (properties at domain level in payload) (#362)
- Fix mso_backup for NDO and ND-based MSO v3.2+ (#333)
- Fix validation condition for path in mso_schema_site_anp_epg_bulk_staticport module (#360)

v2.3.0
======

Release Summary
---------------

Release v2.3.0 of the ``ansible-mso`` collection on 2023-03-30.
This changelog describes all changes made to the modules and plugins included in this collection since v2.2.1.

Minor Changes
-------------

- Add module mso_schema_site_anp_epg_bulk_staticport (#330)
- Add route_reachability attribute to mso_schema_site_external_epg module (#335)

Bugfixes
--------

- Fix idempotency for mso_schema_site_bd_l3out

v2.2.1
======

Release Summary
---------------

Release v2.2.1 of the ``ansible-mso`` collection on 2023-01-31.
This changelog describes all changes made to the modules and plugins included in this collection since v2.2.0.

Bugfixes
--------

- Fix datetime support for python2.7 in mso_backup_schedule (#323)

v2.2.0
======

Release Summary
---------------

Release v2.2.0 of the ``ansible-mso`` collection on 2023-01-29.
This changelog describes all changes made to the modules and plugins included in this collection since v2.1.0.

Minor Changes
-------------

- Add automatic creation of site bd when not existing in mso_schema_site_bd_subnet module (#263)
- Add automatic schema validation functionality to mso_schema_template_deploy and ndo_schema_template_deploy (#318)
- Add ndo_schema_template_deploy to support NDO 4+ deploy functionality (#305)
- Add support for l3out from different template or schema in mso_schema_site_bd_l3out (#304)
- Add support for orchestrator_only attribute for mso_tenant with state absent (#268)

Bugfixes
--------

- Fix MSO HTTPAPI plugin login domain issue (#317)
- Fix deploymentImmediacy key inconsistency in the API used by mso_schema_site_anp and mso_schema_site_anp_epg (#283)
- Fix mso_schema_template_bd issue when created with unicast_routing as false (#278)
- Fix to be able to add multiple filter and filters with "-" in their names (#306)

v2.1.0
======

Release Summary
---------------

Release v2.1.0 of the ``ansible-mso`` collection on 2022-10-14.
This changelog describes all changes made to the modules and plugins included in this collection since v1.4.0.
The version was bumped directly to 2.1.0 due to a previous collection upload issue on galaxy.

Minor Changes
-------------

- Add aci_remote_location module (#259)
- Add mso_backup_schedule module (#250)
- Add mso_chema_template_contract_service_graph module (#257)
- Add mso_schema_template_service_graph, mso_schema_site_service_graph and mso_service_node_type modules (#243)
- Add primary attribute to mso_schema_site_bd_subnet (#254)

Deprecated Features
-------------------

- The mso_schema_template_contract_filter contract_filter_type attribute is deprecated. The value is now deduced from filter_type.

Bugfixes
--------

- Fix time issue when host running ansible is in a different timezone then NDO
- Remove mso_guide from notes

v1.4.0
======

Release Summary
---------------

Release v1.4.0 of the ``ansible-mso`` collection on 2022-03-15.
This changelog describes all changes made to the modules and plugins included in this collection since v1.3.0.

Minor Changes
-------------

- Update mso_schema_template_clone to use new method from NDO and unrestrict it to earlier version

Bugfixes
--------

- Fix arp_entry value issue in mso_schema_template_filter_entry
- Fix mso_schema_site_anp idempotency when children exists
- Fix use_ssl documentation to explain usage when used with HTTPAPI connection plugin

v1.3.0
======

Release Summary
---------------

Release v1.3.0 of the ``cisco.mso`` collection on 2021-12-18.
This changelog describes all changes made to the modules and plugins included in this collection since v1.2.0.

Minor Changes
-------------

- Add container_overlay and underlay_context_profile support to mso_schema_site_vrf_region
- Add description support to various modules
- Add hosted_vrf support to mso_schema_site_vrf_region_cidr_subnet
- Add module mso_schema_validate to check schema validations
- Add private_link_label support to mso_schema_site_anp_epg and mso_schema_site_vrf_region_cidr_subnet
- Add qos_level and Service EPG support to mso_schema_template_anp_epg
- Add qos_level, action and priority support to mso_schema_template_contract_filter
- Add schema and template description support to mso_schema_template
- Add subnet as primary support to mso_schema_template_bd_subnet
- Add support for automatically creating anp structure at site level when using mso_schema_site_anp_epg
- Add support for encap-flood as multi_destination_flooding in mso_schema_template_bd
- Add test file for mso_schema_site_anp, mso_schema_site_anp_epg, mso_schema_template_external_epg_subnet mso_schema_template_filter_entry
- Improve scope attribute documentation in mso_schema_template_external_epg_subnet
- Update Ansible version used in automated testing to v2.9.27, v2.10.16 and addition of v2.11.7 and v2.12.1

Bugfixes
--------

- Add no_log to aws_access_key and secret_key in mso_tenant_site
- Fix MSO HTTP API to work without host, user and password module attribute
- Fix issue with unicast_routing idemptotency in mso_schema_template_bd
- Fix mso_schema_site_anp and mso_schema_site_anp_epg idempotency issue
- Remove sanity ignore files and fix sanity issues that were previously ignored

v1.2.0
======

Release Summary
---------------

Release v1.2.0 of the ``cisco.mso`` collection on 2021-06-02.
This changelog describes all changes made to the modules and plugins included in this collection since v1.1.0.

Minor Changes
-------------

- Add Ansible common HTTPAPI dependancy in galaxy.yml
- Add HTTPAPI connection plugin support and HTTPAPI MSO connection plugin
- Add primary and unicast_routing attributes to mso_schema_template_bd
- Add requirements.txt for Ansible Environment support
- Add schema and template cloning modules mso_schema_clone and mso_schema_template_clone
- Add support cisco.nd.nd connection plugin
- Add support for multiple DCHP policies in a BD and new module mso_schema_template_bd_dhcp_policy
- Upgrade CI to latest Ansible version and Python 3.8

Bugfixes
--------

- Add test case and small fixes to mso_schema_site_bd_l3out module
- Fix documentation issues accross modules
- Fix fail_json usage accross module_utils/mso.py
- Fix mso_rest to support HTTPAPI plugin and tests to support ND platform
- Fix mso_user to due to error in v1 API in MSO 3.2
- Fix path issue in mso_schema_template_migrate
- Fixes for site level external epgs and site level L3Outs
- Fixes to support MSO 3.3
- Remove query of all schemas to get schema ID and only query schema ID indentity list API

New Plugins
-----------

Httpapi
~~~~~~~

- cisco.mso.mso - MSO Ansible HTTPAPI Plugin.

v1.1.0
======

Release Summary
---------------

Release v1.1.0 of the ``cisco.mso`` collection on 2021-01-20.
This changelog describes all changes made to the modules and plugins included in this collection since v1.0.1.

Minor Changes
-------------

- Add DHCP Policy Operations
- Add SVI MAC Addreess option in mso_schema_site_bd
- Add additional test file to add tenant from templated payload file
- Add attribute virtual_ip to mso_schema_site_bd_subnet
- Add capability for restore and download backup
- Add capability to upload backup
- Add check for undeploy under MSO version
- Add error handeling test file
- Add error message to display when yaml has failed to load
- Add galaxy-importer check
- Add galaxy-importer config
- Add mso_dhcp_option_policy and mso_dhcp_option_policy_option and test files
- Add new module mso_rest and test case files to support GET api method
- Add new options to template bd and updated test file
- Add notes to use region_cidr module to create region
- Add task to undeploy the template from the site
- Add tasks in test file to remove templates for mso_schema_template_migrate
- Add test case for schema removing
- Add test cases to verify GET, PUT, POST and DELETE API methods for sites in mso_rest.py
- Add test file for mso_schema
- Add test file for mso_schema_template_anp
- Add test file for region module
- Add test files yaml_inline and yaml_string to support YAML
- Add userAssociations to tenants to resolve CI issues
- Addition of cloud setting for ext epg
- Changes made to payload of mso_schema_template_external_epg
- Changes to options in template bd
- Check warning
- Documentation Corrected
- Force arp flood to be true when l2unkwunicast is flood
- Make changes to display correct status code
- Modify mso library and updated test file
- Modify mso_rest test files to make PATCH available, and test other methods against schemas
- Move options for subnet from mso to the template_bd_subnet module
- Python lint corrected
- Redirect log to both stdout and log.txt file & Check warnings and errors
- Remove creation example in document of mso_schema_site_vrf_region
- Remove present state from mso_schema module
- Removed unused variable in mso_schema_site_vrf_region_hub_network
- Test DHCP Policy Provider added
- Test file for mso_dhcp_relay_policy added
- Test file for template_bd_subnet and new option foe module

Bugfixes
--------

- Fix anp idempotency issue
- Fix crash issue when using irrelevant site-template
- Fix default value for mso_schema state parameter
- Fix examples for mso_schema
- Fix galaxy-importer check warnings
- Fix issue on mso_schema_site_vrf_region_cidr_subnet to allow an AWS subnet to be used for a TGW Attachment (Hub Network)
- Fix module name in example of mso_schema_site_vrf_region
- Fix mso_backup upload issue
- Fix sanity test error mso_schema_site_bd
- Fix some coding standard and improvements to contributed mso_dhcp_relay modules and test files
- Fix space in asssertion
- Fix space in site_anp_epg_domain
- Fix space in test file
- Remove space from template name in all modules
- Remove space in template name

v1.0.1
======

Release Summary
---------------

Release v1.0.1 of the ``cisco.mso`` collection on 2020-10-30.
This changelog describes all changes made to the modules and plugins included in this collection since v1.0.0.

Minor Changes
-------------

- Add delete capability to mso_schema_site
- Add env_fallback for mso_argument_spec params
- Add non existing template deletion test
- Add test file for mso_schema_template
- Add test file for site_bd_subnet
- Bump module to v1.0.1
- Extent mso_tenant test case coverage

Bugfixes
--------

- Fix default value for l2Stretch in mso_schema_template_bd module
- Fix deletion of schema when wrong template is provided in single template schema
- Fix examples in documentation for mso_schema_template_l3out and mso_user
- Fix naming issue in deploy module
- Remove author emails due to length restriction
- Remove dead code branch in mso_schema_template

v1.0.0
======

Release Summary
---------------

This is the first official release of the ``cisco.mso`` collection on 2020-08-18.
This changelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0.

Minor Changes
-------------

- Add changelog
- Fix M() and module to use FQCN
- Update Ansible version in CI and add 2.10.0 to sanity in CI.
- Update Readme with supported versions

Bugfixes
--------

- Fix sanity issues to support 2.10.0

v0.0.8
======

Release Summary
---------------

New release v0.0.8

Minor Changes
-------------

- Add Login Domain support to mso_site
- Add aliases file for contract_filter module
- Add contract information in current and previous part
- Add new module and test file to query MSO version
- New backup module and test file (https://github.com/CiscoDevNet/ansible-mso/pull/80)
- Renaming mso_schema_template_externalepg module to mso_schema_template_external_epg while keeping both working.
- Update cidr module, udpate attributes in hub network module and its test file
- Use a function to reuuse duplicate part

Bugfixes
--------

- Add login_domain to existing test.
- Add missing tests for VRF settings and changing those settings.
- Add test for specifying read-only roles and increase overall test coverage of mso_user (https://github.com/CiscoDevNet/ansible-mso/pull/77)
- Add test to mso_schema_template_vrf, mso_schema_template_external_epg and mso_schema_template_anp_epg to check for API error when pushing changes to object with existing contract.
- Cleanup unused imports, unused variables and branches and change a variable from ambiguous name to reduce warnings at Ansible Galaxy import
- Fix API error when pushing EPG with existing contracts
- Fix role tests to work with pre/post 2.2.4 and re-enable them
- Fix site issue if no site present and fix test issues with MSO v3.0
- Fixing External EPG renaming for 2.9 and later
- Fixing L3MCast test to pass on 2.2.4
- Fixing wrong removal of schemas
- Test hub network module after creating region manually
- Updating Azure site IP in inventory and add second MSO version to inventory

v0.0.7
======

Release Summary
---------------

New release v0.0.7

Minor Changes
-------------

- Add l3out, preferred_group and test file for mso_schema_template_externalepg
- Add mso_schema_template_vrf_contract module and test file
- Add new attribute choice "policy_compression" to mso_Schema_template_contract_filter
- Add new functionality - Direct Port Channel (dpc), micro-seg-vlan and default values
- Add new module for anp-epg-selector in site level
- Add new module mso_schema_template_anp_epg_selector and its test file
- Add new module mso_schema_vrf_contract
- Add new module mso_tenant_site to support cloud and non-cloud sites association with a tenant and test file (https://github.com/CiscoDevNet/ansible-mso/pull/62)
- Add new mso_site_external_epg_selector module and test file
- Add site external epg and contract filter test
- Add support for VGW attribute in mso_schema_site_vrf_region_cidr_subnet
- Add support to set account as inactive using account_status attribute in mso_user
- Add test for mso_schema_site_vrf_region_cidr module
- Add test for mso_schema_site_vrf_region_cidr_subnet module
- Add vzAny attribute in mso_schema_template_vrf
- Automatically add ANP and EPG at site level and new test file for mso_schema_site_anp_epg_staticport (https://github.com/CiscoDevNet/ansible-mso/pull/55)
- Modified External EPG module and addition of new Selector module

Bugfixes
--------

- Fix mso_schema_site_vrf_region_cidr to automatically create VRF and Region if not present at site level
- Fix query condition when VRF or Region do not exist at site level
- Remove unused regions attribute from mso_schema_template_vrf

v0.0.6
======

Release Summary
---------------

New release v0.0.6

Minor Changes
-------------

- ACI/MSO - Use get() dict lookups (https://github.com/ansible/ansible/pull/63074)
- Add EPG and ANP at site level when needed
- Add github action CI pipeline with test coverage
- Add login domain support for authentication in all modules
- Add support for DHCP querier to all subnet objects. Add partial test in mso_schema_template_bd integration test.
- Add support for clean output if needed for debuging
- Add test file for mso_schema_template_anp_epg
- Added DHCP relay options and scope options to MSO schema template bd
- Added ability to bind epg to static fex port
- Added module to manage contracts for external EPG in Cisco MSO (https://github.com/ansible/ansible/pull/63550)
- Added module to manage template external epg subnet for Cisco MSO (https://github.com/ansible/ansible/pull/63542)
- Disabling tests for the role modules as API is not supported after 2.2.3i until further notice
- Increased test coverage for existing module integration tests.
- Modified fail messages for site and updated documentation
- Moving test to Ansible v2.9.9 and increasing timelimit for mutex to 30+ min
- Update authors.
- Update mso_schema_site_anp.py (https://github.com/ansible/ansible/pull/67099)
- Updated Test File Covering all conditions
- mso_schema_site_anp_epg_staticport - Add VPC support (https://github.com/ansible/ansible/pull/62803)

Bugfixes
--------

- Add aliases for backward support of permissions in role module.
- Add integration test for mso_schema_template_db and fix un-needed push to API found by integration test.
- Consistent object output on domain_associations
- Fix EPG / External EPG Contract issue and create test for mso_schema_template_anp_epg_contract and mso_schema_template_external_epg_contract
- Fix contract filter issue and add contract-filter test file
- Fix duplicate user, add admin user to associated user list and update tenant test file
- Fix intersite_multicast_source attribute issue in mso_schema_template_anp_epg and add the proxy_arp argument.
- Fix mso_schema_template_anp_epg idempotancy for both EPG and EPG with contracts
- Remove label with test domain before create it
- Send context instead of vrf when vrf parameter is used
- Update mso_schema_template_bd.py example for BD in another schema

v0.0.5
======

Release Summary
---------------

New release v0.0.5
