==========================================
Ansible OpenStack Collection Release Notes
==========================================

.. contents:: Topics

v2.5.0
======

Release Summary
---------------

Bugfixes and minor changes

Major Changes
-------------

- Add import_method to module
- Add object_containers_info module
- Add support for filters in inventory
- Add volume_manage module
- Introduce share_type modules

Minor Changes
-------------

- Allow role_assignment module to work cross domain
- Don't compare current state for `reboot_*` actions
- Fix disable_gateway_ip for subnet
- Fix disable_gateway_ip for subnet
- Fix example in the dns_zone_info module doc
- Fix router module external IPs when only subnet specified
- Fix the bug reporting url
- Let clouds_yaml_path behave as documented (Override path to clouds.yaml file)
- Shows missing data in `stack_info` module output

v2.4.1
======

Release Summary
---------------

Bugfixes and minor changes

Minor Changes
-------------

- Update tags when changing server

Bugfixes
--------

- Fix missed client_cert in OpenStackModule

v2.4.0
======

Release Summary
---------------

New trait module and minor changes

Major Changes
-------------

- Add trait module

Minor Changes
-------------

- Add loadbalancer quota options
- Allow create instance with tags

New Modules
-----------

- openstack.cloud.trait - Add or Delete a trait from OpenStack

v2.3.3
======

Release Summary
---------------

Bugfixes and minor changes

Minor Changes
-------------

- Add test to only_ipv4 in inventory
- add an option to use only IPv4 only for ansible_host and ansible_ssh_host

Bugfixes
--------

- CI - Fix deprecated ANSIBLE_COLLECTIONS_PATHS variable

v2.3.2
======

Release Summary
---------------

Bugfixes and minor changes

Minor Changes
-------------

- Drop compat implementations for tests

Bugfixes
--------

- Fix openstack.cloud.port module failure in check mode

v2.3.1
======

Release Summary
---------------

Client TLS certificate support

Minor Changes
-------------

- Add ability to pass client tls certificate

v2.3.0
======

Release Summary
---------------

Bugfixes and new modules

Major Changes
-------------

- Add Neutron trunk module
- Add application_credential module
- Add module to filter available volume services

Minor Changes
-------------

- Add inactive state for the images
- Add insecure_registry property to coe_cluster_templates
- Add support for creation of the default external networks
- Add target_all_project option
- Add vlan_tranparency for creation networks
- Allow munch results in server_info module
- Allow to specify multiple allocation pools when creating a subnet
- CI - Disable auto-discovery for setuptools
- CI - Don't create port with binding profile
- CI - Fix CI in collection
- CI - Fix linters-devel and devstack tests
- CI - Fix regression in quota module
- CI - Fix test for server shelve
- CI - Migrate Bifrost jobs to Ubuntu Jammy
- CI - Remove 2.9 jobs from Zuul config
- CI - Run functional testing regardless of pep8/linter results
- Enable glance-direct interop image import
- Ensure coe_cluster_template compare labels properly
- Wait for deleted server to disappear from results
- router - Allow specifying external network name in a different project

Bugfixes
--------

- Allow wait false when auto_ip is false
- Fix exception when creating object from file
- Fix exception when updating container with metadata
- Fix typo in openstack.cloud.lb_pool
- Fix typo in parameter description
- fix subnet module - allow cidr option with subnet_pool

New Modules
-----------

- openstack.cloud.application_credential - Manage OpenStack Identity (Keystone) application credentials
- openstack.cloud.trunk - Add or delete trunks from an OpenStack cloud
- openstack.cloud.volume_service_info - Fetch OpenStack Volume (Cinder) services

v2.2.0
======

Release Summary
---------------

New module for volume_type and bugfixes

Minor Changes
-------------

- Add volume_encryption_type modules
- Add volume_type modules

Bugfixes
--------

- Fix image module filter
- Fix port module idempotency
- Fix router module idempotency

v2.1.0
======

Release Summary
---------------

New module for Ironic and bugfixes

Minor Changes
-------------

- Add baremetal_deploy_template module
- Highlight our mode of operation more prominently

Bugfixes
--------

- Change security group rules only when instructed to do so
- Fix for AttributeError: 'dict' object has no attribute 'status'
- Fix issue with multiple records in recordset
- Fix mistake in compute_flavor_access notes
- Fixed private option in inventory plugin
- Respect description option and delete security group rules first
- Use true and false instead of yes and no for boolean values

v2.0.0
======

Release Summary
---------------

Our new major release 2.0.0 of the Ansible collection for OpenStack clouds aka ``openstack.cloud`` is a complete overhaul of the code base and brings full compatibility with openstacksdk 1.0.0.

Highlights of this release are
* three new modules which for example provide a generic and uniform API for interacting with OpenStack cloud resources,
* a complete refactoring of all existing modules bringing dozens of bugfixes, new features as well as consistent
  and properly documented module results and options,
* 100% compatibility with openstacksdk's first major release 1.0.0,
* new guides for contributors from devstack setup over coding guidelines to our release process and
* massively increased CI coverage with many new integration tests, now covering all modules and plugins.

Note, this ``2.0.0`` release *breaks backward compatibility* with previous ``1.x.x`` releases!
* ``2.x.x`` releases of this collection are compatible with openstacksdk ``1.x.x`` and later *only*,
* ``1.x.x`` releases of this collection are compatible with openstacksdk ``0.x.x`` prior to ``0.99.0`` *only*,
* ``2.x.x`` releases of are not backward compatible with ``1.x.x`` releases,
* ``1.x.x`` release series will be in maintenance mode now and receive bugfixes only.

However, this collection as well as openstacksdk continue to be backward compatible with clouds running on older OpenStack releases. For example, it is fine and a fully supported use case to use this 2.0.0 release with clouds based on OpenStack Train, Wallaby or Zed. Feel encouraged to always use the latest releases of this collection and openstacksdk regardless of which version of OpenStack is installed in your cloud.

This collection is compatible with and tested with Ansible 2.9 and later. However, support for old ``os_*`` short module names such as ``os_server`` have been dropped with this release. You have to call modules using their FQCN (Fully-Qualified Collection Name) such as ``openstack.cloud.server`` instead.

Many thanks to all contributors who made this release possible. Tens of thousands LOCs have been reviewed and changed and fixed and tested throughout last year. You rock!

Major Changes
-------------

- Many modules gained support for Ansible's check mode or have been fixed to properly implement a no change policy during check mode runs.
- Many modules gained support for updates. In the past, those modules allowed to create and delete OpenStack cloud resources but would ignore when module options had been changed.
- Many modules such as ``openstack.cloud.server``, ``openstack.cloud.baremetal_node`` and all load-balancer related modules now properly implement the ``wait`` option. For example, when ``wait`` is set to ``true`` then modules will not return until resources have reached its ``active`` or ``deleted`` state.
- Module ``openstack.cloud.resource`` has been added. It provides an generic and uniform interface to create, update and delete any OpenStack cloud resource which openstacksdk supports. This module unlocks a huge amount of functionality from OpenStack clouds to Ansible users which has been inaccessible with existing modules so far.
- Module ``openstack.cloud.resources`` has been added. It provides an generic and uniform interface to list any type of OpenStack cloud resources which openstacksdk supports. This module fetch any OpenStack cloud resource without having to implement a new Ansible ``*_info`` module for this type of resource first.
- Module ``openstack.cloud.subnet_pool`` has been added. It allows to create and delete subnet pools in OpenStack clouds.
- Module examples have been improved and updated for most modules.
- Module results have been properly documented for all modules.
- Options in all modules have been renamed to match openstacksdk's attribute names (if applicable). The previous option names have been added as aliases to keep module options backward compatible.
- Our CI integration tests have been massively expanded. Our test coverage spans across all modules and plugins now, including tests for our inventory plugin and our new ``openstack.cloud.resource`` and ``openstack.cloud.resources`` modules.
- Our contributors documentation has been heavily extended. In directory ``docs`` you will find the rationale for our branching strategy, a developer's guide on how to contribute to the collection, a tutorial to set up a DevStack environment for hacking on and testing the collection, a step-by-step guide for publishing new releases and a list of questions to ask when doing reviews or submitting patches for review.

Minor Changes
-------------

- Added generic module options ``sdk_log_path`` and ``sdk_log_level`` which allow to track openstacksdk activity.
- Many more options were added to modules but we stopped counting at one point...
- Module ``openstack.cloud.coe_cluster`` gained support for option ``is_floating_ip_enabled``.
- Module ``openstack.cloud.lb_listener`` gained options ``default_tls_container_ref`` and ``sni_container_refs`` which allow to specify TLS certificates when using the ``TERMINATED_HTTPS`` protocol.
- Module ``openstack.cloud.network`` gained support for updates, i.e. existing networks will be properly updated now when module options such as ``mtu`` or ``admin_state_up`` have been changed.
- Module ``openstack.cloud.port`` gained an ``description`` option.
- Module ``openstack.cloud.role_assignment`` gained an ``system`` option.
- Module ``openstack.cloud.security_group_rule`` gained an ``description`` option.
- Module ``openstack.cloud.server_action`` gained an option ``all_projects`` which allows to execute actions on servers outside of the current auth-scoped project (if the user has permission to do so).
- Module ``openstack.cloud.server_info`` gained an ``description`` option.
- Module ``openstack.cloud.server`` gained an ``description`` option.
- Module ``openstack.cloud.server`` gained support for updates. For example, options such as ``description`` and floating ip addresses can be updated now.
- Module ``openstack.cloud.subnet`` gained an ``subnet_pool`` option.

Breaking Changes / Porting Guide
--------------------------------

- 2.x.x releases of this collection are not backward compatible with 1.x.x releases. Backward compatibility is guaranteed within each release series only. Module options have been kept backward compatible across both release series, apart from a few exceptions noted below. However, module results have changed for most modules due to deep changes in openstacksdk. For easier porting and usage, we streamlined return values across modules and documented return values of all modules.
- Default value for option ``security_groups`` in ``openstack.cloud.server`` has been changed from ``['default']`` to ``[]`` because the latter is the default in python-openstackclient and the former behavior causes issues with existing servers.
- Dropped symbolic links with prefix ``os_`` and plugin routing for deprecated ``os_*`` module names. This means users have to call modules of the Ansible OpenStack collection using their FQCN (Fully Qualified Collection Name) such as ``openstack.cloud.server``. Short module names such as ``os_server`` will now raise an Ansible error.
- Module ``openstack.cloud.project_access`` has been split into two separate modules ``openstack.cloud.compute_flavor_access`` and ``openstack.cloud.volume_type_access``.
- Option ``availability_zone`` has been removed from the list of generic options available in all modules. Instead it has been inserted into the ``openstack.cloud.server`` and ``openstack.cloud.volume`` modules because it is relevant to those two modules only.
- Option ``name`` of module ``openstack.cloud.port`` is required now because it is used to find, update and delete ports and idempotency would break otherwise.
- Option ``policies`` has been replaced with option ``policy`` in module ``openstack.cloud.server_group``. The former is ancient and was superceded by ``policy`` a long time ago.
- Release series 2.x.x of this collection is compatible with openstacksdk 1.0.0 and later only. For compatibility with openstacksdk < 0.99.0 use release series 1.x.x of this collection. Ansible will raise an error when modules and plugins in this collection are used with an incompatible release of openstacksdk.
- Special value ``auto`` for option ``id`` in module ``openstack.cloud.compute_flavor`` has been deprecated to be consistent with our other modules and openstacksdk's behaviour.

Deprecated Features
-------------------

- Option ``is_public`` in module ``openstack.cloud.image`` has been deprecated and replaced with option ``visibility``.
- Option ``volume`` in module ``openstack.cloud.image`` has been deprecated and it should be replaced with module ``openstack.cloud.volume`` in user code.

Removed Features (previously deprecated)
----------------------------------------

- Dropped deprecated ``skip_update_of_driver_password`` option from module ``openstack.cloud.baremetal_node``.
- Dropped unmaintained, obsolete and broken inventory script ``scripts/inventory/openstack_inventory.py``. It had been replaced with a proper Ansible inventory plugin ``openstack.cloud.openstack`` during the 1.x.x life cycle.
- Module ``openstack.cloud.object`` no longer allows to create and delete containers, its sole purpose is managing an object in a container now. Use module ``openstack.cloud.object_container`` to managing Swift containers instead.
- Option ``listeners`` has been removed from module ``openstack.cloud.loadbalancer`` because it duplicates a subset of the functionality (and code) provided by our ``openstack.cloud.lb_{listener,member,pool}`` modules.
- Our outdated, undocumented, untested and bloated code templates in ``contrib`` directory which could be used to generate and develop new Ansible modules for this collection have been removed.

Bugfixes
--------

- Ansible check mode has been fixed in module ``openstack.cloud.compute_flavor``, it will no longer apply changes when check mode is enabled.
- Creating load-balancers with module ``openstack.cloud.loadbalancer`` properly handles situations where several provider networks exist. A floating ip address specified in option ``floating_ip_address`` will be allocated from Neutron external network specified in option ``floating_ip_network``.
- Default values for options ``shared``, ``admin_state_up`` and ``external`` in module ``openstack.cloud.network`` have been dropped because they cause failures for clouds which do not have those optional extensions installed.
- Dropped default values for options ``min_disk`` and ``min_ram`` in module ``openstack.cloud.image`` because it interferes with its update mechanism and Glance uses those values anyway. Fixed handling of options ``name``, ``id``, ``visibility`` and ``is_public``.
- Module ``openstack.cloud.baremetal_node_info`` will now properly return machine details when iterating over all available baremetal nodes.
- Module ``openstack.cloud.host_aggregate`` now correctly handles ``hosts`` not being set or being set to ``None``.
- Module ``openstack.cloud.identity_user`` will no longer fail when no password is supplied since Keystone allows to create a user without an password.
- Module ``openstack.cloud.keypair`` no longer removes trailing spaces when reading a public key because this broke idempotency when using openstackclient and this module at the same time.
- Module ``openstack.cloud.quota`` no longer sends invalid attributes such as ``project_id`` to OpenStack API when updating Nova, Neutron and Cinder quotas.
- Module ``openstack.cloud.server`` will no longer change security groups to ``['default']`` on existing servers when option ``security_groups`` has not been specified.
- Module ``openstack.cloud.subnet`` now properly handles updates, thus idempotency has been fixed and restored.
- Modules ``openstack.cloud.security_group`` and ``openstack.cloud.security_group_rule`` gained support for specifying string ``any`` as a valid protocol in security group rules.
- Option ``interfaces`` in module ``openstack.cloud.router`` no longer requires option ``network`` to be set, it is ``external_fixed_ips`` what requires ``network``.
- Option ``is_public`` in module ``openstack.cloud.image`` will now be handled as a boolean instead of a string to be compatible to Glance API and fix issues when interacting with Glance service.
- Option ``network`` in module ``openstack.cloud.router`` is now propery marked as required by options ``enable_snat`` and ``external_fixed_ips``.
- Option ``owner`` in module ``openstack.cloud.image`` is now respected when searching for and creating images.
- Our OpenStack inventory plugin now properly supports Ansible's cache feature.

v1.7.1
======

Release Summary
---------------

Bugfixes

Minor Changes
-------------

- lb_member - Add monitor_[address,port] parameter

Bugfixes
--------

- openstack_inventory - Fix documentation
- quota - Fix description of volumes_types parameter

v1.7.0
======

Release Summary
---------------

New modules for Ironic and bugfixes

Minor Changes
-------------

- openstack_inventory - Adds use_name variable
- port - Add dns_[name,domain] to the port module
- project - Remove project properties tests and support

Bugfixes
--------

- identity_user_info - Fix identity user lookup with a domain
- keystone_domain - Move identity domain to use proxy layer

New Modules
-----------

- openstack.cloud.baremetal_node_info - Retrieve information about Bare Metal nodes from OpenStack an object.
- openstack.cloud.baremetal_port - Create, Update, Remove ironic ports from OpenStack
- openstack.cloud.baremetal_port_info - Retrieve information about Bare Metal ports from OpenStack an object.

v1.6.0
======

Release Summary
---------------

New modules for RBAC and Nova services

Minor Changes
-------------

- quota - Adds metadata_items parameter

New Modules
-----------

- openstack.cloud.compute_service_info - Retrieve information about one or more OpenStack compute services
- openstack.cloud.neutron_rbac_policies_info - Fetch Neutron policies.
- openstack.cloud.neutron_rbac_policy - Create or delete a Neutron policy to apply a RBAC rule against an object.

v1.5.3
======

Release Summary
---------------

Bugfixes

Bugfixes
--------

- Don't require allowed_address_pairs for port
- server_volume - check specified server is found

v1.5.2
======

Release Summary
---------------

Bugfixes

Minor Changes
-------------

- Add documentation links to README.md
- Don't run functional jobs on galaxy.yml change
- Move CI to use Ansible 2.12 version as main

Bugfixes
--------

- Add client and member listener timeouts for persistence (Ex. SSH)
- Added missing warn() used in cloud.openstack.quota
- Fix issue with same host and group names
- Flavor properties are not deleted on changes and id will stay

v1.5.1
======

Release Summary
---------------

Bugfixes for networking modules

Minor Changes
-------------

- Changed minversion in tox to 3.18.0
- Update IRC server in README

Bugfixes
--------

- Add mandatory requires_ansible version to metadata
- Add protocol listener octavia
- Add support check mode for all info modules
- Allow to attach multiple floating ips to a server
- Only add or remove router interfaces when needed
- Wait for pool to be active and online

v1.5.0
======

Release Summary
---------------

New modules for DNS and FIPs and bugfixes.

Minor Changes
-------------

- Add bindep.txt for ansible-builder
- Add check_mode attribute to OpenstackModule
- Migrating image module from AnsibleModule to OpenStackModule
- Switch KeystoneFederationProtocolInfo module to OpenStackModule
- Switch ProjectAccess module to OpenStackModule
- Switch Quota module to OpenStackModule
- Switch Recordset module to OpenStackModule
- Switch ServerGroup module to OpenStackModule
- Switch ServerMetadata module to OpenStackModule
- Switch Snapshot module to OpenStackModule
- Switch Stack module to OpenStackModule
- Switch auth module to OpenStackModule
- Switch catalog_service module to OpenStackModule
- Switch coe_cluster module to OpenStackModule
- Switch coe_cluster_template module to OpenStackModule
- Switch endpoint module to OpenStackModule
- Switch federation_idp module to OpenStackModule
- Switch federation_idp_info module to OpenStackModule
- Switch federation_mapping module to OpenStackModule
- Switch federation_mapping_info module to OpenStackModule
- Switch federation_protocol module to OpenStackModule
- Switch flavor module to OpenStackModule
- Switch flavor_info module to OpenStackModule
- Switch floating_ip module to OpenStackModule
- Switch group_assignment module to OpenStackModule
- Switch hostaggregate module to OpenStackModule
- Switch identity_domain module to OpenStackModule
- Switch identity_domain_info module to OpenStackModule
- Switch identity_group module to OpenStackModule
- Switch identity_group_info module to OpenStackModule
- Switch identity_role module to OpenStackModule
- Switch identity_user module to OpenStackModule
- Switch lb_listener module to OpenStackModule
- Switch lb_member module to OpenStackModule
- Switch lb_pool module to OpenStackModule
- Switch object module to OpenStackModule
- Switch port module to OpenStackModule
- Switch port_info module to OpenStackModule
- Switch project and project_info module to OpenStackModule
- Switch role_assignment module to OpenStackModule
- Switch user_info module to OpenStackModule
- image - Add support to setting image tags

Bugfixes
--------

- Update checks for validate_certs in openstack_cloud_from_module
- compute_flavor - Fix the idempotent of compute_flavor module
- host_aggregate - Fix host_aggregate to tolerate aggregate.hosts being None
- inventory/openstack - Fix inventory plugin on Ansible 2.11
- port - fix update on empty list of allowed address pairs
- setup.cfg Replace dashes with underscores
- subnet - Only apply necessary changes to subnets
- volume - Fail if referenced source image for a new volume does not exist

New Modules
-----------

- openstack.cloud.address_scope - Create or delete address scopes from OpenStack
- openstack.cloud.dns_zone_info - Getting information about dns zones
- openstack.cloud.floating_ip_info - Get information about floating ips

v1.4.0
======

Release Summary
---------------

New object_container module and bugfixes.

Bugfixes
--------

- Add Octavia job for testing Load Balancer
- Add binding profile to port module
- Add execution environment metadata
- Fix CI for latest ansible-test with no_log
- Fix issues with newest ansible-test 2.11
- Prepare for Ansible 2.11 tests
- add option to exclude legacy groups
- security_group_rule add support ipv6-icmp

New Modules
-----------

- openstack.cloud.object_container - Manage Swift container

v1.3.0
======

Release Summary
---------------

New modules and bugfixes.

Minor Changes
-------------

- Fix some typos in readme
- Guidelines Fix links and formatting
- baremetal_node - Add support for new features
- baremetal_node - ironic deprecate sub-options of driver_info
- baremetal_node - ironic stop putting meaningless values to properties
- image_info - Migrating image_info module from AnsibleModule to OpenStackModule
- recordset -  Update recordset docu
- server - Allow description field to be set with os_server
- server_action - Added shelve and unshelve as new server actions

Bugfixes
--------

- port - Fixed check for None in os_port
- project - Fix setting custom property on os_project
- security_group_rule - Remove protocols choice in security rules
- volume_info - Fix volume_info result for SDK < 0.19

New Modules
-----------

- openstack.cloud.identity_role_info - Retrieve information about Openstack Identity roles.
- openstack.cloud.keypair_info - Retrieve information about Openstack key pairs.
- openstack.cloud.security_group_info - Retrieve information about Openstack Security Groups.
- openstack.cloud.security_group_rule_info - Retrieve information about Openstack Security Group rules.
- openstack.cloud.stack_info - Retrieve information about Openstack Heat stacks.

v1.2.1
======

Release Summary
---------------

Porting modules to new OpenstackModule class and fixes.

Minor Changes
-------------

- dns_zone - Migrating dns_zone from AnsibleModule to OpenStackModule
- dns_zone, recordset - Enable update for recordset and add tests for dns and recordset module
- endpoint - Do not fail when endpoint state is absent
- ironic - Refactor ironic authentication into a new module_utils module
- loadbalancer - Refactor loadbalancer module
- network - Migrating network from AnsibleModule to OpenStackModule
- networks_info - Migrating networks_info from AnsibleModule to OpenStackModule
- openstack - Add galaxy.yml to support install from git
- openstack - Fix docs-args mismatch in modules
- openstack - OpenStackModule Support defining a minimum version of the SDK
- router - Migrating routers from AnsibleModule to OpenStackModule
- routers_info - Added deprecated_names for router_info module
- routers_info - Migrating routers_info from AnsibleModule to OpenStackModule
- security_group.py - Migrating security_group from AnsibleModule to OpenStackModule
- security_group_rule - Refactor TCP/UDP port check
- server.py - Improve "server" module with OpenstackModule class
- server_volume - Migrating server_volume from AnsibleModule to OpenStackModule
- subnet - Fix subnets update and idempotency
- subnet - Migrating subnet module from AnsibleModule to OpenStackModule
- subnets_info - Migrating subnets_info from AnsibleModule to OpenStackModule
- volume.py - Migrating volume from AnsibleModule to OpenStackModule
- volume_info - Fix volume_info arguments for SDK 0.19

v1.2.0
======

Release Summary
---------------

New volume backup modules.

Minor Changes
-------------

- lb_health_monitor - Make it possible to create a health monitor to a pool

New Modules
-----------

- openstack.cloud.volume_backup module - Add/Delete Openstack volumes backup.
- openstack.cloud.volume_backup_info module - Retrieve information about Openstack volume backups.
- openstack.cloud.volume_snapshot_info module - Retrieve information about Openstack volume snapshots.

v1.1.0
======

Release Summary
---------------

Starting redesign modules and bugfixes.

Minor Changes
-------------

- A basic module subclass was introduced and a few modules moved to inherit from it.
- Add more useful information from exception
- Added pip installation option for collection.
- Added template for generation of artibtrary module.
- baremetal modules - Do not require ironic_url if cloud or auth.endpoint is provided
- inventory_openstack - Add openstack logger and Ansible display utility
- loadbalancer - Add support for setting the Flavor when creating a load balancer

Bugfixes
--------

- Fix non existing attribuites in SDK exception
- security_group_rule - Don't pass tenant_id for remote group

New Modules
-----------

- openstack.cloud.volume_info - Retrieve information about Openstack volumes.

v1.0.1
======

Release Summary
---------------

Bugfix for server_info

Bugfixes
--------

- server_info - Fix broken server_info module and add tests

v1.0.0
======

Release Summary
---------------

Initial release of collection.

Minor Changes
-------------

- Renaming all modules and removing "os" prefix from names.
- baremetal_node_action - Support json type for the ironic_node config_drive parameter
- config - Update os_client_config to use openstacksdk
- host_aggregate - Add support for not 'purging' missing hosts
- project - Add properties for os_project
- server_action - pass imageRef to rebuild
- subnet - Updated allocation pool checks

Bugfixes
--------

- baremetal_node - Correct parameter name
- coe_cluster - Retrive id/uuid correctly
- federation_mapping - Fixup some minor nits found in followup reviews
- inventory_openstack - Fix constructed compose
- network - Bump minimum openstacksdk version when using os_network/dns_domain
- role_assignment - Fix os_user_role for groups in multidomain context
- role_assignment - Fix os_user_role issue to grant a role in a domain

New Modules
-----------

- openstack.cloud.federation_idp - Add support for Keystone Identity Providers
- openstack.cloud.federation_idp_info - Add support for fetching the information about federation IDPs
- openstack.cloud.federation_mapping - Add support for Keystone mappings
- openstack.cloud.federation_mapping_info - Add support for fetching the information about Keystone mappings
- openstack.cloud.keystone_federation_protocol - Add support for Keystone federation Protocols
- openstack.cloud.keystone_federation_protocol_info - Add support for getting information about Keystone federation Protocols
- openstack.cloud.routers_info - Retrieve information about one or more OpenStack routers.
