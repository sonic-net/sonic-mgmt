====================================
Cisco Iosxr Collection Release Notes
====================================

.. contents:: Topics

v12.1.0
=======

Minor Changes
-------------

- Added few parameters to iosxr_l3_interface module to support new features.

v12.0.0
=======

Release Summary
---------------

With this release, the minimum required version of `ansible.netcommon` for this collection is `>=8.1.0`. The last version known to be compatible with `ansible-core<=2.18.x` is ansible.netcommon `v8.0.1` and cisco.iosxr `v11.1.0`.

Major Changes
-------------

- Bumping `dependencies` of ansible.netcommon to `>=8.1.0`, since previous versions of the dependency had compatibility issues with `ansible-core>=2.19`.

Bugfixes
--------

- iosxr_route_map - Fixes route-policy attribute facts gathering.

v11.1.0
=======

Minor Changes
-------------

- Adds support for missing set route map attributes med and extcommunity
- Enhanced CDP neighbor parsing to support updated output formats in IOS-XR 7.7.21 and 7.4.1
- Modified `parse_cdp_ip` to recognize "IPv4 address" in place of "IP address"
- Updated `parse_cdp_intf_port` to handle newline-separated "Interface" and "Port ID" fields

Bugfixes
--------

- Fixes route map fact gathering to correctly gather facts with a elif condition.
- cisco.iosxr.iosxr_interfaces - Improved handling of the `enabled` state to prevent incorrect `shutdown` or `no shutdown` commands during configuration changes.
- iosxr_route_maps - Fix issue where wrong commands were being generated for several attributes.

v11.0.0
=======

Release Summary
---------------

With this release, the minimum required version of `ansible-core` for this collection is `2.16.0`. The last version known to be compatible with `ansible-core` versions below `2.16` is v10.3.1.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.16.0`, since previous ansible-core versions are EoL now.

v10.3.1
=======

Bugfixes
--------

- Fixes a bug to allow connections to IOS XRd with cliconf.
- Fixes idempotency for static routes with encap interfaces

v10.3.0
=======

Minor Changes
-------------

- Added iosxr_vrf_interfaces resource module, that helps with configuration of vrfs within interface.
- Adds support for setting local-preference with plus/minus values in route policies

New Modules
-----------

- iosxr_vrf_interfaces - Resource module to configure VRF interfaces.

v10.2.2
=======

Bugfixes
--------

- iosxr_acls_facts - Fix incorrect rendering of some acl facts causing errors.

v10.2.1
=======

Bugfixes
--------

- iosxr_static_routes - Fix incorrect handling of the vrf keyword between the destination address and next-hop interface in both global and VRF contexts for IPv4 and IPv6 static_route configurations.

v10.2.0
=======

Minor Changes
-------------

- Added iosxr_route_maps resource module, that helps with configuration of route-policy.

Documentation Changes
---------------------

- Includes a new support related section in the README.

New Modules
-----------

- iosxr_route_maps - Resource module to configure route maps.

v10.1.0
=======

Minor Changes
-------------

- Adds a new module `iosxr_vrf_address_family` to manage VRFs address families on Cisco IOS-XR devices (https://github.com/ansible-collections/cisco.iosxr/pull/489).

v10.0.0
=======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version this collection requires is `2.15.0`. The last known version compatible with ansible-core<2.15 is `v9.0.0`. A new resource module `iosxr_vrf_global` is added to manage VRF global configurations.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.15.0`, since previous ansible-core versions are EoL now.

Minor Changes
-------------

- Adds a new module `iosxr_vrf_global` to manage VRF global configurations on Cisco IOS-XR devices (https://github.com/ansible-collections/cisco.iosxr/pull/467).

v9.0.0
======

Major Changes
-------------

- Update the netcommon base version to support cli_restore plugin.

Minor Changes
-------------

- Add support for cli_restore functionality.
- Please refer the PR to know more about core changes (https://github.com/ansible-collections/ansible.netcommon/pull/618).
- cli_restore module is part of netcommon.

v8.0.0
======

Major Changes
-------------

- This release removes previously deprecated module and attributes from this collection. Please refer to the **Removed Features** section for details.

Removed Features (previously deprecated)
----------------------------------------

- Remove deprecated iosxr_logging module which is replaced with iosxr_logging_global resource module.

v7.2.0
======

Minor Changes
-------------

- Add missing options in afi and safi in address-family of bgp_templates RM.

Bugfixes
--------

- Fix 'afi' value in bgp_templates RM to valid values.

v7.1.0
======

Minor Changes
-------------

- iosxr_facts - Add cdp neighbors in ansible_net_neighbors dictionary (https://github.com/ansible-collections/cisco.iosxr/pull/457).

v7.0.0
======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version this collection requires is `2.14.0`. The last known version compatible with ansible-core<2.14 is `v6.1.1`.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.14.0`, since previous ansible-core versions are EoL now.

v6.1.1
======

Bugfixes
--------

- Fix issue in gathered state of interfaces and l3_interfaces RMs(https://github.com/ansible-collections/cisco.iosxr/issues/452, https://github.com/ansible-collections/cisco.iosxr/issues/451)

v6.1.0
======

Minor Changes
-------------

- iosxr_config - Relax restrictions on I(src) parameter so it can be used more like I(lines). (https://github.com/ansible-collections/cisco.iosxr/issues/343).
- iosxr_config Add updates option in return value(https://github.com/ansible-collections/cisco.iosxr/issues/438).

Documentation Changes
---------------------

- Fix docs for prefix_lists RM.
- iosxr_acls - update examples and use YAML output in them for better readibility.

v6.0.1
======

Bugfixes
--------

- Fix issue in deletion of ospf.(https://github.com/ansible-collections/cisco.iosxr/issues/425)
- Fix issue in facts gathering for Interfaces RM.(https://github.com/ansible-collections/cisco.iosxr/issues/417)
- Fix issue in lacp and lldp_global of local variable commands.
- Support overridden state in bgp_global,lacp and lldp_global module.(https://github.com/ansible-collections/cisco.iosxr/issues/386)

Documentation Changes
---------------------

- Fix grpc sub plugin documentation.
- Update ospf_interfaces examples
- Update ospfv2 examples
- Update ospfv3 examples

v6.0.0
======

Minor Changes
-------------

- Add iosxr_bgp_templates module (https://github.com/ansible-collections/cisco.iosxr/issues/341).
- iosxr_facts - Add CPU utilization.
- iosxr_l2_interfaces - fix issue in supporting multiple iosxr version. (https://github.com/ansible-collections/cisco.iosxr/issues/379).

Deprecated Features
-------------------

- Deprecated iosxr_bgp module in favor of iosxr_bgp_global,iosxr_bgp_neighbor_address_family and iosxr_bgp_address_family.
- iosxr_l2_interfaces - deprecate q_vlan with qvlan which allows vlans in str format e.g "any"

Bugfixes
--------

- Add support to delete specific static route entry.(https://github.com/ansible-collections/cisco.iosxr/issues/375)
- l2_interfaces Fix issue in qvlan parsing.(https://github.com/ansible-collections/cisco.iosxr/issues/403)

Documentation Changes
---------------------

- iosxr_facts - Add ansible_net_cpu_utilization.

New Modules
-----------

- iosxr_bgp_templates - Manages BGP templates resource module.

v5.0.3
======

Bugfixes
--------

- Fixing Bundle-Ether/-POS recognition for resource modules. (https://github.com/ansible-collections/cisco.iosxr/issues/369)
- acls - Fix issue in ``replaced`` state of not replacing ace entries with remark action. (https://github.com/ansible-collections/cisco.iosxr/issues/332)
- l3_interfaces - Fix issue in ``gather`` state of not gathering management interface. (https://github.com/ansible-collections/cisco.iosxr/issues/381)

Documentation Changes
---------------------

- iosxr_interfaces - Fixed module documentation and examples.
- iosxr_l3_interfaces - Fixed module documentation and examples.

v5.0.2
======

Bugfixes
--------

- interfaces - Fix issue in ``overridden`` state of interfaces RM. (https://github.com/ansible-collections/cisco.iosxr/issues/377)

Documentation Changes
---------------------

- iosxr_bgp_global - add task output to module documentation examples.

v5.0.1
======

Bugfixes
--------

- Fixing L2 Interface recognition for resource modules. (https://github.com/ansible-collections/cisco.iosxr/issues/366)
- Iosxr_interfaces - Fix issue in interfaces with interface type.

Documentation Changes
---------------------

- Improve docs of static_routes Resource modules.

v5.0.0
======

Major Changes
-------------

- iosxr_l3_interfaces - fix issue in ipv4 address formatting. (https://github.com/ansible-collections/cisco.iosxr/issues/311).

Minor Changes
-------------

- bgp_global - Add ``no_prepend`` option and  ``set`` and ``replace_as`` suboptions under local_as option. (https://github.com/ansible-collections/cisco.iosxr/issues/336)
- bgp_global - Add ``password`` option and  ``encrypted`` and ``inheritance_disable`` suboptions. (https://github.com/ansible-collections/cisco.iosxr/issues/337)
- bgp_global - Add ``use`` option and  ``neighbor_group`` and ``session_group`` suboptions. (https://github.com/ansible-collections/cisco.iosxr/issues/312)

Bugfixes
--------

- Bgp_global, Bgp_neighbor_address_family, Bgp_address_family. Make all possible option mutually exclusive.
- bgp_neighbor_address_family - mark ``soft_reconfiguration`` suboptions ``set``, ``always``, and ``inheritance_disable`` as mutually exclusive. (https://github.com/ansible-collections/cisco.iosxr/issues/325)
- facts - fix ``ansible_net_model`` and ``ansible_net_seriulnum`` facts gathering issue (https://github.com/ansible-collections/cisco.iosxr/issues/308)

v4.1.0
======

Minor Changes
-------------

- iosxr.iosxr_bgp_global - Add missing set option in fast-detect dict of bgp nbr.

Bugfixes
--------

- bgp_global -  Fix neighbor description parser issue.

Documentation Changes
---------------------

- Add valid example in iosxr_command module which will show handling multiple prompts.

v4.0.3
======

Bugfixes
--------

- Fix issue of iosxr_config parellel uploads.
- Support commit confirmed functionality with replace option.

v4.0.2
======

Bugfixes
--------

- requirements: remove google dependency

v4.0.1
======

Bugfixes
--------

- iosxr_bgp_neighbor_address_family - Added alias to render as_overrride under vrfs as as_override.

v4.0.0
======

Major Changes
-------------

- Only valid connection types for this collection are network_cli and netconf.
- This release drops support for `connection: local` and provider dictionary.

Minor Changes
-------------

- iosxr_bgp_neighbor_address_family - add extra supported values l2vpn, link-state, vpnv4, vpnv6 to afi attribute.

Removed Features (previously deprecated)
----------------------------------------

- iosxr_interface - use iosxr_interfaces instead.

Bugfixes
--------

- Fixing model/version facts gathering (https://github.com/ansible-collections/cisco.iosxr/issues/282)

v3.3.1
======

Bugfixes
--------

- Fixing TenGigE Interface recognition for resource modules. (https://github.com/ansible-collections/cisco.iosxr/issues/270)

v3.3.0
======

Minor Changes
-------------

- Add support for grpc connection plugin

Bugfixes
--------

- `iosxr_ping` - Fix regex to parse ping failure correctly.

v3.2.0
======

Minor Changes
-------------

- Add label and comment to commit_confirmed functionality in IOSXR.

Bugfixes
--------

- Fix commit confirmed for IOSXR versions with atomic commands.
- Fix commit confirmed to render proper command without timeout.

v3.1.0
======

Minor Changes
-------------

- `iosxr_ping` - Add iosxr_ping module.

Bugfixes
--------

- Remove irrelevant warning from facts.

v3.0.0
======

Major Changes
-------------

- Minimum required ansible.netcommon version is 2.5.1.
- Updated base plugin references to ansible.netcommon.
- `facts` - default value for `gather_subset` is changed to min instead of !config.

Minor Changes
-------------

- Add new keys ge, eq, le for iosxr_prefix_lists.

Bugfixes
--------

- Fix iosxr_ospfv2 throwing a traceback with gathered (https://github.com/ansible-collections/cisco.iosxr/issues/227).

v2.9.0
======

Minor Changes
-------------

- IOSXR - Fix sanity for missing elements tag under list type attribute.

Bugfixes
--------

- Add symlink of modules under plugins/action.
- `iosxr_snmp_server` - Add aliases for access-lists in snmp-server(https://github.com/ansible-collections/cisco.iosxr/pull/225).
- iosxr_bgp_global - Add alias for neighbor_address (https://github.com/ansible-collections/cisco.iosxr/issues/216)
- iosxr_snmp_server - Fix gather_facts issue in snmp_servers (https://github.com/ansible-collections/cisco.iosxr/issues/215)

v2.8.1
======

Bugfixes
--------

- `iosxr_acls` - fix acl for parsing wrong command on ( num matches ) data

v2.8.0
======

Minor Changes
-------------

- Add commit_confirmed functionality in IOSXR.
- Add disable_default_comment option to disable default comment in iosxr_config module.

v2.7.0
======

Minor Changes
-------------

- `iosxr_hostname` - New Resource module added.

New Modules
-----------

- iosxr_hostname - Resource module to configure hostname.

v2.6.0
======

Minor Changes
-------------

- Add iosxr_snmp_server resource module.
- Added support for keys net_group, port_group to resolve issue with fact gathering against IOS-XR 6.6.3.

Bugfixes
--------

- fix issue of local variable 'start_index' referenced before assignment with cisco.iosxr.iosxr_config.
- iosxr_user - replaced custom paramiko sftp and ssh usage with native "copy_file" and "send_command" functions. Fixed issue when ssh key copying doesn't work with network_cli or netconf plugin by deleting "provider" usage. Fixed improper handling of "No such configuration item" when getting data for username section, without that ansible always tried to delete user "No" when purging if there is no any user in config. Fixed one-line admin mode commands not work anymore for ssh key management on IOS XR Software, Version 7.1.3, and add support of "admin" module property (https://github.com/ansible-collections/cisco.iosxr/pull/15)

Documentation Changes
---------------------

- Update valid docs for iosxr_logging_global and prefix_list

New Modules
-----------

- iosxr_snmp_server - Resource module to configure snmp server.

v2.5.0
======

Minor Changes
-------------

- Added iosxr ntp_global resource module.

Documentation Changes
---------------------

- Update valid deprecation date in bgp module.

v2.4.0
======

Minor Changes
-------------

- Add iosxr_logging_global resource module.

Deprecated Features
-------------------

- The iosxr_logging module has been deprecated in favor of the new iosxr_logging_global resource module and will be removed in a release after '2023-08-01'.

Bugfixes
--------

- fix issue in prefix-lists facts code when prefix-lists facts are empty. (https://github.com/ansible-collections/cisco.iosxr/pull/161)

New Modules
-----------

- iosxr_logging_global - Resource module to configure logging.

v2.3.0
======

Minor Changes
-------------

- Add `iosxr_prefix_lists` resource module.

Bugfixes
--------

- To add updated route policy params to Bgp nbr AF RM
- fix backword compatibility issue for iosxr 6.x.
- fix intermittent issue on CI for iosxr_banner module.
- fix iosxr_config issue for prefix-set,route-policy config
- fix static routes interface parsing issue.

New Modules
-----------

- iosxr_prefix_lists - Resource module to configure prefix lists.

v2.2.0
======

Minor Changes
-------------

- Add new keys for iosxr_l2_interface, iosxr_logging.
- Fix integration tests for iosxr_config, iosxr_smoke,iosxr_facts,iosxr_l2_interfaces,iosxr_lag_interfaces, iosxr_logging,iosxr_user.

Bugfixes
--------

- Add warning when comment is not supported by IOSXR.
- Fix issue of commit operation which was not failing for invalid inputs.

v2.1.0
======

Minor Changes
-------------

- Add support for available_network_resources key, which allows to fetch the available resources for a platform (https://github.com/ansible-collections/cisco.iosxr/issues/119).
- Update psudo-atomic operation scenario tests with correct assertion.

Bugfixes
--------

- Avoid using default value for comment for iosxr version > 7.2(Module=iosxr_config)
- Avoid using default value for comment when "comment is not supported" by device.

v2.0.2
======

Bugfixes
--------

- For versions >=2.0.1, this collection requires ansible.netcommon >=2.0.1.
- Re-releasing this collection with ansible.netcommon dependency requirements updated.

v2.0.1
======

Security Fixes
--------------

- Properly mask values of sensitive keys in module result.

Bugfixes
--------

- Add fix for interfaces which are not in running config should get merged when state is merged. (https://github.com/ansible-collections/cisco.iosxr/issues/106)
- Update valid hostname info in iosxr_facs using show running-conf hostname command. (https://github.com/ansible-collections/cisco.iosxr/issues/103)

v2.0.0
======

Major Changes
-------------

- Please refer to ansible.netcommon `changelog <https://github.com/ansible-collections/ansible.netcommon/blob/main/changelogs/CHANGELOG.rst#ansible-netcommon-collection-release-notes>`_ for more details.
- Requires ansible.netcommon v2.0.0+ to support `ansible_network_single_user_mode` and `ansible_network_import_modules`.
- ipaddress is no longer in ansible.netcommon. For Python versions without ipaddress (< 3.0), the ipaddress package is now required.

Minor Changes
-------------

- Add iosxr_bgp_address_family resource module (https://github.com/ansible-collections/cisco.iosxr/pull/105.).
- Add iosxr_bgp_global resource module (https://github.com/ansible-collections/cisco.iosxr/pull/101.).
- Add iosxr_bgp_neighbor_address_family resource module (https://github.com/ansible-collections/cisco.iosxr/pull/107.).
- Add missing examples for bgp_address_family module.
- Add support for single_user_mode.
- Fix integration testcases for bgp_address_family and bgp_neighbor_address_family.
- Fix issue in delete state in bgp_address_family (https://github.com/ansible-collections/cisco.iosxr/pull/109).
- Move iosxr_config idempotent warning message with the task response under `warnings` key if `changed` is `True`
- Re-use device_info dict instead of building it every time.

Bugfixes
--------

- Fix to accurately report configuration failure during pseudo-atomic operation fior iosxr-6.6.3 (https://github.com/ansible-collections/cisco.iosxr/issues/92).

New Modules
-----------

- iosxr_bgp_address_family - Resource module to configure BGP Address family.
- iosxr_bgp_global - Resource module to configure BGP.
- iosxr_bgp_neighbor_address_family - Resource module to configure BGP Neighbor Address family.

v1.2.1
======

Bugfixes
--------

- Update docs to clarify the idemptonecy releated caveat and add it in the output warnings (https://github.com/ansible-collections/ansible.netcommon/pull/189)

v1.2.0
======

Minor Changes
-------------

- Added iosxr ospf_interfaces resource module (https://github.com/ansible-collections/cisco.iosxr/pull/84).

Bugfixes
--------

- Add version key to galaxy.yaml to work around ansible-galaxy bug
- Fix iosxr_acls throwing a traceback with overridden (https://github.com/ansible-collections/cisco.iosxr/issues/87).
- require one to specify a banner delimiter in order to fix a timeout when using multi-line strings

New Modules
-----------

- iosxr_ospf_interfaces - Resource module to configure OSPF interfaces.

v1.1.0
======

Minor Changes
-------------

- Added iosxr ospfv3 resource module (https://github.com/ansible-collections/cisco.iosxr/pull/81).
- Platform supported coments token to be provided when invoking the object.

New Modules
-----------

- iosxr_ospfv3 - Resource module to configure OSPFv3.

v1.0.5
======

Bugfixes
--------

- Confirmed commit fails with TypeError in IOS XR netconf plugin (https://github.com/ansible-collections/cisco.iosxr/issues/74)
- running config data for interface split when substring interface starts with newline

v1.0.4
======

Release Summary
---------------

Rereleased 1.0.3 with updated changelog.

v1.0.3
======

Release Summary
---------------

Rereleased 1.0.2 with regenerated documentation.

v1.0.2
======

Bugfixes
--------

- Make `src`, `backup` and `backup_options` in iosxr_config work when module alias is used (https://github.com/ansible-collections/cisco.iosxr/pull/63).
- Makes sure that docstring and argspec are in sync and removes sanity ignores (https://github.com/ansible-collections/cisco.iosxr/pull/62).
- Update docs after sanity fixes to modules.

v1.0.1
======

Minor Changes
-------------

- Bring plugin table to correct position (https://github.com/ansible-collections/cisco.iosxr/pull/44)

v1.0.0
======

New Plugins
-----------

Cliconf
~~~~~~~

- iosxr - Use iosxr cliconf to run command on Cisco IOS XR platform

Netconf
~~~~~~~

- iosxr - Use iosxr netconf plugin to run netconf commands on Cisco IOSXR platform

New Modules
-----------

- iosxr_acl_interfaces - Resource module to configure ACL interfaces.
- iosxr_acls - Resource module to configure ACLs.
- iosxr_banner - Module to configure multiline banners.
- iosxr_command - Module to run commands on remote devices.
- iosxr_config - Module to manage configuration sections.
- iosxr_facts - Module to collect facts from remote devices.
- iosxr_interfaces - Resource module to configure interfaces.
- iosxr_l2_interfaces - Resource Module to configure L2 interfaces.
- iosxr_l3_interfaces - Resource module to configure L3 interfaces.
- iosxr_lacp - Resource module to configure LACP.
- iosxr_lacp_interfaces - Resource module to configure LACP interfaces.
- iosxr_lag_interfaces - Resource module to configure LAG interfaces.
- iosxr_lldp_global - Resource module to configure LLDP.
- iosxr_lldp_interfaces - Resource module to configure LLDP interfaces.
- iosxr_netconf - Configures NetConf sub-system service on Cisco IOS-XR devices
- iosxr_ospfv2 - Resource module to configure OSPFv2.
- iosxr_static_routes - Resource module to configure static routes.
- iosxr_system - Module to manage the system attributes.
- iosxr_user - Module to manage the aggregates of local users.
