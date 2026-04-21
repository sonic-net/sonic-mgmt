===================================
Arista Eos Collection Release Notes
===================================

.. contents:: Topics

v12.0.0
=======

Release Summary
---------------

With this release, the minimum required version of `ansible.netcommon` for this collection is `>=8.1.0`. The last version known to be compatible with `ansible-core<=2.18.x` is ansible.netcommon `v8.0.1` and arista.eos `v11.0.0`.

Major Changes
-------------

- Bumping `dependencies` of ansible.netcommon to `>=8.1.0`, since previous versions of the dependency had compatibility issues with `ansible-core>=2.19`.

Bugfixes
--------

- Add unit and integration tests to verify the change
- Fix regex in route_map module to support match community with or without exact-match
- Update the ACL module to support using protocol names for source port
- arista.eos.eos_interfaces - Improved handling of the `enabled` state to prevent incorrect `shutdown` or `no shutdown` commands during configuration changes

v11.0.1
=======

Bugfixes
--------

- Fix route map community handling to include missing community_attributes level in the dictionary
- Fixed idempotency regarding logging port in differing versions of EOS
- Fixed idempotency when using `replaced` state on host with multiple ACLs present.
- Fixed parsing of relative route-map metric adjustments in when extracting settings from device output.
- Support colon-delimited format in BGP community strings
- Update route_maps to correctly handle ipv6 next-hop address

v11.0.0
=======

Release Summary
---------------

With this release, the minimum required version of `ansible-core` for this collection is `2.16.0`. The last version known to be compatible with `ansible-core` versions below `2.16` is v10.1.1.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.16.0`, since previous ansible-core versions are EoL now.

v10.1.1
=======

Minor Changes
-------------

- Adds a new module `eos_vrf_global` in favor of `eos_vrf` legacy module to manage VRF global configurations on Arista EOS devices.

Bugfixes
--------

- Fixed an issue in the `compare_configs` method where unnecessary negate commands were generated for ACL entries already present in both `have` and `want` configurations.
- Improved validation logic for ACL sequence numbers and content matching to ensure idempotency.
- Prevented redundant configuration updates for Access Control Lists.
- fix facts gathering for ebgp-multihop attribute.

v10.0.1
=======

Bugfixes
--------

- Adds a missing word in the 'bgp client-to-client reflection' command in eos_bgp_global module.
- Fixes a typo in always-compare-med attribute in eos_bgp_global module.
- Handles exception when translating an unknown port to its service name.

Documentation Changes
---------------------

- Includes a new support related section in the README.

v10.0.0
=======

Release Summary
---------------

With this release, the minimum required version of `ansible-core` for this collection is `2.15.0`. The last version known to be compatible with `ansible-core` versions below `2.15` is v9.0.0.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.15.0` due to the end-of-life status of previous `ansible-core` versions.

Bugfixes
--------

- Ensure IPv6 static route definitions are correctly filtered during facts gathering.
- This fix make sure to fetch timer with `lldp` string at the start.
- Update integration tests for parse operations to ensure that ordering or address family (AF) does not affect assertions.
- Update the filter to accurately retrieve relevant static route configurations.

v9.0.0
======

Major Changes
-------------

- Update the netcommon base version 6.1.0 to support cli_restore plugin.

Minor Changes
-------------

- Add support for cli_restore functionality.
- Please refer the PR to know more about core changes (https://github.com/ansible-collections/ansible.netcommon/pull/618).
- cli_restore module is part of netcommon.

v8.0.0
======

Major Changes
-------------

- This release removes previously deprecated modules and attributes from this collection. Please refer to the **Removed Features** section for details.

Removed Features (previously deprecated)
----------------------------------------

- Remove depreacted eos_bgp module which is replaced with eos_bgp_global and eos_bgp_address_family.
- Remove deprecated eos_logging module which is replaced with eos_logging_global resource module.
- Remove deprecated timers.throttle attribute.

v7.1.0
======

Bugfixes
--------

- This fix is needed because static_routes and vlans are not returning anything when resources are not configured.
- This got noticed in this issue (https://github.com/network-automation/toolkit/issues/47)
- correct a missing whitespace and add 'auth' string.
- correct the parsing of the elements in 'name_servers' in 'eos_system' module.
- when static_routes and vlans are not confirgured then return empty list.

Documentation Changes
---------------------

- eos_lag_interface - Updated examples for lag_interface module.

v7.0.0
======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version this collection requires is `2.14.0`. The last known version compatible with ansible-core<2.14 is `v6.2.2`.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.14.0`, since previous ansible-core versions are EoL now.

v6.2.2
======

Bugfixes
--------

- correct the reference of string attribute 'reference_bandwith'.

v6.2.1
======

Release Summary
---------------

Rereleased 6.2.0 with updated galaxy reference.

v6.2.0
======

Minor Changes
-------------

- arista_config - Relax restrictions on I(src) parameter so it can be used more like I(lines).

Bugfixes
--------

- Fix command generated for local-interface with in ntp server attribute.
- Fix command generation for source_interface attribute.
- Fix secondary ip address parsing.
- fix line attribute fact generation and placement in ACE, when ACE is not fully parsed.

Documentation Changes
---------------------

- Fix docs for static_routes and prefix_lists Resource modules.
- eos_interfaces - update examples and use YAML output for better readability.
- eos_l2_interfaces - update examples and use YAML output for better readability.
- eos_l3_interfaces - update examples and use YAML output for better readability.

v6.1.2
======

Bugfixes
--------

- Skip compile testing for python <3.6.

v6.1.1
======

Bugfixes
--------

- fix sanity issues w.r.t python27

v6.1.0
======

Minor Changes
-------------

- Add support for overridden operation in bgp_global resource module.

Documentation Changes
---------------------

- Update bgp examples with yaml callback result
- Update bgp_global examples with yaml callback result
- Update examples for ospfv3
- Update examples with yaml formatted output in ospf_interfaces.
- Update ospf_interfaces examples with yaml callback result
- Update ospfv2 examples with yaml callback result
- Update ospfv3 examples with yaml callback result
- Updateb bgp_address_family examples with yaml callback result

v6.0.1
======

Bugfixes
--------

- fix ntp_global authenticate config.
- https://github.com/ansible-collections/arista.eos/issues/399.

v6.0.0
======

Major Changes
-------------

- Remove following EOS dprecated modules
- Use of connection: local and the provider option are no longer valid on any modules in this collection.
- eos_interface
- eos_l2_interface
- eos_l3_interface
- eos_linkagg
- eos_static_route
- eos_vlan

Minor Changes
-------------

- Add support for setting encryption_password for BGP neighbors in bgp_global module
- Add validate_config option to diff_against in eos_config

v5.0.1
======

Bugfixes
--------

- Add logic to add new interface using overridden.
- Automatiaclly named sessions (ansible_XXXXXXXXX) now use two digits of sub-second precision (if available). This is to work around tasks reusing a session if the previous task completed very quickly.
- Fix the logic to add new aces using replaced and overriden state.
- Normalize interface name from want before comaparing with the interface in have.
- Normalize ntp server source interface.

v5.0.0
======

Major Changes
-------------

- Minimum required ansible.netcommon version is 2.5.1.
- Updated base plugin references to ansible.netcommon.
- `eos_facts` - change default gather_subset to `min` from `!config` (https://github.com/ansible-collections/arista.eos/issues/306).

Breaking Changes / Porting Guide
--------------------------------

- httpapi - the ``eos_use_sessions`` option is now a boolean instead of an integer.

Bugfixes
--------

- Add and fix bgp_global neighbor parsers.
- Fix added to change snmp communities with or without acl.
- Fix parser to parse maximum-paths ecmp command correctly.
- arista.eos.eos_acls - fixed issue that would cause a key value error on `aces` element when no ACEs exist in the access-list.
- arista.eos.eos_acls - fixed issue where protcol_options were rendered to command line using the key _underscore_ value rather than the hyphen nominclature.
- httpapi - detect session support more robustly when ``eos_use_sessions`` is not specified.

v4.1.2
======

Bugfixes
--------

- Add symlink of modules under plugins/action.
- eos_bgp_global - Add alias for peer -  neighbor_address

v4.1.1
======

Bugfixes
--------

- Add check mode support to bgp_global and bgp_address_family
- Add logic to skip unwanted configs from running-config, to collect bgp af facts.
- Fixed an invalid parameter used in example for eos_l2_interfaces

v4.1.0
======

Minor Changes
-------------

- Add eos_hostname resource module.
- eos_acls - Fix examples typos

Bugfixes
--------

- eos_acls - fixes state replaced where new ACEs are not all added

New Modules
-----------

- eos_hostname - Manages hostname resource module

v4.0.0
======

Minor Changes
-------------

- Add eos_snmp_server resource module.

Breaking Changes / Porting Guide
--------------------------------

- eos_command - new suboption ``version`` of parameter ``command``, which controls the JSON response version. Previously the value was assumed to be "latest" for network_cli and "1" for httpapi, but the default will now be "latest" for both connections. This option is also available for use in modules making their own device requests with ``plugins.module_utils.network.eos.eos.run_commands()`` with the same new default behavior. (https://github.com/ansible-collections/arista.eos/pull/258).

New Modules
-----------

- eos_snmp_server - Manages snmp_server resource module

v3.1.0
======

Minor Changes
-------------

- Add eos_ntp_global module.

Deprecated Features
-------------------

- Remove testing with provider for ansible-test integration jobs. This helps prepare us to move to network-ee integration tests.

Bugfixes
--------

- Changed access_group parameter to type list, to enable multiple access-groups configuration.
- Fix logic error while executing replaced and overridden operations on bgp neighbors.
- Fix typo and logic errors in bgp_global, to skip other routing protocol configs from running-config.
- command template fixed supporting Jinja version for centos-8 EEs.

New Modules
-----------

- eos_ntp_global - Manages ntp resource module

v3.0.0
======

Minor Changes
-------------

- Add eos_logging_global resource module.
- Add new keys to vrf->route_target in bgp modules.
- Change cli 'bgp listen limit' to 'dynamic peer max' ( cli changes in eos 4.23 ).
- Fix ospf3 to be ospfv3 in bgp config.
- Update BGP neighbor peer group syntax.

Breaking Changes / Porting Guide
--------------------------------

- Arista released train 4.23.X and newer and along with it replaced and deprecated lots of commands. This PR adds support for syntax changes in release train 4.23 and after. Going forward the eos modules will not support eos sw version < 4.23.

Bugfixes
--------

- Added fix to support multiple keys under ip and ipv6 dict in parser template.
- fix issue in prefix_lists facts code when prefix_lists facts are empty.
- fix issue in route-maps facts code when route-maps facts are empty.

New Modules
-----------

- eos_logging_global - Manages logging resource module

v2.2.0
======

Minor Changes
-------------

- Add eos_prefix_lists resource module.

Bugfixes
--------

- Add alias to neighbor and network in bgp_global so that lists of objects are plural.
- Fix typo in eos_bgp_address_family redirection.

New Modules
-----------

- eos_prefix_lists - Manages Prefix lists resource module

v2.1.2
======

Bugfixes
--------

- Add support to accomodate change in username config cli in latest eos software version.
- Fix regex for password prompt.
- argspec key 'shut_down' changed to 'shutdown'.

v2.1.1
======

Minor Changes
-------------

- Add eos_route_maps resource module.
- Add support for available_network_resources key, which allows to fetch the available resources for a platform (https://github.com/ansible-collections/arista.eos/issues/184).

Security Fixes
--------------

- Mask values of sensitive keys in module result.

Bugfixes
--------

- Modify the split pattern while checking for eapi url in eos_eapi.
- Normalize interface name before any operaion.
- Skip when there are alpha values present following vlan keyword.

v2.0.1
======

Bugfixes
--------

- Add _remove_config before starting every integration test.
- galaxy.yml - change wrong dependency ``ansible.netcommon`` from ``2.0.0`` to ``>= 2.0.0`` (https://github.com/ansible-collections/overview/issues/43).

v2.0.0
======

Major Changes
-------------

- Requires ansible.netcommon v2.0.0+ to support `ansible_network_single_user_mode` and `ansible_network_import_modules` - Please refer to ansible.netcommon `changelog <https://github.com/ansible-collections/ansible.netcommon/blob/main/changelogs/CHANGELOG.rst#ansible-netcommon-collection-release-notes>`_ for more details.

Minor Changes
-------------

- Add support for configuration caching (single_user_mode).
- Add support for syntax changes in ospf bfd command in 4.23 (https://github.com/ansible-collections/arista.eos/pull/134/)
- Move eos_config idempotent warning message with the task response under `warnings` key if `changed` is `True`
- Re-use device_info dictionary in cliconf

Bugfixes
--------

- Add 'virtual' key to denote the existence of virtual address on an interface.(https://github.com/ansible-collections/arista.eos/pull/170).
- Fixed the regex to parse the running config correctly.(https://github.com/ansible-collections/arista.eos/issues/150)
- cliconf plugin - Prevent `get_capabilities()` from getting larger every time it is called

v1.3.0
======

Bugfixes
--------

- Add version key to galaxy.yaml to work around ansible-galaxy bug
- Fix yaml formatting errors in documentation.
- Uncap required ansible version in our collection.
- Update default values in module argspec and docs (https://github.com/ansible-collections/arista.eos/pull/154).
- Update docs to clarify the idemptonecy releated caveat and add it in the output warnings (https://github.com/ansible-collections/ansible.netcommon/pull/189)
- fixes eos interfaces rm where interface in description resulted in failure (https://github.com/ansible-collections/arista.eos/issues/86).
- replace list.copy() with list[:] to support python 2.7  and fix idempotent issue with replaced and overridden (https://github.com/ansible-collections/arista.eos/pull/142).

New Modules
-----------

- eos_bgp_address_family - Manages BGP address family resource module
- eos_bgp_global - Manages BGP global resource module

v1.2.0
======

Minor Changes
-------------

- Added ospf_interfaces resource module. (https://github.com/ansible-collections/arista.eos/pull/125)
- Documented the necessity to use eos_interfaces and eos_l2_interfaces (for l2 configs) in eos_l3_interfaces module.
- modify short description in ospfv3 resource module.
- stop integration testing of local connection as it is deprecated.

Bugfixes
--------

- updated config dict, with duplex key when speed changes from 'x' to 'forced x' (https://github.com/ansible-collections/arista.eos/pull/120).

New Modules
-----------

- eos_ospf_interfaces - OSPF Interfaces Resource Module.

v1.1.0
======

Minor Changes
-------------

- Added 'mode' to examples in documentation of eos_l2_interfaces.
- Added eos ospfv3 resource module (https://github.com/ansible-collections/arista.eos/pull/109).
- Added unit test cases for eos_lldp_global module.

Bugfixes
--------

- Added 'mode' key to eos_interfaces to handle the layer2/3 switchport mode of an interface.
- Added fix to maintain the idempotency while using overridden operation.
- Check for existing configuration when trunk_allowed_vlans is issued, is added.
- Fixed typo and index out of range errors while handling protocol_options. (https://github.com/ansible-collections/arista.eos/pull/115)

New Modules
-----------

- eos_ospfv3 - OSPFv3 resource module

v1.0.3
======

Bugfixes
--------

- Added error pattern to the terminal plugin to handle change mode error seen in lag interfaces config.

v1.0.2
======

v1.0.1
======

Minor Changes
-------------

- Add round trip testcases to the 2.9 resource modules.
- Add unit testcases to the eos_l3_interfaces resource modules.
- Add unit testcases to the eos_lag_interfaces resource modules.
- Sorted the list of params of ip address before forming the tuple.
- Updated docs.

Bugfixes
--------

- Fixes mismatch in documentation and code for using eos_lag_interfaces where the code required 'Port-Channel\d.*:' but the docs did not document this. The module now supports both 'Port-Channel\d.*:' and '\d.*:'.
- Make `src`, `backup` and `backup_options` in eos_config work when module alias is used (https://github.com/ansible-collections/arista.eos/pull/85).

v1.0.0
======

New Plugins
-----------

Cliconf
~~~~~~~

- eos - Use eos cliconf to run command on Arista EOS platform

Httpapi
~~~~~~~

- eos - Use eAPI to run command on eos platform

New Modules
-----------

- eos_acl_interfaces - ACL interfaces resource module
- eos_acls - ACLs resource module
- eos_banner - Manage multiline banners on Arista EOS devices
- eos_command - Run arbitrary commands on an Arista EOS device
- eos_config - Manage Arista EOS configuration sections
- eos_eapi - Manage and configure Arista EOS eAPI.
- eos_facts - Collect facts from remote devices running Arista EOS
- eos_interfaces - Interfaces resource module
- eos_l2_interfaces - L2 interfaces resource module
- eos_l3_interfaces - L3 interfaces resource module
- eos_lacp - LACP resource module
- eos_lacp_interfaces - LACP interfaces resource module
- eos_lag_interfaces - LAG interfaces resource module
- eos_lldp - Manage LLDP configuration on Arista EOS network devices
- eos_lldp_global - LLDP resource module
- eos_lldp_interfaces - LLDP interfaces resource module
- eos_ospfv2 - OSPFv2 resource module
- eos_static_routes - Static routes resource module
- eos_system - Manage the system attributes on Arista EOS devices
- eos_user - Manage the collection of local users on EOS devices
- eos_vlans - VLANs resource module
- eos_vrf - Manage VRFs on Arista EOS network devices
