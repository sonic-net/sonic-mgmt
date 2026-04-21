=============================
Vyos Collection Release Notes
=============================

.. contents:: Topics

v6.0.0
======

Release Summary
---------------

This is the first significant release from the VyOS community for these modules.
This release is focussed on 1.3+ of VyOS and will be the last major release to
support 1.3 fully. Although efforts have been made to maintain compatibility
with the existing vyos collection modules, there have  breaking changes where
necessary to configuration parameters. Please review all changes carefully before updating.

Major Changes
-------------

- bgp modules - Added support for 1.4+ "system-as". 1.3 embedded as_number is still supported
- vyos bgp modules - Many configuration attributes moved from `bgp_global` to `bgp_address_family` module (see documentation).
- vyos_bgp_address_family - Aligned with version 1.3+ configuration - aggregate_address, maximum_paths, network, and redistribute moved from `bgp_global` module. These are now Address-family specific. Many neighbor attributes also moved from `vyos_bgp_global` to `vyos_bgp_address_family` module.
- vyos_bgp_global - Aligned with version 1.3+ configuration - aggregate_address, maximum_paths, network, and redistribute Removed to `bgp_address_family` module.
- vyos_user - add support for encrypted password specification
- vyos_user - add support for public-key authentication

Minor Changes
-------------

- README.md - Add Communication section with Forum information.
- vyos_bgp_address_family - Redistribute, network stanza - added support for modifiers (metric, backdoor etc as per T6829)
- vyos_bgp_global - Added support for `solo` neighbor attribute
- vyos_config - block get_config call if match is set to "none"
- vyos_facts - added `network_os_major_version` to facts
- vyos_firewall_global - Added support for input, output, and forward chains (1.4+)
- vyos_firewall_global - Added support for log-level in state-policy (1.4+)
- vyos_firewall_global - with 1.4+, use the the global keyword to define global firewall rules
- vyos_firewall_interfaces - added support for VIF interfaces
- vyos_firewall_interfaces - enable support for 1.4 firewall
- vyos_firewall_interfaces - expanded firewall interface types to match existing types
- vyos_firewall_rules - Add support for diff mode for rulesets
- vyos_firewall_rules - Added support for 1.4+ firewall rules
- vyos_firewall_rules - Fixed comparing of firewall rules
- vyos_firewall_rules - added support for 1.5+ firewall `match-ipsec-in`, `match-ipsec-out`, `match-none-in`, `match-none-out`
- vyos_firewall_rules - added support for packet-length-exclude for 1.4+ and the states
- vyos_l3_interfaces - make l3_interfaces pick up loopback interfaces
- vyos_lldp_global -  address is now addresses, with appropriate coercion for existing address keys
- vyos_ntp_global - Added ntp options for 1.5+ (interleave, ptp)
- vyos_ntp_global - Added support for VyOS 1.4+ (chronyd vs ntpd)
- vyos_ntp_global - Added syntax for allow_client in 1.4+
- vyos_ospf_interaces - support for 1.4 ospf interfaces
- vyos_ospf_interfaces - add support for VyOS 1.3- virtual interfaces
- vyos_ospf_interfaces - add support for VyOS 1.4+, which moved interface configuration from the interfaces to ospf/ospfv3 interfaces configuration
- vyos_route_maps - add support for as-path-prepend policy option

Breaking Changes / Porting Guide
--------------------------------

- Removed `vyos_logging`. Use `vyos_logging_global` instead.
- lldp_global - if "address" is available, merge will cause it to be added, in contrast to the previous behavior where it was replaced. When used in replace mode, it will remove any existing addresses and replace them with the new one.
- vyos_bgp_address_family - Support for 1.3+ VyOS only
- vyos_bgp_global - Support for 1.3+ VyOS only
- vyos_firewall_rules - removed p2p options as they have been removed prior to 1.3 of VyOS
- vyos_firewall_rules - tcp.flags is now a list with an inversion flag to support 1.4+ firewall rules, but still supports 1.3-
- vyos_lldp_global - civic_address is no longer a valid key (removed prior to 1.3)
- vyos_logging_global - For 1.4, `protocol` is an attribute of the syslog host, not the facility
- vyos_snmp_server - no longer works with versions prior to 1.3
- vyos_snmp_server - parameter `engine_id` is no longer a `user` or `trap_target` parameter and is now a `snmp_v3` parameter
- vyos_snmp_server - parameters `encrypted-key` and `plaintext-key` are now `encrypted-password` and `plaintext-password`
- vyos_user - explicit support for version 1.3+ only
- vyos_user - removed level (and its alias, role) they were removed in 1.3

Deprecated Features
-------------------

- vyos_bgp_global - no_ipv4_unicast - deprecated for use with VyOS 1.4+, use `ipv4_unicast` instead
- vyos_firewall_interfaces - deprecated for use with VyOS 1.4+, firewalls are no longer connected directly to interfaces. See the Firewall Configuration documentation for how to establish a connection betwen the firewall rulesets and the flow, interface, or zone.
- vyos_lldp_global - `address` is deprecated, use `addresses` instead. To be removed in 7.0.0.
- vyos_logging_global - `protocol` is deprecated for 1.4 and later, use `facility` instead. To be removed in next major version where supprot for 1.3 is removed

Bugfixes
--------

- vyos_config - Fix change detection for recent Vyos versions
- vyos_firewall_global - Fix removing last member of a firewall group.
- vyos_firewall_global - Fixed ipv6 route-redirects and tests
- vyos_firewall_global - Fixed parsing of global-options (1.4+)
- vyos_firewall_global - Fixed state-policy deletion (partial and full)
- vyos_firewall_global - fixed behavior for stanzas processing by facts in 1.4+ (e.g. present/absent stanza vs enable/disable)
- vyos_firewall_global - fixed the facts parsers to include state-policies, redirect
- vyos_firewall_rules - Allow deleting of firewall description.
- vyos_firewall_rules - Fix limit parameter processing
- vyos_firewall_rules - fixed behavior for log, disable attributes
- vyos_firewall_rules - fixed behavior for override and replaced states
- vyos_interfaces - fixed bug where 'replace' would delete an active disable and not reinstate it
- vyos_interfaces - fixed over-zealous handling of disable, which could catch other interface items that are disabled.
- vyos_l3_interfaces - fix delete in interfaces to remove vif completely if in affected interface
- vyos_l3_interfaces - fix override in interfaces to remove vif completely if not present in new config
- vyos_l3_interfaces - fix replace in interfaces to remove vif completely if not present in new config
- vyos_logging_global - Fixed v1.3 and before when `protocol` and `level` were set for the same host
- vyos_ospf_interfaces - fixed get_config to cater for unordered command lists in 1.4+
- vyos_ospfv2 - passive-interface processing for 1.3- and 1.4+
- vyos_ospfv3 - added support for adding interfaces to areas
- vyos_static routes - fixed the facts, argspecs, config to include interface-routes
- vyos_user - fix handling of `full-name` in parser and module

Known Issues
------------

- existing code for 1.3 facility protocol and facility level are not compatible, only one will be set and level is the priority.

Documentation Changes
---------------------

- Update module documentation to reflect 1.4+ support

v5.0.0
======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version that this collection requires is `2.15.0`. The last known version compatible with ansible-core<2.15 is v4.1.0.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.15.0`, since previous ansible-core versions are EoL now.

Minor Changes
-------------

- All GHA workflows have been updated to use ones from ansible-content-actions.
- Passes latest ansible-lint with production profile.
- Removes deprecation notice for vyos.vyos.
- Uncaps supported ansible-core versions, this collection now supports ansible-core>=2.15.

v4.1.0
======

Minor Changes
-------------

- vyos-l3_interface_support - Add support for Tunnel, Bridge and Dummy interfaces. (https://github.com/ansible-collections/vyos.vyos/issues/265)

Bugfixes
--------

- vyos-l3_interface_facts - fixed error when using no-default-link-local option. (https://github.com/ansible-collections/vyos.vyos/issues/295)

v4.0.2
======

Bugfixes
--------

- bgp_global - changed to use `neighbor.password` rather than `neighbor.address` (https://github.com/ansible-collections/vyos.vyos/issues/304).

Documentation Changes
---------------------

- vyos_interfaces - Updated documentation with examples and task output.

v4.0.1
======

Bugfixes
--------

- vyos_command - Run commands at least once even when retries is set to 0 (https://github.com/ansible-collections/cisco.nxos/issues/607).

v4.0.0
======

Major Changes
-------------

- Use of connection: local and the provider option are no longer valid on any modules in this collection.

Minor Changes
-------------

- Update fact gathering to support v1.3 show version output

Removed Features (previously deprecated)
----------------------------------------

- vyos_interface - use vyos_interfaces instead.
- vyos_l3_interface - use vyos_l3_interfaces instead.
- vyos_linkagg - use vyos_lag_interfaces instead.
- vyos_lldp - use vyos_lldp_global instead.
- vyos_lldp_interface - use vyos_lldp_interfaces instead.
- vyos_static_route - use vyos_static_routes instead.

v3.0.1
======

Minor Changes
-------------

- firewall_rules - icmpv6 type - add support for vyos sw >= 1.4.

v3.0.0
======

Major Changes
-------------

- Minimum required ansible.netcommon version is 2.5.1.
- Updated base plugin references to ansible.netcommon.
- `vyos_facts` - change default gather_subset to `min` from `!config` (https://github.com/ansible-collections/vyos.vyos/issues/231).

Minor Changes
-------------

- Change preconfig hostname from vyos to vyosuser

Bugfixes
--------

- Add symlink of modules under plugins/action

v2.8.0
======

Minor Changes
-------------

- Add vyos_hostname resource module.
- Rename V4-EGRESS/V6-EGRESS to EGRESS in the tests to test the same-name situation
- Update vyos_facts to support IPv4 and IPv6 rule sets having the same name
- Update vyos_firewall_rules to support IPv4 and IPv6 rule sets having the same name
- vyos_firewall_rules - Add support for log enable on individual rules
- vyos_firewall_rules - fixed incorrect option 'disabled' passed to the rules.

New Modules
-----------

- vyos_hostname - Manages hostname resource module

v2.7.0
======

Major Changes
-------------

- Add 'pool' as value to server key in ntp_global.

Minor Changes
-------------

- Add vyos_snmp_server resource module.

New Modules
-----------

- vyos_snmp_server - Manages snmp_server resource module

v2.6.0
======

Minor Changes
-------------

- Add vyos_ntp Resource Module
- Adds support for specifying an `afi` for an `address_group` for `vyos.vyos.firewall_global`.  As a result, `address_group` now supports IPv6.
- Adds support for specifying an `afi` for an `network_group` for `vyos.vyos.firewall_global`.  As a result, `network_group` now supports IPv6.

Bugfixes
--------

- Fix vyos_firewall_rules with state replaced to only replace the specified rules.

v2.5.1
======

Bugfixes
--------

- fix issue in firewall rules facts code when IPV6 ICMP type name in vyos.vyos.vyos_firewall_rules is not idempotent

v2.5.0
======

Minor Changes
-------------

- vyos_logging_global logging resource module.

Deprecated Features
-------------------

- The vyos_logging module has been deprecated in favor of the new vyos_logging_global resource module and will be removed in a release after "2023-08-01".

Bugfixes
--------

- fix issue in route-maps facts code when route-maps facts are empty.

v2.4.0
======

Minor Changes
-------------

- Add vyos_prefix_lists Resource Module.

New Modules
-----------

- vyos_prefix_lists - Prefix-Lists resource module for VyOS

v2.3.1
======

Bugfixes
--------

- Fix KeyError 'source' - vyos_firewall_rules
- Updated docs resolving spelling typos
- change interface to next-hop-interface while generating static_routes nexthop command.

v2.3.0
======

Minor Changes
-------------

- Add vyos_route_maps resource module (https://github.com/ansible-collections/vyos.vyos/pull/156.).

Bugfixes
--------

- change admin_distance to distance while generating static_routes nexthop command.
- firewall_global - port-groups were not added (https://github.com/ansible-collections/vyos.vyos/issues/107)

New Modules
-----------

- vyos_route_maps - Route Map Resource Module.

v2.2.0
======

Minor Changes
-------------

- Add support for available_network_resources key, which allows to fetch the available resources for a platform (https://github.com/ansible-collections/vyos.vyos/issues/138).

Security Fixes
--------------

- Mask values of sensitive keys in module result.

v2.1.0
======

Minor Changes
-------------

- Add regex for delete failures to terminal_stderr_re
- Add vyos BGP address_family resource module (https://github.com/ansible-collections/vyos.vyos/pull/132).
- Enabled addition and parsing of wireguard interface.

New Modules
-----------

- vyos_bgp_address_family - BGP Address Family Resource Module.

v2.0.0
======

Major Changes
-------------

- Please refer to ansible.netcommon `changelog <https://github.com/ansible-collections/ansible.netcommon/blob/main/changelogs/CHANGELOG.rst#ansible-netcommon-collection-release-notes>`_ for more details.
- Requires ansible.netcommon v2.0.0+ to support `ansible_network_single_user_mode` and `ansible_network_import_modules`
- ipaddress is no longer in ansible.netcommon. For Python versions without ipaddress (< 3.0), the ipaddress package is now required.

Minor Changes
-------------

- Add support for configuration caching (single_user_mode).
- Add vyos BGP global resource module.(https://github.com/ansible-collections/vyos.vyos/pull/125).
- Re-use device_info dictionary in cliconf.

Bugfixes
--------

- Update docs to clarify the idemptonecy related caveat and add it in the output warnings (https://github.com/ansible-collections/ansible.netcommon/pull/189)
- cliconf plugin - Prevent `get_capabilities()` from getting larger every time it is called

New Modules
-----------

- vyos_bgp_global - BGP Global Resource Module.

v1.1.1
======

Bugfixes
--------

- Add version key to galaxy.yaml to work around ansible-galaxy bug
- Enable configuring an interface which is not present in the running config.
- vyos_config - Only process src files as commands when they actually contain commands. This fixes an issue were the whitespace preceding a configuration key named 'set' was stripped, tripping up the parser.

v1.1.0
======

Minor Changes
-------------

- Added ospf_interfaces resource module.

New Modules
-----------

- vyos_ospf_interfaces - OSPF Interfaces Resource Module.

v1.0.5
======

Bugfixes
--------

- Added openvpn vtu interface support.
- Update network integration auth timeout for connection local.
- terminal plugin - Overhaul ansi_re to remove more escape sequences

v1.0.4
======

Minor Changes
-------------

- Moved intent testcases from integration suite to unit tests.
- Reformatted files with latest version of Black (20.8b1).

v1.0.3
======

v1.0.2
======

Minor Changes
-------------

- Fixed the typo in the modulename of ospfv2 and ospfv3 unit tests.
- Updated docs.
- terminal plugin - Added additional escape sequence to be removed from terminal output.

Bugfixes
--------

- Added workaround to avoid set_fact dynamically assigning value. This behavior seems to have been broken after ansible2.9.
- Make `src`, `backup` and `backup_options` in vyos_config work when module alias is used (https://github.com/ansible-collections/vyos.vyos/pull/67).
- vyos_config - fixed issue where config could be saved while in check mode (https://github.com/ansible-collections/vyos.vyos/pull/53)

v1.0.1
======

Minor Changes
-------------

- Add doc plugin fixes (https://github.com/ansible-collections/vyos.vyos/pull/51)

v1.0.0
======

New Plugins
-----------

Cliconf
~~~~~~~

- vyos - Use vyos cliconf to run command on VyOS platform

New Modules
-----------

- vyos_banner - Manage multiline banners on VyOS devices
- vyos_command - Run one or more commands on VyOS devices
- vyos_config - Manage VyOS configuration on remote device
- vyos_facts - Get facts about vyos devices.
- vyos_firewall_global - FIREWALL global resource module
- vyos_firewall_interfaces - FIREWALL interfaces resource module
- vyos_firewall_rules - FIREWALL rules resource module
- vyos_interfaces - Interfaces resource module
- vyos_l3_interfaces - L3 interfaces resource module
- vyos_lag_interfaces - LAG interfaces resource module
- vyos_lldp_global - LLDP global resource module
- vyos_lldp_interfaces - LLDP interfaces resource module
- vyos_logging - Manage logging on network devices
- vyos_ospfv2 - OSPFv2 resource module
- vyos_ospfv3 - OSPFV3 resource module
- vyos_ping - Tests reachability using ping from VyOS network devices
- vyos_static_routes - Static routes resource module
- vyos_system - Run `set system` commands on VyOS devices
- vyos_user - Manage the collection of local users on VyOS device
- vyos_vlan - Manage VLANs on VyOS network devices
