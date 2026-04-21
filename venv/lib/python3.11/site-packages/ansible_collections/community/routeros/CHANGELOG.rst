================================
Community RouterOS Release Notes
================================

.. contents:: Topics

v3.14.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info, api_modify - add missing attribute ``radsec-timeout`` for the ``radius`` path which exists since RouterOS version 7.19.6 (https://github.com/ansible-collections/community.routeros/pull/412).
- api_info, api_modify - add support for path ``interface dot1x client`` (https://github.com/ansible-collections/community.routeros/pull/414).
- api_info, api_modify - add support for path ``interface dot1x server`` (https://github.com/ansible-collections/community.routeros/pull/413).
- api_info, api_modify - add support for paths ``ip hotspot``, ``ip hotspot profile``, ``ip hotspot user``, ``ip hotspot user profile``, ``ip hotspot walled-garden``, and ``ip hotspot walled-garden ip`` (https://github.com/ansible-collections/community.routeros/pull/418).
- api_info, api_modify - allow the ``fib`` parameter to be disabled for the ``routing table`` path (https://github.com/ansible-collections/community.routeros/issues/368, https://github.com/ansible-collections/community.routeros/pull/417).
- api_info, api_modify - remove primary key constraint on 'peer' for path ``ip ipsec identity`` (https://github.com/ansible-collections/community.routeros/pull/421).

Bugfixes
--------

- api_modify, api_info - in the ``routing bgp connection`` and ``bgp templates`` paths, fix spelling of the ``output.remove-private-as`` parameter (https://github.com/ansible-collections/community.routeros/issues/415, https://github.com/ansible-collections/community.routeros/pull/416).
- api_modify, api_info - in the ``routing bgp instance`` path, fix 'Cannot add new entry to this path' error (https://github.com/ansible-collections/community.routeros/issues/409, https://github.com/ansible-collections/community.routeros/pull/420).
- api_modify, api_info - in the ``routing bgp templates`` path, remove ``address-families`` for RouterOS 7.19+ (https://github.com/ansible-collections/community.routeros/issues/415, https://github.com/ansible-collections/community.routeros/pull/416).
- api_modify, api_info - in the ``routing bgp templates`` path, remove ``router-id`` for RouterOS 7.20+ (https://github.com/ansible-collections/community.routeros/issues/415, https://github.com/ansible-collections/community.routeros/pull/416).
- api_modify, api_info - in the ``routing bgp templates`` path, support ``afi`` (RouterOS 7.19+) (RouterOS 7.19 and before) (https://github.com/ansible-collections/community.routeros/issues/415, https://github.com/ansible-collections/community.routeros/pull/416).

v3.13.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_modify - add ``vrf`` for ``snmp`` with a default of ``main`` for RouterOS 7.3 and newer (https://github.com/ansible-collections/community.routeros/pull/411).

v3.12.1
=======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Fix accidental type extensions (https://github.com/ansible-collections/community.routeros/pull/406).

v3.12.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_modify - add ``vrf`` for ``system logging action`` with a default of ``main`` for RouterOS 7.19 and newer (https://github.com/ansible-collections/community.routeros/pull/401).
- api_modify, api_info - field ``instance`` in ``routing bgp connection`` path is required, and ``router-id`` has been moved to ``routing bgp instance`` by RouterOS 7.20 and newer (https://github.com/ansible-collections/community.routeros/pull/404).
- api_modify, api_info - support for field ``new-priority`` in API path ``ipv6 firewall mangle``` (https://github.com/ansible-collections/community.routeros/pull/402).

Bugfixes
--------

- Avoid using ``ansible.module_utils.six`` to avoid deprecation warnings with ansible-core 2.20 (https://github.com/ansible-collections/community.routeros/pull/405).

v3.11.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_find_and_modify, api_modify - instead of comparing supplied values as-is to values retrieved from the API and converted to some types (int, bool) by librouteros, instead compare values by converting them to strings first, using similar conversion rules that librouteros uses (https://github.com/ansible-collections/community.routeros/issues/389, https://github.com/ansible-collections/community.routeros/issues/370, https://github.com/ansible-collections/community.routeros/issues/325, https://github.com/ansible-collections/community.routeros/issues/169, https://github.com/ansible-collections/community.routeros/pull/397).

Bugfixes
--------

- api - allow querying for keys containing ``id``, as long as the key itself is not ``id`` (https://github.com/ansible-collections/community.routeros/issues/396, https://github.com/ansible-collections/community.routeros/pull/398).

v3.10.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info, api_modify - add ``show-at-cli-login`` property in ``system note`` (https://github.com/ansible-collections/community.routeros/pull/392).
- api_info, api_modify - set default value for ``include`` and ``exclude`` properties in ``system note`` to an empty string (https://github.com/ansible-collections/community.routeros/pull/394).

Bugfixes
--------

- api_facts - also report interfaces that are inferred only by reference by IP addresses.
  RouterOS's APIs have IPv4 and IPv6 addresses point at interfaces by their name, which can
  change over time and in-between API calls, such that interfaces may have been enumerated
  under another name, or not at all (for example when removed). Such interfaces are now reported
  under their new or temporary name and with a synthetic ``type`` property set to differentiate
  the more likely and positively confirmed removal case (with ``type: "ansible:unknown"``) from
  the unlikely and probably transient naming mismatch (with ``type: "ansible:mismatch"``).
  Previously, the api_facts module would have crashed with a ``KeyError`` exception
  (https://github.com/ansible-collections/community.routeros/pull/391).

v3.9.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info, api modify - add ``remote-log-format``, ``remote-protocol``, and ``event-delimiter`` to ``system logging action`` (https://github.com/ansible-collections/community.routeros/pull/381).
- api_info, api_modify - add ``disable-link-local-address`` and ``stale-neighbor-timeout`` fields to ``ipv6 settings`` (https://github.com/ansible-collections/community.routeros/pull/380).
- api_info, api_modify - adjust neighbor limit fields in ``ipv6 settings`` to match RouterOS 7.18 and newer (https://github.com/ansible-collections/community.routeros/pull/380).
- api_info, api_modify - set ``passthrough`` default in ``ip firewall mangle`` to ``true`` for RouterOS 7.19 and newer (https://github.com/ansible-collections/community.routeros/pull/382).
- api_info, api_modify - since RouterOS 7.17 VRF is supported for OVPN server. It now supports multiple entries, while ``api_modify`` so far only accepted a single entry. The ``interface ovpn-server server`` path now allows multiple entries on RouterOS 7.17 and newer (https://github.com/ansible-collections/community.routeros/pull/383).

Bugfixes
--------

- routeros terminal plugin - fix ``terminal_stdout_re`` pattern to handle long system identities when connecting to RouterOS through SSH (https://github.com/ansible-collections/community.routeros/pull/386).

v3.8.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- facts and api_facts modules - prevent deprecation warnings when used with ansible-core 2.19 (https://github.com/ansible-collections/community.routeros/pull/384).

v3.8.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add ``interface ethernet switch port-isolation`` which is supported since RouterOS 6.43 (https://github.com/ansible-collections/community.routeros/pull/375).
- api_info, api_modify - add ``routing bfd configuration``. Officially stabilized BFD support for BGP and OSPF is available since RouterOS 7.11
  (https://github.com/ansible-collections/community.routeros/pull/375).
- api_modify, api_info - support API path ``ip ipsec mode-config`` (https://github.com/ansible-collections/community.routeros/pull/376).

v3.7.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_find_and_modify - allow to control whether ``dynamic`` and/or ``builtin`` entries are ignored with the new ``ignore_dynamic`` and ``ignore_builtin`` options (https://github.com/ansible-collections/community.routeros/issues/372, https://github.com/ansible-collections/community.routeros/pull/373).
- api_info, api_modify - add ``port-cost-mode`` to ``interface bridge`` which is supported since RouterOS 7.13 (https://github.com/ansible-collections/community.routeros/pull/371).

v3.6.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add ``mdns-repeat-ifaces`` to ``ip dns`` for RouterOS 7.16 and newer (https://github.com/ansible-collections/community.routeros/pull/358).
- api_info, api_modify - field name change in ``routing bgp connection`` path implemented by RouterOS 7.19 and newer (https://github.com/ansible-collections/community.routeros/pull/360).
- api_info, api_modify - rename ``is-responder`` property in ``interface wireguard peers`` to ``responder`` for RouterOS 7.17 and newer (https://github.com/ansible-collections/community.routeros/pull/364).

v3.5.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - change default for ``/ip/cloud/ddns-enabled`` for RouterOS 7.17 and newer from ``yes`` to ``auto`` (https://github.com/ansible-collections/community.routeros/pull/350).

v3.4.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- api_info, api_modify - add support for the ``ip dns forwarders`` path implemented by RouterOS 7.17 and newer (https://github.com/ansible-collections/community.routeros/pull/343).

Bugfixes
--------

- api_info, api_modify - remove the primary key ``action`` from the ``interface wifi provisioning`` path, since RouterOS also allows to create completely duplicate entries (https://github.com/ansible-collections/community.routeros/issues/344, https://github.com/ansible-collections/community.routeros/pull/345).

v3.3.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add missing attribute ``require-message-auth`` for the ``radius`` path which exists since RouterOS version 7.15 (https://github.com/ansible-collections/community.routeros/issues/338, https://github.com/ansible-collections/community.routeros/pull/339).
- api_info, api_modify - add the ``interface 6to4`` path. Used to manage IPv6 tunnels via tunnel-brokers like HE, where native IPv6 is not provided (https://github.com/ansible-collections/community.routeros/pull/342).
- api_info, api_modify - add the ``interface wireless access-list`` and ``interface wireless connect-list`` paths (https://github.com/ansible-collections/community.routeros/issues/284, https://github.com/ansible-collections/community.routeros/pull/340).
- api_info, api_modify - add the ``use-interface-duid`` option for ``ipv6 dhcp-client`` path. This option prevents issues with Fritzbox modems and routers, when using virtual interfaces (like VLANs) may create duplicated records in hosts config, this breaks original "expose-host" function. Also add the ``script``, ``custom-duid`` and ``validate-server-duid`` as backport from 7.15 version update (https://github.com/ansible-collections/community.routeros/pull/341).

v3.2.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add support for the ``routing filter community-list`` path implemented by RouterOS 7 and newer (https://github.com/ansible-collections/community.routeros/pull/331).

v3.1.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info, api_modify - add missing fields ``comment``, ``next-pool`` to ``ip pool`` path (https://github.com/ansible-collections/community.routeros/pull/327).

Bugfixes
--------

- api_info, api_modify - fields ``log`` and ``log-prefix`` in paths ``ip firewall filter``, ``ip firewall mangle``, ``ip firewall nat``, ``ip firewall raw`` now have the correct default values (https://github.com/ansible-collections/community.routeros/pull/324).

v3.0.0
======

Release Summary
---------------

Major release that drops support for End of Life Python versions and fixes check mode for community.routeros.command.

Breaking Changes / Porting Guide
--------------------------------

- command - the module no longer declares that it supports check mode (https://github.com/ansible-collections/community.routeros/pull/318).

Removed Features (previously deprecated)
----------------------------------------

- The collection no longer supports Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, and ansible-core 2.14. If you need to continue using End of Life versions of Ansible/ansible-base/ansible-core, please use community.routeros 2.x.y (https://github.com/ansible-collections/community.routeros/pull/318).

v2.20.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add new parameters from the RouterOS 7.16 release (https://github.com/ansible-collections/community.routeros/pull/323).
- api_info, api_modify - add support ``interface l2tp-client`` configuration (https://github.com/ansible-collections/community.routeros/pull/322).
- api_info, api_modify - add support for the ``cpu-frequency``, ``memory-frequency``, ``preboot-etherboot`` and ``preboot-etherboot-server`` properties in ``system routerboard settings`` (https://github.com/ansible-collections/community.routeros/pull/320).
- api_info, api_modify - add support for the ``matching-type`` property in ``ip dhcp-server matcher`` introduced by RouterOS 7.16 (https://github.com/ansible-collections/community.routeros/pull/321).

v2.19.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add support for the ``ip dns adlist`` path implemented by RouterOS 7.15 and newer (https://github.com/ansible-collections/community.routeros/pull/310).
- api_info, api_modify - add support for the ``mld-version`` and ``multicast-querier`` properties in ``interface bridge`` (https://github.com/ansible-collections/community.routeros/pull/315).
- api_info, api_modify - add support for the ``routing filter num-list`` path implemented by RouterOS 7 and newer (https://github.com/ansible-collections/community.routeros/pull/313).
- api_info, api_modify - add support for the ``routing igmp-proxy`` path (https://github.com/ansible-collections/community.routeros/pull/309).
- api_modify, api_info - add read-only ``default`` field to ``snmp community`` (https://github.com/ansible-collections/community.routeros/pull/311).

v2.18.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info - allow to restrict the output by limiting fields to specific values with the new ``restrict`` option (https://github.com/ansible-collections/community.routeros/pull/305).
- api_info, api_modify - add support for the ``ip dhcp-server matcher`` path (https://github.com/ansible-collections/community.routeros/pull/300).
- api_info, api_modify - add support for the ``ipv6 nd prefix`` path (https://github.com/ansible-collections/community.routeros/pull/303).
- api_info, api_modify - add support for the ``name`` and ``is-responder`` properties under the ``interface wireguard peers`` path introduced in RouterOS 7.15 (https://github.com/ansible-collections/community.routeros/pull/304).
- api_info, api_modify - add support for the ``routing ospf static-neighbor`` path in RouterOS 7 (https://github.com/ansible-collections/community.routeros/pull/302).
- api_info, api_modify - set default for ``force`` in ``ip dhcp-server option`` to an explicit ``false`` (https://github.com/ansible-collections/community.routeros/pull/300).
- api_modify - allow to restrict what is updated by limiting fields to specific values with the new ``restrict`` option (https://github.com/ansible-collections/community.routeros/pull/305).

Deprecated Features
-------------------

- The collection deprecates support for all Ansible/ansible-base/ansible-core versions that are currently End of Life, `according to the ansible-core support matrix <https://docs.ansible.com/ansible-core/devel/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix>`__. This means that the next major release of the collection will no longer support Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, and ansible-core 2.14.

Bugfixes
--------

- api_modify, api_info - change the default of ``ingress-filtering`` in paths ``interface bridge`` and ``interface bridge port`` back to ``false`` for RouterOS before version 7 (https://github.com/ansible-collections/community.routeros/pull/305).

v2.17.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add ``system health settings`` path (https://github.com/ansible-collections/community.routeros/pull/294).
- api_info, api_modify - add missing path ``/system resource irq rps`` (https://github.com/ansible-collections/community.routeros/pull/295).
- api_info, api_modify - add parameter ``host-key-type`` for ``ip ssh`` path (https://github.com/ansible-collections/community.routeros/issues/280, https://github.com/ansible-collections/community.routeros/pull/297).

v2.16.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add missing path ``/ppp secret`` (https://github.com/ansible-collections/community.routeros/pull/286).
- api_info, api_modify - minor changes ``/interface ethernet`` path fields (https://github.com/ansible-collections/community.routeros/pull/288).

v2.15.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - Add RouterOS 7.x support to ``/mpls ldp`` path (https://github.com/ansible-collections/community.routeros/pull/271).
- api_info, api_modify - add ``/ip route rule`` path for RouterOS 6.x (https://github.com/ansible-collections/community.routeros/pull/278).
- api_info, api_modify - add ``/routing filter`` path for RouterOS 6.x (https://github.com/ansible-collections/community.routeros/pull/279).
- api_info, api_modify - add default value for ``from-pool`` field in ``/ipv6 address`` (https://github.com/ansible-collections/community.routeros/pull/270).
- api_info, api_modify - add missing path ``/interface pppoe-server server`` (https://github.com/ansible-collections/community.routeros/pull/273).
- api_info, api_modify - add missing path ``/ip dhcp-relay`` (https://github.com/ansible-collections/community.routeros/pull/276).
- api_info, api_modify - add missing path ``/queue simple`` (https://github.com/ansible-collections/community.routeros/pull/269).
- api_info, api_modify - add missing path ``/queue type`` (https://github.com/ansible-collections/community.routeros/pull/274).
- api_info, api_modify - add missing paths ``/routing bgp aggregate``, ``/routing bgp network`` and ``/routing bgp peer`` (https://github.com/ansible-collections/community.routeros/pull/277).
- api_info, api_modify - add support for paths ``/mpls interface``, ``/mpls ldp accept-filter``, ``/mpls ldp advertise-filter`` and ``mpls ldp interface`` (https://github.com/ansible-collections/community.routeros/pull/272).

v2.14.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add read-only fields ``installed-version``, ``latest-version`` and ``status`` in ``system package update`` (https://github.com/ansible-collections/community.routeros/pull/263).
- api_info, api_modify - added support for ``interface wifi`` and its sub-paths (https://github.com/ansible-collections/community.routeros/pull/266).
- api_info, api_modify - remove default value for read-only ``running`` field in ``interface wireless`` (https://github.com/ansible-collections/community.routeros/pull/264).

v2.13.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info, api_modify - make path ``user group`` modifiable and add ``comment`` attribute (https://github.com/ansible-collections/community.routeros/issues/256, https://github.com/ansible-collections/community.routeros/pull/257).
- api_modify, api_info - add support for the ``ip vrf`` path in RouterOS 7  (https://github.com/ansible-collections/community.routeros/pull/259)

Bugfixes
--------

- facts - fix date not getting removed for idempotent config export (https://github.com/ansible-collections/community.routeros/pull/262).

v2.12.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- api_info, api_modify - add ``interface ovpn-client`` path (https://github.com/ansible-collections/community.routeros/issues/242, https://github.com/ansible-collections/community.routeros/pull/244).
- api_info, api_modify - add ``radius`` path (https://github.com/ansible-collections/community.routeros/issues/241, https://github.com/ansible-collections/community.routeros/pull/245).
- api_info, api_modify - add ``routing rule`` path (https://github.com/ansible-collections/community.routeros/issues/162, https://github.com/ansible-collections/community.routeros/pull/246).
- api_info, api_modify - add missing path ``routing bgp template`` (https://github.com/ansible-collections/community.routeros/pull/243).
- api_info, api_modify - add support for the ``tx-power`` attribute in ``interface wireless`` (https://github.com/ansible-collections/community.routeros/pull/239).
- api_info, api_modify - removed ``host`` primary key in ``tool netwatch`` path (https://github.com/ansible-collections/community.routeros/pull/248).
- api_modify, api_info - added support for ``interface wifiwave2`` (https://github.com/ansible-collections/community.routeros/pull/226).

v2.11.0
=======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- api_info, api_modify - add missing DoH parameters ``doh-max-concurrent-queries``, ``doh-max-server-connections``, and ``doh-timeout`` to the ``ip dns`` path (https://github.com/ansible-collections/community.routeros/issues/230, https://github.com/ansible-collections/community.routeros/pull/235)
- api_info, api_modify - add missing parameters ``address-list``, ``address-list-timeout``, ``randomise-ports``, and ``realm`` to subpaths of the ``ip firewall`` path (https://github.com/ansible-collections/community.routeros/issues/236, https://github.com/ansible-collections/community.routeros/pull/237).
- api_info, api_modify - mark the ``interface wireless`` parameter ``running`` as read-only (https://github.com/ansible-collections/community.routeros/pull/233).
- api_info, api_modify - set the default value to ``false`` for the  ``disabled`` parameter in some more paths where it can be seen in the documentation (https://github.com/ansible-collections/community.routeros/pull/237).
- api_modify - add missing ``comment`` attribute to ``/routing id`` (https://github.com/ansible-collections/community.routeros/pull/234).
- api_modify - add missing attributes to the ``routing bgp connection`` path (https://github.com/ansible-collections/community.routeros/pull/234).
- api_modify - add versioning to the ``/tool e-mail`` path (RouterOS 7.12 release) (https://github.com/ansible-collections/community.routeros/pull/234).
- api_modify - make ``/ip traffic-flow target`` a multiple value attribute (https://github.com/ansible-collections/community.routeros/pull/234).

v2.10.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info - add new ``include_read_only`` option to select behavior for read-only values. By default these are not returned (https://github.com/ansible-collections/community.routeros/pull/213).
- api_info, api_modify - add support for ``address-list`` and ``match-subdomain`` introduced by RouterOS 7.7 in the ``ip dns static`` path (https://github.com/ansible-collections/community.routeros/pull/197).
- api_info, api_modify - add support for ``user``, ``time`` and ``gmt-offset`` under the ``system clock`` path (https://github.com/ansible-collections/community.routeros/pull/210).
- api_info, api_modify - add support for the ``interface ppp-client`` path (https://github.com/ansible-collections/community.routeros/pull/199).
- api_info, api_modify - add support for the ``interface wireless`` path (https://github.com/ansible-collections/community.routeros/pull/195).
- api_info, api_modify - add support for the ``iot modbus`` path (https://github.com/ansible-collections/community.routeros/pull/205).
- api_info, api_modify - add support for the ``ip dhcp-server option`` and ``ip dhcp-server option sets`` paths (https://github.com/ansible-collections/community.routeros/pull/223).
- api_info, api_modify - add support for the ``ip upnp interfaces``, ``tool graphing interface``, ``tool graphing resource`` paths (https://github.com/ansible-collections/community.routeros/pull/227).
- api_info, api_modify - add support for the ``ipv6 firewall nat`` path (https://github.com/ansible-collections/community.routeros/pull/204).
- api_info, api_modify - add support for the ``mode`` property in ``ip neighbor discovery-settings`` introduced in RouterOS 7.7 (https://github.com/ansible-collections/community.routeros/pull/198).
- api_info, api_modify - add support for the ``port remote-access`` path (https://github.com/ansible-collections/community.routeros/pull/224).
- api_info, api_modify - add support for the ``routing filter rule`` and ``routing filter select-rule`` paths (https://github.com/ansible-collections/community.routeros/pull/200).
- api_info, api_modify - add support for the ``routing table`` path in RouterOS 7 (https://github.com/ansible-collections/community.routeros/pull/215).
- api_info, api_modify - add support for the ``tool netwatch`` path in RouterOS 7 (https://github.com/ansible-collections/community.routeros/pull/216).
- api_info, api_modify - add support for the ``user settings`` path (https://github.com/ansible-collections/community.routeros/pull/201).
- api_info, api_modify - add support for the ``user`` path (https://github.com/ansible-collections/community.routeros/pull/211).
- api_info, api_modify - finalize fields for the ``interface wireless security-profiles`` path and enable it (https://github.com/ansible-collections/community.routeros/pull/203).
- api_info, api_modify - finalize fields for the ``ppp profile`` path and enable it (https://github.com/ansible-collections/community.routeros/pull/217).
- api_modify - add new ``handle_read_only`` and ``handle_write_only`` options to handle the module's behavior for read-only and write-only fields (https://github.com/ansible-collections/community.routeros/pull/213).
- api_modify, api_info - support API paths ``routing id``, ``routing bgp connection`` (https://github.com/ansible-collections/community.routeros/pull/220).

Bugfixes
--------

- api_info, api_modify - in the ``snmp`` path, ensure that ``engine-id-suffix`` is only available on RouterOS 7.10+, and that ``engine-id`` is read-only on RouterOS 7.10+ (https://github.com/ansible-collections/community.routeros/issues/208, https://github.com/ansible-collections/community.routeros/pull/218).

v2.9.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_info, api_modify - add path ``caps-man channel`` and enable path ``caps-man manager interface`` (https://github.com/ansible-collections/community.routeros/issues/193, https://github.com/ansible-collections/community.routeros/pull/194).
- api_info, api_modify - add path ``ip traffic-flow target`` (https://github.com/ansible-collections/community.routeros/issues/191, https://github.com/ansible-collections/community.routeros/pull/192).

Bugfixes
--------

- api_modify, api_info - add missing parameter ``engine-id-suffix`` for the ``snmp`` path (https://github.com/ansible-collections/community.routeros/issues/189, https://github.com/ansible-collections/community.routeros/pull/190).

v2.8.3
======

Release Summary
---------------

Maintenance release with updated documentation.

From this version on, community.routeros is using the new `Ansible semantic markup
<https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_documenting.html#semantic-markup-within-module-documentation>`__
in its documentation. If you look at documentation with the ansible-doc CLI tool
from ansible-core before 2.15, please note that it does not render the markup
correctly. You should be still able to read it in most cases, but you need
ansible-core 2.15 or later to see it as it is intended. Alternatively you can
look at `the devel docsite <https://docs.ansible.com/ansible/devel/collections/community/routeros/>`__
for the rendered HTML version of the documentation of the latest release.

Known Issues
------------

- Ansible markup will show up in raw form on ansible-doc text output for ansible-core before 2.15. If you have trouble deciphering the documentation markup, please upgrade to ansible-core 2.15 (or newer), or read the HTML documentation on https://docs.ansible.com/ansible/devel/collections/community/routeros/.

v2.8.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- api_modify, api_info - add missing parameter ``tls`` for the ``tool e-mail`` path (https://github.com/ansible-collections/community.routeros/issues/179, https://github.com/ansible-collections/community.routeros/pull/180).

v2.8.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- facts - do not crash in CLI output preprocessing in unexpected situations during line unwrapping (https://github.com/ansible-collections/community.routeros/issues/170, https://github.com/ansible-collections/community.routeros/pull/177).

v2.8.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_modify - adapt data for API paths ``ip dhcp-server network`` (https://github.com/ansible-collections/community.routeros/pull/156).
- api_modify - add support for API path ``snmp community`` (https://github.com/ansible-collections/community.routeros/pull/159).
- api_modify - add support for ``trap-interfaces`` in API path ``snmp`` (https://github.com/ansible-collections/community.routeros/pull/159).
- api_modify - add support to disable IPv6 in API paths ``ipv6 settings`` (https://github.com/ansible-collections/community.routeros/pull/158).
- api_modify - support API paths ``ip firewall layer7-protocol`` (https://github.com/ansible-collections/community.routeros/pull/153).
- command - workaround for extra characters in stdout in RouterOS versions between 6.49 and 7.1.5 (https://github.com/ansible-collections/community.routeros/issues/62, https://github.com/ansible-collections/community.routeros/pull/161).

Bugfixes
--------

- api_info, api_modify - fix default and remove behavior for ``dhcp-options`` in path ``ip dhcp-client`` (https://github.com/ansible-collections/community.routeros/issues/148, https://github.com/ansible-collections/community.routeros/pull/154).
- api_modify - fix handling of disabled keys on creation (https://github.com/ansible-collections/community.routeros/pull/154).
- various plugins and modules - remove unnecessary imports (https://github.com/ansible-collections/community.routeros/pull/149).

v2.7.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- api_modify, api_info - support API paths ``ip arp``, ``ip firewall raw``, ``ipv6 firewall raw`` (https://github.com/ansible-collections/community.routeros/pull/144).

Bugfixes
--------

- api_modify, api_info - defaults corrected for fields in ``interface wireguard peers`` API path (https://github.com/ansible-collections/community.routeros/pull/144).

v2.6.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- api_modify, api_info - add field ``regexp`` to ``ip dns static`` (https://github.com/ansible-collections/community.routeros/issues/141).
- api_modify, api_info - support API paths ``interface wireguard``, ``interface wireguard peers`` (https://github.com/ansible-collections/community.routeros/pull/143).

Bugfixes
--------

- api_modify - do not use ``name`` as a unique key in ``ip dns static`` (https://github.com/ansible-collections/community.routeros/issues/141).
- api_modify, api_info - do not crash if router contains ``regexp`` DNS entries in ``ip dns static`` (https://github.com/ansible-collections/community.routeros/issues/141).

v2.5.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- api_info, api_modify - support API paths ``interface ethernet poe``, ``interface gre6``, ``interface vrrp`` and also support all previously missing fields of entries in ``ip dhcp-server`` (https://github.com/ansible-collections/community.routeros/pull/137).

Bugfixes
--------

- api_modify - ``address-pool`` field of entries in API path ``ip dhcp-server`` is not required anymore (https://github.com/ansible-collections/community.routeros/pull/137).

v2.4.0
======

Release Summary
---------------

Feature release improving the ``api*`` modules.

Minor Changes
-------------

- api* modules - Add new option ``force_no_cert`` to connect with ADH ciphers (https://github.com/ansible-collections/community.routeros/pull/124).
- api_info - new parameter ``include_builtin`` which allows to include "builtin" entries that are automatically generated by ROS and cannot be modified by the user (https://github.com/ansible-collections/community.routeros/pull/130).
- api_modify, api_info - support API paths - ``interface bonding``, ``interface bridge mlag``, ``ipv6 firewall mangle``, ``ipv6 nd``, ``system scheduler``, ``system script``, ``system ups`` (https://github.com/ansible-collections/community.routeros/pull/133).
- api_modify, api_info - support API paths ``caps-man access-list``, ``caps-man configuration``, ``caps-man datapath``, ``caps-man manager``, ``caps-man provisioning``, ``caps-man security`` (https://github.com/ansible-collections/community.routeros/pull/126).
- api_modify, api_info - support API paths ``interface list`` and ``interface list member`` (https://github.com/ansible-collections/community.routeros/pull/120).
- api_modify, api_info - support API paths ``interface pppoe-client``, ``interface vlan``, ``interface bridge``, ``interface bridge vlan`` (https://github.com/ansible-collections/community.routeros/pull/125).
- api_modify, api_info - support API paths ``ip ipsec identity``, ``ip ipsec peer``, ``ip ipsec policy``, ``ip ipsec profile``, ``ip ipsec proposal`` (https://github.com/ansible-collections/community.routeros/pull/129).
- api_modify, api_info - support API paths ``ip route`` and ``ip route vrf`` (https://github.com/ansible-collections/community.routeros/pull/123).
- api_modify, api_info - support API paths ``ipv6 address``, ``ipv6 dhcp-server``, ``ipv6 dhcp-server option``, ``ipv6 route``, ``queue tree``, ``routing ospf area``, ``routing ospf area range``, ``routing ospf instance``, ``routing ospf interface-template``, ``routing pimsm instance``, ``routing pimsm interface-template`` (https://github.com/ansible-collections/community.routeros/pull/131).
- api_modify, api_info - support API paths ``system logging``, ``system logging action`` (https://github.com/ansible-collections/community.routeros/pull/127).
- api_modify, api_info - support field ``hw-offload`` for path ``ip firewall filter`` (https://github.com/ansible-collections/community.routeros/pull/121).
- api_modify, api_info - support fields ``address-list``, ``address-list-timeout``, ``connection-bytes``, ``connection-limit``, ``connection-mark``, ``connection-rate``, ``connection-type``, ``content``, ``disabled``, ``dscp``, ``dst-address-list``, ``dst-address-type``, ``dst-limit``, ``fragment``, ``hotspot``, ``icmp-options``, ``in-bridge-port``, ``in-bridge-port-list``, ``ingress-priority``, ``ipsec-policy``, ``ipv4-options``, ``jump-target``, ``layer7-protocol``, ``limit``, ``log``, ``log-prefix``, ``nth``, ``out-bridge-port``, ``out-bridge-port-list``, ``packet-mark``, ``packet-size``, ``per-connection-classifier``, ``port``, ``priority``, ``psd``, ``random``, ``realm``, ``routing-mark``, ``same-not-by-dst``, ``src-address``, ``src-address-list``, ``src-address-type``, ``src-mac-address``, ``src-port``, ``tcp-mss``, ``time``, ``tls-host``, ``ttl`` in ``ip firewall nat`` path (https://github.com/ansible-collections/community.routeros/pull/133).
- api_modify, api_info - support fields ``combo-mode``, ``comment``, ``fec-mode``, ``mdix-enable``, ``poe-out``, ``poe-priority``, ``poe-voltage``, ``power-cycle-interval``, ``power-cycle-ping-address``, ``power-cycle-ping-enabled``, ``power-cycle-ping-timeout`` for path ``interface ethernet`` (https://github.com/ansible-collections/community.routeros/pull/121).
- api_modify, api_info - support fields ``jump-target``, ``reject-with`` in ``ip firewall filter`` API path, field ``comment`` in ``ip firwall address-list`` API path, field ``jump-target`` in ``ip firewall mangle`` API path, field ``comment`` in ``ipv6 firewall address-list`` API path, fields ``jump-target``, ``reject-with`` in ``ipv6 firewall filter`` API path (https://github.com/ansible-collections/community.routeros/pull/133).
- api_modify, api_info - support for API fields that can be disabled and have default value at the same time, support API paths ``interface gre``, ``interface eoip`` (https://github.com/ansible-collections/community.routeros/pull/128).
- api_modify, api_info - support for fields ``blackhole``, ``pref-src``, ``routing-table``, ``suppress-hw-offload``, ``type``, ``vrf-interface`` in ``ip route`` path (https://github.com/ansible-collections/community.routeros/pull/131).
- api_modify, api_info - support paths ``system ntp client servers`` and ``system ntp server`` available in ROS7, as well as new fields ``servers``, ``mode``, and ``vrf`` for ``system ntp client`` (https://github.com/ansible-collections/community.routeros/pull/122).

Bugfixes
--------

- api_modify - ``ip route`` entry can be defined without the need of ``gateway`` field, which is correct for unreachable/blackhole type of routes (https://github.com/ansible-collections/community.routeros/pull/131).
- api_modify - ``queue interface`` path works now (https://github.com/ansible-collections/community.routeros/pull/131).
- api_modify, api_info - removed wrong field ``dynamic`` from API path ``ipv6 firewall address-list`` (https://github.com/ansible-collections/community.routeros/pull/133).
- api_modify, api_info - the default of the field ``ingress-filtering`` in ``interface bridge port`` is now ``true``, which is the default in ROS (https://github.com/ansible-collections/community.routeros/pull/125).
- command, facts - commands do not timeout in safe mode anymore (https://github.com/ansible-collections/community.routeros/pull/134).

Known Issues
------------

- api_modify - when limits for entries in ``queue tree`` are defined as human readable - for example ``25M`` -, the configuration will be correctly set in ROS, but the module will indicate the item is changed on every run even when there was no change done. This is caused by the ROS API which returns the number in bytes - for example ``25000000`` (which is inconsistent with the CLI behavior). In order to mitigate that, the limits have to be defined in bytes (those will still appear as human readable in the ROS CLI) (https://github.com/ansible-collections/community.routeros/pull/131).
- api_modify, api_info - ``routing ospf area``, ``routing ospf area range``, ``routing ospf instance``, ``routing ospf interface-template`` paths are not fully implemented for ROS6 due to the significant changes between ROS6 and ROS7 (https://github.com/ansible-collections/community.routeros/pull/131).

v2.3.1
======

Release Summary
---------------

Maintenance release with improved documentation.

Known Issues
------------

- The ``community.routeros.command`` module claims to support check mode. Since it cannot judge whether the commands executed modify state or not, this behavior is incorrect. Since this potentially breaks existing playbooks, we will not change this behavior until community.routeros 3.0.0.

v2.3.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- The collection repository conforms to the `REUSE specification <https://reuse.software/spec/>`__ except for the changelog fragments (https://github.com/ansible-collections/community.routeros/pull/108).
- api* modules - added ``timeout`` parameter (https://github.com/ansible-collections/community.routeros/pull/109).
- api_modify, api_info - support API path ``ip firewall mangle`` (https://github.com/ansible-collections/community.routeros/pull/110).

Bugfixes
--------

- api_modify, api_info - make API path ``ip dhcp-server`` support ``script``, and ``ip firewall nat`` support ``in-interface`` and ``in-interface-list`` (https://github.com/ansible-collections/community.routeros/pull/110).

v2.2.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- api_modify, api_info - make API path ``ip dhcp-server lease`` support ``server=all`` (https://github.com/ansible-collections/community.routeros/issues/104, https://github.com/ansible-collections/community.routeros/pull/107).
- api_modify, api_info - make API path ``ip dhcp-server network`` support missing options ``boot-file-name``, ``dhcp-option-set``, ``dns-none``, ``domain``, and ``next-server`` (https://github.com/ansible-collections/community.routeros/issues/104, https://github.com/ansible-collections/community.routeros/pull/106).

v2.2.0
======

Release Summary
---------------

New feature release.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root. Moreover, ``SPDX-License-Identifier:`` is used to declare the applicable license for every file that is not automatically generated (https://github.com/ansible-collections/community.routeros/pull/101).

Bugfixes
--------

- Include ``LICENSES/BSD-2-Clause.txt`` file for the ``routeros`` module utils (https://github.com/ansible-collections/community.routeros/pull/101).

New Modules
-----------

- community.routeros.api_info - Retrieve information from API
- community.routeros.api_modify - Modify data at paths with API

v2.1.0
======

Release Summary
---------------

Feature and bugfix release with new modules.

Minor Changes
-------------

- Added a ``community.routeros.api`` module defaults group. Use with ``group/community.routeros.api`` to provide options for all API-based modules (https://github.com/ansible-collections/community.routeros/pull/89).
- Prepare collection for inclusion in an Execution Environment by declaring its dependencies (https://github.com/ansible-collections/community.routeros/pull/83).
- api - add new option ``extended query`` more complex queries against RouterOS API (https://github.com/ansible-collections/community.routeros/pull/63).
- api - update ``query`` to accept symbolic parameters (https://github.com/ansible-collections/community.routeros/pull/63).
- api* modules - allow to set an encoding other than the default ASCII for communicating with the API (https://github.com/ansible-collections/community.routeros/pull/95).

Bugfixes
--------

- query - fix query function check for ``.id`` vs. ``id`` arguments to not conflict with routeros arguments like ``identity`` (https://github.com/ansible-collections/community.routeros/pull/68, https://github.com/ansible-collections/community.routeros/issues/67).
- quoting and unquoting filter plugins, api module - handle the escape sequence ``\_`` correctly as escaping a space and not an underscore (https://github.com/ansible-collections/community.routeros/pull/89).

New Modules
-----------

- community.routeros.api_facts - Collect facts from remote devices running MikroTik RouterOS using the API
- community.routeros.api_find_and_modify - Find and modify information using the API

v2.0.0
======

Release Summary
---------------

A new major release with breaking changes in the behavior of ``community.routeros.api`` and ``community.routeros.command``.

Minor Changes
-------------

- api - make validation of ``WHERE`` for ``query`` more strict (https://github.com/ansible-collections/community.routeros/pull/53).
- command - the ``commands`` and ``wait_for`` options now convert the list elements to strings (https://github.com/ansible-collections/community.routeros/pull/55).
- facts - the ``gather_subset`` option now converts the list elements to strings (https://github.com/ansible-collections/community.routeros/pull/55).

Breaking Changes / Porting Guide
--------------------------------

- api - due to a programming error, the module never failed on errors. This has now been fixed. If you are relying on the module not failing in case of idempotent commands (resulting in errors like ``failure: already have such address``), you need to adjust your roles/playbooks. We suggest to use ``failed_when`` to accept failure in specific circumstances, for example ``failed_when: "'failure: already have ' in result.msg[0]"`` (https://github.com/ansible-collections/community.routeros/pull/39).
- api - splitting commands no longer uses a naive split by whitespace, but a more RouterOS CLI compatible splitting algorithm (https://github.com/ansible-collections/community.routeros/pull/45).
- command - the module now always indicates that a change happens. If this is not correct, please use ``changed_when`` to determine the correct changed status for a task (https://github.com/ansible-collections/community.routeros/pull/50).

Bugfixes
--------

- api - improve splitting of ``WHERE`` queries (https://github.com/ansible-collections/community.routeros/pull/47).
- api - when converting result lists to dictionaries, no longer removes second ``=`` and text following that if present (https://github.com/ansible-collections/community.routeros/pull/47).
- routeros cliconf plugin - adjust function signature that was modified in Ansible after creation of this plugin (https://github.com/ansible-collections/community.routeros/pull/43).

New Plugins
-----------

Filter
~~~~~~

- community.routeros.join - Join a list of arguments to a command
- community.routeros.list_to_dict - Convert a list of arguments to a list of dictionary
- community.routeros.quote_argument - Quote an argument
- community.routeros.quote_argument_value - Quote an argument value
- community.routeros.split - Split a command into arguments

v1.2.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.routeros/pull/38).
- api - add options ``validate_certs`` (default value ``true``), ``validate_cert_hostname`` (default value ``false``), and ``ca_path`` to control certificate validation (https://github.com/ansible-collections/community.routeros/pull/37).
- api - rename option ``ssl`` to ``tls``, and keep the old name as an alias (https://github.com/ansible-collections/community.routeros/pull/37).
- fact - add fact ``ansible_net_config_nonverbose`` to get idempotent config (no date, no verbose) (https://github.com/ansible-collections/community.routeros/pull/23).

Bugfixes
--------

- api - when using TLS/SSL, remove explicit cipher configuration to insecure values, which also makes it impossible to connect to newer RouterOS versions (https://github.com/ansible-collections/community.routeros/pull/34).

v1.1.0
======

Release Summary
---------------

This release allow dashes in usernames for SSH-based modules.

Minor Changes
-------------

- command - added support for a dash (``-``) in username (https://github.com/ansible-collections/community.routeros/pull/18).
- facts - added support for a dash (``-``) in username (https://github.com/ansible-collections/community.routeros/pull/18).

v1.0.1
======

Release Summary
---------------

Maintenance release with a bugfix for ``api``.

Bugfixes
--------

- api - remove ``id to .id`` as default requirement which conflicts with RouterOS ``id`` configuration parameter (https://github.com/ansible-collections/community.routeros/pull/15).

v1.0.0
======

Release Summary
---------------

This is the first production (non-prerelease) release of ``community.routeros``.

Bugfixes
--------

- routeros terminal plugin - allow slashes in hostnames for terminal detection. Without this, slashes in hostnames will result in connection timeouts (https://github.com/ansible-collections/community.network/pull/138).

v0.1.1
======

Release Summary
---------------

Small improvements and bugfixes over the initial release.

Bugfixes
--------

- api - fix crash when the ``ssl`` parameter is used (https://github.com/ansible-collections/community.routeros/pull/3).

v0.1.0
======

Release Summary
---------------

The ``community.routeros`` continues the work on the Ansible RouterOS modules from their state in ``community.network`` 1.2.0. The changes listed here are thus relative to the modules ``community.network.routeros_*``.

Minor Changes
-------------

- facts - now also collecting data about BGP and OSPF (https://github.com/ansible-collections/community.network/pull/101).
- facts - set configuration export on to verbose, for full configuration export (https://github.com/ansible-collections/community.network/pull/104).
