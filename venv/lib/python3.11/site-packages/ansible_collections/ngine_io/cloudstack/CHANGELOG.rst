==========================================
Apache CloudStack Collection Release Notes
==========================================

.. contents:: Topics


v2.5.0
======

Minor Changes
-------------

- cs_instance - Added new arguments ``user_data_name`` and ``user_data_details`` (https://github.com/ngine-io/ansible-collection-cloudstack/pull/134).
- cs_service_offering - Add support for storagetag (https://github.com/ngine-io/ansible-collection-cloudstack/pull/118).

v2.4.1
======

Bugfixes
--------

- Fixed a bug related to the new option ``validate_certs`` (https://github.com/ngine-io/ansible-collection-cloudstack/pull/135).

v2.4.0
======

Minor Changes
-------------

- Added possiblity to disable certs validation using ``validate_certs`` argument (https://github.com/ngine-io/ansible-collection-cloudstack/pull/131).
- cs_project - Extended to pass ``cleanup=true`` to the deleteProject API when deleting a project (https://github.com/ngine-io/ansible-collection-cloudstack/pull/122).

v2.3.0
======

Minor Changes
-------------

- cs_instance - The arguments ``cpu``, ``cpu_speed`` and ``memory`` are no longer required to be set together (https://github.com/ngine-io/ansible-collection-cloudstack/issues/111).
- cs_instance - The optional arguments ``pod`` and ``cluster`` has been added.

v2.2.4
======

Minor Changes
-------------

- Various documentation fixes and code improvements to address ansible sanity tests failure.

v2.2.3
======

Bugfixes
--------

- cs_instance - Fixed regression project ID KeyError if no project is used (https://github.com/ngine-io/ansible-collection-cloudstack/pull/94).

v2.2.2
======

Bugfixes
--------

- cs_instance - Fixed missing project ID to volume query when checking root disk size. (https://github.com/ngine-io/ansible-collection-cloudstack/pull/90).

v2.2.1
======

Bugfixes
--------

- cs_instance - Fixed attribute error in custom service offerings handling (https://github.com/ngine-io/ansible-collection-cloudstack/pull/87).

v2.2.0
======

Minor Changes
-------------

- cs_instance - add support for MAC address and IPv6 in ``ip_to_networks`` (https://github.com/ngine-io/ansible-collection-cloudstack/issues/78).
- cs_instance_info - implemented support for ``host`` filter (https://github.com/ngine-io/ansible-collection-cloudstack/pull/83).
- cs_network_offering - implemented support for ``tags``, ``zones`` and ``domains`` (https://github.com/ngine-io/ansible-collection-cloudstack/pull/82).

Bugfixes
--------

- cs_instance - Fixed custom service offerings usage (https://github.com/ngine-io/ansible-collection-cloudstack/issues/79).

v2.1.0
======

Minor Changes
-------------

- cs_physical_network - Added VXLAN as an option of isolation methods (https://github.com/ngine-io/ansible-collection-cloudstack/pull/73).
- instance - New style inventory plugin implemented for instances (https://github.com/ngine-io/ansible-collection-cloudstack/pull/66)

New Plugins
-----------

Inventory
~~~~~~~~~

- instance - Apache CloudStack instance inventory source

v2.0.0
======

Breaking Changes / Porting Guide
--------------------------------

- Authentication option using INI files e.g. ``cloudstack.ini`` has been removed. The only supported option to authenticate is by using the module params with fallback to the ENV variables.
- default zone deprecation - The `zone` param default value, across multiple modules, has been deprecated due to unreliable API (https://github.com/ngine-io/ansible-collection-cloudstack/pull/62).

v1.2.0
======

Minor Changes
-------------

- cs_instance - Fixed an edge case caused by `displaytext` not available (https://github.com/ngine-io/ansible-collection-cloudstack/pull/49).
- cs_network - Fixed constraints when creating networks. The param `gateway` is no longer required if the param `netmask` is given (https://github.com/ngine-io/ansible-collection-cloudstack/pull/54).

v1.1.0
======

Minor Changes
-------------

- Deprecated the funtionality of first returned zone to be the default zone because of an unreliable API. Zone will be required beginning with next major version 2.0.0.
- cs_ip_address - allow to pick a particular IP address for a network, available since CloudStack v4.13 (https://github.com/ngine-io/ansible-collection-cloudstack/issues/30).

v1.0.1
======

Minor Changes
-------------

- cs_configuration - Workaround for empty global settings idempotency (https://github.com/ngine-io/ansible-collection-cloudstack/pull/25).

v1.0.0
======

Minor Changes
-------------

- cs_vlan_ip_range - Added support to set IP range for system VMs (https://github.com/ngine-io/ansible-collection-cloudstack/pull/18)
- cs_vlan_ip_range - Added support to specify pod name (https://github.com/ngine-io/ansible-collection-cloudstack/pull/20)

v0.3.0
======

Minor Changes
-------------

- Added support for SSL CA cert verification (https://github.com/ngine-io/ansible-collection-cloudstack/pull/3)
