===================================
Infoblox.Nios_Modules Release Notes
===================================

.. contents:: Topics

v1.8.0
======

Release Summary
---------------
This release includes new modules for managing NIOS VLANs and Admin Users, as well as new lookup plugins for nios_next_vlan_id.
Additionally, it features various enhancements, new features, and bug fixes aimed at improving the system's overall functionality and performance.

New Modules
-----------
- infoblox.nios_modules.nios_vlan - Configure Infoblox NIOS VLANs
- infoblox.nios_modules.nios_adminuser - Configure Infoblox NIOS Admin Users

Lookup
------
- infoblox.nios_modules.nios_next_vlan_id - Return the next available VLAN ID for a VLAN View/Range

major Changes
-------------
- Drop support for Ansible Core 2.15 and Python 3.9.

minor Changes
-------------
- Set `ipv4addr` parameter in the `nios_inventory` module. `#271 <https://github.com/infobloxopen/infoblox-ansible/pull/271>`_
- Added support for the `vlans` parameter in the `nios_network` module. `#171 <https://github.com/infobloxopen/infoblox-ansible/pull/171>`_

Bugfixes
--------
- Fixed the issue where the `nios_host_record` module was failing with `aliases` parameter. `#285 <https://github.com/infobloxopen/infoblox-ansible/pull/285>`_


v1.7.1
======

Release Summary
---------------
This update focuses on specific improvements and bug fixes for Host records to enhance system functionality and performance.

Bugfixes
--------
- Refined Host record return fields to ensure use_nextserver and nextserver are only included for IPv4, as these fields are not applicable to IPv6. `#274 <https://github.com/infobloxopen/infoblox-ansible/pull/274>`_
- For Host IPv6, the mac parameter has been renamed to duid. `#274 <https://github.com/infobloxopen/infoblox-ansible/pull/274>`_


v1.7.0
======

Release Summary
---------------
This release brings new modules for managing extensible attribute definition and DNS name server groups.
Additionally, it includes various enhancements, new features, and bug fixes aimed at improving the system's overall functionality and performance.

Minor Changes
-------------
- Added support for the `use_for_ea_inheritance` parameter in Host Record to inherit extensible attribute from Host address. `#265 <https://github.com/infobloxopen/infoblox-ansible/pull/265>`_
- Added support for the `use_dns_ea_inheritance` parameter in Host Record to inherit extensible attribute from associated zone. `#265 <https://github.com/infobloxopen/infoblox-ansible/pull/265>`_
- Enabled IPv4 support for PXE server configuration in the Host Record module. `#146 <https://github.com/infobloxopen/infoblox-ansible/pull/146>`_
- Introduced `use_logic_filter_rules` & `logic_filter_rules` support for both IPv4 and IPv6 networks and network containers. `#233 <https://github.com/infobloxopen/infoblox-ansible/pull/233>`_
- Added IPv6 network container support for the `nios_next_network` lookup plugin. `#178 <https://github.com/infobloxopen/infoblox-ansible/pull/178>`_
- Added `use_range` parameter to the `nios_next_ip` lookup plug-in to enable it to lookup the next available IP address in a network range. `#200 <https://github.com/infobloxopen/infoblox-ansible/pull/200>`_
- Upgraded the base WAPI version to 2.12.3. `#233 <https://github.com/infobloxopen/infoblox-ansible/pull/233>`_
- Improved handling of DHCP options in DHCP Range, Network, and Network Container modules.

New Modules
-----------
- infoblox.nios_modules.nios_extensible_attribute - Configure Infoblox NIOS extensible attribute definition
- infoblox.nios_modules.nios_nsgroup_delegation - Configure InfoBlox DNS Delegation Name server Groups
- infoblox.nios_modules.nios_nsgroup_forwardingmember - Configure InfoBlox DNS Forwarding Member Name server Groups
- infoblox.nios_modules.nios_nsgroup_forwardstubserver - Configure InfoBlox DNS Forward/Stub Server Name server Groups
- infoblox.nios_modules.nios_nsgroup_stubmember - Configure InfoBlox DNS Stub Member Name server Groups

Bugfixes
--------
- Omits DNS view from filter criteria when renaming a host object and bypasses the DNS. (https://github.com/infobloxopen/infoblox-ansible/issues/230)
- nios_host_record - rename logic included DNS view in filter criteria, even when DNS had been bypassed.
- Fixed the handling of `mac` parameter in the `nios_host_record` module.
- Fixed the update operation in the `nios_network` module where the `network` parameter was not handled correctly.
- Adjusted unit test assertions for Mock.called_once_with. `#254 <https://github.com/infobloxopen/infoblox-ansible/pull/254>`_

v1.6.1
======

Release Summary
---------------
This release includes the updates of plug-in version 1.6.0 and the following documentation changes:
Ansible core version in the dependencies updated to 2.14 or later.

Minor Changes
-------------
Ansible core version in the dependencies updated to 2.14 or later.

v1.6.0
======

Release Summary
---------------
Added new modules with CRUD features to manage NIOS DTC health check monitors: DTC HTTP Monitor,
DTC ICMP Monitor, DTC PDP Monitor, DTC SIP Monitor, DTC SNMP Monitor, DTC TCP Monitor.
Added a new module with CRUD features to manage topology rulesets in NIOS.
Added a new field to define topology ruleset for the DTC Pool and DTC LBDN modules.

Major Changes
-------------
- Upgrade Ansible version support from 2.13 to 2.16.
- Upgrade Python version support from 3.8 to 3.10.

New Modules
-----------
- infoblox.nios_modules.nios_dtc_monitor_http - Configures the Infoblox NIOS DTC HTTP monitor
- infoblox.nios_modules.nios_dtc_monitor_icmp - Configures the Infoblox NIOS DTC ICMP monitor
- infoblox.nios_modules.nios_dtc_monitor_pdp - Configures the Infoblox NIOS DTC PDP monitor
- infoblox.nios_modules.nios_dtc_monitor_sip - Configures the Infoblox NIOS DTC SIP monitor
- infoblox.nios_modules.nios_dtc_monitor_snmp - Configures the Infoblox NIOS DTC SNMP monitor
- infoblox.nios_modules.nios_dtc_monitor_tcp - Configures the Infoblox NIOS DTC TCP monitor
- infoblox.nios_modules.nios_dtc_topology - Configures the Infoblox NIOS DTC Topology

Bugfixes
---------
- Fixes typo for environment variable INFOBLOX_WAPI_VERSION `#209 <https://github.com/infobloxopen/infoblox-ansible/pull/209>`_
- Fixes environment variable max_results using INFOBLOX_MAX_RESULTS `#209 <https://github.com/infobloxopen/infoblox-ansible/pull/209>`_
- Fixes index error for transform fields in DTC LBDN (auth_zone and Pool) and DTC POOL (servers and monitors) `#209 <https://github.com/infobloxopen/infoblox-ansible/pull/209>`_

v1.5.0
======

Release Summary
---------------
- Added new module - NIOS Range with Create, Update and Delete features
- Added new feature - Member Assignment to Networks with add and remove functionality
- Fixes Unable to Update/Delete EAs using Ansible plugin
- Fixes Static Allocation of IPV4 address of A Record
- Updates default WAPI version to 2.9
- Added Grid Master Candidate feature

Major Changes
-------------
- Added NIOS Range module with Create, Update and Delete features `#152 <https://github.com/infobloxopen/infoblox-ansible/pull/152>`_
- Added Member Assignment to network and ranges `#152 <https://github.com/infobloxopen/infoblox-ansible/pull/152>`_
- Added Grid Master Candidate feature `#152 <https://github.com/infobloxopen/infoblox-ansible/pull/152>`_
- Fixes issue unable to update/delete EAs using Ansible plugin `#180 <https://github.com/infobloxopen/infoblox-ansible/pull/180>`_
- Fixes static and dynamic allocation of IPV4 address of A Record `#182 <https://github.com/infobloxopen/infoblox-ansible/pull/182>`_
- Fixes to Update host name of  NIOS member `#176 <https://github.com/infobloxopen/infoblox-ansible/pull/176>`_
- Updates default WAPI version to 2.9 `#176 <https://github.com/infobloxopen/infoblox-ansible/pull/176>`_

Bugfixes
---------
- Fixes Update A Record having multiple records with same name and different IP `#182 <https://github.com/infobloxopen/infoblox-ansible/pull/182>`_


v1.4.1
======

Release Summary
---------------
- Ansible Lookup modules can specify network_view to which a network/ip belongs
- Fixes camelCase issue while updating 'nios_network_view' with 'new_name'
- Fixes issue to allocate ip to a_record dynamically
- Updates 'nios_a_record' name with multiple ips having same name

Minor Changes
-------------
- Fix to specify network_view in lookup modules to return absolute network/ip `#157 <https://github.com/infobloxopen/infoblox-ansible/pull/157>`_
- Fix to camelcase issue for updating 'nios_network_view' name `#163 <https://github.com/infobloxopen/infoblox-ansible/pull/163>`_
- Fix to allocate ip to a_record dynamically `#163 <https://github.com/infobloxopen/infoblox-ansible/pull/163>`_
- Fix to update 'nios_a_record' name with multiple ips having same name `#164 <https://github.com/infobloxopen/infoblox-ansible/pull/164>`_
- Fix to changelog yaml file with linting issues `#161 <https://github.com/infobloxopen/infoblox-ansible/pull/161>`_


v1.4.0
======

Release Summary
---------------
- For ansible module, added certificate authentication feature
- Few bug fixes in ansible module nios network

Major Changes
-------------
- Feature for extra layer security, with `cert` and `key` parameters in playbooks for authenticating using certificate and key .pem file absolute path `#154 <https://github.com/infobloxopen/infoblox-ansible/pull/154>`
- Fix to remove issue causing due to template attr in deleting network using Ansible module nios network `#147 <https://github.com/infobloxopen/infoblox-ansible/pull/147>`_


v1.3.0
======

Release Summary
---------------
- Issue fixes to create TXT record with equals sign
- For nonexistent record, update operation creates the new record
- For nonexistent IPv4Address, update operation creates a new A record with new_ipv4addr

Major Changes
-------------
- Update operation using `old_name` and `new_name` for the object with dummy name in `old_name` (which does not exist in system) will not create a new object in the system. An error will be thrown stating the object does not exist in the system `#129 <https://github.com/infobloxopen/infoblox-ansible/pull/129>`_
- Update `text` field of TXT Record `#128 <https://github.com/infobloxopen/infoblox-ansible/pull/128>`_

Bugfixes
---------
- Fix to create TXT record with equals sign `#128 <https://github.com/infobloxopen/infoblox-ansible/pull/128>`_


v1.2.2
======

Release Summary
---------------
- Issue fixes to create PTR record in different network views
- Support extended to determine whether the DTC server is disabled or not

Minor Changes
-------------
- Fix to create PTR record in different network views `#103 <https://github.com/infobloxopen/infoblox-ansible/pull/103>`_
- Remove use_option for DHCP option 60 `#104 <https://github.com/infobloxopen/infoblox-ansible/pull/104>`_
- Allow specifying a template when creating a network `#105 <https://github.com/infobloxopen/infoblox-ansible/pull/105>`_
- Fix unit and sanity test issues `#117 <https://github.com/infobloxopen/infoblox-ansible/pull/117>`_
- Expanding for disable value `#119 <https://github.com/infobloxopen/infoblox-ansible/pull/119>`_


v1.2.1
======

Release Summary
---------------
Added tags to support release on Ansible Automation Hub

Minor Changes
-------------
Added tags 'cloud' and 'networking' in 'galaxy.yaml'


v1.2.0
======
Release Summary
---------------
- Issue fixes to update A Record using 'next_available_ip' function
- Added a new feature - Update canonical name of the CNAME Record
- Updated the 'required' fields in modules

Minor Changes
-------------
- Updated 'required' field in modules `#99 <https://github.com/infobloxopen/infoblox-ansible/pull/99>`_
- Following options are made required in the modules

.. list-table::
   :widths: 25 25
   :header-rows: 1

   * - Record
     - Option made required
   * - A
     - ipv4addr
   * - AAAA
     - ipv6addr
   * - CNAME
     - canonical
   * - MX
     - mail_exchanger, preference
   * - PTR
     - ptrdname

Bugfixes
-------------
- nios_a_record module - KeyError: 'old_ipv4addr' `#79 <https://github.com/infobloxopen/infoblox-ansible/issues/79>`_
- Ansible playbook fails to update canonical name of CName Record `#97 <https://github.com/infobloxopen/infoblox-ansible/pull/97>`_


v1.1.2
======
Release Summary
---------------
- Issue fixes and standardization of inventory plugin and lookup modules as per Ansible guidelines
- Directory restructure and added integration & unit tests

Minor Changes
-------------
- Changes in inventory and lookup plugins documentation `#85 <https://github.com/infobloxopen/infoblox-ansible/pull/85>`_
- Directory restructure and added integration & unit tests `#87 <https://github.com/infobloxopen/infoblox-ansible/pull/87>`_

Bugfixes
-------------
- Handle NoneType parsing in nios_inventory.py `#81 <https://github.com/infobloxopen/infoblox-ansible/pull/81>`_
- Check all dhcp options, not just first one `#83 <https://github.com/infobloxopen/infoblox-ansible/pull/83>`_


v1.1.1
======
Release Summary
---------------
- Support for creating IPv6 Fixed Address with DUID
- Support added to return the next available IP address for an IPv6 network
- Modules made compatible to work with ansible-core 2.11
- Issue fixes and standardization of modules as per Ansible guidelines

Minor Changes
-------------
- The modules are standardized as per Ansible guidelines

Bugfixes
-------------
- Implemented the bugfixes provided by Ansible `community.general`
- Update the name of existing A and AAAA records `#70 <https://github.com/infobloxopen/infoblox-ansible/pull/70>`_
- Update of comment field of SRV, PTR and NAPTR records failing with the following error:
  ```[Err: fatal: [localhost]: FAILED! => {"changed": false, "code": "Client.Ibap.Proto", "msg": "Field is not allowed for update: view", "operation": "update_object", "type": "AdmConProtoError"}]```
  `#70 <https://github.com/infobloxopen/infoblox-ansible/pull/70>`_
- PTR Record failed to update and raises KeyError for view field `#70 <https://github.com/infobloxopen/infoblox-ansible/pull/70>`_
- Update comment field and delete an existing Fixed Address `#73 <https://github.com/infobloxopen/infoblox-ansible/pull/73>`_
- GitHub issue fix - Lookup module for next available IPV6 `#31 <https://github.com/infobloxopen/infoblox-ansible/issues/31>`_
- GitHub issue fix - [nios_zone] changing a nios_zone does not work `#60 <https://github.com/infobloxopen/infoblox-ansible/issues/60>`_
- GitHub issue fix - Getting an error, running every module `#67 <https://github.com/infobloxopen/infoblox-ansible/issues/67>`_
- GitHub issue fix - Error - Dictionary Issues `#68 <https://github.com/infobloxopen/infoblox-ansible/issues/68>`_
- GitHub issue fix - Examples for lookups don't work as written `#72 <https://github.com/infobloxopen/infoblox-ansible/issues/72>`_
- Sanity fixes as per Ansible guidelines to all modules


v1.1.0
======

Release Summary
---------------

This release provides plugins for NIOS DTC

New Modules
-----------

- infoblox.nios_modules.nios_dtc_lbdn - Configure Infoblox NIOS DTC LBDN
- infoblox.nios_modules.nios_dtc_pool - Configure Infoblox NIOS DTC Pool
- infoblox.nios_modules.nios_dtc_server - Configure Infoblox NIOS DTC Server
- infoblox.nios_modules.nios_restartservices - Restart grid services.

v1.0.2
======

Release Summary
---------------

This release provides compatibilty for Ansible v3.0.0

Minor Changes
-------------

- Fixed the ignored sanity errors required for Ansible 3.0.0 collection
- Made it compatible for Ansible v3.0.0

v1.0.1
======

Release Summary
---------------

This release provides compatibilty for Ansible v3.0.0

Minor Changes
-------------

- Made it compatible for Ansible v3.0.0

v1.0.0
======

Release Summary
---------------

First release of the `nios_modules` collection! This release includes multiple plugins:- an `api` plugin, a `network` plugin, a `nios` plugin, a `nios_inventory` plugin, a `lookup plugin`, a `nios_next_ip` plugin, a `nios_next_network` plugin

New Plugins
-----------

Lookup
~~~~~~

- infoblox.nios_modules.nios - Query Infoblox NIOS objects
- infoblox.nios_modules.nios_next_ip - Return the next available IP address for a network
- infoblox.nios_modules.nios_next_network - Return the next available network range for a network-container

New Modules
-----------

- infoblox.nios_modules.nios_a_record - Configure Infoblox NIOS A records
- infoblox.nios_modules.nios_aaaa_record - Configure Infoblox NIOS AAAA records
- infoblox.nios_modules.nios_cname_record - Configure Infoblox NIOS CNAME records
- infoblox.nios_modules.nios_dns_view - Configure Infoblox NIOS DNS views
- infoblox.nios_modules.nios_fixed_address - Configure Infoblox NIOS DHCP Fixed Address
- infoblox.nios_modules.nios_host_record - Configure Infoblox NIOS host records
- infoblox.nios_modules.nios_member - Configure Infoblox NIOS members
- infoblox.nios_modules.nios_mx_record - Configure Infoblox NIOS MX records
- infoblox.nios_modules.nios_naptr_record - Configure Infoblox NIOS NAPTR records
- infoblox.nios_modules.nios_network - Configure Infoblox NIOS network object
- infoblox.nios_modules.nios_network_view - Configure Infoblox NIOS network views
- infoblox.nios_modules.nios_nsgroup - Configure Infoblox NIOS Name server Groups
- infoblox.nios_modules.nios_ptr_record - Configure Infoblox NIOS PTR records
- infoblox.nios_modules.nios_srv_record - Configure Infoblox NIOS SRV records
- infoblox.nios_modules.nios_txt_record - Configure Infoblox NIOS txt records
- infoblox.nios_modules.nios_zone - Configure Infoblox NIOS DNS zones
