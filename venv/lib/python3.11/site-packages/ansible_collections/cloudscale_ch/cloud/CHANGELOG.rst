==============================================
Ansible Collection cloudscale.ch Release Notes
==============================================

.. contents:: Topics

v2.5.2
======

Minor Changes
-------------

- Remove the custom error message from snapshots module to fix root volume snapshots/restores on stopped servers

v2.5.1
======

Minor Changes
-------------

- Add ansible-core 2.19+ compatibility

v2.5.0
======

Minor Changes
-------------

- volume - Add revert parameter.

Bugfixes
--------

- floating_ip - Fix sanity tests.

New Modules
-----------

- volume_snapshot - Manage volume snapshots on the cloudscale.ch IaaS service

v2.4.1
======

Security Fixes
--------------

- Validate API tokens before passing them to Ansible, to ensure that a badly formed one (i.e., one with newlines) is not accidentally logged.

v2.4.0
======

Minor Changes
-------------

- Update source_format of custom images with actually available choices.

v2.3.1
======

Bugfixes
--------

- Add missing modules to the "cloudscale_ch.cloud.cloudscale" action group.
- Remove outdated Ansible version requirement from the README.

v2.3.0
======

Major Changes
-------------

- Bump minimum required Ansible version to 2.13.0

New Modules
-----------

- load_balancer - Manages load balancers on the cloudscale.ch IaaS service
- load_balancer_health_monitor - Manages load balancers on the cloudscale.ch IaaS service
- load_balancer_listener - Manages load balancer listeners on the cloudscale.ch IaaS service
- load_balancer_pool - Manages load balancer pools on the cloudscale.ch IaaS service
- load_balancer_pool_member - Manages load balancer pool members on the cloudscale.ch IaaS service

v2.2.4
======

Minor Changes
-------------

- Add UEFI firmware type option for custom images.

v2.2.3
======

Minor Changes
-------------

- Fixed a typo in region code.
- Fixed various documentation typos.
- Streamlined the flavors to the new format ``flex-y-x`` across the related modules and tests.

v2.2.2
======

Minor Changes
-------------

- Fixed inventory documentation.

v2.2.1
======

Minor Changes
-------------

- Updated documentation: ``ssh_keys`` is a YAML list, not a string.

v2.2.0
======

Major Changes
-------------

- Add custom_image module

Minor Changes
-------------

- Increase api_timeout to 45
- Read CLOUDSCALE_API_TIMEOUT environment variable

New Modules
-----------

- custom_image - Manage custom images on the cloudscale.ch IaaS service

v2.1.0
======

Minor Changes
-------------

- Add interface parameter to server module (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/54).
- Rename server_uuids parameter to servers in volume module (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/54).

Deprecated Features
-------------------

- The aliases ``server_uuids`` and ``server_uuid`` of the servers parameter in the volume module will be removed in version 3.0.0.

v2.0.0
======

Breaking Changes / Porting Guide
--------------------------------

- floating_ip - ``name`` is required for assigning a new floating IP.

v1.3.1
======

Minor Changes
-------------

- Implemented identical naming support of the same resource type per zone (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/46).

Bugfixes
--------

- Fix inventory plugin failing to launch (https://github.com/cloudscale-ch/ansible-collection-cloudscale/issues/49).

v1.3.0
======

Minor Changes
-------------

- floating_ip - Added an optional name parameter to gain idempotency. The parameter will be required for assigning a new floating IP with release of version 2.0.0 (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/43/).
- floating_ip - Allow to reserve an IP without assignment to a server (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/31/).

New Modules
-----------

- subnet - Manages subnets on the cloudscale.ch IaaS service

v1.2.0
======

Minor Changes
-------------

- server_group - The module has been refactored and the code simplifed (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/23).
- volume - The module has been refactored and the code simplifed (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/24).

New Modules
-----------

- network - Manages networks on the cloudscale.ch IaaS service

v1.1.0
======

Minor Changes
-------------

- floating_ip - added tags support (https://github.com/cloudscale-ch/ansible-collection-cloudscale/pull/16)

New Modules
-----------

- objects_user - Manages objects users on the cloudscale.ch IaaS service
