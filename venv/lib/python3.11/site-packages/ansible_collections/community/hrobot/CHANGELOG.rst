================================================
Community Hetzner Robot Collection Release Notes
================================================

.. contents:: Topics

v2.7.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- storagebox_subaccount - filter by username when looking for existing accounts by username (https://github.com/ansible-collections/community.hrobot/pull/182).
- storagebox_subaccount - use the new ``change_home_directory`` action to update a subaccount's home directory, instead of using the now deprecated way using the ``update_access_settings`` action (https://github.com/ansible-collections/community.hrobot/pull/181).

Deprecated Features
-------------------

- storagebox_subaccount - ``password_mode=set-to-random`` is deprecated and will be removed from community.hrobot 3.0.0. Hetzner's new API does not support this anyway, it can only be used with the legacy API (https://github.com/ansible-collections/community.hrobot/pull/183).

v2.6.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Avoid using ``ansible.module_utils.six`` in more places to avoid deprecation warnings with ansible-core 2.20 (https://github.com/ansible-collections/community.hrobot/pull/179).

v2.6.0
======

Release Summary
---------------

Maintenance release deprecating support the old storage box API.

Deprecated Features
-------------------

- storagebox\* modules - membership in the ``community.hrobot.robot`` action group (module defaults group) is deprecated; the modules will be removed from the group in community.hrobot 3.0.0. Use ``community.hrobot.api`` instead (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox\* modules - the ``hetzner_token`` option for these modules will be required from community.hrobot 3.0.0 on (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox\* modules - the ``hetzner_user`` and ``hetzner_pass`` options for these modules are deprecated; support will be removed in community.hrobot 3.0.0. Use ``hetzner_token`` instead (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox_info - the ``storageboxes[].login``, ``storageboxes[].disk_quota``, ``storageboxes[].disk_usage``, ``storageboxes[].disk_usage_data``, ``storageboxes[].disk_usage_snapshot``, ``storageboxes[].webdav``, ``storageboxes[].samba``, ``storageboxes[].ssh``, ``storageboxes[].external_reachability``, and ``storageboxes[].zfs`` return values are deprecated and will be removed from community.routeros. Check out the documentation to find out their new names according to the new API (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox_snapshot_info - the ``snapshots[].timestamp``, ``snapshots[].size``, ``snapshots[].filesystem_size``, ``snapshots[].automatic``, and ``snapshots[].comment`` return values are deprecated and will be removed from community.routeros. Check out the documentation to find out their new names according to the new API (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox_snapshot_plan - the ``plans[].month`` return value is deprecated, since it only returns ``null`` with the new API and cannot be set to any other value (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox_snapshot_plan_info - the ``plans[].month`` return value is deprecated, since it only returns ``null`` with the new API and cannot be set to any other value (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox_subaccount - the ``subaccount.homedirectory``, ``subaccount.samba``, ``subaccount.ssh``, ``subaccount.external_reachability``, ``subaccount.webdav``, ``subaccount.readonly``, ``subaccount.createtime``, and ``subaccount.comment`` return values are deprecated and will be removed from community.routeros. Check out the documentation to find out their new names according to the new API (https://github.com/ansible-collections/community.hrobot/pull/178).
- storagebox_subaccount_info - the ``subaccounts[].accountid``, ``subaccounts[].homedirectory``, ``subaccounts[].samba``, ``subaccounts[].ssh``, ``subaccounts[].external_reachability``, ``subaccounts[].webdav``, ``subaccounts[].readonly``, ``subaccounts[].createtime``, and ``subaccounts[].comment`` return values are deprecated and will be removed from community.routeros. Check out the documentation to find out their new names according to the new API (https://github.com/ansible-collections/community.hrobot/pull/178).

v2.5.2
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Avoid using ``ansible.module_utils.six`` to avoid deprecation warnings with ansible-core 2.20 (https://github.com/ansible-collections/community.hrobot/pull/177).

v2.5.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Avoid deprecated functionality in ansible-core 2.20 (https://github.com/ansible-collections/community.hrobot/pull/174).

v2.5.0
======

Release Summary
---------------

Feature and bugfix release.

This release adds support for the `new Hetzner API for the storage box modules
<https://docs.hetzner.cloud/changelog#2025-06-25-new-api-for-storage-boxes>`__.
You need to use ``hetzner_token`` instead of ``hetzner_user``/``hetzner_password``
to use the new API. Please note that the old API will be sunset on July 30th, 2025;
the modules will then stop working if you do not provide ``hetzner_token`` and stop
providing ``hetzner_user``/``hetzner_password``.

Minor Changes
-------------

- Introduced a new action group (module defaults group) ``community.hrobot.api`` that includes all modules that support the new Hetzner API. This is currently limited to a subset of the storage box modules; these currently support both the ``community.hrobot.robot`` and the new ``community.hrobot.api`` action group, and will eventually drop the ``community.hrobot.robot`` action group once the Robot API for storage boxes is removed by Hetzner (https://github.com/ansible-collections/community.hrobot/pull/166, https://github.com/ansible-collections/community.hrobot/pull/167, https://github.com/ansible-collections/community.hrobot/pull/168, https://github.com/ansible-collections/community.hrobot/pull/169).
- storagebox - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/166).
- storagebox_info - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/166).
- storagebox_set_password - support the new Hetzner API. Note that the new API does not support setting a random password; you must always provide a password when using the new API (https://github.com/ansible-collections/community.hrobot/pull/168).
- storagebox_snapshot - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/168).
- storagebox_snapshot_info - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/168).
- storagebox_snapshot_plan - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/167).
- storagebox_snapshot_plan_info - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/167).
- storagebox_subaccount - no longer mark ``password_mode`` as ``no_log`` (https://github.com/ansible-collections/community.hrobot/pull/168).
- storagebox_subaccount - support the new Hetzner API. Note that the new API does not support setting a random password; you must always provide a password when using the new API to create a storagebox (https://github.com/ansible-collections/community.hrobot/pull/168).
- storagebox_subaccount_info - support the new Hetzner API (https://github.com/ansible-collections/community.hrobot/pull/168).

Bugfixes
--------

- robot inventory plugin - avoid using deprecated option when templating options (https://github.com/ansible-collections/community.hrobot/pull/165).

Known Issues
------------

- storagebox* modules - the Hetzner Robot API for storage boxes is `deprecated and will be sunset on July 30, 2025 <https://docs.hetzner.cloud/changelog#2025-06-25-new-api-for-storage-boxes>`__. The modules are currently not compatible with the new API. We will try to adjust them until then, but usage and return values might change slightly due to differences in the APIs.
  For the new API, an API token needs to be registered and provided as ``hetzner_token`` (https://github.com/ansible-collections/community.hrobot/pull/166).

v2.4.0
======

Release Summary
---------------

Bugfix and feature release.
This release contains three new modules that support the remaining aspects of Hetzner Storage Boxes that were not covered so far.

Bugfixes
--------

- storagebox - make sure that changes of boolean parameters are sent correctly to the Robot service (https://github.com/ansible-collections/community.hrobot/issues/160, https://github.com/ansible-collections/community.hrobot/pull/161).

New Modules
-----------

- community.hrobot.storagebox_snapshot_info - Query the snapshots for a storage box.
- community.hrobot.storagebox_subaccount - Create, update, or delete a subaccount for a storage box.
- community.hrobot.storagebox_subaccount_info - Query the subaccounts for a storage box.

v2.3.0
======

Release Summary
---------------

Feature release.

New Modules
-----------

- community.hrobot.storagebox_snapshot - Create, update, or delete a snapshot of a storage box.

v2.2.0
======

Release Summary
---------------

Feature release.

New Modules
-----------

- community.hrobot.reset_info - Query information on the resetter of a dedicated server.

v2.1.0
======

Release Summary
---------------

Feature release with several new modules and a deprecation.

Minor Changes
-------------

- All modules and plugins now have a ``rate_limit_retry_timeout`` option, which allows to configure for how long to wait in case of rate limiting errors. By default, the modules wait indefinitely. Setting the option to ``0`` does not retry (this was the behavior in previous versions), and a positive value sets a number of seconds to wait at most (https://github.com/ansible-collections/community.hrobot/pull/140).
- boot - it is now possible to specify SSH public keys in ``authorized_keys``. The fingerprint needed by the Robot API will be extracted automatically (https://github.com/ansible-collections/community.hrobot/pull/134).
- v_switch - the module is now part of the ``community.hrobot.robot`` action group, despite already being documented as part of it (https://github.com/ansible-collections/community.hrobot/pull/136).

Deprecated Features
-------------------

- boot - the various ``arch`` suboptions have been deprecated and will be removed from community.hrobot 3.0.0 (https://github.com/ansible-collections/community.hrobot/pull/134).

New Modules
-----------

- community.hrobot.storagebox - Modify a storage box's basic configuration.
- community.hrobot.storagebox_info - Query information on one or more storage boxes.
- community.hrobot.storagebox_set_password - (Re)set the password for a storage box.
- community.hrobot.storagebox_snapshot_plan - Modify a storage box's snapshot plans.
- community.hrobot.storagebox_snapshot_plan_info - Query the snapshot plans for a storage box.

v2.0.3
======

Release Summary
---------------

Maintenance release with updated documentation.

v2.0.2
======

Release Summary
---------------

Maintenance release with updated documentation.

v2.0.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- boot - use PHP array form encoding when sending multiple ``authorized_key`` (https://github.com/ansible-collections/community.hrobot/issues/112, https://github.com/ansible-collections/community.hrobot/pull/113).

v2.0.0
======

Release Summary
---------------

New major release 2.0.0.

Major Changes
-------------

- The ``community.hrobot`` collection now depends on the ``community.library_inventory_filtering_v1`` collection. This utility collection provides host filtering functionality for inventory plugins. If you use the Ansible community package, both collections are included and you do not have to do anything special. If you install the collection with ``ansible-galaxy collection install``, it will be installed automatically. If you install the collection by copying the files of the collection to a place where ansible-core can find it, for example by cloning the git repository, you need to make sure that you also have to install the dependency if you are using the inventory plugin (https://github.com/ansible-collections/community.hrobot/pull/101).

Minor Changes
-------------

- robot inventory plugin - add ``filter`` option which allows to include and exclude hosts based on Jinja2 conditions (https://github.com/ansible-collections/community.hrobot/pull/101).

Breaking Changes / Porting Guide
--------------------------------

- robot inventory plugin - ``filters`` is now no longer an alias of ``simple_filters``, but a new, different option (https://github.com/ansible-collections/community.hrobot/pull/101).

Removed Features (previously deprecated)
----------------------------------------

- The collection no longer supports Ansible, ansible-base, and ansible-core releases that are currently End of Life at the time of the 2.0.0 release. This means that Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, and ansible-core 2.13 are no longer supported. The collection might still work with these versions, but it can stop working at any moment without advance notice, and this will not be considered a bug (https://github.com/ansible-collections/community.hrobot/pull/101).

v1.9.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- inventory plugins - add unsafe wrapper to avoid marking strings that do not contain ``{`` or ``}`` as unsafe, to work around a bug in AWX (https://github.com/ansible-collections/community.hrobot/pull/102).

v1.9.1
======

Release Summary
---------------

Bugfix release.

Security Fixes
--------------

- robot inventory plugin - make sure all data received from the Hetzner robot service server is marked as unsafe, so remote code execution by obtaining texts that can be evaluated as templates is not possible (https://www.die-welt.net/2024/03/remote-code-execution-in-ansible-dynamic-inventory-plugins/, https://github.com/ansible-collections/community.hrobot/pull/99).

v1.9.0
======

Release Summary
---------------

Feature and maintenance release.

Minor Changes
-------------

- robot inventory plugin - the ``filters`` option has been renamed to ``simple_filters``. The old name still works until community.hrobot 2.0.0. Then it will change to allow more complex filtering with the ``community.library_inventory_filtering_v1`` collection's functionality (https://github.com/ansible-collections/community.hrobot/pull/94).

Deprecated Features
-------------------

- robot inventory plugin - the ``filters`` option has been renamed to ``simple_filters``. The old name will stop working in community.hrobot 2.0.0 (https://github.com/ansible-collections/community.hrobot/pull/94).

v1.8.2
======

Release Summary
---------------

Maintenance release with updated documentation.

Bugfixes
--------

- Show more information (if available) from error messages (https://github.com/ansible-collections/community.hrobot/pull/89).

v1.8.1
======

Release Summary
---------------

Maintenance release with updated documentation.

From this version on, community.hrobot is using the new `Ansible semantic markup
<https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_documenting.html#semantic-markup-within-module-documentation>`__
in its documentation. If you look at documentation with the ansible-doc CLI tool
from ansible-core before 2.15, please note that it does not render the markup
correctly. You should be still able to read it in most cases, but you need
ansible-core 2.15 or later to see it as it is intended. Alternatively you can
look at `the devel docsite <https://docs.ansible.com/ansible/devel/collections/community/hrobot/>`__
for the rendered HTML version of the documentation of the latest release.

Known Issues
------------

- Ansible markup will show up in raw form on ansible-doc text output for ansible-core before 2.15. If you have trouble deciphering the documentation markup, please upgrade to ansible-core 2.15 (or newer), or read the HTML documentation on https://docs.ansible.com/ansible/devel/collections/community/hrobot/.

v1.8.0
======

Release Summary
---------------

Feature release for the Hetzner firewall changes.

Major Changes
-------------

- firewall - Hetzner added output rules support to the firewall. This change unfortunately means that using old versions of the firewall module will always set the output rule list to empty, thus disallowing the server to send out packets (https://github.com/ansible-collections/community.hrobot/issues/75, https://github.com/ansible-collections/community.hrobot/pull/76).

Minor Changes
-------------

- firewall, firewall_info - add ``filter_ipv6`` and ``rules.output`` output to support the new IPv6 filtering and output rules features (https://github.com/ansible-collections/community.hrobot/issues/75, https://github.com/ansible-collections/community.hrobot/pull/76).
- firewall, firewall_info - add ``server_number`` option that can be used instead of ``server_ip`` to identify the server. Hetzner deprecated configuring the firewall by ``server_ip``, so using ``server_ip`` will stop at some point in the future (https://github.com/ansible-collections/community.hrobot/pull/77).

v1.7.0
======

Release Summary
---------------

Feature release.

New Modules
-----------

- community.hrobot.v_switch - Manage Hetzner's vSwitch

v1.6.0
======

Release Summary
---------------

Feature release with improved documentation.

Minor Changes
-------------

- Added a ``community.hrobot.robot`` module defaults group / action group. Use with ``group/community.hrobot.robot`` to provide options for all Hetzner Robot modules (https://github.com/ansible-collections/community.hrobot/pull/65).

v1.5.2
======

Release Summary
---------------

Maintenance release with a documentation improvement.

Minor Changes
-------------

- The collection repository conforms to the `REUSE specification <https://reuse.software/spec/>`__ except for the changelog fragments (https://github.com/ansible-collections/community.hrobot/pull/60).

v1.5.1
======

Release Summary
---------------

Maintenance release with small documentation fixes.

v1.5.0
======

Release Summary
---------------

Maintenance release changing the way licenses are declared. No functional changes.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root. Moreover, ``SPDX-License-Identifier:`` is used to declare the applicable license for every file that is not automatically generated (https://github.com/ansible-collections/community.hrobot/pull/52).

v1.4.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- robot inventory plugin - allow to template ``hetzner_user`` and ``hetzner_password`` (https://github.com/ansible-collections/community.hrobot/pull/49).

v1.3.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for the ``robot`` and ``failover`` module utils.

v1.3.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- Prepare collection for inclusion in an Execution Environment by declaring its dependencies (https://github.com/ansible-collections/community.hrobot/pull/45).

Bugfixes
--------

- robot inventory plugin - do not crash if a server neither has name or primary IP set. Instead, fall back to using the server's number as the name. This can happen if unnamed rack reservations show up in your server list (https://github.com/ansible-collections/community.hrobot/issues/40, https://github.com/ansible-collections/community.hrobot/pull/47).

v1.2.3
======

Release Summary
---------------

Docs update release.

v1.2.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- boot - fix incorrect handling of SSH authorized keys (https://github.com/ansible-collections/community.hrobot/issues/32, https://github.com/ansible-collections/community.hrobot/pull/33).

v1.2.1
======

Release Summary
---------------

Maintenance release.

Minor Changes
-------------

- Generic module HTTP support code - fix usage of ``fetch_url`` with changes in latest ansible-core ``devel`` branch (https://github.com/ansible-collections/community.hrobot/pull/30).

v1.2.0
======

Release Summary
---------------

Feature release with multiple new modules.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.hrobot/pull/18).
- firewall - rename option ``whitelist_hos`` to ``allowlist_hos``, keep old name as alias (https://github.com/ansible-collections/community.hrobot/pull/15).
- firewall, firewall_info - add return value ``allowlist_hos``, which contains the same value as ``whitelist_hos``. The old name ``whitelist_hos`` will be removed eventually (https://github.com/ansible-collections/community.hrobot/pull/15).
- robot module utils - add ``allow_empty_result`` parameter to ``plugin_open_url_json`` and ``fetch_url_json`` (https://github.com/ansible-collections/community.hrobot/pull/16).

New Modules
-----------

- community.hrobot.boot - Set boot configuration
- community.hrobot.reset - Reset a dedicated server
- community.hrobot.reverse_dns - Set or remove reverse DNS entry for IP
- community.hrobot.server - Update server information
- community.hrobot.server_info - Query information on one or more servers
- community.hrobot.ssh_key - Add, remove or update SSH key
- community.hrobot.ssh_key_info - Query information on SSH keys

v1.1.1
======

Release Summary
---------------

Bugfix release which reduces the number of HTTPS queries for the modules and plugins.

Bugfixes
--------

- robot - force HTTP basic authentication to reduce number of HTTPS requests (https://github.com/ansible-collections/community.hrobot/pull/9).

v1.1.0
======

Release Summary
---------------

Release with a new inventory plugin.

New Plugins
-----------

Inventory
~~~~~~~~~

- community.hrobot.robot - Hetzner Robot inventory source

v1.0.0
======

Release Summary
---------------

The ``community.hrobot`` continues the work on the Hetzner Robot modules from their state in ``community.general`` 1.2.0. The changes listed here are thus relative to the modules ``community.general.hetzner_*``.

Breaking Changes / Porting Guide
--------------------------------

- firewall - now requires the `ipaddress <https://pypi.org/project/ipaddress/>`_ library (https://github.com/ansible-collections/community.hrobot/pull/2).
