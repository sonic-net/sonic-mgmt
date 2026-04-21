==============================================================
Community Inventory Filtering Library Collection Release Notes
==============================================================

.. contents:: Topics

v1.1.5
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Improve and stricten typing information (https://github.com/ansible-collections/community.library_inventory_filtering/pull/42).

v1.1.4
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Fix accidental type extensions (https://github.com/ansible-collections/community.library_inventory_filtering/pull/40).

v1.1.3
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Stop using ``ansible.module_utils.six`` to avoid user-facing deprecation messages with ansible-core 2.20, while still supporting older ansible-core versions (https://github.com/ansible-collections/community.library_inventory_filtering/pull/39).

v1.1.2
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Avoid deprecated functionality in ansible-core 2.20 (https://github.com/ansible-collections/community.library_inventory_filtering/pull/38).

v1.1.1
======

Release Summary
---------------

Maintenance release.

v1.1.0
======

Release Summary
---------------

Feature, bugfix, and maintenance release with support for Data Tagging.

Minor Changes
-------------

- Add typing information for the ``inventory_filter`` plugin utils (https://github.com/ansible-collections/community.library_inventory_filtering/pull/22).

Bugfixes
--------

- inventory_filter plugin utils - make compatible with ansible-core's Data Tagging feature (https://github.com/ansible-collections/community.library_inventory_filtering/pull/24).
- inventory_plugin plugin util - ``parse_filters`` now filters ``None`` values with allowed keys (https://github.com/ansible-collections/community.library_inventory_filtering/pull/27).

v1.0.2
======

Release Summary
---------------

Maintenance release with updated links.

v1.0.1
======

Release Summary
---------------

Maintenance release with documentation.

v1.0.0
======

Release Summary
---------------

First production ready release.

v0.1.0
======

Release Summary
---------------

Initial test release.
