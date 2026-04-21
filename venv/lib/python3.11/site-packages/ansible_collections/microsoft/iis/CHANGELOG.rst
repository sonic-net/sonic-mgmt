=============================================================
Ansible Microsoft Internet Information Services Release Notes
=============================================================

.. contents:: Topics

v1.1.0
======

Release Summary
---------------

Release summary for v1.1.0

Minor Changes
-------------

- Add official support for Ansible 2.20

Bugfixes
--------

- website_info - Fix error when retrieving website information but none exist - https://github.com/ansible-collections/microsoft.iis/issues/44

v1.0.3
======

Release Summary
---------------

Release summary for v1.0.3

Bugfixes
--------

- website_info - fixed a crash when the specified iis site does not exist, ensuring the module no longer inserts a ``null`` in the site list. (https://github.com/ansible-collections/microsoft.iis/pull/36)

v1.0.2
======

Release Summary
---------------

Another minor release for Galaxy/AH documention update

v1.0.1
======

Release Summary
---------------

Minor release for Galaxy/AH documention update

v1.0.0
======

Release Summary
---------------

First release of the microsoft.iis collection
