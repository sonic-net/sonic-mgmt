===========================
Community SAP Release Notes
===========================

.. contents:: Topics

v1.5.0
======

Release Summary
---------------

This release removes `Python 2` support and updates `ansible-test` workflow to validate latest versions.
Documentation was updated to reflect supported and tested versions.

Minor Changes
-------------
- collection - Update workflow `ansible-test` to include latest versions (https://github.com/sap-linuxlab/community.sap_libs/pull/54)
- collection - Enhance `ansible-test` CI action, remove Python 2 and fix detected issues (https://github.com/sap-linuxlab/community.sap_libs/pull/60)
- collection - Update documentation and changelog for `1.5.0` release (https://github.com/sap-linuxlab/community.sap_libs/pull/61)
- sap_hdbsql - add -E option to filepath command (https://github.com/sap-linuxlab/community.sap_libs/pull/42)
- sap_control_exec - Remove unsupported functions (https://github.com/sap-linuxlab/community.sap_libs/pull/45)
- collection - Pipeline fixes and drop test support for ansible below 2.13 (https://github.com/sap-linuxlab/community.sap_libs/pull/43)


v1.4.1
======

Release Summary
---------------

This is the 1.4.1 patch release of the ``community.sap_libs`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- fixes failures in sanity test for plugins/modules/sap_pyrfc.py
- fixes failures in sanity test for tests/unit/compat/builtins.py
- fixes failures in sanity test for tests/unit/plugins/modules/test_sap_system_facts.py
- fixes failures in sanity test for tests/unit/plugins/modules/test_sap_system_facts.py
- fixes pipeline warnings
- sapcontrol_exec - This pr fixes problems on c(StartSystem), c(StopSystem), c(RestartSystem) which needs parameters they ca not provided by the parameters argument because of special format like c(waittimeout=1) without string quotes. This is caused by the suds module itself.

v1.4.0
======

Release Summary
---------------

This is the 1.3.0 minor release of the ``community.sap_libs`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- fix a bug where some commands produces no output which cause to crash the module.
- modules - fix a "variable used before assignment" that cannot be reached but causes sanity test failures.

v1.3.0
======

Release Summary
---------------

This is the 1.3.0 minor release of the ``community.sap_libs`` collection. This changelog contains all changes to the modules and plugins in this collection that have been made after the previous release.

Minor Changes
-------------

- License requirements are updated.
- The modules purposes are described clearer.
- The namespaces of the modules are removed to provide a flatter design.
- hana_query - module is moved to sap_hdbsql.
- sapcontrol - module is moved to sap_control_exec to have a clearer separation to other roles and references.

v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.sap_libs`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- syp_system_facts - fix a typo in the usage example which lead to an error if it used as supposed.

New Modules
-----------

- sap_pyrfc - Ansible Module for use of SAP PyRFC to execute SAP RFCs (Remote Function Calls) to SAP remote-enabled function modules

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.sap_libs`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

New Modules
-----------

System
~~~~~~

- sapcontrol - Ansible Module to execute SAPCONTROL

v1.0.0
======

Release Summary
---------------

This is the minor release of the ``community.sap`` collection. It is the initial relase for the ``community.sap`` collection

New Modules
-----------

Database
~~~~~~~~

saphana
^^^^^^^

- hana_query - Ansible Module to execute SQL on SAP HANA

Files
~~~~~

- sapcar_extract - Manages SAP SAPCAR archives

Identity
~~~~~~~~

- sap_company - This module will manage a company entities in a SAP S4HANA environment
- sap_user - This module will manage a user entities in a SAP S4/HANA environment

System
~~~~~~

- sap_snote - This module will upload and (de)implements C(SNOTES) in a SAP S4HANA environment.
- sap_system_facts - Gathers SAP facts in a host
- sap_task_list_execute - Perform SAP Task list execution
