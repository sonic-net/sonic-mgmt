===========================================
Community ProxySQL Collection Release Notes
===========================================

.. contents:: Topics

v1.7.0
======

Release Summary
---------------

This is a minor release of the ``community.proxysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxysql_mysql_users - Creating users with the ``caching_sha2_password`` plugin (https://github.com/ansible-collections/community.proxysql/pull/173).

New Modules
-----------

- community.proxysql.proxysql_mysql_hostgroup_attributes - Manages hostgroup attributes using the ProxySQL admin interface

v1.6.0
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxysql role - add the pidfile location management (https://github.com/ansible-collections/community.proxysql/pull/145).
- role_proxysql - Update default proxysql version and fix small bugs (https://github.com/ansible-collections/community.proxysql/pull/92).

Bugfixes
--------

- module_utils - fix ProxySQL version parsing that fails when a suffix wasn't present in the version (https://github.com/ansible-collections/community.proxysql/issues/154).
- role_proxysql - Correct package name (python3-mysqldb instead of python-mysqldb) (https://github.com/ansible-collections/community.proxysql/pull/89).
- role_proxysql - Dynamic user/password in .my.cnf (https://github.com/ansible-collections/community.proxysql/pull/89).

v1.5.1
======

Release Summary
---------------

This is the bugfix release of the ``community.proxysql`` collection.

Bugfixes
--------

- proxysql_manage_config - Fix ``check_mode`` (https://github.com/ansible-collections/community.proxysql/pull/138).

v1.5.0
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.

Minor Changes
-------------

- roles/proxysql - add support for configuring REST API (https://github.com/ansible-collections/community.proxysql/pull/110).

Bugfixes
--------

- proxysql_query_rules_fast_routing - fix query parameter order, that prevents updating ``destination_hostgroup`` parameter (https://github.com/ansible-collections/community.proxysql/pull/108).
- proxysql_query_rules_fast_routing - remove unnecessary ``flagIN`` check, that makes it impossible to update the ``destination_hostgroup`` parameter (https://github.com/ansible-collections/community.proxysql/pull/108).
- roles/proxysql - Fix wait_for task when `proxysql_admin_bind_address` is overridden (https://github.com/ansible-collections/community.proxysql/pull/115).
- roles/proxysql - Missing proxysql_global_variables module parameters (https://github.com/ansible-collections/community.proxysql/pull/116).

v1.4.0
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.
Because ansible <= 2.10 is EOL, ``community.proxysql`` will only be tested against ansible > 2.10.

Bugfixes
--------

- roles/proxysql - As of ProxySQL 2.4.0, `client_found_rows` mysql variable has been removed (https://github.com/ansible-collections/community.proxysql/pull/101).

v1.3.2
======

Release Summary
---------------

This is a bugfix release of the ``community.proxysql`` collection.

Bugfixes
--------

- module_utils/mysql.py - Proxysql version suffix may not be an integer (https://github.com/ansible-collections/community.proxysql/pull/96).

v1.3.1
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- module_utils - Refactor save_config_to_disk and load_config_to_runtime (https://github.com/ansible-collections/community.proxysql/pull/78).
- proxysql_mysql_users - Add missing ``no_log`` option to ``encrypt_password`` parameter (https://github.com/ansible-collections/community.proxysql/pull/86).

v1.3.0
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxysql_query_rules - add ``next_query_flagIN`` argument (https://github.com/ansible-collections/community.proxysql/pull/74).
- proxysql_replication_hostgroups - implement ``check_type`` parameter (https://github.com/ansible-collections/community.proxysql/pull/69).

Bugfixes
--------

- proxysql_query_rules - fix backwards compatibility. Proxysql > 2 does not support parameter ``cache_empty_result`` (https://github.com/ansible-collections/community.proxysql/pull/77).
- proxysql_replication_hostgroups - ability to change ``reader_hostgroup`` (https://github.com/ansible-collections/community.proxysql/pull/69).

v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- refactor ``perform_checks`` function and move ``login_port`` check to ``module_utils/mysql.py`` (https://github.com/ansible-collections/community.proxysql/pull/63).

New Modules
-----------

- community.proxysql.proxysql_info - Gathers information about proxysql server

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.proxysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- Refactoring of connector presence checking (https://github.com/ansible-collections/community.proxysql/pull/50).
- Replace MySQL-Python with mysqlclient in the import error message (https://github.com/ansible-collections/community.proxysql/pull/50).
- proxysql_query_rules - added new parameters ``cache_empty_result``, ``multiplex``, ``OK_msg`` (https://github.com/ansible-collections/community.proxysql/issues/24).

New Modules
-----------

- community.proxysql.proxysql_query_rules_fast_routing - Modifies query rules for fast routing policies using the proxysql admin interface

v1.0.0
======

Release Summary
---------------

This is the first proper release of the ``community.proxysql`` collection. This changelog contains all changes to the modules in this collection that were added after the release of Ansible 2.9.0.
