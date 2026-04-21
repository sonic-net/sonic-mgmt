====================================================
Community MySQL and MariaDB Collection Release Notes
====================================================

.. contents:: Topics

This changelog describes changes after version 2.0.0.

v3.16.1
=======

Release Summary
---------------

This is a patch release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- mysql_info - Fix slave status for source terminology introduced in MySQL 8.0.23 (https://github.com/ansible-collections/community.mysql/issues/682).
- mysql_user, mysql_role - fix not existent grant when revoking perms on user/role which do not have any other perms than grant option (https://github.com/ansible-collections/community.mysql/issues/664).

v3.16.0
=======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- `mysql_query` - add new `session_vars` argument, similar to ansible-collections/community.mysql#489.

v3.15.0
=======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.'

Minor Changes
-------------

- mysql_db - Add support for ``sql_log_bin`` option (https://github.com/ansible-collections/community.mysql/issues/700).

Bugfixes
--------

- mysql_query - fix a Python 2 compatibility issue caused by the addition of ``execution_time_ms`` in version 3.12 (see https://github.com/ansible-collections/community.mysql/issues/716).
- mysql_user - fix a crash (unable to parse the MySQL grant string: SET DEFAULT ROLE `somerole` FOR `someuser`@`%`) when using the ``mysql_user`` module with a DEFAULT role present in MariaDB. The DEFAULT role is now ignored by the parser (https://github.com/ansible-collections/community.mysql/issues/710).

v3.14.0
=======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.'

Minor Changes
-------------

- mysql_replication - change default value for ``primary_ssl_verify_server_cert`` from False to None. This should not affect existing playbooks (https://github.com/ansible-collections/community.mysql/pull/707).

Bugfixes
--------

- mysql_info - fix a crash (ERROR 1141, There is no such grant defined for user 'PUBLIC' on host '%') when using the ``users_info`` filter with a PUBLIC role present in MariaDB 10.11+. Do note that the fix doesn't change the fact that the module won't return the privileges from the PUBLIC role in the users privileges list. It can't do that because you have to login as the particular user and use `SHOW GRANTS FOR CURRENT_USER`. We considered using an aggregation with the `SHOW GRANTS FOR PUBLIC` command. However, this approach would make copying users from one server to another transform the privileges inherited from the role as if they were direct privileges on the user.
- mysql_replication - fixed an issue where setting ``primary_ssl_verify_server_cert`` to false had no effect (https://github.com/ansible-collections/community.mysql/issues/689).

v3.13.0
=======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Minor Changes
-------------

- Integration tests for MariaDB 11.4 have replaced those for 10.5. The previous version is now 10.11.
- mysql_user - add ``locked`` option to lock/unlock users, this is mainly used to have users that will act as definers on stored procedures.

Bugfixes
--------

- mysql_db - fix dump and import to find MariaDB binaries (mariadb and mariadb-dump) when MariaDB 11+ is used and symbolic links to MySQL binaries are absent.

v3.12.0
=======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Minor Changes
-------------

- mysql_db - added ``zstd`` (de)compression support for ``import``/``dump`` states (https://github.com/ansible-collections/community.mysql/issues/696).
- mysql_query - returns the ``execution_time_ms`` list containing execution time per query in milliseconds.

v3.11.0
=======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.

This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Minor Changes
-------------

- mysql_info - adds the count of tables for each database to the returned values. It is possible to exclude this new field using the ``db_table_count`` exclusion filter. (https://github.com/ansible-collections/community.mysql/pull/691)

Bugfixes
--------

- mysql_user,mysql_role - The sql_mode ANSI_QUOTES affects how the modules mysql_user and mysql_role compare the existing privileges with the configured privileges, as well as decide whether double quotes or backticks should be used in the GRANT statements. Pointing out in issue 671, the modules mysql_user and mysql_role allow users to enable/disable ANSI_QUOTES in session variable (within a DB session, the session variable always overwrites the global one). But due to the issue, the modules do not check for ANSI_MODE in the session variable, instead, they only check in the GLOBAL one.That behavior is not only limiting the users' flexibility, but also not allowing users to explicitly disable ANSI_MODE to work around such bugs like https://bugs.mysql.com/bug.php?id=115953. (https://github.com/ansible-collections/community.mysql/issues/671)

v3.10.3
=======

Release Summary
---------------

This is a bugfix release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Bugfixes
--------

- mysql_user - add correct ``ed25519`` auth plugin handling when creating a user (https://github.com/ansible-collections/community.mysql/pull/676).

v3.10.2
=======

Release Summary
---------------

This is a bugfix release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Bugfixes
--------

- mysql_user - add correct ``ed25519`` auth plugin handling when creating a user (https://github.com/ansible-collections/community.mysql/issues/672).

v3.10.1
=======

Release Summary
---------------

This is a patch release of the ``community.mysql`` collection.
Besides a bugfix, it contains an important upcoming breaking-change information.

Deprecated Features
-------------------

- mysql_user - the ``user`` alias of the ``name`` argument has been deprecated and will be removed in collection version 5.0.0. Use the ``name`` argument instead.

Bugfixes
--------

- mysql_user - module makes changes when is executed with ``plugin_auth_string`` parameter and check mode.

v3.10.0
=======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Minor Changes
-------------

- mysql_info - Add ``tls_requires`` returned value for the ``users_info`` filter (https://github.com/ansible-collections/community.mysql/pull/628).
- mysql_info - return a database server engine used (https://github.com/ansible-collections/community.mysql/issues/644).
- mysql_replication - Adds support for `CHANGE REPLICATION SOURCE TO` statement (https://github.com/ansible-collections/community.mysql/issues/635).
- mysql_replication - Adds support for `SHOW BINARY LOG STATUS` and `SHOW BINLOG STATUS` on getprimary mode.
- mysql_replication - Improve detection of IsReplica and IsPrimary by inspecting the dictionary returned from the SQL query instead of relying on variable types. This ensures compatibility with changes in the connector or the output of SHOW REPLICA STATUS and SHOW MASTER STATUS, allowing for easier maintenance if these change in the future.
- mysql_user - Add salt parameter to generate static hash for `caching_sha2_password` and `sha256_password` plugins.

Deprecated Features
-------------------

- collection - support of mysqlclient connector is deprecated - use PyMySQL connector instead! We will stop testing against it in collection version 4.0.0 and remove the related code in 5.0.0 (https://github.com/ansible-collections/community.mysql/issues/654).
- mysql_info - The ``users_info`` filter returned variable ``plugin_auth_string`` contains the hashed password and it's misleading, it will be removed from community.mysql 4.0.0. Use the `plugin_hash_string` return value instead (https://github.com/ansible-collections/community.mysql/pull/629).

Bugfixes
--------

- mysql_info - Add ``plugin_hash_string`` to ``users_info`` filter's output. The existing ``plugin_auth_string`` contained the hashed password and thus is missleading, it will be removed from community.mysql 4.0.0. (https://github.com/ansible-collections/community.mysql/pull/629).
- mysql_user - Added a warning to update_password's on_new_username option if multiple accounts with the same username but different passwords exist (https://github.com/ansible-collections/community.mysql/pull/642).
- mysql_user - Fix ``tls_requires`` not removing ``SSL`` and ``X509`` when sets as empty (https://github.com/ansible-collections/community.mysql/pull/628).
- mysql_user - Fix idempotence when using variables from the ``users_info`` filter of ``mysql_info`` as an input (https://github.com/ansible-collections/community.mysql/pull/628).
- mysql_user - Fixed an IndexError in the update_password functionality introduced in PR https://github.com/ansible-collections/community.mysql/pull/580 and released in community.mysql 3.8.0. If you used this functionality, please avoid versions 3.8.0 to 3.9.0 (https://github.com/ansible-collections/community.mysql/pull/642).
- mysql_user - add correct ``ed25519`` auth plugin handling (https://github.com/ansible-collections/community.mysql/issues/6).
- mysql_variables - fix the module always changes on boolean values (https://github.com/ansible-collections/community.mysql/issues/652).

v3.9.0
======

Release Summary
---------------

This is a minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Major Changes
-------------

- Collection version 2.*.* is EOL, no more bugfixes will be backported. Please consider upgrading to the latest version.

Minor Changes
-------------

- mysql_user - add the ``password_expire`` and ``password_expire_interval`` arguments to implement the password expiration management for mysql user (https://github.com/ansible-collections/community.mysql/pull/598).
- mysql_user - add user attribute support via the ``attributes`` parameter and return value (https://github.com/ansible-collections/community.mysql/pull/604).

Bugfixes
--------

- mysql_info - the ``slave_status`` filter was returning an empty list on MariaDB with multiple replication channels. It now returns all channels by running ``SHOW ALL SLAVES STATUS`` for MariaDB servers (https://github.com/ansible-collections/community.mysql/issues/603).

v3.8.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this
collection that have been made after the previous release.

Major Changes
-------------

- The community.mysql collection no longer supports ``ansible-core 2.12`` and ``ansible-core 2.13``. While we take no active measures to prevent usage and there are no plans to introduce incompatible code to the modules, we will stop testing those versions. Both are or will soon be End of Life and if you are still using them, you should consider upgrading to the ``latest Ansible / ansible-core 2.15 or later`` as soon as possible (https://github.com/ansible-collections/community.mysql/pull/574).
- mysql_role - the ``column_case_sensitive`` argument's default value will be changed to ``true`` in community.mysql 4.0.0. If your playbook expected the column to be automatically uppercased for your roles privileges, you should set this to false explicitly (https://github.com/ansible-collections/community.mysql/issues/578).
- mysql_user - the ``column_case_sensitive`` argument's default value will be changed to ``true`` in community.mysql 4.0.0. If your playbook expected the column to be automatically uppercased for your users privileges, you should set this to false explicitly (https://github.com/ansible-collections/community.mysql/issues/577).

Minor Changes
-------------

- mysql_info - add filter ``users_info`` (https://github.com/ansible-collections/community.mysql/pull/580).
- mysql_role - add ``column_case_sensitive`` option to prevent field names from being uppercased (https://github.com/ansible-collections/community.mysql/pull/569).
- mysql_user - add ``column_case_sensitive`` option to prevent field names from being uppercased (https://github.com/ansible-collections/community.mysql/pull/569).

v3.7.2
======

Release Summary
---------------

This is a patch release of the community.mysql collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- mysql module utils - use the connection arguments ``db`` instead of ``database`` and ``passwd`` instead of ``password`` when running with MySQLdb < 2.0.0 (https://github.com/ansible-collections/community.mysql/pull/553).

v3.7.1
======

Release Summary
---------------

This is a patch release of the community.mysql collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- mysql module utils - use the connection arguments ``db`` instead of ``database`` and ``passwd`` instead of ``password`` when running with older mysql drivers (MySQLdb < 2.1.0 or PyMySQL < 1.0.0) (https://github.com/ansible-collections/community.mysql/pull/551).

v3.7.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- mysql module utils - change deprecated connection parameters ``passwd`` and ``db`` to ``password`` and ``database`` (https://github.com/ansible-collections/community.mysql/pull/177).
- mysql_user - add ``MAX_STATEMENT_TIME`` support for mariadb to the ``resource_limits`` argument (https://github.com/ansible-collections/community.mysql/issues/211).

v3.6.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- mysql_info - add ``connector_name`` and ``connector_version`` to returned values (https://github.com/ansible-collections/community.mysql/pull/497).
- mysql_role - enable auto_commit to avoid MySQL metadata table lock (https://github.com/ansible-collections/community.mysql/issues/479).
- mysql_user - add plugin_auth_string as optional parameter to use a specific pam service if pam/auth_pam plugin is used (https://github.com/ansible-collections/community.mysql/pull/445).
- mysql_user - add the ``session_vars`` argument to set session variables at the beginning of module execution (https://github.com/ansible-collections/community.mysql/issues/478).
- mysql_user - display a more informative invalid privilege exception. Changes the exception handling of the granting permission logic to show the query executed , params and the exception message granting privileges fails` (https://github.com/ansible-collections/community.mysql/issues/465).
- mysql_user - enable auto_commit to avoid MySQL metadata table lock (https://github.com/ansible-collections/community.mysql/issues/479).
- setup_mysql - update MySQL tarball URL (https://github.com/ansible-collections/community.mysql/pull/491).

Bugfixes
--------

- mysql_user - when revoke privs consists only of ``GRANT``, a 2nd revoke query is executed with empty privs to revoke that ended in an SQL exception (https://github.com/ansible-collections/community.mysql/pull/503).
- mysql_variables - add uppercase character pattern to regex to allow GLOBAL variables containing uppercase characters. This recognizes variable names used in Galera, for example, ``wsrep_OSU_method``, which breaks the normal pattern of all lowercase characters (https://github.com/ansible-collections/community.mysql/pull/501).

v3.5.1
======

Release Summary
---------------

This is the patch release of the ``community.mysql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- mysql_user, mysql_role - mysql/mariadb recent versions translate 'ALL PRIVILEGES' to a list of specific privileges. That caused a change every time we modified user privileges. This fix compares privs before and after user modification to avoid this infinite change (https://github.com/ansible-collections/community.mysql/issues/77).

v3.5.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.4.0.

Minor Changes
-------------

- mysql_replication - add a new option: ``primary_ssl_verify_server_cert`` (https://github.com//pull/435).

Bugfixes
--------

- mysql_user - grant option was revoked accidentally when modifying users. This fix revokes grant option only when privs are setup to do that (https://github.com/ansible-collections/community.mysql/issues/77#issuecomment-1209693807).

v3.4.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.3.0.

Major Changes
-------------

- mysql_db - the ``pipefail`` argument's default value will be changed to ``true`` in community.mysql 4.0.0. If your target machines do not use ``bash`` as a default interpreter, set ``pipefail`` to ``false`` explicitly. However, we strongly recommend setting up ``bash`` as a default and ``pipefail=true`` as it will protect you from getting broken dumps you don't know about (https://github.com/ansible-collections/community.mysql/issues/407).

Minor Changes
-------------

- mysql_db - add the ``chdir`` argument to avoid failings when a dump file contains relative paths (https://github.com/ansible-collections/community.mysql/issues/395).
- mysql_db - add the ``pipefail`` argument to avoid broken dumps when ``state`` is ``dump`` and compression is used (https://github.com/ansible-collections/community.mysql/issues/256).

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for various module utils.
- mysql_db - Using compression masks errors messages from mysql_dump. By default the fix is inactive to ensure retro-compatibility with system without bash. To activate the fix, use the module option ``pipefail=true`` (https://github.com/ansible-collections/community.mysql/issues/256).
- mysql_replication - when the ``primary_ssl`` argument is set to ``no``, the module will turn off SSL (https://github.com/ansible-collections/community.mysql/issues/393).

v3.3.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.2.1.

Minor Changes
-------------

- mysql_role - add the argument ``members_must_exist`` (boolean, default true). The assertion that the users supplied in the ``members`` argument exist is only executed when the new argument ``members_must_exist`` is ``true``, to allow opt-out (https://github.com/ansible-collections/community.mysql/pull/369).
- mysql_user - Add the option ``on_new_username`` to argument ``update_password`` to reuse the password (plugin and authentication_string) when creating a new user if some user with the same name already exists. If the existing user with the same name have varying passwords, the password from the arguments is used like with ``update_password: always`` (https://github.com/ansible-collections/community.mysql/pull/365).
- mysql_user - Add the result field ``password_changed`` (boolean). It is true, when the user got a new password. When the user was created with ``update_password: on_new_username`` and an existing password was reused, ``password_changed`` is false (https://github.com/ansible-collections/community.mysql/pull/365).

Bugfixes
--------

- mysql_query - fix false change reports when ``IF EXISTS/IF NOT EXISTS`` clause is used (https://github.com/ansible-collections/community.mysql/issues/268).
- mysql_role - don't add members to a role when creating the role and ``detach_members: true`` is set (https://github.com/ansible-collections/community.mysql/pull/367).
- mysql_role - in some cases (when "SHOW GRANTS" did not use backticks for quotes), no unwanted members were detached from the role (and redundant "GRANT" statements were executed for wanted members). This is fixed by querying the existing role members from the mysql.role_edges (MySQL) or mysql.roles_mapping (MariaDB) tables instead of parsing the "SHOW GRANTS" output (https://github.com/ansible-collections/community.mysql/pull/368).
- mysql_user - fix logic when ``update_password`` is set to ``on_create`` for users using ``plugin*`` arguments (https://github.com/ansible-collections/community.mysql/issues/334). The ``on_create`` sets ``password`` to None for old mysql_native_authentication but not for authentiation methods which uses the ``plugin*`` arguments. This PR changes this so ``on_create`` also exchange ``plugin``, ``plugin_hash_string``, ``plugin_auth_string`` to None in the list of arguments to change

v3.2.1
======

Release Summary
---------------

This is the patch release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.2.0.

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.

v3.2.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.1.3.

Major Changes
-------------

- The community.mysql collection no longer supports ``Ansible 2.9`` and ``ansible-base 2.10``. While we take no active measures to prevent usage and there are no plans to introduce incompatible code to the modules, we will stop testing against ``Ansible 2.9`` and ``ansible-base 2.10``. Both will very soon be End of Life and if you are still using them, you should consider upgrading to the ``latest Ansible / ansible-core 2.11 or later`` as soon as possible (https://github.com/ansible-collections/community.mysql/pull/343).

Minor Changes
-------------

- mysql_user and mysql_role: Add the argument ``subtract_privs`` (boolean, default false, mutually exclusive with ``append_privs``). If set, the privileges given in ``priv`` are revoked and existing privileges are kept (https://github.com/ansible-collections/community.mysql/pull/333).

Bugfixes
--------

- mysql_user - fix missing dynamic privileges after revoke and grant privileges to user (https://github.com/ansible-collections/community.mysql/issues/120).
- mysql_user - fix parsing privs when a user has roles assigned (https://github.com/ansible-collections/community.mysql/issues/231).

v3.1.3
======

Release Summary
---------------

This is the patch release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.1.2.

Bugfixes
--------

- mysql_replication - fails when using the `primary_use_gtid` option with `slave_pos` or `replica_pos` (https://github.com/ansible-collections/community.mysql/issues/335).
- mysql_role - remove redundant connection closing (https://github.com/ansible-collections/community.mysql/pull/330).
- mysql_user - fix the possibility for a race condition that breaks certain (circular) replication configurations when ``DROP USER`` is executed on multiple nodes in the replica set. Adding ``IF EXISTS`` avoids the need to use ``sql_log_bin: no`` making the statement always replication safe (https://github.com/ansible-collections/community.mysql/pull/287).

v3.1.2
======

Release Summary
---------------

This is the patch release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.1.1.

Bugfixes
--------

- Collection core functions - fixes related to the mysqlclient Python connector (https://github.com/ansible-collections/community.mysql/issues/292).

v3.1.1
======

Release Summary
---------------

This is the patch release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.1.0.

Bugfixes
--------

- mysql_role - make the ``set_default_role_all`` parameter actually working (https://github.com/ansible-collections/community.mysql/pull/282).

v3.1.0
======

Release Summary
---------------

This is the minor release of the ``community.mysql`` collection.
This changelog contains all changes to the modules in this collection
that have been added after the release of ``community.mysql`` 3.0.0.

Minor Changes
-------------

- Added explicit description of the supported versions of databases and connectors. Changes to the collection are **NOT** tested against database versions older than `mysql 5.7.31` and `mariadb 10.2.37` or connector versions older than `pymysql 0.7.10` and `mysqlclient 2.0.1`. (https://github.com/ansible-collections/community.mysql/discussions/141)
- mysql_user - added the ``force_context`` boolean option to set the default database context for the queries to be the ``mysql`` database. This way replication/binlog filters can catch the statements (https://github.com/ansible-collections/community.mysql/issues/265).

Bugfixes
--------

- Collection core functions - use vendored version of ``distutils.version`` instead of the deprecated Python standard library ``distutils`` (https://github.com/ansible-collections/community.mysql/pull/269).

v3.0.0
======

Release Summary
---------------

This is the major release of the ``community.mysql`` collection.
This changelog contains all breaking changes to the modules in this collection
that have been added after the release of ``community.mysql`` 2.3.2.

Breaking Changes / Porting Guide
--------------------------------

- mysql_replication - remove ``Is_Slave`` and ``Is_Master`` return values (were replaced with ``Is_Primary`` and ``Is_Replica`` (https://github.com/ansible-collections/community.mysql/issues/145).
- mysql_replication - remove the mode options values containing ``master``/``slave`` and the master_use_gtid option ``slave_pos`` (were replaced with corresponding ``primary``/``replica`` values) (https://github.com/ansible-collections/community.mysql/issues/145).
- mysql_user - remove support for the `REQUIRESSL` special privilege as it has ben superseded by the `tls_requires` option (https://github.com/ansible-collections/community.mysql/discussions/121).
- mysql_user - validate privileges using database engine directly (https://github.com/ansible-collections/community.mysql/issues/234 https://github.com/ansible-collections/community.mysql/pull/243). Do not validate privileges in this module anymore.
