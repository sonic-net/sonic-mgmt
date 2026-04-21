=============================================
Community PostgreSQL Collection Release Notes
=============================================

.. contents:: Topics

v4.2.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_privs - support MAINTAIN privilege on tables (added in PostgreSQL 17) (https://github.com/ansible-collections/community.postgresql/pull/888).

Bugfixes
--------

- postgresql_db - Fix connection limit not being set when value is "0" (https://github.com/ansible-collections/community.postgresql/issues/879).
- postgresql_db - fixed ``session_role`` parameter that was being ignored for raw connections (https://github.com/ansible-collections/community.postgresql/pull/865)
- postgresql_db - restoring from ``.sql`` files would execute the file twice. The module now avoids using both ``--file`` and stdin redirection simultaneously (https://github.com/ansible-collections/community.postgresql/issues/882).

v4.1.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Deprecated Features
-------------------

- postgresql modules - the ``port`` alias is deprecated and will be removed in ``community.postgresql 5.0.0``, use the ``login_port`` argument instead.

Bugfixes
--------

- postgresql_schema - change reported in check_mode was negated. Now it reports a change when removing an existing schema (https://github.com/ansible-collections/community.postgresql/pull/858)

v4.0.1
======

Release Summary
---------------

This is a patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- postgresql_alter_system - fix failure when max_val contains a huge number written in scientific notation (https://github.com/ansible-collections/community.postgresql/issues/853).

v4.0.0
======

Release Summary
---------------

This is a major release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Major Changes
-------------

- the collection does not test against Python 2 and starts accepting content written in Python 3 since collection version 4.0.0 (https://github.com/ansible-collections/community.postgresql/issues/829).

Minor Changes
-------------

- postgresql_user - return a PostgreSQL error message when a user cannot be removed.

Deprecated Features
-------------------

- postgresql modules = the ``login``, ``unix_socket`` and ``host`` aliases are deprecated and will be removed in ``community.postgresql 5.0.0``, use the ``login_user``, ``login_unix_socket`` and ``login_host`` arguments instead.
- postgresql_set - the module has been deprecated and will be removed in ``community.postgresql 5.0.0``. Please use the ``community.postgresql.postgresql_alter_system`` module instead (https://github.com/ansible-collections/community.postgresql/issues/823).

Removed Features (previously deprecated)
----------------------------------------

- postgresql_info - the db alias has been removed in ``community.postgresql 4.0.0``. Please use the ``login_db`` option instead (https://github.com/ansible-collections/community.postgresql/issues/801).
- postgresql_lang - the module has been removed in ``community.postgresql 4.0.0``. Please use the ``community.postgresql.postgresql_ext`` module instead (https://github.com/ansible-collections/community.postgresql/issues/561).
- postgresql_privs - the ``password`` argument has been removed in ``community.postgresql 4.0.0``. Use the ``login_password`` argument instead (https://github.com/ansible-collections/community.postgresql/issues/408).
- postgresql_user - the ``priv`` argument has been removed in ``community.postgresql 4.0.0``. Please use the ``community.postgresql.postgresql_privs`` module to grant/revoke privileges instead (https://github.com/ansible-collections/community.postgresql/issues/493).

v3.14.0
=======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Deprecated Features
-------------------

- postgresql_copy - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_db - the ``rename`` choice of the state option is deprecated and will be removed in version 5.0.0, use the ``postgresql_query`` module instead.
- postgresql_ext - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_idx - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_membership - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_owner - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_ping - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_privs - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_publication - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_query - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_schema - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_script - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_sequence - the ``rename_to`` option is deprecated and will be removed in version 5.0.0, use the ``postgresql_query`` module instead.
- postgresql_sequence - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_set - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_slot - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_subscription - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_table - the ``rename`` option is deprecated and will be removed in version 5.0.0, use the ``postgresql_query module`` instead.
- postgresql_table - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_tablespace - the ``rename_to`` option is deprecated and will be removed in version 5.0.0, use the ``postgresql_query`` module instead.
- postgresql_tablespace - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.
- postgresql_user_obj_stat_info - the parameter aliases db and database are deprecated and will be removed in community.postgresql 5.0.0. Use login_db instead.

v3.13.0
=======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- postgresql_table - consider schema name when checking for table (https://github.com/ansible-collections/community.postgresql/issues/817).  Table names are only unique within a schema. This allows using the same table name in multiple schemas.

New Modules
-----------

- postgresql_alter_system - Change a PostgreSQL server configuration parameter

v3.12.0
=======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_publication - added ``rowfilters`` parameter that adds support for row filtering on PG publications (https://github.com/ansible-collections/community.postgresql/pull/813)

v3.11.0
=======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_pg_hba - adds 'pg_hba_string' which contains the string that is written to the file to the output of the module (https://github.com/ansible-collections/community.postgresql/pull/778)
- postgresql_pg_hba - adds a parameter 'sort_rules' that allows the user to disable sorting in the module, the default is the previous behavior (https://github.com/ansible-collections/community.postgresql/pull/778)
- postgresql_pg_hba - regarding #795 will read all kinds of includes and add them to the end of the file in the same order as they were in the original file, does not allow to add includes (https://github.com/ansible-collections/community.postgresql/pull/778)
- postgresql_user - now there is a ``quote_configuration_values`` parameter that allows to turn off quoting for values which when set to ``false`` allows to set ``search_path`` (https://github.com/ansible-collections/community.postgresql/pull/806)

Breaking Changes / Porting Guide
--------------------------------

- postgresql_info - the ``db`` alias is deprecated and will be removed in the next major release, use the ``login_db`` argument instead.
- postgresql_pg_hba - regarding #776 'keep_comments_at_rules' has been deprecated and won't do anything, the default is to keep the comments at the rules they are specified with. keep_comments_at_rules will be removed in 5.0.0 (https://github.com/ansible-collections/community.postgresql/pull/778)
- postgresql_user - the ``db`` alias is deprecated and will be removed in the next major release, use the ``login_db`` argument instead.

Bugfixes
--------

- postgresql_pg_hba - fixes #776 the module won't be adding/moving comments repeatedly if 'keep_comments_at_rules' is 'false' (https://github.com/ansible-collections/community.postgresql/pull/778)

v3.10.2
=======

Release Summary
---------------

This is a patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- postgresql_info - fix failure when a default database is used (neither ``db`` nor ``login_db`` are specified) (https://github.com/ansible-collections/community.postgresql/issues/794).

v3.10.1
=======

Release Summary
---------------

This is a patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- postgresql_info - fix module failure when the ``db`` parameter is used instead of ``login_db`` (https://github.com/ansible-collections/community.postgresql/issues/794).

v3.10.0
=======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_query - returns the `execution_time_ms` list containing execution time per query in milliseconds (https://github.com/ansible-collections/community.postgresql/issues/787).

Bugfixes
--------

- postgresql_info - fix issue when gathering information fails if user doesn't have access to all databases (https://github.com/ansible-collections/community.postgresql/pull/788).
- postgresql_privs -  fix the error occurring when trying to grant a function execution and set the schema to not-specified (https://github.com/ansible-collections/community.postgresql/pull/783).

v3.9.1
======

Release Summary
---------------

This is a patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Bugfixes
--------

- postgresql_pg_hba - fixes #777 the module will ignore the 'address' and 'netmask' options again when the contype is 'local' (https://github.com/ansible-collections/community.postgresql/pull/779)

v3.9.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_pg_hba - changes ordering of entries that are identical except for the ip-range, but only if the ranges are of the same size, this isn't breaking as ranges of equal size can't overlap (https://github.com/ansible-collections/community.postgresql/pull/772)
- postgresql_pg_hba - orders auth-options alphabetically, this isn't breaking as the order of those options is not relevant to postgresql (https://github.com/ansible-collections/community.postgresql/pull/772)

v3.8.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_pg_hba - show the number of the line with the issue if parsing a file fails (https://github.com/ansible-collections/community.postgresql/pull/766)
- postgresql_publication - add possibility of creating publication with column list (https://github.com/ansible-collections/community.postgresql/pull/763).

Bugfixes
--------

- postgresql_pg_hba - fixes #420 by properly handling hash-symbols in quotes (https://github.com/ansible-collections/community.postgresql/pull/766)
- postgresql_pg_hba - fixes #705 by preventing invalid strings to be written (https://github.com/ansible-collections/community.postgresql/pull/761)
- postgresql_pg_hba - fixes #730 by extending the key we use to identify a rule with the connection type (https://github.com/ansible-collections/community.postgresql/pull/770)
- postgresql_pg_hba - improves parsing of quoted strings and escaped newlines (https://github.com/ansible-collections/community.postgresql/pull/761)
- postgresql_user - doesn't take password_encryption into account when checking if a password should be updated (https://github.com/ansible-collections/community.postgresql/issues/688).

v3.7.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_set - adds the ``queries`` return value to return executed DML statements.

Bugfixes
--------

- postgresql_set - fixes resetting logic to allow resetting shared_preload_libraries with ``reset: true`` (https://github.com/ansible-collections/community.postgresql/issues/744).
- postgresql_set - forbids resetting shared_preload_libraries by passing an empty string (https://github.com/ansible-collections/community.postgresql/issues/744).

v3.6.1
======

Release Summary
---------------

This is a patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been added after the previous release.

Bugfixes
--------

- postgresql_user - remove a comment from unit tests that breaks pre-compile (https://github.com/ansible-collections/community.postgresql/issues/737).

v3.6.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_privs - adds support for granting and revoking privileges on foreign tables (https://github.com/ansible-collections/community.postgresql/issues/724).
- postgresql_subscription - adds support for managing subscriptions in the situation where the ``subconninfo`` column is unavailable (such as in CloudSQL) (https://github.com/ansible-collections/community.postgresql/issues/726).

Bugfixes
--------

- postgresql_db - fix issues due to columns in pg_database changing in Postgres 17. (https://github.com/ansible-collections/community.postgresql/issues/729).
- postgresql_info - Use a server check that works on beta and rc versions as well as on actual releases.

v3.5.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgres - add support for postgres ``infinity`` timestamps by replacing them with ``datetime.min`` / ``datetime.max`` values (https://github.com/ansible-collections/community.postgresql/pull/714).
- postgresql_publication - add the ``tables_in_schema`` argument to implement ``FOR TABLES IN SCHEMA`` feature (https://github.com/ansible-collections/community.postgresql/issues/709).
- postgresql_user - adds the ``configuration`` argument that allows to manage user-specific default configuration (https://github.com/ansible-collections/community.postgresql/issues/598).

Bugfixes
--------

- postgres - psycopg2 automatically sets the datestyle on the connection to iso whenever it encounters a datestyle configuration it doesn't recognize, but psycopg3 does not. Fix now enforces iso datestyle when using psycopg3 (https://github.com/ansible-collections/community.postgresql/issues/711).

v3.4.1
======

Release Summary
---------------

This is a patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been added after the release of ``community.postgresql`` 3.4.0.

Bugfixes
--------

- postgresql_db - ``restore`` custom format as file instead of stdin to allow the use of --job flag in ``target_opts`` (https://github.com/ansible-collections/community.postgresql/issues/594).
- postgresql_ext - Reconnect before upgrade to avoid accidental load of the upgraded extension (https://github.com/ansible-collections/community.postgresql/pull/689).
- postgresql_idx - consider schema name when checking for index (https://github.com/ansible-collections/community.postgresql/issues/692).  Index names are only unique within a schema. This allows using the same index name in multiple schemas.
- postgresql_privs - Enables the ability to revoke functions from user (https://github.com/ansible-collections/community.postgresql/issues/687).

v3.4.0
======

Release Summary
---------------

This is a minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_db - add the ``icu_locale`` argument (https://github.com/ansible-collections/community.postgresql/issues/666).
- postgresql_db - add the ``locale_provider`` argument (https://github.com/ansible-collections/community.postgresql/issues/666).

Bugfixes
--------

- postgresql_privs - fix a failure when altering privileges with ``grant_option: true`` (https://github.com/ansible-collections/community.postgresql/issues/668).

v3.3.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgresql_db - add the ``comment`` argument (https://github.com/ansible-collections/community.postgresql/issues/614).
- postgresql_ext - add the ``comment`` argument (https://github.com/ansible-collections/community.postgresql/issues/354).
- postgresql_publication - add the ``comment`` argument (https://github.com/ansible-collections/community.postgresql/issues/354).
- postgresql_schema - add the ``comment`` argument (https://github.com/ansible-collections/community.postgresql/issues/354).
- postgresql_subscription - add the ``comment`` argument (https://github.com/ansible-collections/community.postgresql/issues/354).
- postgresql_tablespace - add the ``comment`` argument (https://github.com/ansible-collections/community.postgresql/issues/354).

Bugfixes
--------

- postgresql_query - now reports not changed for queries starting with "SHOW" (https://github.com/ansible-collections/community.postgresql/pull/592).
- postgresql_user - module failed when running against an SQL_ASCII encoded database as the user's current password was returned as bytes as opposed to a str. Fix now checks for this case and decodes the bytes as an ascii encoded string. (https://github.com/ansible-collections/community.postgresql/issues/584).

v3.2.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- postgres modules - added support for Psycopg 3 library (https://github.com/ansible-collections/community.postgresql/pull/517).
- postgresql_owner - added support at new object types (https://github.com/ansible-collections/community.postgresql/pull/555).

Bugfixes
--------

- postgresql_info - fix SQL syntax issue (https://github.com/ansible-collections/community.postgresql/issues/570).

v3.1.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Major Changes
-------------

- postgres modules - the minimum version of psycopg2 library the collection supports is 2.5.1 (https://github.com/ansible-collections/community.postgresql/pull/556).

Minor Changes
-------------

- Collection core functions - use ``get_server_version`` in all modules (https://github.com/ansible-collections/community.postgresql/pull/518)."
- Collection core functions - use common cursor arguments in all modules (https://github.com/ansible-collections/community.postgresql/pull/522)."
- postgresql_ext - added idempotence always both in standard and in check mode (https://github.com/ansible-collections/community.postgresql/pull/545).
- postgresql_ext - added idempotence when version=latest (https://github.com/ansible-collections/community.postgresql/pull/504).
- postgresql_ext - added prev_version and version return values (https://github.com/ansible-collections/community.postgresql/pull/545).
- postgresql_ext - added queries in module output also in check mode (https://github.com/ansible-collections/community.postgresql/pull/545).
- postgresql_ext - improved error messages (https://github.com/ansible-collections/community.postgresql/pull/545).
- postgresql_privs - added idempotence when roles=PUBLIC (https://github.com/ansible-collections/community.postgresql/pull/502).
- postgresql_privs - added parameters privileges support for PostgreSQL 15 or higher (https://github.com/ansible-collections/community.postgresql/issues/481).
- postgresql_privs - added support for implicit roles CURRENT_ROLE, CURRENT_USER, and SESSION_USER (https://github.com/ansible-collections/community.postgresql/pull/502).
- postgresql_tablespace - added idempotence when dropping a non-existing tablespace (https://github.com/ansible-collections/community.postgresql/pull/554).

Deprecated Features
-------------------

- postgresql_lang - the module has been deprecated and will be removed in ``community.postgresql 4.0.0``. Please use the ``postgresql_ext`` module instead (https://github.com/ansible-collections/community.postgresql/issues/559).

Bugfixes
--------

- postgresql_ext - fixed queries return value name in documentation (https://github.com/ansible-collections/community.postgresql/pull/545).
- postgresql_privs - fixed error message and documentation (https://github.com/ansible-collections/community.postgresql/pull/510).
- postgresql_set - fixed GUC_LIST_QUOTE parameters (https://github.com/ansible-collections/community.postgresql/pull/521).
- postgresql_set - fixed error message in param_set function (https://github.com/ansible-collections/community.postgresql/pull/505).

v3.0.0
======

Release Summary
---------------

This is a major release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.4.2.

Major Changes
-------------

- postgresql_pg_hba - remove the deprecated ``order`` argument. The sortorder ``sdu`` is hardcoded (https://github.com/ansible-collections/community.postgresql/pull/496).
- postgresql_privs - remove the deprecated ``usage_on_types`` argument. Use the ``type`` option of the ``type`` argument to explicitly manipulate privileges on PG types (https://github.com/ansible-collections/community.postgresql/issues/208).
- postgresql_query - remove the deprecated ``path_to_script`` and ``as_single_query`` arguments. Use the ``postgresql_script`` module to run queries from scripts (https://github.com/ansible-collections/community.postgresql/issues/189).
- postgresql_user - move the deprecated ``privs`` argument removal to community.postgresql 4.0.0 (https://github.com/ansible-collections/community.postgresql/issues/493).
- postgresql_user - remove the deprecated ``groups`` argument. Use the ``postgresql_membership`` module instead (https://github.com/ansible-collections/community.postgresql/issues/300).

v2.4.2
======

Release Summary
---------------

This is a bugfix release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after release 2.4.1.

Bugfixes
--------

- postgresql_db - when the task is completed successfully, close the database connection (https://github.com/ansible-collections/community.postgresql/issues/465).
- postgresql_info - when the task is completed successfully, close the database connection (https://github.com/ansible-collections/community.postgresql/issues/465).
- postgresql_ping - when the task is completed successfully, close the database connection (https://github.com/ansible-collections/community.postgresql/issues/465).
- postgresql_privs - when the task is completed successfully, close the database connection (https://github.com/ansible-collections/community.postgresql/issues/465).

v2.4.1
======

Release Summary
---------------

This is the bugfix release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after release 2.4.0.

Bugfixes
--------

- postgresql_privs - fix a breaking change related to handling the ``password`` argument (https://github.com/ansible-collections/community.postgresql/pull/463).

v2.4.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.3.2.

Major Changes
-------------

- postgresql_privs - the ``password`` argument is deprecated and will be removed in community.postgresql 4.0.0, use the ``login_password`` argument instead (https://github.com/ansible-collections/community.postgresql/issues/406).

Minor Changes
-------------

- Add support for module_defaults with action_group ``all`` (https://github.com/ansible-collections/community.postgresql/pull/430).
- postgresql - added new parameters ``ssl_cert`` and ``ssl_key`` for ssl connection (https://github.com/ansible-collections/community.postgresql/issues/424).
- postgresql - when receiving the connection parameters, the ``PGPORT`` and ``PGUSER`` environment variables are checked. The order of assigning values ``environment variables`` -> ``default values`` -> ``set values`` (https://github.com/ansible-collections/community.postgresql/issues/311).
- postgresql_query - a list of queries can be passed as the ``query`` argument's value, the results will be stored in the ``query_all_results`` return value (is not deprecated anymore, as well as ``query_list``) (https://github.com/ansible-collections/community.postgresql/issues/312).

Bugfixes
--------

- postgresql_info - add support for non numeric extension version (https://github.com/ansible-collections/community.postgresql/issues/428).
- postgresql_info - when getting information about subscriptions, check the list of available columns in the pg_subscription table (https://github.com/ansible-collections/community.postgresql/issues/429).
- postgresql_privs - fix connect_params being ignored (https://github.com/ansible-collections/community.postgresql/issues/450).
- postgresql_query - could crash under certain conditions because of a missing import to `psycopg2.extras` (https://github.com/ansible-collections/community.postgresql/issues/283).
- postgresql_set - avoid throwing ValueError for IP addresses and other values that may look like a number, but which are not (https://github.com/ansible-collections/community.postgresql/pull/422).
- postgresql_set - avoid wrong values for single-value parameters containing commas (https://github.com/ansible-collections/community.postgresql/pull/400).
- postgresql_user - properly close DB connections to prevent possible connection limit exhaustion (https://github.com/ansible-collections/community.postgresql/issues/431).

v2.3.2
======

Release Summary
---------------

This is the bugfix release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after release 2.3.1.

Bugfixes
--------

- postgresql_pg_hba - fix ``changed`` return value for when ``overwrite`` is enabled (https://github.com/ansible-collections/community.postgresql/pull/378).
- postgresql_privs - fix quoting of the ``schema`` parameter in SQL statements (https://github.com/ansible-collections/community.postgresql/pull/382).
- postgresql_privs - raise an error when the ``objs: ALL_IN_SCHEMA`` is used with a value of ``type`` that is not ``table``, ``sequence``, ``function`` or ``procedure`` (https://github.com/ansible-collections/community.postgresql/issues/379).

v2.3.1
======

Release Summary
---------------

This is the bugfix release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after release 2.3.0.

Bugfixes
--------

- postgresql_privs - fails with ``type=default_privs``, ``privs=ALL``, ``objs=ALL_DEFAULT`` (https://github.com/ansible-collections/community.postgresql/issues/373).

v2.3.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.2.0.

Minor Changes
-------------

- postgresql_* - add the ``connect_params`` parameter dict to allow any additional ``libpg`` connection parameters (https://github.com/ansible-collections/community.postgresql/pull/329).

Bugfixes
--------

- postgresql_info - make arguments passed to SHOW command properly quoted to prevent the interpreter evaluating them (https://github.com/ansible-collections/community.postgresql/issues/314).
- postgresql_pg_hba - support the connection types ``hostgssenc`` and ``hostnogssenc`` (https://github.com/ansible-collections/community.postgresql/pull/351).
- postgresql_privs - add support for alter default privileges grant usage on schemas (https://github.com/ansible-collections/community.postgresql/issues/332).
- postgresql_privs - cannot grant select on objects in all schemas; add the ``not-specified`` value to the ``schema`` parameter to make this possible (https://github.com/ansible-collections/community.postgresql/issues/332).
- postgresql_set - avoid postgres puts extra quotes when passing values containing commas (https://github.com/ansible-collections/community.postgresql/issues/78).
- postgresql_user - make the module idempotent when password is scram hashed (https://github.com/ansible-collections/community.postgresql/issues/301).

v2.2.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.1.5.

Major Changes
-------------

- postgresql_user - the ``groups`` argument has been deprecated and will be removed in ``community.postgresql 3.0.0``. Please use the ``postgresql_membership`` module to specify group/role memberships instead (https://github.com/ansible-collections/community.postgresql/issues/277).

Minor Changes
-------------

- postgresql_membership - add the ``exact`` state value to be able to specify a list of only groups a user must be a member of (https://github.com/ansible-collections/community.postgresql/issues/277).
- postgresql_pg_hba - add argument ``overwrite`` (bool, default: false) to remove unmanaged rules (https://github.com/ansible-collections/community.postgresql/issues/297).
- postgresql_pg_hba - add argument ``rules_behavior`` (choices: conflict (default), combine) to fail when ``rules`` and normal rule-specific arguments are given or, when ``combine``, use them as defaults for the ``rules`` items (https://github.com/ansible-collections/community.postgresql/issues/297).
- postgresql_pg_hba - add argument ``rules`` to specify a list of rules using the normal rule-specific argument in each item (https://github.com/ansible-collections/community.postgresql/issues/297).

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for various module utils.
- postgresql_info - fix pg version parsing (https://github.com/ansible-collections/community.postgresql/issues/315).
- postgresql_ping - fix pg version parsing (https://github.com/ansible-collections/community.postgresql/issues/315).
- postgresql_privs.py - add functionality when the PostgreSQL version is 9.0.0 or greater to incorporate ``ALL x IN SCHEMA`` syntax (https://github.com/ansible-collections/community.postgresql/pull/282). Please see the official documentation for details regarding grants (https://www.postgresql.org/docs/9.0/sql-grant.html).
- postgresql_subscription - fix idempotence by casting the ``connparams`` dict variable (https://github.com/ansible-collections/community.postgresql/issues/280).
- postgresql_user - add ``alter user``-statements in the return value ``queries`` (https://github.com/ansible-collections/community.postgresql/issues/307).

v2.1.5
======

Release Summary
---------------

This is the bugfix release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.1.4

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.
- collection core functions - fix attribute error `nonetype` by always calling `ensure_required_libs` (https://github.com/ansible-collections/community.postgresql/issues/252).

v2.1.4
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.1.3.

Major Changes
-------------

- The community.postgresql collection no longer supports ``Ansible 2.9`` and ``ansible-base 2.10``. While we take no active measures to prevent usage and there are no plans to introduce incompatible code to the modules, we will stop testing against ``Ansible 2.9`` and ``ansible-base 2.10``. Both will very soon be End of Life and if you are still using them, you should consider upgrading to the ``latest Ansible / ansible-core 2.11 or later`` as soon as possible (https://github.com/ansible-collections/community.postgresql/pull/245).

v2.1.3
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.1.2.

Major Changes
-------------

- postgresql_user - the ``priv`` argument has been deprecated and will be removed in ``community.postgresql 3.0.0``. Please use the ``postgresql_privs`` module to grant/revoke privileges instead (https://github.com/ansible-collections/community.postgresql/issues/212).

Bugfixes
--------

- postgresql_db - get rid of the deprecated psycopg2 connection alias ``database`` in favor of ``dbname`` when psycopg2 is 2.7+ is used (https://github.com/ansible-collections/community.postgresql/issues/194, https://github.com/ansible-collections/community.postgresql/pull/196).

v2.1.2
======

Release Summary
---------------

This is the patch release of the `community.postgresql` collection. This changelog contains all changes to the modules in this collection that have been added after the release of `community.postgresql` 2.1.1.

Major Changes
-------------

- postgresql_privs - the ``usage_on_types`` feature have been deprecated and will be removed in ``community.postgresql 3.0.0``. Please use the ``type`` option with the ``type`` value to explicitly grant/revoke privileges on types (https://github.com/ansible-collections/community.postgresql/issues/207).

v2.1.1
======

Release Summary
---------------

This is the bugfix release of the community.postgresql collection.
This changelog contains all changes to the modules in this collection that have been added after the release of community.postgresql 2.1.0.

Bugfixes
--------

- module core functions - get rid of the deprecated psycopg2 connection alias ``database`` in favor of ``dbname`` when psycopg2 is 2.7+ (https://github.com/ansible-collections/community.postgresql/pull/196).
- postgresql_query - cannot handle .sql file with \\n at end of file (https://github.com/ansible-collections/community.postgresql/issues/180).

v2.1.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 2.0.0.

Major Changes
-------------

- postgresql_query - the ``path_to_script`` and ``as_single_query`` options as well as the ``query_list`` and ``query_all_results`` return values have been deprecated and will be removed in ``community.postgresql 3.0.0``. Please use the ``community.postgresql.postgresql_script`` module to execute statements from scripts (https://github.com/ansible-collections/community.postgresql/issues/189).

New Modules
-----------

- postgresql_script - Run PostgreSQL statements from a file

v2.0.0
======

Release Summary
---------------

This is the major release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.7.0.

Major Changes
-------------

- postgresql_query - the default value of the ``as_single_query`` option changes to ``yes``. If the related behavior of your tasks where the module is involved changes, please adjust the parameter's value correspondingly (https://github.com/ansible-collections/community.postgresql/issues/85).

v1.6.1
======

Release Summary
---------------

This is the bugfix release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.6.1.

Bugfixes
--------

- Collection core functions - use vendored version of ``distutils.version`` instead of the deprecated Python standard library ``distutils`` (https://github.com/ansible-collections/community.postgresql/pull/179).
- postgres_info - It now works on AWS RDS Postgres.
- postgres_info - Specific info (namespaces, extensions, languages) of each database was not being shown properly. Instead, the info from the DB that was connected was always being shown (https://github.com/ansible-collections/community.postgresql/issues/172).

v1.6.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.5.0.

Bugfixes
--------

- postgresql_ext - Handle postgresql extension updates through path validation instead of version comparison (https://github.com/ansible-collections/community.postgresql/issues/129).

v1.5.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.4.0.

Minor Changes
-------------

- postgresql_db - Add the ``force`` boolean option to drop active connections first and then remove the database (https://github.com/ansible-collections/community.postgresql/issues/109).
- postgresql_info - Add the ``raw`` return value for extension version (https://github.com/ansible-collections/community.postgresql/pull/138).
- postgresql_pg_hba - Add the parameters ``keep_comments_at_rules`` and ``comment`` (https://github.com/ansible-collections/community.postgresql/issues/134).

Bugfixes
--------

- postgresql_ext - Fix extension version handling when it has 0 value (https://github.com/ansible-collections/community.postgresql/issues/136).
- postgresql_info - Fix extension version handling when it has 0 value (https://github.com/ansible-collections/community.postgresql/issues/137).
- postgresql_set - Fix wrong numerical value conversion (https://github.com/ansible-collections/community.postgresql/issues/110).
- postgresql_slot - Correct the server_version check for PG 9.6 (https://github.com/ansible-collections/community.postgresql/issue/120)

v1.4.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.3.0.

Minor Changes
-------------

- postgresql_db - add support for the ``directory`` format when the ``state`` option is ``dump`` or ``restore`` (https://github.com/ansible-collections/community.postgresql/pull/108).
- postgresql_db - add the ``rename`` value to the ``state`` option (https://github.com/ansible-collections/community.postgresql/pull/107).

v1.3.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.2.0.

Major Changes
-------------

- postgresql_query - the default value of the ``as_single_query`` option will be changed to ``yes`` in community.postgresql 2.0.0 (https://github.com/ansible-collections/community.postgresql/issues/85).

Bugfixes
--------

- postgresql_privs - fix ``fail_on_role`` check (https://github.com/ansible-collections/community.postgresql/pull/82).

v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.1.1.

Minor Changes
-------------

- postgresql_info - add the ``patch``, ``full``, and ``raw`` values of the ``version`` return value (https://github.com/ansible-collections/community.postgresql/pull/68).
- postgresql_ping - add the ``patch``, ``full``, and ``raw`` values of the ``server_version`` return value (https://github.com/ansible-collections/community.postgresql/pull/70).

v1.1.1
======

Release Summary
---------------

This is the patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.1.0.

Bugfixes
--------

- postgresql_query - add a warning to set ``as_single_query`` option explicitly (https://github.com/ansible-collections/community.postgresql/pull/54).
- postgresql_query - fix datetime.timedelta type handling (https://github.com/ansible-collections/community.postgresql/issues/47).
- postgresql_query - fix decimal handling (https://github.com/ansible-collections/community.postgresql/issues/45).
- postgresql_set - fails in check_mode on non-numeric values containing `B` (https://github.com/ansible-collections/community.postgresql/issues/48).

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.0.0.

Minor Changes
-------------

- postgresql_query - add ``as_single_query`` option to execute a script content as a single query to avoid semicolon related errors (https://github.com/ansible-collections/community.postgresql/pull/37).

Bugfixes
--------

- postgresql_info - fix crash caused by wrong PgSQL version parsing (https://github.com/ansible-collections/community.postgresql/issues/40).
- postgresql_ping - fix crash caused by wrong PgSQL version parsing (https://github.com/ansible-collections/community.postgresql/issues/40).
- postgresql_set - return a message instead of traceback when a passed parameter has not been found (https://github.com/ansible-collections/community.postgresql/issues/41).

v1.0.0
======

Release Summary
---------------

This is the first proper release of the ``community.postgresql`` collection which is needed to include the collection in Ansible.
This changelog does not contain any changes because there are no changes made since release 0.1.0.

v0.1.0
======

Release Summary
---------------

The ``community.postgresql`` continues the work on the Ansible PostgreSQL
modules from their state in ``community.general`` 1.2.0.
The changes listed here are thus relative to the modules ``community.general.postgresql_*``.

Minor Changes
-------------

- postgresql_info - add ``in_recovery`` return value to show if a service in recovery mode or not (https://github.com/ansible-collections/community.general/issues/1068).
- postgresql_privs - add ``procedure`` type support (https://github.com/ansible-collections/community.general/issues/1002).
- postgresql_query - add ``query_list`` and ``query_all_results`` return values (https://github.com/ansible-collections/community.general/issues/838).

Bugfixes
--------

- postgresql_ext - fix the module crashes when available ext versions cannot be compared with current version (https://github.com/ansible-collections/community.general/issues/1095).
- postgresql_ext - fix version selection when ``version=latest`` (https://github.com/ansible-collections/community.general/pull/1078).
- postgresql_privs - fix module fails when ``type`` group and passing ``objs`` value containing hyphens (https://github.com/ansible-collections/community.general/issues/1058).
