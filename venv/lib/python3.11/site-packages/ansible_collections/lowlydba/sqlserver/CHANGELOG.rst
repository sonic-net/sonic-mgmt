================================
lowlydba.sqlserver Release Notes
================================

.. contents:: Topics

v2.7.0
======

Release Summary
---------------

Added output file support for SQL Agent job steps.

Minor Changes
-------------

- agent_job_step - Added ``output_file`` parameter to specify the output file path for SQL Agent job steps (https://github.com/lowlydba/lowlydba.sqlserver/pull/329).

v2.6.1
======

Release Summary
---------------

Testing updates for Ansible 2.19 compatibility.

Minor Changes
-------------

- Added support for Ansible 2.19
- Updated the test matrix to include Ansible 2.19 and remove Ansible 2.16

v2.6.0
======

Release Summary
---------------

Added support for contained Availability Groups using dbatools 2.1.15 - thanks @DorBreger!

Minor Changes
-------------

- Added support for contained Availability Groups using dbatools 2.1.15 (https://github.com/lowlydba/lowlydba.sqlserver/pull/249).

v2.5.0
======

Release Summary
---------------

New login_role module for managing server role members!

Minor Changes
-------------

- Add new `login_role` module to add/remove server roles for logins (https://github.com/lowlydba/lowlydba.sqlserver/pull/293).

New Modules
-----------

- login_role - Configures a login's  server roles.

v2.4.0
======

Release Summary
---------------

New role user_role added to allow adding/removing database roles for users!

Minor Changes
-------------

- Add new user_role module to manage users' membership to database roles (https://github.com/lowlydba/lowlydba.sqlserver/pull/292).

New Modules
-----------

- user_role - Configures a user's role in a database.

v2.3.6
======

Release Summary
---------------

Bugfix for creating agent job schedules as explicitly enabled.

Bugfixes
--------

- Fix error when creating an agent job schedule with `enabled` as true. (https://github.com/lowlydba/lowlydba.sqlserver/pull/288)

v2.3.5
======

Release Summary
---------------

Bugfix for login module when creating new logins.

Bugfixes
--------

- Fix error that occurred when creating a login with `skip_password_reset` as true. (https://github.com/lowlydba/lowlydba.sqlserver/pull/287)

v2.3.4
======

Release Summary
---------------

Minor bugfix for failed database restores.

Bugfixes
--------

- Include warning logs in failure output for the restore module to indicate root causes (https://github.com/lowlydba/lowlydba.sqlserver/pull/266).

v2.3.3
======

Release Summary
---------------

Minor bugfix for ag listener input types, thanks @daarrn for the contribution!

Bugfixes
--------

- fixed the expected type of the ip_address, subnet_ip, and subnet_mask parameters to be lists instead of strings (lowlydba.sqlserver.ag_listener)

v2.3.2
======

Release Summary
---------------

Small fix for documentation and upstream fix available in dbatools v2.1.9.

Bugfixes
--------

- Update documentation for agent_job_schedule to reflect proper input formatting. (https://github.com/lowlydba/lowlydba.sqlserver/pull/229)

v2.3.1
======

Release Summary
---------------

Update the install script feature to accommodate the latest minor DbOps release (v0.9.x)

Minor Changes
-------------

- Add new input strings to be compatible with dbops v0.9.x (https://github.com/lowlydba/lowlydba.sqlserver/pull/231)

v2.3.0
======

Release Summary
---------------

New feature from @OsirisDBA for skipping login password resets!

Minor Changes
-------------

- Add ability to prevent changing login's password, even if password supplied.

v2.2.3
======

Release Summary
---------------

Minor bugfixes.

Bugfixes
--------

- Add ActiveStartDate to the compare properties so this item is marked accurately as changed.
- Fixed the formatting of the SPN by updating the backslash to a forward-slash for the $spn var (lowlydba.sqlserver.spn)

v2.2.1
======

Release Summary
---------------

Bugfix for database module in the context of availability groups.

Minor Changes
-------------

- Fixes error handling for Remove-DbaDatabase when joined to AvailabilityGroup, exception was not being thrown so we have to parse Status

v2.2.0
======

Release Summary
---------------

Bug fix in the database module.

Minor Changes
-------------

- Added only_accessible as an optional parameter to the database module (https://github.com/lowlydba/lowlydba.sqlserver/pull/198)

v2.1.0
======

Release Summary
---------------

Add sid to login, thanks @OsirisDBA!

Minor Changes
-------------

- Add refresh workaround for agent schedule bug where properties returned are stale. (https://github.com/lowlydba/lowlydba.sqlserver/pull/185)
- Added SID as an optional parameter to the login module (https://github.com/lowlydba/lowlydba.sqlserver/pull/189)

v2.0.0
======

Release Summary
---------------

A major version bump of DBATools to version 2+. This will guarantee compatibility with PowerShell Core versions 7.3+ and future SQL Server versions. For more information on that release, see https://blog.netnerds.net/2023/03/whats-new-dbatools-2.0/. Outside of major problems, new changes to this collection will not be backported to v1.

Breaking Changes / Porting Guide
--------------------------------

- Updating minimum DBATools version to v2.0.0 to allow for pwsh 7.3+ compatibility. There may also be breaking change behavior in DBATools, see https://blog.netnerds.net/2023/03/whats-new-dbatools-2.0/. (https://github.com/lowlydba/lowlydba.sqlserver/pull/181)

v1.3.1
======

Release Summary
---------------

Small bugfixes and documentation enhancements.

Minor Changes
-------------

- Update login module documentation to indicate result will always be changed when a password is supplied. (https://github.com/lowlydba/lowlydba.sqlserver/pull/167)

Bugfixes
--------

- Fixes to incorrect variable reference in Login module (https://github.com/lowlydba/lowlydba.sqlserver/pull/161)

v1.3.0
======

Release Summary
---------------

New module to manage credentials added!

Minor Changes
-------------

- Adding a new credential module

New Modules
-----------

- credential - Configures a credential on a SQL server

v1.2.1
======

Release Summary
---------------

More Azure SQL Managed Instance compatibility fixes.

Bugfixes
--------

- Added missing mapping for UseDestinationDefaultDirectories (https://github.com/lowlydba/lowlydba.sqlserver/pull/153)
- Removed default value for KeepCDC to fix compatability with SQL MI (https://github.com/lowlydba/lowlydba.sqlserver/pull/153)
- Removed default value for UseDestinationDefaultDirectories to fix compatability with SQL MI (https://github.com/lowlydba/lowlydba.sqlserver/pull/153)

v1.2.0
======

Release Summary
---------------

Azure SQL MI compatibility fixes & indicating required restarts for settings changes.

Minor Changes
-------------

- Fixed typo in the traceflag module's documentation. (https://github.com/lowlydba/lowlydba.sqlserver/pull/150)
- Return "RestartRequired" when a module performs changes that require an addition service restart to take effect. (https://github.com/lowlydba/lowlydba.sqlserver/pull/150/)

Bugfixes
--------

- Removed default value for ReplaceDbNameInFile to fix compatability with SQL MI (https://github.com/lowlydba/lowlydba.sqlserver/pull/148)

v1.1.3
======

Release Summary
---------------

Another minor fix to increase SQL Managed Instance support.

Bugfixes
--------

- Removed default value for reuse_source_folder_structure to fix compatability with SQL MI (https://github.com/lowlydba/lowlydba.sqlserver/pull/145)

v1.1.2
======

Release Summary
---------------

Bug fix for Azure Database Managed Instance compatibility.

Bugfixes
--------

- Removed the default value for xp_dirtree to allow compatibility with Azure SQL Mangaed instances (https://github.com/lowlydba/lowlydba.sqlserver/pull/141)

v1.1.1
======

Minor Changes
-------------

- modules - all modules now document their platform and support for check mode in their attributes documentation (https://github.com/lowlydba/lowlydba.sqlserver/pull/134).

v1.1.0
======

Release Summary
---------------

Adding a new user module.

New Modules
-----------

- user - Configures a user within a database

v1.0.4
======

Release Summary
---------------

Minor fixes to resolve new dlevel sanity checks.

Bugfixes
--------

- Fix cleanup_time default to match documentation default & lint fixes (https://github.com/lowlydba/lowlydba.sqlserver/pull/127).

v1.0.3
======

Release Summary
---------------

Minor documentation fixes from the second Ansible inclusion review.

Bugfixes
--------

- Minor documentation fixes (https://github.com/lowlydba/lowlydba.sqlserver/pull/122).

v1.0.2
======

Release Summary
---------------

Minor documentation bugfixes and enhancements as requested in the Ansible inclusion process.

Bugfixes
--------

- _SqlServerUtils module_util - added explicit license to private module util (https://github.com/lowlydba/lowlydba.sqlserver/pull/119).
- meta/runtime.yml - updated out of date runtime version info (https://github.com/lowlydba/lowlydba.sqlserver/pull/119).
- most modules - fixed alignment, formatting, and typos in module documentation (https://github.com/lowlydba/lowlydba.sqlserver/pull/119).

v1.0.1
======

Release Summary
---------------

Minor bug fix.

Bugfixes
--------

- Fixed bug in how the classifier function name is being assigned to the variable in the resource_governor module.

v1.0.0
======

Release Summary
---------------

Bumping to version 1.0.0 now that this collection is being used in production in at least one place 🎉

v0.11.2
=======

Release Summary
---------------

Bumping required dbatools version to ensure the `restore` module works on MacOS PowerShell Core (https://github.com/dataplat/dbatools/pull/8435).

v0.11.1
=======

Release Summary
---------------

Bug fixes for AlwaysOn related modules and fixing errors in some documentation examples.

Bugfixes
--------

- Fix `availability_group` module so that NUL backups can be properly taken if needed.
- Fix incorrect examples in `availability_group` module documentation.
- Fix incorrect examples in `install_script` module documentation.
- Fix incorrect examples in `spn` module documentationb.
- Fixed bugs where adding replica did not work properly for several reasons.

v0.11.0
=======

Release Summary
---------------

Adding new dbops module.

New Modules
-----------

- install_script - Runs migration scripts against a database.

v0.10.1
=======

Release Summary
---------------

Bug fix for resource_governor.

Bugfixes
--------

- Fix change detection in resource_governor module.

v0.10.0
=======

Release Summary
---------------

The first_responder_kit and tcp_port modules, along with a bump in the required dbatools version.

Minor Changes
-------------

- Update minimum required DBATools version universally to 1.1.108 to accommodate new tcp module.

New Modules
-----------

- first_responder_kit - Install/update the First Responder Kit scripts.
- tcp_port - Sets the TCP port for the instance.

v0.9.3
======

Release Summary
---------------

More change detection fixing.

Bugfixes
--------

- memory - Fix improper changed detection.

v0.9.2
======

Release Summary
---------------

Bugfixes for agent related modules that incorrectly reported change statuses.

Bugfixes
--------

- agent_job - Fix incorrectly reported change status when no change occurred.
- agent_job_schedule - Fix incorrectly reported change status when no change occurred.
- agent_job_step - Fix incorrectly reported change status when no change occurred.

v0.9.1
======

Release Summary
---------------

Bugfix!

Bugfixes
--------

- Allow agent job steps to be removed by specifying the step ID only. This is likely needed in cleanup of steps from previous job configurations.

v0.9.0
======

Bugfixes
--------

- backup - Only use blocksize when specified.

New Modules
-----------

- restore - Performs a restore operation.

v0.8.0
======

Release Summary
---------------

A few small fixes and the new 'backup' module.

Minor Changes
-------------

- Standardize use of 'database' vs 'database_name' in all documentation and options specs. Not a breaking change.

Bugfixes
--------

- Fix inability to enable an agent job schedule after it has been disabled.

New Modules
-----------

- backup - Performs a backup operation.

v0.7.0
======

Release Summary
---------------

Add module for DBA Multitool.

New Modules
-----------

- dba_multitool - Install/update the DBA Multitool suite by John McCAll

v0.6.0
======

Release Summary
---------------

Adding new SPN module

New Modules
-----------

- spn - Configures SPNs for SQL Server.

v0.5.0
======

Release Summary
---------------

CI and testing improvements, along with the final availability group module ag_replica.

Minor Changes
-------------

- Remove CI support for Ansible 2.10

New Modules
-----------

- ag_listener - Configures an availability group listener.
- ag_replica - Configures an availability group replica.

v0.4.0
======

Release Summary
---------------

Two new AlwaysOn modules and a few consistency fixes!

Minor Changes
-------------

- Test for 'Name' property for sa module after dbatools release 1.1.95 standardizes command outputs. (https://github.com/dataplat/dbatools/releases/tag/v1.1.95)

Breaking Changes / Porting Guide
--------------------------------

- All modules should use a bool 'enabled' instead of a string 'status' to control object state.

New Modules
-----------

- availability_group - Configures availability group(s).
- hadr - Enable or disable HADR.

v0.3.0
======

Release Summary
---------------

New sa module and fixes for login related modules.

Minor Changes
-------------

- Fix logic to properly pass password policy options to function in the login module.

New Modules
-----------

- sa - Configure the 'sa' login for security best practices.

v0.2.0
======

Release Summary
---------------

Code cleanup, testing improvements, new _info module!

Minor Changes
-------------

- Add DbaTools module requirement to documentation and fix missing examples. (https://github.com/lowlydba/lowlydba.sqlserver/pull/47)
- Utilize PowerShell Requires for dbatools min version needs instead of custom function. Consolidate/standardize credential setup and serialization. (https://github.com/lowlydba/lowlydba.sqlserver/pull/48)

New Modules
-----------

- instance_info - Returns basic information for a SQL Server instance.

v0.1.1
======

Release Summary
---------------

Add database tag for Galaxy

v0.1.0
======

Release Summary
---------------

It's a release! First version to publish to Ansible Galaxy.

New Modules
-----------

- agent_job - Configures a SQL Agent job.
- agent_job_category - Configures a SQL Agent job category.
- agent_job_schedule - Configures a SQL Agent job schedule.
- agent_job_step - Configures a SQL Agent job step.
- database - Creates and configures a database.
- login - Configures a login for the target SQL Server instance.
- maintenance_solution - Install/update Maintenance Solution
- memory - Sets the maximum memory for a SQL Server instance.
- nonquery - Executes a generic nonquery.
- resource_governor - Configures the resource governor on a SQL Server instance.
- rg_resource_pool - Configures a resource pool for use by the Resource Governor.
- rg_workload_group - Configures a workload group for use by the Resource Governor.
- sp_configure - Make instance level system configuration changes via sp_configure.
- sp_whoisactive - Install/update sp_whoisactive by Adam Mechanic.
- traceflag - Enable or disable global trace flags on a SQL  Server instance.
