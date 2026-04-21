#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: restore
short_description: Performs a restore operation
description:
  - Performs a database restore operation.
version_added: 0.9.0
options:
  database:
    description:
      - The database to process.
    type: str
    required: false
  path:
    description:
      - Path to SQL Server backup files.
      - Paths passed in as strings will be scanned using the desired method, default is a recursive folder scan.
      - Accepts multiple paths separated by C(,).
    type: str
    required: true
  destination_data_directory:
    description:
      - Path to restore the SQL Server backups to on the target instance.
      - If only this option is specified, then all database files (data and log) will be restored to this location
    type: str
    required: false
  destination_log_directory:
    description:
      - Path to restore the database log files to.
      - This option can only be specified alongside I(destination_data_directory).
    type: str
    required: false
  destination_filestream_directory:
    description:
      - Path to restore FileStream data to.
      - This option can only be specified alongside I(destination_data_directory).
    type: str
    required: false
  restore_time:
    description:
      - Specify a datetime string C(HH:MM:SS MM/DD/YYYY) to which you want the database restored to.
      - Default is to the latest point available in the specified backups.
    type: str
    required: false
  with_replace:
    description:
      - Indicates if the restore is allowed to replace an existing database.
    type: bool
    required: false
    default: false
  keep_replication:
    description:
      - Indicates whether replication configuration should be restored as part of the database restore operation.
    type: bool
    required: false
    default: false
  xp_dirtree:
    description:
      - Switch that indicated file scanning should be performed by the SQL Server instance using C(xp_dirtree).
      - This will scan recursively from the passed in path.
      - You must have sysadmin role membership on the instance for this to work.
    type: bool
    required: false
  no_xp_dir_recurse:
    description:
      - If specified, prevents the C(XpDirTree) process from recursing (its default behaviour).
    type: bool
    required: false
    default: false
  verify_only:
    description:
      - Indicates the restore should be verified only.
    type: bool
    required: false
    default: false
  maintenance_solution_backup:
    description:
      - Switch to indicate the backup files are in a folder structure as created by Ola Hallengreen's maintenance scripts.
      - This allows for faster file parsing.
    type: bool
    required: false
    default: false
  ignore_log_backup:
    description:
      - Indicates to skip restoring any log backups.
    type: bool
    required: false
    default: false
  ignore_diff_backup:
    description:
      - Indicates to skip restoring any differential backups.
    type: bool
    required: false
    default: false
  use_destination_default_directories:
    description:
      - Switch that tells the restore to use the default Data and Log locations on the target server.
      - If they don't exist, the function will try to create them.
    type: bool
    required: false
  reuse_source_folder_structure:
    description:
      - By default, databases will be migrated to the destination Sql Server's default data and log directories.
      - You can override this by using C(reuse_source_folder_structure).
    type: bool
    required: false
  destination_file_prefix:
    description:
      - This value will be prefixed to B(all) restored files (log and data).
    type: str
    required: false
  restored_database_name_prefix:
    description:
      - A string which will be prefixed to the start of the restore Database's name.
    type: str
    required: false
  directory_recurse:
    description:
      - If specified the specified directory will be recursed into (overriding the default behaviour).
    type: bool
    required: false
    default: false
  standby_directory:
    description:
      - If a directory is specified the database(s) will be restored into a standby state,
        with the standby file placed into this directory (which must exist, and be writable by the target Sql Server instance).
    type: str
    required: false
  replace_db_name_in_file:
    description:
      - If switch set any occurrence of the original database's name in a data or log file
        will be replace with the name specified in the I(database_name) option.
    type: bool
    required: false
  destination_file_suffix:
    description:
      - This value will be suffixed to B(all) restored files (log and data).
    type: str
    required: false
  keep_cdc:
    description:
      - Indicates whether CDC information should be restored as part of the database.
    type: bool
    required: false
  stop_before:
    description:
      - Switch to indicate the restore should stop before I(stop_mark) occurs, default is to stop when mark is created.
    type: bool
    required: false
    default: false
  stop_mark:
    description:
      - Marked point in the transaction log to stop the restore at.
    type: str
    required: false
  stop_after_date:
    description:
      - By default the restore will stop at the first occurence of I(stop_mark) found in the chain,
        passing a datetime string C(HH:MM:SS MM/DD/YYYY) will cause it to stop the first I(stop_mark) after that datetime.
    type: str
    required: false
  no_recovery:
    description:
      - Indicates if the databases should be recovered after last restore.
    type: bool
    required: false
    default: false
  max_transfer_size:
    description:
      - Sets the size of the unit of transfer. Values must be a multiple of 64kb.
    type: int
    required: false
    default: 0
  block_size:
    description:
      - Specifies block size to use.
    type: str
    required: false
    choices: ['0.5kb','1kb','2kb','4kb','8kb','16kb','32kb','64kb']
  buffer_count:
    description:
      - Number of I/O buffers to use.
    type: int
    required: false
    default: 0
  azure_credential:
    description:
      - The name of the SQL Server credential to be used if restoring from an Azure hosted backup using Storage Access Keys.
    type: str
    required: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Restore a Database
  lowlydba.sqlserver.restore:
    sql_instance: sql-01.myco.io
    database: LowlyDB

- name: Restore a Database and allow future T-Log restores
  lowlydba.sqlserver.restore:
    sql_instance: sql-01.myco.io
    database: LowlyDB1
    no_recovery: true

- name: Verify backup files, no restore
  lowlydba.sqlserver.restore:
    sql_instance: sql-01.myco.io
    database: LowlyDB2
    verify_only: true
'''

RETURN = r'''
data:
  description: Modified output from the C(Restore-DbaDatabase) function.
  returned: success, but not in check_mode.
  type: dict
'''
