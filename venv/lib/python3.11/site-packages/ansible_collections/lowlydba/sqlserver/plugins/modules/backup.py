#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: backup
short_description: Performs a backup operation
description:
  - Performs any type of database backup operation.
version_added: 0.8.0
options:
  database:
    description:
      - The database to process.
    type: str
    required: true
  path:
    description:
      - Path in which to place the backup files.
      - If not specified, the backups will be placed in the default backup location for SqlInstance.
    type: str
    required: false
  file_path:
    description:
      - The name of the file to backup to.
      - If no name is specified then the backup files will be named C(DatabaseName_yyyyMMddHHmm) (i.e. C(Database1_201714022131))
    type: str
    required: false
  increment_prefix:
    description:
      - If set, this will prefix backup files with an incrementing integer (ie; C(1-), C(2-)).
      - Using this has been alleged to improved restore times on some Azure based SQL Database platforms.
    type: bool
    required: false
    default: false
  replace_in_name:
    description:
      - If set, the following list of strings will be replaced in the FilePath and Path strings.
        C(instancename) - will be replaced with the instance Name
        C(servername) - will be replaced with the server name
        C(dbname) - will be replaced with the database name
        C(timestamp) - will be replaced with the timestamp (either the default, or the format provided)
        C(backuptype) - will be replaced with C(Full), C(Log), or C(Differential) as appropriate
    type: bool
    required: false
    default: false
  copy_only:
    description:
      - The backup will be CopyOnly.
    type: bool
    required: false
    default: false
  type:
    description:
      - The type of backup to perform.
    type: str
    required: false
    default: 'database'
    choices: ['full', 'log', 'differential', 'diff', 'database']
  create_folder:
    description:
      - If set, database is backed up to its own subfolder within the path.
    type: bool
    required: false
    default: false
  file_count:
    description:
      - The number of striped files to create the backup with.
    type: int
    required: false
    default: 0
  compress:
    description:
      - If set, use compression when creating the backup if it is supported by the version and edition.
    type: bool
    required: false
    default: false
  checksum:
    description:
      - If set, the backup checksum will be calculated.
    type: bool
    required: false
    default: false
  verify:
    description:
      - If set, the backup will be verified via C(RESTORE VERIFYONLY)
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
  azure_base_url:
    description:
      - The URL to the base container of an Azure Storage account to write backups to.
    type: str
    required: false
  azure_credential:
    description:
      - The name of the credential on the SQL instance that can write to the I(azure_base_url),
        only needed if using Storage access keys If using SAS credentials, the command will look for a credential with a name matching the I(azure_base_url).
    type: str
    required: false
  no_recovery:
    description:
      - If set, performs a tail log backup.
    type: bool
    required: false
    default: false
  build_path:
    description:
      - By default this command will not attempt to create missing paths, this switch will change the behaviour so that it will.
    type: bool
    required: false
    default: false
  with_format:
    description:
      - Formats the media as the first step of the backup operation.
    type: bool
    required: false
    default: false
  initialize:
    description:
      - Initializes the media as part of the backup operation.
    type: bool
    required: false
    default: false
  timestamp_format:
    description:
      - By default the command timestamps backups using the format C(yyyyMMddHHmm). Using this option this can be overridden.
    type: str
    required: false
  ignore_file_checks:
    description:
      - If set, stops the function from checking path validity.
    type: bool
    required: false
    default: false
  encryption_algorithm:
    description:
      - Specifies the Encryption Algorithm to used.
    type: str
    required: false
    choices: ['AES128','AES192','AES256','TRIPLEDES']
  encryption_certificate:
    description:
      - The name of the certificate to be used to encrypt the backups.
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
- name: Create striped full database backup in default dir
  lowlydba.sqlserver.backup:
    sql_instance: sql-01.myco.io
    database: LowlyDB
    type: full
    file_count: 8

- name: Create t-log backup
  lowlydba.sqlserver.backup:
    sql_instance: sql-01.myco.io
    database: LowlyDB
    type: log
'''

RETURN = r'''
data:
  description: Modified output from the C(Backup-DbaDatabase) function.
  returned: success, but not in check_mode.
  type: dict
'''
