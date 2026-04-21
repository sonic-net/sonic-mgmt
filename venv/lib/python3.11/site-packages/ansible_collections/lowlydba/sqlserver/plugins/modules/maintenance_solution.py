#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: maintenance_solution
short_description: Install/update Maintenance Solution by Ola Hallengren
description:
  - A wrapper for C(Install-DbaMaintenanceSolution) to fetch the latest version of the Ola Hallengren's Maintenance Solution,
    or install from a local cached version.
version_added: 0.1.0
options:
  backup_location:
    description:
      - Location of the backup root directory. If this is not supplied, the default backup directory will be used.
    type: str
    required: false
  cleanup_time:
    description:
      - Time in hours, after which backup files are deleted.
    type: int
    required: false
    default: 0
  output_file_dir:
    description:
      - Specify the output file directory where the Maintenance Solution will write to.
    type: str
    required: false
  replace_existing:
    description:
      - If this switch is enabled, objects already present in the target database will be dropped and recreated.
    type: bool
    required: false
  log_to_table:
    description:
      - If this switch is enabled, the Maintenance Solution will be configured to log commands to a table.
    type: bool
    required: false
    default: false
  solution:
    description:
      - Specifies which portion of the Maintenance Solution to install.
    type: str
    required: false
    default: 'All'
    choices: ['All', 'Backup', 'IntegrityCheck', 'IndexOptimize']
  install_jobs:
    description:
      - If this switch is enabled, the corresponding SQL Agent Jobs will be created.
    type: bool
    required: false
    default: false
  install_parallel:
    description:
      - If this switch is enabled, the C(Queue) and C(QueueDatabase) tables are created, for use when C(@DatabasesInParallel = 'Y') are set in the jobs.
    type: bool
    required: false
    default: false
  local_file:
    description:
      - Specifies the path to a local file to install Ola's solution from. This should be the zip file as distributed by the maintainers.
      - If this option is not specified, the latest version will be downloaded and installed
        from the L(Maintenance Solution Github,https://github.com/olahallengren/sql-server-maintenance-solution).
    type: str
    required: false
  database:
    description:
      - Name of the target database.
    type: str
    required: true
  force:
    description:
      - If this switch is enabled, the Maintenance Solution will be downloaded from the internet even if previously cached.
    type: bool
    default: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Install/Update Maintenance Solution
  lowlydba.sqlserver.multitool:
    sql_instance: sql-01.myco.io
    database: main
    replace_existing: true
'''

RETURN = r'''
data:
  description: Output from the C(Install-MaintenanceSolution) function.
  returned: success, but not in check_mode.
  type: dict
'''
