#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: install_script
short_description: Runs migration scripts against a database
description:
  - Uses the module C(DBOps) to run C(Dbo-InstallScript) against a target SQL Server database.
version_added: 0.11.0
options:
  database:
    description:
      - Name of the target database.
    required: true
    type: str
  path:
    description:
      - Directory where targeted sql scripts are stored.
    type: str
    required: true
  schema_version_table:
    description:
      - A table that will hold the history of script execution. This table is used to choose what scripts are going to be
        run during the deployment, preventing the scripts from being execured twice.
    type: str
    required: false
  deployment_method:
    description:
      - C(SingleTransaction) - wrap all the deployment scripts into a single transaction and rollback whole deployment on error.
      - C(TransactionPerScript) - wrap each script into a separate transaction; rollback single script deployment in case of error.
      - C(NoTransaction) - deploy as is.
      - C(AlwaysRollback) - roll back the transaction.
    type: str
    required: false
    default: 'NoTransaction'
    choices: ['NoTransaction', 'SingleTransaction', 'TransactionPerScript', 'AlwaysRollback']
  no_log_version:
    description:
      - If set, the deployment will not be tracked in the database. That will also mean that all the scripts
        and all the builds from the package are going to be deployed regardless of any previous deployment history.
    type: bool
    default: false
    required: false
  connection_timeout:
    description:
      - Database server connection timeout in seconds. Only affects connection attempts. Does not affect execution timeout.
    type: int
    default: 30
    required: false
  execution_timeout:
    description:
      - Script execution timeout. The script will be aborted if the execution takes more than specified number of seconds.
    type: int
    default: 0
    required: false
  output_file:
    description:
      - Log output into specified file.
    type: str
    required: false
  create_database:
    description:
      - Will create an empty database if missing.
    type: bool
    default: false
    required: false
  no_recurse:
    description:
      - Only process the first level of the target path.
    type: bool
    required: false
    default: false
  match:
    description:
      - Runs a regex verification against provided file names using the provided string.
    type: str
    required: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
  - L(dbops,https://github.com/dataplat/dbops) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Migrate a database
  lowlydba.sqlserver.install_script:
    sql_instance: test-server.my.company.com
    database: AdventureWorks
    path: migrations
'''

RETURN = r'''
data:
  description: Modified output from the C(Install-DboScript) function.
  returned: success, but not in check_mode.
  type: dict
'''
