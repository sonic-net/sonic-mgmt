#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: availability_group
short_description: Configures availability group(s)
description:
  - Configures SQL Server Availability Group(s) with up to one replica.
version_added: 0.4.0
options:
  sql_instance_secondary:
    description:
      - The secondary SQL Server instance for the new Availability Group.
    type: str
    required: false
  sql_username_secondary:
    description:
      - Username for SQL Authentication for the secondary replica.
    type: str
    required: false
  sql_password_secondary:
    description:
      - Password for SQL Authentication for the secondary replica.
    type: str
    required: false
  database:
    description:
      - Name of the database to create the Availability Group for.
    type: str
    required: false
    aliases:
    - database_name
  ag_name:
    description:
      - Name of the Availability Group.
    type: str
    required: true
  all_ags:
    description:
      - Apply changes to all availability groups on the instance. Only used for configuring existing availability groups.
    type: bool
    required: false
  shared_path:
    description:
      - The network share where the backups will be backed up and restored from.
    type: str
    required: false
  dtc_support_enabled:
    description:
      - Enables Dtc support.
    type: bool
    required: false
  basic_availability_group:
    description:
      - Indicates whether the availability group is Basic Availability Group.
    type: bool
    required: false
  contained_availability_group:
    description:
    - Indicates whether the availability group is Contained. Requires DBATools >= 2.1.15
    type: bool
    required: false
    version_added: "2.6.0"
  database_health_trigger:
    description:
      - Indicates whether the availability group triggers the database health.
    type: bool
    required: false
  is_distributed_ag:
    description:
      - Indicates whether the availability group is distributed.
    type: bool
    required: false
  healthcheck_timeout:
    description:
      - This setting used to specify the length of time, in milliseconds,
        that the SQL Server resource DLL should wait for information returned by the C(sp_server_diagnostics)
        stored procedure before reporting the Always On Failover Cluster Instance (FCI) as unresponsive.
      - Changes that are made to the timeout settings are effective immediately and do not require a restart of the SQL Server resource.
    type: int
    required: false
  failure_condition_level:
    description:
      - Specifies the different conditions that can trigger an automatic failover in Availability Group.
    type: str
    required: false
    choices: ['OnAnyQualifiedFailureCondition', 'OnCriticalServerErrors', 'OnModerateServerErrors', 'OnServerDown', 'OnServerUnresponsive']
  cluster_type:
    description:
      - Cluster type of the Availability Group. Only supported in SQL Server 2017 and above.
    type: str
    required: false
    default: 'Wsfc'
    choices: ['Wsfc', 'External', 'None']
  failover_mode:
    description:
      - Whether the replica have Automatic or Manual failover.
    type: str
    required: false
    default: 'Automatic'
    choices: ['Automatic', 'Manual']
  availability_mode:
    description:
      - Whether the replica should be Asynchronous or Synchronous.
      - Only used in creating a new availability group.
    type: str
    required: false
    default: 'SynchronousCommit'
    choices: ['AsynchronousCommit', 'SynchronousCommit']
  seeding_mode:
    description:
      - Default seeding mode for the replica. Should remain as the default otherwise manual setup may be required.
    type: str
    required: false
    default: 'Manual'
    choices: ['Automatic', 'Manual']
  automated_backup_preference:
    description:
      - How to handle backup requests by default.
    type: str
    required: false
    default: 'Secondary'
    choices: ['None', 'Primary', 'Secondary', 'SecondaryOnly']
  allow_null_backup:
    description:
      - Allow taking a full backup to C(NULL) if one does not exist and I(seeding_mode=Automatic).
    type: bool
    required: false
  force:
    description:
      - Drop and recreate the database on remote servers using fresh backup.
    type: bool
  use_last_backup:
    description:
      - Use the last full and log backup of database. A log backup must be the last backup.
    type: bool
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
  - lowlydba.sqlserver.state
'''

EXAMPLES = r'''
- name: Create Availability Group
  lowlydba.sqlserver.availability_group:
    sql_instance: sql-01.myco.io
    ag_name: AG_MyDatabase
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaAvailabilityGroup) or C(Set-DbaAvailabilityGroup) function.
  returned: success, but not in check_mode.
  type: dict
'''
