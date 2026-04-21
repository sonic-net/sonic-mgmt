#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: ag_replica
short_description: Configures an availability group replica
description:
  - Configures an availability group replica.
version_added: 0.5.0
options:
  sql_instance_replica:
    description:
      - The SQL Server instance where of the replica to be configured.
    type: str
    required: true
  sql_username_replica:
    description:
      - Username for SQL Authentication for the secondary replica.
    type: str
    required: false
  sql_password_replica:
    description:
      - Password for SQL Authentication for the secondary replica.
    type: str
    required: false
  ag_name:
    description:
      - Name of the Availability Group that will have the new replica joined to it.
    type: str
    required: true
  endpoint:
    description:
      - By default, this command will attempt to find a DatabaseMirror endpoint. If one does not exist, it will create it.
    type: str
    required: false
    default: 'hadr_endpoint'
  endpoint_url:
    description:
      - By default, the property C(Fqdn) of C(Get-DbaEndpoint) is used as I(endpoint_url).
        Use I(endpoint_url) if a different URL is required due to special network configurations.
    type: str
    required: false
  backup_priority:
    description:
      - Sets the backup priority availability group replica.
    type: int
    default: 50
  failover_mode:
    description:
      - Whether the replica have Automatic or Manual failover.
    type: str
    required: false
    default: 'Manual'
    choices: ['Automatic', 'Manual']
  availability_mode:
    description:
      - Whether the replica should be Asynchronous or Synchronous.
    type: str
    required: false
    default: 'AsynchronousCommit'
    choices: ['AsynchronousCommit', 'SynchronousCommit']
  seeding_mode:
    description:
      - Default seeding mode for the replica. Should remain as the default otherwise manual setup may be required.
    type: str
    required: false
    default: 'Automatic'
    choices: ['Automatic', 'Manual']
  connection_mode_in_primary_role:
    description:
      - Which connections can be made to the database when it is in the primary role.
    type: str
    required: false
    default: 'AllowAllConnections'
    choices: ['AllowReadIntentConnectionsOnly','AllowAllConnections']
  connection_mode_in_secondary_role:
    description:
      - Which connections can be made to the database when it is in the secondary role.
    type: str
    required: false
    default: 'AllowNoConnections'
    choices: ['AllowNoConnections','AllowReadIntentConnectionsOnly','AllowAllConnections']
  read_only_routing_connection_url:
    description:
      - Sets the read only routing connection url for the availability replica.
    type: str
    required: false
  read_only_routing_list:
    description:
      - Sets the read only routing ordered list of replica server names to use when redirecting read-only connections through this availability replica.
    type: str
    required: false
  cluster_type:
    description:
      - Cluster type of the Availability Group. Only supported in SQL Server 2017 and above.
    type: str
    required: false
    default: 'Wsfc'
    choices: ['Wsfc', 'External', 'None']
  configure_xe_session:
    description:
      - Configure the AlwaysOn_health extended events session to start automatically as the SSMS wizard would do.
    type: bool
    default: false
  session_timeout:
    description:
      - How many seconds an availability replica waits for a ping response from a connected replica before considering the connection to have failed.
    type: int
    required: false
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

- name: Add a DR replica
  lowlydba.sqlserver.ag_replica:
    ag_name: 'AG_MyDatabase'
    sql_instance_primary: sql-01.myco.io
    sql_instance_replica: sql-02.myco.io
    failover_mode: 'Manual'
    availability_mode: 'Asynchronous'
    seeding_mode: 'Automatic'
    connection_mode_in_primary_role: 'AllowAllConnections'
    connection_mode_in_secondary_role: 'AllowNoConnections'
'''

RETURN = r'''
data:
  description: Output from the C(Add-DbaAgReplica) or C(Set-DbaAgReplica) function.
  returned: success, but not in check_mode.
  type: dict
'''
