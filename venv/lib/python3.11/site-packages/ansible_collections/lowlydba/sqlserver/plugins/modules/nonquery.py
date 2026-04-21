#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: nonquery
short_description: Executes a generic nonquery
description:
  - Execute a nonquery against a database. Does not return a resultset. Ideal for ad-hoc configurations or DML queries.
version_added: 0.1.0
options:
  database:
    description:
      - Name of the database to execute the nonquery in.
    type: str
    required: true
  nonquery:
    description:
      - The nonquery to be executed.
    type: str
    required: true
  query_timeout:
    description:
      - Number of seconds to wait before timing out the nonquery execution.
    type: int
    required: false
    default: 60
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Update a table value
  lowlydba.sqlserver.nonquery:
    sql_instance: sql-01-myco.io
    database: userdb
    nonquery: "UPDATE dbo.User set IsActive = 1;"
'''

RETURN = r''' # '''
