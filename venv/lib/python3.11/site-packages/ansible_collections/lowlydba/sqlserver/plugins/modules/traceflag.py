#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# (c) 2021, Sudhir Koduri (@kodurisudhir)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: traceflag
short_description: Enable or disable global trace flags on a SQL Server instance
description:
  - Enable\Disable global trace flag on a SQL Instance. This trace flag takes affect immediately and does not require SQL Instance restart.
  - This setting does not persist after restart.
version_added: 0.1.0
options:
  trace_flag:
    description:
      - Trace Flag number.
    type: int
    required: true
  enabled:
    description:
      - Flag to enable or disable the trace flag.
    type: bool
    required: true
author: "Sudhir Koduri (@kodurisudhir)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Eliminate successful backup information from SQL Error Log
  lowlydba.sqlserver.traceflag:
    sql_instance: sql-01.myco.io
    trace_flag: 3226
    enabled: true

- name: Disable trace flag
  lowlydba.sqlserver.traceflag:
    sql_instance: sql-01.myco.io
    trace_flag: 3226
    enabled: false
'''

RETURN = r'''
data:
  description: Output from the C(Enable-DbaTraceFlag) or C(Disable-DbaTraceFlag) function.
  returned: success, but not in check_mode.
  type: dict
'''
