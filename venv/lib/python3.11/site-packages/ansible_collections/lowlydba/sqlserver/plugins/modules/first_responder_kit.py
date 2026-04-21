#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: first_responder_kit
short_description: Install/update the First Responder Kit scripts
description:
  - A wrapper for C(Install-DbaFirstResponderKit) to fetch the latest version of the scripts, or install from a local cached version.
version_added: 0.10.0
options:
  local_file:
    description:
      - Specifies the path to a local file to install FRK from. This should be the zip file as distributed by the maintainers.
      - If this option is not specified, the latest version will be downloaded and installed Github.
    type: str
    required: false
  only_script:
    description:
      - Specifies the name(s) of the script(s) to run for installation. Wildcards are permitted.
      - This way only part of the First Responder Kit can be installed.
    type: str
    required: false
    default: 'Install-All-Scripts.sql'
    choices: ['Install-All-Scripts.sql',
              'Install-Core-Blitz-No-Query-Store.sql',
              'Install-Core-Blitz-With-Query-Store.sql',
              'sp_Blitz.sql',
              'sp_BlitzFirst.sql',
              'sp_BlitzIndex.sql',
              'sp_BlitzCache.sql',
              'sp_BlitzWho.sql',
              'sp_BlitzQueryStore.sql',
              'sp_BlitzAnalysis.sql',
              'sp_BlitzBackups.sql',
              'sp_BlitzInMemoryOLTP.sql',
              'sp_BlitzLock.sql',
              'sp_AllNightLog.sql',
              'sp_AllNightLog_Setup.sql',
              'sp_DatabaseRestore.sql',
              'sp_ineachdb.sql',
              'SqlServerVersions.sql',
              'Uninstall.sql']
  branch:
    description:
      - Specifies an alternate branch of the First Responder Kit to install.
    type: str
    required: false
    choices: ['main', 'dev']
  database:
    description:
      - Name of the target database.
    type: str
    required: true
  force:
    description:
      - If this switch is enabled, the FRK will be downloaded from the internet even if previously cached.
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
- name: Install FRK
  lowlydba.sqlserver.first_responder_kit:
    sql_instance: test-server.my.company.com
    database: dba_tools
'''

RETURN = r'''
data:
  description: Modified output from the C(Install-DbaFirstResponderKit) function.
  returned: success, but not in check_mode.
  type: dict
'''
