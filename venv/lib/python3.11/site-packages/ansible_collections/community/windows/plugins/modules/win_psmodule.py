#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Wojciech Sciesinski <wojciech[at]sciesinski[dot]net>
# Copyright: (c) 2017, Daniele Lazzari <lazzari@mailup.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_psmodule
short_description: Adds or removes a Windows PowerShell module
description:
  - This module helps to install Windows PowerShell modules and register custom modules repository on Windows-based systems.
options:
  name:
    description:
      - Name of the Windows PowerShell module that has to be installed.
    type: str
    required: yes
  state:
    description:
      - If C(present) a new module is installed.
      - If C(absent) a module is removed.
      - If C(latest) a module is updated to the newest version.
    type: str
    choices: [ absent, latest, present ]
    default: present
  required_version:
    description:
      - The exact version of the PowerShell module that has to be installed.
    type: str
  minimum_version:
    description:
      - The minimum version of the PowerShell module that has to be installed.
    type: str
  maximum_version:
    description:
      - The maximum version of the PowerShell module that has to be installed.
    type: str
  allow_clobber:
    description:
      - If C(yes) allows install modules that contains commands those have the same names as commands that already exists.
    type: bool
    default: no
  skip_publisher_check:
    description:
      - If C(yes), allows you to install a different version of a module that already exists on your computer in the case when a different one
        is not digitally signed by a trusted publisher and the newest existing module is digitally signed by a trusted publisher.
    type: bool
    default: no
  allow_prerelease:
    description:
      - If C(yes) installs modules marked as prereleases.
      - It doesn't work with the parameters C(minimum_version) and/or C(maximum_version).
      - It doesn't work with the C(state) set to absent.
    type: bool
    default: no
  repository:
    description:
      - Name of the custom repository to use.
    type: str
  username:
    description:
      - Username to authenticate against private repository.
    type: str
    required: no
    version_added: '1.10.0'
  password:
    description:
      - Password to authenticate against private repository.
    type: str
    required: no
    version_added: '1.10.0'
  accept_license:
    description:
      - Accepts the module's license.
      - Required for modules that require license acceptance, since interactively answering the prompt is not possible.
      - Corresponds to the C(-AcceptLicense) parameter of C(Install-Module).
      - >-
        Installation of a module or a dependency that requires license acceptance cannot be detected in check mode,
        but will cause a failure at runtime unless I(accept_license=true).
    type: bool
    required: no
    default: false
    version_added: '1.11.0'
  force:
    description:
      - Overrides warning messages about module installation conflicts
      - If there is an existing module with the same name and version, force overwrites that version
      - Corresponds to the C(-Force) parameter of C(Install-Module).
      - >-
        If module as dependency, it will also force reinstallation of dependency.
        Updating them to latest if version isn't specified in module manifest.
    type: bool
    required: no
    default: false
    version_added: '1.13.0'
notes:
  - PowerShell modules needed
      - PowerShellGet >= 1.6.0
      - PackageManagement >= 1.1.7
  - PowerShell package provider needed
      - NuGet >= 2.8.5.201
  - On PowerShell 5.x required modules and a package provider will be updated under the first run of the win_psmodule module.
  - On PowerShell 3.x and 4.x you have to install them before using the win_psmodule.
seealso:
- module: community.windows.win_psrepository
author:
- Wojciech Sciesinski (@it-praktyk)
- Daniele Lazzari (@dlazz)
'''

EXAMPLES = r'''
---
- name: Add a PowerShell module
  community.windows.win_psmodule:
    name: PowerShellModule
    state: present

- name: Add an exact version of PowerShell module
  community.windows.win_psmodule:
    name: PowerShellModule
    required_version: "4.0.2"
    state: present

- name: Install or update an existing PowerShell module to the newest version
  community.windows.win_psmodule:
    name: PowerShellModule
    state: latest

- name: Install newer version of built-in Windows module
  community.windows.win_psmodule:
    name: Pester
    skip_publisher_check: true
    state: present

- name: Add a PowerShell module and register a repository
  community.windows.win_psmodule:
    name: MyCustomModule
    repository: MyRepository
    state: present

- name: Add a PowerShell module from a specific repository
  community.windows.win_psmodule:
    name: PowerShellModule
    repository: MyRepository
    state: present

- name: Add a PowerShell module from a specific repository with credentials
  win_psmodule:
    name: PowerShellModule
    repository: MyRepository
    username: repo_username
    password: repo_password
    state: present

- name: Remove a PowerShell module
  community.windows.win_psmodule:
    name: PowerShellModule
    state: absent
'''

RETURN = r'''
---
output:
  description: A message describing the task result.
  returned: always
  sample: "Module PowerShellCookbook installed"
  type: str
nuget_changed:
  description: True when Nuget package provider is installed.
  returned: always
  type: bool
  sample: true
repository_changed:
  description: True when a custom repository is installed or removed.
  returned: always
  type: bool
  sample: true
'''
