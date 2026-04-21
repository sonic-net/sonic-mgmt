#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_psscript_info
short_description: Gather information about installed PowerShell Scripts
description:
  - Gather information about PowerShell Scripts installed via PowerShellGet.
options:
  name:
    description:
      - The name of the script.
      - Supports any wildcard pattern supported by C(Get-InstalledScript).
      - If omitted then all scripts will returned.
    type: str
    default: '*'
  repository:
    description:
      - The name of the PSRepository the scripts were installed from.
      - This acts as a filter against the scripts that would be returned based on the I(name) option.
      - Only scripts installed from a registered repository will be returned.
      - If the repository was re-registered after script installation with a new C(SourceLocation), this will not match.
    type: str
requirements:
  - C(PowerShellGet) module
seealso:
  - module: community.windows.win_psrepository_info
  - module: community.windows.win_psmodule_info
author:
  - Brian Scholer (@briantist)
'''

EXAMPLES = r'''
- name: Get info about all script on the system
  community.windows.win_psscript_info:

- name: Get info about the Test-RPC script
  community.windows.win_psscript_info:
    name: Test-RPC

- name: Get info about test scripts
  community.windows.win_psscript_info:
    name: Test*

- name: Get info about all scripts installed from the PSGallery repository
  community.windows.win_psscript_info:
    repository: PSGallery
  register: gallery_scripts

- name: Update all scripts retrieved from above example
  community.windows.win_psscript:
    name: "{{ item }}"
    state: latest
  loop: "{{ gallery_scripts.scripts | map(attribute=name) }}"

- name: Get info about all scripts on the system
  community.windows.win_psscript_info:
  register: all_scripts

- name: Find scripts installed from a repository that isn't registered now
  set_fact:
    missing_repository_scripts: "{{
      all_scripts
      | json_query('scripts[?repository!=null && repository==repository_source_location].{name: name, version: version, repository: repository}')
      | list
    }}"

- debug:
    var: missing_repository_scripts
'''

RETURN = r'''
scripts:
  description:
    - A list of installed scripts (or an empty list is there are none).
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description:
        - The name of the script.
      type: str
      sample: Test-RPC
    version:
      description:
        - The script version.
      type: str
      sample: 1.2.3
    installed_location:
      description:
        - The path where the script is installed.
      type: str
      sample: 'C:\Program Files\WindowsPowerShell\Scripts'
    author:
      description:
        - The author of the script.
      type: str
      sample: Ryan Ries
    copyright:
      description:
        - The copyright of the script.
      type: str
      sample: 'Jordan Borean 2017'
    company_name:
      description:
        - The company name of the script.
      type: str
      sample: Microsoft Corporation
    description:
      description:
        - The description of the script.
      type: str
      sample: This scripts tests network connectivity.
    dependencies:
      description:
        - The script's dependencies.
      type: list
      elements: str
    icon_uri:
      description:
        - The address of the icon of the script.
      type: str
      sample: 'https://raw.githubusercontent.com/scripter/script/main/logo.png'
    license_uri:
      description:
        - The address of the license for the script.
      type: str
      sample: 'https://raw.githubusercontent.com/scripter/script/main/LICENSE'
    project_uri:
      description:
        - The address of the script's project.
      type: str
      sample: 'https://github.com/scripter/script'
    repository_source_location:
      description:
        - The source location of the repository where the script was installed from.
      type: str
      sample: 'https://www.powershellgallery.com/api/v2'
    repository:
      description:
        - The PSRepository where the script was installed from.
        - This value is not historical. It depends on the PSRepositories that are registered now for the current user.
        - The C(repository_source_location) must match the current source location of a registered repository to get a repository name.
        - If there is no match, then this value will match C(repository_source_location).
      type: str
      sample: PSGallery
    release_notes:
      description:
        - The script's release notes. This is a free text field and no specific format should be assumed.
      type: str
      sample: |
        ## 1.5.5
        - Add optional param for detailed info

        ## 1.4.7
        - Bug fix for deadlock when getting parameters in an event

        ## 1.1.4
        - Bug fix when installing package from private feeds
    installed_date:
      description:
        - The date the script was installed.
      type: str
      sample: '2018-02-14T17:55:34.9620740-05:00'
    published_date:
      description:
        - The date the script was published.
      type: str
      sample: '2017-03-15T04:18:09.0000000'
    updated_date:
      description:
        - The date the script was last updated.
      type: str
      sample: '2019-12-31T09:20:02.0000000'
    package_management_provider:
      description:
        - This is the PowerShellGet package management provider used to install the script.
      type: str
      sample: NuGet
    tags:
      description:
        - The tags defined in the script's C(AdditionalMetadata).
      type: list
      elements: str
      sample:
        - networking
        - serialization
        - git
        - dsc
    power_shell_get_format_version:
      description:
        - The version of the PowerShellGet specification format.
      type: str
      sample: '2.0'
    additional_metadata:
      description:
        - Additional metadata included with the script or during publishing of the script.
        - Many of the fields here are surfaced at the top level with some standardization. The values here may differ slightly as a result.
        - The field names here vary widely in case, and are not normalized or converted to snake_case.
      type: dict
'''
