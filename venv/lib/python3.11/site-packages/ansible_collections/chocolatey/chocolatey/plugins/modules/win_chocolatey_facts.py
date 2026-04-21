#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2018, Simon Baerlocher <s.baerlocher@sbaerlocher.ch>
# Copyright: (c) 2018, ITIGO AG <opensource@itigo.ch>
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_chocolatey_facts
version_added: '0.2.8'
short_description: Create a facts collection for Chocolatey
description:
- This module shows information from Chocolatey, such as installed packages, outdated packages, configuration, feature and sources.
options:
  filter:
    version_added: "1.5.0"
    description:
    - "If supplied, restrict the facts collected to the given subset.
      Possible values: C(all), C(config), C(feature), C(outdated),
      C(packages), C(sources)."
    - You can provide a list of values to specify a larger subset.
    type: list
    elements: str
    choices: [ all, config, feature, outdated, packages, sources ]
    default: "all"
    aliases: [ gather_subset ]
notes:
- Chocolatey must be installed beforehand, use M(chocolatey.chocolatey.win_chocolatey) to do this.
seealso:
- module: chocolatey.chocolatey.win_chocolatey
- module: chocolatey.chocolatey.win_chocolatey_config
- module: chocolatey.chocolatey.win_chocolatey_feature
- module: chocolatey.chocolatey.win_chocolatey_source
author:
- Simon Bärlocher (@sbaerlocher)
- ITIGO AG (@itigoag)
- Rain Sallow (@vexx32)
- Josh King (@windos)
'''

EXAMPLES = r'''
- name: Gather facts from chocolatey
  win_chocolatey_facts:

- name: Displays the Configuration
  debug:
    var: ansible_chocolatey.config

- name: Displays the Feature
  debug:
    var: ansible_chocolatey.feature

- name: Displays the Sources
  debug:
    var: ansible_chocolatey.sources

- name: Displays the Packages
  debug:
    var: ansible_chocolatey.packages

- name: Displays the Outdated packages
  debug:
    var: ansible_chocolatey.outdated

- name: Gather all facts from chocolatey, except outdated packages
  win_chocolatey_facts:
    filter:
    - 'config'
    - 'feature'
    - 'packages'
    - 'sources'

- name: Displays the collected facts from chocolatey without the outdated packages
  debug:
    var: ansible_chocolatey

- name: Clear existing facts from chocolatey
  ansible.builtin.meta: clear_facts

- name: Gather config and feature facts only from chocolatey
  win_chocolatey_facts:
    filter:
    - 'config'
    - 'feature'

- name: Displays the collected config and feature facts from chocolatey
  debug:
    var: ansible_chocolatey
'''

RETURN = r'''
ansible_facts:
  description: Detailed information about the Chocolatey installation
  returned: always
  type: complex
  contains:
    ansible_chocolatey:
      description: Detailed information about the Chocolatey installation
      returned: always
      type: complex
      contains:
        config:
          description: Detailed information about stored the configurations
          returned: always (except when filter is set to exclude config)
          type: dict
          sample:
            commandExecutionTimeoutSeconds: 2700
            containsLegacyPackageInstalls: true
        feature:
          description: Detailed information about enabled and disabled features
          returned: always (except when filter is set to exclude feature)
          type: dict
          sample:
            allowEmptyCheckums: false
            autoUninstaller: true
            failOnAutoUninstaller: false
        sources:
          description: List of Chocolatey sources
          returned: always (except when filter is set to exclude sources)
          type: complex
          contains:
            admin_only:
              description: Is the source visible to Administrators only
              returned: always
              type: bool
              sample: false
            allow_self_service:
              description: Is the source allowed to be used with self-service
              returned: always
              type: bool
              sample: false
            bypass_proxy:
              description: Can the source explicitly bypass configured proxies
              returned: always
              type: bool
              sample: true
            certificate:
              description: Pth to a PFX certificate for X509 authenticated feeds
              returned: always
              type: str
              sample: C:\chocolatey\cert.pfx
            disabled:
              description: Is the source disabled
              returned: always
              type: bool
              sample: false
            name:
              description: Name of the source
              returned: always
              type: str
              sample: chocolatey
            priority:
              description: The priority order of this source, lower is better, 0 is no priority
              returned: always
              type: int
              sample: 0
            source:
              description: The source, can be a folder/file or an url
              returned: always
              type: str
              sample: https://community.chocolatey.org/api/v2/
            source_username:
              description: Username used to access authenticated feeds
              returned: always
              type: str
              sample: username
        filter:
          description: The list of subsets that were gathered
          returned: always
          type: list
          elements: str
          sample: ['all']
          version_added: '1.5.0'
        packages:
          description: List of installed Packages
          returned: always (except when filter is set to exclude packages)
          type: complex
          contains:
            package:
              description: Name of the package
              returned: always
              type: str
              sample: vscode
            version:
              description: Version of the package
              returned: always
              type: str
              sample: '1.27.2'
        outdated:
          description: List of packages for which an update is available
          returned: always (except when filter is set to exclude outdated)
          type: complex
          version_added: '1.3.0'
          contains:
            available_version:
              description: Available version of the package
              returned: always
              type: str
              sample: 7.2.4
            current_version:
              description: Current version of the package
              returned: always
              type: str
              sample: 7.2.3
            package:
              description: Name of the package
              returned: always
              type: str
              sample: vscodepowershell-core",
            pinned:
              description: Is the version of the package pinned to suppress upgrades
              returned: always
              type: bool
              sample: false
'''
