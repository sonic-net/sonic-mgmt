#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_chocolatey_feature
version_added: '0.2.7'
short_description: Manages Chocolatey features
description:
- Used to enable or disable features in Chocolatey.
options:
  name:
    description:
    - The name of the feature to manage.
    - Run C(choco.exe feature list) to get a list of features that can be
      managed.
    - For a list of options see L(Chocolatey feature docs,https://chocolatey.org/docs/chocolatey-configuration#features)
    type: str
    required: true
  state:
    description:
    - When C(disabled) then the feature will be disabled.
    - When C(enabled) then the feature will be enabled.
    type: str
    choices: [ disabled, enabled ]
    default: enabled
seealso:
- module: chocolatey.chocolatey.win_chocolatey
- module: chocolatey.chocolatey.win_chocolatey_config
- module: chocolatey.chocolatey.win_chocolatey_facts
- module: chocolatey.chocolatey.win_chocolatey_source
author:
- Jordan Borean (@jborean93)
- Rain Sallow (@vexx32)
- Josh King (@windos)
'''

EXAMPLES = r'''
- name: Disable file checksum matching
  win_chocolatey_feature:
    name: checksumFiles
    state: disabled

- name: Stop Chocolatey on the first package failure
  win_chocolatey_feature:
    name: stopOnFirstPackageFailure
    state: enabled
'''

RETURN = r'''
'''
