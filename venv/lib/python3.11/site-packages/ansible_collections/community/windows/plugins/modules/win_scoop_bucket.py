#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Jamie Magee <jamie.magee@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_scoop_bucket
version_added: 1.0.0
short_description: Manage Scoop buckets
description:
- Manage Scoop buckets
requirements:
- git
options:
  name:
    description:
    - Name of the Scoop bucket.
    type: str
    required: yes
  repo:
    description:
    - Git repository that contains the scoop bucket
    type: str
  state:
    description:
    - State of the Scoop bucket.
    - When C(absent), will ensure the package is not installed.
    - When C(present), will ensure the package is installed.
    type: str
    choices: [ absent, present ]
    default: present
seealso:
- module: community.windows.win_scoop
- name: Scoop website
  description: More information about Scoop
  link: https://scoop.sh
- name: Scoop directory
  description: A directory of buckets for the scoop package manager for Windows
  link: https://rasa.github.io/scoop-directory/
author:
- Jamie Magee (@JamieMagee)
'''

EXAMPLES = r'''
- name: Add the extras bucket
  community.windows.win_scoop_bucket:
    name: extras

- name: Remove the versions bucket
  community.windows.win_scoop_bucket:
    name: versions
    state: absent

- name: Add a custom bucket
  community.windows.win_scoop_bucket:
    name: my-bucket
    repo: https://github.com/example/my-bucket
'''

RETURN = r'''
rc:
    description: The result code of the scoop action
    returned: always
    type: int
    sample: 0
stdout:
    description: The raw output from the scoop action
    returned: on failure or when verbosity is greater than 1
    type: str
    sample: The test bucket was added successfully.
'''
