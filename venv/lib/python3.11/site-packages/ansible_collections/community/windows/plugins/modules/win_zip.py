#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Kento Yagisawa <thel.vadam2485@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_zip
short_description: Compress file or directory as zip archive on the Windows node
description:
- Compress file or directory as zip archive.
- For non-Windows targets, use the M(community.general.archive) module instead.
notes:
- The filenames in the zip are encoded using UTF-8.
requirements:
- .NET Framework 4.5 or later
options:
  src:
    description:
      - File or directory path to be zipped (provide absolute path on the target node).
      - When a directory path the directory is zipped as the root entry in the archive.
      - Specify C(\*) to the end of I(src) to zip the contents of the directory and not the directory itself.
    type: str
    required: yes
  dest:
    description:
      - Destination path of zip file (provide absolute path of zip file on the target node).
    type: path
    required: yes
seealso:
- module: community.general.archive
author:
- Kento Yagisawa (@hiyoko_taisa)
'''

EXAMPLES = r'''
- name: Compress a file
  community.windows.win_zip:
    src: C:\Users\hiyoko\log.txt
    dest: C:\Users\hiyoko\log.zip

- name: Compress a directory as the root of the archive
  community.windows.win_zip:
    src: C:\Users\hiyoko\log
    dest: C:\Users\hiyoko\log.zip

- name: Compress the directories contents
  community.windows.win_zip:
    src: C:\Users\hiyoko\log\*
    dest: C:\Users\hiyoko\log.zip
'''
