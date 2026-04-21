#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Sam Liu <sam.liu@activenetwork.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_file_version
short_description: Get DLL or EXE file build version
description:
  - Get DLL or EXE file build version.
notes:
  - This module will always return no change.
options:
  path:
    description:
      - File to get version.
      - Always provide absolute path.
    type: path
    required: yes
seealso:
- module: ansible.windows.win_file
author:
- Sam Liu (@SamLiu79)
- Mikhail Samodurov (@EasyMoney322)
'''

EXAMPLES = r'''
- name: Get acm instance version
  community.windows.win_file_version:
    path: C:\Windows\System32\cmd.exe
  register: exe_file_version

- debug:
    msg: '{{ exe_file_version.win_file_version }}'
'''

RETURN = r'''
win_file_version:
    description: dictionary containing all the version data
    returned: success
    type: complex
    contains:
        file_build_part:
          description: build number of the file.
          returned: no error
          type: str
          sample: "2"
        file_major_part:
          description: the major part of the version number.
          returned: no error
          type: str
          sample: "0"
        file_minor_part:
          description: the minor part of the version number of the file.
          returned: no error
          type: str
          sample: "30"
        file_private_part:
          description: file private part number.
          returned: no error
          type: str
          sample: "0"
        file_version:
          description: File version number.
          returned: no error
          type: str
          sample: "v0.30.2"
        file_version_raw:
          description: File version number that may not match the file_version
          returned: no error
          type: str
          sample: "0.30.2.0"
          version_added: 2.4.0
        path:
          description: file path
          returned: always
          type: str
        product_version:
          description: The version of the product this file is distributed with.
          returned: no error
          type: str
          sample: "0.30.2+b4a594409fc9e79e7c5161763cf1c4328e9c5a5d"
'''
