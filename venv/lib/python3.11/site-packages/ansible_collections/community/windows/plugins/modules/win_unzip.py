#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Phil Schwartz <schwartzmx@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_unzip
short_description: Unzips compressed files and archives on the Windows node
description:
- Unzips compressed files and archives.
- Supports .zip files natively.
- Supports other formats supported by the Powershell Community Extensions (PSCX) module (basically everything 7zip supports).
- For non-Windows targets, use the M(ansible.builtin.unarchive) module instead.
requirements:
- PSCX
options:
  src:
    description:
      - File to be unzipped (provide absolute path).
    type: path
    required: yes
  dest:
    description:
      - Destination of zip file (provide absolute path of directory). If it does not exist, the directory will be created.
    type: path
    required: yes
  delete_archive:
    description:
      - Remove the zip file, after unzipping.
    type: bool
    default: no
    aliases: [ rm ]
  recurse:
    description:
      - Recursively expand zipped files within the src file.
      - Setting to a value of C(yes) requires the PSCX module to be installed.
    type: bool
    default: no
  creates:
    description:
      - If this file or directory exists the specified src will not be extracted.
    type: path
  password:
    description:
      - If a zip file is encrypted with password.
      - Passing a value to a password parameter requires the PSCX module to be installed.
notes:
- This module is not really idempotent, it will extract the archive every time, and report a change.
- For extracting any compression types other than .zip, the PowerShellCommunityExtensions (PSCX) Module is required.  This module (in conjunction with PSCX)
  has the ability to recursively unzip files within the src zip file provided and also functionality for many other compression types. If the destination
  directory does not exist, it will be created before unzipping the file.  Specifying rm parameter will force removal of the src file after extraction.
seealso:
- module: ansible.builtin.unarchive
author:
- Phil Schwartz (@schwartzmx)
'''

EXAMPLES = r'''
# This unzips a library that was downloaded with win_get_url, and removes the file after extraction
# $ ansible -i hosts -m win_unzip -a "src=C:\LibraryToUnzip.zip dest=C:\Lib remove=yes" all

- name: Unzip a bz2 (BZip) file
  community.windows.win_unzip:
    src: C:\Users\Phil\Logs.bz2
    dest: C:\Users\Phil\OldLogs
    creates: C:\Users\Phil\OldLogs

- name: Unzip gz log
  community.windows.win_unzip:
    src: C:\Logs\application-error-logs.gz
    dest: C:\ExtractedLogs\application-error-logs

# Unzip .zip file, recursively decompresses the contained .gz files and removes all unneeded compressed files after completion.
- name: Recursively decompress GZ files in ApplicationLogs.zip
  community.windows.win_unzip:
    src: C:\Downloads\ApplicationLogs.zip
    dest: C:\Application\Logs
    recurse: true
    delete_archive: true

- name: Install PSCX
  community.windows.win_psmodule:
    name: Pscx
    state: present

- name: Unzip .7z file which is password encrypted
  community.windows.win_unzip:
    src: C:\Downloads\ApplicationLogs.7z
    dest: C:\Application\Logs
    password: abcd
    delete_archive: true
'''

RETURN = r'''
dest:
    description: The provided destination path
    returned: always
    type: str
    sample: C:\ExtractedLogs\application-error-logs
removed:
    description: Whether the module did remove any files during task run
    returned: always
    type: bool
    sample: true
src:
    description: The provided source path
    returned: always
    type: str
    sample: C:\Logs\application-error-logs.gz
'''
