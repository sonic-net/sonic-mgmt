#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Peter Mounce <public@neverrunwithscissors.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_webpicmd
short_description: Installs packages using Web Platform Installer command-line
description:
    - Installs packages using Web Platform Installer command-line
      (U(http://www.iis.net/learn/install/web-platform-installer/web-platform-installer-v4-command-line-webpicmdexe-rtw-release)).
    - Must be installed and present in PATH (see M(chocolatey.chocolatey.win_chocolatey) module; 'webpicmd' is the package name, and you must install
      'lessmsi' first too)?
    - Install IIS first (see M(ansible.windows.win_feature) module).
notes:
    - Accepts EULAs and suppresses reboot - you will need to check manage reboots yourself (see M(ansible.windows.win_reboot) module)
options:
  name:
    description:
      - Name of the package to be installed.
    type: str
    required: yes
seealso:
- module: ansible.windows.win_package
author:
- Peter Mounce (@petemounce)
'''

EXAMPLES = r'''
- name: Install URLRewrite2.
  community.windows.win_webpicmd:
    name: URLRewrite2
'''
