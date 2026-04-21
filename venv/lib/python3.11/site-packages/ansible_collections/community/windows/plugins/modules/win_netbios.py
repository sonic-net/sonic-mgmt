#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Thomas Moore (@tmmruk)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_netbios
short_description: Manage NetBIOS over TCP/IP settings on Windows.
description:
  - Enables or disables NetBIOS on Windows network adapters.
  - Can be used to protect a system against NBT-NS poisoning and avoid NBNS broadcast storms.
  - Settings can be applied system wide or per adapter.
options:
  state:
    description:
      - Whether NetBIOS should be enabled, disabled, or default (use setting from DHCP server or if static IP address is assigned enable NetBIOS).
    choices:
      - enabled
      - disabled
      - default
    required: yes
    type: str
  adapter_names:
    description:
      - List of adapter names for which to manage NetBIOS settings. If this option is omitted then configuration is applied to all adapters on the system.
      - The adapter name used is the connection caption in the Network Control Panel or via C(Get-NetAdapter), eg C(Ethernet 2).
    type: list
    elements: str
    required: no

author:
  - Thomas Moore (@tmmruk)
notes:
  - Changing NetBIOS settings does not usually require a reboot and will take effect immediately.
  - UDP port 137/138/139 will no longer be listening once NetBIOS is disabled.
'''

EXAMPLES = r'''
- name: Disable NetBIOS system wide
  community.windows.win_netbios:
    state: disabled

- name: Disable NetBIOS on Ethernet2
  community.windows.win_netbios:
    state: disabled
    adapter_names:
      - Ethernet2

- name: Enable NetBIOS on Public and Backup adapters
  community.windows.win_netbios:
    state: enabled
    adapter_names:
      - Public
      - Backup

- name: Set NetBIOS to system default on all adapters
  community.windows.win_netbios:
    state: default
'''

RETURN = r'''
reboot_required:
    description: Boolean value stating whether a system reboot is required.
    returned: always
    type: bool
    sample: true
'''
