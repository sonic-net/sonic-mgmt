#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_power_plan
short_description: Changes the power plan of a Windows system
description:
  - This module will change the power plan of a Windows system to the defined string.
  - Windows defaults to C(balanced) which will cause CPU throttling. In some cases it can be preferable
    to change the mode to C(high performance) to increase CPU performance.
  - One of I(name) or I(guid) must be provided.
options:
  name:
    description:
      - String value that indicates the desired power plan by name.
      - The power plan must already be present on the system.
      - Commonly there will be options for C(balanced) and C(high performance).
    type: str
    required: false
  guid:
    description:
      - String value that indicates the desired power plan by guid.
      - The power plan must already be present on the system.
      - For out of box guids see U(https://docs.microsoft.com/en-us/windows/win32/power/power-policy-settings).
    type: str
    required: false
    version_added: 1.9.0

author:
  - Noah Sparks (@nwsparks)
'''

EXAMPLES = r'''
- name: Change power plan to high performance
  community.windows.win_power_plan:
    name: high performance

- name: Change power plan to high performance
  community.windows.win_power_plan:
    guid: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
'''

RETURN = r'''
power_plan_name:
  description: Value of the intended power plan.
  returned: always
  type: str
  sample: balanced
power_plan_enabled:
  description: State of the intended power plan.
  returned: success
  type: bool
  sample: true
all_available_plans:
  description: The name and enabled state of all power plans.
  returned: always
  type: dict
  sample: |
    {
        "High performance":  false,
        "Balanced":  true,
        "Power saver":  false
    }
'''
