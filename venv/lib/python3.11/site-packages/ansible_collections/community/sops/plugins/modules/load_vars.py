#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
author: Felix Fontein (@felixfontein)
module: load_vars
short_description: Load SOPS-encrypted variables from files, dynamically within a task
version_added: '0.1.0'
description:
  - Loads SOPS-encrypted YAML/JSON variables dynamically from a file during task runtime.
  - To assign included variables to a different host than C(inventory_hostname), use C(delegate_to) and set C(delegate_facts=true).
options:
  file:
    description:
      - The file name from which variables should be loaded.
      - If the path is relative, it will look for the file in C(vars/) subdirectory of a role or relative to playbook.
    type: path
  name:
    description:
      - The name of a variable into which assign the included vars.
      - If omitted (V(null)) they will be made top level vars.
    type: str
  expressions:
    description:
      - This option controls how Jinja2 expressions in values in the loaded file are handled.
      - If set to V(ignore), expressions will not be evaluated, but treated as regular strings.
      - If set to V(evaluate-on-load), expressions will be evaluated on execution of this module, in other words, when the
        file is loaded.
      - If set to V(lazy-evaluation), expressions will be lazily evaluated. This requires ansible-core 2.19 or newer
        and is the same behavior than M(ansible.builtin.include_vars). V(lazy-evaluation) has been added in community.sops 2.2.0.
    type: str
    default: ignore
    choices:
      - ignore
      - evaluate-on-load
      - lazy-evaluation
extends_documentation_fragment:
  - community.sops.sops
  - community.sops.attributes
  - community.sops.attributes.facts
  - community.sops.attributes.flow
attributes:
  action:
    support: full
  async:
    support: none
    details:
      - This action runs completely on the controller.
  check_mode:
    support: full
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
  facts:
    support: full
  idempotent:
    support: N/A
    details:
      - The action has no C(changed) state.
seealso:
  - module: ansible.builtin.set_fact
  - module: ansible.builtin.include_vars
  - ref: playbooks_delegation
    description: More information related to task delegation.
  - plugin: community.sops.sops
    plugin_type: lookup
    description: The sops lookup can be used decrypt SOPS-encrypted files.
  - plugin: community.sops.decrypt
    plugin_type: filter
    description: The decrypt filter can be used to descrypt SOPS-encrypted in-memory data.
  - plugin: community.sops.sops
    plugin_type: vars
    description: The sops vars plugin can be used to load SOPS-encrypted host or group variables.
"""

EXAMPLES = r"""
---
- name: Include variables of stuff.sops.yaml into the 'stuff' variable
  community.sops.load_vars:
    file: stuff.sops.yaml
    name: stuff
    expressions: evaluate-on-load # interpret Jinja2 expressions in stuf.sops.yaml on load-time!

- name: Conditionally decide to load in variables into 'plans' when x is 0, otherwise do not
  community.sops.load_vars:
    file: contingency_plan.sops.yaml
    name: plans
    expressions: ignore # do not interpret possible Jinja2 expressions
  when: x == 0

- name: Load variables into the global namespace
  community.sops.load_vars:
    file: contingency_plan.sops.yaml
"""

RETURN = r"""
ansible_facts:
  description: Variables that were included and their values.
  returned: success
  type: dict
  sample: {'variable': 'value'}
ansible_included_var_files:
  description: A list of files that were successfully included.
  returned: success
  type: list
  elements: str
  sample: [/path/to/file.sops.yaml]
"""
