#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: validate
author:
- Bradley Thornton (@cidrblock)
- Ganesh Nalawade (@ganeshrn)
short_description: Validate data with provided criteria
description:
- Validate data with provided criteria based on the validation engine.
version_added: 1.0.0
options:
    data:
        type: raw
        description:
        - Data that will be validated against I(criteria). For the type of data refer to the
          documentation of individual validate plugins.
        required: True
    engine:
        type: str
        description:
        - The name of the validate plugin to use. The engine value should follow
          the fully qualified collection name format, that is
          <org-name>.<collection-name>.<validate-plugin-name>.
        default: ansible.utils.jsonschema
    criteria:
        type: raw
        description:
        - The criteria used for validation of I(data). For the type of criteria refer to the
          documentation of individual validate plugins.
        required: True
notes:
- For the type of options I(data) and I(criteria) refer to the individual validate plugin
  documentation that is represented in the value of I(engine) option.
- For additional plugin configuration options refer to the individual validate plugin
  documentation that is represented by the value of I(engine) option.
- The plugin configuration option can be either passed as task or environment variables.
- The precedence of the validate plugin configurable option is task variables followed
  by the environment variables.
"""

EXAMPLES = r"""
- name: set facts for data and criteria
  ansible.builtin.set_fact:
    data: "{{ lookup('ansible.builtin.file', './validate/data/show_interfaces_iosxr.json') }}"
    criteria: "{{ lookup('ansible.builtin.file', './validate/criteria/jsonschema/show_interfaces_iosxr.json') }}"

- name: validate data in with jsonschema engine (by passing task vars as configurable plugin options)
  ansible.utils.validate:
    data: "{{ data }}"
    criteria: "{{ criteria }}"
    engine: ansible.utils.jsonschema
  vars:
    ansible_jsonschema_draft: draft7

- name: validate configuration with config plugin (see config plugin for criteria examples)
  ansible.utils.validate:
    data: "{{ lookup('ansible.builtin.file', './backup/eos.config') }}"
    criteria: "{{ lookup('ansible.builtin.file', './validate/criteria/config/eos_config_rules.yaml') }}"
    engine: ansible.utils.config
"""

RETURN = r"""
msg:
  description:
  - The msg indicates if the I(data) is valid as per the I(criteria).
  - In case data is valid return success message B(all checks passed).
  - In case data is invalid return error message B(Validation errors were found)
    along with more information on error is available.
  returned: always
  type: str
errors:
  description: The list of errors in I(data) based on the I(criteria).
  returned: when I(data) value is invalid
  type: list
  elements: str
"""
