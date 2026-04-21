# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: validate
    author: Ganesh Nalawade (@ganeshrn)
    version_added: "1.0.0"
    short_description: Validate data with provided criteria
    description:
      - Validate I(data) with provided I(criteria) based on the validation I(engine).
    options:
      data:
        type: raw
        description:
          - Data that will be validated against I(criteria).
          - This option represents the value that is passed to the lookup plugin as the first argument.
            For example C(lookup(config_data, config_criteria, engine='ansible.utils.jsonschema')),
            in this case C(config_data) represents this option.
          - For the type of I(data) that represents this value refer to the documentation of individual validate plugins.
        required: True
      criteria:
        type: raw
        description:
          - The criteria used for validation of value that represents I(data) options.
          - This option represents the second argument passed in the lookup plugin
            For example C(lookup(config_data, config_criteria, engine='ansible.utils.jsonschema')),
            in this case the value of C(config_criteria) represents this option.
          - For the type of I(criteria) that represents this value refer to the documentation of individual
            validate plugins.
        required: True
      engine:
        type: str
        description:
          - The name of the validate plugin to use.
          - This option can be passed in lookup plugin as a key, value pair.
            For example C(lookup(config_data, config_criteria, engine='ansible.utils.jsonschema')), in
            this case the value C(ansible.utils.jsonschema) represents the engine to be use for data validation.
            If the value is not provided the default value that is C(ansible.utils.jsonschema) will be used.
          - The value should be in fully qualified collection name format that is
            C(<org-name>.<collection-name>.<validate-plugin-name>).
        default: ansible.utils.jsonschema
    notes:
      - For the type of options I(data) and I(criteria) refer to the individual validate plugin
        documentation that is represented in the value of I(engine) option.
      - For additional plugin configuration options refer to the individual validate plugin
        documentation that is represented by the value of I(engine) option.
      - The plugin configuration option can be either passed as C(key=value) pairs within lookup plugin
        or task or environment variables.
      - The precedence the validate plugin configurable option is the variable passed within lookup plugin
        as C(key=value) pairs followed by task variables followed by environment variables.
"""

EXAMPLES = r"""
- name: set facts for data and criteria
  ansible.builtin.set_fact:
    data: "{{ lookup('ansible.builtin.file', './validate/data/show_interfaces_iosxr.json') }}"
    criteria: "{{ lookup('ansible.builtin.file', './validate/criteria/jsonschema/show_interfaces_iosxr.json') }}"

- name: validate data in json format using jsonschema with lookup plugin by passing plugin configuration variable as key/value pairs
  ansible.builtin.set_fact:
    data_criteria_checks: "{{ lookup('ansible.utils.validate', data, criteria, engine='ansible.utils.jsonschema', draft='draft7') }}"

- name: validate data in json format using jsonschema with lookup plugin by passing plugin configuration variable as task variable
  ansible.builtin.set_fact:
    data_criteria_checks: "{{ lookup('ansible.utils.validate', data, criteria, engine='ansible.utils.jsonschema', draft='draft7') }}"
  vars:
    ansible_validate_jsonschema_draft: draft3
"""

RETURN = """
  _raw:
    description:
      - If data is valid returns empty list.
      - If data is invalid returns list of errors in data.
"""

from ansible.errors import AnsibleError, AnsibleLookupError
from ansible.module_utils._text import to_text
from ansible.plugins.lookup import LookupBase

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    check_argspec,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.utils import to_list
from ansible_collections.ansible.utils.plugins.plugin_utils.base.validate import _load_validator


ARGSPEC_CONDITIONALS = {}


class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):
        if len(terms) < 2:
            raise AnsibleLookupError(
                "missing either 'data' or 'criteria' value in lookup input,"
                " refer ansible.utils.validate lookup plugin documentation for details",
            )

        params = {"data": terms[0], "criteria": terms[1]}
        if kwargs.get("engine"):
            params.update({"engine": kwargs["engine"]})

        valid, argspec_result, updated_params = check_argspec(
            schema=DOCUMENTATION,
            name="validate lookup",
            schema_conditionals=ARGSPEC_CONDITIONALS,
            **params,
        )
        if not valid:
            raise AnsibleLookupError(
                "{argspec_result} with errors: {argspec_errors}".format(
                    argspec_result=argspec_result.get("msg"),
                    argspec_errors=argspec_result.get("errors"),
                ),
            )

        validator_engine, validator_result = _load_validator(
            engine=updated_params["engine"],
            data=updated_params["data"],
            criteria=updated_params["criteria"],
            plugin_vars=variables,
            kwargs=kwargs,
        )
        if validator_result.get("failed"):
            raise AnsibleLookupError(
                "validate lookup plugin failed with errors: {validator_result}".format(
                    validator_result=validator_result.get("msg"),
                ),
            )

        try:
            result = validator_engine.validate()
        except AnsibleError as exc:
            raise AnsibleLookupError(to_text(exc, errors="surrogate_then_replace"))
        except Exception as exc:
            raise AnsibleLookupError(
                "Unhandled exception from validator '{validator}'. Error: {err}".format(
                    validator=updated_params["engine"],
                    err=to_text(exc, errors="surrogate_then_replace"),
                ),
            )

        return to_list(result.get("errors", []))
