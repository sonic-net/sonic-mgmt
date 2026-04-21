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
        - A data that will be validated against I(criteria).
        - This option represents the value that is passed to test plugin as check.
          For example C(config_data is ansible.utils.validate(criteria=criteria), in this case B(config_data)
          represents this option.
        - For the type of I(data) that represents this value refer documentation of individual validate plugins.
        required: True
      criteria:
        type: raw
        description:
        - The criteria used for validation of value that represents I(data) options.
        - This option is passed to the test plugin as key, value pair
          For example C(config_data is ansible.utils.validate(criteria=criteria)), in
          this case the value of I(criteria) key represents this criteria for data validation.
        - For the type of I(criteria) that represents this value refer documentation of individual validate plugins.
        required: True
      engine:
        type: str
        description:
        - The name of the validate plugin to use.
        - This option can be passed in test plugin as a key, value pair
          For example C(config_data is ansible.utils.validate(engine='ansible.utils.jsonschema', criteria=criteria)), in
          this case the value of I(engine) key represents the engine to be use for data validation.
          If the value is not provided the default value that is C(ansible.utils.jsonschema) will be used.
        - The value should be in fully qualified collection name format that is
          B(<org-name>.<collection-name>.<validate-plugin-name>).
        default: ansible.utils.jsonschema
    notes:
    - For the type of options I(data) and I(criteria) refer the individual validate plugin
      documentation that is represented in the value of I(engine) option.
    - For additional plugin configuration options refer the individual validate plugin
      documentation that is represented by the value of I(engine) option.
    - The plugin configuration option can be either passed as C(key=value) pairs within test plugin
      or set as environment variables.
    - The precedence the validate plugin configurable option is the variable passed within test plugin
      as C(key=value) pairs followed by task variables followed by environment variables.
"""

EXAMPLES = r"""
- name: set facts for data and criteria
  ansible.builtin.set_fact:
    data: "{{ lookup('ansible.builtin.file', './validate/data/show_interfaces_iosxr.json')}}"
    criteria: "{{ lookup('ansible.builtin.file', './validate/criteria/jsonschema/show_interfaces_iosxr.json')}}"

- name: validate data in json format using jsonschema with test plugin
  ansible.builtin.set_fact:
    is_data_valid: "{{ data is ansible.utils.validate(engine='ansible.utils.jsonschema', criteria=criteria, draft='draft7') }}"
"""

RETURN = """
  _raw:
    description:
      - If data is valid return C(true)
      - If data is invalid return C(false)
"""

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_text

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    check_argspec,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.utils import to_list
from ansible_collections.ansible.utils.plugins.plugin_utils.base.validate import _load_validator


ARGSPEC_CONDITIONALS = {}


def validate(*args, **kwargs):
    if not len(args):
        raise AnsibleError(
            "Missing either 'data' value in test plugin input,"
            "refer ansible.utils.validate test plugin documentation for details",
        )

    params = {"data": args[0]}

    for item in ["engine", "criteria"]:
        if kwargs.get(item):
            params.update({item: kwargs[item]})

    valid, argspec_result, updated_params = check_argspec(
        DOCUMENTATION,
        "validate test",
        schema_conditionals=ARGSPEC_CONDITIONALS,
        **params,
    )
    if not valid:
        raise AnsibleError(
            "{argspec_result} with errors: {argspec_errors}".format(
                argspec_result=argspec_result.get("msg"),
                argspec_errors=argspec_result.get("errors"),
            ),
        )

    validator_engine, validator_result = _load_validator(
        engine=updated_params["engine"],
        data=updated_params["data"],
        criteria=updated_params["criteria"],
        kwargs=kwargs,
    )
    if validator_result.get("failed"):
        raise AnsibleError(
            "validate lookup plugin failed with errors: %s" % validator_result.get("msg"),
        )

    try:
        result = validator_engine.validate()
    except AnsibleError as exc:
        raise AnsibleError(to_text(exc, errors="surrogate_then_replace"))
    except Exception as exc:
        raise AnsibleError(
            "Unhandled exception from validator '{validator}'. Error: {err}".format(
                validator=updated_params["engine"],
                err=to_text(exc, errors="surrogate_then_replace"),
            ),
        )

    errors = to_list(result.get("errors", []))
    if len(errors):
        return False

    return True


class TestModule(object):
    """data validation test"""

    test_map = {"validate": validate}

    def tests(self):
        return self.test_map
