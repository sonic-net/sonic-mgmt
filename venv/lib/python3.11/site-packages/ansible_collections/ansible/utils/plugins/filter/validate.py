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
        - This option represents the value that is passed to the filter plugin in pipe format.
          For example C(config_data|ansible.utils.validate()), in this case C(config_data)
          represents this option.
        - For the type of I(data) that represents this value refer to the documentation of individual validator plugins.
        required: True
      criteria:
        type: raw
        description:
        - The criteria used for validation of value that represents I(data) options.
        - This option represents the first argument passed in the filter plugin.
          For example C(config_data|ansible.utils.validate(config_criteria)), in
          this case the value of C(config_criteria) represents this option.
        - For the type of I(criteria) that represents this value refer to the  documentation of individual validator plugins.
        required: True
      engine:
        type: str
        description:
        - The name of the validator plugin to use.
        - This option can be passed in lookup plugin as a key, value pair.
          For example C(config_data|ansible.utils.validate(config_criteria, engine='ansible.utils.jsonschema')), in
          this case the value C(ansible.utils.jsonschema) represents the engine to be use for data validation.
          If the value is not provided the default value that is C(ansible.utils.jsonschema) will be used.
        - The value should be in fully qualified collection name format that is
          C(<org-name>.<collection-name>.<validator-plugin-name>).
        default: ansible.utils.jsonschema
    notes:
    - For the type of options I(data) and I(criteria) refer to the individual validate plugin
      documentation that is represented in the value of I(engine) option.
    - For additional plugin configuration options refer to the individual validate plugin
      documentation that is represented by the value of I(engine) option.
    - The plugin configuration option can be either passed as C(key=value) pairs within filter plugin
      or environment variables.
    - The precedence of the I(validate) plugin configurable option is the variable passed within filter plugin
      as C(key=value) pairs followed by the environment variables.
"""

EXAMPLES = r"""
- name: set facts for data and criteria
  ansible.builtin.set_fact:
    data: "{{ lookup('ansible.builtin.file', './validate/data/show_interfaces_iosxr.json')}}"
    criteria: "{{ lookup('ansible.builtin.file', './validate/criteria/jsonschema/show_interfaces_iosxr.json')}}"

- name: validate data in json format using jsonschema by passing plugin configuration variable as key/value pairs
  ansible.builtin.set_fact:
    data_validity: "{{ data|ansible.utils.validate(criteria, engine='ansible.utils.jsonschema', draft='draft7') }}"
"""

RETURN = """
  _raw:
    description:
      - If data is valid returns empty list
      - If data is invalid returns list of errors in data
"""

from ansible.errors import AnsibleError, AnsibleFilterError
from ansible.module_utils._text import to_text

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    check_argspec,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.utils import to_list
from ansible_collections.ansible.utils.plugins.plugin_utils.base.validate import _load_validator


ARGSPEC_CONDITIONALS = {}


def validate(*args, **kwargs):
    if len(args) < 2:
        raise AnsibleFilterError(
            "Missing either 'data' or 'criteria' value in filter input,"
            " refer 'ansible.utils.validate' filter plugin documentation for details",
        )

    params = {"data": args[0], "criteria": args[1]}
    if kwargs.get("engine"):
        params.update({"engine": kwargs["engine"]})

    valid, argspec_result, updated_params = check_argspec(
        DOCUMENTATION,
        "validate filter",
        schema_conditionals=ARGSPEC_CONDITIONALS,
        **params,
    )
    if not valid:
        raise AnsibleFilterError(
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
        raise AnsibleFilterError(
            "validate lookup plugin failed with errors: {msg}".format(
                msg=validator_result.get("msg"),
            ),
        )

    try:
        result = validator_engine.validate()
    except AnsibleError as exc:
        raise AnsibleFilterError(to_text(exc, errors="surrogate_then_replace"))
    except Exception as exc:
        raise AnsibleFilterError(
            "Unhandled exception from validator '{validator}'. Error: {err}".format(
                validator=updated_params["engine"],
                err=to_text(exc, errors="surrogate_then_replace"),
            ),
        )

    return to_list(result.get("errors", []))


class FilterModule(object):
    """index_of"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"validate": validate}
