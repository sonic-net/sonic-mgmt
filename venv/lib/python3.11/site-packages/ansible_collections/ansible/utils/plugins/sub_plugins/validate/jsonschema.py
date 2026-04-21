# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Ganesh Nalawade (@ganeshrn)
    name: jsonschema
    short_description: Define configurable options for jsonschema validate plugin
    description:
    - This sub plugin documentation provides the configurable options that can be passed
      to the validate plugins when C(ansible.utils.jsonschema) is used as a value for
      engine option.
    version_added: 1.0.0
    options:
      draft:
        description:
        - This option provides the jsonschema specification that should be used
          for the validating the data. The I(criteria) option in the validate
          plugin should follow the specification as mentioned by this option.
          If this option is not specified, jsonschema will use the best validator
          for the I($schema) field in the criteria. Specifications 2019-09 and
          2020-12 are only available from jsonschema version 4.0 onwards.
        choices:
        - draft3
        - draft4
        - draft6
        - draft7
        - 2019-09
        - 2020-12
        env:
        - name: ANSIBLE_VALIDATE_JSONSCHEMA_DRAFT
        vars:
        - name: ansible_validate_jsonschema_draft
      check_format:
        description: If enabled, validate the I(format) specification in the criteria.
        type: bool
        default: true
        env:
        - name: ANSIBLE_VALIDATE_JSONSCHEMA_CHECK_FORMAT
        vars:
        - name: ansible_validate_jsonschema_check_format
    notes:
    - The value of I(data) option should be either a valid B(JSON) object or a B(JSON) string.
    - The value of I(criteria) should be B(list) of B(dict) or B(list) of B(strings) and each
      B(string) within the B(list) entry should be a valid B(dict) when read in python.
"""

import json

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_text
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.six import string_types
from ansible.utils.display import Display

from ansible_collections.ansible.utils.plugins.module_utils.common.utils import to_list
from ansible_collections.ansible.utils.plugins.plugin_utils.base.validate import ValidateBase


display = Display()

# PY2 compatibility for JSONDecodeError
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

try:
    import jsonschema
    import jsonschema.validators

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def to_path(fpath):
    return ".".join(str(index) for index in fpath)


def json_path(absolute_path):
    path = "$"
    for elem in absolute_path:
        if isinstance(elem, int):
            path += "[" + str(elem) + "]"
        else:
            path += "." + elem
    return path


class Validate(ValidateBase):
    # All available schema versions with the format_check and validator class names.
    _JSONSCHEMA_DRAFTS = {
        "draft3": {
            "validator_name": "Draft3Validator",
            "format_checker_name": "draft3_format_checker",
        },
        "draft4": {
            "validator_name": "Draft4Validator",
            "format_checker_name": "draft4_format_checker",
        },
        "draft6": {
            "validator_name": "Draft6Validator",
            "format_checker_name": "draft6_format_checker",
        },
        "draft7": {
            "validator_name": "Draft7Validator",
            "format_checker_name": "draft7_format_checker",
        },
        "2019-09": {
            "validator_name": "Draft201909Validator",
            "format_checker_name": "draft201909_format_checker",
        },
        "2020-12": {
            "validator_name": "Draft202012Validator",
            "format_checker_name": "draft202012_format_checker",
        },
    }

    @staticmethod
    def _check_reqs():
        """Check the prerequisites are installed for jsonschema

        :return None: In case all prerequisites are satisfied
        """
        if not HAS_JSONSCHEMA:
            raise AnsibleError(missing_required_lib("jsonschema"))

    def _check_args(self):
        """Ensure specific args are set

        :return: None: In case all arguments passed are valid
        """
        try:
            if isinstance(self._data, string_types):
                self._data = json.loads(self._data)
            else:
                self._data = json.loads(json.dumps(self._data))

        except (TypeError, JSONDecodeError) as exe:
            msg = (
                "'data' option value is invalid, value should a valid JSON."
                " Failed to read with error '{err}'".format(
                    err=to_text(exe, errors="surrogate_then_replace"),
                )
            )
            raise AnsibleError(msg)

        try:
            criteria = []
            for item in to_list(self._criteria):
                if isinstance(self._criteria, string_types):
                    criteria.append(json.loads(item))
                else:
                    criteria.append(json.loads(json.dumps(item)))

            self._criteria = criteria
        except (TypeError, JSONDecodeError) as exe:
            msg = (
                "'criteria' option value is invalid, value should a valid JSON."
                " Failed to read with error '{err}'".format(
                    err=to_text(exe, errors="surrogate_then_replace"),
                )
            )
            raise AnsibleError(msg)

    def _check_drafts(self):
        """For every possible draft check if our jsonschema version supports it and exchange the class names with
        the actual classes. If it is not supported the draft is removed from the list.
        """
        for draft in list(self._JSONSCHEMA_DRAFTS.keys()):
            draft_config = self._JSONSCHEMA_DRAFTS[draft]
            try:
                validator_class = getattr(jsonschema, draft_config["validator_name"])
            except AttributeError:
                display.vvv(
                    'jsonschema draft "{draft}" not supported in this version'.format(draft=draft),
                )
                del self._JSONSCHEMA_DRAFTS[draft]
                continue
            draft_config["validator"] = validator_class
            try:
                format_checker_class = validator_class.FORMAT_CHECKER
            except AttributeError:
                # Older jsonschema version
                format_checker_class = getattr(jsonschema, draft_config["format_checker_name"])
            draft_config["format_checker"] = format_checker_class

    def validate(self):
        """Std entry point for a validate execution

        :return: Errors or parsed text as structured data
        :rtype: dict

        :example:

        The parse function of a parser should return a dict:
        {"errors": [a list of errors]}
        or
        {"parsed": obj}
        """
        self._check_reqs()
        self._check_args()
        self._check_drafts()

        try:
            self._validate_jsonschema()
        except Exception as exc:
            return {"errors": to_text(exc, errors="surrogate_then_replace")}

        return self._result

    def _validate_jsonschema(self):
        error_messages = None

        draft = self._get_sub_plugin_options("draft")
        check_format = self._get_sub_plugin_options("check_format")
        error_messages = []

        for criteria in self._criteria:
            format_checker = None
            validator_class = None
            if draft is not None:
                try:
                    validator_class = self._JSONSCHEMA_DRAFTS[draft]["validator"]
                except KeyError:
                    display.warning(
                        'No validator available for "{draft}", falling back to autodetection. A newer version of jsonschema might support this draft.'.format(
                            draft=draft,
                        ),
                    )
            if validator_class is None:
                # Either no draft was specified or specified draft has no validator class
                # in installed jsonschema version. Do autodetection instead.
                validator_class = jsonschema.validators.validator_for(criteria)

            if check_format:
                try:
                    format_checker = validator_class.FORMAT_CHECKER
                except AttributeError:
                    # TODO: Remove when Python 3.6 support is dropped.
                    # On jsonschema<4.5, there is no connection between a validator and the correct format checker.
                    # So we iterate through our known list of validators and if one matches the current class
                    # we use the format_checker from that validator.
                    for draft, draft_config in self._JSONSCHEMA_DRAFTS.items():
                        if validator_class == draft_config["validator"]:
                            display.vvv(
                                "Using format_checker for {draft} validator".format(draft=draft),
                            )
                            format_checker = draft_config["format_checker"]
                            break
                    else:
                        display.warning("jsonschema format checks not available")

            validator = validator_class(criteria, format_checker=format_checker)
            validation_errors = sorted(validator.iter_errors(self._data), key=lambda e: e.path)

            if validation_errors:
                if "errors" not in self._result:
                    self._result["errors"] = []

                for validation_error in validation_errors:
                    if isinstance(validation_error, jsonschema.ValidationError):
                        error = {
                            "message": validation_error.message,
                            "data_path": to_path(validation_error.absolute_path),
                            "json_path": json_path(validation_error.absolute_path),
                            "schema_path": to_path(validation_error.relative_schema_path),
                            "relative_schema": validation_error.schema,
                            "expected": validation_error.validator_value,
                            "validator": validation_error.validator,
                            "found": validation_error.instance,
                        }
                        self._result["errors"].append(error)
                        error_message = "At '{schema_path}' {message}. ".format(
                            schema_path=error["schema_path"],
                            message=error["message"],
                        )
                        error_messages.append(error_message)
        if error_messages:
            if "msg" not in self._result:
                self._result["msg"] = "\n".join(error_messages)
            else:
                self._result["msg"] += "\n".join(error_messages)
