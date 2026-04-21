#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The parse_xml plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import os
import traceback

from collections.abc import Mapping
from xml.etree.ElementTree import fromstring

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import Template


string_types = (str,)

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

display = Display()


def _raise_error(msg):
    raise AnsibleFilterError(msg)


def _extract_param(template, root, attrs, value):
    key = None
    when = attrs.get("when")
    conditional = "{%% if %s %%}True{%% else %%}False{%% endif %%}" % when
    param_to_xpath_map = attrs["items"]

    if isinstance(value, Mapping):
        key = value.get("key", None)
        if key:
            value = value["values"]

    entries = dict() if key else list()

    for element in root.findall(attrs["top"]):
        entry = dict()
        item_dict = dict()
        for param, param_xpath in param_to_xpath_map.items():
            fields = None
            try:
                fields = element.findall(param_xpath)
            except Exception:
                display.warning(
                    "Failed to evaluate value of '%s' with XPath '%s'.\nUnexpected error: %s."
                    % (param, param_xpath, traceback.format_exc())
                )

            tags = param_xpath.split("/")

            # check if xpath ends with attribute.
            # If yes set attribute key/value dict to param value in case attribute matches
            # else if it is a normal xpath assign matched element text value.
            if len(tags) and tags[-1].endswith("]"):
                if fields:
                    if len(fields) > 1:
                        item_dict[param] = [field.attrib for field in fields]
                    else:
                        item_dict[param] = fields[0].attrib
                else:
                    item_dict[param] = {}
            else:
                if fields:
                    if len(fields) > 1:
                        item_dict[param] = [field.text for field in fields]
                    else:
                        item_dict[param] = fields[0].text
                else:
                    item_dict[param] = None

        if isinstance(value, Mapping):
            for item_key, item_value in value.items():
                entry[item_key] = template(item_value, {"item": item_dict})
        else:
            entry = template(value, {"item": item_dict})

        if key:
            expanded_key = template(key, {"item": item_dict})
            if when:
                if template(
                    conditional,
                    {"item": {"key": expanded_key, "value": entry}},
                ):
                    entries[expanded_key] = entry
            else:
                entries[expanded_key] = entry
        else:
            if when:
                if template(conditional, {"item": entry}):
                    entries.append(entry)
            else:
                entries.append(entry)

    return entries


def parse_xml(output, tmpl):
    if not os.path.exists(tmpl):
        _raise_error("unable to locate parse_xml template: %s" % tmpl)

    if not isinstance(output, string_types):
        _raise_error("parse_xml works on string input, but given input of : %s" % type(output))

    root = fromstring(output)
    try:
        template = Template()
    except ImportError as exc:
        raise AnsibleFilterError(to_native(exc))

    with open(tmpl) as tmpl_fh:
        tmpl_content = tmpl_fh.read()

    spec = yaml.safe_load(tmpl_content)
    obj = {}

    for name, attrs in spec["keys"].items():
        value = attrs["value"]

        try:
            variables = spec.get("vars", {})
            value = template(value, variables)
        except Exception:
            pass

        if "items" in attrs:
            obj[name] = _extract_param(template, root, attrs, value)
        else:
            obj[name] = value

    return obj
