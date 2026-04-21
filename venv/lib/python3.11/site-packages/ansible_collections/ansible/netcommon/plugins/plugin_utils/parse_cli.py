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
import re

from collections.abc import Mapping

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import Template


try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

string_types = (str,)


def _raise_error(msg):
    raise AnsibleFilterError(msg)


def re_matchall(regex, value):
    objects = list()
    for match in re.findall(regex.pattern, value, re.M):
        obj = {}
        if regex.groupindex:
            for name, index in regex.groupindex.items():
                if len(regex.groupindex) == 1:
                    obj[name] = match
                else:
                    obj[name] = match[index - 1]
            objects.append(obj)
    return objects


def re_search(regex, value):
    obj = {}
    match = regex.search(value, re.M)
    if match:
        items = list(match.groups())
        if regex.groupindex:
            for name, index in regex.groupindex.items():
                obj[name] = items[index - 1]
    return obj


def re_finditer(regex, value):
    iter_obj = re.finditer(regex, value)
    values = None
    for each in iter_obj:
        if not values:
            values = each.groupdict()
        else:
            # for backward compatibility
            values.update(each.groupdict())
        # for backward compatibility
        values["match"] = list(each.groups())
        groups = each.groupdict()
        for group in groups:
            if not values.get("match_all"):
                values["match_all"] = dict()
            if not values["match_all"].get(group):
                values["match_all"][group] = list()
            values["match_all"][group].append(groups[group])
    return values


def parse_cli(output, tmpl):
    if not isinstance(output, string_types):
        _raise_error(
            "parse_cli input should be a string, but was given a input of %s" % (type(output))
        )

    if not os.path.exists(tmpl):
        _raise_error("unable to locate parse_cli template: %s" % tmpl)

    try:
        template = Template()
    except ImportError as exc:
        _raise_error(to_native(exc))

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

        if "start_block" in attrs and "end_block" in attrs:
            start_block = re.compile(attrs["start_block"])
            end_block = re.compile(attrs["end_block"])

            blocks = list()
            lines = None
            block_started = False

            for line in output.split("\n"):
                match_start = start_block.match(line)
                match_end = end_block.match(line)

                if match_start:
                    lines = list()
                    lines.append(line)
                    block_started = True

                elif match_end:
                    if lines:
                        lines.append(line)
                        blocks.append("\n".join(lines))
                        lines = None
                    block_started = False

                elif block_started:
                    if lines:
                        lines.append(line)

            regex_items = [re.compile(r) for r in attrs["items"]]
            objects = list()

            for block in blocks:
                if isinstance(value, Mapping) and "key" not in value:
                    items = list()
                    for regex in regex_items:
                        items.append(re_finditer(regex, block))

                    obj = {}
                    for k, v in value.items():
                        try:
                            obj[k] = template(v, {"item": items}, fail_on_undefined=False)
                        except Exception:
                            obj[k] = None
                    objects.append(obj)

                elif isinstance(value, Mapping):
                    items = list()
                    for regex in regex_items:
                        items.append(re_finditer(regex, block))

                    key = template(value["key"], {"item": items})
                    values = dict(
                        [(k, template(v, {"item": items})) for k, v in value["values"].items()]
                    )
                    objects.append({key: values})

            return objects

        elif "items" in attrs:
            regexp = re.compile(attrs["items"])
            when = attrs.get("when")
            conditional = "{%% if %s %%}True{%% else %%}False{%% endif %%}" % when

            if isinstance(value, Mapping) and "key" not in value:
                values = list()

                for item in re_matchall(regexp, output):
                    entry = {}

                    for item_key, item_value in value.items():
                        entry[item_key] = template(item_value, {"item": item})

                    if when:
                        if template(conditional, {"item": entry}):
                            values.append(entry)
                    else:
                        values.append(entry)

                obj[name] = values

            elif isinstance(value, Mapping):
                values = dict()

                for item in re_matchall(regexp, output):
                    entry = {}

                    for item_key, item_value in value["values"].items():
                        entry[item_key] = template(item_value, {"item": item})

                    key = template(value["key"], {"item": item})

                    if when:
                        if template(conditional, {"item": {"key": key, "value": entry}}):
                            values[key] = entry
                    else:
                        values[key] = entry

                obj[name] = values

            else:
                item = re_search(regexp, output)
                obj[name] = template(value, {"item": item})

        else:
            obj[name] = value

    return obj
