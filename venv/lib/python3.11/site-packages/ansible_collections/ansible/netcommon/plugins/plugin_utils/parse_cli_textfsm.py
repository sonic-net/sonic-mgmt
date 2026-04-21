#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The parse_cli_textfsm plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import os

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_native


try:
    import textfsm

    HAS_TEXTFSM = True
except ImportError:
    HAS_TEXTFSM = False

string_types = (str,)


def _raise_error(msg):
    raise AnsibleFilterError(msg)


def parse_cli_textfsm(value, template):
    if not HAS_TEXTFSM:
        _raise_error("parse_cli_textfsm filter requires TextFSM library to be installed")

    if not isinstance(value, string_types):
        _raise_error(
            "parse_cli_textfsm input should be a string, but was given a input of %s"
            % (type(value))
        )

    if not os.path.exists(template):
        _raise_error("unable to locate parse_cli_textfsm template: %s" % template)

    try:
        template = open(template)
    except IOError as exc:
        _raise_error(to_native(exc))

    re_table = textfsm.TextFSM(template)
    fsm_results = re_table.ParseText(value)

    results = list()
    for item in fsm_results:
        results.append(dict(zip(re_table.header, item)))

    return results
