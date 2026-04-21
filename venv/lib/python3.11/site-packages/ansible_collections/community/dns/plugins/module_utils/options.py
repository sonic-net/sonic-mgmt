# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible_collections.community.dns.plugins.module_utils.argspec import ArgumentSpec


def create_bulk_operations_argspec(provider_information):
    """
    If the provider supports bulk operations, return an ArgumentSpec object with appropriate
    options. Otherwise return an empty one.
    """
    if not provider_information.supports_bulk_actions():
        return ArgumentSpec()

    return ArgumentSpec(
        argument_spec={
            'bulk_operation_threshold': {'type': 'int', 'default': 2},
        },
    )


def create_record_transformation_argspec():
    return ArgumentSpec(
        argument_spec={
            'txt_transformation': {'type': 'str', 'default': 'unquoted', 'choices': ['api', 'quoted', 'unquoted']},
            'txt_character_encoding': {'type': 'str', 'default': 'decimal', 'choices': ['decimal', 'octal']},
        },
    )
