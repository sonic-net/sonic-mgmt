# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


class ArgumentSpec(object):
    def __init__(self, argument_spec=None, required_together=None, required_if=None, required_one_of=None, mutually_exclusive=None):
        self.argument_spec = {}
        self.required_together = []
        self.required_if = []
        self.required_one_of = []
        self.mutually_exclusive = []
        if argument_spec:
            self.argument_spec.update(argument_spec)
        if required_together:
            self.required_together.extend(required_together)
        if required_if:
            self.required_if.extend(required_if)
        if required_one_of:
            self.required_one_of.extend(required_one_of)
        if mutually_exclusive:
            self.mutually_exclusive.extend(mutually_exclusive)

    def merge(self, other):
        self.argument_spec.update(other.argument_spec)
        self.required_together.extend(other.required_together)
        self.required_if.extend(other.required_if)
        self.required_one_of.extend(other.required_one_of)
        self.mutually_exclusive.extend(other.mutually_exclusive)
        return self

    def to_kwargs(self):
        return {
            'argument_spec': self.argument_spec,
            'required_together': self.required_together,
            'required_if': self.required_if,
            'required_one_of': self.required_one_of,
            'mutually_exclusive': self.mutually_exclusive,
        }


class ModuleOptionProvider(object):
    def __init__(self, module):
        self.module = module

    def get_option(self, option_name):
        return self.module.params[option_name]
