# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
flatten a complex object to dot bracket notation
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type


def get_path(var, path, environment, wantlist):
    """Get the value of a path within an object

    :param var: The var from which the value is retrieved
    :type var: should be dict or list, but jinja can sort that out
    :param path: The path to get
    :type path: should be a string but jinja can sort that out
    :param environment: The jinja Environment
    :type environment: Environment
    :return: The result of the jinja evaluation
    :rtype: any
    """
    string_to_variable = "{{ %s }}" % path
    result = environment.from_string(string_to_variable).render(**var)
    if wantlist:
        return [result]
    return result
