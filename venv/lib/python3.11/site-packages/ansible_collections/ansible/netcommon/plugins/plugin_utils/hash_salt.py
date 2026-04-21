#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The hash_salt plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.errors import AnsibleFilterError


def _raise_error(msg):
    raise AnsibleFilterError(msg)


def hash_salt(password):
    split_password = password.split("$")
    if len(split_password) != 4:
        _raise_error("Could not parse salt out password correctly from {0}".format(password))
    else:
        return split_password[2]
