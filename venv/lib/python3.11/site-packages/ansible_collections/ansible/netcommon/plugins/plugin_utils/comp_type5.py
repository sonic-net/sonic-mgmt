#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The comp_type5 plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.plugin_utils.hash_salt import hash_salt
from ansible_collections.ansible.netcommon.plugins.plugin_utils.type5_pw import type5_pw


def comp_type5(unencrypted_password, encrypted_password, return_original=False):
    salt = hash_salt(encrypted_password)
    if type5_pw(unencrypted_password, salt) == encrypted_password:
        if return_original is True:
            return encrypted_password
        else:
            return True
    return False
