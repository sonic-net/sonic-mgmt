# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within the community.hashi_vault collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from ..plugin_utils._hashi_vault_plugin import HashiVaultPlugin

display = Display()


class HashiVaultLookupBase(HashiVaultPlugin, LookupBase):

    def __init__(self, loader=None, templar=None, **kwargs):
        HashiVaultPlugin.__init__(self)
        LookupBase.__init__(self, loader=loader, templar=templar, **kwargs)

    def parse_kev_term(self, term, plugin_name, first_unqualified=None):
        '''parses a term string into a dictionary'''
        param_dict = {}

        for i, param in enumerate(term.split()):
            try:
                key, value = param.split('=', 1)
            except ValueError:
                if i == 0 and first_unqualified is not None:
                    # allow first item to be specified as value only and assign to assumed option name
                    key = first_unqualified
                    value = param
                else:
                    raise AnsibleError("%s lookup plugin needs key=value pairs, but received %s" % (plugin_name, term))

            if key in param_dict:
                msg = "Duplicate key '%s' in the term string '%s'." % (key, term)
                raise AnsibleOptionsError(msg)

            param_dict[key] = value

        return param_dict
