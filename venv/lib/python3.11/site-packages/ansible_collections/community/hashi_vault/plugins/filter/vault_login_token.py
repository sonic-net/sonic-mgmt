# -*- coding: utf-8 -*-
# (c) 2021, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError


def vault_login_token(login_response, optional_field='login'):
    '''Extracts the token value from a Vault login response.
    Meant to be used with the vault_login module and lookup plugin.
    '''

    try:
        deref = login_response[optional_field]
    except TypeError:
        raise AnsibleError("The 'vault_login_token' filter expects a dictionary.")
    except KeyError:
        deref = login_response

    try:
        token = deref['auth']['client_token']
    except KeyError:
        raise AnsibleError("Could not find 'auth' or 'auth.client_token' fields. Input may not be a Vault login response.")

    return token


class FilterModule(object):
    '''Ansible jinja2 filters'''

    def filters(self):
        return {
            'vault_login_token': vault_login_token,
        }
