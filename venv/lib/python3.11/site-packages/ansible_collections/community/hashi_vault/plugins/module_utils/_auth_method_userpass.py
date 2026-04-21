# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

'''Python versions supported: >=3.8'''

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within the community.hashi_vault collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultAuthMethodBase


class HashiVaultAuthMethodUserpass(HashiVaultAuthMethodBase):
    '''HashiVault option group class for auth: userpass'''

    NAME = 'userpass'
    OPTIONS = ['username', 'password', 'mount_point']

    def __init__(self, option_adapter, warning_callback, deprecate_callback):
        super(HashiVaultAuthMethodUserpass, self).__init__(option_adapter, warning_callback, deprecate_callback)

    def validate(self):
        self.validate_by_required_fields('username', 'password')

    def authenticate(self, client, use_token=True):
        params = self._options.get_filled_options(*self.OPTIONS)
        try:
            response = client.auth.userpass.login(**params)
        except (NotImplementedError, AttributeError):
            self.warn("HVAC should be updated to version 0.9.6 or higher. Deprecated method 'auth_userpass' will be used.")
            response = client.auth_userpass(**params)

        # must manually set the client token with userpass login
        # see https://github.com/hvac/hvac/issues/644
        # fixed in 0.11.0 (https://github.com/hvac/hvac/pull/733)
        # but we keep the old behavior to maintain compatibility with older hvac
        if use_token:
            client.token = response['auth']['client_token']

        return response
