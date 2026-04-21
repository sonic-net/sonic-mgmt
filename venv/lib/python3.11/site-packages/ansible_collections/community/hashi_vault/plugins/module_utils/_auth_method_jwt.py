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


class HashiVaultAuthMethodJwt(HashiVaultAuthMethodBase):
    '''HashiVault option group class for auth: jwt'''

    NAME = 'jwt'
    OPTIONS = ['jwt', 'role_id', 'mount_point']

    def __init__(self, option_adapter, warning_callback, deprecate_callback):
        super(HashiVaultAuthMethodJwt, self).__init__(option_adapter, warning_callback, deprecate_callback)

    def validate(self):
        self.validate_by_required_fields('role_id', 'jwt')

    def authenticate(self, client, use_token=True):
        params = self._options.get_filled_options(*self.OPTIONS)
        params['role'] = params.pop('role_id')

        if 'mount_point' in params:
            params['path'] = params.pop('mount_point')

        try:
            response = client.auth.jwt.jwt_login(**params)
        except (NotImplementedError, AttributeError):
            raise NotImplementedError("JWT authentication requires HVAC version 0.10.5 or higher.")

        # must manually set the client token with JWT login
        # see https://github.com/hvac/hvac/issues/644
        # fixed in https://github.com/hvac/hvac/pull/746
        # but we do it manually to maintain compatibilty with older hvac versions.
        if use_token:
            client.token = response['auth']['client_token']

        return response
